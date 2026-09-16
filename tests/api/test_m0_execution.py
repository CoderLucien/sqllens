from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest
from sqllens_api.evidence_connector import (
    QueryResult,
    ValidatedM0Select,
    bind_m0_ordinary_explain,
    query_pack,
)
from sqllens_api.m0_connection import (
    CLIENT_MULTI_STATEMENTS,
    M0DriverInvariantError,
    M0LiveConnection,
    M0TidbTimeoutError,
    M0TidbUnavailableError,
)


def _quote_driver_value(value: object) -> str:
    if value is None:
        return "NULL"
    if type(value) in (int, float):
        return str(value)
    if not isinstance(value, str):
        raise TypeError("unsupported fake driver value")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


class ExecutionCursor:
    def __init__(self, connection: ExecutionConnection) -> None:
        self.connection = connection
        self.description = tuple(
            (column, None, None, None, None, None, None) for column in connection.columns
        )

    async def __aenter__(self) -> ExecutionCursor:
        self.connection.cursor_entries += 1
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def mogrify(self, query: str, args: object = None) -> str:
        self.connection.mogrified.append((query, args))
        if self.connection.mogrify_override is not None:
            return self.connection.mogrify_override
        values = () if args is None else tuple(args)  # type: ignore[arg-type]
        pieces = query.split("%s")
        if len(pieces) != len(values) + 1:
            raise ValueError("fake placeholder mismatch")
        return "".join(
            piece + (_quote_driver_value(values[index]) if index < len(values) else "")
            for index, piece in enumerate(pieces)
        )

    async def execute(self, query: str, args: object = None) -> None:
        self.connection.executed.append((query, args))
        self.connection.execute_started.set()
        if self.connection.execute_waiter is not None:
            await self.connection.execute_waiter.wait()
        if self.connection.execute_error is not None:
            raise self.connection.execute_error

    async def fetchmany(self, size: int | None = None) -> list[tuple[object, ...]]:
        self.connection.fetch_sizes.append(size)
        return list(self.connection.rows)


class ExecutionConnection:
    def __init__(
        self,
        *,
        columns: tuple[str, ...],
        rows: tuple[tuple[object, ...], ...],
    ) -> None:
        self._client_flag = 0
        self._password: object = b""
        self._password_creator: object = None
        self.server_status = 0
        self.columns = columns
        self.rows = rows
        self.cursor_entries = 0
        self.mogrified: list[tuple[str, object]] = []
        self.executed: list[tuple[str, object]] = []
        self.fetch_sizes: list[int | None] = []
        self.execute_started = asyncio.Event()
        self.execute_waiter: asyncio.Event | None = None
        self.execute_error: BaseException | None = None
        self.mogrify_override: str | None = None
        self.ensure_closed_calls = 0
        self.close_calls = 0

    def cursor(self) -> ExecutionCursor:
        return ExecutionCursor(self)

    async def ensure_closed(self) -> None:
        self.ensure_closed_calls += 1

    def close(self) -> None:
        self.close_calls += 1


def live_connection(
    raw: ExecutionConnection,
    *,
    timeout_seconds: float = 5.0,
) -> M0LiveConnection:
    return M0LiveConnection(
        database="shop",
        _raw=raw,
        _io_timeout_seconds=timeout_seconds,
        version="8.5.4",
    )


@pytest.mark.asyncio
async def test_registered_executor_binds_values_and_reparses_before_driver_io() -> None:
    query = query_pack("tidb-8.5")["sql_digest.encode"]
    expected_digest = "a" * 64
    raw = ExecutionConnection(
        columns=query.result_columns,
        rows=((expected_digest,),),
    )
    live = live_connection(raw)
    sql_text = "SELECT '; DELETE FROM orders' AS marker FROM orders"

    result = await live.execute(
        execution_id="exec_0123456789abcdef",
        query=query,
        parameters={"sql_text": sql_text},
    )

    assert result == QueryResult(
        columns=("sql_digest",),
        rows=({"sql_digest": expected_digest},),
        truncated=False,
        observed_bytes=result.observed_bytes,
        elapsed_ms=result.elapsed_ms,
    )
    assert result.observed_bytes > 0
    assert result.elapsed_ms >= 0
    assert raw.cursor_entries == 1
    assert raw.fetch_sizes == [2]
    assert raw.mogrified == [("SELECT TIDB_ENCODE_SQL_DIGEST(%s) AS sql_digest", (sql_text,))]
    assert raw.executed == [("SELECT TIDB_ENCODE_SQL_DIGEST(%s) AS sql_digest", (sql_text,))]


@pytest.mark.asyncio
async def test_executor_rejects_registry_tampering_before_cursor_io() -> None:
    registered = query_pack("tidb-8.5")["sql_digest.encode"]
    tampered = replace(registered, sql=f"{registered.sql}; DELETE FROM orders")
    raw = ExecutionConnection(columns=registered.result_columns, rows=(("a" * 64,),))

    with pytest.raises(M0DriverInvariantError):
        await live_connection(raw).execute(
            execution_id="exec_0123456789abcdef",
            query=tampered,
            parameters={"sql_text": "SELECT id FROM orders"},
        )

    assert raw.cursor_entries == 0
    assert raw.executed == []


@pytest.mark.asyncio
async def test_executor_rejects_driver_bound_second_statement_before_execute_io() -> None:
    query = query_pack("tidb-8.5")["sql_digest.encode"]
    raw = ExecutionConnection(columns=query.result_columns, rows=(("a" * 64,),))
    raw.mogrify_override = "SELECT 'a' AS sql_digest; DELETE FROM orders"

    with pytest.raises(M0DriverInvariantError):
        await live_connection(raw).execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders"},
        )

    assert raw.executed == []
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_statistics_bound_validation_does_not_log_driver_escaped_identifiers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    query = query_pack("tidb-8.5")["statistics.health.current_table"]
    raw = ExecutionConnection(
        columns=query.result_columns,
        rows=(("private_schema", "orders", "", 75),),
    )
    private_schema = "private_schema'; DELETE FROM orders; --"
    caplog.set_level("WARNING")

    result = await live_connection(raw).execute(
        execution_id="exec_0123456789abcdef",
        query=query,
        parameters={"schema_name": private_schema, "table_name": "orders"},
    )

    assert result.rows[0]["healthy"] == 75
    assert "private_schema" not in caplog.text
    assert private_schema not in caplog.text
    assert "DELETE FROM orders" not in caplog.text


@pytest.mark.asyncio
async def test_statistics_bound_validation_rejects_a_real_second_statement() -> None:
    query = query_pack("tidb-8.5")["statistics.health.current_table"]
    raw = ExecutionConnection(columns=query.result_columns, rows=())
    raw.mogrify_override = (
        "SHOW STATS_HEALTHY WHERE db_name = 'shop' "
        "AND table_name = 'orders' AND partition_name = ''; DELETE FROM orders"
    )

    with pytest.raises(M0DriverInvariantError):
        await live_connection(raw).execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={"schema_name": "shop", "table_name": "orders"},
        )

    assert raw.executed == []
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_executor_rejects_wrong_parameter_shape_before_cursor_io() -> None:
    query = query_pack("tidb-8.5")["sql_digest.encode"]
    raw = ExecutionConnection(columns=query.result_columns, rows=(("a" * 64,),))

    with pytest.raises(M0DriverInvariantError):
        await live_connection(raw).execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders", "extra": "forbidden"},
        )

    assert raw.cursor_entries == 0


@pytest.mark.asyncio
async def test_generic_executor_rejects_caller_created_dynamic_explain() -> None:
    value = ValidatedM0Select(
        canonical_sql="SELECT id FROM orders",
        sql_digest="a" * 64,
        database="shop",
        table_name="orders",
    )
    query = bind_m0_ordinary_explain(value)
    raw = ExecutionConnection(columns=query.result_columns, rows=())

    with pytest.raises(M0DriverInvariantError):
        await live_connection(raw).execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={},
        )

    assert raw.cursor_entries == 0


@pytest.mark.asyncio
async def test_dynamic_explain_executor_rebuilds_the_exact_binder_query() -> None:
    value = ValidatedM0Select(
        canonical_sql="SELECT id FROM orders WHERE customer_id = 42",
        sql_digest="a" * 64,
        database="shop",
        table_name="orders",
    )
    query = bind_m0_ordinary_explain(value)
    raw = ExecutionConnection(
        columns=("id", "estRows", "task", "access object", "operator info"),
        rows=(("TableFullScan_5", 10000, "cop[tikv]", "table:orders", "keep order:false"),),
    )

    result = await live_connection(raw).execute_ordinary_explain(
        execution_id="exec_0123456789abcdef",
        value=value,
    )

    assert result.columns == query.result_columns
    assert result.rows[0]["id"] == "TableFullScan_5"
    assert raw.mogrified == [(query.sql, None)]
    assert raw.executed == [(query.sql, None)]


@pytest.mark.asyncio
async def test_executor_checks_multi_statement_capability_before_every_io() -> None:
    query = query_pack("tidb-8.5")["sql_digest.encode"]
    raw = ExecutionConnection(columns=query.result_columns, rows=(("a" * 64,),))
    raw._client_flag |= CLIENT_MULTI_STATEMENTS

    with pytest.raises(M0DriverInvariantError):
        await live_connection(raw).execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders"},
        )

    assert raw.cursor_entries == 0


@pytest.mark.asyncio
async def test_executor_fails_closed_on_wrong_columns_or_oversized_result() -> None:
    query = query_pack("tidb-8.5")["sql_digest.encode"]
    wrong_columns = ExecutionConnection(columns=("raw_sql",), rows=(("secret",),))

    with pytest.raises(M0TidbUnavailableError):
        await live_connection(wrong_columns).execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders"},
        )

    assert wrong_columns.ensure_closed_calls + wrong_columns.close_calls >= 1

    oversized = ExecutionConnection(
        columns=query.result_columns,
        rows=(("a" * query.budget.max_bytes,),),
    )
    with pytest.raises(M0TidbUnavailableError):
        await live_connection(oversized).execute(
            execution_id="exec_1123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders"},
        )

    assert oversized.ensure_closed_calls + oversized.close_calls >= 1


@pytest.mark.asyncio
async def test_executor_truncates_only_at_the_registered_row_cap() -> None:
    query = query_pack("tidb-8.5")["sql_candidates.current_user"]
    raw = ExecutionConnection(
        columns=query.result_columns,
        rows=tuple(
            ("a" * 64, 1, 2, 3, 4, 1_788_376_800_000) for _ in range(query.budget.max_rows + 1)
        ),
    )

    result = await live_connection(raw).execute(
        execution_id="exec_0123456789abcdef",
        query=query,
        parameters={
            "window_start": "2026-09-03T06:00:00Z",
            "window_end": "2026-09-03T06:30:00Z",
            "schema_name": "shop",
        },
    )

    assert len(result.rows) == query.budget.max_rows
    assert result.truncated is True
    assert raw.fetch_sizes == [query.budget.max_rows + 1]


@pytest.mark.asyncio
async def test_executor_timeout_closes_socket_and_raises_sanitized_error() -> None:
    query = query_pack("tidb-8.5")["sql_digest.encode"]
    raw = ExecutionConnection(columns=query.result_columns, rows=(("a" * 64,),))
    raw.execute_waiter = asyncio.Event()

    with pytest.raises(M0TidbTimeoutError):
        await live_connection(raw, timeout_seconds=0.01).execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders"},
        )

    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_executor_cancellation_aborts_socket_and_does_not_background_query() -> None:
    query = query_pack("tidb-8.5")["sql_digest.encode"]
    raw = ExecutionConnection(columns=query.result_columns, rows=(("a" * 64,),))
    raw.execute_waiter = asyncio.Event()
    operation = asyncio.create_task(
        live_connection(raw).execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders"},
        )
    )
    await raw.execute_started.wait()

    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation

    assert raw.close_calls >= 1


@pytest.mark.asyncio
async def test_executor_rejects_concurrent_or_reused_execution_identity() -> None:
    query = query_pack("tidb-8.5")["sql_digest.encode"]
    raw = ExecutionConnection(columns=query.result_columns, rows=(("a" * 64,),))
    raw.execute_waiter = asyncio.Event()
    live = live_connection(raw)
    first = asyncio.create_task(
        live.execute(
            execution_id="exec_0123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders"},
        )
    )
    await raw.execute_started.wait()

    with pytest.raises(M0DriverInvariantError):
        await live.execute(
            execution_id="exec_1123456789abcdef",
            query=query,
            parameters={"sql_text": "SELECT id FROM orders"},
        )

    first.cancel()
    await asyncio.gather(first, return_exceptions=True)
