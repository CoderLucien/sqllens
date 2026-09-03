from __future__ import annotations

import asyncio
import math
import re
import secrets
import unicodedata
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlglot import Dialect, exp
from sqlglot.errors import ErrorLevel, SqlglotError
from sqlglot.optimizer.scope import Scope, traverse_scope

from sqllens_api.evidence_connector import (
    MAX_SAFE_INTEGER,
    JsonValue,
    QueryResult,
    QueryValue,
    ServerQuery,
    ValidatedM0Select,
    bind_m0_ordinary_explain,
    query_pack,
)
from sqllens_api.m0_connection import (
    M0BusyError,
    M0ConnectionStore,
    M0DriverInvariantError,
    M0TidbTimeoutError,
    M0TidbUnavailableError,
)

M0_MIN_WINDOW_MINUTES = 5
M0_MAX_WINDOW_MINUTES = 60
M0_MAX_SQL_BYTES = 32_768
M0_MAX_PREDICATE_COLUMNS = 32
M0_DIAGNOSIS_TIMEOUT_SECONDS = 30.0
M0_DIAGNOSIS_MAX_ROWS = 1_000
M0_DIAGNOSIS_MAX_BYTES = 2 * 1_024 * 1_024
_SQL_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UNSAFE_SELECT_EXPRESSIONS = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.Merge,
    exp.TruncateTable,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Grant,
    exp.Revoke,
    exp.Copy,
    exp.LoadData,
    exp.Into,
    exp.Lock,
    exp.Analyze,
    exp.Execute,
    exp.Set,
    exp.Command,
    exp.Use,
    exp.Pragma,
)

type Clock = Callable[[], datetime]
type ExecutionIdFactory = Callable[[], str]


class M0DiagnosisInput(BaseModel):
    """Closed request model whose SQL text never appears in object representations."""

    model_config = ConfigDict(extra="forbid", strict=True)

    sql_digest: str = Field(pattern=_SQL_DIGEST.pattern)
    sql_text: str = Field(repr=False)
    window_minutes: int = Field(ge=M0_MIN_WINDOW_MINUTES, le=M0_MAX_WINDOW_MINUTES)

    @field_validator("sql_text")
    @classmethod
    def validate_sql_bytes(cls, value: str) -> str:
        try:
            byte_length = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError("SQL text must be valid UTF-8") from None
        if not 1 <= byte_length <= M0_MAX_SQL_BYTES:
            raise ValueError("SQL text must encode to between 1 and 32768 UTF-8 bytes")
        return value


class M0DiagnosisValidationError(ValueError):
    def __init__(self) -> None:
        super().__init__("The SQL is not a supported M0 SELECT.")


@dataclass(frozen=True, slots=True)
class ParsedM0Select:
    """Request-local SQL structure safe to retain only for one diagnosis call."""

    canonical_sql: str = field(repr=False)
    database: str
    table_name: str
    predicate_columns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class M0RawQueryResult:
    """One verified query/result pair retained only until Evidence wrapping."""

    query: ServerQuery
    result: QueryResult = field(repr=False)


@dataclass(frozen=True, slots=True)
class M0RawDiagnosis:
    """Request-local bounded collection awaiting the managed-Evidence wrapper."""

    validated_select: ValidatedM0Select = field(repr=False)
    predicate_columns: tuple[str, ...]
    window_start: datetime
    window_end: datetime
    results: tuple[M0RawQueryResult, ...] = field(repr=False)

    @property
    def database(self) -> str:
        return self.validated_select.database

    @property
    def sql_digest(self) -> str:
        return self.validated_select.sql_digest

    @property
    def table_name(self) -> str:
        return self.validated_select.table_name


class _M0DiagnosisQueryClient(Protocol):
    async def execute(
        self,
        *,
        execution_id: str,
        query: ServerQuery,
        parameters: Mapping[str, QueryValue],
    ) -> QueryResult: ...

    async def execute_ordinary_explain(
        self,
        *,
        execution_id: str,
        value: ValidatedM0Select,
    ) -> QueryResult: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _execution_id() -> str:
    return f"exec_{secrets.token_hex(8)}"


def parse_m0_select(sql_text: str, *, database: str) -> ParsedM0Select:
    """Parse one bounded single-table SELECT without exposing its text in diagnostics."""

    try:
        sql_bytes = sql_text.encode("utf-8")
    except (AttributeError, UnicodeEncodeError):
        raise M0DiagnosisValidationError from None
    if (
        not 1 <= len(sql_bytes) <= M0_MAX_SQL_BYTES
        or not _bounded_identifier(database)
        or any(
            unicodedata.category(character).startswith("C") and character not in "\t\n\r"
            for character in sql_text
        )
    ):
        raise M0DiagnosisValidationError

    statement = _parse_user_statement(sql_text)
    if not isinstance(statement, exp.Select):
        raise M0DiagnosisValidationError
    if any(isinstance(node, _UNSAFE_SELECT_EXPRESSIONS) for node in statement.walk()):
        raise M0DiagnosisValidationError
    if next(statement.find_all(exp.Join), None) is not None:
        raise M0DiagnosisValidationError
    if next(statement.find_all(exp.Subquery), None) is not None:
        raise M0DiagnosisValidationError
    with_expression = statement.args.get("with_")
    if isinstance(with_expression, exp.With) and bool(with_expression.args.get("recursive")):
        raise M0DiagnosisValidationError

    physical_tables: list[exp.Table] = []
    try:
        scopes = list(traverse_scope(statement))
    except (SqlglotError, ValueError, RecursionError):
        raise M0DiagnosisValidationError from None
    if not scopes:
        raise M0DiagnosisValidationError
    for scope in scopes:
        if len(scope.selected_sources) != 1:
            raise M0DiagnosisValidationError
        for _name, (_node, source) in scope.selected_sources.items():
            if isinstance(source, exp.Table):
                physical_tables.append(source)
            elif isinstance(source, Scope) and source.is_cte and not source.is_derived_table:
                continue
            else:
                raise M0DiagnosisValidationError
    if len(physical_tables) != 1:
        raise M0DiagnosisValidationError

    physical_table = physical_tables[0]
    table_name = physical_table.name
    table_database = physical_table.db
    if (
        not _bounded_identifier(table_name)
        or physical_table.catalog
        or (table_database and table_database != database)
    ):
        raise M0DiagnosisValidationError

    try:
        canonical_sql = statement.sql(dialect="mysql", pretty=False)
        canonical_bytes = canonical_sql.encode("utf-8")
    except (SqlglotError, ValueError, UnicodeError, RecursionError):
        raise M0DiagnosisValidationError from None
    if not 1 <= len(canonical_bytes) <= M0_MAX_SQL_BYTES:
        raise M0DiagnosisValidationError

    predicate_columns: list[str] = []
    seen_columns: set[str] = set()
    for where in statement.find_all(exp.Where):
        for column in _columns_in_expression_order(where):
            name = column.name
            if not _bounded_identifier(name):
                raise M0DiagnosisValidationError
            normalized_name = name.casefold()
            if normalized_name in seen_columns:
                continue
            seen_columns.add(normalized_name)
            predicate_columns.append(name)
            if len(predicate_columns) == M0_MAX_PREDICATE_COLUMNS:
                break
        if len(predicate_columns) == M0_MAX_PREDICATE_COLUMNS:
            break

    return ParsedM0Select(
        canonical_sql=canonical_sql,
        database=database,
        table_name=table_name,
        predicate_columns=tuple(predicate_columns),
    )


def _columns_in_expression_order(expression: exp.Expr) -> Iterator[exp.Column]:
    pending = [expression]
    while pending:
        current = pending.pop()
        if isinstance(current, exp.Column):
            yield current
        pending.extend(reversed(tuple(current.iter_expressions())))


def _parse_user_statement(sql_text: str) -> exp.Expr:
    try:
        dialect = Dialect.get_or_raise("mysql")
        tokens = dialect.tokenize(sql_text)
        statements = [
            statement
            for statement in dialect.parser(error_level=ErrorLevel.RAISE).parse(
                tokens,
                "?" * len(sql_text),
            )
            if statement is not None
        ]
    except (SqlglotError, ValueError, UnicodeError, RecursionError):
        raise M0DiagnosisValidationError from None
    if len(statements) != 1:
        raise M0DiagnosisValidationError
    return statements[0]


def _bounded_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 64
        and value == value.strip()
        and not any(unicodedata.category(character).startswith("C") for character in value)
    )


class M0ConnectionRequiredError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("A live TiDB connection is required.")


class M0DiagnosisService:
    """Request-local candidate discovery and diagnosis orchestration."""

    def __init__(
        self,
        *,
        store: M0ConnectionStore,
        clock: Clock = _utc_now,
        execution_id_factory: ExecutionIdFactory = _execution_id,
    ) -> None:
        self._store = store
        self._clock = clock
        self._execution_id_factory = execution_id_factory

    async def collect_diagnosis(self, value: M0DiagnosisInput) -> M0RawDiagnosis:
        """Verify one SQL identity and collect only its bounded server-owned roles."""

        if not isinstance(value, M0DiagnosisInput):
            raise M0DiagnosisValidationError
        view = await self._store.view()
        if view is None:
            raise M0ConnectionRequiredError
        parsed = parse_m0_select(value.sql_text, database=view.database)
        window_end = _aware_utc(self._clock())
        window_start = window_end - timedelta(minutes=value.window_minutes)
        parameters = {
            "window_start": _format_time(window_start),
            "window_end": _format_time(window_end),
            "schema_name": parsed.database,
            "sql_digest": value.sql_digest,
        }
        try:
            async with self._store.use() as raw_client:
                leased_view = await self._store.view()
                if leased_view is None or leased_view.database != parsed.database:
                    raise M0TidbUnavailableError
                client = cast(_M0DiagnosisQueryClient, raw_client)
                async with asyncio.timeout(M0_DIAGNOSIS_TIMEOUT_SECONDS):
                    rows_read = 0
                    bytes_read = 0
                    digest_query = query_pack("tidb-8.5")["sql_digest.encode"]
                    digest_result = await client.execute(
                        execution_id=self._execution_id_factory(),
                        query=digest_query,
                        parameters={"sql_text": value.sql_text},
                    )
                    rows_read, bytes_read = _consume_aggregate_budget(
                        digest_query,
                        digest_result,
                        rows_read=rows_read,
                        bytes_read=bytes_read,
                    )
                    _verify_server_digest(
                        digest_result,
                        query=digest_query,
                        requested_digest=value.sql_digest,
                    )
                    validated = ValidatedM0Select(
                        canonical_sql=parsed.canonical_sql,
                        sql_digest=value.sql_digest,
                        database=parsed.database,
                        table_name=parsed.table_name,
                    )
                    collected: list[M0RawQueryResult] = []
                    for query_id in (
                        "slow_query.current_user",
                        "statement_summary.cross_user",
                    ):
                        query = query_pack("tidb-8.5")[query_id]
                        result = await client.execute(
                            execution_id=self._execution_id_factory(),
                            query=query,
                            parameters=parameters,
                        )
                        rows_read, bytes_read = _consume_aggregate_budget(
                            query,
                            result,
                            rows_read=rows_read,
                            bytes_read=bytes_read,
                        )
                        collected.append(M0RawQueryResult(query=query, result=result))

                    if parsed.predicate_columns:
                        ordinary_query = bind_m0_ordinary_explain(validated)
                        ordinary_result = await client.execute_ordinary_explain(
                            execution_id=self._execution_id_factory(),
                            value=validated,
                        )
                        rows_read, bytes_read = _consume_aggregate_budget(
                            ordinary_query,
                            ordinary_result,
                            rows_read=rows_read,
                            bytes_read=bytes_read,
                        )
                        collected.append(
                            M0RawQueryResult(query=ordinary_query, result=ordinary_result)
                        )

                        index_query = query_pack("tidb-8.5")["index.current_table"]
                        index_result = await client.execute(
                            execution_id=self._execution_id_factory(),
                            query=index_query,
                            parameters={
                                "schema_name": parsed.database,
                                "table_name": parsed.table_name,
                            },
                        )
                        rows_read, bytes_read = _consume_aggregate_budget(
                            index_query,
                            index_result,
                            rows_read=rows_read,
                            bytes_read=bytes_read,
                        )
                        collected.append(M0RawQueryResult(query=index_query, result=index_result))

                    statistics_query = query_pack("tidb-8.5")["statistics.health.current_table"]
                    statistics_result = await client.execute(
                        execution_id=self._execution_id_factory(),
                        query=statistics_query,
                        parameters={
                            "schema_name": parsed.database,
                            "table_name": parsed.table_name,
                        },
                    )
                    _consume_aggregate_budget(
                        statistics_query,
                        statistics_result,
                        rows_read=rows_read,
                        bytes_read=bytes_read,
                    )
                    collected.append(
                        M0RawQueryResult(query=statistics_query, result=statistics_result)
                    )
        except (M0BusyError, M0ConnectionRequiredError, M0DiagnosisValidationError):
            raise
        except asyncio.CancelledError:
            await asyncio.shield(self._store.force_close())
            raise
        except (TimeoutError, M0TidbTimeoutError):
            await self._store.force_close()
            raise M0TidbTimeoutError from None
        except (M0DriverInvariantError, M0TidbUnavailableError):
            await self._store.force_close()
            raise M0TidbUnavailableError from None

        return M0RawDiagnosis(
            validated_select=validated,
            predicate_columns=parsed.predicate_columns,
            window_start=window_start,
            window_end=window_end,
            results=tuple(collected),
        )

    async def list_candidates(self, window_minutes: int) -> dict[str, JsonValue]:
        if (
            isinstance(window_minutes, bool)
            or not isinstance(window_minutes, int)
            or not M0_MIN_WINDOW_MINUTES <= window_minutes <= M0_MAX_WINDOW_MINUTES
        ):
            raise ValueError("candidate window is invalid")
        collected_at = _aware_utc(self._clock())
        window_start = collected_at - timedelta(minutes=window_minutes)
        query = query_pack("tidb-8.5")["sql_candidates.current_user"]
        parameters = {
            "window_start": _format_time(window_start),
            "window_end": _format_time(collected_at),
            "schema_name": "",
        }
        try:
            view = await self._store.view()
            if view is None:
                raise M0ConnectionRequiredError
            async with self._store.use() as client:
                leased_view = await self._store.view()
                if leased_view is None:
                    raise M0TidbUnavailableError
                parameters["schema_name"] = leased_view.database
                result = await client.execute(
                    execution_id=self._execution_id_factory(),
                    query=query,
                    parameters=parameters,
                )
            items = _project_candidates(
                result,
                query=query,
                window_start=window_start,
                window_end=collected_at,
            )
        except M0BusyError:
            raise
        except M0ConnectionRequiredError:
            raise
        except asyncio.CancelledError:
            await asyncio.shield(self._store.force_close())
            raise
        except M0TidbTimeoutError:
            await self._store.force_close()
            raise
        except (M0DriverInvariantError, M0TidbUnavailableError):
            await self._store.force_close()
            raise M0TidbUnavailableError from None
        return {
            "schema_version": "m0-sql-candidates/v1",
            "window_minutes": window_minutes,
            "collected_at": _format_time(collected_at),
            "truncated": (
                result.truncated
                or len(result.rows) == query.budget.max_rows
                or result.observed_bytes == query.budget.max_bytes
            ),
            "items": items,
        }


def _project_candidates(
    result: QueryResult,
    *,
    query: object,
    window_start: datetime,
    window_end: datetime,
) -> list[JsonValue]:
    registered = query_pack("tidb-8.5")["sql_candidates.current_user"]
    if query != registered:
        raise M0DriverInvariantError
    if (
        result.columns != registered.result_columns
        or not isinstance(result.truncated, bool)
        or not _bounded_integer(result.elapsed_ms, lower=0, upper=registered.budget.timeout_ms)
        or not _bounded_integer(
            result.observed_bytes,
            lower=1,
            upper=registered.budget.max_bytes,
        )
        or len(result.rows) > registered.budget.max_rows
    ):
        raise M0TidbUnavailableError

    items: list[JsonValue] = []
    seen_digests: set[str] = set()
    expected_columns = set(registered.result_columns)
    for row in result.rows:
        if not isinstance(row, Mapping) or set(row) != expected_columns:
            raise M0TidbUnavailableError
        digest = row["sql_digest"]
        if not isinstance(digest, str) or not _SQL_DIGEST.fullmatch(digest):
            raise M0TidbUnavailableError
        if digest in seen_digests:
            raise M0TidbUnavailableError
        seen_digests.add(digest)
        execution_count = _required_integer(row["execution_count"], lower=1)
        p95_ms = _required_integer(row["p95_ms"], lower=0)
        average_scan_rows = _required_integer(row["average_scan_rows"], lower=0)
        average_return_rows = _required_integer(row["average_return_rows"], lower=0)
        last_seen_ms = _required_integer(row["last_seen"], lower=0)
        try:
            last_seen = datetime.fromtimestamp(last_seen_ms / 1_000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            raise M0TidbUnavailableError from None
        if not window_start <= last_seen <= window_end:
            raise M0TidbUnavailableError
        items.append(
            {
                "sql_digest": digest,
                "execution_count": execution_count,
                "p95_ms": p95_ms,
                "average_scan_rows": average_scan_rows,
                "average_return_rows": average_return_rows,
                "last_seen": _format_time(last_seen),
            }
        )
    return items


def _verify_server_digest(
    result: QueryResult,
    *,
    query: ServerQuery,
    requested_digest: str,
) -> None:
    if (
        query != query_pack("tidb-8.5")["sql_digest.encode"]
        or result.columns != query.result_columns
        or result.truncated is not False
        or len(result.rows) != 1
    ):
        raise M0TidbUnavailableError
    row = result.rows[0]
    if not isinstance(row, Mapping) or set(row) != {"sql_digest"}:
        raise M0TidbUnavailableError
    server_digest = row["sql_digest"]
    if not isinstance(server_digest, str) or not _SQL_DIGEST.fullmatch(server_digest):
        raise M0TidbUnavailableError
    if server_digest != requested_digest:
        raise M0DiagnosisValidationError


def _consume_aggregate_budget(
    query: ServerQuery,
    result: QueryResult,
    *,
    rows_read: int,
    bytes_read: int,
) -> tuple[int, int]:
    if (
        not isinstance(result, QueryResult)
        or result.columns != query.result_columns
        or not isinstance(result.truncated, bool)
        or not _bounded_integer(
            result.elapsed_ms,
            lower=0,
            upper=query.budget.timeout_ms,
        )
        or not _bounded_integer(
            result.observed_bytes,
            lower=1,
            upper=query.budget.max_bytes,
        )
        or len(result.rows) > query.budget.max_rows
    ):
        raise M0TidbUnavailableError
    expected_columns = set(query.result_columns)
    for row in result.rows:
        if not isinstance(row, Mapping) or set(row) != expected_columns:
            raise M0TidbUnavailableError
        for item in row.values():
            if item is None or type(item) in (str, bool):
                continue
            if type(item) is int and abs(item) <= MAX_SAFE_INTEGER:
                continue
            if type(item) is float and math.isfinite(item):
                continue
            raise M0TidbUnavailableError

    aggregate_rows = rows_read + len(result.rows)
    aggregate_bytes = bytes_read + result.observed_bytes
    if aggregate_rows > M0_DIAGNOSIS_MAX_ROWS or aggregate_bytes > M0_DIAGNOSIS_MAX_BYTES:
        raise M0TidbUnavailableError
    return aggregate_rows, aggregate_bytes


def _required_integer(value: object, *, lower: int) -> int:
    if not _bounded_integer(value, lower=lower, upper=MAX_SAFE_INTEGER):
        raise M0TidbUnavailableError
    return cast(int, value)


def _bounded_integer(value: object, *, lower: int, upper: int) -> bool:
    return type(value) is int and lower <= value <= upper


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise M0DriverInvariantError
    return value.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
