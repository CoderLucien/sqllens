from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqllens_api.app import create_app
from sqllens_api.config import Settings
from sqllens_api.evidence_connector import (
    QueryResult,
    QueryValue,
    ServerQuery,
    ValidatedM0Select,
    bind_m0_ordinary_explain,
    query_pack,
)
from sqllens_api.m0_connection import (
    M0BusyError,
    M0ConnectionView,
    M0DriverInvariantError,
    M0TidbTimeoutError,
    M0TidbUnavailableError,
)
from sqllens_api.m0_diagnosis import (
    M0DiagnosisInput,
    M0DiagnosisService,
    M0DiagnosisValidationError,
    M0RawDiagnosis,
    parse_m0_select,
)


class CandidateClient:
    def __init__(self, result: QueryResult) -> None:
        self.result = result
        self.error: BaseException | None = None
        self.calls: list[tuple[str, ServerQuery, Mapping[str, QueryValue]]] = []

    async def execute(
        self,
        *,
        execution_id: str,
        query: ServerQuery,
        parameters: Mapping[str, QueryValue],
    ) -> QueryResult:
        self.calls.append((execution_id, query, parameters))
        if self.error is not None:
            raise self.error
        return self.result

    async def cancel(self, _execution_id: str) -> None:
        return None


class CandidateStore:
    def __init__(self, client: CandidateClient) -> None:
        self.client = client
        self.connected = True
        self.busy = False
        self.force_close_calls = 0
        self.use_entries = 0

    @asynccontextmanager
    async def use(self) -> AsyncIterator[CandidateClient]:
        if self.busy:
            raise M0BusyError
        self.use_entries += 1
        yield self.client

    async def force_close(self) -> None:
        self.force_close_calls += 1

    async def view(self) -> M0ConnectionView | None:
        if not self.connected:
            return None
        return M0ConnectionView(
            connection_id="conn_0123456789abcdef",
            state="ready",
            product="tidb",
            version="8.5.4",
            database="shop",
            tls_mode="verify_ca",
            connected_at=FIXED_NOW,
        )

    async def disconnect(self) -> None:
        return None


class DiagnosisClient:
    def __init__(self, *, sql_digest: str = "a" * 64) -> None:
        self.sql_digest = sql_digest
        self.calls: list[tuple[str, ServerQuery, Mapping[str, QueryValue]]] = []
        self.ordinary_calls: list[tuple[str, ValidatedM0Select]] = []
        self.events: list[str] = []
        self.results: dict[str, QueryResult] = {}

    async def execute(
        self,
        *,
        execution_id: str,
        query: ServerQuery,
        parameters: Mapping[str, QueryValue],
    ) -> QueryResult:
        self.calls.append((execution_id, query, parameters))
        self.events.append(query.query_id)
        if query.query_id == "sql_digest.encode":
            return bounded_result(query, rows=({"sql_digest": self.sql_digest},))
        return self.results.get(query.query_id, bounded_result(query))

    async def execute_ordinary_explain(
        self,
        *,
        execution_id: str,
        value: ValidatedM0Select,
    ) -> QueryResult:
        self.ordinary_calls.append((execution_id, value))
        bound = bind_m0_ordinary_explain(value)
        self.events.append(bound.query_id)
        return self.results.get(bound.query_id, bounded_result(bound))

    async def cancel(self, _execution_id: str) -> None:
        return None


FIXED_NOW = datetime(2026, 9, 3, 6, 30, tzinfo=UTC)
LOCAL_ORIGIN = "http://localhost:18080"
VALID_SQL_DIGEST = "a" * 64


def bounded_result(
    query: ServerQuery,
    *,
    rows: tuple[Mapping[str, QueryValue], ...] = (),
    truncated: bool = False,
    observed_bytes: int = 128,
) -> QueryResult:
    return QueryResult(
        columns=query.result_columns,
        rows=rows,
        truncated=truncated,
        observed_bytes=observed_bytes,
        elapsed_ms=20,
    )


def test_diagnosis_input_is_closed_strict_and_excludes_sql_from_repr() -> None:
    sql_text = "SELECT id FROM orders WHERE customer_id = 42"

    value = M0DiagnosisInput.model_validate(
        {
            "sql_digest": VALID_SQL_DIGEST,
            "sql_text": sql_text,
            "window_minutes": 30,
        }
    )

    assert value.sql_text == sql_text
    assert sql_text not in repr(value)


@pytest.mark.parametrize(
    "payload",
    [
        {"sql_digest": "A" * 64, "sql_text": "SELECT id FROM orders", "window_minutes": 30},
        {"sql_digest": "a" * 63, "sql_text": "SELECT id FROM orders", "window_minutes": 30},
        {"sql_digest": VALID_SQL_DIGEST, "sql_text": "", "window_minutes": 30},
        {
            "sql_digest": VALID_SQL_DIGEST,
            "sql_text": "\u00e9" * 16_385,
            "window_minutes": 30,
        },
        {"sql_digest": VALID_SQL_DIGEST, "sql_text": "SELECT id FROM orders", "window_minutes": 4},
        {"sql_digest": VALID_SQL_DIGEST, "sql_text": "SELECT id FROM orders", "window_minutes": 61},
        {
            "sql_digest": VALID_SQL_DIGEST,
            "sql_text": "SELECT id FROM orders",
            "window_minutes": True,
        },
        {
            "sql_digest": VALID_SQL_DIGEST,
            "sql_text": "SELECT id FROM orders",
            "window_minutes": 30.0,
        },
        {
            "sql_digest": VALID_SQL_DIGEST,
            "sql_text": "SELECT id FROM orders",
            "window_minutes": 30,
            "extra": "not allowed",
        },
    ],
)
def test_diagnosis_input_rejects_open_or_noncanonical_values(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        M0DiagnosisInput.model_validate(payload)


def test_parse_m0_select_returns_only_bounded_structure_and_hides_sql_from_repr() -> None:
    sql_text = "SELECT id FROM orders WHERE customer_id = 42 AND state = 'paid'"

    parsed = parse_m0_select(sql_text, database="shop")

    assert parsed.canonical_sql == sql_text
    assert parsed.database == "shop"
    assert parsed.table_name == "orders"
    assert parsed.predicate_columns == ("customer_id", "state")
    assert "customer_id = 42" not in repr(parsed)
    assert "paid" not in repr(parsed)


def test_parse_m0_select_accepts_one_nonrecursive_cte_over_one_base_table() -> None:
    parsed = parse_m0_select(
        "WITH recent AS (SELECT id, customer_id FROM shop.orders WHERE state = 'paid') "
        "SELECT id FROM recent WHERE customer_id = 42",
        database="shop",
    )

    assert parsed.table_name == "orders"
    assert parsed.predicate_columns == ("customer_id", "state")


def test_parse_m0_select_accepts_normal_multiline_sql_whitespace() -> None:
    parsed = parse_m0_select(
        "SELECT id\nFROM orders\nWHERE customer_id = 42\tAND state = 'paid'",
        database="shop",
    )

    assert parsed.table_name == "orders"
    assert parsed.predicate_columns == ("customer_id", "state")


def test_parse_m0_select_bounds_and_deduplicates_the_filter_column_prefix() -> None:
    predicates = " OR ".join(f"column_{index} = {index}" for index in range(40))

    parsed = parse_m0_select(f"SELECT id FROM orders WHERE {predicates}", database="shop")

    assert parsed.predicate_columns == tuple(f"column_{index}" for index in range(32))


def test_parse_m0_select_handles_deep_predicates_without_recursing() -> None:
    predicates = " OR ".join(f"column_{index} = 1" for index in range(1_200))

    parsed = parse_m0_select(f"SELECT id FROM orders WHERE {predicates}", database="shop")

    assert parsed.predicate_columns == tuple(f"column_{index}" for index in range(32))


@pytest.mark.parametrize(
    "sql_text",
    [
        "UPDATE orders SET state = 'paid' WHERE id = 1",
        "EXPLAIN SELECT id FROM orders",
        "SELECT o.id FROM orders AS o JOIN customers AS c ON c.id = o.customer_id",
        "SELECT orders.id FROM orders, customers",
        "SELECT id FROM (SELECT id FROM orders) AS derived_orders",
        "SELECT (SELECT MAX(id) FROM customers) FROM orders",
        "SELECT id FROM orders FOR UPDATE",
        "SELECT id INTO OUTFILE '/tmp/m0-out' FROM orders",
        "SELECT id FROM orders; SELECT id FROM customers",
        "WITH RECURSIVE descendants AS (SELECT id FROM orders) SELECT id FROM descendants",
        "SELECT 1",
        "SELECT id FROM other.orders",
    ],
)
def test_parse_m0_select_rejects_every_non_single_table_read_only_shape(sql_text: str) -> None:
    with pytest.raises(M0DiagnosisValidationError):
        parse_m0_select(sql_text, database="shop")


def test_parse_m0_select_never_logs_or_raises_with_raw_sql(
    caplog: pytest.LogCaptureFixture,
) -> None:
    marker = "m0_confidential_marker_4f67"
    sql_text = f"SELECT id FROM orders WHERE state = '{marker}' AND"

    with pytest.raises(M0DiagnosisValidationError) as caught:
        parse_m0_select(sql_text, database="shop")

    assert marker not in str(caught.value)
    assert marker not in caplog.text


def diagnosis_input(
    *, sql_text: str = "SELECT id FROM orders WHERE customer_id = 42"
) -> M0DiagnosisInput:
    return M0DiagnosisInput(
        sql_digest=VALID_SQL_DIGEST,
        sql_text=sql_text,
        window_minutes=30,
    )


@pytest.mark.asyncio
async def test_collect_diagnosis_verifies_digest_then_collects_one_bounded_sequence() -> None:
    diagnosis_client = DiagnosisClient()
    store = CandidateStore(cast(Any, diagnosis_client))
    execution_ids = iter(f"exec_{index:016x}" for index in range(6))
    service = M0DiagnosisService(
        store=cast(Any, store),
        clock=lambda: FIXED_NOW,
        execution_id_factory=lambda: next(execution_ids),
    )

    collected = await service.collect_diagnosis(diagnosis_input())

    assert isinstance(collected, M0RawDiagnosis)
    assert collected.database == "shop"
    assert collected.sql_digest == VALID_SQL_DIGEST
    assert collected.table_name == "orders"
    assert collected.predicate_columns == ("customer_id",)
    assert collected.window_start == datetime(2026, 9, 3, 6, 0, tzinfo=UTC)
    assert collected.window_end == FIXED_NOW
    assert [item.query.query_id for item in collected.results] == [
        "slow_query.current_user",
        "statement_summary.cross_user",
        "ordinary_plan.validated_select",
        "index.current_table",
        "statistics.health.current_table",
    ]
    assert diagnosis_client.events == [
        "sql_digest.encode",
        "slow_query.current_user",
        "statement_summary.cross_user",
        "ordinary_plan.validated_select",
        "index.current_table",
        "statistics.health.current_table",
    ]
    assert store.use_entries == 1
    assert store.force_close_calls == 0
    digest_call = diagnosis_client.calls[0]
    assert digest_call[2] == {"sql_text": diagnosis_input().sql_text}
    assert all(
        call[1].query_id != "ordinary_plan.validated_select" for call in diagnosis_client.calls
    )
    assert len(diagnosis_client.ordinary_calls) == 1
    calls_by_id = {call[1].query_id: call[2] for call in diagnosis_client.calls}
    assert calls_by_id["slow_query.current_user"] == {
        "window_start": "2026-09-03T06:00:00Z",
        "window_end": "2026-09-03T06:30:00Z",
        "schema_name": "shop",
        "sql_digest": VALID_SQL_DIGEST,
    }
    assert calls_by_id["statement_summary.cross_user"] == calls_by_id["slow_query.current_user"]
    assert calls_by_id["index.current_table"] == {
        "schema_name": "shop",
        "table_name": "orders",
    }
    assert calls_by_id["statistics.health.current_table"] == {
        "schema_name": "shop",
        "table_name": "orders",
    }
    ordinary = diagnosis_client.ordinary_calls[0][1]
    assert ordinary.sql_digest == VALID_SQL_DIGEST
    assert ordinary.database == "shop"
    assert ordinary.table_name == "orders"
    assert ordinary.canonical_sql == diagnosis_input().sql_text
    assert diagnosis_input().sql_text not in repr(collected)


@pytest.mark.asyncio
async def test_collect_diagnosis_skips_index_roles_when_sql_has_no_predicates() -> None:
    diagnosis_client = DiagnosisClient()
    store = CandidateStore(cast(Any, diagnosis_client))
    service = M0DiagnosisService(store=cast(Any, store), clock=lambda: FIXED_NOW)

    collected = await service.collect_diagnosis(diagnosis_input(sql_text="SELECT id FROM orders"))

    assert [item.query.query_id for item in collected.results] == [
        "slow_query.current_user",
        "statement_summary.cross_user",
        "statistics.health.current_table",
    ]
    assert diagnosis_client.events == [
        "sql_digest.encode",
        "slow_query.current_user",
        "statement_summary.cross_user",
        "statistics.health.current_table",
    ]


@pytest.mark.asyncio
async def test_collect_diagnosis_rejects_digest_mismatch_without_closing_healthy_socket() -> None:
    diagnosis_client = DiagnosisClient(sql_digest="b" * 64)
    store = CandidateStore(cast(Any, diagnosis_client))
    service = M0DiagnosisService(store=cast(Any, store), clock=lambda: FIXED_NOW)

    with pytest.raises(M0DiagnosisValidationError):
        await service.collect_diagnosis(diagnosis_input())

    assert diagnosis_client.events == ["sql_digest.encode"]
    assert store.use_entries == 1
    assert store.force_close_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "digest_result",
    [
        bounded_result(
            query_pack("tidb-8.5")["sql_digest.encode"],
            rows=(),
        ),
        bounded_result(
            query_pack("tidb-8.5")["sql_digest.encode"],
            rows=({"sql_digest": "A" * 64},),
        ),
        QueryResult(
            columns=("raw_sql",),
            rows=({"raw_sql": VALID_SQL_DIGEST},),
            truncated=False,
            observed_bytes=128,
            elapsed_ms=20,
        ),
    ],
)
async def test_collect_diagnosis_invalid_digest_result_fails_closed(
    digest_result: QueryResult,
) -> None:
    class InvalidDigestClient(DiagnosisClient):
        async def execute(
            self,
            *,
            execution_id: str,
            query: ServerQuery,
            parameters: Mapping[str, QueryValue],
        ) -> QueryResult:
            self.calls.append((execution_id, query, parameters))
            self.events.append(query.query_id)
            return digest_result

    diagnosis_client = InvalidDigestClient()
    store = CandidateStore(cast(Any, diagnosis_client))
    service = M0DiagnosisService(store=cast(Any, store), clock=lambda: FIXED_NOW)

    with pytest.raises(M0TidbUnavailableError):
        await service.collect_diagnosis(diagnosis_input())

    assert diagnosis_client.events == ["sql_digest.encode"]
    assert store.force_close_calls == 1


@pytest.mark.asyncio
async def test_collect_diagnosis_rejects_local_sql_before_connection_io() -> None:
    diagnosis_client = DiagnosisClient()
    store = CandidateStore(cast(Any, diagnosis_client))
    service = M0DiagnosisService(store=cast(Any, store), clock=lambda: FIXED_NOW)

    with pytest.raises(M0DiagnosisValidationError):
        await service.collect_diagnosis(
            diagnosis_input(sql_text="DELETE FROM orders WHERE customer_id = 42")
        )

    assert diagnosis_client.events == []
    assert store.use_entries == 0
    assert store.force_close_calls == 0


@pytest.mark.asyncio
async def test_collect_diagnosis_enforces_the_two_mebibyte_aggregate_cap() -> None:
    diagnosis_client = DiagnosisClient()
    for query_id in (
        "slow_query.current_user",
        "statement_summary.cross_user",
        "index.current_table",
    ):
        query = query_pack("tidb-8.5")[query_id]
        diagnosis_client.results[query_id] = bounded_result(
            query,
            observed_bytes=query.budget.max_bytes,
        )
    ordinary_value = parse_m0_select(diagnosis_input().sql_text, database="shop")
    ordinary_query = bind_m0_ordinary_explain(
        ValidatedM0Select(
            canonical_sql=ordinary_value.canonical_sql,
            sql_digest=VALID_SQL_DIGEST,
            database="shop",
            table_name="orders",
        )
    )
    diagnosis_client.results[ordinary_query.query_id] = bounded_result(
        ordinary_query,
        observed_bytes=ordinary_query.budget.max_bytes,
    )
    store = CandidateStore(cast(Any, diagnosis_client))
    service = M0DiagnosisService(store=cast(Any, store), clock=lambda: FIXED_NOW)

    with pytest.raises(M0TidbUnavailableError):
        await service.collect_diagnosis(diagnosis_input())

    assert diagnosis_client.events == [
        "sql_digest.encode",
        "slow_query.current_user",
        "statement_summary.cross_user",
        "ordinary_plan.validated_select",
        "index.current_table",
    ]
    assert store.force_close_calls == 1


def candidate_result(
    *,
    rows: tuple[Mapping[str, QueryValue], ...] | None = None,
    columns: tuple[str, ...] | None = None,
    truncated: bool = False,
    observed_bytes: int = 512,
) -> QueryResult:
    query = query_pack("tidb-8.5")["sql_candidates.current_user"]
    default_row: Mapping[str, QueryValue] = {
        "sql_digest": "a" * 64,
        "execution_count": 18,
        "p95_ms": 1_400,
        "average_scan_rows": 120_000,
        "average_return_rows": 8,
        "last_seen": int(datetime(2026, 9, 3, 6, 29, tzinfo=UTC).timestamp() * 1_000),
    }
    return QueryResult(
        columns=columns or query.result_columns,
        rows=rows if rows is not None else (default_row,),
        truncated=truncated,
        observed_bytes=observed_bytes,
        elapsed_ms=20,
    )


def authenticated_candidate_client(
    tmp_path: Path,
    store: CandidateStore,
) -> tuple[TestClient, str]:
    settings = Settings(data_dir=tmp_path / "data", web_dist_dir=None)
    service = M0DiagnosisService(
        store=cast(Any, store),
        clock=lambda: FIXED_NOW,
        execution_id_factory=lambda: "exec_0123456789abcdef",
    )
    client = TestClient(
        create_app(
            settings=settings,
            clock=lambda: FIXED_NOW,
            m0_connection_store=cast(Any, store),
            m0_diagnosis_service=service,
        ),
        base_url=LOCAL_ORIGIN,
    )
    status = client.get("/api/v1/setup/status")
    owner = client.post(
        "/api/v1/setup/owner",
        headers={"Origin": LOCAL_ORIGIN, "X-Setup-Nonce": status.json()["setup_nonce"]},
        json={"password": "correct-horse-battery-staple"},
    )
    assert owner.status_code == 201
    return client, str(owner.json()["csrf_token"])


def test_candidate_route_returns_only_the_closed_safe_projection(tmp_path: Path) -> None:
    query = query_pack("tidb-8.5")["sql_candidates.current_user"]
    candidate_client = CandidateClient(candidate_result())
    store = CandidateStore(candidate_client)
    client, _csrf = authenticated_candidate_client(tmp_path, store)

    response = client.get("/api/v1/m0/sql-candidates")

    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "m0-sql-candidates/v1",
        "window_minutes": 30,
        "collected_at": "2026-09-03T06:30:00Z",
        "truncated": False,
        "items": [
            {
                "sql_digest": "a" * 64,
                "execution_count": 18,
                "p95_ms": 1_400,
                "average_scan_rows": 120_000,
                "average_return_rows": 8,
                "last_seen": "2026-09-03T06:29:00Z",
            }
        ],
    }
    assert response.headers["cache-control"] == "no-store"
    assert len(candidate_client.calls) == 1
    execution_id, called_query, parameters = candidate_client.calls[0]
    assert execution_id == "exec_0123456789abcdef"
    assert called_query == query
    assert parameters == {
        "window_start": "2026-09-03T06:00:00Z",
        "window_end": "2026-09-03T06:30:00Z",
        "schema_name": "shop",
    }
    serialized = response.text.lower()
    assert "select " not in serialized
    assert "username" not in serialized
    assert "host" not in serialized
    assert "plan" not in serialized


@pytest.mark.parametrize("window_minutes", [5, 60])
def test_candidate_route_accepts_only_the_frozen_window_boundaries(
    tmp_path: Path,
    window_minutes: int,
) -> None:
    candidate_client = CandidateClient(candidate_result(rows=()))
    store = CandidateStore(candidate_client)
    client, _csrf = authenticated_candidate_client(tmp_path, store)

    response = client.get(
        "/api/v1/m0/sql-candidates",
        params={"window_minutes": str(window_minutes)},
    )

    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["window_minutes"] == window_minutes


@pytest.mark.parametrize(
    "query_string",
    [
        "window_minutes=4",
        "window_minutes=61",
        "window_minutes=5.0",
        "window_minutes=5&window_minutes=6",
        "window_minutes=30&extra=1",
    ],
)
def test_candidate_route_rejects_non_integer_out_of_range_or_open_query_shape(
    tmp_path: Path,
    query_string: str,
) -> None:
    candidate_client = CandidateClient(candidate_result())
    store = CandidateStore(candidate_client)
    client, _csrf = authenticated_candidate_client(tmp_path, store)

    response = client.get(f"/api/v1/m0/sql-candidates?{query_string}")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert candidate_client.calls == []


def test_candidate_route_requires_owner_authentication(tmp_path: Path) -> None:
    candidate_client = CandidateClient(candidate_result())
    store = CandidateStore(candidate_client)
    service = M0DiagnosisService(
        store=cast(Any, store),
        clock=lambda: FIXED_NOW,
    )
    anonymous = TestClient(
        create_app(
            settings=Settings(data_dir=tmp_path / "data", web_dist_dir=None),
            m0_connection_store=cast(Any, store),
            m0_diagnosis_service=service,
        ),
        base_url=LOCAL_ORIGIN,
    )

    assert anonymous.get("/api/v1/m0/sql-candidates").status_code == 401
    assert candidate_client.calls == []


def test_candidate_route_requires_a_live_connection_without_invalidating_state(
    tmp_path: Path,
) -> None:
    candidate_client = CandidateClient(candidate_result())
    store = CandidateStore(candidate_client)
    store.connected = False
    client, _csrf = authenticated_candidate_client(tmp_path, store)

    response = client.get("/api/v1/m0/sql-candidates")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "M0_CONNECTION_REQUIRED"
    assert candidate_client.calls == []
    assert store.force_close_calls == 0


@pytest.mark.parametrize(
    "result",
    [
        candidate_result(columns=("raw_sql",)),
        candidate_result(
            rows=(
                {
                    **candidate_result().rows[0],
                    "sql_digest": "A" * 64,
                },
            )
        ),
        candidate_result(
            rows=(
                {
                    **candidate_result().rows[0],
                    "execution_count": True,
                },
            )
        ),
        candidate_result(
            rows=(
                {
                    **candidate_result().rows[0],
                    "p95_ms": 59.0,
                },
            )
        ),
        candidate_result(observed_bytes=262_145),
    ],
)
def test_candidate_route_rejects_untrusted_or_over_budget_results(
    tmp_path: Path,
    result: QueryResult,
) -> None:
    candidate_client = CandidateClient(result)
    store = CandidateStore(candidate_client)
    client, _csrf = authenticated_candidate_client(tmp_path, store)

    response = client.get("/api/v1/m0/sql-candidates")

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "M0_TIDB_UNAVAILABLE"
    assert store.force_close_calls == 1


@pytest.mark.parametrize(
    ("error", "status", "code", "force_closed"),
    [
        (M0BusyError(), 409, "M0_BUSY", False),
        (M0TidbTimeoutError(), 504, "M0_TIDB_TIMEOUT", True),
        (M0TidbUnavailableError(), 502, "M0_TIDB_UNAVAILABLE", True),
        (M0DriverInvariantError(), 502, "M0_TIDB_UNAVAILABLE", True),
    ],
)
def test_candidate_route_maps_closed_errors_and_invalidates_broken_connection(
    tmp_path: Path,
    error: BaseException,
    status: int,
    code: str,
    force_closed: bool,
) -> None:
    candidate_client = CandidateClient(candidate_result())
    store = CandidateStore(candidate_client)
    if isinstance(error, M0BusyError):
        store.busy = True
    else:
        candidate_client.error = error
    client, _csrf = authenticated_candidate_client(tmp_path, store)

    response = client.get("/api/v1/m0/sql-candidates")

    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert store.force_close_calls == int(force_closed)
