from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from sqllens_api.evidence_connector import (
    QueryBudget,
    QueryCardinality,
    QueryPriorityPolicy,
    QueryResult,
    QueryRuPolicy,
    ServerQuery,
    UnsafeServerQueryError,
    capability_matrix,
    query_pack,
    validate_server_query,
)

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "evidence_connector"
PACK_FIXTURES = {
    "tidb-8.5": "tidb-8.5.4.json",
    "pingkaidb-7.1": "pingkaidb-7.1.8.json",
}


def server_query(
    sql: str,
    *,
    parameters: tuple[str, ...] = (),
    cardinality: QueryCardinality = QueryCardinality.SINGLE_ROW,
    max_rows: int = 1,
) -> ServerQuery:
    return ServerQuery(
        pack_id="tidb-8.5",
        pack_revision="tidb-8.5/queries-v2",
        query_id="test.query",
        query_revision="tidb-8.5/test.query-v1",
        sql=sql,
        parameters=parameters,
        result_columns=("value",),
        required_capability=None,
        cardinality=cardinality,
        budget=QueryBudget(
            timeout_ms=1_000,
            max_rows=max_rows,
            max_bytes=4_096,
            concurrency_cost=1,
            ru_policy=QueryRuPolicy.NOT_REQUESTED,
            priority_policy=QueryPriorityPolicy.DATABASE_DEFAULT,
        ),
    )


def test_query_result_records_elapsed_budget_usage() -> None:
    result = QueryResult(
        columns=("value",),
        rows=({"value": 1},),
        truncated=False,
        observed_bytes=8,
        elapsed_ms=4,
    )

    assert result.elapsed_ms == 4


@pytest.mark.parametrize("pack_id", ["tidb-8.5", "pingkaidb-7.1"])
def test_slow_query_registry_collects_result_rows(pack_id: str) -> None:
    queries = query_pack(pack_id)

    assert queries["slow_query.current_user"].pack_revision == (
        f"{pack_id}/queries-v2"
    )
    assert queries["slow_query.current_user"].query_revision == (
        f"{pack_id}/slow_query.current_user-v2"
    )
    assert "result_rows" in queries["slow_query.current_user"].result_columns
    assert queries["slow_query.cross_user"].query_revision == (
        f"{pack_id}/slow_query.cross_user-v2"
    )
    assert "result_rows" in queries["slow_query.cross_user"].result_columns


@pytest.mark.parametrize("pack_id", ["tidb-8.5", "pingkaidb-7.1"])
def test_every_builtin_query_is_versioned_validated_and_budgeted(pack_id: str) -> None:
    queries = query_pack(pack_id)
    capabilities = capability_matrix(pack_id)

    assert queries
    assert "server.identity" in queries
    assert "slow_query.current_user" in queries
    assert "statement_summary.cross_user" in queries
    assert "slow_query.cross_user" in queries
    for query in queries.values():
        validate_server_query(query)
        assert query.pack_id == pack_id
        assert query.pack_revision.startswith(f"{pack_id}/")
        assert query.query_revision.startswith(f"{pack_id}/{query.query_id}-")
        assert query.budget.timeout_ms > 0
        assert query.budget.max_rows > 0
        assert query.budget.max_bytes > 0
        assert query.budget.concurrency_cost == 1
        assert query.budget.kill_switch_required is True
        assert query.budget.ru_policy is QueryRuPolicy.NOT_REQUESTED
        assert query.budget.priority_policy is QueryPriorityPolicy.DATABASE_DEFAULT
        assert query.required_capability is None or query.required_capability in capabilities


@pytest.mark.parametrize("pack_id", ["tidb-8.5", "pingkaidb-7.1"])
def test_process_denial_uses_only_explicit_current_user_slow_query(pack_id: str) -> None:
    queries = query_pack(pack_id)

    assert "statement_summary.current_user" not in queries
    current_user_query = queries["slow_query.current_user"]
    assert current_user_query.required_capability is None
    assert "FROM information_schema.slow_query" in current_user_query.sql
    assert "user = SUBSTRING_INDEX(CURRENT_USER(), '@', 1)" in current_user_query.sql
    assert queries["statement_summary.cross_user"].required_capability == "process"
    assert queries["slow_query.cross_user"].required_capability == "process"


@pytest.mark.parametrize(
    "unsafe_sql",
    [
        "DELETE FROM t",
        "CREATE TABLE t(a INT)",
        "ADMIN SHOW DDL JOBS",
        "SET GLOBAL tidb_mem_quota_query = 1",
        "SELECT 1; SELECT 2",
        "EXPLAIN ANALYZE SELECT 1",
        "SELECT value INTO OUTFILE '/tmp/result' FROM t",
        "SELECT value FROM t FOR UPDATE",
    ],
)
def test_registry_rejects_unsafe_server_query(unsafe_sql: str) -> None:
    with pytest.raises(UnsafeServerQueryError):
        validate_server_query(server_query(unsafe_sql))


def test_registry_accepts_server_owned_ordinary_explain() -> None:
    query = server_query(
        "EXPLAIN SELECT value FROM t WHERE id = :row_id",
        parameters=("row_id",),
        cardinality=QueryCardinality.BOUNDED_ROWS,
        max_rows=64,
    )

    validate_server_query(query)


def test_registry_rejects_wildcards_and_unbounded_row_queries() -> None:
    with pytest.raises(UnsafeServerQueryError, match="wildcard"):
        validate_server_query(
            server_query(
                "SELECT * FROM information_schema.tables LIMIT 10",
                cardinality=QueryCardinality.BOUNDED_ROWS,
                max_rows=10,
            )
        )


@pytest.mark.parametrize(
    "sensitive_column",
    ["query", "query_sample_text", "digest_text", "plan", "binary_plan", "prev_stmt"],
)
def test_registry_rejects_sensitive_text_sources(sensitive_column: str) -> None:
    query = server_query(
        f"SELECT {sensitive_column} AS value FROM information_schema.slow_query LIMIT 1",
        cardinality=QueryCardinality.BOUNDED_ROWS,
    )

    with pytest.raises(UnsafeServerQueryError, match="sensitive source"):
        validate_server_query(query)


def test_registry_rejects_sensitive_decode_functions() -> None:
    query = server_query(
        "SELECT TIDB_DECODE_SQL_DIGESTS(:sql_digest) AS value",
        parameters=("sql_digest",),
    )

    with pytest.raises(UnsafeServerQueryError, match="sensitive source"):
        validate_server_query(query)


def test_registry_rejects_result_projection_mismatch() -> None:
    query = replace(
        server_query("SELECT 1 AS actual"),
        result_columns=("claimed",),
    )

    with pytest.raises(UnsafeServerQueryError, match="result projection"):
        validate_server_query(query)
    with pytest.raises(UnsafeServerQueryError, match="literal LIMIT"):
        validate_server_query(
            server_query(
                "SELECT table_name AS value FROM information_schema.tables",
                cardinality=QueryCardinality.BOUNDED_ROWS,
                max_rows=10,
            )
        )


def test_registry_requires_exact_declared_placeholders() -> None:
    with pytest.raises(UnsafeServerQueryError, match="parameter declarations"):
        validate_server_query(
            server_query(
                "SELECT table_name AS value FROM information_schema.tables "
                "WHERE table_schema = :schema_name LIMIT 10",
                cardinality=QueryCardinality.BOUNDED_ROWS,
                max_rows=10,
            )
        )
    with pytest.raises(UnsafeServerQueryError, match="parameter declarations"):
        validate_server_query(
            server_query(
                "SELECT table_name AS value FROM information_schema.tables LIMIT 10",
                parameters=("schema_name",),
                cardinality=QueryCardinality.BOUNDED_ROWS,
                max_rows=10,
            )
        )


@pytest.mark.parametrize(
    ("budget_change", "error"),
    [
        ({"timeout_ms": 0}, "timeout"),
        ({"max_rows": 0}, "row budget"),
        ({"max_bytes": 0}, "byte budget"),
        ({"concurrency_cost": 2}, "concurrency"),
        ({"kill_switch_required": False}, "kill switch"),
    ],
)
def test_registry_rejects_unenforceable_budgets(
    budget_change: dict[str, int | bool], error: str
) -> None:
    query = server_query("SELECT 1 AS value")
    unsafe = replace(query, budget=replace(query.budget, **budget_change))

    with pytest.raises(UnsafeServerQueryError, match=error):
        validate_server_query(unsafe)


@pytest.mark.parametrize("pack_id", ["tidb-8.5", "pingkaidb-7.1"])
def test_recorded_fixture_rows_match_the_server_owned_registry(pack_id: str) -> None:
    fixture_text = (FIXTURE_DIR / PACK_FIXTURES[pack_id]).read_text(encoding="utf-8")
    fixture = json.loads(fixture_text)
    queries = query_pack(pack_id)

    assert fixture["provenance"]["kind"] == "documentation-derived-normalized"
    assert fixture["provenance"]["runtimeVerified"] is False
    assert all(
        sensitive not in fixture_text.lower()
        for sensitive in (
            "password",
            "api_key",
            "access_token",
            "query_sample_text",
            "digest_text",
        )
    )
    for query_id, recording in fixture["recordings"].items():
        query = queries[query_id]
        assert tuple(recording["columns"]) == query.result_columns
        assert len(recording["rows"]) <= query.budget.max_rows
        assert all(set(row) == set(query.result_columns) for row in recording["rows"])


def test_unknown_pack_has_no_query_registry() -> None:
    with pytest.raises(ValueError, match="unsupported version pack"):
        query_pack("mysql-8.0")
