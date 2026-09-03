from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

import sqlglot
from sqlglot import exp
from sqlglot.errors import ErrorLevel, SqlglotError

from sqllens_api.evidence_connector.capabilities import capability_matrix

MAX_SERVER_QUERY_BYTES = 16_384
MAX_QUERY_TIMEOUT_MS = 30_000
MAX_QUERY_ROWS = 1_000
MAX_QUERY_RESULT_BYTES = 1_048_576


class UnsafeServerQueryError(ValueError):
    pass


class QueryCardinality(StrEnum):
    SINGLE_ROW = "single_row"
    BOUNDED_ROWS = "bounded_rows"


class QueryRuPolicy(StrEnum):
    NOT_REQUESTED = "not_requested"


class QueryPriorityPolicy(StrEnum):
    DATABASE_DEFAULT = "database_default"


@dataclass(frozen=True, slots=True)
class QueryBudget:
    timeout_ms: int
    max_rows: int
    max_bytes: int
    concurrency_cost: int
    ru_policy: QueryRuPolicy
    priority_policy: QueryPriorityPolicy
    kill_switch_required: bool = True


@dataclass(frozen=True, slots=True)
class ServerQuery:
    pack_id: str
    pack_revision: str
    query_id: str
    query_revision: str
    sql: str = field(repr=False)
    parameters: tuple[str, ...]
    result_columns: tuple[str, ...]
    required_capability: str | None
    cardinality: QueryCardinality
    budget: QueryBudget


_MUTATING_OR_CONTROL_EXPRESSIONS = (
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
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.]*$")
_PARAMETER = re.compile(r"^[a-z][a-z0-9_]*$")
_SENSITIVE_SOURCE_COLUMNS = frozenset(
    {
        "backoff_detail",
        "binary_plan",
        "digest_text",
        "plan",
        "prev_stmt",
        "query",
        "query_sample_text",
        "session_connect_attrs",
        "warnings",
    }
)
_SENSITIVE_FUNCTIONS = frozenset({"tidb_decode_plan", "tidb_decode_sql_digests"})

_STATEMENT_SUMMARY_COLUMNS = (
    "instance",
    "summary_begin_time",
    "summary_end_time",
    "schema_name",
    "digest",
    "plan_digest",
    "exec_count",
    "sum_latency",
    "avg_latency",
    "max_latency",
    "sum_errors",
    "avg_mem",
    "max_mem",
    "avg_disk",
    "max_disk",
    "avg_total_keys",
    "avg_processed_keys",
    "first_seen",
    "last_seen",
)
_SLOW_QUERY_COLUMNS = (
    "observed_at",
    "schema_name",
    "digest",
    "plan_digest",
    "query_time",
    "parse_time",
    "compile_time",
    "cop_time",
    "process_time",
    "wait_time",
    "backoff_time",
    "total_keys",
    "process_keys",
    "mem_max",
    "disk_max",
    "result_rows",
)


def validate_server_query(query: ServerQuery) -> None:
    _validate_metadata(query)
    _validate_budget(query.budget)
    statement = _parse_single_statement(query.sql)

    if any(isinstance(node, _MUTATING_OR_CONTROL_EXPRESSIONS) for node in statement.walk()):
        raise UnsafeServerQueryError("server query must be non-locking and read-only")
    if any(isinstance(node, exp.Star) for node in statement.walk()):
        raise UnsafeServerQueryError("server query wildcard projections are not allowed")
    if any(
        column.name.lower() in _SENSITIVE_SOURCE_COLUMNS
        for column in statement.find_all(exp.Column)
    ) or any(
        function.name.lower() in _SENSITIVE_FUNCTIONS
        for function in statement.find_all(exp.Anonymous)
    ):
        raise UnsafeServerQueryError("server query references a sensitive source")

    query_expression: exp.Query | None = None
    is_explain = False
    if isinstance(statement, exp.Describe):
        style = statement.args.get("style")
        if style is not None and str(style).upper() == "ANALYZE":
            raise UnsafeServerQueryError("EXPLAIN ANALYZE is not allowed")
        if not isinstance(statement.this, exp.Query):
            raise UnsafeServerQueryError("only ordinary EXPLAIN of a query is allowed")
        query_expression = statement.this
        is_explain = True
    elif isinstance(statement, exp.Query):
        query_expression = statement
    elif not isinstance(statement, exp.Show):
        raise UnsafeServerQueryError("only SELECT, SHOW, or ordinary EXPLAIN is allowed")

    placeholders = {str(placeholder.this) for placeholder in statement.find_all(exp.Placeholder)}
    if placeholders != set(query.parameters):
        raise UnsafeServerQueryError("query parameter declarations do not match placeholders")

    if query_expression is not None and not is_explain:
        _validate_result_projection(query, query_expression)
        _validate_cardinality(query, query_expression)


def query_pack(pack_id: str) -> Mapping[str, ServerQuery]:
    queries = _QUERY_PACKS.get(pack_id)
    if queries is None:
        raise ValueError(f"unsupported version pack: {pack_id}")
    return queries


def _validate_metadata(query: ServerQuery) -> None:
    capabilities = capability_matrix(query.pack_id)
    if query.pack_revision != f"{query.pack_id}/queries-v2":
        raise UnsafeServerQueryError("query pack revision is invalid")
    if not _IDENTIFIER.fullmatch(query.query_id):
        raise UnsafeServerQueryError("query identifier is invalid")
    if not query.query_revision.startswith(f"{query.pack_id}/{query.query_id}-"):
        raise UnsafeServerQueryError("query revision is invalid")
    if not query.sql.strip() or len(query.sql.encode("utf-8")) > MAX_SERVER_QUERY_BYTES:
        raise UnsafeServerQueryError("server query is empty or too large")
    if len(query.parameters) != len(set(query.parameters)) or any(
        not _PARAMETER.fullmatch(parameter) for parameter in query.parameters
    ):
        raise UnsafeServerQueryError("query parameter declarations are invalid")
    if not query.result_columns or len(query.result_columns) != len(set(query.result_columns)):
        raise UnsafeServerQueryError("query result columns are invalid")
    if any(not _IDENTIFIER.fullmatch(column) for column in query.result_columns):
        raise UnsafeServerQueryError("query result columns are invalid")
    if query.required_capability is not None and query.required_capability not in capabilities:
        raise UnsafeServerQueryError("query capability is not defined by its version pack")


def _validate_budget(budget: QueryBudget) -> None:
    if not 0 < budget.timeout_ms <= MAX_QUERY_TIMEOUT_MS:
        raise UnsafeServerQueryError("query timeout budget is invalid")
    if not 0 < budget.max_rows <= MAX_QUERY_ROWS:
        raise UnsafeServerQueryError("query row budget is invalid")
    if not 0 < budget.max_bytes <= MAX_QUERY_RESULT_BYTES:
        raise UnsafeServerQueryError("query byte budget is invalid")
    if budget.concurrency_cost != 1:
        raise UnsafeServerQueryError("query concurrency cost is invalid")
    if budget.ru_policy is not QueryRuPolicy.NOT_REQUESTED:
        raise UnsafeServerQueryError("query RU policy is invalid")
    if budget.priority_policy is not QueryPriorityPolicy.DATABASE_DEFAULT:
        raise UnsafeServerQueryError("query priority policy is invalid")
    if budget.kill_switch_required is not True:
        raise UnsafeServerQueryError("query kill switch is required")


def _parse_single_statement(sql: str) -> exp.Expr:
    try:
        statements = [
            statement
            for statement in sqlglot.parse(
                sql,
                read="mysql",
                error_level=ErrorLevel.RAISE,
            )
            if statement is not None
        ]
    except (SqlglotError, ValueError, RecursionError) as error:
        raise UnsafeServerQueryError("server query failed strict parsing") from error
    if len(statements) != 1:
        raise UnsafeServerQueryError("server query must contain exactly one statement")
    return statements[0]


def _validate_cardinality(query: ServerQuery, expression: exp.Query) -> None:
    literal_limit = _literal_limit(expression)
    if query.cardinality is QueryCardinality.SINGLE_ROW:
        if next(expression.find_all(exp.Table), None) is not None and literal_limit != 1:
            raise UnsafeServerQueryError("single-row query must have literal LIMIT 1")
        return
    if literal_limit is None or literal_limit > query.budget.max_rows:
        raise UnsafeServerQueryError(
            "bounded-row query requires a literal LIMIT within its row budget"
        )


def _validate_result_projection(query: ServerQuery, expression: exp.Query) -> None:
    projection = tuple(projected.output_name.lower() for projected in expression.selects)
    if projection != query.result_columns:
        raise UnsafeServerQueryError("query result projection does not match declared columns")


def _literal_limit(expression: exp.Query) -> int | None:
    limit = expression.args.get("limit")
    if not isinstance(limit, exp.Limit) or not isinstance(limit.expression, exp.Literal):
        return None
    if not limit.expression.is_int:
        return None
    return int(limit.expression.this)


def _budget(*, timeout_ms: int, max_rows: int, max_bytes: int) -> QueryBudget:
    return QueryBudget(
        timeout_ms=timeout_ms,
        max_rows=max_rows,
        max_bytes=max_bytes,
        concurrency_cost=1,
        ru_policy=QueryRuPolicy.NOT_REQUESTED,
        priority_policy=QueryPriorityPolicy.DATABASE_DEFAULT,
    )


def _query(
    pack_id: str,
    query_id: str,
    sql: str,
    *,
    parameters: tuple[str, ...],
    result_columns: tuple[str, ...],
    required_capability: str | None,
    cardinality: QueryCardinality,
    budget: QueryBudget,
    revision: int = 1,
) -> ServerQuery:
    return ServerQuery(
        pack_id=pack_id,
        pack_revision=f"{pack_id}/queries-v2",
        query_id=query_id,
        query_revision=f"{pack_id}/{query_id}-v{revision}",
        sql=sql,
        parameters=parameters,
        result_columns=result_columns,
        required_capability=required_capability,
        cardinality=cardinality,
        budget=budget,
    )


def _build_query_pack(pack_id: str) -> Mapping[str, ServerQuery]:
    statement_columns = ",\n        ".join(_STATEMENT_SUMMARY_COLUMNS)
    queries = (
        _query(
            pack_id,
            "server.identity",
            """\
SELECT
    @@version AS version,
    @@version_comment AS version_comment,
    TIDB_VERSION() AS tidb_version
""",
            parameters=(),
            result_columns=("version", "version_comment", "tidb_version"),
            required_capability=None,
            cardinality=QueryCardinality.SINGLE_ROW,
            budget=_budget(timeout_ms=2_000, max_rows=1, max_bytes=16_384),
        ),
        _query(
            pack_id,
            "slow_query.current_user",
            _slow_query_sql("slow_query", current_user_only=True),
            parameters=("window_start", "window_end", "schema_name", "sql_digest"),
            result_columns=_SLOW_QUERY_COLUMNS,
            required_capability=None,
            cardinality=QueryCardinality.BOUNDED_ROWS,
            budget=_budget(timeout_ms=5_000, max_rows=200, max_bytes=524_288),
            revision=2,
        ),
        _query(
            pack_id,
            "statement_summary.cross_user",
            f"""\
SELECT
        {statement_columns}
FROM information_schema.cluster_statements_summary_history
WHERE summary_begin_time >= :window_start
  AND summary_end_time <= :window_end
  AND schema_name = :schema_name
  AND digest = :sql_digest
ORDER BY summary_begin_time DESC
LIMIT 200
""",
            parameters=("window_start", "window_end", "schema_name", "sql_digest"),
            result_columns=_STATEMENT_SUMMARY_COLUMNS,
            required_capability="process",
            cardinality=QueryCardinality.BOUNDED_ROWS,
            budget=_budget(timeout_ms=8_000, max_rows=200, max_bytes=524_288),
        ),
        _query(
            pack_id,
            "slow_query.cross_user",
            _slow_query_sql("cluster_slow_query", current_user_only=False),
            parameters=("window_start", "window_end", "schema_name", "sql_digest"),
            result_columns=("instance", *_SLOW_QUERY_COLUMNS),
            required_capability="process",
            cardinality=QueryCardinality.BOUNDED_ROWS,
            budget=_budget(timeout_ms=8_000, max_rows=200, max_bytes=524_288),
            revision=2,
        ),
    )
    for query in queries:
        validate_server_query(query)
    return MappingProxyType({query.query_id: query for query in queries})


def _slow_query_sql(table: str, *, current_user_only: bool) -> str:
    instance_projection = "    instance,\n" if table == "cluster_slow_query" else ""
    current_user_predicate = (
        "  AND user = SUBSTRING_INDEX(CURRENT_USER(), '@', 1)\n" if current_user_only else ""
    )
    return f"""\
SELECT
{instance_projection}    time AS observed_at,
    db AS schema_name,
    digest,
    plan_digest,
    query_time,
    parse_time,
    compile_time,
    cop_time,
    process_time,
    wait_time,
    backoff_time,
    total_keys,
    process_keys,
    mem_max,
    disk_max,
    result_rows
FROM information_schema.{table}
WHERE time >= :window_start
  AND time <= :window_end
  AND db = :schema_name
  AND digest = :sql_digest
{current_user_predicate}ORDER BY time DESC
LIMIT 200
"""


_QUERY_PACKS = {pack_id: _build_query_pack(pack_id) for pack_id in ("tidb-8.5", "pingkaidb-7.1")}
