from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

import sqlglot
from sqlglot import exp
from sqlglot.errors import ErrorLevel, SqlglotError
from sqlglot.optimizer.scope import Scope, traverse_scope

from sqllens_api.evidence_connector.capabilities import capability_matrix

MAX_SERVER_QUERY_BYTES = 16_384
MAX_M0_SELECT_BYTES = 32_768
_M0_ORDINARY_EXPLAIN_PREFIX = "EXPLAIN FORMAT='brief' "
MAX_M0_ORDINARY_QUERY_BYTES = MAX_M0_SELECT_BYTES + len(_M0_ORDINARY_EXPLAIN_PREFIX.encode("utf-8"))
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


@dataclass(frozen=True, slots=True)
class ValidatedM0Select:
    """A request-local SELECT identity verified before ordinary EXPLAIN binding."""

    canonical_sql: str = field(repr=False)
    sql_digest: str
    database: str
    table_name: str


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
_SQL_DIGEST = re.compile(r"^[0-9a-f]{64}$")
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
_M0_CANDIDATE_COLUMNS = (
    "sql_digest",
    "execution_count",
    "p95_ms",
    "average_scan_rows",
    "average_return_rows",
    "last_seen",
)
_M0_INDEX_COLUMNS = (
    "table_schema",
    "table_name",
    "non_unique",
    "key_name",
    "seq_in_index",
    "column_name",
    "is_visible",
)
_M0_STATISTICS_COLUMNS = ("db_name", "table_name", "partition_name", "healthy")
_M0_ORDINARY_PLAN_COLUMNS = (
    "id",
    "est_rows",
    "task",
    "access_object",
    "operator_info",
)
_M0_STATISTICS_SQL = (
    "SHOW STATS_HEALTHY WHERE db_name = :schema_name "
    "AND table_name = :table_name AND partition_name = ''"
)
_M0_STATISTICS_BOUND_PREFIX = "SHOW STATS_HEALTHY WHERE db_name = "
_M0_STATISTICS_BOUND_MIDDLE = " AND table_name = "
_M0_STATISTICS_BOUND_SUFFIX = " AND partition_name = ''"
_UTC_RFC3339_DRIVER_FORMAT = "%%Y-%%m-%%dT%%H:%%i:%%s.%%fZ"
_STATEMENT_SUMMARY_TIMESTAMP_COLUMNS = frozenset(
    {"summary_begin_time", "summary_end_time", "first_seen", "last_seen"}
)


def validate_server_query(query: ServerQuery) -> None:
    _validate_metadata(query)
    _validate_budget(query.budget)
    if query.query_id == "statistics.health.current_table":
        _validate_m0_statistics_query(query)
        return
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


def _validate_bound_server_query(
    query: ServerQuery,
    bound_sql: str,
    *,
    backslash_escapes: bool,
) -> None:
    """Reparse one driver-mogrified query without logging its bound literals."""

    if not isinstance(bound_sql, str) or not 1 <= len(bound_sql.encode("utf-8")) <= 131_072:
        raise UnsafeServerQueryError("bound server query is empty or too large")
    if query.query_id == "statistics.health.current_table":
        _validate_bound_m0_statistics_query(
            bound_sql,
            backslash_escapes=backslash_escapes,
        )
        return
    statement = _parse_single_statement(bound_sql)
    if next(statement.find_all(exp.Placeholder), None) is not None:
        raise UnsafeServerQueryError("bound server query retains a placeholder")
    if any(isinstance(node, _MUTATING_OR_CONTROL_EXPRESSIONS) for node in statement.walk()) and (
        query.query_id != "statistics.health.current_table"
        or not isinstance(statement, exp.Command)
    ):
        raise UnsafeServerQueryError("bound server query must remain read-only")
    if any(isinstance(node, exp.Star) for node in statement.walk()):
        raise UnsafeServerQueryError("bound server query wildcard projections are not allowed")

    if isinstance(statement, exp.Describe):
        style = statement.args.get("style")
        if style is not None and str(style).upper() == "ANALYZE":
            raise UnsafeServerQueryError("EXPLAIN ANALYZE is not allowed")
        if query.query_id != "ordinary_plan.validated_select" or not isinstance(
            statement.this, exp.Query
        ):
            raise UnsafeServerQueryError("bound ordinary EXPLAIN is invalid")
        return
    if not isinstance(statement, exp.Query):
        raise UnsafeServerQueryError("bound server query is not a SELECT")
    _validate_result_projection(query, statement)
    _validate_cardinality(query, statement)


def _validate_bound_m0_statistics_query(
    bound_sql: str,
    *,
    backslash_escapes: bool,
) -> None:
    """Validate the sole TiDB SHOW shape without a parser fallback that logs literals."""

    if type(backslash_escapes) is not bool or not bound_sql.startswith(_M0_STATISTICS_BOUND_PREFIX):
        raise UnsafeServerQueryError("bound statistics query is invalid")
    position = len(_M0_STATISTICS_BOUND_PREFIX)
    position = _consume_mysql_string_literal(
        bound_sql,
        position,
        backslash_escapes=backslash_escapes,
    )
    if not bound_sql.startswith(_M0_STATISTICS_BOUND_MIDDLE, position):
        raise UnsafeServerQueryError("bound statistics query is invalid")
    position += len(_M0_STATISTICS_BOUND_MIDDLE)
    position = _consume_mysql_string_literal(
        bound_sql,
        position,
        backslash_escapes=backslash_escapes,
    )
    if bound_sql[position:] != _M0_STATISTICS_BOUND_SUFFIX:
        raise UnsafeServerQueryError("bound statistics query is invalid")


def _consume_mysql_string_literal(
    sql: str,
    start: int,
    *,
    backslash_escapes: bool,
) -> int:
    if start >= len(sql) or sql[start] != "'":
        raise UnsafeServerQueryError("bound statistics query is invalid")
    position = start + 1
    while position < len(sql):
        character = sql[position]
        if unicodedata.category(character).startswith("C"):
            raise UnsafeServerQueryError("bound statistics query is invalid")
        if character == "\\" and backslash_escapes:
            position += 2
            if position > len(sql):
                raise UnsafeServerQueryError("bound statistics query is invalid")
            continue
        if character == "'":
            if position + 1 < len(sql) and sql[position + 1] == "'":
                position += 2
                continue
            return position + 1
        position += 1
    raise UnsafeServerQueryError("bound statistics query is invalid")


def bind_m0_ordinary_explain(value: ValidatedM0Select) -> ServerQuery:
    """Revalidate and bind the sole M0 dynamic ordinary-EXPLAIN query."""

    _validate_m0_identity(value)
    statement, physical_table = _validate_m0_select_statement(value.canonical_sql)
    canonical_sql = statement.sql(dialect="mysql", pretty=False)
    if canonical_sql != value.canonical_sql:
        raise UnsafeServerQueryError("M0 SELECT is not in canonical form")
    if physical_table.name != value.table_name:
        raise UnsafeServerQueryError("M0 SELECT table identity does not match")
    table_database = physical_table.db
    if table_database and table_database != value.database:
        raise UnsafeServerQueryError("M0 SELECT database identity does not match")

    query = _query(
        "tidb-8.5",
        "ordinary_plan.validated_select",
        f"{_M0_ORDINARY_EXPLAIN_PREFIX}{canonical_sql}",
        parameters=(),
        result_columns=_M0_ORDINARY_PLAN_COLUMNS,
        required_capability="ordinary_explain",
        cardinality=QueryCardinality.BOUNDED_ROWS,
        budget=_budget(timeout_ms=5_000, max_rows=200, max_bytes=524_288),
    )
    validate_server_query(query)
    return query


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
    max_sql_bytes = (
        MAX_M0_ORDINARY_QUERY_BYTES
        if (
            query.pack_id == "tidb-8.5"
            and query.query_id == "ordinary_plan.validated_select"
            and query.query_revision == "tidb-8.5/ordinary_plan.validated_select-v1"
        )
        else MAX_SERVER_QUERY_BYTES
    )
    if not query.sql.strip() or len(query.sql.encode("utf-8")) > max_sql_bytes:
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


def _validate_m0_statistics_query(query: ServerQuery) -> None:
    """Allow one exact TiDB SHOW command without widening generic validation."""

    if (
        query.pack_id != "tidb-8.5"
        or query.pack_revision != "tidb-8.5/queries-v2"
        or query.query_revision != "tidb-8.5/statistics.health.current_table-v1"
        or query.sql != _M0_STATISTICS_SQL
        or query.parameters != ("schema_name", "table_name")
        or query.result_columns != _M0_STATISTICS_COLUMNS
        or query.required_capability != "statistics_metadata"
        or query.cardinality is not QueryCardinality.SINGLE_ROW
        or query.budget != _budget(timeout_ms=5_000, max_rows=1, max_bytes=65_536)
    ):
        raise UnsafeServerQueryError("statistics query does not match the immutable M0 card")


def _validate_m0_identity(value: ValidatedM0Select) -> None:
    if not _SQL_DIGEST.fullmatch(value.sql_digest):
        raise UnsafeServerQueryError("M0 SQL digest is invalid")
    for identity in (value.database, value.table_name):
        if (
            not 1 <= len(identity) <= 64
            or identity != identity.strip()
            or any(unicodedata.category(character).startswith("C") for character in identity)
        ):
            raise UnsafeServerQueryError("M0 SELECT identity is invalid")
    if not 1 <= len(value.canonical_sql.encode("utf-8")) <= MAX_M0_SELECT_BYTES:
        raise UnsafeServerQueryError("M0 SELECT is empty or too large")


def _validate_m0_select_statement(sql: str) -> tuple[exp.Select, exp.Table]:
    statement = _parse_single_statement(sql)
    if not isinstance(statement, exp.Select):
        raise UnsafeServerQueryError("M0 diagnosis requires one SELECT")
    if any(isinstance(node, _MUTATING_OR_CONTROL_EXPRESSIONS) for node in statement.walk()):
        raise UnsafeServerQueryError("M0 SELECT must be non-locking and read-only")
    if next(statement.find_all(exp.Join), None) is not None:
        raise UnsafeServerQueryError("M0 SELECT cannot join multiple sources")
    if next(statement.find_all(exp.Subquery), None) is not None:
        raise UnsafeServerQueryError("M0 SELECT cannot use a derived or scalar subquery")
    with_expression = statement.args.get("with_")
    if isinstance(with_expression, exp.With) and bool(with_expression.args.get("recursive")):
        raise UnsafeServerQueryError("M0 SELECT cannot use a recursive CTE")

    physical_tables: list[exp.Table] = []
    try:
        scopes = list(traverse_scope(statement))
    except (SqlglotError, ValueError, RecursionError):
        raise UnsafeServerQueryError("M0 SELECT scope analysis failed") from None
    if not scopes:
        raise UnsafeServerQueryError("M0 SELECT requires one base table")
    for scope in scopes:
        if len(scope.selected_sources) != 1:
            raise UnsafeServerQueryError("M0 SELECT requires one source per scope")
        for _name, (_node, source) in scope.selected_sources.items():
            if isinstance(source, exp.Table):
                physical_tables.append(source)
            elif isinstance(source, Scope) and source.is_cte and not source.is_derived_table:
                continue
            else:
                raise UnsafeServerQueryError("M0 SELECT source is not a base table or CTE")
    if len(physical_tables) != 1:
        raise UnsafeServerQueryError("M0 SELECT requires exactly one base table")
    physical_table = physical_tables[0]
    if not physical_table.name or physical_table.catalog:
        raise UnsafeServerQueryError("M0 SELECT table identity is unsupported")
    return statement, physical_table


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


def _utc_timestamp_projection(column: str, *, alias: str | None = None) -> str:
    output_name = alias or column
    return (
        f"DATE_FORMAT(CONVERT_TZ({column}, @@session.time_zone, '+00:00'), "
        f"'{_UTC_RFC3339_DRIVER_FORMAT}') AS {output_name}"
    )


def _build_query_pack(pack_id: str) -> Mapping[str, ServerQuery]:
    projects_utc_timestamps = pack_id == "tidb-8.5"
    statement_columns = ",\n        ".join(
        _utc_timestamp_projection(column)
        if projects_utc_timestamps and column in _STATEMENT_SUMMARY_TIMESTAMP_COLUMNS
        else column
        for column in _STATEMENT_SUMMARY_COLUMNS
    )
    common_queries = (
        _query(
            pack_id,
            "server.identity",
            """\
SELECT
    @@version AS version,
    @@version_comment AS version_comment,
    TIDB_VERSION() AS tidb_version,
    @@autocommit AS autocommit
""",
            parameters=(),
            result_columns=("version", "version_comment", "tidb_version", "autocommit"),
            required_capability=None,
            cardinality=QueryCardinality.SINGLE_ROW,
            budget=_budget(timeout_ms=2_000, max_rows=1, max_bytes=16_384),
        ),
        _query(
            pack_id,
            "slow_query.current_user",
            _slow_query_sql(
                "slow_query",
                current_user_only=True,
                project_utc_timestamp=projects_utc_timestamps,
            ),
            parameters=("window_start", "window_end", "schema_name", "sql_digest"),
            result_columns=_SLOW_QUERY_COLUMNS,
            required_capability=None,
            cardinality=QueryCardinality.BOUNDED_ROWS,
            budget=_budget(timeout_ms=5_000, max_rows=200, max_bytes=524_288),
            revision=3 if projects_utc_timestamps else 2,
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
            revision=2 if projects_utc_timestamps else 1,
        ),
        _query(
            pack_id,
            "slow_query.cross_user",
            _slow_query_sql(
                "cluster_slow_query",
                current_user_only=False,
                project_utc_timestamp=projects_utc_timestamps,
            ),
            parameters=("window_start", "window_end", "schema_name", "sql_digest"),
            result_columns=("instance", *_SLOW_QUERY_COLUMNS),
            required_capability="process",
            cardinality=QueryCardinality.BOUNDED_ROWS,
            budget=_budget(timeout_ms=8_000, max_rows=200, max_bytes=524_288),
            revision=3 if projects_utc_timestamps else 2,
        ),
    )
    m0_queries: tuple[ServerQuery, ...] = ()
    if pack_id == "tidb-8.5":
        m0_queries = (
            _query(
                pack_id,
                "sql_candidates.current_user",
                _m0_candidate_sql(),
                parameters=("window_start", "window_end", "schema_name"),
                result_columns=_M0_CANDIDATE_COLUMNS,
                required_capability=None,
                cardinality=QueryCardinality.BOUNDED_ROWS,
                budget=_budget(timeout_ms=5_000, max_rows=20, max_bytes=262_144),
                revision=2,
            ),
            _query(
                pack_id,
                "sql_digest.encode",
                "SELECT TIDB_ENCODE_SQL_DIGEST(:sql_text) AS sql_digest",
                parameters=("sql_text",),
                result_columns=("sql_digest",),
                required_capability=None,
                cardinality=QueryCardinality.SINGLE_ROW,
                budget=_budget(timeout_ms=2_000, max_rows=1, max_bytes=16_384),
            ),
            _query(
                pack_id,
                "index.current_table",
                """\
SELECT
    table_schema,
    table_name,
    non_unique,
    key_name,
    seq_in_index,
    column_name,
    is_visible
FROM information_schema.tidb_indexes
WHERE table_schema = :schema_name
  AND table_name = :table_name
ORDER BY key_name, seq_in_index
LIMIT 200
""",
                parameters=("schema_name", "table_name"),
                result_columns=_M0_INDEX_COLUMNS,
                required_capability="schema_metadata",
                cardinality=QueryCardinality.BOUNDED_ROWS,
                budget=_budget(timeout_ms=5_000, max_rows=200, max_bytes=524_288),
            ),
            _query(
                pack_id,
                "statistics.health.current_table",
                _M0_STATISTICS_SQL,
                parameters=("schema_name", "table_name"),
                result_columns=_M0_STATISTICS_COLUMNS,
                required_capability="statistics_metadata",
                cardinality=QueryCardinality.SINGLE_ROW,
                budget=_budget(timeout_ms=5_000, max_rows=1, max_bytes=65_536),
            ),
        )
    queries = (*common_queries, *m0_queries)
    for query in queries:
        validate_server_query(query)
    return MappingProxyType({query.query_id: query for query in queries})


def _m0_candidate_sql() -> str:
    return """\
SELECT
    observations.sql_digest AS sql_digest,
    COUNT(observations.sql_digest) AS execution_count,
    CAST(ROUND(APPROX_PERCENTILE(observations.query_time, 95) * 1000) AS SIGNED) AS p95_ms,
    ROUND(AVG(observations.total_keys)) AS average_scan_rows,
    ROUND(AVG(observations.result_rows)) AS average_return_rows,
    ROUND(UNIX_TIMESTAMP(MAX(observations.observed_at)) * 1000) AS last_seen
FROM (
    SELECT
        time AS observed_at,
        digest AS sql_digest,
        query_time,
        total_keys,
        result_rows
    FROM information_schema.slow_query
    WHERE time >= :window_start
      AND time <= :window_end
      AND db = :schema_name
      AND user = SUBSTRING_INDEX(CURRENT_USER(), '@', 1)
      AND digest IS NOT NULL
    ORDER BY time DESC
    LIMIT 200
) AS observations
GROUP BY observations.sql_digest
ORDER BY p95_ms DESC, execution_count DESC, sql_digest
LIMIT 20
"""


def _slow_query_sql(
    table: str,
    *,
    current_user_only: bool,
    project_utc_timestamp: bool,
) -> str:
    instance_projection = "    instance,\n" if table == "cluster_slow_query" else ""
    observed_at_projection = (
        _utc_timestamp_projection("time", alias="observed_at")
        if project_utc_timestamp
        else "time AS observed_at"
    )
    current_user_predicate = (
        "  AND user = SUBSTRING_INDEX(CURRENT_USER(), '@', 1)\n" if current_user_only else ""
    )
    return f"""\
SELECT
{instance_projection}    {observed_at_projection},
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
