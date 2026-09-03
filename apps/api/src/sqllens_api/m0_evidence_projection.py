"""Pure, bounded TiDB 8.5 result projections for the M0 report slice."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal, DecimalException

from sqllens_api.evidence_connector.canonical import MAX_SAFE_INTEGER, JsonValue
from sqllens_api.evidence_connector.client import QueryResult

STATISTICS_HEALTH_COLUMNS = (
    "db_name",
    "table_name",
    "partition_name",
    "healthy",
)
STATEMENT_SUMMARY_COLUMNS = (
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

_SUBJECT_ID = re.compile(r"^subject_[a-z0-9]{16,64}$")
_SQL_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:"
    r"(?:[0-5]\d|60)(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
_NONNEGATIVE_MEASUREMENTS = (
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
)


class EvidenceProjectionError(ValueError):
    """A raw result cannot safely become a closed M0 typed payload."""


def project_statistics_health_v1(
    result: QueryResult,
    *,
    database: str,
    table_name: str,
    profile_subject_ref: str,
    profile_object_ref: str,
) -> dict[str, JsonValue]:
    """Project one exact non-partitioned SHOW STATS_HEALTHY row."""

    _require_bounded_name(database, "database")
    _require_bounded_name(table_name, "table name")
    _require_subject(profile_subject_ref)
    if profile_object_ref != table_name:
        raise EvidenceProjectionError("statistics profile object must equal the table name")
    rows = _validate_result_shape(result, STATISTICS_HEALTH_COLUMNS)
    if len(rows) != 1:
        raise EvidenceProjectionError("statistics health requires exactly one row")
    row = rows[0]
    if row["db_name"] != database or row["table_name"] != table_name:
        raise EvidenceProjectionError("statistics health row targets another table")
    if row["partition_name"] != "":
        raise EvidenceProjectionError("partitioned statistics health is outside M0")
    healthy = _require_integer(row["healthy"], "healthy percent", minimum=0, maximum=100)
    return {
        "kind": "statistics",
        "profileSubjectRef": profile_subject_ref,
        "profileObjectRef": profile_object_ref,
        "tableName": table_name,
        "healthyPercent": healthy,
    }


def project_statement_summary_v3(
    result: QueryResult,
    *,
    database: str,
    sql_digest: str,
    window_start: datetime,
    window_end: datetime,
    profile_subject_ref: str,
    profile_object_ref: str,
) -> dict[str, JsonValue]:
    """Project checked Statement Summary aggregates for one digest and window."""

    _require_bounded_name(database, "database")
    if not isinstance(sql_digest, str) or not _SQL_DIGEST.fullmatch(sql_digest):
        raise EvidenceProjectionError("SQL digest is invalid")
    _require_subject(profile_subject_ref)
    if profile_object_ref != f"sql:{sql_digest}":
        raise EvidenceProjectionError("Statement Summary profile object must equal the SQL digest")
    start = _aware_utc(window_start, "requested window start")
    end = _aware_utc(window_end, "requested window end")
    window_minutes = _window_minutes(start, end)
    rows = _validate_result_shape(result, STATEMENT_SUMMARY_COLUMNS)
    if not rows:
        raise EvidenceProjectionError("Statement Summary requires at least one row")

    executions = 0
    weighted_total = 0
    weighted_processed = 0
    buckets: defaultdict[tuple[datetime, datetime], list[Mapping[str, object]]] = defaultdict(
        list
    )
    for row in rows:
        begin, row_end = _validate_statement_row(
            row,
            database=database,
            sql_digest=sql_digest,
            window_start=start,
            window_end=end,
        )
        execution_count = _require_integer(
            row["exec_count"], "execution count", minimum=1, maximum=MAX_SAFE_INTEGER
        )
        average_total = _require_integer(
            row["avg_total_keys"],
            "average total keys",
            minimum=0,
            maximum=MAX_SAFE_INTEGER,
        )
        average_processed = _require_integer(
            row["avg_processed_keys"],
            "average processed keys",
            minimum=0,
            maximum=MAX_SAFE_INTEGER,
        )
        executions = _checked_add(executions, execution_count, "execution count")
        weighted_total = _checked_add(
            weighted_total,
            _checked_multiply(execution_count, average_total, "weighted total keys"),
            "weighted total keys",
        )
        weighted_processed = _checked_add(
            weighted_processed,
            _checked_multiply(
                execution_count,
                average_processed,
                "weighted processed keys",
            ),
            "weighted processed keys",
        )
        buckets[(begin, row_end)].append(row)

    return {
        "kind": "statement_summary",
        "profileSubjectRef": profile_subject_ref,
        "profileObjectRef": profile_object_ref,
        "windowMinutes": window_minutes,
        "executionCount": executions,
        "averageTotalKeys": _round_half_up(weighted_total, executions),
        "averageProcessedKeys": _round_half_up(weighted_processed, executions),
        "weightedTotalKeys": weighted_total,
        "sqlStability": _derive_sql_stability(buckets),
    }


def _validate_result_shape(
    result: QueryResult,
    expected_columns: tuple[str, ...],
) -> tuple[Mapping[str, object], ...]:
    if not isinstance(result, QueryResult):
        raise EvidenceProjectionError("query result type is invalid")
    if result.columns != expected_columns:
        raise EvidenceProjectionError("query result columns are not the frozen tuple")
    if not isinstance(result.truncated, bool) or result.truncated:
        raise EvidenceProjectionError("truncated query results cannot be projected")
    expected_keys = set(expected_columns)
    rows: list[Mapping[str, object]] = []
    for row in result.rows:
        if not isinstance(row, Mapping) or set(row) != expected_keys:
            raise EvidenceProjectionError("query result row differs from its declared columns")
        rows.append(row)
    return tuple(rows)


def _validate_statement_row(
    row: Mapping[str, object],
    *,
    database: str,
    sql_digest: str,
    window_start: datetime,
    window_end: datetime,
) -> tuple[datetime, datetime]:
    instance = row["instance"]
    if not isinstance(instance, str) or not 1 <= len(instance) <= 256:
        raise EvidenceProjectionError("Statement Summary instance is invalid")
    if row["schema_name"] != database or row["digest"] != sql_digest:
        raise EvidenceProjectionError("Statement Summary row has mismatched identity")
    plan_digest = row["plan_digest"]
    if plan_digest is not None and (
        not isinstance(plan_digest, str) or not _SQL_DIGEST.fullmatch(plan_digest)
    ):
        raise EvidenceProjectionError("Statement Summary plan digest is invalid")
    begin = _parse_time(row["summary_begin_time"], "summary window start")
    end = _parse_time(row["summary_end_time"], "summary window end")
    if not window_start <= begin < end <= window_end:
        raise EvidenceProjectionError("Statement Summary row is outside the requested window")
    first_seen = _parse_time(row["first_seen"], "Statement Summary first seen")
    last_seen = _parse_time(row["last_seen"], "Statement Summary last seen")
    if not begin <= first_seen <= last_seen <= end:
        raise EvidenceProjectionError("Statement Summary observation range is invalid")
    _require_integer(row["exec_count"], "execution count", minimum=1, maximum=MAX_SAFE_INTEGER)
    for field_name in _NONNEGATIVE_MEASUREMENTS:
        _require_integer(
            row[field_name],
            field_name.replace("_", " "),
            minimum=0,
            maximum=MAX_SAFE_INTEGER,
        )
    return begin, end


def _derive_sql_stability(
    buckets: Mapping[tuple[datetime, datetime], list[Mapping[str, object]]],
) -> str:
    ordered = sorted(buckets)
    if len(ordered) < 2:
        return "unknown"
    previous_key, current_key = ordered[-2:]
    if previous_key[1] > current_key[0]:
        return "unknown"
    previous = _window_signature(buckets[previous_key])
    current = _window_signature(buckets[current_key])
    if previous is None or current is None:
        return "unknown"
    previous_plan, previous_ratios = previous
    current_plan, current_ratios = current
    if previous_plan != current_plan:
        return "plan_changed"
    if all(
        _ratios_equal(previous_ratio, current_ratio)
        for previous_ratio, current_ratio in zip(
            previous_ratios,
            current_ratios,
            strict=True,
        )
    ):
        return "plan_and_scan_stable"
    return "unknown"


def _window_signature(
    rows: list[Mapping[str, object]],
) -> tuple[str, tuple[tuple[int, int], tuple[int, int]]] | None:
    plans: set[str] = set()
    executions = 0
    weighted_total = 0
    weighted_processed = 0
    for row in rows:
        plan = row["plan_digest"]
        if plan is None:
            return None
        if not isinstance(plan, str):
            raise EvidenceProjectionError("Statement Summary plan digest is invalid")
        plans.add(plan)
        execution_count = _require_integer(
            row["exec_count"], "execution count", minimum=1, maximum=MAX_SAFE_INTEGER
        )
        average_total = _require_integer(
            row["avg_total_keys"],
            "average total keys",
            minimum=0,
            maximum=MAX_SAFE_INTEGER,
        )
        average_processed = _require_integer(
            row["avg_processed_keys"],
            "average processed keys",
            minimum=0,
            maximum=MAX_SAFE_INTEGER,
        )
        executions = _checked_add(executions, execution_count, "window execution count")
        weighted_total = _checked_add(
            weighted_total,
            _checked_multiply(execution_count, average_total, "window total keys"),
            "window total keys",
        )
        weighted_processed = _checked_add(
            weighted_processed,
            _checked_multiply(execution_count, average_processed, "window processed keys"),
            "window processed keys",
        )
    if len(plans) != 1:
        return None
    return next(iter(plans)), (
        (weighted_total, executions),
        (weighted_processed, executions),
    )


def _ratios_equal(previous: tuple[int, int], current: tuple[int, int]) -> bool:
    left = _checked_multiply(previous[0], current[1], "stability ratio")
    right = _checked_multiply(current[0], previous[1], "stability ratio")
    return left == right


def _round_half_up(numerator: int, denominator: int) -> int:
    try:
        rounded = int(
            (Decimal(numerator) / Decimal(denominator)).quantize(
                Decimal("1"),
                rounding=ROUND_HALF_UP,
            )
        )
    except (DecimalException, ValueError, OverflowError, ZeroDivisionError) as error:
        raise EvidenceProjectionError("weighted average cannot be represented") from error
    if not 0 <= rounded <= MAX_SAFE_INTEGER:
        raise EvidenceProjectionError("weighted average exceeds the safe integer range")
    return rounded


def _checked_add(left: int, right: int, label: str) -> int:
    value = left + right
    if value > MAX_SAFE_INTEGER:
        raise EvidenceProjectionError(f"{label} exceeds the safe integer range")
    return value


def _checked_multiply(left: int, right: int, label: str) -> int:
    if left and right > MAX_SAFE_INTEGER // left:
        raise EvidenceProjectionError(f"{label} exceeds the safe integer range")
    return left * right


def _require_integer(value: object, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceProjectionError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise EvidenceProjectionError(f"{label} is outside the supported range")
    return value


def _require_subject(value: str) -> None:
    if not isinstance(value, str) or not _SUBJECT_ID.fullmatch(value):
        raise EvidenceProjectionError("profile subject is invalid")


def _require_bounded_name(value: str, label: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise EvidenceProjectionError(f"{label} is invalid")


def _window_minutes(start: datetime, end: datetime) -> int:
    duration = end - start
    if duration.days < 0 or (duration.days == 0 and duration.seconds == 0):
        raise EvidenceProjectionError("requested window is not positive")
    if duration.microseconds:
        raise EvidenceProjectionError("requested window must use whole minutes")
    seconds = duration.days * 86_400 + duration.seconds
    if seconds % 60:
        raise EvidenceProjectionError("requested window must use whole minutes")
    minutes = seconds // 60
    if not 1 <= minutes <= 1_440:
        raise EvidenceProjectionError("requested window is outside the supported range")
    return minutes


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339_DATETIME.fullmatch(value):
        raise EvidenceProjectionError(f"{label} is not a valid RFC3339 timestamp")
    normalized = value[:10] + "T" + value[11:]
    if normalized[-1] in {"Z", "z"}:
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise EvidenceProjectionError(f"{label} is invalid") from error
    return _aware_utc(parsed, label)


def _aware_utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise EvidenceProjectionError(f"{label} must include a timezone")
    return value.astimezone(UTC)
