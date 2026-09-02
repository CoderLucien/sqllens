"""Pure managed-source adapter from bounded query results to Evidence/v2."""

from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal, DecimalException
from enum import StrEnum
from typing import cast

from sqllens_api.evidence_connector.canonical import (
    MAX_SAFE_INTEGER,
    JsonValue,
    canonical_sha256,
    strict_json_bytes,
    strict_json_loads,
)
from sqllens_api.evidence_connector.client import QueryResult
from sqllens_api.evidence_connector.queries import (
    ServerQuery,
    query_pack,
    validate_server_query,
)

EXTRACTION_REVISION = "evidence-extractor/v1"
CANONICAL_REVISION = "rfc8785-safe-integer/v1"
REDACTION_REVISION = "evidence-redaction/v2"
COLLECTOR_REVISION = "evidence-connector/v1"

_EVIDENCE_ID = re.compile(r"^ev_[a-z0-9]{16,64}$")
_CASE_ID = re.compile(r"^case_[a-z0-9]{16,64}$")
_SUBJECT_ID = re.compile(r"^subject_[a-z0-9]{16,64}$")
_SOURCE_ID = re.compile(r"^src_[a-z0-9]{16,64}$")
_STORAGE_ID = re.compile(r"^payload_[a-z0-9]{16,64}$")
_SQL_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:"
    r"(?:[0-5]\d|60)(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)

_QUERY_KINDS = {
    "slow_query.current_user": "slow_query",
    "slow_query.cross_user": "slow_query",
    "statement_summary.cross_user": "statement_summary",
}
_SCHEMA_REVISIONS = {
    "slow_query": "slow-query/v2",
    "statement_summary": "statement-summary/v2",
}
_COLLECTOR_IDS = {
    "tidb-8.5": "tidb-readonly",
    "pingkaidb-7.1": "pingkaidb-readonly",
}


class EvidenceBuildError(ValueError):
    """The bounded result cannot safely produce contract-valid Evidence."""


class EvidenceFreshness(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ManagedEvidenceContext:
    evidence_id: str
    case_id: str
    profile_subject_ref: str
    profile_object_ref: str
    source_id: str
    source_revision: int
    storage_ref: str
    window_start: datetime
    window_end: datetime
    collected_at: datetime
    freshness: EvidenceFreshness
    coverage_basis_points: int
    schema_name: str
    sql_digest: str


@dataclass(frozen=True, slots=True)
class CollectedEvidence:
    """Immutable serialized Evidence plus its separately stored raw payload."""

    _document_json: bytes = field(repr=False)
    storage_payload: bytes = field(repr=False)

    @property
    def document(self) -> dict[str, JsonValue]:
        loaded = strict_json_loads(self._document_json)
        if not isinstance(loaded, dict):
            raise RuntimeError("serialized Evidence document is not an object")
        return loaded

    @property
    def document_json(self) -> bytes:
        return self._document_json


def build_managed_evidence(
    *,
    query: ServerQuery,
    result: QueryResult,
    context: ManagedEvidenceContext,
) -> CollectedEvidence:
    """Validate one managed collection and construct an immutable Evidence/v2."""

    try:
        validate_server_query(query)
        registered_query = query_pack(query.pack_id).get(query.query_id)
    except (TypeError, ValueError) as error:
        raise EvidenceBuildError("query is not a valid server registry entry") from error
    if registered_query != query:
        raise EvidenceBuildError("query is not the exact server registry entry")
    kind = _QUERY_KINDS.get(query.query_id)
    if kind is None:
        raise EvidenceBuildError(f"query cannot produce diagnostic Evidence: {query.query_id}")
    collector_id = _COLLECTOR_IDS.get(query.pack_id)
    if collector_id is None:
        raise EvidenceBuildError(f"query pack cannot produce Evidence: {query.pack_id}")

    window_minutes = _validate_context(context)
    normalized_rows = _validate_result(query, result)
    storage_document: dict[str, JsonValue] = {
        "packId": query.pack_id,
        "packRevision": query.pack_revision,
        "queryId": query.query_id,
        "queryRevision": query.query_revision,
        "columns": list(result.columns),
        "rows": cast(list[JsonValue], normalized_rows),
    }
    try:
        storage_payload = strict_json_bytes(storage_document)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise EvidenceBuildError("query result content is not serializable") from error
    effective_bytes = max(result.observed_bytes, len(storage_payload))
    if effective_bytes > query.budget.max_bytes:
        raise EvidenceBuildError("query result content exceeded its byte budget")

    if kind == "slow_query":
        typed = _extract_slow_query(
            normalized_rows,
            context=context,
            window_minutes=window_minutes,
        )
    else:
        typed = _extract_statement_summary(normalized_rows, context=context)

    payload_digest = f"sha256:{hashlib.sha256(storage_payload).hexdigest()}"
    truncated = (
        result.truncated
        or len(normalized_rows) == query.budget.max_rows
        or effective_bytes == query.budget.max_bytes
    )
    document: dict[str, JsonValue] = {
        "schemaVersion": "evidence/v2",
        "evidenceId": context.evidence_id,
        "revision": 1,
        "caseId": context.case_id,
        "profileSubjectRef": context.profile_subject_ref,
        "profileObjectRef": context.profile_object_ref,
        "origin": "managed_source",
        "kind": kind,
        "sourceRef": {
            "sourceId": context.source_id,
            "revision": context.source_revision,
        },
        "observedAt": _format_time(context.window_end),
        "collectedAt": _format_time(context.collected_at),
        "freshness": context.freshness.value,
        "coverage": context.coverage_basis_points / 10_000,
        "sensitivity": "confidential",
        "integrityDigest": payload_digest,
        "summaryZh": _render_summary(kind, typed),
        "payload": {
            "schemaRevision": _SCHEMA_REVISIONS[kind],
            "extractionRevision": EXTRACTION_REVISION,
            "canonicalRevision": CANONICAL_REVISION,
            "storageRef": context.storage_ref,
            "recordCount": len(normalized_rows),
            "truncated": truncated,
            "digest": payload_digest,
            "typed": typed,
            "typedDigest": canonical_sha256(typed),
        },
        "collection": {
            "collectorId": collector_id,
            "collectorRevision": COLLECTOR_REVISION,
            "queryId": query.query_id,
            "queryRevision": query.query_revision,
            "status": "truncated" if truncated else "complete",
            "redactionRevision": REDACTION_REVISION,
            "budget": {
                "timeoutMs": query.budget.timeout_ms,
                "maxRows": query.budget.max_rows,
                "maxBytes": query.budget.max_bytes,
                "elapsedMs": result.elapsed_ms,
                "rowsRead": len(normalized_rows),
                "bytesRead": effective_bytes,
            },
        },
    }
    return CollectedEvidence(
        _document_json=strict_json_bytes(document),
        storage_payload=storage_payload,
    )


def _validate_context(context: ManagedEvidenceContext) -> int:
    _require_pattern(context.evidence_id, _EVIDENCE_ID, "evidence ID")
    _require_pattern(context.case_id, _CASE_ID, "Case ID")
    _require_pattern(context.profile_subject_ref, _SUBJECT_ID, "profile subject")
    _require_pattern(context.source_id, _SOURCE_ID, "Source ID")
    _require_pattern(context.storage_ref, _STORAGE_ID, "storage reference")
    if (
        not isinstance(context.profile_object_ref, str)
        or not 1 <= len(context.profile_object_ref) <= 256
    ):
        raise EvidenceBuildError("profile object reference is invalid")
    if (
        isinstance(context.source_revision, bool)
        or not isinstance(context.source_revision, int)
        or context.source_revision < 1
    ):
        raise EvidenceBuildError("Source revision is invalid")
    if not isinstance(context.freshness, EvidenceFreshness):
        raise EvidenceBuildError("Evidence freshness is invalid")
    if (
        isinstance(context.coverage_basis_points, bool)
        or not isinstance(context.coverage_basis_points, int)
        or not 0 <= context.coverage_basis_points <= 10_000
    ):
        raise EvidenceBuildError("Evidence coverage is invalid")
    if not isinstance(context.schema_name, str) or not 1 <= len(context.schema_name) <= 64:
        raise EvidenceBuildError("schema name is invalid")
    _require_pattern(context.sql_digest, _SQL_DIGEST, "SQL digest")

    start = _aware_utc(context.window_start, "window start")
    end = _aware_utc(context.window_end, "window end")
    collected = _aware_utc(context.collected_at, "collection time")
    if not start < end <= collected:
        raise EvidenceBuildError("Evidence time window is invalid")
    duration_seconds = (end - start).total_seconds()
    if not duration_seconds.is_integer() or int(duration_seconds) % 60:
        raise EvidenceBuildError("Evidence window must use whole minutes")
    window_minutes = int(duration_seconds) // 60
    if not 1 <= window_minutes <= 1_440:
        raise EvidenceBuildError("Evidence window is outside the contract range")
    return window_minutes


def _validate_result(
    query: ServerQuery,
    result: QueryResult,
) -> list[dict[str, JsonValue]]:
    if result.columns != query.result_columns:
        raise EvidenceBuildError("query result columns differ from the registry")
    if not isinstance(result.truncated, bool):
        raise EvidenceBuildError("query truncation flag is invalid")
    _require_nonnegative_integer(result.elapsed_ms, "elapsed milliseconds")
    _require_positive_integer(result.observed_bytes, "observed bytes")
    if result.elapsed_ms > query.budget.timeout_ms:
        raise EvidenceBuildError("query result exceeded its timeout budget")
    if len(result.rows) > query.budget.max_rows:
        raise EvidenceBuildError("query result exceeded its row budget")
    if result.observed_bytes > query.budget.max_bytes:
        raise EvidenceBuildError("query result exceeded its byte budget")
    if not result.rows:
        raise EvidenceBuildError("empty collection cannot produce typed Evidence")

    expected_columns = set(result.columns)
    normalized_rows: list[dict[str, JsonValue]] = []
    for row in result.rows:
        if set(row) != expected_columns:
            raise EvidenceBuildError("query result row differs from declared columns")
        normalized: dict[str, JsonValue] = {}
        for key in result.columns:
            value = row[key]
            if not isinstance(value, (str, int, float, bool)) and value is not None:
                raise EvidenceBuildError(f"query result value is not JSON-safe: {key}")
            if isinstance(value, float) and not math.isfinite(value):
                raise EvidenceBuildError(f"query result number is not finite: {key}")
            normalized[key] = value
        normalized_rows.append(normalized)
    return normalized_rows


def _extract_slow_query(
    rows: list[dict[str, JsonValue]],
    *,
    context: ManagedEvidenceContext,
    window_minutes: int,
) -> dict[str, JsonValue]:
    latency_ms: list[int] = []
    scanned_rows: list[int] = []
    returned_rows: list[int] = []
    for row in rows:
        _validate_selected_row(row, context)
        _validate_slow_query_measurements(row)
        observed = _parse_row_time(row["observed_at"], "slow query observation")
        if not context.window_start <= observed <= context.window_end:
            raise EvidenceBuildError("slow query observation is outside the requested window")
        latency_ms.append(_seconds_to_milliseconds(row["query_time"]))
        scanned_rows.append(_require_positive_integer(row["total_keys"], "total keys"))
        returned_rows.append(_require_positive_integer(row["result_rows"], "result rows"))

    sorted_latency = sorted(latency_ms)
    percentile_index = math.ceil(len(sorted_latency) * 95 / 100) - 1
    typed: dict[str, JsonValue] = {
        "kind": "slow_query",
        "profileSubjectRef": context.profile_subject_ref,
        "profileObjectRef": context.profile_object_ref,
        "windowMinutes": window_minutes,
        "callCount": len(rows),
        "p95Ms": sorted_latency[percentile_index],
        "averageScanRows": _rounded_average(scanned_rows),
        "averageReturnRows": _rounded_average(returned_rows),
    }
    _validate_slow_query_contract_ranges(typed)
    return typed


def _extract_statement_summary(
    rows: list[dict[str, JsonValue]],
    *,
    context: ManagedEvidenceContext,
) -> dict[str, JsonValue]:
    buckets: defaultdict[tuple[datetime, datetime], list[dict[str, JsonValue]]] = defaultdict(list)
    for row in rows:
        _validate_selected_row(row, context)
        begin = _parse_row_time(row["summary_begin_time"], "summary window start")
        end = _parse_row_time(row["summary_end_time"], "summary window end")
        if not context.window_start <= begin < end <= context.window_end:
            raise EvidenceBuildError("Statement Summary row is outside the requested window")
        _validate_statement_summary_measurements(row, begin=begin, end=end)
        buckets[(begin, end)].append(row)

    stability = "unknown"
    ordered_windows = sorted(buckets)
    if len(ordered_windows) >= 2:
        previous_key, current_key = ordered_windows[-2:]
        if previous_key[1] <= current_key[0]:
            previous = _summary_window_signature(buckets[previous_key])
            current = _summary_window_signature(buckets[current_key])
            if previous is not None and current is not None:
                previous_plan, previous_scans = previous
                current_plan, current_scans = current
                if previous_plan != current_plan:
                    stability = "plan_changed"
                elif _exact_scan_ratios_equal(previous_scans, current_scans):
                    stability = "plan_and_scan_stable"

    return {
        "kind": "statement_summary",
        "profileSubjectRef": context.profile_subject_ref,
        "profileObjectRef": context.profile_object_ref,
        "sqlStability": stability,
    }


def _summary_window_signature(
    rows: list[dict[str, JsonValue]],
) -> tuple[str, tuple[tuple[int, int], tuple[int, int]]] | None:
    plan_digests: set[str] = set()
    weighted_total = 0
    weighted_processed = 0
    executions = 0
    for row in rows:
        plan_digest = row["plan_digest"]
        if plan_digest is None:
            return None
        if not isinstance(plan_digest, str) or not _SQL_DIGEST.fullmatch(plan_digest):
            raise EvidenceBuildError("Statement Summary plan digest is invalid")
        plan_digests.add(plan_digest)
        exec_count = _require_positive_integer(row["exec_count"], "execution count")
        average_total = _require_nonnegative_integer(row["avg_total_keys"], "average total keys")
        average_processed = _require_nonnegative_integer(
            row["avg_processed_keys"], "average processed keys"
        )
        executions += exec_count
        weighted_total += average_total * exec_count
        weighted_processed += average_processed * exec_count
    if len(plan_digests) != 1:
        return None
    return (
        next(iter(plan_digests)),
        (
            (weighted_total, executions),
            (weighted_processed, executions),
        ),
    )


def _exact_scan_ratios_equal(
    previous: tuple[tuple[int, int], tuple[int, int]],
    current: tuple[tuple[int, int], tuple[int, int]],
) -> bool:
    return all(
        previous_numerator * current_denominator == current_numerator * previous_denominator
        for (previous_numerator, previous_denominator), (
            current_numerator,
            current_denominator,
        ) in zip(previous, current, strict=True)
    )


def _validate_slow_query_measurements(row: Mapping[str, JsonValue]) -> None:
    if "instance" in row:
        instance = row["instance"]
        if not isinstance(instance, str) or not 1 <= len(instance) <= 256:
            raise EvidenceBuildError("Slow Query instance is invalid")
    plan_digest = row["plan_digest"]
    if plan_digest is not None and (
        not isinstance(plan_digest, str) or not _SQL_DIGEST.fullmatch(plan_digest)
    ):
        raise EvidenceBuildError("Slow Query plan digest is invalid")
    for field_name, label in (
        ("parse_time", "parse time"),
        ("compile_time", "compile time"),
        ("cop_time", "coprocessor time"),
        ("process_time", "process time"),
        ("wait_time", "wait time"),
        ("backoff_time", "backoff time"),
    ):
        _require_nonnegative_number(row[field_name], label)
    for field_name, label in (
        ("process_keys", "process keys"),
        ("mem_max", "peak memory"),
        ("disk_max", "peak disk"),
    ):
        _require_nonnegative_integer(row[field_name], label)


def _validate_statement_summary_measurements(
    row: Mapping[str, JsonValue],
    *,
    begin: datetime,
    end: datetime,
) -> None:
    instance = row["instance"]
    if not isinstance(instance, str) or not 1 <= len(instance) <= 256:
        raise EvidenceBuildError("Statement Summary instance is invalid")
    plan_digest = row["plan_digest"]
    if plan_digest is not None and (
        not isinstance(plan_digest, str) or not _SQL_DIGEST.fullmatch(plan_digest)
    ):
        raise EvidenceBuildError("Statement Summary plan digest is invalid")
    _require_positive_integer(row["exec_count"], "execution count")
    for field_name, label in (
        ("sum_latency", "sum latency"),
        ("avg_latency", "average latency"),
        ("max_latency", "maximum latency"),
        ("sum_errors", "error count"),
        ("avg_mem", "average memory"),
        ("max_mem", "maximum memory"),
        ("avg_disk", "average disk"),
        ("max_disk", "maximum disk"),
        ("avg_total_keys", "average total keys"),
        ("avg_processed_keys", "average processed keys"),
    ):
        _require_nonnegative_integer(row[field_name], label)
    first_seen = _parse_row_time(row["first_seen"], "Statement Summary first seen")
    last_seen = _parse_row_time(row["last_seen"], "Statement Summary last seen")
    if not begin <= first_seen <= last_seen <= end:
        raise EvidenceBuildError("Statement Summary observation range is invalid")


def _validate_selected_row(row: Mapping[str, JsonValue], context: ManagedEvidenceContext) -> None:
    if row["schema_name"] != context.schema_name:
        raise EvidenceBuildError("query result belongs to another schema")
    if row["digest"] != context.sql_digest:
        raise EvidenceBuildError("query result belongs to another SQL digest")


def _seconds_to_milliseconds(value: JsonValue) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceBuildError("query latency must be a numeric second value")
    try:
        seconds = Decimal(str(value))
    except (DecimalException, ValueError, OverflowError) as error:
        raise EvidenceBuildError("query latency is invalid") from error
    if seconds <= 0:
        raise EvidenceBuildError("query latency is outside the typed Evidence range")
    if seconds > Decimal(3_600):
        raise EvidenceBuildError("query latency is out of range")
    try:
        milliseconds = int(
            (seconds * Decimal(1_000)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        )
    except (DecimalException, ValueError, OverflowError) as error:
        raise EvidenceBuildError("query latency is invalid") from error
    if milliseconds < 1:
        raise EvidenceBuildError("query latency is outside the typed Evidence range")
    return milliseconds


def _rounded_average(values: list[int]) -> int:
    return _rounded_ratio(sum(values), len(values))


def _rounded_ratio(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator < 1:
        raise EvidenceBuildError("rounded ratio inputs are invalid")
    quotient, remainder = divmod(numerator, denominator)
    return quotient + int(remainder * 2 >= denominator)


def _validate_slow_query_contract_ranges(typed: dict[str, JsonValue]) -> None:
    ranges = {
        "windowMinutes": (1, 1_440),
        "callCount": (1, 1_000_000_000),
        "p95Ms": (1, 3_600_000),
        "averageScanRows": (1, 1_000_000_000_000),
        "averageReturnRows": (1, 1_000_000_000_000),
    }
    for field_name, (minimum, maximum) in ranges.items():
        value = typed[field_name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise EvidenceBuildError(f"typed Slow Query field is not an integer: {field_name}")
        if not minimum <= value <= maximum:
            raise EvidenceBuildError(f"typed Slow Query field is out of range: {field_name}")


def _render_summary(kind: str, typed: dict[str, JsonValue]) -> str:
    if kind == "slow_query":
        scan_ten_thousands = _format_derived_ratio(cast(int, typed["averageScanRows"]), 10_000)
        return (
            f"该 SQL 在 {typed['windowMinutes']} 分钟窗口内执行 "
            f"{typed['callCount']} 次，P95 {_format_ms(cast(int, typed['p95Ms']))}，"  # noqa: RUF001
            f"平均扫描 {scan_ten_thousands} 万行。"
        )
    if kind == "statement_summary":
        templates = {
            "plan_and_scan_stable": "SQL 计划摘要和扫描行数与前一基线窗口接近。",
            "plan_changed": "SQL 计划摘要相对前一基线窗口发生变化。",
            "scan_changed": "SQL 扫描行数相对前一基线窗口发生变化。",
            "unknown": "当前 Statement Summary 证据不足以判断计划和扫描稳定性。",
        }
        return templates[cast(str, typed["sqlStability"])]
    raise EvidenceBuildError(f"Evidence summary kind is unsupported: {kind}")


def _format_ms(value: int) -> str:
    if value < 1_000:
        return f"{value} ms"
    seconds = Decimal(value) / Decimal(1_000)
    return f"{format(seconds.normalize(), 'f')} 秒"


def _format_derived_ratio(numerator: int, denominator: int) -> str:
    if numerator < 1 or denominator < 1:
        raise EvidenceBuildError("derived ratio inputs must be positive")
    ratio = (Decimal(numerator) / Decimal(denominator)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    return format(ratio.normalize(), "f")


def _require_pattern(value: object, pattern: re.Pattern[str], label: str) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise EvidenceBuildError(f"{label} is invalid")


def _require_nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceBuildError(f"{label} must be a non-negative integer")
    return value


def _require_positive_integer(value: object, label: str) -> int:
    number = _require_nonnegative_integer(value, label)
    if number < 1:
        raise EvidenceBuildError(f"{label} must be positive")
    return number


def _require_nonnegative_number(value: object, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceBuildError(f"{label} must be a non-negative finite number")
    if isinstance(value, float) and not math.isfinite(value):
        raise EvidenceBuildError(f"{label} must be a non-negative finite number")
    if value < 0:
        raise EvidenceBuildError(f"{label} must be a non-negative finite number")
    if value > MAX_SAFE_INTEGER:
        raise EvidenceBuildError(f"{label} is out of range")
    return value


def _parse_row_time(value: JsonValue, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceBuildError(f"{label} must be an RFC3339 string")
    if not _RFC3339_DATETIME.fullmatch(value):
        raise EvidenceBuildError(f"{label} is invalid RFC3339")
    normalized = value[:10] + "T" + value[11:]
    if normalized[-1] in {"Z", "z"}:
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise EvidenceBuildError(f"{label} is invalid") from error
    return _aware_utc(parsed, label)


def _aware_utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise EvidenceBuildError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return _aware_utc(value, "Evidence time").isoformat().replace("+00:00", "Z")
