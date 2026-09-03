# ruff: noqa: RUF001
"""Pure deterministic TiDB 8.5 M0 rule evaluation and report rendering."""

from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

from sqllens_api.evidence_connector.canonical import (
    JsonValue,
    canonical_sha256,
    strict_json_bytes,
    strict_json_loads,
)
from sqllens_api.evidence_connector.evidence import CollectedEvidence

RULE_PACK_REVISION = "tidb-8.5-m0-rules/v1"
INDEX_RULE_ID = "TIDB85_INDEX_SCAN_RISK"
STATISTICS_RULE_ID = "TIDB85_STATISTICS_HEALTH_RISK"
REPEATED_SCAN_RULE_ID = "TIDB85_REPEATED_HEAVY_SCAN"
MIN_COVERAGE_BASIS_POINTS = 8_000

NO_BUSINESS_EVIDENCE_ZH = "未提供业务影响证据，仅说明数据库技术影响"
_DOCUMENT_PACK_REVISION = "tidb-8.5-m0-guidance/v1"
_POLICY_REVISION = "m0-report-policy/v1"
_PARSER_REVISION = "sqlglot/mysql@30.17.0"
_REDACTION_REVISION = "evidence-redaction/v2"

_CASE_ID = re.compile(r"^case_[a-z0-9]{16,64}$")
_EVIDENCE_ID = re.compile(r"^ev_[a-z0-9]{16,64}$")
_SUBJECT_ID = re.compile(r"^subject_[a-z0-9]{16,64}$")
_SOURCE_ID = re.compile(r"^src_[a-z0-9]{16,64}$")
_STORAGE_ID = re.compile(r"^payload_[a-z0-9]{16,64}$")
_SQL_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_SHA256 = re.compile(r"^sha256:[a-f0-9]{64}$")
_RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:"
    r"(?:[0-5]\d|60)(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)

_TOP_LEVEL_FIELDS = {
    "schemaVersion",
    "evidenceId",
    "revision",
    "caseId",
    "profileSubjectRef",
    "profileObjectRef",
    "origin",
    "kind",
    "sourceRef",
    "observedAt",
    "collectedAt",
    "freshness",
    "coverage",
    "sensitivity",
    "integrityDigest",
    "summaryZh",
    "payload",
    "collection",
}
_PAYLOAD_FIELDS = {
    "schemaRevision",
    "extractionRevision",
    "canonicalRevision",
    "storageRef",
    "recordCount",
    "truncated",
    "digest",
    "typed",
    "typedDigest",
}
_COLLECTION_FIELDS = {
    "collectorId",
    "collectorRevision",
    "queryId",
    "queryRevision",
    "status",
    "redactionRevision",
    "budget",
}
_BUDGET_FIELDS = {
    "timeoutMs",
    "maxRows",
    "maxBytes",
    "elapsedMs",
    "rowsRead",
    "bytesRead",
}
_ROLE_ORDER = (
    "sql_structure",
    "ordinary_plan",
    "index",
    "statistics",
    "statement_summary",
    "slow_query",
)
_RULE_ORDER = (REPEATED_SCAN_RULE_ID, INDEX_RULE_ID, STATISTICS_RULE_ID)
_ROLE_LABELS = {
    "sql_structure": "SQL 结构（sql_structure）",
    "ordinary_plan": "普通执行计划（ordinary_plan）",
    "index": "索引元数据（index）",
    "statistics": "统计健康度（statistics）",
    "statement_summary": "语句汇总（statement_summary）",
    "slow_query": "慢查询观测（slow_query）",
}


class M0ReportError(ValueError):
    """The report request itself is outside the frozen M0 interface."""


@dataclass(frozen=True, slots=True)
class M0ReportInput:
    case_id: str
    database: str
    sql_digest: str
    window_start: datetime
    window_end: datetime
    evidence: tuple[CollectedEvidence, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _EvidenceRecord:
    evidence_id: str
    kind: str
    profile_subject_ref: str
    profile_object_ref: str
    source_id: str
    source_revision: int
    observed_at: datetime
    eligible_quality: bool
    typed: Mapping[str, JsonValue] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _Assessment:
    rule_id: str
    required_roles: tuple[str, ...]
    eligible: Mapping[str, _EvidenceRecord] = field(repr=False)
    hit: bool = False

    @property
    def completeness(self) -> int:
        return len(self.eligible) * 100 // len(self.required_roles)

    @property
    def missing_roles(self) -> tuple[str, ...]:
        return tuple(role for role in self.required_roles if role not in self.eligible)


def build_m0_rules_report(value: M0ReportInput) -> bytes:
    """Return canonical UTF-8 JSON conforming to diagnosis-report/v1."""

    window_minutes = _validate_input(value)
    records, invalid_roles, identity_conflict = _read_evidence_bundle(value, window_minutes)
    by_kind: defaultdict[str, list[_EvidenceRecord]] = defaultdict(list)
    for record in records:
        by_kind[record.kind].append(record)

    def select(kind: str) -> _EvidenceRecord | None:
        candidates = by_kind[kind]
        if (
            identity_conflict
            or kind in invalid_roles
            or len(candidates) != 1
            or not candidates[0].eligible_quality
        ):
            return None
        return candidates[0]

    index = _assess_index(select)
    statistics = _assess_statistics(select)
    repeated = _assess_repeated_placeholder(select)
    assessments = {
        INDEX_RULE_ID: index,
        STATISTICS_RULE_ID: statistics,
        REPEATED_SCAN_RULE_ID: repeated,
    }
    hits = [assessments[rule_id] for rule_id in _RULE_ORDER if assessments[rule_id].hit]
    leading = (
        hits[0]
        if hits
        else max(
            assessments.values(),
            key=lambda item: (item.completeness, -_RULE_ORDER.index(item.rule_id)),
        )
    )
    priority = _priority(hits, select)
    evidence_ids = sorted(
        {record.evidence_id for assessment in hits for record in assessment.eligible.values()}
    )
    if not hits:
        evidence_ids = sorted(record.evidence_id for record in records if record.eligible_quality)
    source_revisions = sorted(
        {
            f"{record.source_id}@{record.source_revision}"
            for record in records
            if record.eligible_quality
        }
    )
    report = {
        "schemaVersion": "diagnosis-report/v1",
        "caseId": value.case_id,
        "caseRevision": 1,
        "audience": "dba_sre",
        "titleZh": _title(hits),
        "priority": priority,
        "configuredMode": "rules",
        "effectiveMode": "rules",
        "conclusionZh": _conclusion(hits),
        "impact": {
            "clusterZh": "当前本地连接的 TiDB 集群",
            "databaseZh": value.database,
            "sqlDigest": value.sql_digest,
            "timeWindowZh": (
                f"{_format_time(value.window_start)} 至 {_format_time(value.window_end)}"
            ),
            "businessZh": NO_BUSINESS_EVIDENCE_ZH,
            "businessEvidenceIds": [],
        },
        "evidenceSummary": _evidence_summary(hits, leading),
        "reasoning": {
            "ruleFindingsZh": [_finding_text(item) for item in hits],
            "aiContributionZh": None,
            "aiStatus": "not_requested",
            "aiCode": None,
            "aiReasonZh": None,
        },
        "actions": _actions(hits),
        "uncertainty": _uncertainty(
            hits,
            leading,
            list(assessments.values()),
            identity_conflict,
            invalid_roles,
        ),
        "trace": {
            "evidenceLevel": "E2",
            "evidenceCompleteness": leading.completeness,
            "evidenceIds": evidence_ids,
            "ruleIds": [item.rule_id for item in hits],
            "claimIds": [],
            "sourceRevisions": source_revisions,
            "aiInvocation": None,
            "pinnedRevisions": {
                "rulePack": RULE_PACK_REVISION,
                "documentPack": _DOCUMENT_PACK_REVISION,
                "parser": _PARSER_REVISION,
                "policy": _POLICY_REVISION,
                "redaction": _REDACTION_REVISION,
                "provider": None,
                "model": None,
                "prompt": None,
                "payload": None,
                "payloadDigest": None,
            },
        },
    }
    return strict_json_bytes(cast(JsonValue, report))


def _validate_input(value: M0ReportInput) -> int:
    if not isinstance(value, M0ReportInput):
        raise M0ReportError("report input type is invalid")
    _require_pattern(value.case_id, _CASE_ID, "Case ID")
    if not isinstance(value.database, str) or not 1 <= len(value.database) <= 128:
        raise M0ReportError("database name is invalid")
    _require_pattern(value.sql_digest, _SQL_DIGEST, "SQL digest")
    if not isinstance(value.evidence, tuple) or not all(
        isinstance(item, CollectedEvidence) for item in value.evidence
    ):
        raise M0ReportError("evidence must be an immutable CollectedEvidence tuple")
    start = _aware_utc(value.window_start, "window start")
    end = _aware_utc(value.window_end, "window end")
    delta = end - start
    if delta.days < 0 or (delta.days == 0 and delta.seconds == 0):
        raise M0ReportError("report window is not positive")
    if delta.microseconds:
        raise M0ReportError("report window must use whole minutes")
    seconds = delta.days * 86_400 + delta.seconds
    if seconds % 60:
        raise M0ReportError("report window must use whole minutes")
    minutes = seconds // 60
    if not 5 <= minutes <= 60:
        raise M0ReportError("report window is outside the M0 range")
    return minutes


def _read_evidence_bundle(
    value: M0ReportInput,
    window_minutes: int,
) -> tuple[list[_EvidenceRecord], set[str], bool]:
    records: list[_EvidenceRecord] = []
    invalid_roles: set[str] = set()
    seen_ids: set[str] = set()
    for collected in value.evidence:
        role = _peek_role(collected)
        try:
            record = _read_evidence(collected, value=value, window_minutes=window_minutes)
        except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
            if role is not None:
                invalid_roles.add(role)
            continue
        if record.evidence_id in seen_ids:
            invalid_roles.add(record.kind)
            continue
        seen_ids.add(record.evidence_id)
        records.append(record)
    contexts = {
        (record.source_id, record.source_revision, record.profile_subject_ref) for record in records
    }
    return records, invalid_roles, len(contexts) > 1


def _peek_role(collected: CollectedEvidence) -> str | None:
    try:
        value = strict_json_loads(collected.document_json)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return None
    if not isinstance(value, dict):
        return None
    kind = value.get("kind")
    return kind if isinstance(kind, str) and kind in _ROLE_ORDER else None


def _read_evidence(
    collected: CollectedEvidence,
    *,
    value: M0ReportInput,
    window_minutes: int,
) -> _EvidenceRecord:
    loaded = strict_json_loads(collected.document_json)
    document = _require_object(loaded, "Evidence")
    _require_exact_fields(document, _TOP_LEVEL_FIELDS, "Evidence")
    if strict_json_bytes(cast(JsonValue, document)) != collected.document_json:
        raise ValueError("Evidence is not canonical strict JSON")
    if document["schemaVersion"] != "evidence/v2" or document["revision"] != 1:
        raise ValueError("Evidence version is unsupported")
    evidence_id = _require_pattern(document["evidenceId"], _EVIDENCE_ID, "Evidence ID")
    if document["caseId"] != value.case_id:
        raise ValueError("Evidence belongs to another Case")
    subject = _require_pattern(document["profileSubjectRef"], _SUBJECT_ID, "profile subject")
    object_ref = _require_string(document["profileObjectRef"], "profile object", maximum=256)
    if document["origin"] != "managed_source":
        raise ValueError("M0 reports require managed Evidence")
    kind = document["kind"]
    if not isinstance(kind, str) or kind not in _ROLE_ORDER:
        raise ValueError("Evidence kind is outside the M0 rule pack")
    source = _require_object(document["sourceRef"], "Source reference")
    _require_exact_fields(source, {"sourceId", "revision"}, "Source reference")
    source_id = _require_pattern(source["sourceId"], _SOURCE_ID, "Source ID")
    source_revision = _require_integer(source["revision"], "Source revision", 1, 10**12)
    observed_at = _parse_time(document["observedAt"], "observed time")
    collected_at = _parse_time(document["collectedAt"], "collected time")
    if observed_at > collected_at:
        raise ValueError("Evidence was observed after collection")
    freshness = document["freshness"]
    if freshness not in {"fresh", "stale", "unknown"}:
        raise ValueError("Evidence freshness is invalid")
    coverage = document["coverage"]
    if isinstance(coverage, bool) or not isinstance(coverage, (int, float)):
        raise ValueError("Evidence coverage is invalid")
    if isinstance(coverage, float) and not math.isfinite(coverage):
        raise ValueError("Evidence coverage is invalid")
    if not 0 <= coverage <= 1:
        raise ValueError("Evidence coverage is outside the contract range")
    if document["sensitivity"] not in {"public", "metadata", "confidential"}:
        raise ValueError("Evidence sensitivity is invalid")
    _require_string(document["summaryZh"], "Evidence summary", maximum=4096)

    payload = _require_object(document["payload"], "Evidence payload")
    _require_exact_fields(payload, _PAYLOAD_FIELDS, "Evidence payload")
    if payload["extractionRevision"] != "evidence-extractor/v1":
        raise ValueError("Evidence extractor revision is unsupported")
    if payload["canonicalRevision"] != "rfc8785-safe-integer/v1":
        raise ValueError("Evidence canonical revision is unsupported")
    _require_pattern(payload["storageRef"], _STORAGE_ID, "storage reference")
    record_count = _require_integer(payload["recordCount"], "record count", 0, 100_000)
    if not isinstance(payload["truncated"], bool):
        raise ValueError("Evidence truncation flag is invalid")
    raw_digest = _require_pattern(payload["digest"], _SHA256, "payload digest")
    integrity_digest = _require_pattern(document["integrityDigest"], _SHA256, "integrity digest")
    if raw_digest != integrity_digest:
        raise ValueError("Evidence digest fields differ")
    raw_loaded = strict_json_loads(collected.storage_payload)
    _require_object(raw_loaded, "raw Evidence payload")
    actual_raw_digest = f"sha256:{hashlib.sha256(collected.storage_payload).hexdigest()}"
    if actual_raw_digest != raw_digest:
        raise ValueError("raw Evidence digest mismatch")
    typed = _require_object(payload["typed"], "typed Evidence payload")
    _validate_typed_payload(kind, payload["schemaRevision"], typed)
    if payload["typedDigest"] != canonical_sha256(cast(dict[str, JsonValue], typed)):
        raise ValueError("typed Evidence digest mismatch")
    if typed["kind"] != kind:
        raise ValueError("typed Evidence kind differs from envelope")
    if "profileSubjectRef" in typed and typed["profileSubjectRef"] != subject:
        raise ValueError("typed Evidence subject differs from envelope")
    if "profileObjectRef" in typed and typed["profileObjectRef"] != object_ref:
        raise ValueError("typed Evidence object differs from envelope")

    collection = _require_object(document["collection"], "Evidence collection")
    _require_exact_fields(collection, _COLLECTION_FIELDS, "Evidence collection")
    if collection["collectorId"] != "tidb-readonly":
        raise ValueError("Evidence collector is unsupported")
    _require_string(collection["collectorRevision"], "collector revision", maximum=128)
    _require_string(collection["queryId"], "query ID", maximum=128)
    query_revision = _require_string(collection["queryRevision"], "query revision", maximum=128)
    supported_version = query_revision.startswith("tidb-8.5/")
    if collection["status"] not in {"complete", "truncated"}:
        raise ValueError("collection status is invalid")
    if collection["redactionRevision"] != _REDACTION_REVISION:
        raise ValueError("redaction revision is unsupported")
    if payload["truncated"] != (collection["status"] == "truncated"):
        raise ValueError("Evidence truncation states differ")
    budget = _require_object(collection["budget"], "Evidence budget")
    _require_exact_fields(budget, _BUDGET_FIELDS, "Evidence budget")
    timeout = _require_integer(budget["timeoutMs"], "timeout budget", 100, 60_000)
    max_rows = _require_integer(budget["maxRows"], "row budget", 1, 100_000)
    max_bytes = _require_integer(budget["maxBytes"], "byte budget", 1_024, 67_108_864)
    elapsed = _require_integer(budget["elapsedMs"], "elapsed time", 0, 60_000)
    rows_read = _require_integer(budget["rowsRead"], "rows read", 0, 100_000)
    bytes_read = _require_integer(budget["bytesRead"], "bytes read", 0, 67_108_864)
    if elapsed > timeout or rows_read > max_rows or bytes_read > max_bytes:
        raise ValueError("Evidence collection exceeded its budget")
    if record_count != rows_read:
        raise ValueError("Evidence record count differs from rows read")

    sql_level = kind in {"sql_structure", "slow_query", "statement_summary"}
    relevant_identity = not sql_level or object_ref == f"sql:{value.sql_digest}"
    relevant_window = True
    if kind in {"slow_query", "statement_summary"}:
        relevant_window = typed["windowMinutes"] == window_minutes and observed_at == _aware_utc(
            value.window_end, "window end"
        )
    eligible_quality = (
        freshness == "fresh"
        and coverage * 10_000 >= MIN_COVERAGE_BASIS_POINTS
        and payload["truncated"] is False
        and collection["status"] == "complete"
        and supported_version
        and relevant_identity
        and relevant_window
    )
    return _EvidenceRecord(
        evidence_id=evidence_id,
        kind=kind,
        profile_subject_ref=subject,
        profile_object_ref=object_ref,
        source_id=source_id,
        source_revision=source_revision,
        observed_at=observed_at,
        eligible_quality=eligible_quality,
        typed=cast(Mapping[str, JsonValue], typed),
    )


def _validate_typed_payload(kind: str, revision: object, typed: Mapping[str, object]) -> None:
    validators = {
        "sql_structure": ("sql-structure/v1", _validate_sql_structure),
        "ordinary_plan": ("ordinary-plan/v2", _validate_ordinary_plan),
        "index": ("index-metadata/v2", _validate_index),
        "statistics": ("statistics-health/v1", _validate_statistics),
        "statement_summary": ("statement-summary/v3", _validate_statement_summary),
        "slow_query": ("slow-query/v2", _validate_slow_query),
    }
    expected_revision, validator = validators[kind]
    if revision != expected_revision:
        raise ValueError("typed Evidence revision is outside the M0 rule pack")
    validator(typed)


def _validate_sql_structure(typed: Mapping[str, object]) -> None:
    _require_exact_fields(
        typed,
        {"kind", "statementType", "tables", "predicateColumns"},
        "SQL structure payload",
    )
    if typed["kind"] != "sql_structure" or typed["statementType"] != "select":
        raise ValueError("SQL structure is not a SELECT")
    _require_string_list(typed["tables"], "SQL tables", maximum_items=64, allow_empty=True)
    _require_string_list(
        typed["predicateColumns"],
        "predicate columns",
        maximum_items=128,
        allow_empty=True,
    )


def _validate_ordinary_plan(typed: Mapping[str, object]) -> None:
    _require_exact_fields(
        typed,
        {"kind", "profileSubjectRef", "profileObjectRef", "tableName", "accessPath"},
        "ordinary plan payload",
    )
    _validate_typed_identity(typed, "ordinary_plan")
    table = _require_string(typed["tableName"], "plan table", maximum=128)
    if typed["profileObjectRef"] != table:
        raise ValueError("ordinary plan object differs from table")
    if typed["accessPath"] not in {
        "table_full_scan",
        "index_full_scan",
        "index_range_scan",
        "point_get",
        "other",
    }:
        raise ValueError("ordinary plan access path is invalid")


def _validate_index(typed: Mapping[str, object]) -> None:
    _require_exact_fields(
        typed,
        {
            "kind",
            "profileSubjectRef",
            "profileObjectRef",
            "tableName",
            "filterColumns",
            "indexCoverage",
        },
        "index payload",
    )
    _validate_typed_identity(typed, "index")
    table = _require_string(typed["tableName"], "index table", maximum=128)
    if typed["profileObjectRef"] != table:
        raise ValueError("index object differs from table")
    _require_string_list(typed["filterColumns"], "filter columns", maximum_items=32)
    if typed["indexCoverage"] not in {
        "matching_composite_index",
        "no_matching_composite_index",
        "unknown",
    }:
        raise ValueError("index coverage is invalid")


def _validate_statistics(typed: Mapping[str, object]) -> None:
    _require_exact_fields(
        typed,
        {"kind", "profileSubjectRef", "profileObjectRef", "tableName", "healthyPercent"},
        "statistics payload",
    )
    _validate_typed_identity(typed, "statistics")
    table = _require_string(typed["tableName"], "statistics table", maximum=128)
    if typed["profileObjectRef"] != table:
        raise ValueError("statistics object differs from table")
    _require_integer(typed["healthyPercent"], "healthy percent", 0, 100)


def _validate_statement_summary(typed: Mapping[str, object]) -> None:
    _require_exact_fields(
        typed,
        {
            "kind",
            "profileSubjectRef",
            "profileObjectRef",
            "windowMinutes",
            "executionCount",
            "averageTotalKeys",
            "averageProcessedKeys",
            "weightedTotalKeys",
            "sqlStability",
        },
        "Statement Summary payload",
    )
    _validate_typed_identity(typed, "statement_summary")
    _require_pattern(typed["profileObjectRef"], re.compile(r"^sql:[a-f0-9]{64}$"), "SQL object")
    _require_integer(typed["windowMinutes"], "summary window", 1, 1_440)
    _require_integer(typed["executionCount"], "execution count", 1, 9_007_199_254_740_991)
    for name in ("averageTotalKeys", "averageProcessedKeys", "weightedTotalKeys"):
        _require_integer(typed[name], name, 0, 9_007_199_254_740_991)
    if typed["sqlStability"] not in {"plan_and_scan_stable", "plan_changed", "unknown"}:
        raise ValueError("Statement Summary stability is invalid")


def _validate_slow_query(typed: Mapping[str, object]) -> None:
    _require_exact_fields(
        typed,
        {
            "kind",
            "profileSubjectRef",
            "profileObjectRef",
            "windowMinutes",
            "callCount",
            "p95Ms",
            "averageScanRows",
            "averageReturnRows",
        },
        "Slow Query payload",
    )
    _validate_typed_identity(typed, "slow_query")
    _require_pattern(typed["profileObjectRef"], re.compile(r"^sql:[a-f0-9]{64}$"), "SQL object")
    _require_integer(typed["windowMinutes"], "slow query window", 1, 1_440)
    _require_integer(typed["callCount"], "call count", 1, 1_000_000_000)
    _require_integer(typed["p95Ms"], "P95 latency", 1, 3_600_000)
    _require_integer(typed["averageScanRows"], "average scan rows", 1, 1_000_000_000_000)
    _require_integer(
        typed["averageReturnRows"],
        "average return rows",
        1,
        1_000_000_000_000,
    )


def _validate_typed_identity(typed: Mapping[str, object], expected_kind: str) -> None:
    if typed["kind"] != expected_kind:
        raise ValueError("typed Evidence kind is invalid")
    _require_pattern(typed["profileSubjectRef"], _SUBJECT_ID, "typed profile subject")
    _require_string(typed["profileObjectRef"], "typed profile object", maximum=256)


type RoleSelector = Callable[[str], _EvidenceRecord | None]


def _assess_index(select: RoleSelector) -> _Assessment:
    roles = ("sql_structure", "ordinary_plan", "index", "slow_query")
    eligible = _correlated_roles(select, roles)
    if all(role in eligible for role in roles):
        slow = eligible["slow_query"].typed
        structure = eligible["sql_structure"].typed
        plan = eligible["ordinary_plan"].typed
        index = eligible["index"].typed
        hit = (
            plan["accessPath"] == "table_full_scan"
            and index["indexCoverage"] == "no_matching_composite_index"
            and index["filterColumns"] == structure["predicateColumns"]
            and cast(int, slow["averageScanRows"]) >= 10_000
            and cast(int, slow["averageScanRows"])
            >= 100 * max(cast(int, slow["averageReturnRows"]), 1)
            and cast(int, slow["callCount"]) >= 3
        )
    else:
        hit = False
    return _Assessment(INDEX_RULE_ID, roles, eligible, hit)


def _assess_statistics(select: RoleSelector) -> _Assessment:
    roles = ("sql_structure", "statistics")
    eligible = _correlated_roles(select, roles)
    hit = (
        all(role in eligible for role in roles)
        and cast(int, eligible["statistics"].typed["healthyPercent"]) < 80
    )
    return _Assessment(STATISTICS_RULE_ID, roles, eligible, hit)


def _assess_repeated_placeholder(select: RoleSelector) -> _Assessment:
    roles = ("statement_summary", "slow_query")
    eligible = _correlated_roles(select, roles)
    return _Assessment(REPEATED_SCAN_RULE_ID, roles, eligible, False)


def _correlated_roles(
    select: RoleSelector,
    roles: tuple[str, ...],
) -> dict[str, _EvidenceRecord]:
    chosen = {role: select(role) for role in roles}
    eligible = {
        role: record for role, record in chosen.items() if isinstance(record, _EvidenceRecord)
    }
    structure = eligible.get("sql_structure")
    table: str | None = None
    if structure is not None:
        tables = structure.typed["tables"]
        if isinstance(tables, list) and len(tables) == 1 and isinstance(tables[0], str):
            table = tables[0]
        else:
            eligible.pop("sql_structure", None)
    for role in ("ordinary_plan", "index", "statistics"):
        record = eligible.get(role)
        if record is not None and (
            table is None
            or record.profile_object_ref != table
            or record.typed["tableName"] != table
        ):
            eligible.pop(role)
    return eligible


def _priority(
    hits: list[_Assessment],
    select: RoleSelector,
) -> str:
    if not hits:
        return "observe"
    slow = select("slow_query")
    summary = select("statement_summary")
    if (
        slow is not None
        and summary is not None
        and (
            slow.source_id,
            slow.source_revision,
            slow.profile_subject_ref,
            slow.profile_object_ref,
        )
        == (
            summary.source_id,
            summary.source_revision,
            summary.profile_subject_ref,
            summary.profile_object_ref,
        )
        and cast(int, slow.typed["p95Ms"]) >= 5_000
        and cast(int, summary.typed["executionCount"]) >= 20
    ):
        return "P1"
    return "P2"


def _title(hits: list[_Assessment]) -> str:
    if not hits:
        return "现有证据不足以发布异常 SQL 处置结论"
    titles = {
        INDEX_RULE_ID: "发现高扫描放大全表扫描，先验证访问路径",
        STATISTICS_RULE_ID: "发现统计健康度风险，先由 DBA 复核统计信息",
        REPEATED_SCAN_RULE_ID: "发现重复重扫描热点，先控制调用与访问路径",
    }
    return titles[hits[0].rule_id]


def _conclusion(hits: list[_Assessment]) -> str:
    if not hits:
        return "当前合格证据未同时满足任一 M0 规则阈值，因此不发布根因或变更建议。"
    texts: list[str] = []
    for assessment in hits:
        if assessment.rule_id == INDEX_RULE_ID:
            text = (
                "该 SQL 存在高扫描放大，普通计划显示全表扫描，且未找到匹配过滤列前缀的"
                "复合索引；是否新增索引仍需在代表性数据上验证。"
            )
        elif assessment.rule_id == STATISTICS_RULE_ID:
            statistics = assessment.eligible["statistics"].typed
            text = (
                f"{statistics['tableName']} 表统计健康度为 "
                f"{statistics['healthyPercent']}%，统计质量可能影响优化器估算；"
                "尚不能据此判断执行计划估算是否准确。"
            )
        else:
            text = "重复执行将一次重扫描放大为窗口内热点，尚未推断 CPU、I/O 或业务影响。"
        texts.append(text)
    return "；".join(texts)


def _finding_text(assessment: _Assessment) -> str:
    if assessment.rule_id == INDEX_RULE_ID:
        return (
            "该 SQL 的实测扫描放大达到规则阈值，普通计划为全表扫描，且未找到匹配过滤列"
            "前缀的复合索引。"
        )
    if assessment.rule_id == STATISTICS_RULE_ID:
        typed = assessment.eligible["statistics"].typed
        return (
            f"{typed['tableName']} 表统计健康度低于 M0 的 80% 检查阈值；统计质量可能影响"
            "优化器估算，需由 DBA 复核。"
        )
    return "重复执行将一次重扫描放大为窗口内热点。"


def _evidence_summary(
    hits: list[_Assessment],
    leading: _Assessment,
) -> list[dict[str, JsonValue]]:
    if not hits:
        missing = "、".join(_ROLE_LABELS[role] for role in leading.missing_roles)
        value = f"最完整规则具备 {len(leading.eligible)}/{len(leading.required_roles)} 项必需证据"
        if missing:
            value += f"；缺少或不可用：{missing}"
        return [{"labelZh": "证据完整度", "valueZh": value, "evidenceIds": []}]
    summaries: list[dict[str, JsonValue]] = []
    for assessment in hits:
        ids = sorted(record.evidence_id for record in assessment.eligible.values())
        if assessment.rule_id == INDEX_RULE_ID:
            slow = assessment.eligible["slow_query"].typed
            table = assessment.eligible["ordinary_plan"].typed["tableName"]
            summaries.append(
                {
                    "labelZh": "扫描与访问路径",
                    "valueZh": (
                        f"{table} 表为全表扫描；平均扫描 {slow['averageScanRows']} 行、返回 "
                        f"{slow['averageReturnRows']} 行，窗口内调用 {slow['callCount']} 次"
                    ),
                    "evidenceIds": cast(list[JsonValue], ids),
                }
            )
        elif assessment.rule_id == STATISTICS_RULE_ID:
            typed = assessment.eligible["statistics"].typed
            summaries.append(
                {
                    "labelZh": "统计健康度",
                    "valueZh": (
                        f"{typed['tableName']} 表 SHOW STATS_HEALTHY 为 {typed['healthyPercent']}%"
                    ),
                    "evidenceIds": cast(list[JsonValue], ids),
                }
            )
    return summaries


def _actions(hits: list[_Assessment]) -> list[dict[str, JsonValue]]:
    actions: list[dict[str, JsonValue]] = []
    for assessment in hits:
        if assessment.rule_id == INDEX_RULE_ID:
            slow = assessment.eligible["slow_query"].typed
            scan_target = max(1, cast(int, slow["averageScanRows"]) // 10)
            action: dict[str, JsonValue] = {
                "actionId": "act_m0indexscanrisk001",
                "order": 0,
                "titleZh": "先验证访问路径与复合索引候选",
                "rationaleZh": (
                    "全表扫描、扫描放大与索引覆盖证据同时命中，但新增索引的收益和写入代价仍需实测。"
                ),
                "ownerRole": "dba",
                "risk": "medium",
                "prerequisitesZh": ["准备代表性参数与数据分布", "确认索引空间和写放大预算"],
                "stepsZh": [
                    "复核普通 EXPLAIN 与现有索引列顺序",
                    "仅在隔离或受控灰度环境创建候选索引并运行同一参数分布",
                ],
                "validation": {
                    "metricZh": "扫描行数、P95 延迟与写入开销",
                    "targetZh": (
                        f"平均扫描行数降至不高于 {scan_target} 行，SQL P95 不高于当前 "
                        f"{slow['p95Ms']} ms 基线；写入 P95 不高于灰度前冻结基线的 110%"
                    ),
                },
                "rollbackZh": [
                    "若收益不足或写入回归超阈值，停止灰度",
                    "确认无其他负载依赖后，仅删除本次新建的候选索引",
                ],
            }
        elif assessment.rule_id == STATISTICS_RULE_ID:
            action = {
                "actionId": "act_m0statisticsrisk01",
                "order": 0,
                "titleZh": "复核并受控刷新目标表统计信息",
                "rationaleZh": (
                    "SHOW STATS_HEALTHY 低于 M0 检查阈值，只能说明统计质量风险，不能直接"
                    "证明估算偏差。"
                ),
                "ownerRole": "dba",
                "risk": "medium",
                "prerequisitesZh": [
                    "确认统计信息更新时间与数据变更窗口",
                    "保存刷新前计划与统计元数据",
                ],
                "stepsZh": [
                    "由 DBA 复核统计元数据及采样策略",
                    "如符合运维窗口，在 SQLLens 外执行经批准的目标表统计刷新",
                    "SQLLens 不执行 ANALYZE、DDL 或任何自动变更",
                ],
                "validation": {
                    "metricZh": "普通计划选择与代表性参数 P95 延迟",
                    "targetZh": (
                        "SHOW STATS_HEALTHY 恢复至不低于 80%，普通计划不退化，"
                        "代表性参数 P95 不高于刷新前基线"
                    ),
                },
                "rollbackZh": [
                    "按运维方既有流程恢复刷新前统计或绑定",
                    "若计划退化立即停止后续推广",
                ],
            }
        else:
            continue
        action["order"] = len(actions) + 1
        if not any(existing["stepsZh"] == action["stepsZh"] for existing in actions):
            actions.append(action)
        if len(actions) == 3:
            break
    return actions


def _uncertainty(
    hits: list[_Assessment],
    leading: _Assessment,
    assessments: list[_Assessment],
    identity_conflict: bool,
    invalid_roles: set[str],
) -> list[str]:
    if hits:
        items = [NO_BUSINESS_EVIDENCE_ZH]
        if any(item.rule_id == INDEX_RULE_ID for item in hits):
            items.append("当前证据未覆盖全部参数分布，索引收益与写入代价必须受控验证。")
        if any(item.rule_id == STATISTICS_RULE_ID for item in hits):
            items.append("统计健康度不是估算偏差实测值，刷新是否有益必须通过计划和延迟验证。")
        return items
    if identity_conflict:
        return [
            "证据来自不同 Source revision 或 profile subject，无法安全关联；请重新采集同一诊断。"
        ]
    if leading.completeness == 100:
        return ["现有合格证据未同时达到任一规则阈值；不发布根因、置信度或处置动作。"]
    required_roles = {role for assessment in assessments for role in assessment.required_roles}
    missing = {role for assessment in assessments for role in assessment.missing_roles} | (
        invalid_roles & required_roles
    )
    if missing:
        ordered = [role for role in _ROLE_ORDER if role in missing]
        labels = "、".join(_ROLE_LABELS[role] for role in ordered)
        return [f"缺少或不可用的证据角色：{labels}；请在同一诊断窗口重新采集。"]
    return ["现有合格证据未同时达到任一规则阈值；不发布根因、置信度或处置动作。"]


def _require_exact_fields(value: Mapping[str, object], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ValueError(f"{label} fields differ from the closed contract")


def _require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _require_string(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _require_pattern(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _require_integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside the integer contract")
    return value


def _require_string_list(
    value: object,
    label: str,
    *,
    maximum_items: int,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or not (0 if allow_empty else 1) <= len(value) <= maximum_items:
        raise ValueError(f"{label} is outside the list contract")
    if not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in value):
        raise ValueError(f"{label} contains an invalid value")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} contains duplicates")
    return cast(list[str], value)


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339_DATETIME.fullmatch(value):
        raise ValueError(f"{label} is not RFC3339")
    normalized = value[:10] + "T" + value[11:]
    if normalized[-1] in {"Z", "z"}:
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    return _aware_utc(parsed, label)


def _aware_utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return _aware_utc(value, "report time").isoformat().replace("+00:00", "Z")
