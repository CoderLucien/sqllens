from __future__ import annotations

import copy
import re
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, RefResolver
from vnext_canonical_json import (
    canonical_sha256,
    reject_non_finite_json,
    strict_json_loads,
)
from vnext_diagnosis_policy import (
    DIAGNOSIS_DEPENDENCY_REGISTRY,
    EVIDENCE_LEVELS,
    FACT_CANDIDATE_IDENTITY_REGISTRY,
    FACT_DEPENDENCY_REGISTRY,
    derive_completeness,
    derive_evidence_level,
    evidence_candidate_identity,
    evidence_eligibility_reasons,
    evidence_profile_values,
    expected_rule_findings,
    expected_uncertainty,
    require_eligible,
    validate_evidence_object_identity,
    validate_gap_fact,
    validate_policy_pins,
)
from vnext_outcome_policy import validate_outcome_policy
from vnext_source_ledger import replay_source_history

ROOT = Path(__file__).parent
EXAMPLES = ROOT / "examples"
FORMAT_CHECKER = FormatChecker()
SCHEMA_NAMES = (
    "source-v1.schema.json",
    "evidence-v2.schema.json",
    "diagnosis-case-v2.schema.json",
    "diagnosis-report-v1.schema.json",
)
CASE_NAMES = (
    "diagnosis-case-v2.valid.json",
    "diagnosis-case-v2.statistics.valid.json",
    "diagnosis-case-v2.runtime-correlation.valid.json",
)
REPORT_NAMES = (
    "diagnosis-report-v1.index-access.review.json",
    "diagnosis-report-v1.statistics.review.json",
    "diagnosis-report-v1.runtime-correlation.review.json",
)
M0_REPORT_EXPECTATIONS = (
    (
        "diagnosis-report-v1.m0-index-scan.review.json",
        "TIDB85_INDEX_SCAN_RISK",
        "P2",
    ),
    (
        "diagnosis-report-v1.m0-statistics-health.review.json",
        "TIDB85_STATISTICS_HEALTH_RISK",
        "P2",
    ),
    (
        "diagnosis-report-v1.m0-repeated-scan.review.json",
        "TIDB85_REPEATED_HEAVY_SCAN",
        "P1",
    ),
)
WORKFLOW_TRANSITIONS = {
    "queued": {"queued", "collecting", "failed", "cancelled"},
    "collecting": {"collecting", "analyzing", "failed", "cancelled"},
    "analyzing": {"analyzing", "ready", "failed", "cancelled"},
    "ready": {"ready"},
    "failed": {"failed"},
    "cancelled": {"cancelled"},
}
OUTCOME_TRANSITIONS = {
    "pending": {
        "pending",
        "validated_effective",
        "rolled_back",
        "evidence_insufficient",
        "risk_accepted",
    },
    "validated_effective": set(),
    "rolled_back": set(),
    "evidence_insufficient": set(),
    "risk_accepted": set(),
}
SOURCE_STATE_TRANSITIONS = {
    "draft": {"draft", "enabled", "verification_failed", "draining"},
    "enabled": {"enabled", "draining"},
    "draining": {
        "draining",
        "enabled",
        "disabled",
        "verification_failed",
        "tombstoned",
    },
    "disabled": {"disabled", "enabled", "draining"},
    "verification_failed": {"verification_failed", "draft", "enabled", "draining"},
    "tombstoned": {"tombstoned"},
}
SOURCE_AUDIT_TRANSITIONS = {
    "registered": {(None, "draft")},
    "verified": {("draft", "draft"), ("verification_failed", "draft")},
    "enabled": {("draft", "enabled"), ("disabled", "enabled")},
    "edited": {
        ("draft", "draft"),
        ("enabled", "enabled"),
        ("disabled", "disabled"),
        ("verification_failed", "verification_failed"),
    },
    "leases_updated": {("enabled", "enabled")},
    "rotation_started": {("enabled", "draining")},
    "rotation_completed": {("draining", "enabled")},
    "disable_started": {("enabled", "draining")},
    "disabled": {("draining", "disabled")},
    "delete_started": {("enabled", "draining"), ("disabled", "draining")},
    "leases_drained": {("draining", "draining")},
    "tombstoned": {("draining", "tombstoned")},
    "verification_failure_started": {("enabled", "draining")},
    "verification_failed": {
        ("draft", "verification_failed"),
        ("draining", "verification_failed"),
    },
}
SOURCE_OPERATION_ACTORS = {
    "registered": "user",
    "verified": "system",
    "enabled": "user",
    "edited": "user",
    "leases_updated": "system",
    "rotation_started": "user",
    "rotation_completed": "system",
    "disable_started": "user",
    "disabled": "system",
    "delete_started": "user",
    "leases_drained": "system",
    "tombstoned": "system",
    "verification_failure_started": "system",
    "verification_failed": "system",
}
AI_CLAIM_TEMPLATES = {
    ("ai.index_candidate_priority", "v1"): (
        {
            "preferredActionFamily": "index_candidate",
            "deprioritizedActionFamily": "resource_investigation",
        },
        "该 SQL 是当前窗口的主要可行动瓶颈；应先在隔离环境验证复合索引候选，而不是调整集群资源。",
    ),
    ("ai.resource_hotspot_priority", "v1"): (
        {
            "preferredActionFamily": "resource_investigation",
            "causality": "correlated_not_proven",
        },
        "SQL、Prometheus 和 TEM 的时间窗关系支持优先调查 TiKV 热点，但相关性不等于已证明物理因果。",
    ),
}
AI_STATUS_TEMPLATES = {
    ("not_requested", "AI_NOT_REQUESTED"): ("此诊断配置为仅规则模式，未调用外部模型。"),
    ("abstained", "EVIDENCE_POLICY_ABSTENTION"): (
        "证据策略不允许调用外部模型，本报告仅使用确定性规则。"
    ),
    ("degraded", "MODEL_TIMEOUT"): (
        "外部模型超时，本报告使用确定性规则生成；事实、动作和证据不受影响。"
    ),
    ("degraded", "PROVIDER_ERROR"): (
        "外部模型服务不可用，本报告使用确定性规则生成；事实、动作和证据不受影响。"
    ),
    ("degraded", "INVALID_MODEL_OUTPUT"): (
        "外部模型输出未通过证据约束校验，本报告使用确定性规则生成。"
    ),
}
EVIDENCE_SCHEMA_REVISIONS = {
    "business_observation": frozenset({"business-observation/v1"}),
    "sql_structure": frozenset({"sql-structure/v1"}),
    "statement_summary": frozenset({"statement-summary/v2", "statement-summary/v3"}),
    "slow_query": frozenset({"slow-query/v2"}),
    "schema": frozenset({"schema-metadata/v1"}),
    "index": frozenset({"index-metadata/v2"}),
    "statistics": frozenset({"statistics-health/v1", "statistics-health/v2"}),
    "ordinary_plan": frozenset({"ordinary-plan/v2"}),
    "runtime_metric": frozenset({"prometheus-window/v2"}),
    "alert": frozenset({"tem-alert/v2"}),
    "validation_result": frozenset({"validation-result/v1"}),
    "effect_metric_comparison": frozenset({"effect-metric-comparison/v2"}),
    "rollback_confirmation": frozenset({"rollback-confirmation/v1"}),
}
NO_BUSINESS_EVIDENCE_ZH = "未提供业务影响证据，仅说明数据库技术影响"
RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:"
    r"(?:[0-5]\d|60)(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)

# This fixture models a server-owned authorization audit store. It is not part
# of the caller-controlled Case payload; runtime validation must resolve the
# opaque record ID from an authenticated server-side ledger.
SERVER_AUTHORIZATION_AUDIT_FIXTURES = {
    "authz_0000000000000001": {
        "auditRecordId": "authz_0000000000000001",
        "attestationRevision": "server-authorization-audit/v1",
        "caseId": "case_0000000000000002",
        "caseRevision": 2,
        "actionId": "act_0000000000000001",
        "actionDigest": "sha256:54c28de30bace7de68e0f9f14a8c8fecff0eb52fdcc690f09bac3bfdb3647bc6",
        "reviewId": "rev_0000000000000001",
        "principalId": "owner",
        "role": "owner",
        "permission": "approve_diagnosis_action",
        "authorizationRevision": "owner-action-approval/v2",
        "capturedAt": "2026-09-02T08:05:59Z",
    }
}


def resolve_authorization_audit(record_id: str) -> dict[str, Any] | None:
    record = SERVER_AUTHORIZATION_AUDIT_FIXTURES.get(record_id)
    return copy.deepcopy(record) if record is not None else None


def load(path: Path) -> dict[str, Any]:
    loaded = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError(f"JSON contract document must be an object: {path}")
    return loaded


SCHEMAS = {name: load(ROOT / name) for name in SCHEMA_NAMES}
SCHEMA_STORE = {schema["$id"]: schema for schema in SCHEMAS.values()}


def parse_time(value: str) -> datetime:
    if not RFC3339_DATETIME.fullmatch(value):
        raise ValueError(f"invalid RFC 3339 date-time: {value!r}")
    normalized = value[:10] + "T" + value[11:]
    if normalized[-1] in {"Z", "z"}:
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized)


def schema_validator(name: str) -> Draft202012Validator:
    schema = SCHEMAS[name]
    Draft202012Validator.check_schema(schema)
    resolver = RefResolver.from_schema(schema, store=SCHEMA_STORE)
    return Draft202012Validator(
        schema,
        resolver=resolver,
        format_checker=FORMAT_CHECKER,
    )


def validate_schema(schema_name: str, example_names: list[str]) -> list[dict[str, Any]]:
    validator = schema_validator(schema_name)
    examples: list[dict[str, Any]] = []
    for name in example_names:
        example = load(EXAMPLES / name)
        validator.validate(example)
        examples.append(example)
    return examples


def require_unique(items: list[dict[str, Any]], field: str) -> set[str]:
    values = [str(item[field]) for item in items]
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {field}")
    return set(values)


def validate_source_audit(source: dict[str, Any]) -> None:
    require_unique(source["transitionEvents"], "eventId")
    source_created = parse_time(source["createdAt"])
    source_updated = parse_time(source["updatedAt"])
    previous_state: str | None = None
    previous_time: datetime | None = None
    previous_revision = 0
    previous_credential_revision = 0

    for index, event in enumerate(source["transitionEvents"]):
        event_at = parse_time(event["createdAt"])
        if not source_created <= event_at <= source_updated:
            raise ValueError(
                "Source transition event is outside the Source time window"
            )
        if previous_time is not None and event_at < previous_time:
            raise ValueError("Source transition events must be chronological")
        if event["sourceRevision"] != previous_revision + 1:
            raise ValueError("Source transition revisions must increase by exactly one")
        if event["sourceRevision"] > source["revision"]:
            raise ValueError("Source transition references a future revision")
        if index == 0 and event["fromState"] is not None:
            raise ValueError("Source audit must start from an unregistered state")
        if event["fromState"] != previous_state:
            raise ValueError("Source transition audit is discontinuous")
        transition = (event["fromState"], event["toState"])
        if transition not in SOURCE_AUDIT_TRANSITIONS[event["operation"]]:
            raise ValueError("Source operation does not match audited state transition")
        if event["actor"]["kind"] != SOURCE_OPERATION_ACTORS[event["operation"]]:
            raise ValueError("Source operation actor is not authoritative")

        credential_revision = event["credentialRevision"]
        if credential_revision is not None:
            if credential_revision < previous_credential_revision:
                raise ValueError("Source audit credential revision decreased")
            previous_credential_revision = credential_revision
        previous_state = event["toState"]
        previous_time = event_at
        previous_revision = event["sourceRevision"]

    if previous_state != source["state"]:
        raise ValueError("latest Source transition does not match current state")
    if previous_revision != source["revision"]:
        raise ValueError("current Source revision lacks a transition audit event")
    if (
        source["transitionEvents"][-1]["credentialRevision"]
        != source["auth"]["credentialRevision"]
    ):
        raise ValueError(
            "latest Source audit credential revision differs from snapshot"
        )


def validate_source_lease_audit(source: dict[str, Any]) -> None:
    require_unique(source["leaseEvents"], "eventId")
    require_unique(source["activeLeases"], "leaseId")
    require_unique(source["activeLeases"], "jobId")
    source_created = parse_time(source["createdAt"])
    source_updated = parse_time(source["updatedAt"])
    previous_time: datetime | None = None
    active: dict[str, dict[str, Any]] = {}
    seen_lease_ids: set[str] = set()
    seen_job_ids: set[str] = set()
    for event in source["leaseEvents"]:
        event_at = parse_time(event["createdAt"])
        if not source_created <= event_at <= source_updated:
            raise ValueError("Source lease event is outside the Source time window")
        if previous_time is not None and event_at < previous_time:
            raise ValueError("Source lease events must be chronological")
        if event["sourceRevision"] > source["revision"]:
            raise ValueError("Source lease event references a future revision")
        if event["fromLeaseCount"] != len(active):
            raise ValueError("Source lease ledger count chain is discontinuous")
        if event["actor"]["kind"] != "system":
            raise ValueError(
                "Source lease ledger events must be emitted by the runtime"
            )
        approval = event["ownerApproval"]
        if event["operation"] == "lease_acquired":
            if event["leaseId"] in seen_lease_ids or event["jobId"] in seen_job_ids:
                raise ValueError("Source lease acquisition reuses an audit identity")
            if event["toLeaseCount"] != event["fromLeaseCount"] + 1:
                raise ValueError("lease acquisition must add exactly one active lease")
            if approval is not None:
                raise ValueError("lease acquisition cannot carry Owner approval")
            active[event["leaseId"]] = {
                "leaseId": event["leaseId"],
                "jobId": event["jobId"],
                "acquiredRevision": event["sourceRevision"],
                "acquiredAt": event["createdAt"],
            }
            seen_lease_ids.add(event["leaseId"])
            seen_job_ids.add(event["jobId"])
            previous_time = event_at
            continue

        if event["leaseId"] not in active:
            raise ValueError("Source lease release references an inactive lease")
        if active[event["leaseId"]]["jobId"] != event["jobId"]:
            raise ValueError("Source lease release job differs from acquisition")
        if event["toLeaseCount"] != event["fromLeaseCount"] - 1:
            raise ValueError("lease release must remove exactly one active lease")
        if event["operation"] == "lease_released" and approval is not None:
            raise ValueError(
                "ordinary lease release cannot carry force-cancel approval"
            )
        if event["operation"] == "lease_force_cancelled":
            if (
                approval is None
                or approval["approvedBy"]["kind"] != "user"
                or approval["approvedBy"].get("role") != "owner"
            ):
                raise ValueError("force-cancelled lease requires Owner approval")
            approved_at = parse_time(approval["approvedAt"])
            if not source_created <= approved_at <= event_at:
                raise ValueError("force-cancel approval must precede the lease event")
        del active[event["leaseId"]]
        previous_time = event_at

    snapshot = {item["leaseId"]: item for item in source["activeLeases"]}
    if snapshot != active:
        raise ValueError("Source active lease snapshot differs from replayed ledger")
    if source["credentialLifecycle"]["activeLeaseCount"] != len(active):
        raise ValueError("Source activeLeaseCount differs from authoritative ledger")


def typed_payload_digest(value: dict[str, Any]) -> str:
    return canonical_sha256(value)


def join_zh(values: list[str]) -> str:
    if len(values) == 1:
        return values[0]
    return f"{'、'.join(values[:-1])} 与 {values[-1]}"


def format_ms(value: int) -> str:
    if value < 1000:
        return f"{value} ms"
    seconds = Decimal(value) / Decimal(1000)
    return f"{format(seconds.normalize(), 'f')} 秒"


def render_evidence_summary(evidence: dict[str, Any]) -> str:
    typed = evidence["payload"]["typed"]
    kind = evidence["kind"]
    if kind == "business_observation":
        return typed["textZh"]
    if kind == "sql_structure":
        tables = join_zh(typed["tables"]) if typed["tables"] else "未识别表"
        predicates = (
            join_zh(typed["predicateColumns"])
            if typed["predicateColumns"]
            else "未识别过滤列"
        )
        return (
            f"SQL 结构解析为 {typed['statementType'].upper()}，涉及 {tables}；"
            f"过滤列为 {predicates}。"
        )
    if kind == "statement_summary":
        if evidence["payload"]["schemaRevision"] == "statement-summary/v3":
            return (
                f"该 SQL 在 {typed['windowMinutes']} 分钟窗口内执行 "
                f"{typed['executionCount']} 次，按聚合字段计算共读取 "
                f"{typed['weightedTotalKeys']} 个键。"
            )
        return {
            "plan_and_scan_stable": "SQL 计划摘要和扫描行数与前一基线窗口接近。",
            "plan_changed": "SQL 计划摘要相对前一基线窗口发生变化。",
            "scan_changed": "SQL 扫描行数相对前一基线窗口发生变化。",
            "unknown": "当前 Statement Summary 证据不足以判断计划和扫描稳定性。",
        }[typed["sqlStability"]]
    if kind == "slow_query":
        scan_ten_thousands = format_derived_ratio(typed["averageScanRows"], 10000)
        return (
            f"该 SQL 在 {typed['windowMinutes']} 分钟窗口内执行 "
            f"{typed['callCount']} 次，P95 {format_ms(typed['p95Ms'])}，"
            f"平均扫描 {scan_ten_thousands} 万行。"
        )
    if kind == "schema":
        return f"Schema 元数据包含表 {join_zh(typed['tableNames'])}。"
    if kind == "index":
        filters = join_zh(typed["filterColumns"])
        if typed["indexCoverage"] == "matching_composite_index":
            return f"现有复合索引覆盖 {filters} 的过滤顺序。"
        if typed["indexCoverage"] == "no_matching_composite_index":
            return f"现有索引没有同时覆盖 {filters} 的过滤顺序。"
        return f"当前证据无法确认是否存在覆盖 {filters} 的复合索引。"
    if kind == "statistics":
        if evidence["payload"]["schemaRevision"] == "statistics-health/v1":
            return f"{typed['tableName']} 表统计健康度为 {typed['healthyPercent']}%。"
        freshness = {
            "current": "统计信息处于当前窗口",
            "predates_bulk_import": "统计更新时间早于最近一次大批量导入",
            "stale": "统计信息已过期",
            "unknown": "统计信息新鲜度未知",
        }[typed["statisticsFreshness"]]
        return (
            f"{typed['tableName']} 表 estRows 为 {typed['estimatedRows']}、运行时 rows 为 "
            f"{typed['actualRows']}，且{freshness}。"
        )
    if kind == "ordinary_plan":
        if typed["accessPath"] == "table_full_scan":
            return (
                f"普通执行计划显示 {typed['tableName']} 表发生 TableFullScan，"
                "过滤条件未形成可用访问路径。"
            )
        access_path = {
            "index_full_scan": "IndexFullScan",
            "index_range_scan": "IndexRangeScan",
            "point_get": "PointGet",
            "other": "其他访问路径",
        }[typed["accessPath"]]
        return f"普通执行计划显示 {typed['tableName']} 表使用 {access_path}。"
    if kind == "runtime_metric":
        return {
            "same_window_elevated": "TiKV 请求延迟和 Region 热点指标在 SQL 异常时间窗内同步升高。",
            "not_correlated": "TiKV 请求延迟和 Region 热点指标未与 SQL 异常时间窗同步升高。",
            "unknown": "当前运行指标不足以判断与 SQL 异常时间窗的关系。",
        }[typed["resourceCorrelation"]]
    if kind == "alert":
        return {
            "cluster_component_window_match": "TEM 告警的集群、TiKV 组件与异常时间窗匹配。",
            "partial_match": "TEM 告警仅与异常集群、组件或时间窗部分匹配。",
            "not_matched": "TEM 告警未与异常集群、组件和时间窗匹配。",
            "unknown": "当前告警证据不足以判断与异常时间窗的关系。",
        }[typed["alertScope"]]
    if kind == "validation_result":
        status = {
            "passed": "通过",
            "failed": "失败",
            "inconclusive": "无法判断",
        }[typed["status"]]
        return f"验证检查 {typed['checkId']} 的结果为{status}。"
    if kind == "effect_metric_comparison":
        metric_zh = {
            "p95_latency_ms": "P95 延迟",
            "average_scan_rows": "平均扫描行数",
            "write_regression_basis_points": "写入开销回归",
            "estimation_ratio_basis_points": "估算/实际行数比",
            "join_order_change_count": "Join 顺序变化次数",
            "batch_duration_minutes": "批处理耗时",
            "tikv_p99_latency_ms": "TiKV P99 延迟",
            "hotspot_score_basis_points": "热点指标",
            "payment_error_rate_basis_points": "支付接口错误率",
        }[typed["metricCode"]]
        return (
            f"隔离环境验证显示{metric_zh}从 {typed['baselineValue']} "
            f"{typed['unit']} 变为 {typed['observedValue']} {typed['unit']}。"
        )
    if kind == "rollback_confirmation":
        state = {
            "confirmed": "已确认回滚完成",
            "failed": "回滚失败",
            "unknown": "无法确认回滚状态",
        }[typed["rollbackState"]]
        return f"回滚验证结果：{state}。"
    raise ValueError(f"unknown typed evidence summary template: {kind}")


def render_ai_claim(claim: dict[str, Any]) -> str:
    key = (claim["templateId"], claim["templateRevision"])
    if key not in AI_CLAIM_TEMPLATES:
        raise ValueError(f"unknown AI claim template: {key}")
    expected_params, rendered = AI_CLAIM_TEMPLATES[key]
    if claim["params"] != expected_params:
        raise ValueError(
            f"AI claim parameters do not match template: {claim['claimId']}"
        )
    return rendered


def format_derived_ratio(numerator: int, denominator: int) -> str:
    if numerator < 1 or denominator < 1:
        raise ValueError("derived ratio inputs must be positive")
    ratio = (Decimal(numerator) / Decimal(denominator)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    return format(ratio.normalize(), "f")


def fact_dependency_spec(fact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    key = (fact["templateId"], fact["templateRevision"])
    if key not in FACT_DEPENDENCY_REGISTRY:
        raise ValueError(f"unknown fact dependency template: {key}")
    return FACT_DEPENDENCY_REGISTRY[key]


def fact_role_evidence_ids(fact: dict[str, Any]) -> dict[str, str]:
    spec = fact_dependency_spec(fact)
    params = fact["params"]
    if not set(spec) <= set(params):
        raise ValueError(f"fact lacks typed evidence roles: {fact['factId']}")
    bindings = {role: params[role] for role in spec}
    if len(set(bindings.values())) != len(bindings):
        raise ValueError(f"fact evidence roles must be distinct: {fact['factId']}")
    return bindings


def rebuild_fact_params(
    fact: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    spec = fact_dependency_spec(fact)
    role_bindings = fact_role_evidence_ids(fact)
    rebuilt: dict[str, Any] = dict(role_bindings)
    for role, evidence_id in role_bindings.items():
        if evidence_id not in evidence_by_id:
            raise ValueError(
                f"fact references missing evidence: {fact['factId']} -> {evidence_id}"
            )
        evidence = evidence_by_id[evidence_id]
        expected_kind = spec[role]["kind"]
        if evidence["kind"] != expected_kind:
            raise ValueError(
                f"fact evidence kind mismatch: {fact['factId']} -> {evidence_id}"
            )
        require_eligible(evidence, f"Fact {fact['factId']} role {role}")
        for fact_field, value in evidence_profile_values(spec[role], evidence).items():
            if fact_field in rebuilt and rebuilt[fact_field] != value:
                raise ValueError(
                    f"fact evidence roles disagree on {fact_field}: {fact['factId']}"
                )
            rebuilt[fact_field] = value
    return rebuilt


def validate_fact_evidence_projection(
    fact: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]
) -> None:
    if fact["templateId"] == "fact.evidence_gap_profile":
        validate_gap_fact(fact, evidence_by_id)
        return
    expected = rebuild_fact_params(fact, evidence_by_id)
    if fact["params"] != expected:
        raise ValueError(
            f"fact parameters are not reconstructed from typed evidence: {fact['factId']}"
        )
    fact_key = (fact["templateId"], fact["templateRevision"])
    identity_spec = FACT_CANDIDATE_IDENTITY_REGISTRY[fact_key]
    role_bindings = fact_role_evidence_ids(fact)
    if set(identity_spec) != set(role_bindings):
        raise ValueError("Fact candidate identity roles differ from typed bindings")
    identities = [
        evidence_candidate_identity(fact_key, role, evidence_by_id[evidence_id])
        for role, evidence_id in role_bindings.items()
    ]
    if any(identity != identities[0] for identity in identities[1:]):
        raise ValueError("Fact Evidence roles bind different profile subjects")


def normalized_fact_profile(fact: dict[str, Any]) -> dict[str, Any]:
    key = (fact["templateId"], fact["templateRevision"])
    params = fact["params"]
    if key == ("fact.index_scan_profile", "v1"):
        expected_keys = {
            "windowMinutes",
            "callCount",
            "p95Ms",
            "averageScanRows",
            "averageReturnRows",
            "tableName",
            "filterColumns",
            "accessPath",
            "indexCoverage",
            "runtimeEvidenceId",
            "planEvidenceId",
            "indexEvidenceId",
        }
        if set(params) != expected_keys:
            raise ValueError("index fact parameters do not match the typed profile")
        if params["averageReturnRows"] > params["averageScanRows"]:
            raise ValueError("index fact cannot return more rows than it scans")
        return {
            **params,
            "averageScanRowsTenThousands": format_derived_ratio(
                params["averageScanRows"], 10000
            ),
            "scanReturnRatio": format_derived_ratio(
                params["averageScanRows"], params["averageReturnRows"]
            ),
        }
    if key == ("fact.statistics_estimation_profile", "v1"):
        expected_keys = {
            "estimatedRows",
            "actualRows",
            "statisticsFreshness",
            "statisticsEvidenceId",
        }
        if set(params) != expected_keys:
            raise ValueError(
                "statistics fact parameters do not match the typed profile"
            )
        return {
            **params,
            "estimateRatio": format_derived_ratio(
                max(params["estimatedRows"], params["actualRows"]),
                min(params["estimatedRows"], params["actualRows"]),
            ),
        }
    if key == ("fact.runtime_hotspot_profile", "v1"):
        expected_keys = {
            "sqlStability",
            "resourceCorrelation",
            "alertScope",
            "statementEvidenceId",
            "runtimeEvidenceId",
            "alertEvidenceId",
        }
        if set(params) != expected_keys:
            raise ValueError("runtime fact parameters do not match the typed profile")
        return dict(params)
    if key == ("fact.evidence_gap_profile", "v1"):
        expected_keys = {
            "attemptedDecisionTemplateId",
            "attemptedDecisionTemplateRevision",
            "profileIdentity",
            "roleAssessments",
        }
        if set(params) != expected_keys:
            raise ValueError("evidence-gap Fact parameters are not closed")
        assessments = params["roleAssessments"]
        eligible_count = sum(item["eligible"] for item in assessments)
        missing_kinds = sorted(
            {item["expectedKind"] for item in assessments if not item["eligible"]}
        )
        return {
            **params,
            "eligibleCount": eligible_count,
            "requiredCount": len(assessments),
            "completeness": round(eligible_count * 100 / len(assessments)),
            "missingKinds": missing_kinds,
            "boundEvidenceIds": [
                item["evidenceId"]
                for item in assessments
                if item["evidenceId"] is not None
            ],
        }
    raise ValueError(f"unknown fact template: {key}")


def render_fact(fact: dict[str, Any]) -> dict[str, str]:
    key = (fact["templateId"], fact["templateRevision"])
    params = normalized_fact_profile(fact)
    if key == ("fact.index_scan_profile", "v1"):
        return {
            "kind": "scan_amplification",
            "statementZh": (
                f"当前 {params['windowMinutes']} 分钟内调用 {params['callCount']} 次，"
                f"P95 为 {params['p95Ms']} ms，平均扫描 "
                f"{params['averageScanRowsTenThousands']} 万行；"
                f"{params['tableName']} 表为 TableFullScan，扫描/返回比 "
                f"{params['scanReturnRatio']}:1，且现有索引未匹配 "
                f"{'、'.join(params['filterColumns'])} 的过滤顺序。"
            ),
            "valueText": f"{params['scanReturnRatio']}:1",
        }
    if key == ("fact.statistics_estimation_profile", "v1"):
        return {
            "kind": "estimation_error",
            "statementZh": (
                f"核心表估算 {params['estimatedRows']} 行、实际 "
                f"{params['actualRows']} 行，相差约 {params['estimateRatio']} 倍；"
                "目标表统计更新时间早于最近一次大批量导入。"
            ),
            "valueText": f"{params['estimateRatio']}x",
        }
    if key == ("fact.runtime_hotspot_profile", "v1"):
        return {
            "kind": "time_window_correlation",
            "statementZh": (
                "SQL 延迟与 TiKV 热点在同一时间窗异常，SQL 计划本身保持稳定。"
            ),
            "valueText": "correlated",
        }
    if key == ("fact.evidence_gap_profile", "v1"):
        missing_zh = "、".join(
            {
                "slow_query": "慢查询运行",
                "ordinary_plan": "普通执行计划",
                "index": "索引元数据",
                "statistics": "统计信息",
                "statement_summary": "Statement Summary",
                "runtime_metric": "运行指标",
                "alert": "告警",
            }[kind]
            for kind in params["missingKinds"]
        )
        return {
            "kind": "evidence_gap",
            "statementZh": (
                f"诊断所需证据中缺少符合资格的{missing_zh}证据；"
                f"当前仅 {params['eligibleCount']}/{params['requiredCount']} 个角色合格，"
                "不能形成可发布根因。"
            ),
            "valueText": f"{params['completeness']}%",
        }
    raise ValueError(f"unknown fact template: {key}")


def fact_evidence_bindings(fact: dict[str, Any]) -> dict[str, str]:
    if fact["templateId"] == "fact.evidence_gap_profile":
        return {
            item["evidenceId"]: item["expectedKind"]
            for item in fact["params"]["roleAssessments"]
            if item["evidenceId"] is not None
        }
    spec = fact_dependency_spec(fact)
    role_bindings = fact_role_evidence_ids(fact)
    return {
        evidence_id: spec[role]["kind"] for role, evidence_id in role_bindings.items()
    }


def render_decision(
    decision: dict[str, Any], facts_by_id: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    key = (decision["templateId"], decision["templateRevision"])
    params = decision["params"]
    if set(params) != {"profileFactId"}:
        raise ValueError("decision parameters must contain one typed profileFactId")
    fact_id = params["profileFactId"]
    if fact_id not in facts_by_id:
        raise ValueError("decision references a missing typed profile fact")
    fact = facts_by_id[fact_id]
    profile = normalized_fact_profile(fact)
    if key == ("decision.evidence_insufficient", "v1"):
        if fact["templateId"] != "fact.evidence_gap_profile":
            raise ValueError("insufficient decision requires an evidence-gap Fact")
        missing_zh = "、".join(
            {
                "slow_query": "慢查询运行",
                "ordinary_plan": "普通执行计划",
                "index": "索引元数据",
                "statistics": "统计信息",
                "statement_summary": "Statement Summary",
                "runtime_metric": "运行指标",
                "alert": "告警",
            }[kind]
            for kind in profile["missingKinds"]
        )
        return {
            "titleZh": "证据不足，暂不发布诊断动作",
            "priority": "observe",
            "conclusionZh": (
                f"当前诊断证据完整度为 {profile['completeness']}%，"
                f"缺少符合资格的{missing_zh}证据；系统仅记录证据缺口，"
                "不发布根因、优先级动作或 AI 解释。"
            ),
            "evidenceSummary": [
                {
                    "labelZh": "证据完整度",
                    "valueZh": (
                        f"所需 {profile['requiredCount']} 个证据角色中 "
                        f"{profile['eligibleCount']} 个合格（{profile['completeness']}%）"
                    ),
                    "evidenceIds": profile["boundEvidenceIds"],
                }
            ],
        }
    if key == ("decision.index_scan_priority", "v1"):
        if fact["templateId"] != "fact.index_scan_profile":
            raise ValueError("index decision requires an index scan profile fact")
        return {
            "titleZh": "订单查询存在高频全表扫描，优先验证复合索引候选",
            "priority": "P1",
            "conclusionZh": (
                f"该 SQL 是当前 {profile['windowMinutes']} 分钟窗口的主要可行动瓶颈："
                f"{profile['callCount']} 次调用平均扫描 "
                f"{profile['averageScanRowsTenThousands']} 万行，普通计划为全表扫描，"
                "建议先在隔离环境验证索引候选。"
            ),
            "evidenceSummary": [
                {
                    "labelZh": "运行表现",
                    "valueZh": (
                        f"{profile['callCount']} 次调用，P95 "
                        f"{profile['p95Ms'] / 1000:g} 秒，平均扫描 "
                        f"{profile['averageScanRowsTenThousands']} 万行"
                    ),
                    "evidenceIds": [profile["runtimeEvidenceId"]],
                },
                {
                    "labelZh": "执行计划",
                    "valueZh": (
                        f"{profile['tableName']} 表 TableFullScan，扫描/返回比 "
                        f"{profile['scanReturnRatio']}:1"
                    ),
                    "evidenceIds": [profile["planEvidenceId"]],
                },
                {
                    "labelZh": "索引覆盖",
                    "valueZh": (
                        "现有索引未匹配 "
                        f"{'、'.join(profile['filterColumns'])} 的过滤顺序"
                    ),
                    "evidenceIds": [profile["indexEvidenceId"]],
                },
            ],
        }
    if key == ("decision.statistics_estimation", "v1"):
        if fact["templateId"] != "fact.statistics_estimation_profile":
            raise ValueError("statistics decision requires a statistics profile fact")
        return {
            "titleZh": "统计信息偏差导致 Join 顺序失真，先验证统计而不是直接加索引",
            "priority": "P1",
            "conclusionZh": (
                f"执行计划对核心表估算 {profile['estimatedRows']} 行，"
                f"实际运行证据为 {profile['actualRows'] // 10000} 万行；"
                "估算偏差足以改变 Join 顺序，应先在隔离环境刷新并验证统计。"
            ),
            "evidenceSummary": [
                {
                    "labelZh": "估算偏差",
                    "valueZh": (
                        f"estRows {profile['estimatedRows']}，运行时 rows "
                        f"{profile['actualRows']}，偏差约 {profile['estimateRatio']} 倍"
                    ),
                    "evidenceIds": [profile["statisticsEvidenceId"]],
                },
                {
                    "labelZh": "统计健康",
                    "valueZh": "目标表统计更新时间早于最近一次大批量导入",
                    "evidenceIds": [profile["statisticsEvidenceId"]],
                },
            ],
        }
    if key == ("decision.runtime_hotspot", "v1"):
        if fact["templateId"] != "fact.runtime_hotspot_profile":
            raise ValueError("runtime decision requires a hotspot profile fact")
        return {
            "titleZh": "SQL 延迟与 TiKV 热点时间窗一致，优先处置热点而不是改写 SQL",
            "priority": "P0",
            "conclusionZh": (
                "告警窗口内 SQL 计划和扫描量稳定，但目标 Region 的 TiKV 延迟与热点指标"
                "同步升高；当前更支持资源热点，而不是 SQL 结构退化。"
            ),
            "evidenceSummary": [
                {
                    "labelZh": "SQL 稳定性",
                    "valueZh": "计划摘要、扫描行数和调用量与前一基线窗口接近",
                    "evidenceIds": [profile["statementEvidenceId"]],
                },
                {
                    "labelZh": "资源相关性",
                    "valueZh": "同一时间窗 TiKV 请求延迟和 Region 热点指标显著升高",
                    "evidenceIds": [profile["runtimeEvidenceId"]],
                },
                {
                    "labelZh": "告警关联",
                    "valueZh": "TEM 告警的集群、组件与异常时间窗匹配",
                    "evidenceIds": [profile["alertEvidenceId"]],
                },
            ],
        }
    raise ValueError(f"unknown decision template: {key}")


def render_action(action: dict[str, Any]) -> dict[str, Any]:
    key = (action["templateId"], action["templateRevision"])
    params = action["params"]
    if key == ("action.index_candidate_isolated", "v1"):
        return {
            "family": "index_candidate",
            "titleZh": "在隔离环境验证复合索引候选",
            "rationaleZh": "现有计划为全表扫描，过滤列组合没有匹配的访问路径。",
            "risk": "medium",
            "ownerRole": "dba",
            "prerequisitesZh": [
                "使用 Plan Replayer 或等价隔离环境",
                "确认索引空间与写放大预算",
            ],
            "stepsZh": [
                "生成候选索引并只在隔离环境创建",
                "对相同参数分布运行普通 EXPLAIN 和压测",
            ],
            "validation": {
                "metricZh": "扫描行数、P95 延迟和写入开销",
                "targetZh": (
                    f"扫描行数下降 {params['minScanReductionPct']}% 以上，"
                    f"P95 低于 {params['maxP95Ms']} ms，写入回归不超过 "
                    f"{format_derived_ratio(params['maxWriteRegressionBasisPoints'], 100)}%"
                ),
            },
            "rollbackZh": [
                "若收益或写入开销不达标，删除隔离环境候选索引并停止灰度",
                "生产环境不执行任何自动变更",
            ],
            "requiresHumanApproval": True,
        }
    if key == ("action.statistics_refresh_isolated", "v1"):
        return {
            "family": "statistics_refresh",
            "titleZh": "在隔离环境验证统计刷新后的计划",
            "rationaleZh": "估算偏差和统计时效性共同支持先验证统计，而不是直接增加索引。",
            "risk": "medium",
            "ownerRole": "dba",
            "prerequisitesZh": [
                "准备 Plan Replayer 或测试集群",
                "确认受控 ANALYZE 的资源窗口和采样策略",
            ],
            "stepsZh": [
                "复现当前统计和执行计划",
                "按版本文档刷新统计并对比 Join 顺序与任务耗时",
            ],
            "validation": {
                "metricZh": "估算偏差、Join 顺序和批处理耗时",
                "targetZh": (
                    f"估算偏差低于 {params['maxEstimateRatio']} 倍，Join 顺序稳定，"
                    f"批处理耗时回到 {params['maxDurationMinutes']} 分钟以内"
                ),
            },
            "rollbackZh": [
                "若计划退化，不在生产执行统计刷新",
                "保留原统计与计划证据并重新评估绑定候选",
            ],
            "requiresHumanApproval": True,
        }
    if key == ("action.resource_hotspot_runbook", "v1"):
        return {
            "family": "resource_investigation",
            "titleZh": "由 SRE/DBA 先验证并缓解 TiKV 热点",
            "rationaleZh": "SQL 计划稳定，资源指标和告警在相同时间窗异常，应先验证热点。",
            "risk": "high",
            "ownerRole": "sre",
            "prerequisitesZh": [
                "核对热点 Region、Store 与业务 Key 范围",
                "取得生产资源处置审批",
            ],
            "stepsZh": [
                "按既有应急手册选择低风险缓解动作",
                "保持 SQL 与计划不变以避免同时引入第二变量",
            ],
            "validation": {
                "metricZh": "TiKV P99、热点指标和支付接口错误率",
                "targetZh": (
                    f"三项指标在 {params['observationMinutes']} 分钟内共同回落到客户基线阈值"
                ),
            },
            "rollbackZh": [
                "若缓解动作无效或副作用超阈值，立即按客户应急手册回滚",
                "保留 Region、Store 与时间窗证据",
            ],
            "requiresHumanApproval": True,
        }
    raise ValueError(f"unknown action template: {key}")


def validate_ai_invocation(case: dict[str, Any]) -> None:
    synthesis = case["aiSynthesis"]
    if not isinstance(synthesis, dict):
        raise TypeError("Case requires an explicit AI state object")
    pins = case["pinnedRevisions"]
    invocation_keys = ("provider", "model", "prompt", "payload", "payloadDigest")
    mode_matrix = {
        ("rules", "rules"): {"not_requested"},
        ("rules_ai", "rules_ai"): {"applied"},
        ("rules_ai", "rules"): {"degraded", "abstained"},
    }
    mode = (case["configuredMode"], case["effectiveMode"])
    if mode not in mode_matrix or synthesis["status"] not in mode_matrix[mode]:
        raise ValueError("AI status is not valid for configured/effective mode")

    status = synthesis["status"]
    if status == "applied":
        if synthesis["code"] is not None or synthesis["messageZh"] is not None:
            raise ValueError("applied AI cannot expose a degradation reason")
        if not synthesis["claims"]:
            raise ValueError("applied AI requires evidence-bound claims")
    else:
        key = (status, synthesis["code"])
        if key not in AI_STATUS_TEMPLATES:
            raise ValueError("AI status code is not server-owned")
        if synthesis["messageZh"] != AI_STATUS_TEMPLATES[key]:
            raise ValueError("AI status reason is not the server-owned rendering")
        if synthesis["claims"]:
            raise ValueError("non-applied AI cannot expose claims")

    if status in {"abstained", "not_requested"}:
        if synthesis["invocation"] is not None:
            raise ValueError("non-invoked AI cannot retain an invocation")
        if any(pins[key] is not None for key in invocation_keys):
            raise ValueError("non-invoked AI cannot retain invocation revisions")
        return

    invocation = synthesis["invocation"]
    if invocation is None:
        raise ValueError("applied/degraded AI requires an invocation")
    expected = {
        "providerRevision": pins["provider"],
        "modelRevision": pins["model"],
        "promptRevision": pins["prompt"],
        "payloadRevision": pins["payload"],
        "payloadDigest": pins["payloadDigest"],
        "redactionRevision": pins["redaction"],
    }
    if any(value is None for value in expected.values()):
        raise ValueError("applied/degraded AI requires complete invocation revisions")
    if invocation != expected:
        raise ValueError("AI invocation provenance differs from pinned revisions")


def validate_diagnosis_dependency_closure(
    case: dict[str, Any],
    facts_by_id: dict[str, dict[str, Any]],
) -> None:
    decision = case["decision"]
    decision_key = (decision["templateId"], decision["templateRevision"])
    if decision_key not in DIAGNOSIS_DEPENDENCY_REGISTRY:
        raise ValueError(f"unknown diagnosis dependency template: {decision_key}")
    spec = DIAGNOSIS_DEPENDENCY_REGISTRY[decision_key]
    fact_id = decision["params"]["profileFactId"]
    if fact_id not in facts_by_id:
        raise ValueError("diagnosis dependency closure lacks its profile fact")
    fact = facts_by_id[fact_id]
    if fact["templateId"] != spec["factTemplate"]:
        raise ValueError("decision dependency registry rejects the profile fact type")
    if len(facts_by_id) != 1:
        raise ValueError("P0 diagnosis dependency closure requires one profile fact")
    if decision_key == ("decision.evidence_insufficient", "v1"):
        if case["outcome"] not in {"pending", "evidence_insufficient"}:
            raise ValueError("evidence-gap diagnosis has an incompatible outcome")
        if case["ruleFindings"] or case["actions"] or case["aiSynthesis"]["claims"]:
            raise ValueError("evidence-gap diagnosis cannot publish rules or actions")
        if decision["ruleIds"] or decision["claimIds"] or decision["actionIds"]:
            raise ValueError("evidence-gap decision dependency closure is not empty")
        expected_evidence = {
            *fact["evidenceIds"],
            *case["subject"]["businessEvidenceIds"],
        }
        if set(decision["evidenceIds"]) != expected_evidence:
            raise ValueError("evidence-gap decision omits its exact provenance")
        return
    role_ids = fact_role_evidence_ids(fact)

    findings_by_id = {item["ruleId"]: item for item in case["ruleFindings"]}
    if set(findings_by_id) != set(spec["rules"]):
        raise ValueError("diagnosis rules differ from the decision dependency registry")
    for rule_id, roles in spec["rules"].items():
        expected_evidence = {role_ids[role] for role in roles}
        if set(findings_by_id[rule_id]["evidenceIds"]) != expected_evidence:
            raise ValueError(f"rule provenance is not closed: {rule_id}")
    for rule_id in spec["supportRules"]:
        if findings_by_id[rule_id]["status"] != "hit":
            raise ValueError(f"non-hit rule cannot support a diagnosis: {rule_id}")

    synthesis = case["aiSynthesis"]
    claims = synthesis["claims"]
    claims_by_template: dict[tuple[str, str], dict[str, Any]] = {}
    for claim in claims:
        key = (claim["templateId"], claim["templateRevision"])
        if key in claims_by_template:
            raise ValueError(f"duplicate AI claim dependency template: {key}")
        claims_by_template[key] = claim
    expected_claim_templates = (
        set(spec["claims"]) if synthesis["status"] == "applied" else set()
    )
    if set(claims_by_template) != expected_claim_templates:
        raise ValueError("AI claims differ from the decision dependency registry")
    for key, claim in claims_by_template.items():
        dependency = spec["claims"][key]
        expected_evidence = {role_ids[role] for role in dependency["evidenceRoles"]}
        if set(claim["evidenceIds"]) != expected_evidence:
            raise ValueError(f"AI claim provenance is not closed: {claim['claimId']}")
        if set(claim["ruleIds"]) != set(dependency["rules"]):
            raise ValueError(
                f"AI claim rule provenance is not closed: {claim['claimId']}"
            )
        if any(
            findings_by_id[rule_id]["status"] != "hit" for rule_id in claim["ruleIds"]
        ):
            raise ValueError("AI claim is supported by a non-hit rule")

    actions_by_template: dict[tuple[str, str], dict[str, Any]] = {}
    for action in case["actions"]:
        key = (action["templateId"], action["templateRevision"])
        if key in actions_by_template:
            raise ValueError(f"duplicate Action dependency template: {key}")
        actions_by_template[key] = action
    if set(actions_by_template) != set(spec["actions"]):
        raise ValueError("Actions differ from the decision dependency registry")
    for key, action in actions_by_template.items():
        dependency = spec["actions"][key]
        expected_evidence = {role_ids[role] for role in dependency["evidenceRoles"]}
        if set(action["evidenceIds"]) != expected_evidence:
            raise ValueError(f"Action provenance is not closed: {action['actionId']}")
        if set(action["ruleIds"]) != set(dependency["rules"]):
            raise ValueError(
                f"Action rule provenance is not closed: {action['actionId']}"
            )
        if any(
            findings_by_id[rule_id]["status"] != "hit" for rule_id in action["ruleIds"]
        ):
            raise ValueError("Action is supported by a non-hit rule")

    expected_decision_evidence = {
        *role_ids.values(),
        *case["subject"]["businessEvidenceIds"],
    }
    if set(decision["evidenceIds"]) != expected_decision_evidence:
        raise ValueError("decision evidence is not the closed dependency projection")
    if set(decision["ruleIds"]) != set(spec["supportRules"]):
        raise ValueError("decision rules are not the closed dependency projection")
    if set(decision["claimIds"]) != {
        item["claimId"] for item in claims_by_template.values()
    }:
        raise ValueError("decision claims are not the closed dependency projection")
    if set(decision["actionIds"]) != {
        item["actionId"] for item in actions_by_template.values()
    }:
        raise ValueError("decision actions are not the closed dependency projection")


def validate_source_semantics(source: dict[str, Any]) -> None:
    reject_non_finite_json(source)
    validate_source_audit(source)
    validate_source_lease_audit(source)
    replay_source_history(source, parse_time)
    capability_names = [item["name"] for item in source["capabilities"]]
    if len(capability_names) != len(set(capability_names)):
        raise ValueError("duplicate Source capability name")
    if source["sourceId"] in source["associatedSourceIds"]:
        raise ValueError("Source cannot associate itself")

    product_matrix = {
        "tidb": ("tidb", {"tidb-8.5", "unknown"}, {"password"}),
        "pingkaidb": ("tidb", {"pingkaidb-7.1", "unknown"}, {"password"}),
        "prometheus": (
            "prometheus",
            {"prometheus", "unknown"},
            {"none", "basic", "bearer", "mtls"},
        ),
        "tem": ("tem", {"tem", "unknown"}, {"api_key", "bearer", "mtls"}),
        "alertmanager": (
            "alertmanager",
            {"alertmanager", "unknown"},
            {"none", "basic", "bearer", "mtls"},
        ),
    }
    expected_type, version_families, auth_kinds = product_matrix[source["product"]]
    if source["type"] != expected_type:
        raise ValueError("Source product does not match connector type")
    if source["version"]["family"] not in version_families:
        raise ValueError("Source product does not match version family")
    expected_auth_kinds = {"none"} if source["state"] == "tombstoned" else auth_kinds
    if source["auth"]["kind"] not in expected_auth_kinds:
        raise ValueError("Source product does not match authentication kind")
    if source["version"]["family"] == "unknown" and source["version"]["supported"]:
        raise ValueError("unknown Source version cannot be supported")
    if (
        source["state"] == "verification_failed"
        and source["verification"]["status"] != "failed"
    ):
        raise ValueError("verification_failed Source requires failed verification")
    if source["verification"]["status"] == "failed" and not (
        source["state"] == "verification_failed"
        or (
            source["state"] == "draining"
            and source["credentialLifecycle"]["pendingOperation"]
            == "verification_failure"
        )
    ):
        raise ValueError(
            "failed verification requires verification-failure drain or terminal state"
        )

    required_by_type = {
        "tidb": {"version", "schema"},
        "prometheus": {"prom_query"},
        "tem": {"alert_read"},
        "alertmanager": {"alert_read"},
    }
    if source["state"] == "enabled":
        available = {
            item["name"]
            for item in source["capabilities"]
            if item["status"] == "available"
        }
        missing = required_by_type[source["type"]] - available
        if missing:
            raise ValueError(
                f"enabled Source lacks required capabilities: {sorted(missing)}"
            )

    lifecycle = source["credentialLifecycle"]
    if source["state"] == "draining" and lifecycle["pendingOperation"] not in {
        "rotate",
        "disable",
        "delete",
        "verification_failure",
    }:
        raise ValueError("draining Source requires an explicit pending operation")
    if (
        source["state"] in {"draft", "disabled", "verification_failed"}
        and lifecycle["activeLeaseCount"]
    ):
        raise ValueError("inactive Source cannot retain active job leases")
    if lifecycle["pendingOperation"] is not None and source["state"] != "draining":
        raise ValueError("pending credential operation requires draining Source")
    if lifecycle["state"] in {"rotating", "retiring"} and source["state"] != "draining":
        raise ValueError("credential retirement requires draining Source")
    if (
        lifecycle["state"] in {"rotating", "retiring"}
        and lifecycle["retireAfter"] is None
    ):
        raise ValueError("draining credential requires a retirement deadline")
    if lifecycle["pendingOperation"] == "rotate" and lifecycle["state"] != "rotating":
        raise ValueError("rotate operation requires rotating credential state")
    if (
        lifecycle["pendingOperation"] in {"disable", "delete"}
        and lifecycle["state"] != "retiring"
    ):
        raise ValueError("disable/delete operation requires retiring credential state")
    if lifecycle["pendingOperation"] == "verification_failure":
        if lifecycle["state"] != "active" or lifecycle["retireAfter"] is not None:
            raise ValueError(
                "verification-failure drain must retain the active credential"
            )
        if source["verification"]["status"] != "failed":
            raise ValueError(
                "verification-failure drain requires a failed verification snapshot"
            )
    if lifecycle["state"] == "active" and lifecycle["pendingOperation"] not in {
        None,
        "verification_failure",
    }:
        raise ValueError("active credential has an incompatible pending operation")
    if (
        lifecycle["state"] == "active"
        and lifecycle["pendingOperation"] is None
        and lifecycle["retireAfter"] is not None
    ):
        raise ValueError("active credential cannot retain a retirement deadline")
    if lifecycle["state"] == "tombstoned":
        if source["state"] != "tombstoned" or lifecycle["activeLeaseCount"]:
            raise ValueError("tombstoned Source must have zero active leases")
        if source["auth"]["credentialRef"] is not None:
            raise ValueError("tombstoned Source cannot retain a credential reference")


def validate_source_transition(prior: dict[str, Any], proposed: dict[str, Any]) -> None:
    if prior["sourceId"] != proposed["sourceId"]:
        raise ValueError("Source transition cannot change sourceId")
    if proposed["revision"] != prior["revision"] + 1:
        raise ValueError("Source revision must increase by exactly one")
    if proposed["createdAt"] != prior["createdAt"]:
        raise ValueError("Source transition cannot rewrite createdAt")
    if parse_time(proposed["updatedAt"]) <= parse_time(prior["updatedAt"]):
        raise ValueError("Source updatedAt must increase across revisions")
    for field in ("schemaVersion", "sourceId", "type", "product"):
        if proposed[field] != prior[field]:
            raise ValueError(f"Source transition rewrites immutable field: {field}")

    require_append_only(
        prior["transitionEvents"],
        proposed["transitionEvents"],
        "Source transitionEvents",
    )
    new_events = proposed["transitionEvents"][len(prior["transitionEvents"]) :]
    if len(new_events) != 1:
        raise ValueError("Source revision requires exactly one state audit event")
    if any(event["sourceRevision"] != proposed["revision"] for event in new_events):
        raise ValueError("new Source audit event must bind the proposed revision")
    if any(
        parse_time(event["createdAt"]) <= parse_time(prior["updatedAt"])
        for event in new_events
    ):
        raise ValueError("new Source audit event predates the prior revision")
    state_event = new_events[0]

    require_append_only(
        prior["leaseEvents"],
        proposed["leaseEvents"],
        "Source leaseEvents",
    )
    new_lease_events = proposed["leaseEvents"][len(prior["leaseEvents"]) :]
    if any(
        event["sourceRevision"] != proposed["revision"] for event in new_lease_events
    ):
        raise ValueError("new lease audit event must bind the proposed revision")
    if any(
        parse_time(event["createdAt"]) <= parse_time(prior["updatedAt"])
        for event in new_lease_events
    ):
        raise ValueError("new lease audit event predates the prior revision")
    if any(
        parse_time(event["createdAt"]) > parse_time(state_event["createdAt"])
        for event in new_lease_events
    ):
        raise ValueError("Source state audit precedes its lease ledger events")

    if proposed["state"] not in SOURCE_STATE_TRANSITIONS[prior["state"]]:
        raise ValueError("illegal Source state transition")
    prior_lifecycle = prior["credentialLifecycle"]
    proposed_lifecycle = proposed["credentialLifecycle"]
    prior_lease_count = prior_lifecycle["activeLeaseCount"]
    proposed_lease_count = proposed_lifecycle["activeLeaseCount"]
    if proposed["state"] == "draining" and prior["state"] != "draining":
        pending_operation = proposed_lifecycle["pendingOperation"]
        if pending_operation not in {
            "rotate",
            "disable",
            "delete",
            "verification_failure",
        }:
            raise ValueError("drain admission requires a recognized pending operation")
        if proposed_lease_count != prior_lease_count:
            raise ValueError("Source must preserve active leases when entering drain")
        if proposed["activeLeases"] != prior["activeLeases"]:
            raise ValueError(
                "Source must preserve lease identities when entering drain"
            )
        expected_start = {
            "rotate": "rotation_started",
            "disable": "disable_started",
            "delete": "delete_started",
            "verification_failure": "verification_failure_started",
        }[pending_operation]
        if state_event["operation"] != expected_start:
            raise ValueError("drain start operation does not match pendingOperation")
        if pending_operation == "verification_failure":
            if state_event["actor"]["kind"] != "system":
                raise ValueError(
                    "verification-failure drain must be initiated by the verifier"
                )
        elif (
            state_event["actor"]["kind"] != "user"
            or state_event["actor"].get("role") != "owner"
        ):
            raise ValueError("drain start requires an explicit Owner action")
        if new_lease_events:
            raise ValueError(
                "leases cannot be released in the drain admission revision"
            )
    if prior["state"] == "draining":
        if any(event["operation"] == "lease_acquired" for event in new_lease_events):
            raise ValueError("draining Source cannot acquire new leases")
        if proposed_lease_count > prior_lease_count:
            raise ValueError("draining Source cannot acquire new leases")
        if proposed["state"] == "draining":
            for field in ("pendingOperation", "retireAfter"):
                if proposed_lifecycle[field] != prior_lifecycle[field]:
                    raise ValueError("draining Source cannot rewrite pending operation")
            released_count = prior_lease_count - proposed_lease_count
            if released_count != len(new_lease_events):
                raise ValueError(
                    "draining lease count change lacks one audit per lease"
                )
            expected_count = prior_lease_count
            for event in new_lease_events:
                if (
                    event["fromLeaseCount"] != expected_count
                    or event["toLeaseCount"] != expected_count - 1
                ):
                    raise ValueError("lease audit count chain is discontinuous")
                expected_count -= 1
            if expected_count != proposed_lease_count:
                raise ValueError("lease audit does not reach the proposed lease count")
            if released_count and state_event["operation"] != "leases_drained":
                raise ValueError("lease release revision requires leases_drained audit")
            if not released_count and state_event["operation"] == "leases_drained":
                raise ValueError("leases_drained audit requires a lease count decrease")
        else:
            if prior_lease_count != 0:
                raise ValueError("Source cannot leave draining with active leases")
            if new_lease_events:
                raise ValueError("lease release must complete before drain completion")
            pending_operation = prior_lifecycle["pendingOperation"]
            if pending_operation not in {
                "rotate",
                "disable",
                "delete",
                "verification_failure",
            }:
                raise ValueError(
                    "drain completion requires a recognized pending operation"
                )
            expected_state = {
                "rotate": "enabled",
                "disable": "disabled",
                "delete": "tombstoned",
                "verification_failure": "verification_failed",
            }[pending_operation]
            if proposed["state"] != expected_state:
                raise ValueError(
                    "Source drain completion does not match pending operation"
                )
            expected_completion = {
                "rotate": "rotation_completed",
                "disable": "disabled",
                "delete": "tombstoned",
                "verification_failure": "verification_failed",
            }[pending_operation]
            if state_event["operation"] != expected_completion:
                raise ValueError(
                    "Source completion operation does not match pendingOperation"
                )
    elif new_lease_events:
        if not (prior["state"] == proposed["state"] == "enabled"):
            raise ValueError(
                "lease ledger changes outside draining require an enabled Source"
            )
        if any(
            event["operation"] == "lease_force_cancelled" for event in new_lease_events
        ):
            raise ValueError("force cancellation requires an admitted drain operation")
        if state_event["operation"] != "leases_updated":
            raise ValueError(
                "enabled lease ledger changes require a leases_updated state audit"
            )

    prior_ref = prior["auth"]["credentialRef"]
    proposed_ref = proposed["auth"]["credentialRef"]
    prior_credential_revision = prior["auth"]["credentialRevision"]
    proposed_credential_revision = proposed["auth"]["credentialRevision"]
    if prior["state"] == "draining" and proposed["state"] != "draining":
        pending_operation = prior_lifecycle["pendingOperation"]
        if pending_operation == "rotate" and not (
            prior_ref != proposed_ref
            and proposed_ref is not None
            and prior_credential_revision is not None
            and proposed_credential_revision is not None
            and proposed_credential_revision > prior_credential_revision
        ):
            raise ValueError("rotation completion requires a newer credential revision")
        if pending_operation == "disable" and not (
            prior_ref == proposed_ref
            and prior_credential_revision == proposed_credential_revision
        ):
            raise ValueError("disable completion must retain its credential revision")
        if pending_operation == "verification_failure" and not (
            prior_ref == proposed_ref
            and prior_credential_revision == proposed_credential_revision
        ):
            raise ValueError(
                "verification-failure completion must retain its credential revision"
            )
        if pending_operation == "delete" and not (
            proposed_ref is None and proposed_credential_revision is None
        ):
            raise ValueError("delete completion must destroy the credential reference")
    if prior_ref == proposed_ref and (
        prior_credential_revision != proposed_credential_revision
    ):
        raise ValueError("credential revision changed without a new credential")
    if (
        prior_credential_revision is not None
        and proposed_credential_revision is not None
        and proposed_credential_revision < prior_credential_revision
    ):
        raise ValueError("credential revision cannot decrease")
    if prior_ref != proposed_ref:
        rotation_completed = (
            prior["state"] == "draining"
            and prior_lifecycle["pendingOperation"] == "rotate"
            and prior_lifecycle["activeLeaseCount"] == 0
            and proposed["state"] == "enabled"
            and proposed_credential_revision is not None
            and (
                prior_credential_revision is None
                or proposed_credential_revision > prior_credential_revision
            )
        )
        credential_deleted = (
            prior["state"] == "draining"
            and prior_lifecycle["pendingOperation"] == "delete"
            and prior_lifecycle["activeLeaseCount"] == 0
            and proposed["state"] == "tombstoned"
            and proposed_ref is None
            and proposed_credential_revision is None
        )
        if not rotation_completed and not credential_deleted:
            raise ValueError(
                "credential identity changed outside rotation/delete completion"
            )

    validate_source_semantics(prior)
    validate_source_semantics(proposed)


def build_source_rotation(
    source: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    draining = copy.deepcopy(source)
    draining["revision"] = source["revision"] + 1
    draining["state"] = "draining"
    draining["credentialLifecycle"] = {
        "state": "rotating",
        "activeLeaseCount": source["credentialLifecycle"]["activeLeaseCount"],
        "pendingOperation": "rotate",
        "retireAfter": "2026-09-02T09:30:00Z",
    }
    draining["updatedAt"] = "2026-09-02T09:25:00Z"
    draining["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000004",
            "sourceRevision": draining["revision"],
            "type": "source_state",
            "operation": "rotation_started",
            "fromState": "enabled",
            "toState": "draining",
            "credentialRevision": source["auth"]["credentialRevision"],
            "actor": {
                "kind": "user",
                "role": "owner",
                "id": "owner",
                "displayName": "本机 Owner",
            },
            "createdAt": draining["updatedAt"],
            "reason": "停止旧凭据的新任务准入并等待租约排空",
        }
    )

    rotated = copy.deepcopy(draining)
    rotated["revision"] = draining["revision"] + 1
    rotated["state"] = "enabled"
    rotated["auth"]["credentialRef"] = "cred_0000000000000002"
    rotated["auth"]["credentialRevision"] = 3
    rotated["credentialLifecycle"] = {
        "state": "active",
        "activeLeaseCount": 0,
        "pendingOperation": None,
        "retireAfter": None,
    }
    rotated["updatedAt"] = "2026-09-02T09:30:00Z"
    rotated["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000005",
            "sourceRevision": rotated["revision"],
            "type": "source_state",
            "operation": "rotation_completed",
            "fromState": "draining",
            "toState": "enabled",
            "credentialRevision": rotated["auth"]["credentialRevision"],
            "actor": {
                "kind": "system",
                "role": "system",
                "id": "source-lifecycle",
                "displayName": "数据源生命周期",
            },
            "createdAt": rotated["updatedAt"],
            "reason": "旧租约归零，启用新凭据 revision",
        }
    )
    return draining, rotated


def build_source_lease_drain(
    source: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    leased = copy.deepcopy(source)
    leased["revision"] = source["revision"] + 1
    leased["credentialLifecycle"]["activeLeaseCount"] = 2
    leased["updatedAt"] = "2026-09-02T09:23:00Z"
    leased["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000101",
            "sourceRevision": leased["revision"],
            "type": "source_state",
            "operation": "leases_updated",
            "fromState": "enabled",
            "toState": "enabled",
            "credentialRevision": leased["auth"]["credentialRevision"],
            "actor": {
                "kind": "system",
                "role": "system",
                "id": "diagnosis-job",
                "displayName": "诊断任务",
            },
            "createdAt": leased["updatedAt"],
            "reason": "两个只读诊断任务取得数据源租约",
        }
    )
    leased["leaseEvents"].extend(
        [
            {
                "eventId": "levt_0000000000000101",
                "sourceRevision": leased["revision"],
                "operation": "lease_acquired",
                "leaseId": "lease_0000000000000001",
                "jobId": "job_0000000000000001",
                "fromLeaseCount": 0,
                "toLeaseCount": 1,
                "actor": {
                    "kind": "system",
                    "role": "system",
                    "id": "diagnosis-job",
                    "displayName": "诊断任务",
                },
                "ownerApproval": None,
                "createdAt": "2026-09-02T09:21:00Z",
                "reason": "只读诊断任务取得数据源租约",
            },
            {
                "eventId": "levt_0000000000000102",
                "sourceRevision": leased["revision"],
                "operation": "lease_acquired",
                "leaseId": "lease_0000000000000002",
                "jobId": "job_0000000000000002",
                "fromLeaseCount": 1,
                "toLeaseCount": 2,
                "actor": {
                    "kind": "system",
                    "role": "system",
                    "id": "diagnosis-job",
                    "displayName": "诊断任务",
                },
                "ownerApproval": None,
                "createdAt": "2026-09-02T09:22:00Z",
                "reason": "只读诊断任务取得数据源租约",
            },
        ]
    )
    leased["activeLeases"] = [
        {
            "leaseId": event["leaseId"],
            "jobId": event["jobId"],
            "acquiredRevision": event["sourceRevision"],
            "acquiredAt": event["createdAt"],
        }
        for event in leased["leaseEvents"][-2:]
    ]

    draining = copy.deepcopy(leased)
    draining["revision"] = leased["revision"] + 1
    draining["state"] = "draining"
    draining["credentialLifecycle"] = {
        "state": "rotating",
        "activeLeaseCount": 2,
        "pendingOperation": "rotate",
        "retireAfter": "2026-09-02T09:30:00Z",
    }
    draining["updatedAt"] = "2026-09-02T09:25:00Z"
    draining["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000102",
            "sourceRevision": draining["revision"],
            "type": "source_state",
            "operation": "rotation_started",
            "fromState": "enabled",
            "toState": "draining",
            "credentialRevision": draining["auth"]["credentialRevision"],
            "actor": {
                "kind": "user",
                "role": "owner",
                "id": "owner",
                "displayName": "本机 Owner",
            },
            "createdAt": draining["updatedAt"],
            "reason": "停止旧凭据的新任务准入并等待租约排空",
        }
    )

    drained = copy.deepcopy(draining)
    drained["revision"] = draining["revision"] + 1
    drained["credentialLifecycle"]["activeLeaseCount"] = 0
    drained["activeLeases"] = []
    drained["updatedAt"] = "2026-09-02T09:29:00Z"
    drained["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000006",
            "sourceRevision": drained["revision"],
            "type": "source_state",
            "operation": "leases_drained",
            "fromState": "draining",
            "toState": "draining",
            "credentialRevision": drained["auth"]["credentialRevision"],
            "actor": {
                "kind": "system",
                "role": "system",
                "id": "source-lifecycle",
                "displayName": "数据源生命周期",
            },
            "createdAt": drained["updatedAt"],
            "reason": "活动租约已逐项释放或经 Owner 批准强制取消",
        }
    )
    drained["leaseEvents"].extend(
        [
            {
                "eventId": "levt_0000000000000001",
                "sourceRevision": drained["revision"],
                "operation": "lease_released",
                "leaseId": "lease_0000000000000001",
                "jobId": "job_0000000000000001",
                "fromLeaseCount": 2,
                "toLeaseCount": 1,
                "actor": {
                    "kind": "system",
                    "role": "system",
                    "id": "diagnosis-job",
                    "displayName": "诊断任务",
                },
                "ownerApproval": None,
                "createdAt": "2026-09-02T09:27:00Z",
                "reason": "只读诊断任务正常完成并释放租约",
            },
            {
                "eventId": "levt_0000000000000002",
                "sourceRevision": drained["revision"],
                "operation": "lease_force_cancelled",
                "leaseId": "lease_0000000000000002",
                "jobId": "job_0000000000000002",
                "fromLeaseCount": 1,
                "toLeaseCount": 0,
                "actor": {
                    "kind": "system",
                    "role": "system",
                    "id": "source-lifecycle",
                    "displayName": "数据源生命周期",
                },
                "ownerApproval": {
                    "approvedBy": {
                        "kind": "user",
                        "role": "owner",
                        "id": "owner",
                        "displayName": "本机 Owner",
                    },
                    "approvedAt": "2026-09-02T09:27:30Z",
                    "reason": "删除窗口到期，批准取消剩余只读诊断任务",
                },
                "createdAt": "2026-09-02T09:28:00Z",
                "reason": "按 Owner 审批强制取消剩余任务并释放租约",
            },
        ]
    )
    return leased, draining, drained


def build_source_verification_failure_drain(source: dict[str, Any]) -> dict[str, Any]:
    draining = copy.deepcopy(source)
    draining["revision"] = source["revision"] + 1
    draining["state"] = "draining"
    draining["credentialLifecycle"] = {
        "state": "active",
        "activeLeaseCount": source["credentialLifecycle"]["activeLeaseCount"],
        "pendingOperation": "verification_failure",
        "retireAfter": None,
    }
    draining["verification"] = {
        "status": "failed",
        "testedAt": "2026-09-02T09:24:00Z",
        "identityDigest": None,
        "errorCode": "CONNECT_TIMEOUT",
    }
    draining["updatedAt"] = "2026-09-02T09:24:00Z"
    draining["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000103",
            "sourceRevision": draining["revision"],
            "type": "source_state",
            "operation": "verification_failure_started",
            "fromState": "enabled",
            "toState": "draining",
            "credentialRevision": draining["auth"]["credentialRevision"],
            "actor": {
                "kind": "system",
                "role": "system",
                "id": "source-verifier",
                "displayName": "连接校验器",
            },
            "createdAt": draining["updatedAt"],
            "reason": "连接重新校验失败，停止新任务并保留已有租约直到排空",
        }
    )
    return draining


def validate_evidence_semantics(
    evidence: dict[str, Any],
    case_id: str,
    source_revisions: set[str],
) -> None:
    reject_non_finite_json(evidence)
    if evidence["caseId"] != case_id:
        raise ValueError(f"evidence belongs to another case: {evidence['evidenceId']}")
    if parse_time(evidence["observedAt"]) > parse_time(evidence["collectedAt"]):
        raise ValueError(
            f"evidence observed after collection: {evidence['evidenceId']}"
        )
    source_ref = evidence["sourceRef"]
    if source_ref is not None:
        ref = f"{source_ref['sourceId']}@{source_ref['revision']}"
        if ref not in source_revisions:
            raise ValueError(f"evidence has unknown Source revision: {ref}")

    payload = evidence["payload"]
    collection = evidence["collection"]
    budget = collection["budget"]
    typed = payload["typed"]
    allowed_schema_revisions = EVIDENCE_SCHEMA_REVISIONS[evidence["kind"]]
    if payload["schemaRevision"] not in allowed_schema_revisions:
        raise ValueError(
            f"evidence schema revision does not match kind: {evidence['evidenceId']}"
        )
    if payload["extractionRevision"] != "evidence-extractor/v1":
        raise ValueError(
            f"unsupported evidence extraction revision: {evidence['evidenceId']}"
        )
    if payload["canonicalRevision"] != "rfc8785-safe-integer/v1":
        raise ValueError(
            f"unsupported evidence canonical revision: {evidence['evidenceId']}"
        )
    if typed["kind"] != evidence["kind"]:
        raise ValueError(
            f"typed evidence payload does not match kind: {evidence['evidenceId']}"
        )
    validate_evidence_object_identity(evidence)
    if payload["typedDigest"] != typed_payload_digest(typed):
        raise ValueError(
            f"typed evidence projection digest mismatch: {evidence['evidenceId']}"
        )
    if evidence["summaryZh"] != render_evidence_summary(evidence):
        raise ValueError(
            f"evidence summary differs from typed payload: {evidence['evidenceId']}"
        )
    if payload["digest"] != evidence["integrityDigest"]:
        raise ValueError(
            f"evidence and payload digests differ: {evidence['evidenceId']}"
        )
    if payload["truncated"] != (collection["status"] == "truncated"):
        raise ValueError(f"evidence truncation state differs: {evidence['evidenceId']}")
    if budget["elapsedMs"] > budget["timeoutMs"]:
        raise ValueError(f"evidence exceeded timeout budget: {evidence['evidenceId']}")
    if budget["rowsRead"] > budget["maxRows"]:
        raise ValueError(f"evidence exceeded row budget: {evidence['evidenceId']}")
    if budget["bytesRead"] > budget["maxBytes"]:
        raise ValueError(f"evidence exceeded byte budget: {evidence['evidenceId']}")


def validate_standalone_evidence(
    evidence: dict[str, Any], available_source_revisions: set[str]
) -> None:
    validate_evidence_semantics(
        evidence,
        evidence["caseId"],
        available_source_revisions,
    )


def validate_transition_events(case: dict[str, Any]) -> None:
    require_unique(case["transitionEvents"], "eventId")
    created_at = parse_time(case["createdAt"])
    updated_at = parse_time(case["updatedAt"])
    reviews_by_id = {item["reviewId"]: item for item in case["reviews"]}
    feedback_by_id = {item["feedbackId"]: item for item in case["feedback"]}
    evidence_by_id = {item["evidenceId"]: item for item in case["evidence"]}
    previous_event_at: datetime | None = None
    ready_at: datetime | None = None
    workflow_current: str | None = None
    outcome_current = "pending"
    saw_workflow = False

    for event in case["transitionEvents"]:
        event_at = parse_time(event["createdAt"])
        if not created_at <= event_at <= updated_at:
            raise ValueError("transition event is outside the Case time window")
        if previous_event_at is not None and event_at < previous_event_at:
            raise ValueError("transition events must be chronological")
        if event["caseRevision"] > case["revision"]:
            raise ValueError("transition event references a future Case revision")
        previous_event_at = event_at

        if event["type"] == "workflow_state":
            source = event["fromWorkflowState"]
            target = event["toWorkflowState"]
            if not saw_workflow:
                if source is not None or target != "queued":
                    raise ValueError("workflow audit must start at null -> queued")
                saw_workflow = True
            else:
                if source != workflow_current:
                    raise ValueError("workflow transition chain is discontinuous")
                if target not in WORKFLOW_TRANSITIONS[source]:
                    raise ValueError(
                        f"illegal workflow transition: {source} -> {target}"
                    )
            workflow_current = target
            if target == "ready" and ready_at is None:
                ready_at = event_at
        else:
            source = event["fromOutcome"]
            target = event["toOutcome"]
            if workflow_current != "ready":
                raise ValueError("outcome transition requires workflow state ready")
            referenced_records = [
                *(reviews_by_id[item] for item in event["reviewIds"]),
                *(feedback_by_id[item] for item in event["feedbackIds"]),
            ]
            if any(
                parse_time(item["createdAt"]) > event_at for item in referenced_records
            ):
                raise ValueError("outcome transition references a future audit record")
            if any(
                parse_time(evidence_by_id[item]["collectedAt"]) > event_at
                for item in event["evidenceIds"]
            ):
                raise ValueError("outcome transition references future evidence")
            if any(
                item["caseRevision"] > event["caseRevision"]
                for item in referenced_records
            ):
                raise ValueError("outcome transition references a future Case revision")
            if source != outcome_current:
                raise ValueError("outcome transition chain is discontinuous")
            if target not in OUTCOME_TRANSITIONS[source]:
                raise ValueError(f"illegal outcome transition: {source} -> {target}")
            outcome_current = target

    if workflow_current != case["workflowState"]:
        raise ValueError("latest workflow transition does not match Case state")
    if outcome_current != case["outcome"]:
        raise ValueError("latest outcome transition does not match Case outcome")
    if case["workflowState"] == "ready":
        if ready_at is None:
            raise ValueError("ready Case lacks a ready transition event")
        frozen_evidence_ids = {
            *case["subject"]["businessEvidenceIds"],
            *case["decision"]["evidenceIds"],
            *(
                evidence_id
                for item in case["facts"]
                for evidence_id in item["evidenceIds"]
            ),
            *(
                evidence_id
                for item in case["ruleFindings"]
                for evidence_id in item["evidenceIds"]
            ),
            *(
                evidence_id
                for item in case["actions"]
                for evidence_id in item["evidenceIds"]
            ),
            *(
                evidence_id
                for item in (case["aiSynthesis"] or {}).get("claims", [])
                for evidence_id in item["evidenceIds"]
            ),
        }
        if any(
            parse_time(evidence_by_id[evidence_id]["collectedAt"]) > ready_at
            for evidence_id in frozen_evidence_ids
        ):
            raise ValueError("ready Case uses evidence collected after the ready event")
        if any(
            parse_time(evidence_by_id[evidence_id]["collectedAt"]) > updated_at
            for evidence_id in frozen_evidence_ids
        ):
            raise ValueError("ready Case uses evidence collected after its revision")


def validate_outcome_semantics(
    case: dict[str, Any], authorization_not_before: datetime | None = None
) -> None:
    validate_outcome_policy(
        case,
        parse_time,
        resolve_authorization_audit,
        authorization_not_before,
    )


def validate_case_references(
    case: dict[str, Any], authorization_not_before: datetime | None = None
) -> None:
    reject_non_finite_json(case)
    validate_policy_pins(case)
    source_ids = require_unique(case["sourceSnapshots"], "sourceId")
    source_revisions = {
        f"{item['sourceId']}@{item['revision']}" for item in case["sourceSnapshots"]
    }
    evidence_ids = require_unique(case["evidence"], "evidenceId")
    evidence_by_id = {item["evidenceId"]: item for item in case["evidence"]}
    storage_refs = require_unique(
        [item["payload"] for item in case["evidence"]], "storageRef"
    )
    _ = storage_refs
    fact_ids = require_unique(case["facts"], "factId")
    facts_by_id = {item["factId"]: item for item in case["facts"]}
    rule_ids = require_unique(case["ruleFindings"], "ruleId")
    action_ids = require_unique(case["actions"], "actionId")
    review_ids = require_unique(case["reviews"], "reviewId")
    feedback_ids = require_unique(case["feedback"], "feedbackId")

    for evidence in case["evidence"]:
        validate_evidence_semantics(evidence, case["caseId"], source_revisions)
    for fact in case["facts"]:
        if not set(fact["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling fact evidence: {fact['factId']}")
        if fact["templateId"] == "fact.evidence_gap_profile":
            if fact["params"]["profileIdentity"] != {
                "profileSubjectRef": case["profileSubjectRef"],
                "profileObjectRef": case["profileObjectRef"],
            }:
                raise ValueError("evidence-gap Fact targets another profile subject")
        elif any(
            (
                evidence_by_id[evidence_id]["profileSubjectRef"],
                evidence_by_id[evidence_id]["profileObjectRef"],
            )
            != (case["profileSubjectRef"], case["profileObjectRef"])
            for evidence_id in fact["evidenceIds"]
        ):
            raise ValueError("Fact Evidence targets another profile subject")
        validate_fact_evidence_projection(fact, evidence_by_id)
        expected_fact = render_fact(fact)
        rendered_fact = {
            field: fact[field] for field in ("kind", "statementZh", "valueText")
        }
        if rendered_fact != expected_fact:
            raise ValueError(
                f"fact is not the deterministic typed rendering: {fact['factId']}"
            )
        bindings = fact_evidence_bindings(fact)
        if set(fact["evidenceIds"]) != set(bindings):
            raise ValueError(
                f"fact evidence does not match typed bindings: {fact['factId']}"
            )
        for evidence_id, expected_kind in bindings.items():
            if evidence_by_id[evidence_id]["kind"] != expected_kind:
                raise ValueError(
                    f"fact evidence kind mismatch: {fact['factId']} -> {evidence_id}"
                )

    diagnostic_evidence_ids = {
        evidence_id for fact in case["facts"] for evidence_id in fact["evidenceIds"]
    }
    derived_level = derive_evidence_level(case["evidence"], diagnostic_evidence_ids)
    if case["evidenceLevel"] != derived_level:
        raise ValueError(
            f"Case evidenceLevel is self-reported: expected {derived_level}"
        )
    derived_completeness = derive_completeness(
        case["decision"], facts_by_id, evidence_by_id
    )
    if case["evidenceCompleteness"] != derived_completeness:
        raise ValueError(
            "Case evidenceCompleteness is not derived from eligible Fact roles"
        )
    expected_findings = expected_rule_findings(
        case["pinnedRevisions"]["rulePack"],
        case["decision"],
        facts_by_id,
        evidence_by_id,
    )
    if case["ruleFindings"] != expected_findings:
        raise ValueError("rule findings are not the deterministic rule-pack result")
    if case["uncertainty"] != expected_uncertainty(case):
        raise ValueError("Case uncertainty is not the server-owned policy projection")

    for finding in case["ruleFindings"]:
        if not set(finding["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling rule evidence: {finding['ruleId']}")
        if (
            finding["status"] == "hit"
            and EVIDENCE_LEVELS[finding["minimumEvidenceLevel"]]
            > EVIDENCE_LEVELS[case["evidenceLevel"]]
        ):
            raise ValueError(f"rule exceeds Case evidence ceiling: {finding['ruleId']}")
    for action in case["actions"]:
        if not set(action["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling action evidence: {action['actionId']}")
        if not set(action["ruleIds"]) <= rule_ids:
            raise ValueError(f"dangling action rule: {action['actionId']}")
        expected_action = render_action(action)
        rendered_action = {
            field: action[field]
            for field in (
                "family",
                "titleZh",
                "rationaleZh",
                "risk",
                "ownerRole",
                "prerequisitesZh",
                "stepsZh",
                "validation",
                "rollbackZh",
                "requiresHumanApproval",
            )
        }
        if rendered_action != expected_action:
            raise ValueError(
                f"action is not the deterministic template rendering: {action['actionId']}"
            )

    claim_ids: set[str] = set()
    synthesis = case["aiSynthesis"]
    validate_ai_invocation(case)
    if synthesis is not None:
        claim_ids = require_unique(synthesis["claims"], "claimId")
        for claim in synthesis["claims"]:
            if not set(claim["evidenceIds"]) <= evidence_ids:
                raise ValueError(f"dangling claim evidence: {claim['claimId']}")
            if not set(claim["ruleIds"]) <= rule_ids:
                raise ValueError(f"dangling claim rule: {claim['claimId']}")
            if claim["textZh"] != render_ai_claim(claim):
                raise ValueError(
                    f"AI claim is not the deterministic template rendering: {claim['claimId']}"
                )
    if case["effectiveMode"] == "rules_ai" and (
        synthesis is None or synthesis["status"] != "applied" or not claim_ids
    ):
        raise ValueError("rules_ai effective mode requires applied AI claims")
    if (
        case["configuredMode"] == "rules_ai"
        and case["effectiveMode"] == "rules"
        and (synthesis is None or synthesis["status"] not in {"degraded", "abstained"})
    ):
        raise ValueError(
            "rules_ai fallback requires explicit degradation or abstention"
        )
    if (
        case["effectiveMode"] == "rules"
        and synthesis is not None
        and synthesis["status"] == "applied"
    ):
        raise ValueError("rules effective mode cannot expose applied AI synthesis")

    validate_diagnosis_dependency_closure(case, facts_by_id)
    decision = case["decision"]
    rendered_decision = render_decision(decision, facts_by_id)
    if any(decision[field] != value for field, value in rendered_decision.items()):
        raise ValueError("decision is not the deterministic template rendering")
    if decision["params"]["profileFactId"] not in fact_ids:
        raise ValueError("decision does not reference a typed profile fact")
    for summary in decision["evidenceSummary"]:
        if not set(summary["evidenceIds"]) <= evidence_ids:
            raise ValueError("decision summary contains dangling evidence")
    if not set(case["subject"]["businessEvidenceIds"]) <= evidence_ids:
        raise ValueError("business impact contains dangling evidence")
    business_evidence = [
        evidence_by_id[evidence_id]
        for evidence_id in case["subject"]["businessEvidenceIds"]
    ]
    for evidence in business_evidence:
        require_eligible(evidence, "business impact")
        if (
            evidence["profileSubjectRef"],
            evidence["profileObjectRef"],
        ) != (case["profileSubjectRef"], case["profileObjectRef"]):
            raise ValueError("business impact targets another profile subject")
    if not any(
        item["kind"] == "business_observation"
        and item["summaryZh"] == case["subject"]["businessZh"]
        for item in business_evidence
    ):
        raise ValueError("business impact lacks a matching business observation")
    if not set(decision["evidenceIds"]) <= evidence_ids:
        raise ValueError("decision contains dangling evidence")
    if not set(decision["ruleIds"]) <= rule_ids:
        raise ValueError("decision contains dangling rules")
    if not set(decision["claimIds"]) <= claim_ids:
        raise ValueError("decision contains dangling AI claims")
    if not set(decision["actionIds"]) <= action_ids:
        raise ValueError("decision contains dangling actions")
    if not set(case["subject"]["businessEvidenceIds"]) <= set(decision["evidenceIds"]):
        raise ValueError("decision omits business-impact evidence")

    for review in case["reviews"]:
        if review["caseRevision"] > case["revision"]:
            raise ValueError(
                f"review references a future Case revision: {review['reviewId']}"
            )
        if not (
            parse_time(case["createdAt"])
            <= parse_time(review["createdAt"])
            <= parse_time(case["updatedAt"])
        ):
            raise ValueError(
                f"review is outside the Case time window: {review['reviewId']}"
            )
        if not set(review["actionIds"]) <= action_ids:
            raise ValueError(f"review contains dangling action: {review['reviewId']}")
    for feedback in case["feedback"]:
        if feedback["caseRevision"] > case["revision"]:
            raise ValueError(
                f"feedback references a future Case revision: {feedback['feedbackId']}"
            )
        if not (
            parse_time(case["createdAt"])
            <= parse_time(feedback["createdAt"])
            <= parse_time(case["updatedAt"])
        ):
            raise ValueError(
                f"feedback is outside the Case time window: {feedback['feedbackId']}"
            )
        if feedback["actionId"] is not None and feedback["actionId"] not in action_ids:
            raise ValueError(
                f"feedback contains dangling action: {feedback['feedbackId']}"
            )
        if not set(feedback["evidenceIds"]) <= evidence_ids:
            raise ValueError(
                f"feedback contains dangling evidence: {feedback['feedbackId']}"
            )
    for event in case["transitionEvents"]:
        if event["type"] == "outcome":
            if not set(event["reviewIds"]) <= review_ids:
                raise ValueError(
                    f"transition contains dangling review: {event['eventId']}"
                )
            if not set(event["feedbackIds"]) <= feedback_ids:
                raise ValueError(
                    f"transition contains dangling feedback: {event['eventId']}"
                )
            if not set(event["actionIds"]) <= action_ids:
                raise ValueError(
                    f"transition contains dangling action: {event['eventId']}"
                )
            if not set(event["evidenceIds"]) <= evidence_ids:
                raise ValueError(
                    f"transition contains dangling evidence: {event['eventId']}"
                )

    if not source_ids and case["inputMode"] == "managed_source":
        raise ValueError("managed-source Case requires a Source snapshot")
    validate_transition_events(case)
    validate_outcome_semantics(case, authorization_not_before)


def require_append_only(
    prior_items: list[dict[str, Any]],
    proposed_items: list[dict[str, Any]],
    label: str,
) -> None:
    if len(proposed_items) < len(prior_items):
        raise ValueError(f"{label} cannot remove prior records")
    if proposed_items[: len(prior_items)] != prior_items:
        raise ValueError(f"{label} cannot rewrite or reorder prior records")


def validate_case_transition(prior: dict[str, Any], proposed: dict[str, Any]) -> None:
    if prior["caseId"] != proposed["caseId"]:
        raise ValueError("Case transition cannot change caseId")
    if proposed["revision"] != prior["revision"] + 1:
        raise ValueError("Case revision must increase by exactly one")
    if parse_time(proposed["updatedAt"]) <= parse_time(prior["updatedAt"]):
        raise ValueError("Case updatedAt must increase across revisions")

    immutable_fields = (
        "schemaVersion",
        "caseId",
        "profileSubjectRef",
        "profileObjectRef",
        "inputMode",
        "configuredMode",
        "createdAt",
    )
    for field in immutable_fields:
        if proposed[field] != prior[field]:
            raise ValueError(f"Case transition rewrites immutable field: {field}")

    append_only_fields = (
        "sourceSnapshots",
        "evidence",
        "facts",
        "ruleFindings",
        "actions",
        "uncertainty",
        "reviews",
        "feedback",
        "transitionEvents",
    )
    for field in append_only_fields:
        require_append_only(prior[field], proposed[field], f"Case {field}")

    if prior["workflowState"] == "ready":
        ready_immutable_fields = (
            "workflowState",
            "effectiveMode",
            "evidenceLevel",
            "subject",
            "decision",
            "sourceSnapshots",
            "facts",
            "ruleFindings",
            "aiSynthesis",
            "actions",
            "uncertainty",
            "pinnedRevisions",
        )
        for field in ready_immutable_fields:
            if proposed[field] != prior[field]:
                raise ValueError(f"ready Case transition rewrites field: {field}")

    prior_updated = parse_time(prior["updatedAt"])
    new_time_fields = {
        "evidence": "collectedAt",
        "reviews": "createdAt",
        "feedback": "createdAt",
        "transitionEvents": "createdAt",
    }
    for field, time_field in new_time_fields.items():
        for item in proposed[field][len(prior[field]) :]:
            if parse_time(item[time_field]) <= prior_updated:
                raise ValueError(f"new Case {field} record predates the prior revision")
            if (
                field in {"reviews", "feedback", "transitionEvents"}
                and item["caseRevision"] != proposed["revision"]
            ):
                raise ValueError(
                    f"new Case {field} record does not bind the proposed revision"
                )

    validate_case_references(prior)
    validate_case_references(proposed, prior_updated)


def build_evidence_insufficient_cases(
    case: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a ready actionless Case and its terminal insufficiency revision."""

    pending = copy.deepcopy(case)
    runtime_evidence = pending["evidence"][0]
    runtime_evidence["freshness"] = "stale"
    runtime_evidence["coverage"] = 0.5

    original_fact = pending["facts"][0]
    original_key = (original_fact["templateId"], original_fact["templateRevision"])
    role_assessments: list[dict[str, Any]] = []
    evidence_by_id = {item["evidenceId"]: item for item in pending["evidence"]}
    for role, dependency in FACT_DEPENDENCY_REGISTRY[original_key].items():
        evidence_id = original_fact["params"][role]
        reasons = evidence_eligibility_reasons(evidence_by_id[evidence_id])
        role_assessments.append(
            {
                "role": role,
                "expectedKind": dependency["kind"],
                "evidenceId": evidence_id,
                "eligible": not reasons,
                "reasonCodes": reasons,
            }
        )

    gap_fact = {
        "factId": original_fact["factId"],
        "templateId": "fact.evidence_gap_profile",
        "templateRevision": "v1",
        "params": {
            "attemptedDecisionTemplateId": case["decision"]["templateId"],
            "attemptedDecisionTemplateRevision": case["decision"]["templateRevision"],
            "profileIdentity": {
                "profileSubjectRef": case["profileSubjectRef"],
                "profileObjectRef": case["profileObjectRef"],
            },
            "roleAssessments": role_assessments,
        },
        "kind": "evidence_gap",
        "statementZh": "",
        "valueText": None,
        "evidenceIds": [
            item["evidenceId"]
            for item in role_assessments
            if item["evidenceId"] is not None
        ],
    }
    gap_fact.update(render_fact(gap_fact))
    pending["facts"] = [gap_fact]
    pending["decision"] = {
        "templateId": "decision.evidence_insufficient",
        "templateRevision": "v1",
        "params": {"profileFactId": gap_fact["factId"]},
        "titleZh": "",
        "priority": "observe",
        "conclusionZh": "",
        "evidenceSummary": [],
        "evidenceIds": [
            *gap_fact["evidenceIds"],
            *pending["subject"]["businessEvidenceIds"],
        ],
        "ruleIds": [],
        "claimIds": [],
        "actionIds": [],
    }
    pending["decision"].update(
        render_decision(pending["decision"], {gap_fact["factId"]: gap_fact})
    )
    pending["ruleFindings"] = []
    pending["actions"] = []
    pending["configuredMode"] = "rules_ai"
    pending["effectiveMode"] = "rules"
    pending["aiSynthesis"] = {
        "status": "abstained",
        "code": "EVIDENCE_POLICY_ABSTENTION",
        "messageZh": "证据策略不允许调用外部模型，本报告仅使用确定性规则。",
        "invocation": None,
        "claims": [],
    }
    for key in ("provider", "model", "prompt", "payload", "payloadDigest"):
        pending["pinnedRevisions"][key] = None
    pending["evidenceLevel"] = derive_evidence_level(
        pending["evidence"], set(gap_fact["evidenceIds"])
    )
    pending["evidenceCompleteness"] = derive_completeness(
        pending["decision"],
        {gap_fact["factId"]: gap_fact},
        evidence_by_id,
    )
    pending["uncertainty"] = expected_uncertainty(pending)

    terminal = copy.deepcopy(pending)
    terminal["revision"] = pending["revision"] + 1
    terminal["outcome"] = "evidence_insufficient"
    terminal["updatedAt"] = "2026-09-02T08:06:00Z"
    terminal["feedback"] = [
        {
            "feedbackId": "fb_0000000000000099",
            "caseRevision": terminal["revision"],
            "actor": {
                "kind": "system",
                "id": "diagnosis-policy",
                "displayName": "诊断证据策略",
            },
            "kind": "evidence_insufficient",
            "actionId": None,
            "evidenceIds": [],
            "createdAt": terminal["updatedAt"],
            "comment": "证据完整度不足，未发布根因或动作。",
        }
    ]
    terminal["transitionEvents"].append(
        {
            "eventId": "evt_0000000000000099",
            "caseRevision": terminal["revision"],
            "type": "outcome",
            "fromOutcome": "pending",
            "toOutcome": "evidence_insufficient",
            "actor": {
                "kind": "system",
                "id": "diagnosis-policy",
                "displayName": "诊断证据策略",
            },
            "createdAt": terminal["updatedAt"],
            "reason": "证据资格策略阻止发布诊断动作",
            "outcomeTuple": {
                "actionId": None,
                "approvalReviewId": None,
                "implementationFeedbackId": None,
                "resultEvidenceIds": [],
                "terminalFeedbackId": "fb_0000000000000099",
            },
            "reviewIds": [],
            "feedbackIds": ["fb_0000000000000099"],
            "actionIds": [],
            "evidenceIds": [],
        }
    )
    return pending, terminal


def build_validated_case(case: dict[str, Any]) -> dict[str, Any]:
    validated = copy.deepcopy(case)
    validated["revision"] = 2
    validated["outcome"] = "validated_effective"
    validated["updatedAt"] = "2026-09-02T08:12:00Z"

    result_specs = (
        ("0000000000000005", "average_scan_rows", 1_260_000, 100_000, "rows", "5"),
        ("0000000000000006", "p95_latency_ms", 2_800, 420, "ms", "6"),
        (
            "0000000000000007",
            "write_regression_basis_points",
            0,
            300,
            "basis_points",
            "7",
        ),
    )
    result_evidence_ids: list[str] = []
    for suffix, metric_code, baseline, observed, unit, digest_digit in result_specs:
        effect = copy.deepcopy(validated["evidence"][-1])
        evidence_id = f"ev_{suffix}"
        effect.update(
            {
                "evidenceId": evidence_id,
                "kind": "effect_metric_comparison",
                "observedAt": "2026-09-02T08:10:00Z",
                "collectedAt": "2026-09-02T08:11:00Z",
                "integrityDigest": f"sha256:{digest_digit * 64}",
            }
        )
        effect["payload"].update(
            {
                "schemaRevision": "effect-metric-comparison/v2",
                "storageRef": f"payload_{suffix}",
                "digest": effect["integrityDigest"],
                "typed": {
                    "kind": "effect_metric_comparison",
                    "actionId": "act_0000000000000001",
                    "metricCode": metric_code,
                    "validationTargetZh": validated["actions"][0]["validation"][
                        "targetZh"
                    ],
                    "baselineValue": baseline,
                    "observedValue": observed,
                    "unit": unit,
                },
            }
        )
        effect["payload"]["typedDigest"] = typed_payload_digest(
            effect["payload"]["typed"]
        )
        effect["summaryZh"] = render_evidence_summary(effect)
        validated["evidence"].append(effect)
        result_evidence_ids.append(evidence_id)
    validated["reviews"] = [
        {
            "reviewId": "rev_0000000000000001",
            "caseRevision": 2,
            "reviewer": {
                "kind": "user",
                "id": "owner",
                "displayName": "本机 Owner",
            },
            "authorizationSnapshot": {
                "auditRecordId": "authz_0000000000000001",
                "attestationRevision": "server-authorization-audit/v1",
            },
            "decision": "approved",
            "actionIds": ["act_0000000000000001"],
            "createdAt": "2026-09-02T08:06:00Z",
            "comment": "批准隔离环境验证，不批准自动生产变更。",
        }
    ]
    validated["feedback"] = [
        {
            "feedbackId": "fb_0000000000000001",
            "caseRevision": 2,
            "actor": {"kind": "user", "id": "owner", "displayName": "本机 Owner"},
            "kind": "implemented",
            "actionId": "act_0000000000000001",
            "evidenceIds": [],
            "createdAt": "2026-09-02T08:07:00Z",
            "comment": "已在隔离环境创建并验证候选索引。",
        },
        {
            "feedbackId": "fb_0000000000000002",
            "caseRevision": 2,
            "actor": {"kind": "user", "id": "owner", "displayName": "本机 Owner"},
            "kind": "validated",
            "actionId": "act_0000000000000001",
            "evidenceIds": result_evidence_ids,
            "createdAt": "2026-09-02T08:12:00Z",
            "comment": "隔离环境验证达到预设收益阈值。",
        },
    ]
    validated["transitionEvents"].append(
        {
            "eventId": "evt_0000000000000005",
            "caseRevision": 2,
            "type": "outcome",
            "fromOutcome": "pending",
            "toOutcome": "validated_effective",
            "actor": {"kind": "user", "id": "owner", "displayName": "本机 Owner"},
            "createdAt": "2026-09-02T08:12:00Z",
            "reason": "隔离环境验证达到预设收益阈值",
            "outcomeTuple": {
                "actionId": "act_0000000000000001",
                "approvalReviewId": "rev_0000000000000001",
                "implementationFeedbackId": "fb_0000000000000001",
                "resultEvidenceIds": result_evidence_ids,
                "terminalFeedbackId": "fb_0000000000000002",
            },
            "reviewIds": ["rev_0000000000000001"],
            "feedbackIds": [
                "fb_0000000000000001",
                "fb_0000000000000002",
            ],
            "actionIds": ["act_0000000000000001"],
            "evidenceIds": result_evidence_ids,
        }
    )
    return validated


def build_rolled_back_case(case: dict[str, Any]) -> dict[str, Any]:
    rolled_back = build_validated_case(case)
    rolled_back["outcome"] = "rolled_back"
    effect = next(
        item
        for item in rolled_back["evidence"]
        if item["kind"] == "effect_metric_comparison"
        and item["payload"]["typed"]["metricCode"] == "p95_latency_ms"
    )
    effect["payload"]["typed"]["observedValue"] = 800
    effect["payload"]["typedDigest"] = typed_payload_digest(effect["payload"]["typed"])
    effect["summaryZh"] = render_evidence_summary(effect)

    rollback = copy.deepcopy(effect)
    rollback.update(
        {
            "evidenceId": "ev_0000000000000008",
            "kind": "rollback_confirmation",
            "observedAt": "2026-09-02T08:10:30Z",
            "collectedAt": "2026-09-02T08:11:30Z",
            "integrityDigest": (
                "sha256:8888888888888888888888888888888888888888888888888888888888888888"
            ),
        }
    )
    rollback["payload"].update(
        {
            "schemaRevision": "rollback-confirmation/v1",
            "storageRef": "payload_0000000000000008",
            "digest": rollback["integrityDigest"],
            "typed": {
                "kind": "rollback_confirmation",
                "actionId": "act_0000000000000001",
                "rollbackState": "confirmed",
            },
        }
    )
    rollback["payload"]["typedDigest"] = typed_payload_digest(
        rollback["payload"]["typed"]
    )
    rollback["summaryZh"] = render_evidence_summary(rollback)
    rolled_back["evidence"].append(rollback)

    terminal = rolled_back["feedback"][-1]
    terminal["kind"] = "rolled_back"
    terminal["evidenceIds"] = [
        item["evidenceId"]
        for item in rolled_back["evidence"]
        if item["kind"] == "effect_metric_comparison"
    ] + [rollback["evidenceId"]]
    terminal["comment"] = "隔离环境验证未达阈值，已确认回滚完成。"
    event = rolled_back["transitionEvents"][-1]
    event["toOutcome"] = "rolled_back"
    event["reason"] = "验证未达阈值且回滚已确认"
    event["outcomeTuple"]["resultEvidenceIds"] = terminal["evidenceIds"]
    event["evidenceIds"] = terminal["evidenceIds"]
    return rolled_back


def projected_action(action: dict[str, Any], order: int) -> dict[str, Any]:
    return {
        "actionId": action["actionId"],
        "order": order,
        "titleZh": action["titleZh"],
        "rationaleZh": action["rationaleZh"],
        "ownerRole": action["ownerRole"],
        "risk": action["risk"],
        "prerequisitesZh": action["prerequisitesZh"],
        "stepsZh": action["stepsZh"],
        "validation": action["validation"],
        "rollbackZh": action["rollbackZh"],
    }


def build_report_projection(case: dict[str, Any], audience: str) -> dict[str, Any]:
    decision = case["decision"]
    rules_by_id = {item["ruleId"]: item for item in case["ruleFindings"]}
    claims_by_id = {item["claimId"]: item for item in case["aiSynthesis"]["claims"]}
    actions_by_id = {item["actionId"]: item for item in case["actions"]}
    return {
        "schemaVersion": "diagnosis-report/v1",
        "caseId": case["caseId"],
        "caseRevision": case["revision"],
        "audience": audience,
        "titleZh": decision["titleZh"],
        "priority": decision["priority"],
        "configuredMode": case["configuredMode"],
        "effectiveMode": case["effectiveMode"],
        "conclusionZh": decision["conclusionZh"],
        "impact": copy.deepcopy(case["subject"]),
        "evidenceSummary": copy.deepcopy(decision["evidenceSummary"]),
        "reasoning": {
            "ruleFindingsZh": [
                rules_by_id[item]["conclusionZh"] for item in decision["ruleIds"]
            ],
            "aiContributionZh": (
                "\n".join(claims_by_id[item]["textZh"] for item in decision["claimIds"])
                if decision["claimIds"]
                else None
            ),
            "aiStatus": case["aiSynthesis"]["status"],
            "aiCode": case["aiSynthesis"]["code"],
            "aiReasonZh": case["aiSynthesis"]["messageZh"],
        },
        "actions": [
            projected_action(actions_by_id[action_id], order)
            for order, action_id in enumerate(decision["actionIds"], start=1)
        ],
        "uncertainty": [item["descriptionZh"] for item in case["uncertainty"]],
        "trace": {
            "evidenceLevel": case["evidenceLevel"],
            "evidenceCompleteness": case["evidenceCompleteness"],
            "evidenceIds": decision["evidenceIds"],
            "ruleIds": decision["ruleIds"],
            "claimIds": decision["claimIds"],
            "sourceRevisions": [
                f"{item['sourceId']}@{item['revision']}"
                for item in case["sourceSnapshots"]
            ],
            "aiInvocation": case["aiSynthesis"]["invocation"],
            "pinnedRevisions": copy.deepcopy(case["pinnedRevisions"]),
        },
    }


def validate_report_projection(report: dict[str, Any], case: dict[str, Any]) -> None:
    validate_report_business_impact(report)
    if report["caseId"] != case["caseId"] or report["caseRevision"] != case["revision"]:
        raise ValueError("report projection does not identify its source Case revision")
    decision = case["decision"]
    exact_fields = {
        "titleZh": decision["titleZh"],
        "priority": decision["priority"],
        "configuredMode": case["configuredMode"],
        "effectiveMode": case["effectiveMode"],
        "conclusionZh": decision["conclusionZh"],
        "impact": case["subject"],
        "evidenceSummary": decision["evidenceSummary"],
        "uncertainty": [item["descriptionZh"] for item in case["uncertainty"]],
    }
    for field, expected in exact_fields.items():
        if report[field] != expected:
            raise ValueError(f"report projection rewrites Case field: {field}")

    rules_by_id = {item["ruleId"]: item for item in case["ruleFindings"]}
    claims_by_id = {
        item["claimId"]: item for item in (case["aiSynthesis"] or {}).get("claims", [])
    }
    expected_rule_text = [
        rules_by_id[item]["conclusionZh"] for item in decision["ruleIds"]
    ]
    expected_ai_text = (
        "\n".join(claims_by_id[item]["textZh"] for item in decision["claimIds"])
        if decision["claimIds"]
        else None
    )
    synthesis = case["aiSynthesis"]
    if report["reasoning"] != {
        "ruleFindingsZh": expected_rule_text,
        "aiContributionZh": expected_ai_text,
        "aiStatus": synthesis["status"],
        "aiCode": synthesis["code"],
        "aiReasonZh": synthesis["messageZh"],
    }:
        raise ValueError("report reasoning is not a Case projection")

    actions_by_id = {item["actionId"]: item for item in case["actions"]}
    expected_actions = [
        projected_action(actions_by_id[action_id], order)
        for order, action_id in enumerate(decision["actionIds"], start=1)
    ]
    if report["actions"] != expected_actions:
        raise ValueError("report actions are not a Case projection")

    expected_trace = {
        "evidenceLevel": case["evidenceLevel"],
        "evidenceCompleteness": case["evidenceCompleteness"],
        "evidenceIds": decision["evidenceIds"],
        "ruleIds": decision["ruleIds"],
        "claimIds": decision["claimIds"],
        "sourceRevisions": [
            f"{item['sourceId']}@{item['revision']}" for item in case["sourceSnapshots"]
        ],
        "aiInvocation": (case["aiSynthesis"] or {}).get("invocation"),
        "pinnedRevisions": case["pinnedRevisions"],
    }
    if report["trace"] != expected_trace:
        raise ValueError("report trace is not the exact decision provenance")


def validate_report_business_impact(report: dict[str, Any]) -> None:
    impact = report["impact"]
    if not impact["businessEvidenceIds"] and impact["businessZh"] != NO_BUSINESS_EVIDENCE_ZH:
        raise ValueError("report without business evidence must use the fixed M0 disclosure")


def validate_m0_review_report(
    report: dict[str, Any],
    *,
    expected_rule_id: str,
    expected_priority: str,
) -> None:
    validate_report_business_impact(report)
    if report["configuredMode"] != "rules" or report["effectiveMode"] != "rules":
        raise ValueError("M0 review report must be rules-only")
    if report["priority"] != expected_priority:
        raise ValueError("M0 review report priority differs from the frozen sample")
    if report["reasoning"] != {
        "ruleFindingsZh": report["reasoning"]["ruleFindingsZh"],
        "aiContributionZh": None,
        "aiStatus": "not_requested",
        "aiCode": None,
        "aiReasonZh": None,
    }:
        raise ValueError("M0 review report contains an AI contribution")
    trace = report["trace"]
    if trace["aiInvocation"] is not None:
        raise ValueError("M0 review report contains an AI invocation")
    pins = trace["pinnedRevisions"]
    if pins["rulePack"] != "tidb-8.5-m0-rules/v1":
        raise ValueError("M0 review report uses the wrong rule pack")
    if any(pins[key] is not None for key in ("provider", "model", "prompt", "payload")):
        raise ValueError("M0 review report contains a model pin")
    if pins["payloadDigest"] is not None:
        raise ValueError("M0 review report contains an AI payload digest")
    if trace["ruleIds"] != [expected_rule_id]:
        raise ValueError("M0 review report rule ID differs from the frozen sample")
    if trace["evidenceCompleteness"] != 100:
        raise ValueError("M0 positive review report must have complete required evidence")
    summarized_ids = {
        evidence_id
        for summary in report["evidenceSummary"]
        for evidence_id in summary["evidenceIds"]
    }
    if summarized_ids != set(trace["evidenceIds"]):
        raise ValueError("M0 review summary and trace Evidence IDs differ")
    if not report["actions"] or [action["order"] for action in report["actions"]] != list(
        range(1, len(report["actions"]) + 1)
    ):
        raise ValueError("M0 review actions are missing or out of order")
    rendered = str(report)
    if "20%" in rendered or "confidence" in rendered.lower():
        raise ValueError("M0 review report contains legacy fixed completeness prose")


def validate_m0_contract_increments() -> None:
    evidence_validator = schema_validator("evidence-v2.schema.json")
    report_validator = schema_validator("diagnosis-report-v1.schema.json")
    base_evidence = load(EXAMPLES / "evidence-v2.valid.json")
    vectors = (
        (
            "statistics-health/v1",
            "statistics",
            "orders",
            {
                "kind": "statistics",
                "profileSubjectRef": "subject_0000000000000002",
                "profileObjectRef": "orders",
                "tableName": "orders",
                "healthyPercent": 42,
            },
        ),
        (
            "statement-summary/v3",
            "statement_summary",
            f"sql:{'a' * 64}",
            {
                "kind": "statement_summary",
                "profileSubjectRef": "subject_0000000000000002",
                "profileObjectRef": f"sql:{'a' * 64}",
                "windowMinutes": 30,
                "executionCount": 18,
                "averageTotalKeys": 120_000,
                "averageProcessedKeys": 119_000,
                "weightedTotalKeys": 2_160_000,
                "sqlStability": "plan_and_scan_stable",
            },
        ),
    )
    for revision, kind, object_ref, typed in vectors:
        evidence = copy.deepcopy(base_evidence)
        evidence["kind"] = kind
        evidence["profileObjectRef"] = object_ref
        evidence["payload"]["schemaRevision"] = revision
        evidence["payload"]["typed"] = typed
        evidence["payload"]["typedDigest"] = typed_payload_digest(typed)
        evidence["summaryZh"] = render_evidence_summary(evidence)
        evidence_validator.validate(evidence)
        validate_evidence_semantics(
            evidence,
            evidence["caseId"],
            {"src_0000000000000001@3"},
        )
        wrong_revision = copy.deepcopy(evidence)
        wrong_revision["payload"]["schemaRevision"] = "unbound-m0-shape/v1"
        if evidence_validator.is_valid(wrong_revision):
            raise ValueError("M0 typed Evidence shape is not bound to its schema revision")

    report = load(EXAMPLES / REPORT_NAMES[0])
    report["impact"]["businessEvidenceIds"] = []
    report["impact"]["businessZh"] = NO_BUSINESS_EVIDENCE_ZH
    report_validator.validate(report)
    validate_report_business_impact(report)
    report["impact"]["businessZh"] = "没有证据，但仍给出业务影响"
    try:
        validate_report_business_impact(report)
    except ValueError:
        pass
    else:
        raise ValueError("empty business Evidence accepted non-disclosure copy")


def main() -> None:
    sources = validate_schema(
        "source-v1.schema.json",
        [
            "source-v1.valid.json",
            "source-v1.no-auth-draining.valid.json",
            "source-v1.tombstoned.valid.json",
        ],
    )
    evidence_examples = validate_schema(
        "evidence-v2.schema.json", ["evidence-v2.valid.json"]
    )
    cases = validate_schema("diagnosis-case-v2.schema.json", list(CASE_NAMES))
    reports = validate_schema("diagnosis-report-v1.schema.json", list(REPORT_NAMES))
    m0_reports = validate_schema(
        "diagnosis-report-v1.schema.json",
        [name for name, _, _ in M0_REPORT_EXPECTATIONS],
    )
    for source in sources:
        validate_source_semantics(source)
    draining_source, rotated_source = build_source_rotation(sources[0])
    source_validator = schema_validator("source-v1.schema.json")
    source_validator.validate(draining_source)
    source_validator.validate(rotated_source)
    validate_source_transition(sources[0], draining_source)
    validate_source_transition(draining_source, rotated_source)
    leased_source, leased_draining, drained_source = build_source_lease_drain(
        sources[0]
    )
    source_validator.validate(leased_source)
    source_validator.validate(leased_draining)
    source_validator.validate(drained_source)
    validate_source_transition(sources[0], leased_source)
    validate_source_transition(leased_source, leased_draining)
    validate_source_transition(leased_draining, drained_source)
    verification_failure_draining = build_source_verification_failure_drain(
        leased_source
    )
    source_validator.validate(verification_failure_draining)
    validate_source_transition(leased_source, verification_failure_draining)
    available_source_revisions = {
        f"{source['sourceId']}@{source['revision']}" for source in sources
    }
    for evidence in evidence_examples:
        if evidence["caseId"] != "case_0000000000000002":
            raise ValueError("standalone Evidence fixture has unexpected Case")
        validate_standalone_evidence(evidence, available_source_revisions)
    cases_by_revision = {(case["caseId"], case["revision"]): case for case in cases}
    for case in cases:
        validate_case_references(case)
    abstained_case = copy.deepcopy(cases[1])
    abstained_case["aiSynthesis"] = {
        "status": "abstained",
        "code": "EVIDENCE_POLICY_ABSTENTION",
        "messageZh": "证据策略不允许调用外部模型，本报告仅使用确定性规则。",
        "invocation": None,
        "claims": [],
    }
    for key in ("provider", "model", "prompt", "payload", "payloadDigest"):
        abstained_case["pinnedRevisions"][key] = None
    schema_validator("diagnosis-case-v2.schema.json").validate(abstained_case)
    validate_case_references(abstained_case)
    rules_only_case = copy.deepcopy(cases[1])
    rules_only_case["configuredMode"] = "rules"
    rules_only_case["aiSynthesis"] = {
        "status": "not_requested",
        "code": "AI_NOT_REQUESTED",
        "messageZh": "此诊断配置为仅规则模式，未调用外部模型。",
        "invocation": None,
        "claims": [],
    }
    for key in ("provider", "model", "prompt", "payload", "payloadDigest"):
        rules_only_case["pinnedRevisions"][key] = None
    rules_only_case["uncertainty"] = expected_uncertainty(rules_only_case)
    schema_validator("diagnosis-case-v2.schema.json").validate(rules_only_case)
    validate_case_references(rules_only_case)
    terminal_case = build_validated_case(cases[0])
    schema_validator("diagnosis-case-v2.schema.json").validate(terminal_case)
    validate_case_references(terminal_case)
    validate_case_transition(cases[0], terminal_case)
    rolled_back_case = build_rolled_back_case(cases[0])
    schema_validator("diagnosis-case-v2.schema.json").validate(rolled_back_case)
    validate_case_references(rolled_back_case)
    validate_case_transition(cases[0], rolled_back_case)
    insufficient_pending, insufficient_terminal = build_evidence_insufficient_cases(
        cases[0]
    )
    case_validator = schema_validator("diagnosis-case-v2.schema.json")
    for candidate in (insufficient_pending, insufficient_terminal):
        case_validator.validate(candidate)
        validate_case_references(candidate)
    validate_case_transition(insufficient_pending, insufficient_terminal)
    for report in reports:
        key = (report["caseId"], report["caseRevision"])
        if key not in cases_by_revision:
            raise ValueError(f"report has no matching Case fixture: {key}")
        validate_report_projection(report, cases_by_revision[key])
    for report, (_, rule_id, priority) in zip(
        m0_reports, M0_REPORT_EXPECTATIONS, strict=True
    ):
        validate_m0_review_report(
            report,
            expected_rule_id=rule_id,
            expected_priority=priority,
        )
    rules_only_report = copy.deepcopy(reports[1])
    rules_only_report["configuredMode"] = "rules"
    rules_only_report["reasoning"].update(
        {
            "aiStatus": "not_requested",
            "aiCode": "AI_NOT_REQUESTED",
            "aiReasonZh": "此诊断配置为仅规则模式，未调用外部模型。",
        }
    )
    rules_only_report["trace"]["aiInvocation"] = None
    rules_only_report["trace"]["pinnedRevisions"] = copy.deepcopy(
        rules_only_case["pinnedRevisions"]
    )
    rules_only_report["uncertainty"] = [
        item["descriptionZh"] for item in rules_only_case["uncertainty"]
    ]
    schema_validator("diagnosis-report-v1.schema.json").validate(rules_only_report)
    validate_report_projection(rules_only_report, rules_only_case)
    insufficient_report = build_report_projection(
        insufficient_pending, "incident_owner"
    )
    schema_validator("diagnosis-report-v1.schema.json").validate(insufficient_report)
    validate_report_projection(insufficient_report, insufficient_pending)
    validate_m0_contract_increments()
    print(
        "vNext contract examples valid: "
        "3 sources, 1 lease-drain chain, 1 standalone evidence, 3 cases, "
        "1 AI abstention, 1 rules-only projection, 3 terminal transitions, "
        "4 report projections, 2 M0 typed Evidence increments, 3 M0 review reports"
    )


if __name__ == "__main__":
    main()
