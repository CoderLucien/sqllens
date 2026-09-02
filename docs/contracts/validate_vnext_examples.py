from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, RefResolver

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
    "validated_effective": {"validated_effective"},
    "rolled_back": {"rolled_back"},
    "evidence_insufficient": {"evidence_insufficient"},
    "risk_accepted": {"risk_accepted"},
}
SOURCE_STATE_TRANSITIONS = {
    "draft": {"draft", "enabled", "verification_failed", "draining"},
    "enabled": {"enabled", "draining"},
    "draining": {"draining", "enabled", "disabled", "tombstoned"},
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
    "rotation_started": {("enabled", "draining")},
    "rotation_completed": {("draining", "enabled")},
    "disable_started": {("enabled", "draining")},
    "disabled": {("draining", "disabled")},
    "delete_started": {("enabled", "draining"), ("disabled", "draining")},
    "tombstoned": {("draining", "tombstoned")},
    "verification_failed": {
        ("draft", "verification_failed"),
        ("enabled", "verification_failed"),
    },
}
EVIDENCE_LEVELS = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4}
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
RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:"
    r"(?:[0-5]\d|60)(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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


def render_decision(decision: dict[str, Any]) -> dict[str, str]:
    key = (decision["templateId"], decision["templateRevision"])
    params = decision["params"]
    if key == ("decision.index_scan_priority", "v1"):
        return {
            "titleZh": "订单查询存在高频全表扫描，优先验证复合索引候选",
            "conclusionZh": (
                f"该 SQL 是当前 {params['windowMinutes']} 分钟窗口的主要可行动瓶颈："
                f"{params['callCount']} 次调用平均扫描 "
                f"{params['averageScanRowsTenThousands']} 万行，普通计划为全表扫描，"
                "建议先在隔离环境验证索引候选。"
            ),
        }
    if key == ("decision.statistics_estimation", "v1"):
        return {
            "titleZh": "统计信息偏差导致 Join 顺序失真，先验证统计而不是直接加索引",
            "conclusionZh": (
                f"执行计划对核心表估算 {params['estimatedRows']} 行，"
                f"实际运行证据为 {params['actualRows'] // 10000} 万行；"
                "估算偏差足以改变 Join 顺序，应先在隔离环境刷新并验证统计。"
            ),
        }
    if key == ("decision.runtime_hotspot", "v1"):
        if params:
            raise ValueError("runtime hotspot decision does not accept parameters")
        return {
            "titleZh": "SQL 延迟与 TiKV 热点时间窗一致，优先处置热点而不是改写 SQL",
            "conclusionZh": (
                "告警窗口内 SQL 计划和扫描量稳定，但目标 Region 的 TiKV 延迟与热点指标"
                "同步升高；当前更支持资源热点，而不是 SQL 结构退化。"
            ),
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
                    f"P95 低于 {params['maxP95Ms']} ms，写入回归在审批阈值内"
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
    pins = case["pinnedRevisions"]
    invocation_keys = ("provider", "model", "prompt", "payload", "payloadDigest")
    if synthesis is None or synthesis["status"] == "not_requested":
        if any(pins[key] is not None for key in invocation_keys):
            raise ValueError("non-invoked AI cannot retain invocation revisions")
        return

    invocation = synthesis["invocation"]
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


def validate_source_semantics(source: dict[str, Any]) -> None:
    validate_source_audit(source)
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
    if not new_events:
        raise ValueError("Source revision requires an appended audit event")
    if any(event["sourceRevision"] != proposed["revision"] for event in new_events):
        raise ValueError("new Source audit event must bind the proposed revision")
    if any(
        parse_time(event["createdAt"]) <= parse_time(prior["updatedAt"])
        for event in new_events
    ):
        raise ValueError("new Source audit event predates the prior revision")

    if proposed["state"] not in SOURCE_STATE_TRANSITIONS[prior["state"]]:
        raise ValueError("illegal Source state transition")
    prior_lifecycle = prior["credentialLifecycle"]
    proposed_lifecycle = proposed["credentialLifecycle"]
    if (
        proposed["state"] == "draining"
        and proposed_lifecycle["activeLeaseCount"] > prior_lifecycle["activeLeaseCount"]
    ):
        raise ValueError("Source cannot acquire leases while entering/draining")
    if prior["state"] == "draining":
        if proposed_lifecycle["activeLeaseCount"] > prior_lifecycle["activeLeaseCount"]:
            raise ValueError("draining Source cannot acquire new leases")
        if proposed["state"] == "draining":
            for field in ("pendingOperation", "retireAfter"):
                if proposed_lifecycle[field] != prior_lifecycle[field]:
                    raise ValueError("draining Source cannot rewrite pending operation")
        else:
            if prior_lifecycle["activeLeaseCount"] != 0:
                raise ValueError("Source cannot leave draining with active leases")
            expected_state = {
                "rotate": "enabled",
                "disable": "disabled",
                "delete": "tombstoned",
            }[prior_lifecycle["pendingOperation"]]
            if proposed["state"] != expected_state:
                raise ValueError(
                    "Source drain completion does not match pending operation"
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
        "activeLeaseCount": 0,
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
            "actor": {"kind": "user", "id": "owner", "displayName": "本机 Owner"},
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
                "id": "source-lifecycle",
                "displayName": "数据源生命周期",
            },
            "createdAt": rotated["updatedAt"],
            "reason": "旧租约归零，启用新凭据 revision",
        }
    )
    return draining, rotated


def validate_evidence_semantics(
    evidence: dict[str, Any],
    case_id: str,
    source_revisions: set[str],
) -> None:
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
    if case["outcome"] != "pending" and not any(
        event["type"] == "outcome"
        and event["caseRevision"] == case["revision"]
        and event["toOutcome"] == case["outcome"]
        for event in case["transitionEvents"]
    ):
        raise ValueError(
            "terminal outcome requires a transition event in this revision"
        )


def validate_outcome_semantics(case: dict[str, Any]) -> None:
    outcome = case["outcome"]
    if outcome == "pending":
        return
    action_ids = {item["actionId"] for item in case["actions"]}
    evidence_by_id = {item["evidenceId"]: item for item in case["evidence"]}
    current_events = [
        event
        for event in case["transitionEvents"]
        if event["type"] == "outcome"
        and event["caseRevision"] == case["revision"]
        and event["toOutcome"] == outcome
    ]

    if outcome == "risk_accepted":
        reviews = [
            item
            for item in case["reviews"]
            if item["decision"] == "risk_accepted"
            and item["caseRevision"] == case["revision"]
            and set(item["actionIds"]) & action_ids
        ]
        if not reviews or not any(
            any(
                review["reviewId"] in event["reviewIds"]
                and bool(set(review["actionIds"]) & set(event["actionIds"]))
                for review in reviews
            )
            for event in current_events
        ):
            raise ValueError(
                "risk_accepted requires linked review and transition event"
            )
        return

    if outcome == "evidence_insufficient":
        feedback = [
            item
            for item in case["feedback"]
            if item["kind"] == outcome and item["caseRevision"] == case["revision"]
        ]
        if not feedback or not any(
            any(item["feedbackId"] in event["feedbackIds"] for item in feedback)
            for event in current_events
        ):
            raise ValueError(
                "evidence_insufficient requires feedback and transition event"
            )
        return

    terminal_kind = "validated" if outcome == "validated_effective" else "rolled_back"
    required_evidence = (
        {"effect_metric_comparison"}
        if outcome == "validated_effective"
        else {"effect_metric_comparison", "rollback_confirmation"}
    )
    for terminal in [
        item
        for item in case["feedback"]
        if item["kind"] == terminal_kind and item["caseRevision"] == case["revision"]
    ]:
        action_id = terminal["actionId"]
        if action_id not in action_ids:
            continue
        approvals = [
            item
            for item in case["reviews"]
            if item["decision"] == "approved" and action_id in item["actionIds"]
        ]
        implementations = [
            item
            for item in case["feedback"]
            if item["kind"] == "implemented" and item["actionId"] == action_id
        ]
        result_evidence = [
            evidence_by_id[evidence_id]
            for evidence_id in terminal["evidenceIds"]
            if evidence_id in evidence_by_id
        ]
        if required_evidence - {item["kind"] for item in result_evidence}:
            continue
        terminal_at = parse_time(terminal["createdAt"])
        causal_chain = any(
            parse_time(review["createdAt"])
            <= parse_time(implementation["createdAt"])
            <= min(parse_time(item["observedAt"]) for item in result_evidence)
            <= max(parse_time(item["collectedAt"]) for item in result_evidence)
            <= terminal_at
            for review in approvals
            for implementation in implementations
        )
        if causal_chain:
            for event in current_events:
                if (
                    action_id in event["actionIds"]
                    and set(terminal["evidenceIds"]) <= set(event["evidenceIds"])
                    and terminal["feedbackId"] in event["feedbackIds"]
                    and any(
                        review["reviewId"] in event["reviewIds"] for review in approvals
                    )
                    and any(
                        implementation["feedbackId"] in event["feedbackIds"]
                        for implementation in implementations
                    )
                ):
                    return
    raise ValueError(f"{outcome} lacks one linked, ordered outcome evidence chain")


def validate_case_references(case: dict[str, Any]) -> None:
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
    require_unique(case["facts"], "factId")
    rule_ids = require_unique(case["ruleFindings"], "ruleId")
    action_ids = require_unique(case["actions"], "actionId")
    review_ids = require_unique(case["reviews"], "reviewId")
    feedback_ids = require_unique(case["feedback"], "feedbackId")

    for evidence in case["evidence"]:
        validate_evidence_semantics(evidence, case["caseId"], source_revisions)
    for fact in case["facts"]:
        if not set(fact["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling fact evidence: {fact['factId']}")
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
        case["effectiveMode"] == "rules"
        and synthesis is not None
        and synthesis["status"] == "applied"
    ):
        raise ValueError("rules effective mode cannot expose applied AI synthesis")

    decision = case["decision"]
    rendered_decision = render_decision(decision)
    if any(decision[field] != value for field, value in rendered_decision.items()):
        raise ValueError("decision is not the deterministic template rendering")
    for summary in decision["evidenceSummary"]:
        if not set(summary["evidenceIds"]) <= evidence_ids:
            raise ValueError("decision summary contains dangling evidence")
    if not set(case["subject"]["businessEvidenceIds"]) <= evidence_ids:
        raise ValueError("business impact contains dangling evidence")
    business_evidence = [
        evidence_by_id[evidence_id]
        for evidence_id in case["subject"]["businessEvidenceIds"]
    ]
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
    validate_outcome_semantics(case)


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

    validate_case_references(prior)
    validate_case_references(proposed)


def build_validated_case(case: dict[str, Any]) -> dict[str, Any]:
    validated = copy.deepcopy(case)
    validated["revision"] = 2
    validated["outcome"] = "validated_effective"
    validated["updatedAt"] = "2026-09-02T08:12:00Z"

    effect = copy.deepcopy(validated["evidence"][-1])
    effect.update(
        {
            "evidenceId": "ev_0000000000000005",
            "kind": "effect_metric_comparison",
            "observedAt": "2026-09-02T08:10:00Z",
            "collectedAt": "2026-09-02T08:11:00Z",
            "integrityDigest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            "summaryZh": "隔离环境验证显示扫描行数下降 94%，P95 降至 420 ms。",
        }
    )
    effect["payload"].update(
        {
            "schemaRevision": "effect-metric-comparison/v1",
            "storageRef": "payload_0000000000000005",
            "digest": effect["integrityDigest"],
        }
    )
    validated["evidence"].append(effect)
    validated["reviews"] = [
        {
            "reviewId": "rev_0000000000000001",
            "caseRevision": 1,
            "reviewer": {
                "kind": "user",
                "id": "owner",
                "displayName": "本机 Owner",
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
            "caseRevision": 1,
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
            "evidenceIds": ["ev_0000000000000005"],
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
            "reviewIds": ["rev_0000000000000001"],
            "feedbackIds": [
                "fb_0000000000000001",
                "fb_0000000000000002",
            ],
            "actionIds": ["act_0000000000000001"],
            "evidenceIds": ["ev_0000000000000005"],
        }
    )
    return validated


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


def validate_report_projection(report: dict[str, Any], case: dict[str, Any]) -> None:
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
    expected_code = (
        synthesis["code"] if synthesis and synthesis["status"] == "degraded" else None
    )
    expected_degradation = synthesis["messageZh"] if expected_code else None
    if report["reasoning"] != {
        "ruleFindingsZh": expected_rule_text,
        "aiContributionZh": expected_ai_text,
        "degradationCode": expected_code,
        "degradationZh": expected_degradation,
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
    for source in sources:
        validate_source_semantics(source)
    draining_source, rotated_source = build_source_rotation(sources[0])
    source_validator = schema_validator("source-v1.schema.json")
    source_validator.validate(draining_source)
    source_validator.validate(rotated_source)
    validate_source_transition(sources[0], draining_source)
    validate_source_transition(draining_source, rotated_source)
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
    terminal_case = build_validated_case(cases[0])
    schema_validator("diagnosis-case-v2.schema.json").validate(terminal_case)
    validate_case_references(terminal_case)
    validate_case_transition(cases[0], terminal_case)
    for report in reports:
        key = (report["caseId"], report["caseRevision"])
        if key not in cases_by_revision:
            raise ValueError(f"report has no matching Case fixture: {key}")
        validate_report_projection(report, cases_by_revision[key])
    print(
        "vNext contract examples valid: "
        "3 sources, 1 standalone evidence, 3 cases, 1 terminal transition, "
        "3 reports"
    )


if __name__ == "__main__":
    main()
