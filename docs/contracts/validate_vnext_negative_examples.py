from __future__ import annotations

import copy
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import validate_vnext_examples as contracts
from jsonschema import ValidationError
from validate_vnext_examples import (
    EXAMPLES,
    ROOT,
    build_rolled_back_case,
    build_validated_case,
    load,
    schema_validator,
    validate_case_references,
    validate_report_projection,
    validate_source_semantics,
)
from vnext_canonical_json import canonical_sha256

REJECTED = 0


def expect_error(action: Callable[[], None], label: str) -> None:
    global REJECTED
    try:
        action()
    except (TypeError, ValidationError, ValueError):
        REJECTED += 1
        return
    raise AssertionError(f"negative contract case was accepted: {label}")


def typed_digest(value: dict[str, Any]) -> str:
    return canonical_sha256(value)


def main() -> None:
    case_validator = schema_validator("diagnosis-case-v2.schema.json")
    source_validator = schema_validator("source-v1.schema.json")
    evidence_validator = schema_validator("evidence-v2.schema.json")
    case = load(EXAMPLES / "diagnosis-case-v2.valid.json")
    statistics_case = load(EXAMPLES / "diagnosis-case-v2.statistics.valid.json")
    report = load(EXAMPLES / "diagnosis-report-v1.index-access.review.json")
    source = load(EXAMPLES / "source-v1.valid.json")
    evidence = load(EXAMPLES / "evidence-v2.valid.json")

    with tempfile.TemporaryDirectory() as directory:
        duplicate_json = Path(directory) / "duplicate.json"
        duplicate_json.write_text(
            '{"typed":{"kind":"attacker","kind":"slow_query"}}',
            encoding="utf-8",
        )
        expect_error(
            lambda: load(duplicate_json),
            "JSON ingress collapses a nested duplicate object member",
        )

    invalid_evidence = copy.deepcopy(evidence)
    invalid_evidence["payload"].pop("canonicalRevision")
    expect_error(
        lambda: evidence_validator.validate(invalid_evidence),
        "typed Evidence omits its canonical serialization revision",
    )

    invalid_evidence = copy.deepcopy(evidence)
    invalid_evidence.pop("profileSubjectRef")
    expect_error(
        lambda: evidence_validator.validate(invalid_evidence),
        "Evidence omits its server-owned profile subject identity",
    )

    invalid_evidence = copy.deepcopy(
        next(item for item in case["evidence"] if item["kind"] == "index")
    )
    invalid_evidence["profileObjectRef"] = "customers"
    invalid_evidence["payload"]["typed"]["profileObjectRef"] = "customers"
    invalid_evidence["payload"]["typedDigest"] = typed_digest(
        invalid_evidence["payload"]["typed"]
    )
    expect_error(
        lambda: contracts.validate_standalone_evidence(
            invalid_evidence,
            {
                f"{item['sourceId']}@{item['revision']}"
                for item in case["sourceSnapshots"]
            },
        ),
        "table-scoped Evidence object identity differs from typed tableName",
    )

    invalid_evidence = copy.deepcopy(evidence)
    invalid_evidence["profileSubjectRef"] = "subject_0000000000000099"
    expect_error(
        lambda: contracts.validate_standalone_evidence(
            invalid_evidence,
            {
                f"{item['sourceId']}@{item['revision']}"
                for item in case["sourceSnapshots"]
            },
        ),
        "Evidence envelope relabels an unchanged canonical typed subject",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case.pop("profileObjectRef")
    expect_error(
        lambda: case_validator.validate(invalid_case),
        "Case omits its server-owned profile object identity",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["evidence"][0]["profileObjectRef"] = "customers"
    expect_error(
        lambda: validate_case_references(invalid_case),
        "Fact role Evidence binds another profile object",
    )

    invalid_evidence = copy.deepcopy(evidence)
    invalid_evidence["payload"]["canonicalRevision"] = "python-json/v1"
    expect_error(
        lambda: contracts.validate_standalone_evidence(
            invalid_evidence,
            {"src_0000000000000001@3"},
        ),
        "typed Evidence selects an implementation-specific canonical revision",
    )

    def validate_source(candidate: dict[str, Any]) -> None:
        source_validator.validate(candidate)
        validate_source_semantics(candidate)

    def validate_rerendered_fact_case(candidate: dict[str, Any]) -> None:
        candidate["facts"][0].update(contracts.render_fact(candidate["facts"][0]))
        candidate["decision"].update(
            contracts.render_decision(
                candidate["decision"],
                {item["factId"]: item for item in candidate["facts"]},
            )
        )
        validate_case_references(candidate)

    for outcome in ("validated_effective", "risk_accepted"):
        invalid = copy.deepcopy(case)
        invalid["workflowState"] = "queued"
        invalid["outcome"] = outcome
        invalid["sourceSnapshots"] = []
        invalid["evidence"] = []
        invalid["facts"] = []
        invalid["ruleFindings"] = []
        invalid["actions"] = []
        expect_error(
            lambda invalid=invalid: case_validator.validate(invalid),
            f"queued case with terminal outcome {outcome}",
        )

    projection_mutations = {
        "configured mode": ("configuredMode", "rules"),
        "effective mode": ("effectiveMode", "rules"),
        "conclusion": ("conclusionZh", "A fabricated conclusion."),
    }
    for label, (field, value) in projection_mutations.items():
        invalid = copy.deepcopy(report)
        invalid[field] = value
        expect_error(
            lambda invalid=invalid: validate_report_projection(invalid, case),
            f"report rewrites {label}",
        )

    invalid = copy.deepcopy(report)
    invalid["impact"]["businessZh"] = "A fabricated impact with no Case fact."
    expect_error(
        lambda: validate_report_projection(invalid, case),
        "report rewrites impact",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["subject"]["businessZh"] = "没有证据支持的业务影响。"
    expect_error(
        lambda: validate_case_references(invalid_case),
        "Case business impact has no matching observation evidence",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["aiSynthesis"]["claims"][0]["textZh"] = (
        "立即 DROP TABLE production.orders"
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "AI claim bypasses the server template registry",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["decision"]["conclusionZh"] = "立即 DROP TABLE production.orders"
    expect_error(
        lambda: validate_case_references(invalid_case),
        "decision conclusion bypasses the server template registry",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["decision"]["params"]["callCount"] = 999999999
    expect_error(
        lambda: validate_case_references(invalid_case),
        "decision numeric values are not bound to typed facts and evidence",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["facts"][0]["params"]["callCount"] = 999999999
    invalid_case["decision"].update(
        contracts.render_decision(
            invalid_case["decision"],
            {item["factId"]: item for item in invalid_case["facts"]},
        )
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "decision and conclusion rewrite a typed fact without rerendering its audit text",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["facts"][0]["params"].update(
        {
            "callCount": 999999999,
            "p95Ms": 1,
            "tableName": "fabricated_table",
        }
    )
    invalid_case["facts"][0].update(contracts.render_fact(invalid_case["facts"][0]))
    invalid_case["decision"].update(
        contracts.render_decision(
            invalid_case["decision"],
            {item["factId"]: item for item in invalid_case["facts"]},
        )
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "typed Fact raw values are fabricated independently from Evidence payload",
    )

    invalid_case = copy.deepcopy(case)
    slow_evidence = next(
        item for item in invalid_case["evidence"] if item["kind"] == "slow_query"
    )
    slow_evidence["payload"]["typed"].update({"callCount": 999999999, "p95Ms": 1})
    slow_evidence["summaryZh"] = (
        "该 SQL 在 10 分钟窗口内执行 999999999 次，P95 1 ms，平均扫描 126 万行。"
    )
    invalid_case["facts"][0]["params"].update({"callCount": 999999999, "p95Ms": 1})
    invalid_case["facts"][0].update(contracts.render_fact(invalid_case["facts"][0]))
    invalid_case["decision"].update(
        contracts.render_decision(
            invalid_case["decision"],
            {item["factId"]: item for item in invalid_case["facts"]},
        )
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "typed Evidence projection changes without updating its canonical digest",
    )

    invalid_case = copy.deepcopy(case)
    slow_evidence = next(
        item for item in invalid_case["evidence"] if item["kind"] == "slow_query"
    )
    slow_evidence["payload"]["typed"].update({"callCount": 999999999, "p95Ms": 1})
    slow_evidence["payload"]["typedDigest"] = typed_digest(
        slow_evidence["payload"]["typed"]
    )
    invalid_case["facts"][0]["params"].update({"callCount": 999999999, "p95Ms": 1})
    invalid_case["facts"][0].update(contracts.render_fact(invalid_case["facts"][0]))
    invalid_case["decision"].update(
        contracts.render_decision(
            invalid_case["decision"],
            {item["factId"]: item for item in invalid_case["facts"]},
        )
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "typed Evidence summary is not the deterministic typed projection",
    )

    invalid_case = copy.deepcopy(case)
    aliased_evidence_id = invalid_case["facts"][0]["params"]["indexEvidenceId"]
    invalid_case["facts"][0]["params"].update(
        {
            "runtimeEvidenceId": aliased_evidence_id,
            "planEvidenceId": aliased_evidence_id,
        }
    )
    invalid_case["facts"][0]["evidenceIds"] = [aliased_evidence_id]
    invalid_case["facts"][0].update(contracts.render_fact(invalid_case["facts"][0]))
    invalid_case["decision"].update(
        contracts.render_decision(
            invalid_case["decision"],
            {item["factId"]: item for item in invalid_case["facts"]},
        )
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "one Evidence object aliases multiple typed Fact roles",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["decision"]["evidenceIds"] = list(
        invalid_case["subject"]["businessEvidenceIds"]
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "decision omits the evidence provenance of its Fact, Rule, Claim, and Action",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["facts"][0]["params"]["scanReturnRatio"] = 999999999
    expect_error(
        lambda: validate_rerendered_fact_case(invalid_case),
        "derived scan/return ratio is supplied independently from raw fact values",
    )

    invalid_case = copy.deepcopy(statistics_case)
    invalid_case["facts"][0]["params"]["estimateRatio"] = 1
    expect_error(
        lambda: validate_rerendered_fact_case(invalid_case),
        "derived estimate ratio is supplied independently from raw fact values",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["facts"][0]["params"]["averageReturnRows"] = 1260001
    expect_error(
        lambda: validate_rerendered_fact_case(invalid_case),
        "index fact returns more rows than it scans",
    )

    invalid_case = copy.deepcopy(statistics_case)
    invalid_case["facts"][0]["params"]["estimatedRows"] = 0
    expect_error(
        lambda: validate_rerendered_fact_case(invalid_case),
        "statistics ratio uses a zero denominator",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["decision"]["evidenceSummary"][0].update(
        {
            "labelZh": "立即执行",
            "valueZh": "立即 DROP TABLE production.orders",
        }
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "decision evidence summary bypasses deterministic rendering",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["decision"]["priority"] = "P0"
    expect_error(
        lambda: validate_case_references(invalid_case),
        "decision priority bypasses deterministic rendering",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["evidence"][0]["kind"] = "ordinary_plan"
    invalid_case["evidence"][1]["kind"] = "slow_query"
    expect_error(
        lambda: validate_case_references(invalid_case),
        "typed fact binds an evidence ID with the wrong evidence kind",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["actions"][0]["stepsZh"] = ["立即 DROP TABLE production.orders"]
    invalid_case["actions"][0]["rollbackZh"] = ["无法回滚"]
    expect_error(
        lambda: validate_case_references(invalid_case),
        "action bypasses the server template registry",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["pinnedRevisions"]["provider"] = None
    invalid_case["pinnedRevisions"]["model"] = None
    invalid_case["pinnedRevisions"]["prompt"] = None
    expect_error(
        lambda: validate_case_references(invalid_case),
        "applied AI synthesis omits invocation provenance",
    )

    invalid_case = copy.deepcopy(statistics_case)
    invalid_case["aiSynthesis"] = None
    for key in ("provider", "model", "prompt", "payload", "payloadDigest"):
        invalid_case["pinnedRevisions"][key] = None
    expect_error(
        lambda: validate_case_references(invalid_case),
        "rules_ai silently falls back to rules without an abstention record",
    )

    invalid_case = copy.deepcopy(statistics_case)
    invalid_case["aiSynthesis"] = {
        "status": "abstained",
        "code": "EVIDENCE_POLICY_ABSTENTION",
        "messageZh": "证据策略不允许调用外部模型，本报告仅使用确定性规则。",
        "invocation": None,
        "claims": [],
    }
    expect_error(
        lambda: validate_case_references(invalid_case),
        "non-invoked AI abstention retains provider invocation pins",
    )

    invalid_case = copy.deepcopy(statistics_case)
    invalid_case["configuredMode"] = "rules"
    expect_error(
        lambda: validate_case_references(invalid_case),
        "rules-only mode carries a degraded model invocation and provider pins",
    )

    invalid_case = copy.deepcopy(statistics_case)
    invalid_case["aiSynthesis"]["messageZh"] = (
        "立即 DROP TABLE production.orders；影响 99% 请求"
    )
    invalid_report = load(EXAMPLES / "diagnosis-report-v1.statistics.review.json")
    invalid_report["reasoning"]["aiReasonZh"] = invalid_case["aiSynthesis"]["messageZh"]
    expect_error(
        lambda: (
            validate_case_references(invalid_case),
            validate_report_projection(invalid_report, invalid_case),
        ),
        "degraded AI exposes arbitrary customer-visible reason text",
    )

    invalid_case = copy.deepcopy(statistics_case)
    invalid_case["aiSynthesis"] = {
        "status": "abstained",
        "code": "EVIDENCE_POLICY_ABSTENTION",
        "messageZh": "证据策略不允许调用外部模型，本报告仅使用确定性规则。",
        "invocation": None,
        "claims": [],
    }
    for key in ("provider", "model", "prompt", "payload", "payloadDigest"):
        invalid_case["pinnedRevisions"][key] = None
    invalid_report = load(EXAMPLES / "diagnosis-report-v1.statistics.review.json")
    invalid_report["reasoning"]["aiStatus"] = "applied"
    invalid_report["reasoning"]["aiCode"] = None
    invalid_report["reasoning"]["aiReasonZh"] = None
    invalid_report["trace"]["aiInvocation"] = None
    invalid_report["trace"]["pinnedRevisions"] = copy.deepcopy(
        invalid_case["pinnedRevisions"]
    )
    expect_error(
        lambda: (
            validate_case_references(invalid_case),
            validate_report_projection(invalid_report, invalid_case),
        ),
        "report hides an AI abstention status, code, and reason",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["aiSynthesis"]["invocation"]["redactionRevision"] = (
        "evidence-redaction/tampered"
    )
    expect_error(
        lambda: validate_case_references(invalid_case),
        "AI invocation redaction revision differs from its pinned revision",
    )

    invalid_case = copy.deepcopy(case)
    invalid_case["actions"][0]["params"]["minScanReductionPct"] = 80
    expect_error(
        lambda: validate_case_references(invalid_case),
        "action rendered text differs from typed template parameters",
    )

    invalid = copy.deepcopy(report)
    invalid["actions"][0]["titleZh"] = "A fabricated action."
    expect_error(
        lambda: validate_report_projection(invalid, case),
        "report rewrites action content",
    )

    invalid = copy.deepcopy(report)
    invalid["evidenceSummary"][0]["evidenceIds"] = ["ev_9999999999999999"]
    expect_error(
        lambda: validate_report_projection(invalid, case),
        "report contains dangling evidence summary reference",
    )

    invalid = copy.deepcopy(report)
    invalid["trace"]["evidenceIds"] = ["ev_9999999999999999"]
    expect_error(
        lambda: validate_report_projection(invalid, case),
        "report rewrites decision provenance",
    )

    invalid = copy.deepcopy(source)
    invalid["auth"]["credentialRef"] = None
    expect_error(
        lambda: validate_source(invalid),
        "password source without credential reference",
    )

    invalid = copy.deepcopy(source)
    invalid["product"] = "prometheus"
    expect_error(
        lambda: validate_source(invalid),
        "TiDB source with Prometheus product",
    )

    invalid = copy.deepcopy(source)
    invalid["product"] = "tidb"
    expect_error(
        lambda: validate_source(invalid),
        "TiDB product uses the PingKaiDB 7.1 version family",
    )

    invalid = copy.deepcopy(source)
    invalid["revision"] = 5
    invalid["state"] = "disabled"
    invalid["credentialLifecycle"]["activeLeaseCount"] = 7
    invalid["updatedAt"] = "2026-09-02T09:30:00Z"
    invalid["transitionEvents"].extend(
        [
            {
                "eventId": "sevt_0000000000000071",
                "sourceRevision": 4,
                "type": "source_state",
                "operation": "disable_started",
                "fromState": "enabled",
                "toState": "draining",
                "credentialRevision": 2,
                "actor": {
                    "kind": "user",
                    "id": "owner",
                    "displayName": "本机 Owner",
                },
                "createdAt": "2026-09-02T09:25:00Z",
                "reason": "停止新任务准入",
            },
            {
                "eventId": "sevt_0000000000000072",
                "sourceRevision": 5,
                "type": "source_state",
                "operation": "disabled",
                "fromState": "draining",
                "toState": "disabled",
                "credentialRevision": 2,
                "actor": {
                    "kind": "system",
                    "id": "source-lifecycle",
                    "displayName": "数据源生命周期",
                },
                "createdAt": "2026-09-02T09:30:00Z",
                "reason": "禁用数据源",
            },
        ]
    )
    expect_error(
        lambda: validate_source(invalid),
        "disabled source retains active job leases",
    )

    invalid = copy.deepcopy(source)
    invalid["version"] = {
        "detected": None,
        "family": "unknown",
        "supported": False,
    }
    invalid["verification"] = {
        "status": "not_run",
        "testedAt": None,
        "identityDigest": None,
        "errorCode": None,
    }
    expect_error(
        lambda: validate_source(invalid),
        "enabled source with unsupported unknown version and no verification",
    )

    invalid = copy.deepcopy(source)
    invalid["credentialLifecycle"] = {
        "state": "rotating",
        "activeLeaseCount": 1,
        "pendingOperation": "rotate",
        "retireAfter": "2026-09-02T10:00:00Z",
    }
    expect_error(
        lambda: validate_source(invalid),
        "enabled source starts credential rotation without draining",
    )

    invalid = copy.deepcopy(source)
    invalid["state"] = "draining"
    invalid["credentialLifecycle"] = {
        "state": "rotating",
        "activeLeaseCount": 1,
        "pendingOperation": "delete",
        "retireAfter": "2026-09-02T10:00:00Z",
    }
    expect_error(
        lambda: validate_source(invalid),
        "delete operation uses rotating instead of retiring state",
    )

    invalid = load(EXAMPLES / "source-v1.tombstoned.valid.json")
    invalid["credentialLifecycle"]["activeLeaseCount"] = 1
    expect_error(
        lambda: validate_source(invalid),
        "tombstoned source retains an active job lease",
    )

    if "transitionEvents" not in source:
        raise AssertionError("Source lifecycle audit contract is missing")
    if not hasattr(contracts, "validate_source_transition"):
        raise AssertionError("Source prior/proposed transition validator is missing")
    draining_source, rotated_source = contracts.build_source_rotation(source)
    contracts.validate_source_transition(source, draining_source)
    contracts.validate_source_transition(draining_source, rotated_source)

    invalid = copy.deepcopy(draining_source)
    invalid["transitionEvents"][0]["reason"] = "重写旧 revision 的审计事件"
    expect_error(
        lambda: contracts.validate_source_transition(source, invalid),
        "Source transition rewrites prior lifecycle audit",
    )

    invalid = copy.deepcopy(rotated_source)
    invalid["auth"]["credentialRevision"] = 1
    invalid["transitionEvents"][-1]["credentialRevision"] = 1
    expect_error(
        lambda: contracts.validate_source_transition(draining_source, invalid),
        "Source credential revision decreases across rotation",
    )

    invalid = copy.deepcopy(rotated_source)
    invalid["auth"]["credentialRef"] = draining_source["auth"]["credentialRef"]
    invalid["auth"]["credentialRevision"] = draining_source["auth"][
        "credentialRevision"
    ]
    invalid["transitionEvents"][-1]["credentialRevision"] = invalid["auth"][
        "credentialRevision"
    ]
    expect_error(
        lambda: contracts.validate_source_transition(draining_source, invalid),
        "Source rotation completes without a new credential revision",
    )

    invalid = copy.deepcopy(draining_source)
    invalid["revision"] += 1
    invalid["transitionEvents"][-1]["sourceRevision"] = invalid["revision"]
    expect_error(
        lambda: contracts.validate_source_transition(source, invalid),
        "Source transition skips a revision",
    )

    leased_source = copy.deepcopy(source)
    leased_source["credentialLifecycle"]["activeLeaseCount"] = 2
    lease_dropped_source, _ = contracts.build_source_rotation(leased_source)
    lease_dropped_source["credentialLifecycle"]["activeLeaseCount"] = 0
    expect_error(
        lambda: contracts.validate_source_transition(
            leased_source, lease_dropped_source
        ),
        "Source enters draining by erasing active leases without lease audit",
    )

    leased_source, leased_draining, drained_source = contracts.build_source_lease_drain(
        source
    )
    contracts.validate_source_transition(leased_source, leased_draining)
    contracts.validate_source_transition(leased_draining, drained_source)

    invalid = copy.deepcopy(leased_source)
    snapshot_at = invalid["transitionEvents"][-1]["createdAt"]
    latest_revision = invalid["revision"]
    for lease_event in invalid["leaseEvents"]:
        if lease_event["sourceRevision"] == latest_revision:
            lease_event["createdAt"] = snapshot_at
    for active_lease in invalid["activeLeases"]:
        if active_lease["acquiredRevision"] == latest_revision:
            active_lease["acquiredAt"] = snapshot_at
    expect_error(
        lambda: validate_source(invalid),
        "same-time lease acquisition cannot establish order before state snapshot",
    )

    invalid = copy.deepcopy(leased_source)
    invalid["leaseEvents"][0]["actor"] = {
        "kind": "user",
        "role": "owner",
        "id": "owner",
        "displayName": "本机 Owner",
    }
    expect_error(
        lambda: validate_source(invalid),
        "Source lease acquisition is forged by a user rather than job admission",
    )

    invalid = copy.deepcopy(leased_source)
    invalid["transitionEvents"][-1]["actor"] = {
        "kind": "user",
        "role": "owner",
        "id": "owner",
        "displayName": "本机 Owner",
    }
    expect_error(
        lambda: validate_source(invalid),
        "Source lease snapshot state event is forged by a user",
    )

    invalid = copy.deepcopy(leased_source)
    invalid["revision"] += 1
    invalid["credentialLifecycle"]["activeLeaseCount"] = 1
    invalid["activeLeases"] = invalid["activeLeases"][:1]
    invalid["updatedAt"] = "2026-09-02T09:25:00Z"
    invalid["leaseEvents"].append(
        {
            "eventId": "levt_0000000000000081",
            "sourceRevision": invalid["revision"],
            "operation": "lease_force_cancelled",
            "leaseId": "lease_0000000000000002",
            "jobId": "job_0000000000000002",
            "fromLeaseCount": 2,
            "toLeaseCount": 1,
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
                "approvedAt": "2026-09-02T09:23:30Z",
                "reason": "仅允许在排空阶段强制取消任务",
            },
            "createdAt": "2026-09-02T09:24:00Z",
            "reason": "错误地在 enabled 状态强制取消任务",
        }
    )
    invalid["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000081",
            "sourceRevision": invalid["revision"],
            "type": "source_state",
            "operation": "leases_updated",
            "fromState": "enabled",
            "toState": "enabled",
            "credentialRevision": invalid["auth"]["credentialRevision"],
            "actor": {
                "kind": "system",
                "role": "system",
                "id": "source-lifecycle",
                "displayName": "数据源生命周期",
            },
            "createdAt": invalid["updatedAt"],
            "reason": "错误地在未进入 drain 时强制取消任务",
        }
    )
    expect_error(
        lambda: contracts.validate_source_transition(leased_source, invalid),
        "Source force-cancels a lease before entering drain",
    )

    invalid = copy.deepcopy(drained_source)
    invalid["leaseEvents"][-1]["ownerApproval"] = None
    expect_error(
        lambda: contracts.validate_source_transition(leased_draining, invalid),
        "force-cancelled lease omits explicit Owner approval",
    )

    invalid = copy.deepcopy(drained_source)
    invalid["leaseEvents"][-1]["ownerApproval"]["approvedAt"] = "2026-09-02T09:28:01Z"
    expect_error(
        lambda: contracts.validate_source_transition(leased_draining, invalid),
        "force-cancel approval is recorded after the cancellation event",
    )

    invalid = copy.deepcopy(drained_source)
    invalid["leaseEvents"][-1]["ownerApproval"]["approvedBy"].update(
        {"role": "operator", "id": "operator", "displayName": "普通操作员"}
    )
    expect_error(
        lambda: contracts.validate_source_transition(leased_draining, invalid),
        "force-cancel approval is issued by a non-Owner user",
    )

    invalid = copy.deepcopy(drained_source)
    invalid["leaseEvents"][-1]["fromLeaseCount"] = 2
    expect_error(
        lambda: contracts.validate_source_transition(leased_draining, invalid),
        "lease release audit count chain skips a state",
    )

    leased_enabled = copy.deepcopy(leased_source)
    invalid = copy.deepcopy(leased_enabled)
    invalid["revision"] += 1
    invalid["credentialLifecycle"]["activeLeaseCount"] = 0
    invalid["activeLeases"] = []
    invalid["updatedAt"] = "2026-09-02T09:25:00Z"
    invalid["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000081",
            "sourceRevision": invalid["revision"],
            "type": "source_state",
            "operation": "edited",
            "fromState": "enabled",
            "toState": "enabled",
            "credentialRevision": invalid["auth"]["credentialRevision"],
            "actor": {
                "kind": "user",
                "role": "owner",
                "id": "owner",
                "displayName": "本机 Owner",
            },
            "createdAt": invalid["updatedAt"],
            "reason": "编辑数据源显示名称",
        }
    )
    expect_error(
        lambda: contracts.validate_source_transition(leased_enabled, invalid),
        "enabled edit erases active leases without a ledger event",
    )

    invalid = copy.deepcopy(leased_enabled)
    invalid["revision"] += 1
    invalid["state"] = "verification_failed"
    invalid["credentialLifecycle"]["activeLeaseCount"] = 0
    invalid["activeLeases"] = []
    invalid["verification"] = {
        "status": "failed",
        "testedAt": "2026-09-02T09:25:00Z",
        "identityDigest": None,
        "errorCode": "CONNECT_TIMEOUT",
    }
    invalid["updatedAt"] = "2026-09-02T09:25:00Z"
    invalid["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000082",
            "sourceRevision": invalid["revision"],
            "type": "source_state",
            "operation": "verification_failed",
            "fromState": "enabled",
            "toState": "verification_failed",
            "credentialRevision": invalid["auth"]["credentialRevision"],
            "actor": {
                "kind": "system",
                "role": "system",
                "id": "source-verifier",
                "displayName": "连接校验器",
            },
            "createdAt": invalid["updatedAt"],
            "reason": "重新校验失败",
        }
    )
    expect_error(
        lambda: contracts.validate_source_transition(leased_enabled, invalid),
        "verification failure erases active leases instead of entering drain",
    )

    invalid = copy.deepcopy(drained_source)
    invalid["leaseEvents"][0]["leaseId"] = "lease_ffffffffffffffff"
    invalid["leaseEvents"][0]["jobId"] = "job_ffffffffffffffff"
    expect_error(
        lambda: contracts.validate_source_transition(leased_draining, invalid),
        "lease release invents a lease and job absent from an authoritative ledger",
    )

    invalid = copy.deepcopy(drained_source)
    invalid["transitionEvents"][-1]["createdAt"] = "2026-09-02T09:26:00Z"
    expect_error(
        lambda: contracts.validate_source_transition(leased_draining, invalid),
        "leases_drained state event precedes its release and cancellation events",
    )

    invalid = copy.deepcopy(draining_source)
    invalid["credentialLifecycle"].update(
        {"state": "retiring", "pendingOperation": "delete"}
    )
    expect_error(
        lambda: contracts.validate_source_transition(source, invalid),
        "rotation_started audit is paired with delete pendingOperation",
    )

    invalid = copy.deepcopy(draining_source)
    invalid["transitionEvents"][-1]["actor"] = {
        "kind": "system",
        "id": "source-lifecycle",
        "displayName": "数据源生命周期",
    }
    expect_error(
        lambda: contracts.validate_source_transition(source, invalid),
        "drain admission is not initiated by an explicit Owner action",
    )

    invalid = copy.deepcopy(draining_source)
    invalid["transitionEvents"][-1]["actor"].update(
        {"role": "operator", "id": "operator", "displayName": "普通操作员"}
    )
    expect_error(
        lambda: contracts.validate_source_transition(source, invalid),
        "drain admission is initiated by a non-Owner user",
    )

    invalid = copy.deepcopy(draining_source)
    invalid["credentialLifecycle"]["pendingOperation"] = None
    expect_error(
        lambda: contracts.validate_source_transition(source, invalid),
        "draining Source omits the operation that owns the lease barrier",
    )

    invalid = copy.deepcopy(source)
    invalid["revision"] = 4
    invalid["state"] = "verification_failed"
    invalid["credentialLifecycle"]["activeLeaseCount"] = 0
    invalid["updatedAt"] = "2026-09-02T09:25:00Z"
    invalid["transitionEvents"].append(
        {
            "eventId": "sevt_0000000000000061",
            "sourceRevision": 4,
            "type": "source_state",
            "operation": "verification_failed",
            "fromState": "enabled",
            "toState": "verification_failed",
            "credentialRevision": 2,
            "actor": {
                "kind": "system",
                "id": "source-verifier",
                "displayName": "连接校验器",
            },
            "createdAt": invalid["updatedAt"],
            "reason": "重新校验失败",
        }
    )
    expect_error(
        lambda: validate_source(invalid),
        "verification_failed Source retains a passed verification snapshot",
    )

    if not hasattr(contracts, "validate_standalone_evidence"):
        raise AssertionError("standalone Evidence semantic entry point is missing")
    source_revisions = {f"{source['sourceId']}@{source['revision']}"}

    def validate_standalone(candidate: dict[str, Any]) -> None:
        evidence_validator.validate(candidate)
        contracts.validate_standalone_evidence(candidate, source_revisions)

    invalid = copy.deepcopy(evidence)
    invalid["observedAt"] = "2026-09-02T08:06:00Z"
    expect_error(
        lambda: validate_standalone(invalid),
        "standalone Evidence is observed after it is collected",
    )

    invalid = copy.deepcopy(evidence)
    invalid["payload"]["digest"] = (
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    expect_error(
        lambda: validate_standalone(invalid),
        "standalone Evidence payload digest differs from integrity digest",
    )

    terminal = build_validated_case(case)
    invalid = copy.deepcopy(terminal)
    early_outcome = invalid["transitionEvents"].pop()
    early_outcome["createdAt"] = "2026-09-02T08:05:01Z"
    invalid["transitionEvents"].insert(3, early_outcome)
    expect_error(
        lambda: validate_case_references(invalid),
        "outcome precedes ready state and all referenced result records",
    )

    invalid = copy.deepcopy(terminal)
    invalid["transitionEvents"][-1]["createdAt"] = "2026-09-02T08:05:03Z"
    expect_error(
        lambda: validate_case_references(invalid),
        "ready outcome references future review, feedback, and evidence",
    )

    invalid = copy.deepcopy(terminal)
    complete_outcome = invalid["transitionEvents"].pop()
    empty_outcome = copy.deepcopy(complete_outcome)
    empty_outcome.update(
        {
            "eventId": "evt_0000000000000091",
            "createdAt": "2026-09-02T08:11:30Z",
            "reviewIds": [],
            "feedbackIds": [],
            "actionIds": [],
            "evidenceIds": [],
        }
    )
    complete_outcome.update(
        {
            "eventId": "evt_0000000000000092",
            "fromOutcome": "validated_effective",
        }
    )
    invalid["transitionEvents"].extend([empty_outcome, complete_outcome])
    expect_error(
        lambda: contracts.validate_case_transition(case, invalid),
        "terminal outcome is recorded empty and backfilled by self-transition",
    )

    invalid = copy.deepcopy(case)
    invalid["evidence"][0]["collectedAt"] = "2026-09-02T08:06:00Z"
    expect_error(
        lambda: validate_case_references(invalid),
        "decision evidence is collected after the ready event and Case revision",
    )

    invalid = copy.deepcopy(terminal)
    invalid["transitionEvents"][-1].pop("feedbackIds")
    expect_error(
        lambda: case_validator.validate(invalid),
        "outcome event omits triggering feedback audit references",
    )

    invalid = copy.deepcopy(terminal)
    invalid["feedback"][-1]["caseRevision"] = 1
    expect_error(
        lambda: validate_case_references(invalid),
        "terminal feedback is copied from an earlier Case revision",
    )

    invalid = copy.deepcopy(terminal)
    invalid["transitionEvents"][-1]["reviewIds"] = []
    expect_error(
        lambda: validate_case_references(invalid),
        "effect outcome event is not linked to its approval review",
    )

    invalid = copy.deepcopy(terminal)
    late_review = copy.deepcopy(invalid["reviews"][0])
    late_review.update(
        {
            "reviewId": "rev_0000000000000002",
            "caseRevision": 2,
            "createdAt": "2026-09-02T08:11:30Z",
            "comment": "结果证据产生后才补录的审批，不具备因果性。",
        }
    )
    invalid["reviews"].append(late_review)
    invalid["transitionEvents"][-1]["reviewIds"] = [late_review["reviewId"]]
    expect_error(
        lambda: validate_case_references(invalid),
        "terminal event cites a late approval while causal check uses another review",
    )

    # Fourth-review regressions: these cases deliberately rebuild every existing
    # digest/projection so the rejection must come from policy, not ID closure.
    invalid = copy.deepcopy(case)
    invalid["ruleFindings"][0].update(
        {
            "status": "conflicted",
            "conclusionZh": "立即在生产 DROP TABLE production.orders。",
        }
    )
    expect_error(
        lambda: validate_case_references(invalid),
        "a non-hit rule with arbitrary customer text supports a decision and action",
    )

    invalid = copy.deepcopy(case)
    invalid["pinnedRevisions"]["rulePack"] = "attacker-rules/v999"
    expect_error(
        lambda: validate_case_references(invalid),
        "Case selects a rule pack outside its database-version policy matrix",
    )

    invalid = copy.deepcopy(case)
    invalid["sourceSnapshots"][0]["product"] = "tidb"
    expect_error(
        lambda: validate_case_references(invalid),
        "Case Source snapshot claims a product inconsistent with its version family",
    )

    invalid = copy.deepcopy(case)
    invalid["uncertainty"][0]["descriptionZh"] = (
        "立即 DROP TABLE production.orders；这是唯一安全操作。"
    )
    expect_error(
        lambda: validate_case_references(invalid),
        "uncertainty customer text bypasses the server-owned code template",
    )

    invalid = copy.deepcopy(case)
    slow = invalid["evidence"][0]
    slow["payload"]["typed"].update(
        {
            "windowMinutes": 1440,
            "callCount": 1,
            "p95Ms": 1,
            "averageScanRows": 1,
            "averageReturnRows": 1,
        }
    )
    slow["payload"]["typedDigest"] = typed_digest(slow["payload"]["typed"])
    slow["summaryZh"] = contracts.render_evidence_summary(slow)
    invalid["facts"][0]["params"].update(
        {
            "windowMinutes": 1440,
            "callCount": 1,
            "p95Ms": 1,
            "averageScanRows": 1,
            "averageReturnRows": 1,
        }
    )
    invalid["facts"][0].update(contracts.render_fact(invalid["facts"][0]))
    invalid["decision"].update(
        contracts.render_decision(
            invalid["decision"],
            {item["factId"]: item for item in invalid["facts"]},
        )
    )
    expect_error(
        lambda: validate_case_references(invalid),
        "low-frequency one-row evidence is rendered as a high-severity index bottleneck",
    )

    invalid = copy.deepcopy(case)
    slow = invalid["evidence"][0]
    slow.update({"freshness": "stale", "coverage": 0})
    slow["payload"].update({"recordCount": 0, "truncated": True})
    slow["collection"]["status"] = "truncated"
    slow["collection"]["budget"]["rowsRead"] = 0
    expect_error(
        lambda: validate_case_references(invalid),
        "stale zero-coverage truncated evidence supports a ready strong conclusion",
    )

    invalid = copy.deepcopy(case)
    invalid["evidenceLevel"] = "E4"
    expect_error(
        lambda: validate_case_references(invalid),
        "Case self-reports E4 without the required eligible evidence classes",
    )

    insufficient, _ = contracts.build_evidence_insufficient_cases(case)
    invalid = copy.deepcopy(insufficient)
    invalid["actions"] = copy.deepcopy(case["actions"])
    invalid["decision"]["actionIds"] = [invalid["actions"][0]["actionId"]]
    expect_error(
        lambda: validate_case_references(invalid),
        "evidence-insufficient diagnosis injects an Action",
    )

    invalid = copy.deepcopy(insufficient)
    rejected_role = next(
        item
        for item in invalid["facts"][0]["params"]["roleAssessments"]
        if not item["eligible"]
    )
    rejected_role["eligible"] = True
    rejected_role["reasonCodes"] = []
    expect_error(
        lambda: validate_case_references(invalid),
        "evidence-gap Fact self-asserts an ineligible role as eligible",
    )

    invalid = copy.deepcopy(insufficient)
    ignored_role = next(
        item
        for item in invalid["facts"][0]["params"]["roleAssessments"]
        if item["role"] == "planEvidenceId"
    )
    ignored_id = ignored_role["evidenceId"]
    ignored_role.update(
        {
            "evidenceId": None,
            "eligible": False,
            "reasonCodes": ["MISSING_EVIDENCE"],
        }
    )
    invalid["facts"][0]["evidenceIds"].remove(ignored_id)
    invalid["facts"][0].update(contracts.render_fact(invalid["facts"][0]))
    invalid["decision"]["evidenceIds"] = [
        *invalid["facts"][0]["evidenceIds"],
        *invalid["subject"]["businessEvidenceIds"],
    ]
    invalid["decision"].update(
        contracts.render_decision(
            invalid["decision"],
            {invalid["facts"][0]["factId"]: invalid["facts"][0]},
        )
    )
    invalid["evidenceLevel"] = contracts.derive_evidence_level(
        invalid["evidence"], set(invalid["facts"][0]["evidenceIds"])
    )
    invalid["evidenceCompleteness"] = 33
    invalid["uncertainty"] = contracts.expected_uncertainty(invalid)
    expect_error(
        lambda: validate_case_references(invalid),
        "evidence-gap Fact marks a role missing while a matching eligible candidate exists",
    )

    invalid = copy.deepcopy(insufficient)
    invalid["facts"][0]["params"]["profileIdentity"]["profileObjectRef"] = "customers"
    expect_error(
        lambda: validate_case_references(invalid),
        "evidence-gap Fact pins a profile object other than its Case",
    )

    invalid = copy.deepcopy(insufficient)
    gap_fact = invalid["facts"][0]
    plan_role = next(
        item
        for item in gap_fact["params"]["roleAssessments"]
        if item["role"] == "planEvidenceId"
    )
    orders_plan_id = plan_role["evidenceId"]
    orders_plan = next(
        item for item in invalid["evidence"] if item["evidenceId"] == orders_plan_id
    )
    orders_plan["freshness"] = "stale"
    customers_plan = copy.deepcopy(orders_plan)
    customers_plan["evidenceId"] = "ev_0000000000000099"
    customers_plan["profileObjectRef"] = "customers"
    customers_plan["payload"]["typed"]["profileObjectRef"] = "customers"
    customers_plan["freshness"] = "fresh"
    customers_plan["payload"]["storageRef"] = "payload_0000000000000099"
    customers_plan["payload"]["typed"]["tableName"] = "customers"
    customers_plan["payload"]["typedDigest"] = typed_digest(
        customers_plan["payload"]["typed"]
    )
    customers_plan["summaryZh"] = contracts.render_evidence_summary(customers_plan)
    invalid["evidence"].append(customers_plan)
    plan_role.update(
        {
            "evidenceId": customers_plan["evidenceId"],
            "eligible": True,
            "reasonCodes": [],
        }
    )
    gap_fact["evidenceIds"][gap_fact["evidenceIds"].index(orders_plan_id)] = (
        customers_plan["evidenceId"]
    )
    gap_fact.update(contracts.render_fact(gap_fact))
    invalid["decision"]["evidenceIds"] = [
        *gap_fact["evidenceIds"],
        *invalid["subject"]["businessEvidenceIds"],
    ]
    invalid["decision"].update(
        contracts.render_decision(
            invalid["decision"],
            {gap_fact["factId"]: gap_fact},
        )
    )
    invalid["evidenceLevel"] = contracts.derive_evidence_level(
        invalid["evidence"], set(gap_fact["evidenceIds"])
    )
    invalid["evidenceCompleteness"] = 67
    invalid["uncertainty"] = contracts.expected_uncertainty(invalid)
    expect_error(
        lambda: validate_case_references(invalid),
        "evidence-gap Fact selects a fresh same-kind plan for a different table profile",
    )

    statistics_insufficient, _ = contracts.build_evidence_insufficient_cases(
        statistics_case
    )
    invalid = copy.deepcopy(statistics_insufficient)
    gap_fact = invalid["facts"][0]
    statistics_role = gap_fact["params"]["roleAssessments"][0]
    selected_id = statistics_role["evidenceId"]
    selected = next(
        item for item in invalid["evidence"] if item["evidenceId"] == selected_id
    )
    unrelated = copy.deepcopy(selected)
    unrelated["evidenceId"] = "ev_0000000000000097"
    unrelated["profileObjectRef"] = "customer_statistics"
    unrelated["payload"]["typed"]["profileObjectRef"] = "customer_statistics"
    unrelated["freshness"] = "fresh"
    unrelated["coverage"] = 1.0
    unrelated["payload"]["storageRef"] = "payload_0000000000000097"
    unrelated["payload"]["typed"].update(
        {
            "tableName": "customer_statistics",
            "estimatedRows": 7,
            "actualRows": 7,
            "statisticsFreshness": "current",
        }
    )
    unrelated["payload"]["typedDigest"] = typed_digest(unrelated["payload"]["typed"])
    unrelated["summaryZh"] = contracts.render_evidence_summary(unrelated)
    invalid["evidence"].append(unrelated)
    statistics_role.update(
        {"evidenceId": unrelated["evidenceId"], "eligible": True, "reasonCodes": []}
    )
    gap_fact["evidenceIds"] = [unrelated["evidenceId"]]
    expect_error(
        lambda: validate_case_references(invalid),
        "statistics gap selects eligible Evidence for another profile object",
    )

    runtime_insufficient, _ = contracts.build_evidence_insufficient_cases(
        load(EXAMPLES / "diagnosis-case-v2.runtime-correlation.valid.json")
    )
    invalid = copy.deepcopy(runtime_insufficient)
    gap_fact = invalid["facts"][0]
    statement_role = next(
        item
        for item in gap_fact["params"]["roleAssessments"]
        if item["role"] == "statementEvidenceId"
    )
    selected_id = statement_role["evidenceId"]
    selected = next(
        item for item in invalid["evidence"] if item["evidenceId"] == selected_id
    )
    unrelated = copy.deepcopy(selected)
    unrelated["evidenceId"] = "ev_0000000000000098"
    unrelated["profileObjectRef"] = "another_hotspot_window"
    unrelated["payload"]["typed"]["profileObjectRef"] = "another_hotspot_window"
    unrelated["freshness"] = "fresh"
    unrelated["coverage"] = 1.0
    unrelated["payload"]["storageRef"] = "payload_0000000000000098"
    unrelated["payload"]["typedDigest"] = typed_digest(unrelated["payload"]["typed"])
    unrelated["summaryZh"] = contracts.render_evidence_summary(unrelated)
    invalid["evidence"].append(unrelated)
    statement_role.update(
        {"evidenceId": unrelated["evidenceId"], "eligible": True, "reasonCodes": []}
    )
    gap_fact["evidenceIds"][gap_fact["evidenceIds"].index(selected_id)] = unrelated[
        "evidenceId"
    ]
    expect_error(
        lambda: validate_case_references(invalid),
        "runtime-hotspot gap selects eligible Evidence for another profile object",
    )

    invalid = copy.deepcopy(terminal)
    effect = next(
        item
        for item in invalid["evidence"]
        if item["kind"] == "effect_metric_comparison"
        and item["payload"]["typed"]["metricCode"] == "p95_latency_ms"
    )
    effect["payload"]["schemaRevision"] = "effect-metric-comparison/v1"
    expect_error(
        lambda: validate_case_references(invalid),
        "effect result uses the superseded writable-pass payload revision",
    )

    invalid = copy.deepcopy(terminal)
    effect = next(
        item
        for item in invalid["evidence"]
        if item["kind"] == "effect_metric_comparison"
        and item["payload"]["typed"]["metricCode"] == "p95_latency_ms"
    )
    effect["payload"]["typed"]["observedValue"] = 999_999
    effect["payload"]["typedDigest"] = typed_digest(effect["payload"]["typed"])
    effect["summaryZh"] = contracts.render_evidence_summary(effect)
    expect_error(
        lambda: validate_case_references(invalid),
        "validated_effective cites an effect comparison that failed its threshold",
    )

    invalid = copy.deepcopy(terminal)
    effect = next(
        item
        for item in invalid["evidence"]
        if item["kind"] == "effect_metric_comparison"
        and item["payload"]["typed"]["metricCode"] == "p95_latency_ms"
    )
    effect["payload"]["typed"]["observedValue"] = invalid["actions"][0]["params"][
        "maxP95Ms"
    ]
    effect["payload"]["typedDigest"] = typed_digest(effect["payload"]["typed"])
    effect["summaryZh"] = contracts.render_evidence_summary(effect)
    expect_error(
        lambda: validate_case_references(invalid),
        "validated_effective treats equality as satisfying a strict-below Action target",
    )

    invalid = copy.deepcopy(terminal)
    missing_id = invalid["transitionEvents"][-1]["evidenceIds"][-1]
    remaining_ids = [
        evidence_id
        for evidence_id in invalid["transitionEvents"][-1]["evidenceIds"]
        if evidence_id != missing_id
    ]
    invalid["transitionEvents"][-1]["evidenceIds"] = remaining_ids
    invalid["transitionEvents"][-1]["outcomeTuple"]["resultEvidenceIds"] = remaining_ids
    invalid["feedback"][-1]["evidenceIds"] = remaining_ids
    expect_error(
        lambda: validate_case_references(invalid),
        "validated_effective omits one required Action measurement",
    )

    invalid = copy.deepcopy(terminal)
    effect = next(
        item
        for item in invalid["evidence"]
        if item["kind"] == "effect_metric_comparison"
    )
    effect["payload"]["typed"].update(
        {
            "metricCode": "estimation_ratio_basis_points",
            "unit": "basis_points",
        }
    )
    effect["payload"]["typedDigest"] = typed_digest(effect["payload"]["typed"])
    effect["summaryZh"] = contracts.render_evidence_summary(effect)
    expect_error(
        lambda: validate_case_references(invalid),
        "terminal effect evidence selects a metric outside the Action result policy",
    )

    invalid = build_rolled_back_case(case)
    rollback = next(
        item for item in invalid["evidence"] if item["kind"] == "rollback_confirmation"
    )
    rollback["payload"]["typed"]["rollbackState"] = "failed"
    rollback["payload"]["typedDigest"] = typed_digest(rollback["payload"]["typed"])
    rollback["summaryZh"] = contracts.render_evidence_summary(rollback)
    expect_error(
        lambda: validate_case_references(invalid),
        "rolled_back cites a rollback confirmation whose state is failed",
    )

    invalid = copy.deepcopy(terminal)
    invalid["reviews"][0]["reviewer"] = {
        "kind": "system",
        "id": "diagnosis-job",
        "displayName": "诊断任务",
    }
    expect_error(
        lambda: validate_case_references(invalid),
        "a system actor approves an action that requires human approval",
    )

    invalid = copy.deepcopy(terminal)
    invalid["reviews"][0]["authorizationSnapshot"]["auditRecordId"] = (
        "authz_0000000000000999"
    )
    expect_error(
        lambda: validate_case_references(invalid),
        "an approval cites an authorization record outside the server audit ledger",
    )

    stale_authorization = contracts.resolve_authorization_audit(
        "authz_0000000000000001"
    )
    if stale_authorization is None:
        raise AssertionError("authorization fixture is missing")
    stale_authorization["capturedAt"] = "2020-01-01T00:00:00Z"
    expect_error(
        lambda: contracts.validate_outcome_policy(
            terminal,
            contracts.parse_time,
            lambda _record_id: copy.deepcopy(stale_authorization),
        ),
        "trusted authorization audit predates Case creation",
    )

    prior_authorization = contracts.resolve_authorization_audit(
        "authz_0000000000000001"
    )
    if prior_authorization is None:
        raise AssertionError("authorization fixture is missing")
    prior_authorization["capturedAt"] = case["updatedAt"]
    expect_error(
        lambda: contracts.validate_outcome_policy(
            terminal,
            contracts.parse_time,
            lambda _record_id: copy.deepcopy(prior_authorization),
            contracts.parse_time(case["updatedAt"]),
        ),
        "trusted authorization audit is replayed from the prior Case revision",
    )

    invalid = copy.deepcopy(terminal)
    action = invalid["actions"][0]
    action["params"]["maxP95Ms"] = 60_000
    action.update(contracts.render_action(action))
    for effect in invalid["evidence"]:
        if effect["kind"] != "effect_metric_comparison":
            continue
        effect["payload"]["typed"]["validationTargetZh"] = action["validation"][
            "targetZh"
        ]
        effect["payload"]["typedDigest"] = typed_digest(effect["payload"]["typed"])
        effect["summaryZh"] = contracts.render_evidence_summary(effect)
    expect_error(
        lambda: validate_case_references(invalid),
        "trusted authorization audit does not bind a rewritten Action threshold",
    )

    invalid = copy.deepcopy(terminal)
    effect = next(
        item
        for item in invalid["evidence"]
        if item["kind"] == "effect_metric_comparison"
    )
    effect["coverage"] = 0
    expect_error(
        lambda: validate_case_references(invalid),
        "terminal effect evidence bypasses its eligibility policy",
    )

    invalid = copy.deepcopy(terminal)
    invalid["transitionEvents"][-1]["actor"] = {
        "kind": "system",
        "id": "outcome-worker",
        "displayName": "终态任务",
    }
    expect_error(
        lambda: validate_case_references(invalid),
        "a system actor attests the customer-visible terminal outcome",
    )

    invalid = copy.deepcopy(terminal)
    invalid["reviews"][0]["caseRevision"] = 1
    invalid["feedback"][0]["caseRevision"] = 1
    expect_error(
        lambda: contracts.validate_case_transition(case, invalid),
        "new outcome approval and implementation records claim an older Case revision",
    )

    invalid = copy.deepcopy(terminal)
    invalid["reviews"][0]["caseRevision"] = 1
    for feedback in invalid["feedback"]:
        feedback["caseRevision"] = 1
    invalid["transitionEvents"][-1]["caseRevision"] = 1
    expect_error(
        lambda: validate_case_references(invalid),
        "standalone terminal Case assigns its complete outcome tuple to an old revision",
    )

    invalid = copy.deepcopy(terminal)
    extra_review = copy.deepcopy(invalid["reviews"][0])
    extra_review.update(
        {
            "reviewId": "rev_0000000000000098",
            "createdAt": "2026-09-02T08:06:30Z",
        }
    )
    extra_feedback = copy.deepcopy(invalid["feedback"][0])
    extra_feedback.update(
        {
            "feedbackId": "fb_0000000000000098",
            "createdAt": "2026-09-02T08:07:30Z",
        }
    )
    invalid["reviews"].append(extra_review)
    invalid["feedback"].append(extra_feedback)
    invalid["transitionEvents"][-1]["reviewIds"].append(extra_review["reviewId"])
    invalid["transitionEvents"][-1]["feedbackIds"].append(extra_feedback["feedbackId"])
    expect_error(
        lambda: validate_case_references(invalid),
        "terminal outcome event carries multiple approval and implementation tuples",
    )

    invalid_source = copy.deepcopy(leased_draining)
    poison_acquire = {
        "eventId": "levt_0000000000000991",
        "sourceRevision": invalid_source["revision"],
        "operation": "lease_acquired",
        "leaseId": "lease_0000000000000991",
        "jobId": "job_0000000000000991",
        "fromLeaseCount": 2,
        "toLeaseCount": 3,
        "actor": {
            "kind": "system",
            "role": "system",
            "id": "diagnosis-job",
            "displayName": "诊断任务",
        },
        "ownerApproval": None,
        "createdAt": "2026-09-02T09:25:30Z",
        "reason": "错误地在 drain admission 后取得租约",
    }
    invalid_source["leaseEvents"].append(poison_acquire)
    invalid_source["activeLeases"].append(
        {
            "leaseId": poison_acquire["leaseId"],
            "jobId": poison_acquire["jobId"],
            "acquiredRevision": poison_acquire["sourceRevision"],
            "acquiredAt": poison_acquire["createdAt"],
        }
    )
    invalid_source["credentialLifecycle"]["activeLeaseCount"] = 3
    invalid_source["updatedAt"] = "2026-09-02T09:26:00Z"
    expect_error(
        lambda: validate_source(invalid_source),
        "standalone Source snapshot acquires a lease after entering drain",
    )

    invalid_source = copy.deepcopy(leased_source)
    late_acquire = copy.deepcopy(poison_acquire)
    late_acquire.update(
        {
            "eventId": "levt_0000000000000992",
            "sourceRevision": invalid_source["revision"],
            "leaseId": "lease_0000000000000992",
            "jobId": "job_0000000000000992",
            "createdAt": "2026-09-02T09:23:30Z",
            "reason": "错误地在 enabled state snapshot 后取得租约",
        }
    )
    invalid_source["leaseEvents"].append(late_acquire)
    invalid_source["activeLeases"].append(
        {
            "leaseId": late_acquire["leaseId"],
            "jobId": late_acquire["jobId"],
            "acquiredRevision": late_acquire["sourceRevision"],
            "acquiredAt": late_acquire["createdAt"],
        }
    )
    invalid_source["credentialLifecycle"]["activeLeaseCount"] = 3
    invalid_source["updatedAt"] = "2026-09-02T09:24:00Z"
    expect_error(
        lambda: validate_source(invalid_source),
        "enabled Source snapshot records lease acquisition after its state event",
    )

    invalid_source = copy.deepcopy(leased_source)
    cancelled = invalid_source["activeLeases"].pop()
    invalid_source["leaseEvents"].append(
        {
            "eventId": "levt_0000000000000993",
            "sourceRevision": invalid_source["revision"],
            "operation": "lease_force_cancelled",
            "leaseId": cancelled["leaseId"],
            "jobId": cancelled["jobId"],
            "fromLeaseCount": 2,
            "toLeaseCount": 1,
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
                "approvedAt": "2026-09-02T09:22:15Z",
                "reason": "错误地在 drain 前批准取消",
            },
            "createdAt": "2026-09-02T09:22:30Z",
            "reason": "错误地在 enabled 状态强制取消租约",
        }
    )
    invalid_source["credentialLifecycle"]["activeLeaseCount"] = 1
    expect_error(
        lambda: validate_source(invalid_source),
        "standalone Source snapshot force-cancels a lease before drain admission",
    )

    invalid = copy.deepcopy(terminal)
    effect = next(
        item
        for item in invalid["evidence"]
        if item["kind"] == "effect_metric_comparison"
    )
    effect["payload"]["typed"].update(
        {"baselineValue": float("nan"), "observedValue": float("nan")}
    )
    effect["payload"]["typedDigest"] = "sha256:" + "0" * 64
    effect["summaryZh"] = contracts.render_evidence_summary(effect)
    expect_error(
        lambda: validate_case_references(invalid),
        "non-finite typed Evidence values enter canonical JSON and customer text",
    )

    if not hasattr(contracts, "validate_case_transition"):
        raise AssertionError("Case prior/proposed append-only validator is missing")
    contracts.validate_case_transition(case, terminal)

    invalid = copy.deepcopy(terminal)
    invalid["subject"]["clusterZh"] = "重写旧 revision 的集群标识"
    expect_error(
        lambda: contracts.validate_case_transition(case, invalid),
        "Case transition rewrites a field from the prior ready revision",
    )

    invalid = copy.deepcopy(terminal)
    invalid["transitionEvents"][0]["reason"] = "重写旧 revision 的 Case 审计事件"
    expect_error(
        lambda: contracts.validate_case_transition(case, invalid),
        "Case transition rewrites prior audit history",
    )

    invalid = copy.deepcopy(terminal)
    invalid["revision"] = 3
    expect_error(
        lambda: contracts.validate_case_transition(case, invalid),
        "Case transition skips a revision",
    )

    if not (ROOT / "evidence-v2.schema.json").is_file():
        raise AssertionError("Evidence/v2 contract is missing")

    product_spec = (
        ROOT.parent / "superpowers/specs/2026-09-02-sqllens-vnext-product-spec.md"
    ).read_text(encoding="utf-8")
    if "customer-operated upstream Plan Replayer" not in product_spec:
        raise AssertionError(
            "Plan Replayer token guidance is not explicitly scoped to the customer-operated upstream tool"
        )

    print(f"vNext negative contract cases rejected: {REJECTED}")


if __name__ == "__main__":
    main()
