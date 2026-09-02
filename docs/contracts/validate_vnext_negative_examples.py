from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import validate_vnext_examples as contracts
from jsonschema import ValidationError
from validate_vnext_examples import (
    EXAMPLES,
    ROOT,
    build_validated_case,
    load,
    schema_validator,
    validate_case_references,
    validate_report_projection,
    validate_source_semantics,
)

REJECTED = 0


def expect_error(action: Callable[[], None], label: str) -> None:
    global REJECTED
    try:
        action()
    except (ValidationError, ValueError):
        REJECTED += 1
        return
    raise AssertionError(f"negative contract case was accepted: {label}")


def main() -> None:
    case_validator = schema_validator("diagnosis-case-v2.schema.json")
    source_validator = schema_validator("source-v1.schema.json")
    evidence_validator = schema_validator("evidence-v2.schema.json")
    case = load(EXAMPLES / "diagnosis-case-v2.valid.json")
    statistics_case = load(EXAMPLES / "diagnosis-case-v2.statistics.valid.json")
    report = load(EXAMPLES / "diagnosis-report-v1.index-access.review.json")
    source = load(EXAMPLES / "source-v1.valid.json")
    evidence = load(EXAMPLES / "evidence-v2.valid.json")

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

    print(f"vNext negative contract cases rejected: {REJECTED}")


if __name__ == "__main__":
    main()
