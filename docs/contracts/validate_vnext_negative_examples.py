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
    report = load(EXAMPLES / "diagnosis-report-v1.index-access.review.json")
    source = load(EXAMPLES / "source-v1.valid.json")
    evidence = load(EXAMPLES / "evidence-v2.valid.json")

    def validate_source(candidate: dict[str, Any]) -> None:
        source_validator.validate(candidate)
        validate_source_semantics(candidate)

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
