from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

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


def expect_error(action: Callable[[], None], label: str) -> None:
    try:
        action()
    except (ValidationError, ValueError):
        return
    raise AssertionError(f"negative contract case was accepted: {label}")


def main() -> None:
    case_validator = schema_validator("diagnosis-case-v2.schema.json")
    source_validator = schema_validator("source-v1.schema.json")
    case = load(EXAMPLES / "diagnosis-case-v2.valid.json")
    report = load(EXAMPLES / "diagnosis-report-v1.index-access.review.json")
    source = load(EXAMPLES / "source-v1.valid.json")

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

    terminal = build_validated_case(case)
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

    if not (ROOT / "evidence-v2.schema.json").is_file():
        raise AssertionError("Evidence/v2 contract is missing")

    print("vNext negative contract cases rejected: 19")


if __name__ == "__main__":
    main()
