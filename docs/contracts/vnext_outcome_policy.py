"""Singular, causal outcome policy for Diagnosis Case terminal revisions."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from vnext_canonical_json import canonical_sha256
from vnext_diagnosis_policy import require_eligible

AUTHORIZATION_REVISION = "owner-action-approval/v2"
AUTHORIZATION_ATTESTATION_REVISION = "server-authorization-audit/v1"

ACTION_RESULT_POLICY = {
    ("action.index_candidate_isolated", "v1"): (
        {
            "metricCode": "average_scan_rows",
            "unit": "rows",
            "predicate": "reduction_percent_at_least",
            "parameter": "minScanReductionPct",
        },
        {
            "metricCode": "p95_latency_ms",
            "unit": "ms",
            "predicate": "observed_at_most",
            "parameter": "maxP95Ms",
        },
        {
            "metricCode": "write_regression_basis_points",
            "unit": "basis_points",
            "predicate": "regression_at_most",
            "parameter": "maxWriteRegressionBasisPoints",
        },
    ),
    ("action.statistics_refresh_isolated", "v1"): (
        {
            "metricCode": "estimation_ratio_basis_points",
            "unit": "basis_points",
            "predicate": "ratio_at_most",
            "parameter": "maxEstimateRatio",
        },
        {
            "metricCode": "join_order_change_count",
            "unit": "count",
            "predicate": "observed_zero",
            "parameter": None,
        },
        {
            "metricCode": "batch_duration_minutes",
            "unit": "minutes",
            "predicate": "observed_at_most",
            "parameter": "maxDurationMinutes",
        },
    ),
    ("action.resource_hotspot_runbook", "v1"): (
        {
            "metricCode": "tikv_p99_latency_ms",
            "unit": "ms",
            "predicate": "at_or_below_baseline",
            "parameter": None,
        },
        {
            "metricCode": "hotspot_score_basis_points",
            "unit": "basis_points",
            "predicate": "at_or_below_baseline",
            "parameter": None,
        },
        {
            "metricCode": "payment_error_rate_basis_points",
            "unit": "basis_points",
            "predicate": "at_or_below_baseline",
            "parameter": None,
        },
    ),
}


def _require_record(
    records: dict[str, dict[str, Any]], record_id: str | None, label: str
) -> dict[str, Any]:
    if record_id is None or record_id not in records:
        raise ValueError(f"terminal outcome has no valid {label}")
    return records[record_id]


def _exact_event_projection(
    event: dict[str, Any], outcome_tuple: dict[str, Any]
) -> None:
    review_ids = (
        [outcome_tuple["approvalReviewId"]]
        if outcome_tuple["approvalReviewId"] is not None
        else []
    )
    feedback_ids = [
        item
        for item in (
            outcome_tuple["implementationFeedbackId"],
            outcome_tuple["terminalFeedbackId"],
        )
        if item is not None
    ]
    action_ids = (
        [outcome_tuple["actionId"]] if outcome_tuple["actionId"] is not None else []
    )
    if event["reviewIds"] != review_ids:
        raise ValueError("outcome event reviewIds are not its singular tuple")
    if event["feedbackIds"] != feedback_ids:
        raise ValueError("outcome event feedbackIds are not its singular tuple")
    if event["actionIds"] != action_ids:
        raise ValueError("outcome event actionIds are not its singular tuple")
    if event["evidenceIds"] != outcome_tuple["resultEvidenceIds"]:
        raise ValueError("outcome event evidenceIds are not its singular tuple")


def _measurement_passes(
    typed: dict[str, Any], policy: dict[str, Any], action: dict[str, Any]
) -> bool:
    baseline = typed["baselineValue"]
    observed = typed["observedValue"]
    predicate = policy["predicate"]
    parameter = policy["parameter"]
    threshold = action["params"].get(parameter) if parameter is not None else None
    if predicate == "reduction_percent_at_least":
        return (
            baseline > 0
            and 0 <= observed <= baseline
            and (baseline - observed) * 100 >= baseline * threshold
        )
    if predicate == "observed_at_most":
        return baseline >= 0 and observed >= 0 and observed <= threshold
    if predicate == "regression_at_most":
        return baseline == 0 and 0 <= observed <= threshold
    if predicate == "ratio_at_most":
        return baseline > 0 and 0 < observed <= threshold * 10_000
    if predicate == "observed_zero":
        return baseline >= 0 and observed == 0
    if predicate == "at_or_below_baseline":
        return baseline > 0 and 0 <= observed <= baseline
    raise ValueError(f"unknown Action measurement predicate: {predicate}")


def _require_human_approval(
    review: dict[str, Any],
    action: dict[str, Any],
    case: dict[str, Any],
    parse_time: Callable[[str], datetime],
    resolve_authorization_audit: Callable[[str], dict[str, Any] | None],
    expected_decision: str = "approved",
) -> None:
    if review["decision"] != expected_decision or review["actionIds"] != [
        action["actionId"]
    ]:
        raise ValueError("outcome approval does not approve its Action")
    reviewer = review["reviewer"]
    authorization_ref = review.get("authorizationSnapshot")
    if reviewer["kind"] != "user" or authorization_ref is None:
        raise ValueError("human-approved Action requires an authorization audit")
    if authorization_ref["attestationRevision"] != AUTHORIZATION_ATTESTATION_REVISION:
        raise ValueError("authorization audit attestation revision is not supported")
    authorization = resolve_authorization_audit(authorization_ref["auditRecordId"])
    if authorization is None:
        raise ValueError("authorization audit record is not trusted by the server")
    expected_binding = {
        "auditRecordId": authorization_ref["auditRecordId"],
        "attestationRevision": AUTHORIZATION_ATTESTATION_REVISION,
        "caseId": case["caseId"],
        "caseRevision": case["revision"],
        "actionId": action["actionId"],
        "actionDigest": canonical_sha256(action),
        "reviewId": review["reviewId"],
        "principalId": reviewer["id"],
        "permission": "approve_diagnosis_action",
        "authorizationRevision": AUTHORIZATION_REVISION,
    }
    if any(authorization.get(key) != value for key, value in expected_binding.items()):
        raise ValueError("authorization audit does not bind the terminal approval")
    if authorization.get("role") not in {"owner", "dba", "sre"}:
        raise ValueError("authorization audit role is not permitted")
    if parse_time(authorization["capturedAt"]) > parse_time(review["createdAt"]):
        raise ValueError("approval authorization snapshot was captured after review")


def _required_authorization_resolver(
    resolver: Callable[[str], dict[str, Any] | None] | None,
) -> Callable[[str], dict[str, Any] | None]:
    if resolver is None:
        raise ValueError(
            "terminal approval has no trusted authorization audit resolver"
        )
    return resolver


def validate_outcome_policy(
    case: dict[str, Any],
    parse_time: Callable[[str], datetime],
    resolve_authorization_audit: Callable[[str], dict[str, Any] | None] | None = None,
) -> None:
    outcome = case["outcome"]
    if outcome == "pending":
        return

    terminal_events = [
        event
        for event in case["transitionEvents"]
        if event["type"] == "outcome"
        and event["fromOutcome"] == "pending"
        and event["toOutcome"] == outcome
    ]
    if len(terminal_events) != 1:
        raise ValueError("terminal outcome requires one pending transition")
    event = terminal_events[0]
    terminal_revision = event["caseRevision"]
    if terminal_revision != case["revision"]:
        raise ValueError(
            "terminal outcome event does not belong to current Case revision"
        )
    outcome_tuple = event["outcomeTuple"]
    _exact_event_projection(event, outcome_tuple)

    actions = {item["actionId"]: item for item in case["actions"]}
    reviews = {item["reviewId"]: item for item in case["reviews"]}
    feedback = {item["feedbackId"]: item for item in case["feedback"]}
    evidence = {item["evidenceId"]: item for item in case["evidence"]}

    if outcome == "evidence_insufficient":
        if (
            any(
                outcome_tuple[field] is not None
                for field in (
                    "actionId",
                    "approvalReviewId",
                    "implementationFeedbackId",
                )
            )
            or outcome_tuple["resultEvidenceIds"]
        ):
            raise ValueError("evidence_insufficient tuple carries implementation data")
        terminal = _require_record(
            feedback,
            outcome_tuple["terminalFeedbackId"],
            "evidence-insufficient feedback",
        )
        if (
            terminal["kind"] != "evidence_insufficient"
            or terminal["caseRevision"] != terminal_revision
        ):
            raise ValueError("evidence_insufficient tuple cites another feedback kind")
        return

    action = _require_record(actions, outcome_tuple["actionId"], "Action")
    review = _require_record(
        reviews, outcome_tuple["approvalReviewId"], "approval review"
    )
    if review["caseRevision"] != terminal_revision:
        raise ValueError("outcome approval is not owned by its terminal Case revision")

    if outcome == "risk_accepted":
        if review["decision"] != "risk_accepted":
            raise ValueError("risk_accepted tuple lacks its review decision")
        _require_human_approval(
            review,
            action,
            case,
            parse_time,
            _required_authorization_resolver(resolve_authorization_audit),
            expected_decision="risk_accepted",
        )
        if (
            any(
                outcome_tuple[field] is not None
                for field in ("implementationFeedbackId", "terminalFeedbackId")
            )
            or outcome_tuple["resultEvidenceIds"]
        ):
            raise ValueError("risk_accepted tuple carries implementation results")
        return

    implementation = _require_record(
        feedback,
        outcome_tuple["implementationFeedbackId"],
        "implementation feedback",
    )
    terminal = _require_record(
        feedback,
        outcome_tuple["terminalFeedbackId"],
        "terminal feedback",
    )
    if (
        implementation["caseRevision"] != terminal_revision
        or terminal["caseRevision"] != terminal_revision
    ):
        raise ValueError("outcome feedback is not owned by its terminal Case revision")
    _require_human_approval(
        review,
        action,
        case,
        parse_time,
        _required_authorization_resolver(resolve_authorization_audit),
    )
    if (
        implementation["kind"] != "implemented"
        or implementation["actionId"] != action["actionId"]
    ):
        raise ValueError("outcome implementation does not implement its Action")
    expected_terminal_kind = (
        "validated" if outcome == "validated_effective" else "rolled_back"
    )
    if (
        terminal["kind"] != expected_terminal_kind
        or terminal["actionId"] != action["actionId"]
    ):
        raise ValueError("terminal feedback does not close its Action")

    result_ids = outcome_tuple["resultEvidenceIds"]
    if terminal["evidenceIds"] != result_ids:
        raise ValueError("terminal feedback evidence differs from singular tuple")
    results = [
        _require_record(evidence, evidence_id, "result Evidence")
        for evidence_id in result_ids
    ]
    for result in results:
        require_eligible(result, "terminal outcome")

    action_template = (action["templateId"], action["templateRevision"])
    if action_template not in ACTION_RESULT_POLICY:
        raise ValueError("Action has no terminal result metric policy")
    measurement_policy = ACTION_RESULT_POLICY[action_template]
    effects = [item for item in results if item["kind"] == "effect_metric_comparison"]
    rollbacks = [item for item in results if item["kind"] == "rollback_confirmation"]
    if len(effects) + len(rollbacks) != len(results):
        raise ValueError("terminal tuple contains an unsupported result Evidence kind")
    expected_metric_codes = [item["metricCode"] for item in measurement_policy]
    actual_metric_codes = [item["payload"]["typed"]["metricCode"] for item in effects]
    if actual_metric_codes != expected_metric_codes:
        raise ValueError("terminal tuple lacks the complete Action measurement policy")

    measurement_results: list[bool] = []
    for effect, policy in zip(effects, measurement_policy, strict=True):
        typed = effect["payload"]["typed"]
        if (
            typed["actionId"] != action["actionId"]
            or typed["validationTargetZh"] != action["validation"]["targetZh"]
            or typed["metricCode"] != policy["metricCode"]
            or typed["unit"] != policy["unit"]
        ):
            raise ValueError("effect evidence is not bound to the Action result policy")
        measurement_results.append(_measurement_passes(typed, policy, action))

    if outcome == "validated_effective" and (rollbacks or not all(measurement_results)):
        raise ValueError(
            "validated_effective does not satisfy the Action measurement policy"
        )
    if outcome == "rolled_back":
        if len(rollbacks) != 1 or all(measurement_results):
            raise ValueError(
                "rolled_back requires one failed Action measurement and one rollback"
            )
        rollback = rollbacks[0]
        rollback_typed = rollback["payload"]["typed"]
        if (
            rollback_typed["actionId"] != action["actionId"]
            or rollback_typed["rollbackState"] != "confirmed"
        ):
            raise ValueError(
                "rolled_back requires confirmed rollback for the same Action"
            )

    approval_at = parse_time(review["createdAt"])
    implemented_at = parse_time(implementation["createdAt"])
    observed_at = min(parse_time(item["observedAt"]) for item in results)
    collected_at = max(parse_time(item["collectedAt"]) for item in results)
    terminal_at = parse_time(terminal["createdAt"])
    event_at = parse_time(event["createdAt"])
    event_actor = event["actor"]
    terminal_actor = terminal["actor"]
    if (
        event_actor["kind"] != "user"
        or terminal_actor["kind"] != "user"
        or event_actor["id"] != terminal_actor["id"]
    ):
        raise ValueError("terminal outcome must be attested by one user principal")
    if not (
        approval_at
        <= implemented_at
        <= observed_at
        <= collected_at
        <= terminal_at
        <= event_at
    ):
        raise ValueError("terminal outcome tuple is not causally ordered")
