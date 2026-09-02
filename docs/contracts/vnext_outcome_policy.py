"""Singular, causal outcome policy for Diagnosis Case terminal revisions."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from vnext_canonical_json import canonical_sha256
from vnext_diagnosis_policy import require_eligible

AUTHORIZATION_REVISION = "owner-action-approval/v1"
ACTION_RESULT_METRICS = {
    ("action.index_candidate_isolated", "v1"): ("p95_latency_ms", "ms"),
    ("action.statistics_refresh_isolated", "v1"): (
        "estimation_ratio_basis_points",
        "basis_points",
    ),
    ("action.resource_hotspot_runbook", "v1"): ("tikv_p99_latency_ms", "ms"),
}


def authorization_snapshot_digest(snapshot: dict[str, Any]) -> str:
    """Digest the server-owned authorization fields without its digest."""

    return canonical_sha256(
        {
            key: snapshot[key]
            for key in (
                "principalId",
                "role",
                "permission",
                "authorizationRevision",
                "capturedAt",
            )
        }
    )


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


def _require_human_approval(
    review: dict[str, Any],
    action: dict[str, Any],
    parse_time: Callable[[str], datetime],
    expected_decision: str = "approved",
) -> None:
    if review["decision"] != expected_decision or review["actionIds"] != [
        action["actionId"]
    ]:
        raise ValueError("outcome approval does not approve its Action")
    reviewer = review["reviewer"]
    authorization = review.get("authorizationSnapshot")
    if reviewer["kind"] != "user" or authorization is None:
        raise ValueError("human-approved Action requires a user authorization snapshot")
    if authorization["principalId"] != reviewer["id"]:
        raise ValueError("approval authorization snapshot belongs to another principal")
    if authorization["permission"] != "approve_diagnosis_action":
        raise ValueError("approval authorization snapshot lacks Action permission")
    if authorization["role"] not in {"owner", "dba", "sre"}:
        raise ValueError("approval authorization role is not permitted")
    if authorization["authorizationRevision"] != AUTHORIZATION_REVISION:
        raise ValueError("approval authorization policy revision is not supported")
    if authorization["identityDigest"] != authorization_snapshot_digest(authorization):
        raise ValueError("approval authorization snapshot digest is inconsistent")
    if parse_time(authorization["capturedAt"]) > parse_time(review["createdAt"]):
        raise ValueError("approval authorization snapshot was captured after review")


def validate_outcome_policy(
    case: dict[str, Any], parse_time: Callable[[str], datetime]
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
            parse_time,
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
    _require_human_approval(review, action, parse_time)
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
    kinds = {item["kind"] for item in results}
    required = (
        {"effect_metric_comparison"}
        if outcome == "validated_effective"
        else {"effect_metric_comparison", "rollback_confirmation"}
    )
    if kinds != required or len(results) != len(required):
        raise ValueError(
            "terminal tuple has an incomplete or extra result evidence set"
        )
    for result in results:
        require_eligible(result, "terminal outcome")

    effect = next(
        item for item in results if item["kind"] == "effect_metric_comparison"
    )
    effect_typed = effect["payload"]["typed"]
    action_template = (action["templateId"], action["templateRevision"])
    if action_template not in ACTION_RESULT_METRICS:
        raise ValueError("Action has no terminal result metric policy")
    if (
        effect_typed["actionId"] != action["actionId"]
        or effect_typed["validationTargetZh"] != action["validation"]["targetZh"]
        or (effect_typed["metricCode"], effect_typed["unit"])
        != ACTION_RESULT_METRICS[action_template]
    ):
        raise ValueError("effect evidence is not bound to the Action result policy")
    if outcome == "validated_effective" and not effect_typed["passed"]:
        raise ValueError("validated_effective requires a passed effect comparison")
    if outcome == "rolled_back":
        rollback = next(
            item for item in results if item["kind"] == "rollback_confirmation"
        )
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
