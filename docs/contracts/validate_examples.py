from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).parent
EXAMPLES = ROOT / "examples"
RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:"
    r"(?P<second>[0-5]\d|60)(?:\.\d+)?"
    r"(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
FORMAT_CHECKER = FormatChecker()
APPEND_ONLY_COLLECTIONS = (
    "evidence",
    "hypotheses",
    "recommendations",
    "reviews",
    "feedback",
)
AUDIT_COLLECTIONS = ("reviews", "feedback")
STABLE_FIELDS = (
    "schemaVersion",
    "caseId",
    "sourceLayer",
    "inputFingerprint",
    "createdAt",
    "pinnedRevisions",
)
WORKFLOW_TRANSITIONS = {
    "queued": {"queued", "collecting", "failed", "cancelled"},
    "collecting": {"collecting", "analyzing", "failed", "cancelled"},
    "analyzing": {"analyzing", "ready", "failed", "cancelled"},
    "ready": {"ready"},
    "failed": {"failed"},
    "cancelled": {"cancelled"},
}
TERMINAL_OUTCOMES = {
    "validated_effective",
    "rolled_back",
    "evidence_insufficient",
    "risk_accepted",
}
OUTCOME_TRANSITIONS = {
    "pending": {"pending", *TERMINAL_OUTCOMES},
    "validated_effective": {"validated_effective"},
    "rolled_back": {"rolled_back"},
    "evidence_insufficient": {"evidence_insufficient"},
    "risk_accepted": {"risk_accepted"},
}
OUTCOME_PREREQUISITES = {
    "validated_effective": (
        ("reviews", "decision", "approved"),
        ("feedback", "kind", "implemented"),
        ("feedback", "kind", "validated"),
    ),
    "rolled_back": (
        ("reviews", "decision", "approved"),
        ("feedback", "kind", "implemented"),
        ("feedback", "kind", "rolled_back"),
    ),
    "evidence_insufficient": (("feedback", "kind", "evidence_insufficient"),),
    "risk_accepted": (("reviews", "decision", "risk_accepted"),),
}
OUTCOME_TRIGGERS = {
    "validated_effective": ("feedback", "kind", "validated"),
    "rolled_back": ("feedback", "kind", "rolled_back"),
    "evidence_insufficient": ("feedback", "kind", "evidence_insufficient"),
    "risk_accepted": ("reviews", "decision", "risk_accepted"),
}
LEGACY_DRAFT_OUTCOME_ALIASES = {
    "not_reviewed": "pending",
    "accepted": "pending",
    "rejected": "pending",
    "implemented": "pending",
    "validated": "pending",
}
OUTCOME_EVIDENCE_KINDS = {
    "validated_effective": {"effect_metric_comparison"},
    "rolled_back": {"effect_metric_comparison", "rollback_confirmation"},
}


# jsonschema only registers date-time when its optional validator is installed.
@FORMAT_CHECKER.checks("date-time", raises=ValueError)
def is_rfc3339_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return True

    try:
        parse_rfc3339_datetime(value)
    except ValueError:
        return False
    return True


def parse_rfc3339_datetime(value: str) -> datetime:
    match = RFC3339_DATETIME.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid RFC 3339 date-time: {value!r}")

    normalized = value[:10] + "T" + value[11:]
    if match.group("second") == "60":
        normalized = normalized[:17] + "59" + normalized[19:]
    if normalized[-1] in {"Z", "z"}:
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"RFC 3339 date-time requires an offset: {value!r}")
    return parsed


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def migrate_legacy_draft_outcome(case: dict[str, Any]) -> dict[str, Any]:
    migrated = copy.deepcopy(case)
    migrated["outcome"] = LEGACY_DRAFT_OUTCOME_ALIASES.get(
        case["outcome"], case["outcome"]
    )
    return migrated


def next_revision_of(case: dict[str, Any]) -> dict[str, Any]:
    current = copy.deepcopy(case)
    current["revision"] = case["revision"] + 1
    current["updatedAt"] = "2026-08-31T10:00:02Z"
    return current


def review_record(
    valid: dict[str, Any],
    decision: str,
    ordinal: int,
    created_at: str = "2026-08-31T10:00:02Z",
) -> dict[str, Any]:
    review = copy.deepcopy(valid["reviews"][0])
    review["reviewId"] = f"rev_{ordinal:016d}"
    review["decision"] = decision
    review["createdAt"] = created_at
    return review


def feedback_record(
    valid: dict[str, Any],
    kind: str,
    ordinal: int,
    created_at: str = "2026-08-31T10:00:02Z",
) -> dict[str, Any]:
    feedback = copy.deepcopy(valid["feedback"][0])
    feedback["feedbackId"] = f"fb_{ordinal:016d}"
    feedback["kind"] = kind
    feedback["createdAt"] = created_at
    return feedback


def evidence_record(
    valid: dict[str, Any], kind: str, ordinal: int
) -> dict[str, Any]:
    evidence = copy.deepcopy(valid["evidence"][0])
    evidence["evidenceId"] = f"ev_{ordinal:016d}"
    evidence["kind"] = kind
    evidence["source"] = "effect_validation_policy"
    evidence["observedAt"] = "2026-08-31T10:00:00.300Z"
    evidence["collectedAt"] = "2026-08-31T10:00:00.400Z"
    evidence["integrityDigest"] = f"sha256:{ordinal:064x}"
    evidence["summary"] = f"Policy-validated {kind.replace('_', ' ')} evidence."
    return evidence


def case_for_outcome(valid: dict[str, Any], outcome: str) -> dict[str, Any]:
    case = copy.deepcopy(valid)
    case["workflowState"] = "ready"
    case["outcome"] = outcome
    case["reviews"] = []
    case["feedback"] = []

    if outcome in {"validated_effective", "rolled_back"}:
        case["reviews"].append(
            review_record(valid, "approved", 1, "2026-08-31T10:00:00.100Z")
        )
    elif outcome == "risk_accepted":
        case["reviews"].append(
            review_record(valid, "risk_accepted", 1, "2026-08-31T10:00:00.500Z")
        )

    effect_evidence_ids: list[str] = []
    if outcome in OUTCOME_EVIDENCE_KINDS:
        for ordinal, kind in enumerate(
            sorted(OUTCOME_EVIDENCE_KINDS[outcome]), start=2
        ):
            evidence = evidence_record(valid, kind, ordinal)
            case["evidence"].append(evidence)
            effect_evidence_ids.append(evidence["evidenceId"])

    if outcome in {"validated_effective", "rolled_back"}:
        case["feedback"].append(
            feedback_record(valid, "implemented", 1, "2026-08-31T10:00:00.200Z")
        )
    if outcome == "validated_effective":
        feedback = feedback_record(
            valid, "validated", 2, "2026-08-31T10:00:00.500Z"
        )
        feedback["evidenceIds"] = effect_evidence_ids
        case["feedback"].append(feedback)
    elif outcome == "rolled_back":
        feedback = feedback_record(
            valid, "rolled_back", 2, "2026-08-31T10:00:00.500Z"
        )
        feedback["evidenceIds"] = effect_evidence_ids
        case["feedback"].append(feedback)
    elif outcome == "evidence_insufficient":
        case["evidenceCompleteness"] = {
            "score": 0.2,
            "classification": "insufficient",
            "missing": ["schema", "statistics", "runtime_metrics"],
        }
        case["recommendations"] = []
        feedback = feedback_record(
            valid, "evidence_insufficient", 1, "2026-08-31T10:00:00.500Z"
        )
        feedback["recommendationId"] = None
        case["feedback"].append(feedback)
    return case


def legacy_case_for_outcome(valid: dict[str, Any], outcome: str) -> dict[str, Any]:
    case = copy.deepcopy(valid)
    case["outcome"] = outcome
    case["reviews"] = []
    case["feedback"] = []

    if outcome == "rejected":
        case["reviews"].append(
            review_record(valid, "rejected", 1, "2026-08-31T10:00:01Z")
        )
    elif outcome in {"accepted", "implemented", "validated"}:
        case["reviews"].append(
            review_record(valid, "approved", 1, "2026-08-31T10:00:01Z")
        )
    if outcome in {"implemented", "validated"}:
        case["feedback"].append(
            feedback_record(valid, "implemented", 1, "2026-08-31T10:00:01Z")
        )
    if outcome == "validated":
        case["feedback"].append(
            feedback_record(valid, "validated", 2, "2026-08-31T10:00:01Z")
        )
    return case


def pending_case_before_outcome(
    valid: dict[str, Any], outcome: str
) -> dict[str, Any]:
    case = case_for_outcome(valid, outcome)
    collection, field, expected = OUTCOME_TRIGGERS[outcome]
    case[collection] = [
        record for record in case[collection] if record[field] != expected
    ]
    case["outcome"] = "pending"
    return case


def validate_references(case: dict[str, Any]) -> None:
    evidence_ids = require_unique_ids(case["evidence"], "evidenceId", "evidence")
    require_unique_ids(case["hypotheses"], "hypothesisId", "hypothesis")
    recommendation_ids = require_unique_ids(
        case["recommendations"], "recommendationId", "recommendation"
    )
    require_unique_ids(case["reviews"], "reviewId", "review")
    require_unique_ids(case["feedback"], "feedbackId", "feedback")

    for hypothesis in case["hypotheses"]:
        supporting = set(hypothesis["supportingEvidenceIds"])
        contradicting = set(hypothesis["contradictingEvidenceIds"])
        overlap = supporting & contradicting
        if overlap:
            raise ValueError(
                "supporting and contradicting evidence IDs overlap: "
                f"{sorted(overlap)}"
            )
        referenced = supporting | contradicting
        missing = referenced - evidence_ids
        if missing:
            raise ValueError(f"hypothesis has unknown evidence IDs: {sorted(missing)}")
        if hypothesis["status"] == "favored" and not supporting:
            raise ValueError("favored hypothesis requires supporting evidence")
        if hypothesis["status"] == "rejected" and not contradicting:
            raise ValueError("rejected hypothesis requires contradicting evidence")

    for recommendation in case["recommendations"]:
        missing = set(recommendation["evidenceIds"]) - evidence_ids
        if missing:
            raise ValueError(
                f"recommendation has unknown evidence IDs: {sorted(missing)}"
            )

    for review in case["reviews"]:
        missing = set(review.get("recommendationIds", [])) - recommendation_ids
        if missing:
            raise ValueError(
                f"review has unknown recommendation IDs: {sorted(missing)}"
            )

    for feedback in case["feedback"]:
        recommendation_id = feedback.get("recommendationId")
        if recommendation_id and recommendation_id not in recommendation_ids:
            raise ValueError(
                f"feedback has unknown recommendation ID: {recommendation_id}"
            )
        missing_evidence = set(feedback.get("evidenceIds", [])) - evidence_ids
        if missing_evidence:
            raise ValueError(
                "feedback has unknown evidence IDs: "
                f"{sorted(missing_evidence)}"
            )


def require_unique_ids(
    records: list[dict[str, Any]], key: str, label: str
) -> set[str]:
    identifiers = [record[key] for record in records]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError(f"duplicate {label} ID")
    return set(identifiers)


def expect_value_error(action: Callable[[], None], message_fragment: str) -> None:
    try:
        action()
    except ValueError as error:
        if message_fragment not in str(error):
            raise AssertionError(
                f"expected {message_fragment!r} in error, got {str(error)!r}"
            ) from error
    else:
        raise AssertionError(f"expected ValueError containing {message_fragment!r}")


def validate_audit_time_order(case: dict[str, Any]) -> None:
    created_at = parse_rfc3339_datetime(case["createdAt"])
    updated_at = parse_rfc3339_datetime(case["updatedAt"])
    if updated_at < created_at:
        raise ValueError("case updatedAt cannot precede createdAt")

    for field in AUDIT_COLLECTIONS:
        prior_record_time: datetime | None = None
        for record in case[field]:
            record_time = parse_rfc3339_datetime(record["createdAt"])
            if not created_at <= record_time <= updated_at:
                raise ValueError(
                    f"{field} createdAt must be inside the case time window"
                )
            if prior_record_time is not None and record_time < prior_record_time:
                raise ValueError(f"{field} createdAt order must be chronological")
            prior_record_time = record_time


def is_effect_outcome_chain(
    case: dict[str, Any], outcome: str, terminal_feedback: dict[str, Any]
) -> bool:
    required_feedback_kind = (
        "validated" if outcome == "validated_effective" else "rolled_back"
    )
    recommendation_id = terminal_feedback.get("recommendationId")
    recommendation_ids = {
        recommendation["recommendationId"]
        for recommendation in case["recommendations"]
    }
    if (
        terminal_feedback.get("kind") != required_feedback_kind
        or recommendation_id not in recommendation_ids
        or not terminal_feedback.get("evidenceIds")
    ):
        return False

    evidence_by_id = {
        evidence["evidenceId"]: evidence for evidence in case["evidence"]
    }
    bound_result_evidence = [
        evidence_by_id[evidence_id]
        for evidence_id in terminal_feedback["evidenceIds"]
        if evidence_id in evidence_by_id
        and evidence_by_id[evidence_id]["kind"] in OUTCOME_EVIDENCE_KINDS[outcome]
    ]
    if OUTCOME_EVIDENCE_KINDS[outcome] - {
        evidence["kind"] for evidence in bound_result_evidence
    }:
        return False

    terminal_time = parse_rfc3339_datetime(terminal_feedback["createdAt"])
    updated_at = parse_rfc3339_datetime(case["updatedAt"])
    if terminal_time > updated_at:
        return False

    approvals = [
        review
        for review in case["reviews"]
        if review["decision"] == "approved"
        and recommendation_id in review.get("recommendationIds", [])
    ]
    implementations = [
        feedback
        for feedback in case["feedback"]
        if feedback["kind"] == "implemented"
        and feedback.get("recommendationId") == recommendation_id
    ]

    for approval in approvals:
        approval_time = parse_rfc3339_datetime(approval["createdAt"])
        for implementation in implementations:
            implementation_time = parse_rfc3339_datetime(
                implementation["createdAt"]
            )
            if approval_time > implementation_time:
                continue
            if all(
                implementation_time
                <= parse_rfc3339_datetime(evidence["observedAt"])
                <= parse_rfc3339_datetime(evidence["collectedAt"])
                <= terminal_time
                for evidence in bound_result_evidence
            ):
                return True
    return False


def is_qualifying_outcome_trigger(
    case: dict[str, Any], outcome: str, record: dict[str, Any]
) -> bool:
    collection, field, expected = OUTCOME_TRIGGERS[outcome]
    if record.get(field) != expected:
        return False

    if collection == "reviews":
        recommendation_ids = {
            recommendation["recommendationId"]
            for recommendation in case["recommendations"]
        }
        return bool(set(record.get("recommendationIds", [])) & recommendation_ids)

    if outcome in OUTCOME_EVIDENCE_KINDS:
        return is_effect_outcome_chain(case, outcome, record)

    return True


def validate_case_semantics(case: dict[str, Any]) -> None:
    validate_audit_time_order(case)
    outcome = case["outcome"]
    if outcome != "pending" and case["workflowState"] != "ready":
        raise ValueError(f"{outcome} outcome requires ready workflowState")

    for collection, field, expected in OUTCOME_PREREQUISITES.get(outcome, ()):
        if not any(record[field] == expected for record in case[collection]):
            label = "review" if collection == "reviews" else "feedback"
            raise ValueError(f"{outcome} outcome requires {expected} {label}")

    if outcome == "evidence_insufficient":
        completeness = case["evidenceCompleteness"]
        if completeness["classification"] != "insufficient":
            raise ValueError(
                "evidence_insufficient outcome requires insufficient completeness"
            )
        if not completeness["missing"]:
            raise ValueError(
                "evidence_insufficient outcome requires missing evidence details"
            )
        if case["recommendations"]:
            raise ValueError(
                "evidence_insufficient outcome cannot contain recommendations"
            )

    if outcome == "risk_accepted" and not any(
        is_qualifying_outcome_trigger(case, outcome, review)
        for review in case["reviews"]
    ):
        raise ValueError(
            "risk_accepted outcome requires a review linked to recommendations"
        )

    if outcome in {"validated_effective", "rolled_back"}:
        required_kind = (
            "validated" if outcome == "validated_effective" else "rolled_back"
        )
        if not any(
            is_qualifying_outcome_trigger(case, outcome, feedback)
            for feedback in case["feedback"]
        ):
            raise ValueError(
                f"{outcome} outcome requires approval, implemented feedback, "
                f"and linked {required_kind} feedback with evidence in causal "
                "order for the same recommendation"
            )


def validate_revision(previous: dict[str, Any], current: dict[str, Any]) -> None:
    if current["revision"] != previous["revision"] + 1:
        raise ValueError("revision must increase by exactly one")

    previous_workflow = previous["workflowState"]
    current_workflow = current["workflowState"]
    if current_workflow not in WORKFLOW_TRANSITIONS[previous_workflow]:
        raise ValueError(
            "illegal workflowState transition: "
            f"{previous_workflow} -> {current_workflow}"
        )

    previous_outcome = previous["outcome"]
    current_outcome = current["outcome"]
    if current_outcome not in OUTCOME_TRANSITIONS[previous_outcome]:
        raise ValueError(
            f"illegal outcome transition: {previous_outcome} -> {current_outcome}"
        )

    for field in STABLE_FIELDS:
        if current[field] != previous[field]:
            raise ValueError(f"{field} is immutable across revisions")

    previous_time = parse_rfc3339_datetime(previous["updatedAt"])
    current_time = parse_rfc3339_datetime(current["updatedAt"])
    if current_time <= previous_time:
        raise ValueError("updatedAt must increase across revisions")

    for field in APPEND_ONLY_COLLECTIONS:
        previous_items = previous[field]
        if current[field][: len(previous_items)] != previous_items:
            raise ValueError(f"{field} cannot mutate or remove prior records")

    for field in AUDIT_COLLECTIONS:
        for record in current[field][len(previous[field]) :]:
            created_at = parse_rfc3339_datetime(record["createdAt"])
            if not previous_time < created_at <= current_time:
                raise ValueError(
                    f"new {field} createdAt must be inside the revision time window"
                )

    validate_case_semantics(previous)
    validate_case_semantics(current)

    if current_outcome != previous_outcome:
        collection, field, expected = OUTCOME_TRIGGERS[current_outcome]
        new_records = current[collection][len(previous[collection]) :]
        if not any(
            is_qualifying_outcome_trigger(current, current_outcome, record)
            for record in new_records
        ):
            label = "review" if collection == "reviews" else "feedback"
            raise ValueError(
                f"{previous_outcome} -> {current_outcome} requires a qualifying "
                f"new {expected} {label}"
            )


def main() -> None:
    schema = load_json(ROOT / "diagnosis-case-v1.schema.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)

    workflow_states = set(schema["properties"]["workflowState"]["enum"])
    outcome_states = set(schema["properties"]["outcome"]["enum"])
    assert outcome_states == {"pending", *TERMINAL_OUTCOMES}
    assert not {"accepted", "rejected", "implemented", "validated"} & outcome_states
    assert (
        schema["properties"]["outcome"]["x-legacyDraftAliases"]
        == LEGACY_DRAFT_OUTCOME_ALIASES
    )
    assert set(WORKFLOW_TRANSITIONS) == workflow_states
    assert set().union(*WORKFLOW_TRANSITIONS.values()) == workflow_states
    assert set(OUTCOME_TRANSITIONS) == outcome_states
    assert set().union(*OUTCOME_TRANSITIONS.values()) == outcome_states
    assert set(OUTCOME_PREREQUISITES) == TERMINAL_OUTCOMES
    assert set(OUTCOME_TRIGGERS) == TERMINAL_OUTCOMES

    valid = load_json(EXAMPLES / "diagnosis-case-v1.valid.json")
    validator.validate(valid)
    validate_references(valid)
    validate_case_semantics(valid)

    for legacy_outcome, expected_outcome in LEGACY_DRAFT_OUTCOME_ALIASES.items():
        legacy = legacy_case_for_outcome(valid, legacy_outcome)
        assert any(error.validator == "enum" for error in validator.iter_errors(legacy))
        migrated = migrate_legacy_draft_outcome(legacy)
        assert legacy["outcome"] == legacy_outcome
        assert migrated["outcome"] == expected_outcome
        validator.validate(migrated)
        validate_references(migrated)
        validate_case_semantics(migrated)

    no_provenance = copy.deepcopy(valid)
    no_provenance["recommendations"][0]["evidenceIds"] = []
    assert any(
        error.validator == "minItems"
        for error in validator.iter_errors(no_provenance)
    )

    missing_model_pin = copy.deepcopy(valid)
    del missing_model_pin["pinnedRevisions"]["model"]
    assert any(
        error.validator == "required" and "model" in error.message
        for error in validator.iter_errors(missing_model_pin)
    )

    timestamp_paths = (
        ("createdAt",),
        ("updatedAt",),
        ("evidence", 0, "observedAt"),
        ("evidence", 0, "collectedAt"),
        ("reviews", 0, "createdAt"),
        ("feedback", 0, "createdAt"),
    )
    malformed_timestamp_values = (
        "not-a-date",
        "2026-02-30T10:00:00Z",
        "2026-08-31 10:00:00Z",
        "2026-08-31T10:00:00",
    )
    for path in timestamp_paths:
        for value in malformed_timestamp_values:
            malformed_timestamp = copy.deepcopy(valid)
            target: Any = malformed_timestamp
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = value
            assert any(
                error.validator == "format"
                for error in validator.iter_errors(malformed_timestamp)
            ), f"malformed timestamp {value!r} at {path} must fail"

    missing_owner = load_json(
        EXAMPLES / "diagnosis-case-v1.invalid-missing-owner.json"
    )
    owner_errors = list(validator.iter_errors(missing_owner))
    assert any(
        error.validator == "required" and "owner" in error.message
        for error in owner_errors
    )

    invalid_reference = load_json(
        EXAMPLES / "diagnosis-case-v1.invalid-reference.json"
    )
    validator.validate(invalid_reference)
    try:
        validate_references(invalid_reference)
    except ValueError:
        pass
    else:
        raise AssertionError("dangling references must fail domain validation")

    conflicting_evidence = copy.deepcopy(valid)
    evidence_id = conflicting_evidence["hypotheses"][0][
        "supportingEvidenceIds"
    ][0]
    conflicting_evidence["hypotheses"][0]["contradictingEvidenceIds"] = [
        evidence_id
    ]
    expect_value_error(
        lambda: validate_references(conflicting_evidence),
        "supporting and contradicting",
    )

    for status, required_field, message in (
        ("favored", "supportingEvidenceIds", "supporting evidence"),
        ("rejected", "contradictingEvidenceIds", "contradicting evidence"),
    ):
        unsupported_decision = copy.deepcopy(valid)
        unsupported_decision["hypotheses"][0]["status"] = status
        unsupported_decision["hypotheses"][0][required_field] = []
        expect_value_error(
            lambda case=unsupported_decision: validate_references(case),
            message,
        )

    duplicate_evidence = copy.deepcopy(valid)
    duplicate_evidence["evidence"].append(copy.deepcopy(valid["evidence"][0]))
    try:
        validate_references(duplicate_evidence)
    except ValueError as error:
        assert "duplicate evidence" in str(error)
    else:
        raise AssertionError("duplicate evidence IDs must fail domain validation")

    duplicate_recommendation = copy.deepcopy(valid)
    duplicate_recommendation["recommendations"].append(
        copy.deepcopy(valid["recommendations"][0])
    )
    try:
        validate_references(duplicate_recommendation)
    except ValueError as error:
        assert "duplicate recommendation" in str(error)
    else:
        raise AssertionError(
            "duplicate recommendation IDs must fail domain validation"
        )

    next_revision = next_revision_of(valid)
    next_revision["feedback"].append(
        {
            "feedbackId": "fb_0000000000000002",
            "actor": {
                "kind": "user",
                "id": "user-1",
                "displayName": "DBA reviewer",
            },
            "kind": "useful",
            "createdAt": "2026-08-31T10:00:02Z",
            "comment": "Validated in an isolated environment.",
            "recommendationId": "rec_0000000000000001",
        }
    )
    validator.validate(next_revision)
    validate_references(next_revision)
    validate_revision(valid, next_revision)

    mutated_revision = copy.deepcopy(next_revision)
    mutated_revision["evidence"][0]["summary"] = "Prior evidence was overwritten."
    expect_value_error(
        lambda: validate_revision(valid, mutated_revision), "evidence cannot mutate"
    )

    mutated_pin = copy.deepcopy(next_revision)
    mutated_pin["pinnedRevisions"]["policy"] = "policy/tampered"
    expect_value_error(
        lambda: validate_revision(valid, mutated_pin), "pinnedRevisions"
    )

    lower_case_z = next_revision_of(valid)
    lower_case_z["updatedAt"] = "2026-08-31T10:00:02z"
    validator.validate(lower_case_z)
    validate_revision(valid, lower_case_z)

    for collection in AUDIT_COLLECTIONS:
        for created_at in (
            "2026-08-31T09:59:59Z",
            "2026-08-31T10:00:03Z",
        ):
            outside_revision = next_revision_of(valid)
            if collection == "reviews":
                outside_revision[collection].append(
                    review_record(valid, "needs_changes", 2, created_at)
                )
            else:
                outside_revision[collection].append(
                    feedback_record(valid, "useful", 2, created_at)
                )
            expect_value_error(
                lambda case=outside_revision: validate_revision(valid, case),
                "createdAt",
            )

    for created_at in (
        "2026-08-31T09:59:59Z",
        "2026-08-31T10:00:02Z",
    ):
        invalid_initial_audit = copy.deepcopy(valid)
        invalid_initial_audit["reviews"][0]["createdAt"] = created_at
        expect_value_error(
            lambda case=invalid_initial_audit: validate_case_semantics(case),
            "createdAt",
        )

    unordered_audit = next_revision_of(valid)
    unordered_audit["updatedAt"] = "2026-08-31T10:00:03Z"
    unordered_audit["feedback"].extend(
        (
            feedback_record(valid, "useful", 2, "2026-08-31T10:00:02Z"),
            feedback_record(valid, "useful", 3, "2026-08-31T10:00:01.500Z"),
        )
    )
    expect_value_error(
        lambda: validate_revision(valid, unordered_audit), "createdAt"
    )

    illegal_workflow_transition = next_revision_of(valid)
    illegal_workflow_transition["workflowState"] = "queued"
    expect_value_error(
        lambda: validate_revision(valid, illegal_workflow_transition),
        "workflowState transition",
    )

    validated = case_for_outcome(valid, "validated_effective")
    illegal_terminal_transition = next_revision_of(validated)
    illegal_terminal_transition["outcome"] = "rolled_back"
    expect_value_error(
        lambda: validate_revision(validated, illegal_terminal_transition),
        "outcome transition",
    )

    for outcome, prerequisites in OUTCOME_PREREQUISITES.items():
        for collection, field, expected in prerequisites:
            missing_prerequisite = case_for_outcome(valid, outcome)
            missing_prerequisite[collection] = [
                record
                for record in missing_prerequisite[collection]
                if record[field] != expected
            ]
            expect_value_error(
                lambda case=missing_prerequisite: validate_case_semantics(case),
                expected,
            )

    insufficient_with_partial_classification = case_for_outcome(
        valid, "evidence_insufficient"
    )
    insufficient_with_partial_classification["evidenceCompleteness"][
        "classification"
    ] = "partial"
    expect_value_error(
        lambda: validate_case_semantics(insufficient_with_partial_classification),
        "insufficient completeness",
    )

    insufficient_without_missing = case_for_outcome(valid, "evidence_insufficient")
    insufficient_without_missing["evidenceCompleteness"]["missing"] = []
    expect_value_error(
        lambda: validate_case_semantics(insufficient_without_missing),
        "missing evidence",
    )

    insufficient_with_recommendation = case_for_outcome(
        valid, "evidence_insufficient"
    )
    insufficient_with_recommendation["recommendations"] = copy.deepcopy(
        valid["recommendations"]
    )
    expect_value_error(
        lambda: validate_case_semantics(insufficient_with_recommendation),
        "cannot contain recommendations",
    )

    unlinked_risk_acceptance = case_for_outcome(valid, "risk_accepted")
    unlinked_risk_acceptance["reviews"][0]["recommendationIds"] = []
    expect_value_error(
        lambda: validate_case_semantics(unlinked_risk_acceptance),
        "linked to recommendations",
    )

    dangling_risk_acceptance = case_for_outcome(valid, "risk_accepted")
    dangling_risk_acceptance["recommendations"] = []
    expect_value_error(
        lambda: validate_case_semantics(dangling_risk_acceptance),
        "linked to recommendations",
    )

    for outcome, feedback_kind in (
        ("validated_effective", "validated"),
        ("rolled_back", "rolled_back"),
    ):
        unlinked_feedback = case_for_outcome(valid, outcome)
        for feedback in unlinked_feedback["feedback"]:
            if feedback["kind"] == feedback_kind:
                feedback["recommendationId"] = None
        expect_value_error(
            lambda case=unlinked_feedback: validate_case_semantics(case),
            f"linked {feedback_kind}",
        )

        missing_effect_evidence = case_for_outcome(valid, outcome)
        effect_feedback = next(
            feedback
            for feedback in missing_effect_evidence["feedback"]
            if feedback["kind"] == feedback_kind
        )
        del effect_feedback["evidenceIds"]
        expect_value_error(
            lambda case=missing_effect_evidence: validate_case_semantics(case),
            "evidence",
        )

        empty_effect_evidence = case_for_outcome(valid, outcome)
        effect_feedback = next(
            feedback
            for feedback in empty_effect_evidence["feedback"]
            if feedback["kind"] == feedback_kind
        )
        effect_feedback["evidenceIds"] = []
        assert any(
            error.validator == "minItems"
            for error in validator.iter_errors(empty_effect_evidence)
        )
        expect_value_error(
            lambda case=empty_effect_evidence: validate_case_semantics(case),
            "evidence",
        )

        dangling_effect_evidence = case_for_outcome(valid, outcome)
        effect_feedback = next(
            feedback
            for feedback in dangling_effect_evidence["feedback"]
            if feedback["kind"] == feedback_kind
        )
        effect_feedback["evidenceIds"] = ["ev_ffffffffffffffff"]
        expect_value_error(
            lambda case=dangling_effect_evidence: validate_references(case),
            "unknown evidence",
        )

        wrong_effect_evidence = case_for_outcome(valid, outcome)
        effect_feedback = next(
            feedback
            for feedback in wrong_effect_evidence["feedback"]
            if feedback["kind"] == feedback_kind
        )
        effect_feedback["evidenceIds"] = [valid["evidence"][0]["evidenceId"]]
        expect_value_error(
            lambda case=wrong_effect_evidence: validate_case_semantics(case),
            "evidence",
        )

    cross_recommendation_chain = case_for_outcome(valid, "validated_effective")
    second_recommendation = copy.deepcopy(
        cross_recommendation_chain["recommendations"][0]
    )
    second_recommendation["recommendationId"] = "rec_0000000000000002"
    cross_recommendation_chain["recommendations"].append(second_recommendation)
    cross_recommendation_chain["feedback"][-1][
        "recommendationId"
    ] = second_recommendation["recommendationId"]
    expect_value_error(
        lambda: validate_case_semantics(cross_recommendation_chain),
        "same recommendation",
    )

    for scenario in (
        "approval_after_implementation",
        "evidence_before_implementation",
        "evidence_collected_before_observed",
    ):
        invalid_chain = case_for_outcome(valid, "validated_effective")
        result_evidence = next(
            evidence
            for evidence in invalid_chain["evidence"]
            if evidence["kind"] == "effect_metric_comparison"
        )
        if scenario == "approval_after_implementation":
            invalid_chain["reviews"][0][
                "createdAt"
            ] = "2026-08-31T10:00:00.250Z"
        elif scenario == "evidence_before_implementation":
            result_evidence["observedAt"] = "2026-08-31T10:00:00.150Z"
            result_evidence["collectedAt"] = "2026-08-31T10:00:00.160Z"
        else:
            result_evidence["observedAt"] = "2026-08-31T10:00:00.300Z"
            result_evidence["collectedAt"] = "2026-08-31T10:00:00.250Z"
        expect_value_error(
            lambda case=invalid_chain: validate_case_semantics(case),
            "causal order",
        )

    queued = case_for_outcome(valid, "pending")
    queued["workflowState"] = "queued"
    collecting_with_terminal_outcome = next_revision_of(queued)
    collecting_with_terminal_outcome["workflowState"] = "collecting"
    collecting_with_terminal_outcome["outcome"] = "risk_accepted"
    collecting_with_terminal_outcome["reviews"].append(
        review_record(valid, "risk_accepted", 1)
    )
    expect_value_error(
        lambda: validate_revision(queued, collecting_with_terminal_outcome),
        "ready workflowState",
    )

    for outcome in TERMINAL_OUTCOMES:
        previous = case_for_outcome(valid, outcome)
        previous["outcome"] = "pending"
        reused_trigger = next_revision_of(previous)
        reused_trigger["outcome"] = outcome
        _, _, expected = OUTCOME_TRIGGERS[outcome]
        expect_value_error(
            lambda old=previous, new=reused_trigger: validate_revision(old, new),
            f"qualifying new {expected}",
        )

    for outcome, trigger_kind in (
        ("validated_effective", "validated"),
        ("rolled_back", "rolled_back"),
    ):
        previous = case_for_outcome(valid, outcome)
        previous["outcome"] = "pending"
        unbound_trigger = next_revision_of(previous)
        unbound_trigger["outcome"] = outcome
        feedback = feedback_record(valid, trigger_kind, 99)
        feedback["recommendationId"] = None
        feedback.pop("evidenceIds", None)
        unbound_trigger["feedback"].append(feedback)
        expect_value_error(
            lambda old=previous, new=unbound_trigger: validate_revision(old, new),
            f"qualifying new {trigger_kind}",
        )

    previous = case_for_outcome(valid, "risk_accepted")
    previous["outcome"] = "pending"
    unbound_risk_acceptance = next_revision_of(previous)
    unbound_risk_acceptance["outcome"] = "risk_accepted"
    review = review_record(valid, "risk_accepted", 99)
    review["recommendationIds"] = []
    unbound_risk_acceptance["reviews"].append(review)
    expect_value_error(
        lambda: validate_revision(previous, unbound_risk_acceptance),
        "qualifying new risk_accepted",
    )

    for source, allowed_targets in WORKFLOW_TRANSITIONS.items():
        previous = case_for_outcome(valid, "pending")
        previous["workflowState"] = source
        for target in WORKFLOW_TRANSITIONS:
            current = next_revision_of(previous)
            current["workflowState"] = target
            if target in allowed_targets:
                validate_revision(previous, current)
                continue
            try:
                validate_revision(previous, current)
            except ValueError as error:
                assert "workflowState transition" in str(error)
            else:
                raise AssertionError(
                    f"forbidden workflow transition passed: {source} -> {target}"
                )

    for source, allowed_targets in OUTCOME_TRANSITIONS.items():
        for target in OUTCOME_TRANSITIONS:
            previous = case_for_outcome(valid, source)
            current = next_revision_of(previous)
            current["outcome"] = target
            if target not in allowed_targets:
                expect_value_error(
                    lambda old=previous, new=current: validate_revision(old, new),
                    "outcome transition",
                )
                continue

            if target != source:
                previous = pending_case_before_outcome(valid, target)
                current = next_revision_of(previous)
                current["outcome"] = target
                collection, field, expected = OUTCOME_TRIGGERS[target]
                ordinal = len(current[collection]) + 1
                target_case = case_for_outcome(valid, target)
                trigger = copy.deepcopy(
                    next(
                        record
                        for record in target_case[collection]
                        if record[field] == expected
                    )
                )
                id_field = "reviewId" if collection == "reviews" else "feedbackId"
                id_prefix = "rev" if collection == "reviews" else "fb"
                trigger[id_field] = f"{id_prefix}_{ordinal:016d}"
                trigger["createdAt"] = "2026-08-31T10:00:02Z"
                current[collection].append(trigger)
            validator.validate(current)
            validate_references(current)
            validate_revision(previous, current)

    print("contract fixtures passed")


if __name__ == "__main__":
    main()
