from __future__ import annotations

import copy
import json
import re
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
OUTCOME_TRANSITIONS = {
    "not_reviewed": {"not_reviewed", "accepted", "rejected"},
    "accepted": {"accepted", "rejected", "implemented"},
    "rejected": {"rejected", "accepted"},
    "implemented": {"implemented", "validated", "rolled_back"},
    "validated": {"validated", "rolled_back"},
    "rolled_back": {"rolled_back"},
}
OUTCOME_PREREQUISITES = {
    "accepted": (("reviews", "decision", "approved"),),
    "rejected": (("reviews", "decision", "rejected"),),
    "implemented": (
        ("reviews", "decision", "approved"),
        ("feedback", "kind", "implemented"),
    ),
    "validated": (
        ("reviews", "decision", "approved"),
        ("feedback", "kind", "implemented"),
        ("feedback", "kind", "validated"),
    ),
    "rolled_back": (
        ("reviews", "decision", "approved"),
        ("feedback", "kind", "implemented"),
        ("feedback", "kind", "rolled_back"),
    ),
}
OUTCOME_TRIGGERS = {
    "accepted": ("reviews", "decision", "approved"),
    "rejected": ("reviews", "decision", "rejected"),
    "implemented": ("feedback", "kind", "implemented"),
    "validated": ("feedback", "kind", "validated"),
    "rolled_back": ("feedback", "kind", "rolled_back"),
}


# jsonschema only registers date-time when its optional validator is installed.
@FORMAT_CHECKER.checks("date-time", raises=ValueError)
def is_rfc3339_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return True

    match = RFC3339_DATETIME.fullmatch(value)
    if match is None:
        return False

    normalized = value[:10] + "T" + value[11:]
    if match.group("second") == "60":
        normalized = normalized[:17] + "59" + normalized[19:]
    if normalized[-1] in {"Z", "z"}:
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized).tzinfo is not None


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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


def case_for_outcome(valid: dict[str, Any], outcome: str) -> dict[str, Any]:
    case = copy.deepcopy(valid)
    case["workflowState"] = "ready"
    case["outcome"] = outcome
    case["reviews"] = []
    case["feedback"] = []

    if outcome == "rejected":
        case["reviews"].append(
            review_record(valid, "rejected", 1, "2026-08-31T10:00:01Z")
        )
    elif outcome != "not_reviewed":
        case["reviews"].append(
            review_record(valid, "approved", 1, "2026-08-31T10:00:01Z")
        )

    if outcome in {"implemented", "validated", "rolled_back"}:
        case["feedback"].append(
            feedback_record(valid, "implemented", 1, "2026-08-31T10:00:01Z")
        )
    if outcome == "validated":
        case["feedback"].append(
            feedback_record(valid, "validated", 2, "2026-08-31T10:00:01Z")
        )
    elif outcome == "rolled_back":
        case["feedback"].append(
            feedback_record(valid, "rolled_back", 2, "2026-08-31T10:00:01Z")
        )
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
        referenced = set(hypothesis["supportingEvidenceIds"])
        referenced.update(hypothesis["contradictingEvidenceIds"])
        missing = referenced - evidence_ids
        if missing:
            raise ValueError(f"hypothesis has unknown evidence IDs: {sorted(missing)}")

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


def require_unique_ids(
    records: list[dict[str, Any]], key: str, label: str
) -> set[str]:
    identifiers = [record[key] for record in records]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError(f"duplicate {label} ID")
    return set(identifiers)


def validate_case_semantics(case: dict[str, Any]) -> None:
    outcome = case["outcome"]
    if outcome != "not_reviewed" and case["workflowState"] != "ready":
        raise ValueError(f"{outcome} outcome requires ready workflowState")

    for collection, field, expected in OUTCOME_PREREQUISITES.get(outcome, ()):
        if not any(record[field] == expected for record in case[collection]):
            label = "review" if collection == "reviews" else "feedback"
            raise ValueError(f"{outcome} outcome requires {expected} {label}")


def validate_revision(previous: dict[str, Any], current: dict[str, Any]) -> None:
    if current["revision"] != previous["revision"] + 1:
        raise ValueError("revision must increase by exactly one")

    previous_workflow = previous["workflowState"]
    current_workflow = current["workflowState"]
    if current_workflow not in WORKFLOW_TRANSITIONS[previous_workflow]:
        raise ValueError(
            f"illegal workflowState transition: {previous_workflow} -> {current_workflow}"
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

    previous_time = datetime.fromisoformat(previous["updatedAt"].replace("Z", "+00:00"))
    current_time = datetime.fromisoformat(current["updatedAt"].replace("Z", "+00:00"))
    if current_time <= previous_time:
        raise ValueError("updatedAt must increase across revisions")

    for field in APPEND_ONLY_COLLECTIONS:
        previous_items = previous[field]
        if current[field][: len(previous_items)] != previous_items:
            raise ValueError(f"{field} cannot mutate or remove prior records")

    validate_case_semantics(previous)
    validate_case_semantics(current)

    if current_outcome != previous_outcome:
        collection, field, expected = OUTCOME_TRIGGERS[current_outcome]
        new_records = current[collection][len(previous[collection]) :]
        if not any(record[field] == expected for record in new_records):
            label = "review" if collection == "reviews" else "feedback"
            raise ValueError(
                f"{previous_outcome} -> {current_outcome} requires a new "
                f"{expected} {label}"
            )


def main() -> None:
    schema = load_json(ROOT / "diagnosis-case-v1.schema.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)

    workflow_states = set(schema["properties"]["workflowState"]["enum"])
    outcome_states = set(schema["properties"]["outcome"]["enum"])
    assert set(WORKFLOW_TRANSITIONS) == workflow_states
    assert set().union(*WORKFLOW_TRANSITIONS.values()) == workflow_states
    assert set(OUTCOME_TRANSITIONS) == outcome_states
    assert set().union(*OUTCOME_TRANSITIONS.values()) == outcome_states
    assert set(OUTCOME_PREREQUISITES) == outcome_states - {"not_reviewed"}
    assert set(OUTCOME_TRIGGERS) == outcome_states - {"not_reviewed"}

    valid = load_json(EXAMPLES / "diagnosis-case-v1.valid.json")
    validator.validate(valid)
    validate_references(valid)
    validate_case_semantics(valid)

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
    try:
        validate_revision(valid, mutated_revision)
    except ValueError:
        pass
    else:
        raise AssertionError("mutating prior records must fail revision validation")

    mutated_pin = copy.deepcopy(next_revision)
    mutated_pin["pinnedRevisions"]["policy"] = "policy/tampered"
    try:
        validate_revision(valid, mutated_pin)
    except ValueError as error:
        assert "pinnedRevisions" in str(error)
    else:
        raise AssertionError("pinned revisions must be immutable")

    illegal_workflow_transition = next_revision_of(valid)
    illegal_workflow_transition["workflowState"] = "queued"
    try:
        validate_revision(valid, illegal_workflow_transition)
    except ValueError as error:
        assert "workflowState transition" in str(error)
    else:
        raise AssertionError("ready -> queued workflow transition must fail")

    not_reviewed = copy.deepcopy(valid)
    not_reviewed["outcome"] = "not_reviewed"
    not_reviewed["reviews"] = []
    not_reviewed["feedback"] = []
    illegal_outcome_transition = next_revision_of(not_reviewed)
    illegal_outcome_transition["outcome"] = "validated"
    try:
        validate_revision(not_reviewed, illegal_outcome_transition)
    except ValueError as error:
        assert "outcome transition" in str(error)
    else:
        raise AssertionError("not_reviewed -> validated outcome transition must fail")

    accepted_without_review = next_revision_of(not_reviewed)
    accepted_without_review["outcome"] = "accepted"
    try:
        validate_revision(not_reviewed, accepted_without_review)
    except ValueError as error:
        assert "approved review" in str(error)
    else:
        raise AssertionError("acceptance without a new approved review must fail")

    implemented_without_feedback = next_revision_of(valid)
    implemented_without_feedback["outcome"] = "implemented"
    try:
        validate_revision(valid, implemented_without_feedback)
    except ValueError as error:
        assert "implemented feedback" in str(error)
    else:
        raise AssertionError("implementation without new feedback must fail")

    queued = copy.deepcopy(not_reviewed)
    queued["workflowState"] = "queued"
    collecting_accepted = next_revision_of(queued)
    collecting_accepted["workflowState"] = "collecting"
    collecting_accepted["outcome"] = "accepted"
    collecting_accepted["reviews"].append(copy.deepcopy(valid["reviews"][0]))
    try:
        validate_revision(queued, collecting_accepted)
    except ValueError as error:
        assert "ready workflowState" in str(error)
    else:
        raise AssertionError("non-ready workflow cannot have a reviewed outcome")

    for outcome, prerequisites in OUTCOME_PREREQUISITES.items():
        for collection, field, expected in prerequisites:
            missing_prerequisite = case_for_outcome(valid, outcome)
            missing_prerequisite[collection] = [
                record
                for record in missing_prerequisite[collection]
                if record[field] != expected
            ]
            try:
                validate_case_semantics(missing_prerequisite)
            except ValueError as error:
                assert expected in str(error)
            else:
                raise AssertionError(
                    f"{outcome} without {expected} {collection} must fail"
                )

    for source, allowed_targets in OUTCOME_TRANSITIONS.items():
        for target in allowed_targets - {source}:
            previous = case_for_outcome(valid, source)
            collection, field, expected = OUTCOME_TRIGGERS[target]
            ordinal = len(previous[collection]) + 1
            if collection == "reviews":
                previous[collection].append(
                    review_record(
                        valid, expected, ordinal, "2026-08-31T10:00:01Z"
                    )
                )
            else:
                previous[collection].append(
                    feedback_record(
                        valid, expected, ordinal, "2026-08-31T10:00:01Z"
                    )
                )

            reused_trigger = next_revision_of(previous)
            reused_trigger["outcome"] = target
            try:
                validate_revision(previous, reused_trigger)
            except ValueError as error:
                assert f"new {expected}" in str(error)
            else:
                raise AssertionError(
                    f"old {expected} record triggered {source} -> {target}"
                )

    for source, allowed_targets in WORKFLOW_TRANSITIONS.items():
        previous = case_for_outcome(valid, "not_reviewed")
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
        previous = case_for_outcome(valid, source)
        for target in OUTCOME_TRANSITIONS:
            current = next_revision_of(previous)
            current["outcome"] = target
            if target not in allowed_targets:
                try:
                    validate_revision(previous, current)
                except ValueError as error:
                    assert "outcome transition" in str(error)
                else:
                    raise AssertionError(
                        f"forbidden outcome transition passed: {source} -> {target}"
                    )
                continue

            if target != source:
                collection, field, expected = OUTCOME_TRIGGERS[target]
                ordinal = len(current[collection]) + 1
                if collection == "reviews":
                    current[collection].append(review_record(valid, expected, ordinal))
                else:
                    current[collection].append(
                        feedback_record(valid, expected, ordinal)
                    )
            validate_revision(previous, current)

    print("contract fixtures passed")


if __name__ == "__main__":
    main()
