from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).parent
EXAMPLES = ROOT / "examples"
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
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_references(case: dict[str, Any]) -> None:
    evidence_ids = {item["evidenceId"] for item in case["evidence"]}
    recommendation_ids = {
        item["recommendationId"] for item in case["recommendations"]
    }

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


def validate_revision(previous: dict[str, Any], current: dict[str, Any]) -> None:
    if current["revision"] != previous["revision"] + 1:
        raise ValueError("revision must increase by exactly one")

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


def main() -> None:
    schema = load_json(ROOT / "diagnosis-case-v1.schema.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    valid = load_json(EXAMPLES / "diagnosis-case-v1.valid.json")
    validator.validate(valid)
    validate_references(valid)

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

    next_revision = copy.deepcopy(valid)
    next_revision["revision"] = 2
    next_revision["updatedAt"] = "2026-08-31T10:00:02Z"
    next_revision["feedback"].append(
        {
            "feedbackId": "fb_0000000000000002",
            "actor": {
                "kind": "user",
                "id": "user-1",
                "displayName": "DBA reviewer",
            },
            "kind": "validated",
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

    print("contract fixtures passed")


if __name__ == "__main__":
    main()
