from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIR = ROOT / "docs" / "contracts"


def load_validator_module():
    path = CONTRACT_DIR / "validate_examples.py"
    spec = importlib.util.spec_from_file_location("diagnosis_contract_validator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load contract validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class DiagnosisCaseContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validation = load_validator_module()
        schema = load_json(CONTRACT_DIR / "diagnosis-case-v1.schema.json")
        cls.validator = Draft202012Validator(schema)
        cls.valid = load_json(
            CONTRACT_DIR / "examples" / "diagnosis-case-v1.valid.json"
        )

    def test_recommendation_requires_at_least_one_provenance_evidence_id(self) -> None:
        case = copy.deepcopy(self.valid)
        case["recommendations"][0]["evidenceIds"] = []

        with self.assertRaises(ValidationError):
            self.validator.validate(case)

    def test_all_pinned_revision_fields_are_explicit_even_when_null(self) -> None:
        required = {"provider", "model", "modelArtifact", "prompt"}

        for field in required:
            with self.subTest(field=field):
                case = copy.deepcopy(self.valid)
                del case["pinnedRevisions"][field]
                with self.assertRaises(ValidationError):
                    self.validator.validate(case)

    def test_duplicate_evidence_ids_fail_domain_validation(self) -> None:
        case = copy.deepcopy(self.valid)
        duplicate = copy.deepcopy(case["evidence"][0])
        duplicate["summary"] = "A second record reuses the same stable identifier."
        case["evidence"].append(duplicate)

        with self.assertRaisesRegex(ValueError, "duplicate evidence"):
            self.validation.validate_references(case)

    def test_duplicate_recommendation_ids_fail_domain_validation(self) -> None:
        case = copy.deepcopy(self.valid)
        duplicate = copy.deepcopy(case["recommendations"][0])
        duplicate["title"] = "A second recommendation reuses the same identifier"
        case["recommendations"].append(duplicate)

        with self.assertRaisesRegex(ValueError, "duplicate recommendation"):
            self.validation.validate_references(case)

    def test_pinned_revisions_are_immutable_across_case_revisions(self) -> None:
        current = copy.deepcopy(self.valid)
        current["revision"] = 2
        current["updatedAt"] = "2026-08-31T10:00:02Z"
        current["pinnedRevisions"]["policy"] = "policy/tampered"

        with self.assertRaisesRegex(ValueError, "pinnedRevisions"):
            self.validation.validate_revision(self.valid, current)

    def test_ready_case_cannot_transition_back_to_queued(self) -> None:
        current = copy.deepcopy(self.valid)
        current["revision"] = 2
        current["updatedAt"] = "2026-08-31T10:00:02Z"
        current["workflowState"] = "queued"

        with self.assertRaisesRegex(ValueError, "workflowState"):
            self.validation.validate_revision(self.valid, current)

    def test_contract_command_rejects_a_malformed_review_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            copied_contracts = Path(temp_dir) / "contracts"
            shutil.copytree(CONTRACT_DIR, copied_contracts)
            valid_path = (
                copied_contracts / "examples" / "diagnosis-case-v1.valid.json"
            )
            case = load_json(valid_path)
            case["reviews"][0]["createdAt"] = "not-a-date"
            valid_path.write_text(json.dumps(case), encoding="utf-8")

            completed = subprocess.run(
                [sys.executable, str(copied_contracts / "validate_examples.py")],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(
            completed.returncode,
            0,
            "contract validation accepted an invalid date-time",
        )

    def test_outcome_contract_can_represent_all_approved_terminal_states(self) -> None:
        schema = load_json(CONTRACT_DIR / "diagnosis-case-v1.schema.json")
        outcome_schema = schema["properties"]["outcome"]
        actual = set(outcome_schema["enum"])
        legacy_read_only = set(outcome_schema.get("x-legacyReadOnlyValues", []))
        legacy_read_only.update(
            outcome_schema.get("x-legacyDraftAliases", {}).keys()
        )
        required = {
            "validated_effective",
            "rolled_back",
            "evidence_insufficient",
            "risk_accepted",
        }
        process_only = {"accepted", "rejected", "implemented", "validated"}
        missing = required - actual
        unclassified_process_states = (process_only & actual) - legacy_read_only
        transition_targets = set().union(
            *self.validation.OUTCOME_TRANSITIONS.values()
        )
        writable_legacy_states = legacy_read_only & transition_targets

        self.assertFalse(
            missing or unclassified_process_states or writable_legacy_states,
            "DiagnosisCase outcome does not match the approved business-result "
            f"boundary: missing={sorted(missing)}, "
            f"unclassified_process_states={sorted(unclassified_process_states)}, "
            f"writable_legacy_states={sorted(writable_legacy_states)}",
        )

    def test_effect_outcomes_have_a_machine_validated_evidence_binding(self) -> None:
        schema = load_json(CONTRACT_DIR / "diagnosis-case-v1.schema.json")
        case_properties = schema["properties"]
        feedback_properties = schema["$defs"]["feedback"]["properties"]
        binding_sites = {
            "case.outcomeEvidenceIds": "outcomeEvidenceIds" in case_properties,
            "feedback.evidenceIds": "evidenceIds" in feedback_properties,
        }

        self.assertTrue(
            any(binding_sites.values()),
            "validated-effective and rolled-back outcomes have no field that "
            f"can bind the result to evidence: {binding_sites}",
        )

        case = copy.deepcopy(self.valid)
        case["outcome"] = "validated_effective"
        implemented = copy.deepcopy(self.valid["feedback"][0])
        implemented["feedbackId"] = "fb_0000000000000002"
        implemented["kind"] = "implemented"
        validated = copy.deepcopy(self.valid["feedback"][0])
        validated["feedbackId"] = "fb_0000000000000003"
        validated["kind"] = "validated"
        case["feedback"] = [implemented, validated]

        with self.assertRaisesRegex(ValueError, "evidence"):
            self.validation.validate_references(case)
            self.validation.validate_case_semantics(case)

    def test_effect_outcome_rejects_dangling_evidence_binding(self) -> None:
        case = copy.deepcopy(self.valid)
        case["outcome"] = "validated_effective"
        implemented = copy.deepcopy(self.valid["feedback"][0])
        implemented["feedbackId"] = "fb_0000000000000002"
        implemented["kind"] = "implemented"
        validated = copy.deepcopy(self.valid["feedback"][0])
        validated["feedbackId"] = "fb_0000000000000003"
        validated["kind"] = "validated"
        validated["evidenceIds"] = ["ev_ffffffffffffffff"]
        case["feedback"] = [implemented, validated]

        with self.assertRaisesRegex(ValueError, "evidence"):
            self.validation.validate_references(case)

    def test_effect_outcome_events_must_reference_the_same_recommendation(self) -> None:
        case = copy.deepcopy(self.valid)
        case["outcome"] = "validated_effective"
        second_recommendation = copy.deepcopy(case["recommendations"][0])
        second_recommendation["recommendationId"] = "rec_0000000000000002"
        case["recommendations"].append(second_recommendation)

        implemented = copy.deepcopy(self.valid["feedback"][0])
        implemented["feedbackId"] = "fb_0000000000000002"
        implemented["kind"] = "implemented"
        implemented["createdAt"] = "2026-08-31T10:00:00.500Z"
        implemented["recommendationId"] = "rec_0000000000000001"

        effect_evidence = copy.deepcopy(self.valid["evidence"][0])
        effect_evidence["evidenceId"] = "ev_0000000000000002"
        effect_evidence["kind"] = "effect_metric_comparison"
        effect_evidence["observedAt"] = "2026-08-31T10:00:00.600Z"
        effect_evidence["collectedAt"] = "2026-08-31T10:00:00.700Z"
        case["evidence"].append(effect_evidence)

        validated = copy.deepcopy(self.valid["feedback"][0])
        validated["feedbackId"] = "fb_0000000000000003"
        validated["kind"] = "validated"
        validated["createdAt"] = "2026-08-31T10:00:00.800Z"
        validated["recommendationId"] = "rec_0000000000000002"
        validated["evidenceIds"] = [effect_evidence["evidenceId"]]
        case["feedback"] = [implemented, validated]

        with self.assertRaisesRegex(ValueError, "recommendation|same"):
            self.validation.validate_references(case)
            self.validation.validate_case_semantics(case)

    def test_effect_outcome_enforces_approval_and_evidence_causal_order(self) -> None:
        for scenario in (
            "approval_after_implementation",
            "evidence_before_implementation",
            "evidence_collected_before_observed",
        ):
            with self.subTest(scenario=scenario):
                case = copy.deepcopy(self.valid)
                case["outcome"] = "validated_effective"
                case["reviews"][0]["createdAt"] = (
                    "2026-08-31T10:00:00.900Z"
                    if scenario == "approval_after_implementation"
                    else "2026-08-31T10:00:00.200Z"
                )

                implemented = copy.deepcopy(self.valid["feedback"][0])
                implemented["feedbackId"] = "fb_0000000000000002"
                implemented["kind"] = "implemented"
                implemented["createdAt"] = "2026-08-31T10:00:00.500Z"

                effect_evidence = copy.deepcopy(self.valid["evidence"][0])
                effect_evidence["evidenceId"] = "ev_0000000000000002"
                effect_evidence["kind"] = "effect_metric_comparison"
                if scenario == "evidence_before_implementation":
                    effect_evidence["observedAt"] = "2026-08-31T10:00:00.300Z"
                    effect_evidence["collectedAt"] = "2026-08-31T10:00:00.400Z"
                elif scenario == "evidence_collected_before_observed":
                    effect_evidence["observedAt"] = "2026-08-31T10:00:00.700Z"
                    effect_evidence["collectedAt"] = "2026-08-31T10:00:00.600Z"
                else:
                    effect_evidence["observedAt"] = "2026-08-31T10:00:00.600Z"
                    effect_evidence["collectedAt"] = "2026-08-31T10:00:00.700Z"
                case["evidence"].append(effect_evidence)

                validated = copy.deepcopy(self.valid["feedback"][0])
                validated["feedbackId"] = "fb_0000000000000003"
                validated["kind"] = "validated"
                validated["createdAt"] = "2026-08-31T10:00:00.800Z"
                validated["evidenceIds"] = [effect_evidence["evidenceId"]]
                case["feedback"] = [implemented, validated]

                with self.assertRaisesRegex(
                    ValueError, "approval|implemented|evidence|order"
                ):
                    self.validation.validate_references(case)
                    self.validation.validate_case_semantics(case)

    def test_one_evidence_item_cannot_both_support_and_contradict_a_hypothesis(
        self,
    ) -> None:
        case = copy.deepcopy(self.valid)
        evidence_id = case["hypotheses"][0]["supportingEvidenceIds"][0]
        case["hypotheses"][0]["contradictingEvidenceIds"] = [evidence_id]

        with self.assertRaisesRegex(ValueError, "supporting|contradicting|overlap"):
            self.validation.validate_references(case)

    def test_new_audit_records_must_fall_inside_the_revision_time_window(self) -> None:
        for created_at in (
            "2026-08-31T09:59:59Z",
            "2026-08-31T10:00:03Z",
        ):
            with self.subTest(created_at=created_at):
                current = copy.deepcopy(self.valid)
                current["revision"] = 2
                current["updatedAt"] = "2026-08-31T10:00:02Z"
                feedback = copy.deepcopy(self.valid["feedback"][0])
                feedback["feedbackId"] = "fb_0000000000000002"
                feedback["createdAt"] = created_at
                current["feedback"].append(feedback)

                with self.assertRaisesRegex(ValueError, "createdAt"):
                    self.validation.validate_revision(self.valid, current)

    def test_initial_audit_records_must_fall_inside_the_case_time_window(self) -> None:
        for created_at in (
            "2026-08-31T09:59:59Z",
            "2026-08-31T10:00:02Z",
        ):
            with self.subTest(created_at=created_at):
                case = copy.deepcopy(self.valid)
                case["reviews"][0]["createdAt"] = created_at

                with self.assertRaisesRegex(ValueError, "createdAt"):
                    self.validation.validate_case_semantics(case)

    def test_new_audit_records_are_chronologically_ordered(self) -> None:
        current = copy.deepcopy(self.valid)
        current["revision"] = 2
        current["updatedAt"] = "2026-08-31T10:00:03Z"
        later = copy.deepcopy(self.valid["feedback"][0])
        later["feedbackId"] = "fb_0000000000000002"
        later["createdAt"] = "2026-08-31T10:00:02Z"
        earlier = copy.deepcopy(self.valid["feedback"][0])
        earlier["feedbackId"] = "fb_0000000000000003"
        earlier["createdAt"] = "2026-08-31T10:00:01.500Z"
        current["feedback"].extend((later, earlier))

        with self.assertRaisesRegex(ValueError, "createdAt|order"):
            self.validation.validate_revision(self.valid, current)

    def test_schema_valid_lowercase_z_is_compatible_with_revision_validation(
        self,
    ) -> None:
        current = copy.deepcopy(self.valid)
        current["revision"] = 2
        current["updatedAt"] = "2026-08-31T10:00:02z"

        self.assertTrue(
            self.validation.FORMAT_CHECKER.conforms(
                current["updatedAt"], "date-time"
            )
        )
        try:
            self.validation.validate_revision(self.valid, current)
        except ValueError as error:
            self.fail(f"schema-valid date-time failed revision validation: {error}")


if __name__ == "__main__":
    unittest.main()
