from __future__ import annotations

import copy
import math
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

CONTRACTS = Path(__file__).parent
sys.path.insert(0, str(CONTRACTS))

import validate_vnext_examples as contracts
from vnext_canonical_json import canonical_json_bytes, canonical_sha256
from vnext_diagnosis_policy import (
    DIAGNOSIS_DEPENDENCY_REGISTRY,
    RULE_PACK_BY_VERSION_FAMILY,
    RULE_POLICY_REGISTRY,
    derive_completeness,
    derive_evidence_level,
    expected_rule_findings,
    validate_gap_fact,
    validate_policy_pins,
)
from vnext_outcome_policy import (
    ACTION_RESULT_POLICY,
    _measurement_passes,
    validate_outcome_policy,
)
from vnext_source_ledger import replay_source_history


class CanonicalJsonTests(unittest.TestCase):
    def test_orders_keys_and_uses_integer_base_units(self) -> None:
        self.assertEqual(
            canonical_json_bytes({"中": 2, "a": 1}), b'{"a":1,"\xe4\xb8\xad":2}'
        )
        self.assertEqual(
            canonical_sha256({"b": [True, None], "a": 1}),
            canonical_sha256({"a": 1, "b": [True, None]}),
        )

    def test_rejects_non_finite_or_fractional_typed_numbers(self) -> None:
        for value in (math.nan, math.inf, -math.inf, 1.5, 9_007_199_254_740_992):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                canonical_json_bytes({"measurement": value})

    def test_json_ingress_rejects_nested_duplicate_object_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"typed":{"kind":"attacker","kind":"slow_query"}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON object member"):
                contracts.load(path)


class DiagnosisPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = contracts.load(contracts.EXAMPLES / "diagnosis-case-v2.valid.json")

    def test_fixture_rule_is_a_deterministic_registry_projection(self) -> None:
        facts = {item["factId"]: item for item in self.case["facts"]}
        evidence = {item["evidenceId"]: item for item in self.case["evidence"]}
        self.assertEqual(
            expected_rule_findings(
                self.case["pinnedRevisions"]["rulePack"],
                self.case["decision"],
                facts,
                evidence,
            ),
            self.case["ruleFindings"],
        )
        self.assertEqual(
            derive_evidence_level(
                self.case["evidence"], set(self.case["facts"][0]["evidenceIds"])
            ),
            "E3",
        )
        self.assertEqual(
            derive_completeness(self.case["decision"], facts, evidence), 100
        )

    def test_low_signal_profile_cannot_hit_index_bottleneck_rule(self) -> None:
        case = copy.deepcopy(self.case)
        case["facts"][0]["params"].update(
            {
                "windowMinutes": 1440,
                "callCount": 1,
                "p95Ms": 1,
                "averageScanRows": 1,
                "averageReturnRows": 1,
            }
        )
        facts = {item["factId"]: item for item in case["facts"]}
        evidence = {item["evidenceId"]: item for item in case["evidence"]}
        finding = expected_rule_findings(
            case["pinnedRevisions"]["rulePack"],
            case["decision"],
            facts,
            evidence,
        )[0]
        self.assertEqual(finding["status"], "not_applicable")
        self.assertEqual(finding["severity"], "info")

    def test_quality_policy_derives_level_and_completeness(self) -> None:
        case = copy.deepcopy(self.case)
        case["evidence"][0].update({"freshness": "stale", "coverage": 0})
        case["evidence"][0]["payload"].update({"recordCount": 0, "truncated": True})
        case["evidence"][0]["collection"]["status"] = "truncated"
        case["evidence"][0]["collection"]["budget"]["rowsRead"] = 0
        facts = {item["factId"]: item for item in case["facts"]}
        evidence = {item["evidenceId"]: item for item in case["evidence"]}
        self.assertEqual(
            derive_evidence_level(
                case["evidence"], set(case["facts"][0]["evidenceIds"])
            ),
            "E2",
        )
        self.assertEqual(derive_completeness(case["decision"], facts, evidence), 67)

    def test_irrelevant_evidence_cannot_raise_the_case_ceiling(self) -> None:
        runtime_case = contracts.load(
            contracts.EXAMPLES / "diagnosis-case-v2.runtime-correlation.valid.json"
        )
        case = copy.deepcopy(self.case)
        case["evidence"].extend(runtime_case["evidence"][:3])
        self.assertEqual(
            derive_evidence_level(
                case["evidence"], set(case["facts"][0]["evidenceIds"])
            ),
            "E3",
        )

    def test_database_version_selects_the_only_allowed_rule_pack(self) -> None:
        case = copy.deepcopy(self.case)
        case["pinnedRevisions"]["rulePack"] = "attacker-rules/v999"
        with self.assertRaises(ValueError):
            validate_policy_pins(case)

        case = copy.deepcopy(self.case)
        case["sourceSnapshots"][0]["product"] = "tidb"
        with self.assertRaises(ValueError):
            validate_policy_pins(case)

    def test_each_supported_database_pack_covers_each_p0_diagnosis(self) -> None:
        required_rules = {
            rule_id
            for decision in DIAGNOSIS_DEPENDENCY_REGISTRY.values()
            for rule_id in decision["rules"]
        }
        for family, pack_revision in RULE_PACK_BY_VERSION_FAMILY.items():
            with self.subTest(family=family):
                self.assertLessEqual(
                    required_rules,
                    set(RULE_POLICY_REGISTRY[pack_revision]),
                )

    def test_incomplete_evidence_has_an_actionless_terminal_representation(
        self,
    ) -> None:
        pending, terminal = contracts.build_evidence_insufficient_cases(self.case)
        validator = contracts.schema_validator("diagnosis-case-v2.schema.json")
        for candidate in (pending, terminal):
            validator.validate(candidate)
            contracts.validate_case_references(candidate)

        contracts.validate_case_transition(pending, terminal)
        self.assertEqual(pending["evidenceLevel"], "E2")
        self.assertEqual(pending["evidenceCompleteness"], 67)
        self.assertEqual(
            pending["decision"]["templateId"], "decision.evidence_insufficient"
        )
        self.assertEqual(pending["ruleFindings"], [])
        self.assertEqual(pending["actions"], [])
        self.assertEqual(terminal["outcome"], "evidence_insufficient")

    def test_evidence_gap_fact_ids_are_an_exact_role_projection(self) -> None:
        pending, _ = contracts.build_evidence_insufficient_cases(self.case)
        pending["facts"][0]["evidenceIds"] = pending["facts"][0]["evidenceIds"][:-1]
        with self.assertRaisesRegex(ValueError, "role projection"):
            contracts.validate_case_references(pending)

    def test_evidence_gap_cannot_ignore_a_matching_case_candidate(self) -> None:
        pending, _ = contracts.build_evidence_insufficient_cases(self.case)
        fact = pending["facts"][0]
        plan_role = next(
            item
            for item in fact["params"]["roleAssessments"]
            if item["role"] == "planEvidenceId"
        )
        plan_evidence_id = plan_role["evidenceId"]
        plan_role.update(
            {
                "evidenceId": None,
                "eligible": False,
                "reasonCodes": ["MISSING_EVIDENCE"],
            }
        )
        fact["evidenceIds"].remove(plan_evidence_id)
        evidence = {item["evidenceId"]: item for item in pending["evidence"]}

        with self.assertRaisesRegex(ValueError, "matching Evidence candidate"):
            validate_gap_fact(fact, evidence)


class OutcomePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        case = contracts.load(contracts.EXAMPLES / "diagnosis-case-v2.valid.json")
        self.case = contracts.build_validated_case(case)

    def test_accepts_one_authorized_causal_tuple(self) -> None:
        validate_outcome_policy(
            self.case,
            contracts.parse_time,
            contracts.resolve_authorization_audit,
        )

    def test_each_supported_action_has_a_complete_result_policy(self) -> None:
        action_templates = {
            template
            for diagnosis in DIAGNOSIS_DEPENDENCY_REGISTRY.values()
            for template in diagnosis["actions"]
        }
        self.assertLessEqual(action_templates, set(ACTION_RESULT_POLICY))
        for template in action_templates:
            with self.subTest(template=template):
                policy = ACTION_RESULT_POLICY[template]
                metric_codes = [item["metricCode"] for item in policy]
                self.assertTrue(metric_codes)
                self.assertEqual(len(metric_codes), len(set(metric_codes)))

    def test_recomputes_effect_instead_of_trusting_persisted_claims(self) -> None:
        case = copy.deepcopy(self.case)
        effect = next(
            item
            for item in case["evidence"]
            if item["kind"] == "effect_metric_comparison"
            and item["payload"]["typed"]["metricCode"] == "p95_latency_ms"
        )
        effect["payload"]["typed"].update(
            {"baselineValue": 100, "observedValue": 999_999}
        )
        with self.assertRaisesRegex(ValueError, "measurement policy"):
            validate_outcome_policy(
                case,
                contracts.parse_time,
                contracts.resolve_authorization_audit,
            )

    def test_strict_below_action_targets_reject_equal_measurements(self) -> None:
        index_policy = ACTION_RESULT_POLICY[("action.index_candidate_isolated", "v1")]
        statistics_policy = ACTION_RESULT_POLICY[
            ("action.statistics_refresh_isolated", "v1")
        ]
        action = {
            "params": {
                "maxP95Ms": 500,
                "maxEstimateRatio": 10,
            }
        }

        self.assertFalse(
            _measurement_passes(
                {"baselineValue": 2_800, "observedValue": 500},
                index_policy[1],
                action,
            )
        )
        self.assertFalse(
            _measurement_passes(
                {"baselineValue": 200_000, "observedValue": 100_000},
                statistics_policy[0],
                action,
            )
        )

    def test_rejects_incomplete_action_measurement_set(self) -> None:
        case = copy.deepcopy(self.case)
        missing_id = case["transitionEvents"][-1]["evidenceIds"][-1]
        remaining_ids = [
            evidence_id
            for evidence_id in case["transitionEvents"][-1]["evidenceIds"]
            if evidence_id != missing_id
        ]
        case["transitionEvents"][-1]["evidenceIds"] = remaining_ids
        case["transitionEvents"][-1]["outcomeTuple"]["resultEvidenceIds"] = (
            remaining_ids
        )
        case["feedback"][-1]["evidenceIds"] = remaining_ids
        with self.assertRaisesRegex(ValueError, "complete Action measurement"):
            validate_outcome_policy(
                case,
                contracts.parse_time,
                contracts.resolve_authorization_audit,
            )

    def test_rejects_ineligible_terminal_evidence(self) -> None:
        case = copy.deepcopy(self.case)
        effect = next(
            item
            for item in case["evidence"]
            if item["kind"] == "effect_metric_comparison"
        )
        effect["coverage"] = 0
        with self.assertRaises(ValueError):
            validate_outcome_policy(
                case,
                contracts.parse_time,
                contracts.resolve_authorization_audit,
            )

    def test_rejects_unattested_terminal_event(self) -> None:
        case = copy.deepcopy(self.case)
        event = next(
            item for item in case["transitionEvents"] if item["type"] == "outcome"
        )
        event["actor"] = {
            "kind": "system",
            "id": "outcome-worker",
            "displayName": "Outcome worker",
        }
        with self.assertRaises(ValueError):
            validate_outcome_policy(
                case,
                contracts.parse_time,
                contracts.resolve_authorization_audit,
            )

    def test_rejects_mutated_authorization_snapshot(self) -> None:
        case = copy.deepcopy(self.case)
        case["reviews"][0]["authorizationSnapshot"]["auditRecordId"] = (
            "authz_0000000000000999"
        )
        with self.assertRaisesRegex(ValueError, "not trusted"):
            validate_outcome_policy(
                case,
                contracts.parse_time,
                contracts.resolve_authorization_audit,
            )

    def test_rejects_publicly_rehashed_forged_authorization(self) -> None:
        case = copy.deepcopy(self.case)
        review = case["reviews"][0]
        review["reviewer"]["id"] = "attacker"
        with self.assertRaisesRegex(ValueError, "authorization audit"):
            validate_outcome_policy(
                case,
                contracts.parse_time,
                contracts.resolve_authorization_audit,
            )

    def test_authorization_audit_binds_the_exact_action_snapshot(self) -> None:
        case = copy.deepcopy(self.case)
        action = case["actions"][0]
        action["params"]["maxP95Ms"] = 60_000
        action.update(contracts.render_action(action))
        for effect in case["evidence"]:
            if effect["kind"] != "effect_metric_comparison":
                continue
            effect["payload"]["typed"]["validationTargetZh"] = action["validation"][
                "targetZh"
            ]
        with self.assertRaisesRegex(ValueError, "authorization audit"):
            validate_outcome_policy(
                case,
                contracts.parse_time,
                contracts.resolve_authorization_audit,
            )

    def test_authorization_audit_cannot_predate_case_creation(self) -> None:
        authorization = contracts.resolve_authorization_audit("authz_0000000000000001")
        assert authorization is not None
        authorization["capturedAt"] = "2020-01-01T00:00:00Z"

        with self.assertRaisesRegex(ValueError, "before Case creation"):
            validate_outcome_policy(
                self.case,
                contracts.parse_time,
                lambda _record_id: copy.deepcopy(authorization),
            )

    def test_authorization_audit_cannot_predate_terminal_revision(self) -> None:
        prior = contracts.load(contracts.EXAMPLES / "diagnosis-case-v2.valid.json")
        authorization = contracts.resolve_authorization_audit("authz_0000000000000001")
        assert authorization is not None
        authorization["capturedAt"] = prior["updatedAt"]

        with (
            patch.dict(
                contracts.SERVER_AUTHORIZATION_AUDIT_FIXTURES,
                {authorization["auditRecordId"]: authorization},
            ),
            self.assertRaisesRegex(ValueError, "prior Case revision"),
        ):
            contracts.validate_case_transition(prior, self.case)

    def test_rejects_terminal_approval_without_trusted_audit_resolver(self) -> None:
        with self.assertRaisesRegex(ValueError, "trusted authorization audit resolver"):
            validate_outcome_policy(self.case, contracts.parse_time)

    def test_terminal_tuple_records_must_belong_to_current_case_revision(self) -> None:
        case = copy.deepcopy(self.case)
        case["reviews"][0]["caseRevision"] = 1
        for feedback in case["feedback"]:
            feedback["caseRevision"] = 1
        case["transitionEvents"][-1]["caseRevision"] = 1
        with self.assertRaisesRegex(ValueError, "current Case revision"):
            validate_outcome_policy(
                case,
                contracts.parse_time,
                contracts.resolve_authorization_audit,
            )


class SourceLedgerTests(unittest.TestCase):
    def test_rejects_unbounded_revision_without_expanding_it(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        source["revision"] = 10**12
        with self.assertRaises(ValueError):
            replay_source_history(source, contracts.parse_time)

    def test_replays_valid_enabled_drain_history(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        leased, draining, drained = contracts.build_source_lease_drain(source)
        for snapshot in (leased, draining, drained):
            replay_source_history(snapshot, contracts.parse_time)

    def test_rejects_acquisition_after_drain_snapshot(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        _, draining, _ = contracts.build_source_lease_drain(source)
        poisoned = copy.deepcopy(draining)
        poisoned["leaseEvents"].append(
            {
                "eventId": "levt_0000000000000999",
                "sourceRevision": poisoned["revision"],
                "operation": "lease_acquired",
                "leaseId": "lease_0000000000000999",
                "jobId": "job_0000000000000999",
                "fromLeaseCount": 2,
                "toLeaseCount": 3,
                "actor": {"kind": "system"},
                "ownerApproval": None,
                "createdAt": "2026-09-02T09:25:30Z",
                "reason": "poisoned history",
            }
        )
        with self.assertRaises(ValueError):
            replay_source_history(poisoned, contracts.parse_time)

    def test_rejects_lease_event_at_the_same_time_as_state_snapshot(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        leased, _, _ = contracts.build_source_lease_drain(source)
        poisoned = copy.deepcopy(leased)
        poisoned["leaseEvents"][-1]["createdAt"] = poisoned["transitionEvents"][-1][
            "createdAt"
        ]
        poisoned["activeLeases"][-1]["acquiredAt"] = poisoned["leaseEvents"][-1][
            "createdAt"
        ]
        with self.assertRaisesRegex(ValueError, "must precede"):
            replay_source_history(poisoned, contracts.parse_time)

    def test_rejects_equal_timestamps_inside_one_lease_revision(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        _, _, drained = contracts.build_source_lease_drain(source)
        latest_revision = drained["revision"]
        revision_events = [
            item
            for item in drained["leaseEvents"]
            if item["sourceRevision"] == latest_revision
        ]
        revision_events[1]["createdAt"] = revision_events[0]["createdAt"]
        with self.assertRaisesRegex(ValueError, "strictly ordered"):
            replay_source_history(drained, contracts.parse_time)


if __name__ == "__main__":
    unittest.main()
