from __future__ import annotations

import copy
import math
import sys
import unittest
from pathlib import Path

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
    validate_policy_pins,
)
from vnext_outcome_policy import validate_outcome_policy
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


class OutcomePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        case = contracts.load(contracts.EXAMPLES / "diagnosis-case-v2.valid.json")
        self.case = contracts.build_validated_case(case)

    def test_accepts_one_authorized_causal_tuple(self) -> None:
        validate_outcome_policy(self.case, contracts.parse_time)

    def test_rejects_failed_effect_for_validated_outcome(self) -> None:
        case = copy.deepcopy(self.case)
        effect = next(
            item
            for item in case["evidence"]
            if item["kind"] == "effect_metric_comparison"
        )
        effect["payload"]["typed"]["passed"] = False
        with self.assertRaises(ValueError):
            validate_outcome_policy(case, contracts.parse_time)

    def test_rejects_ineligible_terminal_evidence(self) -> None:
        case = copy.deepcopy(self.case)
        effect = next(
            item
            for item in case["evidence"]
            if item["kind"] == "effect_metric_comparison"
        )
        effect["coverage"] = 0
        with self.assertRaises(ValueError):
            validate_outcome_policy(case, contracts.parse_time)

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
            validate_outcome_policy(case, contracts.parse_time)

    def test_rejects_mutated_authorization_snapshot(self) -> None:
        case = copy.deepcopy(self.case)
        case["reviews"][0]["authorizationSnapshot"]["role"] = "dba"
        with self.assertRaises(ValueError):
            validate_outcome_policy(case, contracts.parse_time)


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


if __name__ == "__main__":
    unittest.main()
