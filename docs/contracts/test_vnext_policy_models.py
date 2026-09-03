from __future__ import annotations

import copy
import math
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import patch

CONTRACTS = Path(__file__).parent
sys.path.insert(0, str(CONTRACTS))

import validate_vnext_examples as contracts
from vnext_canonical_json import canonical_json_bytes, canonical_sha256
from vnext_diagnosis_policy import (
    DIAGNOSIS_DEPENDENCY_REGISTRY,
    FACT_CANDIDATE_IDENTITY_REGISTRY,
    FACT_DEPENDENCY_REGISTRY,
    RULE_PACK_BY_VERSION_FAMILY,
    RULE_POLICY_REGISTRY,
    derive_completeness,
    derive_evidence_level,
    evidence_candidate_identity,
    expected_rule_findings,
    validate_gap_fact,
    validate_policy_pins,
)
from vnext_outcome_policy import (
    ACTION_RESULT_POLICY,
    _measurement_passes,
    validate_outcome_policy,
)
from vnext_source_audit import source_verification_binding
from vnext_source_idempotency import (
    evaluate_source_idempotency_receipt,
    source_write_intent_digest,
    source_write_scope_digest,
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

    def test_each_profile_explicitly_declares_candidate_identity_per_role(
        self,
    ) -> None:
        self.assertEqual(
            set(FACT_CANDIDATE_IDENTITY_REGISTRY),
            set(FACT_DEPENDENCY_REGISTRY),
        )
        for profile, roles in FACT_DEPENDENCY_REGISTRY.items():
            with self.subTest(profile=profile):
                self.assertEqual(
                    set(FACT_CANDIDATE_IDENTITY_REGISTRY[profile]), set(roles)
                )
                self.assertTrue(
                    all(
                        fields == ("profileSubjectRef", "profileObjectRef")
                        for fields in FACT_CANDIDATE_IDENTITY_REGISTRY[profile].values()
                    )
                )

    def test_statistics_candidate_identity_cannot_be_relabelled_in_envelope(
        self,
    ) -> None:
        case = contracts.load(
            contracts.EXAMPLES / "diagnosis-case-v2.statistics.valid.json"
        )
        evidence = next(
            item for item in case["evidence"] if item["kind"] == "statistics"
        )
        relabelled = copy.deepcopy(evidence)
        relabelled["profileSubjectRef"] = "subject_0000000000000099"

        with self.assertRaisesRegex(ValueError, "typed profile identity"):
            evidence_candidate_identity(
                ("fact.statistics_estimation_profile", "v1"),
                "statisticsEvidenceId",
                relabelled,
            )

    def test_runtime_candidate_identity_cannot_be_relabelled_in_envelope(
        self,
    ) -> None:
        case = contracts.load(
            contracts.EXAMPLES / "diagnosis-case-v2.runtime-correlation.valid.json"
        )
        evidence = next(
            item for item in case["evidence"] if item["kind"] == "runtime_metric"
        )
        relabelled = copy.deepcopy(evidence)
        relabelled["profileObjectRef"] = "another_hotspot_window"

        with self.assertRaisesRegex(ValueError, "typed profile identity"):
            evidence_candidate_identity(
                ("fact.runtime_hotspot_profile", "v1"),
                "runtimeEvidenceId",
                relabelled,
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

    def test_evidence_gap_keeps_an_ineligible_compatible_candidate(self) -> None:
        pending, _ = contracts.build_evidence_insufficient_cases(self.case)
        fact = pending["facts"][0]
        evidence = {item["evidenceId"]: item for item in pending["evidence"]}
        plan_role = next(
            item
            for item in fact["params"]["roleAssessments"]
            if item["role"] == "planEvidenceId"
        )
        orders_plan = evidence[plan_role["evidenceId"]]
        orders_plan["freshness"] = "stale"
        plan_role.update({"eligible": False, "reasonCodes": ["NOT_FRESH"]})

        customers_plan = copy.deepcopy(orders_plan)
        customers_plan["evidenceId"] = "ev_0000000000000099"
        customers_plan["profileObjectRef"] = "customers"
        customers_plan["payload"]["typed"]["profileObjectRef"] = "customers"
        customers_plan["freshness"] = "fresh"
        customers_plan["payload"]["storageRef"] = "payload_0000000000000099"
        customers_plan["payload"]["typed"]["tableName"] = "customers"
        customers_plan["payload"]["typedDigest"] = canonical_sha256(
            customers_plan["payload"]["typed"]
        )
        customers_plan["summaryZh"] = contracts.render_evidence_summary(customers_plan)
        evidence[customers_plan["evidenceId"]] = customers_plan

        assessments = validate_gap_fact(fact, evidence)
        self.assertEqual(
            next(item for item in assessments if item["role"] == "planEvidenceId"),
            plan_role,
        )

    def test_evidence_gap_keeps_selected_identity_without_corroborating_role(
        self,
    ) -> None:
        pending, _ = contracts.build_evidence_insufficient_cases(self.case)
        fact = pending["facts"][0]
        evidence = {item["evidenceId"]: item for item in pending["evidence"]}
        assessments = fact["params"]["roleAssessments"]
        plan_role = next(
            item for item in assessments if item["role"] == "planEvidenceId"
        )
        index_role = next(
            item for item in assessments if item["role"] == "indexEvidenceId"
        )
        orders_plan = evidence[plan_role["evidenceId"]]
        orders_plan["freshness"] = "stale"
        plan_role.update({"eligible": False, "reasonCodes": ["NOT_FRESH"]})
        removed_index_id = index_role["evidenceId"]
        index_role.update(
            {
                "evidenceId": None,
                "eligible": False,
                "reasonCodes": ["MISSING_EVIDENCE"],
            }
        )
        fact["evidenceIds"].remove(removed_index_id)
        del evidence[removed_index_id]

        customers_plan = copy.deepcopy(orders_plan)
        customers_plan["evidenceId"] = "ev_0000000000000099"
        customers_plan["profileObjectRef"] = "customers"
        customers_plan["payload"]["typed"]["profileObjectRef"] = "customers"
        customers_plan["freshness"] = "fresh"
        customers_plan["payload"]["storageRef"] = "payload_0000000000000099"
        customers_plan["payload"]["typed"]["tableName"] = "customers"
        customers_plan["payload"]["typedDigest"] = canonical_sha256(
            customers_plan["payload"]["typed"]
        )
        customers_plan["summaryZh"] = contracts.render_evidence_summary(customers_plan)
        evidence[customers_plan["evidenceId"]] = customers_plan

        rebuilt = validate_gap_fact(fact, evidence)
        self.assertEqual(
            next(item for item in rebuilt if item["role"] == "planEvidenceId"),
            plan_role,
        )

    def test_evidence_gap_rejects_an_incompatible_selected_candidate(self) -> None:
        pending, _ = contracts.build_evidence_insufficient_cases(self.case)
        fact = pending["facts"][0]
        evidence = {item["evidenceId"]: item for item in pending["evidence"]}
        plan_role = next(
            item
            for item in fact["params"]["roleAssessments"]
            if item["role"] == "planEvidenceId"
        )
        orders_plan_id = plan_role["evidenceId"]
        evidence[orders_plan_id]["freshness"] = "stale"

        customers_plan = copy.deepcopy(evidence[orders_plan_id])
        customers_plan["evidenceId"] = "ev_0000000000000099"
        customers_plan["profileObjectRef"] = "customers"
        customers_plan["payload"]["typed"]["profileObjectRef"] = "customers"
        customers_plan["freshness"] = "fresh"
        customers_plan["payload"]["storageRef"] = "payload_0000000000000099"
        customers_plan["payload"]["typed"]["tableName"] = "customers"
        customers_plan["payload"]["typedDigest"] = canonical_sha256(
            customers_plan["payload"]["typed"]
        )
        customers_plan["summaryZh"] = contracts.render_evidence_summary(customers_plan)
        evidence[customers_plan["evidenceId"]] = customers_plan
        plan_role.update(
            {
                "evidenceId": customers_plan["evidenceId"],
                "eligible": True,
                "reasonCodes": [],
            }
        )
        fact["evidenceIds"][fact["evidenceIds"].index(orders_plan_id)] = customers_plan[
            "evidenceId"
        ]

        with self.assertRaisesRegex(ValueError, "profile-compatible"):
            validate_gap_fact(fact, evidence)

    def test_statistics_gap_ignores_an_eligible_candidate_for_another_object(
        self,
    ) -> None:
        statistics_case = contracts.load(
            contracts.EXAMPLES / "diagnosis-case-v2.statistics.valid.json"
        )
        pending, _ = contracts.build_evidence_insufficient_cases(statistics_case)
        fact = pending["facts"][0]
        evidence = {item["evidenceId"]: item for item in pending["evidence"]}
        statistics_role = fact["params"]["roleAssessments"][0]
        selected = evidence[statistics_role["evidenceId"]]
        selected["profileSubjectRef"] = "subject_0000000000000003"

        unrelated = copy.deepcopy(selected)
        unrelated["evidenceId"] = "ev_0000000000000099"
        unrelated["profileSubjectRef"] = "subject_0000000000000003"
        unrelated["profileObjectRef"] = "customer_statistics"
        unrelated["payload"]["typed"].update(
            {
                "profileSubjectRef": unrelated["profileSubjectRef"],
                "profileObjectRef": unrelated["profileObjectRef"],
            }
        )
        unrelated["freshness"] = "fresh"
        unrelated["coverage"] = 1.0
        unrelated["payload"]["storageRef"] = "payload_0000000000000099"
        unrelated["payload"]["typed"].update(
            {
                "estimatedRows": 7,
                "actualRows": 7,
                "statisticsFreshness": "current",
                "tableName": "customer_statistics",
            }
        )
        unrelated["payload"]["typedDigest"] = canonical_sha256(
            unrelated["payload"]["typed"]
        )
        unrelated["summaryZh"] = contracts.render_evidence_summary(unrelated)
        evidence[unrelated["evidenceId"]] = unrelated

        rebuilt = validate_gap_fact(fact, evidence)
        self.assertEqual(rebuilt[0], statistics_role)

    def test_statistics_gap_rejects_ignoring_a_same_profile_candidate(self) -> None:
        statistics_case = contracts.load(
            contracts.EXAMPLES / "diagnosis-case-v2.statistics.valid.json"
        )
        pending, _ = contracts.build_evidence_insufficient_cases(statistics_case)
        fact = pending["facts"][0]
        evidence = {item["evidenceId"]: item for item in pending["evidence"]}
        statistics_role = fact["params"]["roleAssessments"][0]
        selected = evidence[statistics_role["evidenceId"]]
        selected["profileSubjectRef"] = "subject_0000000000000003"

        replacement = copy.deepcopy(selected)
        replacement["evidenceId"] = "ev_0000000000000099"
        replacement["freshness"] = "fresh"
        replacement["coverage"] = 1.0
        replacement["payload"]["storageRef"] = "payload_0000000000000099"
        replacement["payload"]["typedDigest"] = canonical_sha256(
            replacement["payload"]["typed"]
        )
        replacement["summaryZh"] = contracts.render_evidence_summary(replacement)
        evidence[replacement["evidenceId"]] = replacement

        with self.assertRaisesRegex(ValueError, "eligible matching Evidence"):
            validate_gap_fact(fact, evidence)

    def test_runtime_gap_ignores_an_eligible_candidate_for_another_object(
        self,
    ) -> None:
        runtime_case = contracts.load(
            contracts.EXAMPLES / "diagnosis-case-v2.runtime-correlation.valid.json"
        )
        pending, _ = contracts.build_evidence_insufficient_cases(runtime_case)
        fact = pending["facts"][0]
        evidence = {item["evidenceId"]: item for item in pending["evidence"]}
        statement_role = next(
            item
            for item in fact["params"]["roleAssessments"]
            if item["role"] == "statementEvidenceId"
        )
        selected = evidence[statement_role["evidenceId"]]
        selected["profileSubjectRef"] = "subject_0000000000000004"

        unrelated = copy.deepcopy(selected)
        unrelated["evidenceId"] = "ev_0000000000000098"
        unrelated["profileSubjectRef"] = "subject_0000000000000004"
        unrelated["profileObjectRef"] = "another_hotspot_window"
        unrelated["payload"]["typed"].update(
            {
                "profileSubjectRef": unrelated["profileSubjectRef"],
                "profileObjectRef": unrelated["profileObjectRef"],
            }
        )
        unrelated["freshness"] = "fresh"
        unrelated["coverage"] = 1.0
        unrelated["payload"]["storageRef"] = "payload_0000000000000098"
        unrelated["payload"]["typed"]["sqlStability"] = "unknown"
        unrelated["payload"]["typedDigest"] = canonical_sha256(
            unrelated["payload"]["typed"]
        )
        unrelated["summaryZh"] = contracts.render_evidence_summary(unrelated)
        evidence[unrelated["evidenceId"]] = unrelated

        rebuilt = validate_gap_fact(fact, evidence)
        self.assertEqual(
            next(item for item in rebuilt if item["role"] == "statementEvidenceId"),
            statement_role,
        )

    def test_runtime_gap_rejects_ignoring_a_same_profile_candidate(self) -> None:
        runtime_case = contracts.load(
            contracts.EXAMPLES / "diagnosis-case-v2.runtime-correlation.valid.json"
        )
        pending, _ = contracts.build_evidence_insufficient_cases(runtime_case)
        fact = pending["facts"][0]
        evidence = {item["evidenceId"]: item for item in pending["evidence"]}
        statement_role = next(
            item
            for item in fact["params"]["roleAssessments"]
            if item["role"] == "statementEvidenceId"
        )
        selected = evidence[statement_role["evidenceId"]]

        replacement = copy.deepcopy(selected)
        replacement["evidenceId"] = "ev_0000000000000098"
        replacement["freshness"] = "fresh"
        replacement["coverage"] = 1.0
        replacement["payload"]["storageRef"] = "payload_0000000000000098"
        replacement["payload"]["typedDigest"] = canonical_sha256(
            replacement["payload"]["typed"]
        )
        replacement["summaryZh"] = contracts.render_evidence_summary(replacement)
        evidence[replacement["evidenceId"]] = replacement

        with self.assertRaisesRegex(ValueError, "eligible matching Evidence"):
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


class SourceIdempotencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.digest_key = b"source-intent-digest-test-key-32"
        self.scope_digest = source_write_scope_digest(
            owner_principal_id="owner",
            method="POST",
            canonical_route="/api/v1/sources",
            idempotency_key="source-create-key-0001",
        )
        self.intent_digest = source_write_intent_digest(
            source_id=None,
            expected_revision=None,
            request_body={"name": "订单库", "secret": "never-persist-this"},
            digest_key=self.digest_key,
        )

    def _receipt(self, *, state: str = "committed") -> dict[str, Any]:
        committed = state == "committed"
        response_body = (
            {"sourceId": "src_0000000000000001", "revision": 1} if committed else None
        )
        return {
            "receiptRevision": "source-idempotency-receipt/v1",
            "receiptId": "idem_0000000000000001",
            "scopeDigest": self.scope_digest,
            "intentDigest": self.intent_digest,
            "state": state,
            "httpStatus": 201 if committed else None,
            "responseDigest": (canonical_sha256(response_body) if committed else None),
            "responseBody": response_body,
            "resultSourceId": "src_0000000000000001" if committed else None,
            "resultRevision": 1 if committed else None,
            "createdAt": "2026-09-03T00:00:00Z",
            "expiresAt": "2026-09-04T00:00:00Z",
        }

    def test_missing_receipt_reserves_and_committed_receipt_replays(self) -> None:
        self.assertEqual(
            evaluate_source_idempotency_receipt(
                None,
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            ),
            "reserve",
        )
        receipt = self._receipt()
        self.assertEqual(
            evaluate_source_idempotency_receipt(
                receipt,
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            ),
            "replay",
        )
        self.assertNotIn("never-persist-this", repr(receipt))

    def test_same_key_with_different_intent_fails_closed(self) -> None:
        different = source_write_intent_digest(
            source_id=None,
            expected_revision=None,
            request_body={"name": "另一数据源"},
            digest_key=self.digest_key,
        )
        with self.assertRaisesRegex(ValueError, "IDEMPOTENCY_KEY_REUSED"):
            evaluate_source_idempotency_receipt(
                self._receipt(),
                scope_digest=self.scope_digest,
                intent_digest=different,
            )

    def test_in_progress_receipt_never_reexecutes(self) -> None:
        with self.assertRaisesRegex(ValueError, "IDEMPOTENCY_IN_PROGRESS"):
            evaluate_source_idempotency_receipt(
                self._receipt(state="in_progress"),
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            )

    def test_receipt_retention_and_shape_are_fail_closed(self) -> None:
        short = self._receipt()
        short["expiresAt"] = "2026-09-03T23:59:59Z"
        with self.assertRaisesRegex(ValueError, "below 24 hours"):
            evaluate_source_idempotency_receipt(
                short,
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            )

        leaked = self._receipt()
        leaked["rawIdempotencyKey"] = "source-create-key-0001"
        with self.assertRaisesRegex(ValueError, "receipt shape"):
            evaluate_source_idempotency_receipt(
                leaked,
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            )

        invalid_time = self._receipt()
        invalid_time["createdAt"] = None
        with self.assertRaisesRegex(ValueError, "receipt time"):
            evaluate_source_idempotency_receipt(
                invalid_time,
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            )

    def test_receipt_values_fail_closed_without_runtime_type_errors(self) -> None:
        invalid_receipts = (
            ("receiptId", None),
            ("receiptId", 7),
            ("resultSourceId", "src_../not-canonical"),
        )
        for field, value in invalid_receipts:
            receipt = self._receipt()
            receipt[field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaisesRegex(ValueError, "receipt"),
            ):
                evaluate_source_idempotency_receipt(
                    receipt,
                    scope_digest=self.scope_digest,
                    intent_digest=self.intent_digest,
                )

        malformed_response = self._receipt()
        malformed_response["responseBody"][7] = "not a JSON object key"
        with self.assertRaisesRegex(ValueError, "redacted response"):
            evaluate_source_idempotency_receipt(
                malformed_response,
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            )

        noncanonical_response = self._receipt()
        noncanonical_response["responseBody"]["ratio"] = 0.5
        with self.assertRaisesRegex(ValueError, "receipt response body"):
            evaluate_source_idempotency_receipt(
                noncanonical_response,
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            )

        for scope_digest, intent_digest in (
            (None, self.intent_digest),
            (self.scope_digest, None),
        ):
            with (
                self.subTest(
                    scope_digest=scope_digest,
                    intent_digest=intent_digest,
                ),
                self.assertRaisesRegex(ValueError, "idempotency digest"),
            ):
                evaluate_source_idempotency_receipt(
                    self._receipt(),
                    scope_digest=scope_digest,
                    intent_digest=intent_digest,
                )

    def test_scope_rejects_noncanonical_source_routes(self) -> None:
        for route in (
            "/api/v1/sources-evil",
            "/api/v1/sources?source=other",
            "/api/v1/sources/../setup/owner",
            "/api/v1/sources//src_0000000000000001",
        ):
            with (
                self.subTest(route=route),
                self.assertRaisesRegex(ValueError, "idempotency scope"),
            ):
                source_write_scope_digest(
                    owner_principal_id="owner",
                    method="POST",
                    canonical_route=route,
                    idempotency_key="source-create-key-0001",
                )

    def test_scope_and_intent_types_fail_closed(self) -> None:
        invalid_scopes = (
            {"owner_principal_id": 1},
            {"method": None},
            {"canonical_route": 1},
            {"idempotency_key": None},
        )
        base_scope: dict[str, Any] = {
            "owner_principal_id": "owner",
            "method": "POST",
            "canonical_route": "/api/v1/sources",
            "idempotency_key": "source-create-key-0001",
        }
        for change in invalid_scopes:
            with (
                self.subTest(scope=change),
                self.assertRaisesRegex(ValueError, "invalid Source idempotency scope"),
            ):
                source_write_scope_digest(**{**base_scope, **change})

        invalid_intents = (
            {"source_id": True, "expected_revision": 1},
            {"source_id": "src_0000000000000001", "expected_revision": True},
            {"source_id": "src_0000000000000001", "expected_revision": None},
            {"source_id": None, "expected_revision": 1},
            {"source_id": None, "expected_revision": None, "request_body": []},
        )
        base_intent: dict[str, Any] = {
            "source_id": None,
            "expected_revision": None,
            "request_body": {},
            "digest_key": self.digest_key,
        }
        for change in invalid_intents:
            with (
                self.subTest(intent=change),
                self.assertRaisesRegex(ValueError, "invalid Source write intent"),
            ):
                source_write_intent_digest(**{**base_intent, **change})

    def test_intent_digest_is_keyed_and_replay_body_is_integrity_bound(self) -> None:
        request = {"name": "订单库", "secret": "guessable-password"}
        first = source_write_intent_digest(
            source_id=None,
            expected_revision=None,
            request_body=request,
            digest_key=self.digest_key,
        )
        second = source_write_intent_digest(
            source_id=None,
            expected_revision=None,
            request_body=request,
            digest_key=b"another-source-intent-key-000001",
        )
        self.assertTrue(first.startswith("hmac-sha256:"))
        self.assertNotEqual(first, second)
        self.assertNotIn("guessable-password", first)

        tampered = self._receipt()
        tampered["responseBody"]["revision"] = 2
        with self.assertRaisesRegex(ValueError, "response digest"):
            evaluate_source_idempotency_receipt(
                tampered,
                scope_digest=self.scope_digest,
                intent_digest=self.intent_digest,
            )

        for index, leak in enumerate(
            (
                {"password": "must-not-persist"},
                {"nested": {"newSecretValue": "must-not-persist"}},
                {"access_token": "must-not-persist"},
            )
        ):
            secret_response = self._receipt()
            secret_response["responseBody"].update(leak)
            secret_response["responseDigest"] = canonical_sha256(
                secret_response["responseBody"]
            )
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(ValueError, "redacted response"),
            ):
                evaluate_source_idempotency_receipt(
                    secret_response,
                    scope_digest=self.scope_digest,
                    intent_digest=self.intent_digest,
                )


class SourceLedgerTests(unittest.TestCase):
    OWNER: ClassVar[dict[str, str]] = {
        "kind": "user",
        "role": "owner",
        "id": "owner",
        "displayName": "本机 Owner",
    }
    VERIFIER: ClassVar[dict[str, str]] = {
        "kind": "system",
        "role": "system",
        "id": "source-verifier",
        "displayName": "连接校验器",
    }
    LIFECYCLE: ClassVar[dict[str, str]] = {
        "kind": "system",
        "role": "system",
        "id": "source-lifecycle",
        "displayName": "数据源生命周期",
    }
    UNKNOWN_VERSION: ClassVar[dict[str, Any]] = {
        "detected": None,
        "family": "unknown",
        "supported": False,
    }
    NOT_RUN: ClassVar[dict[str, Any]] = {
        "status": "not_run",
        "testedAt": None,
        "identityDigest": None,
        "errorCode": None,
    }

    @classmethod
    def _audit_resolver(cls, *snapshots: dict[str, Any]):
        """Model a server-owned ledger captured before adversarial rewrites."""
        return contracts.build_fixture_source_audit_resolver(*snapshots)

    def _validate_transition(
        self, prior: dict[str, Any], proposed: dict[str, Any]
    ) -> None:
        contracts.validate_source_transition(
            prior,
            proposed,
            self._audit_resolver(prior, proposed),
        )

    @staticmethod
    def _verification_binding_digest(source: dict[str, Any]) -> str:
        return canonical_sha256(source_verification_binding(source))

    @staticmethod
    def _one_second_before(value: str) -> str:
        return (
            (contracts.parse_time(value) - timedelta(seconds=1))
            .isoformat()
            .replace("+00:00", "Z")
        )

    @classmethod
    def _revision(
        cls,
        source: dict[str, Any],
        *,
        operation: str,
        to_state: str,
        event_id: str,
        event_at: str,
        actor: dict[str, str],
    ) -> dict[str, Any]:
        proposed = copy.deepcopy(source)
        proposed["revision"] += 1
        proposed["state"] = to_state
        proposed["updatedAt"] = event_at
        proposed["transitionEvents"].append(
            {
                "eventId": event_id,
                "sourceRevision": proposed["revision"],
                "type": "source_state",
                "operation": operation,
                "fromState": source["state"],
                "toState": to_state,
                "credentialRevision": source["auth"]["credentialRevision"],
                "actor": copy.deepcopy(actor),
                "createdAt": event_at,
                "reason": f"测试 {operation} 生命周期边界",
            }
        )
        return proposed

    @classmethod
    def _invalidate(cls, source: dict[str, Any]) -> None:
        source["version"] = copy.deepcopy(cls.UNKNOWN_VERSION)
        source["capabilities"] = []
        source["verification"] = copy.deepcopy(cls.NOT_RUN)

    @classmethod
    def _unverified_disabled(cls) -> tuple[dict[str, Any], dict[str, Any]]:
        enabled = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        _, disabled = contracts.build_source_rotation(enabled)
        return enabled, disabled

    @classmethod
    def _verification_reserved(
        cls,
        source: dict[str, Any],
        *,
        event_id: str,
        event_at: str,
        lease_id: str,
        job_id: str,
    ) -> dict[str, Any]:
        reserved = cls._revision(
            source,
            operation="leases_updated",
            to_state=source["state"],
            event_id=event_id,
            event_at=event_at,
            actor=cls.VERIFIER,
        )
        binding_digest = cls._verification_binding_digest(source)
        lease_at = cls._one_second_before(event_at)
        credential_revision = source["auth"]["credentialRevision"]
        reserved["credentialLifecycle"]["activeLeaseCount"] += 1
        reserved["activeLeases"].append(
            {
                "leaseId": lease_id,
                "jobId": job_id,
                "purpose": "verification",
                "credentialRevision": credential_revision,
                "bindingDigest": binding_digest,
                "acquiredRevision": reserved["revision"],
                "acquiredAt": lease_at,
            }
        )
        reserved["leaseEvents"].append(
            {
                "eventId": lease_id.replace("lease_", "levt_"),
                "sourceRevision": reserved["revision"],
                "operation": "lease_acquired",
                "leaseId": lease_id,
                "jobId": job_id,
                "purpose": "verification",
                "credentialRevision": credential_revision,
                "bindingDigest": binding_digest,
                "fromLeaseCount": len(source["activeLeases"]),
                "toLeaseCount": len(source["activeLeases"]) + 1,
                "actor": copy.deepcopy(cls.VERIFIER),
                "ownerApproval": None,
                "createdAt": lease_at,
                "reason": "连接校验器取得受信 reservation 后方可解密凭据",
            }
        )
        return reserved

    @classmethod
    def _verification_result(
        cls,
        reserved: dict[str, Any],
        *,
        passed: bool,
        event_id: str,
        event_at: str,
    ) -> dict[str, Any]:
        lease = next(
            item
            for item in reserved["activeLeases"]
            if item["purpose"] == "verification"
        )
        operation = "verified" if passed else "verification_failed"
        to_state = (
            reserved["state"]
            if passed
            else (
                "verification_failed" if reserved["state"] != "enabled" else "draining"
            )
        )
        if not passed and reserved["state"] == "enabled":
            operation = "verification_failure_started"
        result = cls._revision(
            reserved,
            operation=operation,
            to_state=to_state,
            event_id=event_id,
            event_at=event_at,
            actor=cls.VERIFIER,
        )
        result["activeLeases"] = [
            item for item in result["activeLeases"] if item != lease
        ]
        result["credentialLifecycle"]["activeLeaseCount"] -= 1
        release_at = cls._one_second_before(event_at)
        result["leaseEvents"].append(
            {
                "eventId": lease["leaseId"].replace("lease_", "levt_")[:-1] + "9",
                "sourceRevision": result["revision"],
                "operation": "lease_released",
                "leaseId": lease["leaseId"],
                "jobId": lease["jobId"],
                "purpose": lease["purpose"],
                "credentialRevision": lease["credentialRevision"],
                "bindingDigest": lease["bindingDigest"],
                "fromLeaseCount": len(reserved["activeLeases"]),
                "toLeaseCount": len(reserved["activeLeases"]) - 1,
                "actor": copy.deepcopy(cls.VERIFIER),
                "ownerApproval": None,
                "createdAt": release_at,
                "reason": "连接校验完成并原子释放 verification reservation",
            }
        )
        if passed:
            enabled = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
            result["version"] = copy.deepcopy(enabled["version"])
            result["capabilities"] = copy.deepcopy(enabled["capabilities"])
            result["verification"] = {
                "status": "passed",
                "testedAt": event_at,
                "identityDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "errorCode": None,
            }
        else:
            result["verification"] = {
                "status": "failed",
                "testedAt": event_at,
                "identityDigest": None,
                "errorCode": "SOURCE_IDENTITY_MISMATCH",
            }
            if reserved["state"] == "enabled":
                result["credentialLifecycle"]["pendingOperation"] = (
                    "verification_failure"
                )
        return result

    @classmethod
    def _verified_disabled(cls) -> tuple[dict[str, Any], dict[str, Any]]:
        _, disabled = cls._unverified_disabled()
        reserved = cls._verification_reserved(
            disabled,
            event_id="sevt_0000000000002001",
            event_at="2026-09-02T09:30:30Z",
            lease_id="lease_0000000000002001",
            job_id="job_0000000000002001",
        )
        verified = cls._verification_result(
            reserved,
            passed=True,
            event_id="sevt_0000000000002002",
            event_at="2026-09-02T09:31:00Z",
        )
        return reserved, verified

    @classmethod
    def _failed_source(cls) -> tuple[dict[str, Any], dict[str, Any]]:
        _, disabled = cls._unverified_disabled()
        reserved = cls._verification_reserved(
            disabled,
            event_id="sevt_0000000000002011",
            event_at="2026-09-02T09:30:30Z",
            lease_id="lease_0000000000002011",
            job_id="job_0000000000002011",
        )
        failed = cls._verification_result(
            reserved,
            passed=False,
            event_id="sevt_0000000000002012",
            event_at="2026-09-02T09:31:00Z",
        )
        return reserved, failed

    @classmethod
    def _edit_source(
        cls,
        source: dict[str, Any],
        *,
        event_id: str,
        event_at: str,
        endpoint: dict[str, Any] | None = None,
        allowed_schemas: list[str] | None = None,
        invalidate: bool = False,
        to_state: str | None = None,
    ) -> dict[str, Any]:
        edited = cls._revision(
            source,
            operation="edited",
            to_state=to_state or source["state"],
            event_id=event_id,
            event_at=event_at,
            actor=cls.OWNER,
        )
        if endpoint is not None:
            edited["endpoint"] = endpoint
        if allowed_schemas is not None:
            edited["allowedSchemas"] = allowed_schemas
        if invalidate:
            cls._invalidate(edited)
        return edited

    @classmethod
    def _draft(cls) -> dict[str, Any]:
        draft = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        draft.update(
            revision=1,
            state="draft",
            version=copy.deepcopy(cls.UNKNOWN_VERSION),
            capabilities=[],
            verification=copy.deepcopy(cls.NOT_RUN),
            updatedAt="2026-09-02T09:00:00Z",
        )
        draft["auth"]["credentialRef"] = "cred_0000000000000001"
        draft["auth"]["credentialRevision"] = 1
        draft["transitionEvents"] = draft["transitionEvents"][:1]
        draft["transitionEvents"][0]["credentialRevision"] = 1
        draft["leaseEvents"] = []
        draft["activeLeases"] = []
        return draft

    @classmethod
    def _delete_chain(
        cls, source: dict[str, Any], *, suffix: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        minute = 32 if source["revision"] > 1 else 1
        draining = cls._revision(
            source,
            operation="delete_started",
            to_state="draining",
            event_id=f"sevt_{suffix}01",
            event_at=f"2026-09-02T09:{minute:02d}:00Z",
            actor=cls.OWNER,
        )
        draining["credentialLifecycle"] = {
            "state": "retiring",
            "activeLeaseCount": 0,
            "pendingOperation": "delete",
            "retireAfter": f"2026-09-02T09:{minute + 1:02d}:00Z",
        }

        tombstone = cls._revision(
            draining,
            operation="tombstoned",
            to_state="tombstoned",
            event_id=f"sevt_{suffix}02",
            event_at=f"2026-09-02T09:{minute + 1:02d}:00Z",
            actor=cls.LIFECYCLE,
        )
        tombstone["endpoint"].update(host="deleted.invalid", path=None)
        tombstone["auth"] = {
            "kind": "none",
            "credentialRef": None,
            "credentialRevision": None,
            "username": None,
            "expiresAt": None,
        }
        tombstone["transitionEvents"][-1]["credentialRevision"] = None
        tombstone["credentialLifecycle"] = {
            "state": "tombstoned",
            "activeLeaseCount": 0,
            "pendingOperation": None,
            "retireAfter": None,
        }
        tombstone["associatedSourceIds"] = []
        tombstone["allowedSchemas"] = []
        cls._invalidate(tombstone)
        return draining, tombstone

    def test_disabled_source_persists_fresh_reverification_results(self) -> None:
        disabled, verified = self._verified_disabled()
        self._validate_transition(disabled, verified)

        disabled, failed = self._failed_source()
        self._validate_transition(disabled, failed)

    def test_source_snapshot_requires_server_owned_audit(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        resolver = self._audit_resolver(source)

        with self.assertRaisesRegex(ValueError, "trusted Source audit resolver"):
            contracts.validate_source_semantics(source)
        contracts.validate_source_semantics(source, resolver)

        rewritten = copy.deepcopy(source)
        rewritten["endpoint"]["host"] = "other-cluster.prod.internal"
        rewritten["allowedSchemas"] = ["sensitive_schema"]
        rewritten["auth"]["credentialRef"] = "cred_9999999999999999"
        with self.assertRaisesRegex(ValueError, "snapshot digest"):
            contracts.validate_source_semantics(rewritten, resolver)

    def test_verification_status_has_one_closed_projection_shape(self) -> None:
        source_schema = contracts.schema_validator("source-v1.schema.json")
        draft = self._draft()
        stale_not_run = copy.deepcopy(draft)
        stale_not_run["verification"].update(
            testedAt=stale_not_run["updatedAt"], errorCode="STALE_ERROR"
        )

        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        reserved = self._verification_reserved(
            source,
            event_id="sevt_0000000000003121",
            event_at="2026-09-02T09:21:00Z",
            lease_id="lease_0000000000003121",
            job_id="job_0000000000003121",
        )
        failed_without_error = self._verification_result(
            reserved,
            passed=False,
            event_id="sevt_0000000000003122",
            event_at="2026-09-02T09:22:00Z",
        )
        failed_without_error["verification"]["errorCode"] = None

        for label, invalid in (
            ("not_run", stale_not_run),
            ("failed", failed_without_error),
        ):
            with self.subTest(status=label, boundary="json-schema"):
                self.assertTrue(list(source_schema.iter_errors(invalid)))
            with (
                self.subTest(status=label, boundary="semantic"),
                self.assertRaisesRegex(
                    ValueError, "verification projection is incomplete"
                ),
            ):
                contracts.validate_source_semantics(
                    invalid, self._audit_resolver(invalid)
                )

    def test_verification_result_requires_and_releases_reservation(self) -> None:
        _, disabled = self._unverified_disabled()
        direct = self._revision(
            disabled,
            operation="verified",
            to_state="disabled",
            event_id="sevt_0000000000003101",
            event_at="2026-09-02T09:31:00Z",
            actor=self.VERIFIER,
        )
        enabled = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        direct["version"] = copy.deepcopy(enabled["version"])
        direct["capabilities"] = copy.deepcopy(enabled["capabilities"])
        direct["verification"] = {
            "status": "passed",
            "testedAt": direct["updatedAt"],
            "identityDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "errorCode": None,
        }
        with self.assertRaisesRegex(ValueError, "verification reservation"):
            self._validate_transition(disabled, direct)

        reserved = self._verification_reserved(
            disabled,
            event_id="sevt_0000000000003102",
            event_at="2026-09-02T09:31:00Z",
            lease_id="lease_0000000000003102",
            job_id="job_0000000000003102",
        )
        verified = self._verification_result(
            reserved,
            passed=True,
            event_id="sevt_0000000000003103",
            event_at="2026-09-02T09:32:00Z",
        )
        source_validator = contracts.schema_validator("source-v1.schema.json")
        source_validator.validate(reserved)
        source_validator.validate(verified)
        self._validate_transition(disabled, reserved)
        self._validate_transition(reserved, verified)

    def test_enabled_source_can_publish_a_successful_reverification(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        reserved = self._verification_reserved(
            source,
            event_id="sevt_0000000000003111",
            event_at="2026-09-02T09:21:00Z",
            lease_id="lease_0000000000003111",
            job_id="job_0000000000003111",
        )
        verified = self._verification_result(
            reserved,
            passed=True,
            event_id="sevt_0000000000003112",
            event_at="2026-09-02T09:22:00Z",
        )

        self._validate_transition(source, reserved)
        self._validate_transition(reserved, verified)
        self.assertEqual(verified["state"], "enabled")

    def test_verification_result_cannot_cross_an_intervening_revision(self) -> None:
        _, disabled = self._unverified_disabled()
        reserved = self._verification_reserved(
            disabled,
            event_id="sevt_0000000000003121",
            event_at="2026-09-02T09:31:00Z",
            lease_id="lease_0000000000003121",
            job_id="job_0000000000003121",
        )
        edited = self._edit_source(
            reserved,
            event_id="sevt_0000000000003122",
            event_at="2026-09-02T09:32:00Z",
        )
        edited["name"] = "仅修改展示名"
        stale_result = self._verification_result(
            edited,
            passed=True,
            event_id="sevt_0000000000003123",
            event_at="2026-09-02T09:33:00Z",
        )

        self._validate_transition(disabled, reserved)
        self._validate_transition(reserved, edited)
        with self.assertRaisesRegex(ValueError, "reservation source revision"):
            self._validate_transition(edited, stale_result)

        reservation = next(
            item for item in edited["activeLeases"] if item["purpose"] == "verification"
        )
        released = self._revision(
            edited,
            operation="leases_updated",
            to_state="disabled",
            event_id="sevt_0000000000003124",
            event_at="2026-09-02T09:34:00Z",
            actor=self.VERIFIER,
        )
        released["activeLeases"] = []
        released["credentialLifecycle"]["activeLeaseCount"] = 0
        released["leaseEvents"].append(
            {
                "eventId": "levt_0000000000003124",
                "sourceRevision": released["revision"],
                "operation": "lease_released",
                "leaseId": reservation["leaseId"],
                "jobId": reservation["jobId"],
                "purpose": "verification",
                "credentialRevision": reservation["credentialRevision"],
                "bindingDigest": reservation["bindingDigest"],
                "fromLeaseCount": 1,
                "toLeaseCount": 0,
                "actor": copy.deepcopy(self.VERIFIER),
                "ownerApproval": None,
                "createdAt": "2026-09-02T09:33:59Z",
                "reason": "版本冲突后只释放已终止的 verifier，不发布陈旧结果",
            }
        )
        self._validate_transition(edited, released)

    def test_verification_failure_drain_completes_as_lifecycle_work(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        reserved = self._verification_reserved(
            source,
            event_id="sevt_0000000000003131",
            event_at="2026-09-02T09:21:00Z",
            lease_id="lease_0000000000003131",
            job_id="job_0000000000003131",
        )
        failed = self._verification_result(
            reserved,
            passed=False,
            event_id="sevt_0000000000003132",
            event_at="2026-09-02T09:22:00Z",
        )
        completed = self._revision(
            failed,
            operation="verification_failed",
            to_state="verification_failed",
            event_id="sevt_0000000000003133",
            event_at="2026-09-02T09:23:00Z",
            actor=self.LIFECYCLE,
        )
        completed["credentialLifecycle"] = {
            "state": "active",
            "activeLeaseCount": 0,
            "pendingOperation": None,
            "retireAfter": None,
        }

        self._validate_transition(source, reserved)
        self._validate_transition(reserved, failed)
        contracts.schema_validator("source-v1.schema.json").validate(completed)
        self._validate_transition(failed, completed)

    def test_source_audit_rejects_self_asserted_authority(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        resolver = self._audit_resolver(source)

        forged_system = copy.deepcopy(source)
        forged_system["transitionEvents"][2]["actor"]["id"] = "source-lifecycle"
        with self.assertRaisesRegex(ValueError, "not authoritative"):
            contracts.validate_source_semantics(forged_system, resolver)

        forged_owner = copy.deepcopy(source)
        forged_owner["transitionEvents"][-1]["actor"]["id"] = "attacker"
        with self.assertRaisesRegex(ValueError, "trusted Source audit record"):
            contracts.validate_source_semantics(forged_owner, resolver)

    def test_registered_snapshot_cannot_self_assert_passed_verification(self) -> None:
        draft = self._draft()
        resolver = self._audit_resolver(draft)
        forged = copy.deepcopy(draft)
        enabled = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        forged["version"] = copy.deepcopy(enabled["version"])
        forged["capabilities"] = copy.deepcopy(enabled["capabilities"])
        forged["verification"] = copy.deepcopy(enabled["verification"])
        with self.assertRaisesRegex(ValueError, "snapshot digest"):
            contracts.validate_source_semantics(forged, resolver)

        self_attested = copy.deepcopy(draft)
        self_attested["version"] = copy.deepcopy(enabled["version"])
        self_attested["capabilities"] = copy.deepcopy(enabled["capabilities"])
        self_attested["verification"] = copy.deepcopy(enabled["verification"])
        with self.assertRaisesRegex(ValueError, "trusted verifier result"):
            contracts.validate_source_semantics(
                self_attested, self._audit_resolver(self_attested)
            )

    def test_owner_actions_require_committed_idempotency_receipts(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        trusted = self._audit_resolver(source)

        def missing_receipt(record_id: str) -> dict[str, Any] | None:
            record = trusted(record_id)
            if (
                record is not None
                and record_id == source["transitionEvents"][0]["eventId"]
            ):
                record.pop("idempotencyReceiptId")
            return record

        with self.assertRaisesRegex(ValueError, "idempotency receipt"):
            contracts.validate_source_semantics(source, missing_receipt)

    def test_verifier_audit_chain_requires_one_idempotency_receipt(self) -> None:
        _, disabled = self._unverified_disabled()
        reserved = self._verification_reserved(
            disabled,
            event_id="sevt_0000000000003191",
            event_at="2026-09-02T09:31:00Z",
            lease_id="lease_0000000000003191",
            job_id="job_0000000000003191",
        )
        verified = self._verification_result(
            reserved,
            passed=True,
            event_id="sevt_0000000000003192",
            event_at="2026-09-02T09:32:00Z",
        )
        trusted = self._audit_resolver(disabled, reserved, verified)
        audited_ids = {
            trusted(event_id).get("idempotencyReceiptId")
            for event_id in (
                reserved["transitionEvents"][-1]["eventId"],
                reserved["leaseEvents"][-1]["eventId"],
                verified["transitionEvents"][-1]["eventId"],
                verified["leaseEvents"][-1]["eventId"],
            )
        }
        self.assertEqual(len(audited_ids), 1)
        self.assertNotIn(None, audited_ids)

        acquisition_id = reserved["leaseEvents"][-1]["eventId"]

        def missing_receipt(record_id: str) -> dict[str, Any] | None:
            record = trusted(record_id)
            if record is not None and record_id == acquisition_id:
                record.pop("idempotencyReceiptId")
            return record

        with self.assertRaisesRegex(ValueError, "idempotency receipt"):
            contracts.validate_source_semantics(reserved, missing_receipt)

        result_state_id = verified["transitionEvents"][-1]["eventId"]

        def mismatched_receipt(record_id: str) -> dict[str, Any] | None:
            record = trusted(record_id)
            if record is not None and record_id == result_state_id:
                record["idempotencyReceiptId"] = "idem_9999999999999999"
            return record

        with self.assertRaisesRegex(ValueError, "one idempotency receipt"):
            contracts.validate_source_semantics(verified, mismatched_receipt)

    def test_idempotency_receipt_cannot_authorize_distinct_source_intents(
        self,
    ) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        trusted = self._audit_resolver(source)
        registered_id = source["transitionEvents"][0]["eventId"]
        enabled_id = source["transitionEvents"][-1]["eventId"]
        registered_receipt = trusted(registered_id)["idempotencyReceiptId"]

        def reused_owner_receipt(record_id: str) -> dict[str, Any] | None:
            record = trusted(record_id)
            if record is not None and record_id == enabled_id:
                record["idempotencyReceiptId"] = registered_receipt
            return record

        with self.assertRaisesRegex(ValueError, "distinct Source intents"):
            contracts.validate_source_semantics(source, reused_owner_receipt)

        _, disabled = self._unverified_disabled()
        first_reserved = self._verification_reserved(
            disabled,
            event_id="sevt_0000000000003183",
            event_at="2026-09-02T09:31:00Z",
            lease_id="lease_0000000000003183",
            job_id="job_0000000000003183",
        )
        first_verified = self._verification_result(
            first_reserved,
            passed=True,
            event_id="sevt_0000000000003184",
            event_at="2026-09-02T09:32:00Z",
        )
        second_reserved = self._verification_reserved(
            first_verified,
            event_id="sevt_0000000000003195",
            event_at="2026-09-02T09:33:00Z",
            lease_id="lease_0000000000003195",
            job_id="job_0000000000003195",
        )
        second_verified = self._verification_result(
            second_reserved,
            passed=True,
            event_id="sevt_0000000000003196",
            event_at="2026-09-02T09:34:00Z",
        )
        two_jobs = self._audit_resolver(
            disabled,
            first_reserved,
            first_verified,
            second_reserved,
            second_verified,
        )
        first_receipt = two_jobs(first_reserved["leaseEvents"][-1]["eventId"])[
            "idempotencyReceiptId"
        ]
        second_event_ids = {
            second_reserved["transitionEvents"][-1]["eventId"],
            second_reserved["leaseEvents"][-1]["eventId"],
            second_verified["transitionEvents"][-1]["eventId"],
            second_verified["leaseEvents"][-1]["eventId"],
        }

        def reused_verifier_receipt(record_id: str) -> dict[str, Any] | None:
            record = two_jobs(record_id)
            if record is not None and record_id in second_event_ids:
                record["idempotencyReceiptId"] = first_receipt
            return record

        with self.assertRaisesRegex(ValueError, "distinct Source intents"):
            contracts.validate_source_semantics(
                second_verified,
                reused_verifier_receipt,
            )

    def test_reservation_audit_proves_commit_and_execution_termination(self) -> None:
        _, disabled = self._unverified_disabled()
        reserved = self._verification_reserved(
            disabled,
            event_id="sevt_0000000000003201",
            event_at="2026-09-02T09:31:00Z",
            lease_id="lease_0000000000003201",
            job_id="job_0000000000003201",
        )
        verified = self._verification_result(
            reserved,
            passed=True,
            event_id="sevt_0000000000003202",
            event_at="2026-09-02T09:32:00Z",
        )

        reserved_audit = self._audit_resolver(disabled, reserved)

        def uncommitted(record_id: str) -> dict[str, Any] | None:
            record = reserved_audit(record_id)
            if (
                record is not None
                and record_id == reserved["leaseEvents"][-1]["eventId"]
            ):
                record["committedBeforeCredentialUse"] = False
            return record

        with self.assertRaisesRegex(ValueError, "before credential use"):
            contracts.validate_source_semantics(reserved, uncommitted)

        result_audit = self._audit_resolver(disabled, reserved, verified)
        release_id = verified["leaseEvents"][-1]["eventId"]

        def unterminated(record_id: str) -> dict[str, Any] | None:
            record = result_audit(record_id)
            if record is not None and record_id == release_id:
                record["executionTerminated"] = False
            return record

        with self.assertRaisesRegex(ValueError, "before execution termination"):
            contracts.validate_source_semantics(verified, unterminated)

    def test_force_cancel_requires_an_idempotent_trusted_owner_command(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        leased, draining, drained = contracts.build_source_lease_drain(source)
        trusted = self._audit_resolver(source, leased, draining, drained)
        force_event_id = next(
            event["eventId"]
            for event in drained["leaseEvents"]
            if event["operation"] == "lease_force_cancelled"
        )

        def missing_command_receipt(record_id: str) -> dict[str, Any] | None:
            record = trusted(record_id)
            if record is not None and record_id == force_event_id:
                record.pop("commandReceiptId", None)
            return record

        with self.assertRaisesRegex(ValueError, "force-cancel command receipt"):
            contracts.validate_source_semantics(drained, missing_command_receipt)

    def test_force_cancel_owner_approval_must_follow_drain_admission(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        for approved_at in (
            "2026-09-02T09:24:30Z",
            "2026-09-02T09:25:00Z",
        ):
            leased, draining, drained = contracts.build_source_lease_drain(source)
            force_event = next(
                event
                for event in drained["leaseEvents"]
                if event["operation"] == "lease_force_cancelled"
            )
            force_event["ownerApproval"]["approvedAt"] = approved_at
            trusted = self._audit_resolver(source, leased, draining, drained)

            with (
                self.subTest(approved_at=approved_at),
                self.assertRaisesRegex(ValueError, "after drain admission"),
            ):
                contracts.validate_source_semantics(drained, trusted)

    def test_verification_reservation_uses_unified_drain_barrier(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        reserved = self._verification_reserved(
            source,
            event_id="sevt_0000000000003301",
            event_at="2026-09-02T09:21:00Z",
            lease_id="lease_0000000000003301",
            job_id="job_0000000000003301",
        )
        draining, unsafe_completion = contracts.build_source_rotation(reserved)
        self._validate_transition(source, reserved)
        self._validate_transition(reserved, draining)
        with self.assertRaisesRegex(ValueError, "active leases"):
            self._validate_transition(draining, unsafe_completion)

    def test_source_allows_only_one_verification_reservation(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        first = self._verification_reserved(
            source,
            event_id="sevt_0000000000003401",
            event_at="2026-09-02T09:21:00Z",
            lease_id="lease_0000000000003401",
            job_id="job_0000000000003401",
        )
        second = self._verification_reserved(
            first,
            event_id="sevt_0000000000003402",
            event_at="2026-09-02T09:22:00Z",
            lease_id="lease_0000000000003402",
            job_id="job_0000000000003402",
        )
        self._validate_transition(source, first)
        with self.assertRaisesRegex(ValueError, "only one verification reservation"):
            self._validate_transition(first, second)

    def test_failed_reverification_releases_only_verifier_and_starts_drain(
        self,
    ) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        source["budgets"]["maxConcurrency"] = 3
        leased, _, _ = contracts.build_source_lease_drain(source)
        reserved = self._verification_reserved(
            leased,
            event_id="sevt_0000000000003501",
            event_at="2026-09-02T09:23:30Z",
            lease_id="lease_0000000000003501",
            job_id="job_0000000000003501",
        )
        failed = self._verification_result(
            reserved,
            passed=False,
            event_id="sevt_0000000000003502",
            event_at="2026-09-02T09:24:00Z",
        )

        self._validate_transition(source, leased)
        self._validate_transition(leased, reserved)
        self._validate_transition(reserved, failed)
        self.assertEqual(failed["state"], "draining")
        self.assertEqual(
            failed["credentialLifecycle"]["pendingOperation"],
            "verification_failure",
        )
        self.assertEqual(
            {item["purpose"] for item in failed["activeLeases"]}, {"diagnosis"}
        )
        self.assertEqual(len(failed["activeLeases"]), 2)

    def test_verified_revision_requires_fresh_passed_projection(self) -> None:
        disabled, verified = self._verified_disabled()
        verified["verification"] = copy.deepcopy(disabled["verification"])
        with self.assertRaisesRegex(ValueError, "fresh passed verification"):
            self._validate_transition(disabled, verified)

    def test_owner_cannot_publish_or_replay_a_pass(self) -> None:
        disabled, verified = self._verified_disabled()
        owner_forgery = copy.deepcopy(verified)
        owner_forgery["transitionEvents"][-1].update(actor=copy.deepcopy(self.OWNER))
        with self.assertRaisesRegex(ValueError, "not authored by its verifier"):
            self._validate_transition(disabled, owner_forgery)

        _, old_pass = self._verified_disabled()
        reserved = self._verification_reserved(
            old_pass,
            event_id="sevt_0000000000002101",
            event_at="2026-09-02T09:32:00Z",
            lease_id="lease_0000000000002101",
            job_id="job_0000000000002101",
        )
        stale = self._verification_result(
            reserved,
            passed=True,
            event_id="sevt_0000000000002102",
            event_at="2026-09-02T09:33:00Z",
        )
        stale["verification"] = copy.deepcopy(old_pass["verification"])
        with self.assertRaisesRegex(ValueError, "fresh passed verification"):
            self._validate_transition(reserved, stale)

    def test_failed_reverification_cannot_retain_stale_pass(self) -> None:
        disabled, failed = self._failed_source()
        failed["verification"] = {
            "status": "passed",
            "testedAt": disabled["updatedAt"],
            "identityDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "errorCode": None,
        }
        with self.assertRaisesRegex(ValueError, "fresh failed verification"):
            self._validate_transition(disabled, failed)

    def test_verifier_cannot_rewrite_input_or_identity(self) -> None:
        disabled, verified = self._verified_disabled()
        verified["endpoint"]["host"] = "unverified.prod.internal"
        with self.assertRaisesRegex(ValueError, "tested input: endpoint"):
            self._validate_transition(disabled, verified)

        _, verified = self._verified_disabled()
        verified["transitionEvents"][-1]["actor"]["id"] = "source-lifecycle"
        with self.assertRaisesRegex(ValueError, "not authored by its verifier"):
            self._validate_transition(disabled, verified)

        forged_history = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        resolver = self._audit_resolver(forged_history)
        forged_history["transitionEvents"][2]["actor"]["id"] = "source-lifecycle"
        with self.assertRaisesRegex(ValueError, "system actor is not authoritative"):
            contracts.validate_source_semantics(forged_history, resolver)

    def test_scope_change_cannot_reuse_stale_pass(self) -> None:
        _, disabled = self._verified_disabled()
        for index, schemas in enumerate(
            (["order_center", "unverified_sensitive_schema"], []), start=1
        ):
            stale = self._edit_source(
                disabled,
                event_id=f"sevt_00000000000022{index:02d}",
                event_at=f"2026-09-02T09:32:0{index}Z",
                allowed_schemas=schemas,
            )
            with (
                self.subTest(schemas=schemas),
                self.assertRaisesRegex(
                    ValueError, "verification-bound edit must invalidate"
                ),
            ):
                self._validate_transition(disabled, stale)

    def test_allowed_schema_reordering_preserves_the_same_verification(self) -> None:
        _, disabled = self._unverified_disabled()
        expanded = self._edit_source(
            disabled,
            event_id="sevt_0000000000002291",
            event_at="2026-09-02T09:31:00Z",
            allowed_schemas=["order_center", "reporting"],
            invalidate=True,
        )
        reserved = self._verification_reserved(
            expanded,
            event_id="sevt_0000000000002292",
            event_at="2026-09-02T09:32:00Z",
            lease_id="lease_0000000000002292",
            job_id="job_0000000000002292",
        )
        verified = self._verification_result(
            reserved,
            passed=True,
            event_id="sevt_0000000000002293",
            event_at="2026-09-02T09:33:00Z",
        )
        reordered = self._edit_source(
            verified,
            event_id="sevt_0000000000002294",
            event_at="2026-09-02T09:34:00Z",
            allowed_schemas=["reporting", "order_center"],
        )

        self._validate_transition(disabled, expanded)
        self._validate_transition(expanded, reserved)
        self._validate_transition(reserved, verified)
        self._validate_transition(verified, reordered)
        self.assertEqual(reordered["verification"], verified["verification"])

    def test_verification_binding_uses_canonical_utf16_set_order(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        source["allowedSchemas"] = ["\ue000", "\U00010000"]

        binding = source_verification_binding(source)

        self.assertEqual(binding["allowedSchemas"], ["\U00010000", "\ue000"])

    def test_enabled_source_cannot_change_verified_endpoint_or_scope(self) -> None:
        enabled = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        endpoint = copy.deepcopy(enabled["endpoint"])
        endpoint["host"] = "unverified.prod.internal"
        cases = ({"endpoint": endpoint}, {"allowed_schemas": ["other"]})
        for index, changes in enumerate(cases, start=1):
            edited = self._edit_source(
                enabled,
                event_id=f"sevt_00000000000023{index:02d}",
                event_at=f"2026-09-02T09:21:0{index}Z",
                **changes,
            )
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(ValueError, "must be disabled"),
            ):
                self._validate_transition(enabled, edited)

    def test_bound_edit_invalidates_and_failed_source_returns_to_draft(self) -> None:
        _, disabled = self._verified_disabled()
        disabled_edit = self._edit_source(
            disabled,
            event_id="sevt_0000000000002401",
            event_at="2026-09-02T09:32:00Z",
            allowed_schemas=["replacement_schema"],
            invalidate=True,
        )
        self._validate_transition(disabled, disabled_edit)

        _, failed = self._failed_source()
        failed_edit = self._edit_source(
            failed,
            event_id="sevt_0000000000002402",
            event_at="2026-09-02T09:32:00Z",
            endpoint={**failed["endpoint"], "host": "replacement.prod.internal"},
            invalidate=True,
            to_state="draft",
        )
        self._validate_transition(failed, failed_edit)

    def test_metadata_edit_preserves_projection_and_credential_identity(self) -> None:
        _, disabled = self._verified_disabled()
        edited = self._edit_source(
            disabled,
            event_id="sevt_0000000000002501",
            event_at="2026-09-02T09:32:00Z",
        )
        edited.update(name="生产订单集群（别名）", associatedSourceIds=[])
        edited["budgets"]["ratePerMinute"] = 20
        self._validate_transition(disabled, edited)

        cleared = self._edit_source(
            disabled,
            event_id="sevt_0000000000002502",
            event_at="2026-09-02T09:32:01Z",
            invalidate=True,
        )
        with self.assertRaisesRegex(ValueError, "metadata-only edit"):
            self._validate_transition(disabled, cleared)

        for index, (field, value) in enumerate(
            (("username", "another-user"), ("expiresAt", "2027-01-01T00:00:00Z")),
            start=3,
        ):
            relabeled = self._edit_source(
                disabled,
                event_id=f"sevt_00000000000025{index:02d}",
                event_at=f"2026-09-02T09:32:0{index}Z",
            )
            relabeled["auth"][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    ValueError, "credential metadata changed outside rotation/delete"
                ),
            ):
                self._validate_transition(disabled, relabeled)

    def test_rotation_stops_unverified_credential_before_admission(self) -> None:
        enabled = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        draining, safe = contracts.build_source_rotation(enabled)
        contracts.schema_validator("source-v1.schema.json").validate(safe)
        self._validate_transition(draining, safe)

        immediately_enabled = copy.deepcopy(safe)
        immediately_enabled["state"] = "enabled"
        immediately_enabled["transitionEvents"][-1]["toState"] = "enabled"
        stale_pass = copy.deepcopy(safe)
        for candidate in (immediately_enabled, stale_pass):
            candidate["version"] = copy.deepcopy(enabled["version"])
            candidate["capabilities"] = copy.deepcopy(enabled["capabilities"])
            candidate["verification"] = copy.deepcopy(enabled["verification"])
            with (
                self.subTest(state=candidate["state"]),
                self.assertRaisesRegex(
                    ValueError, "rotated credential must remain disabled and unverified"
                ),
            ):
                self._validate_transition(draining, candidate)

        unrelated_rewrite = copy.deepcopy(safe)
        unrelated_rewrite["owner"]["reference"] = "attacker-owned"
        with self.assertRaisesRegex(ValueError, "rotation completion rewrites"):
            self._validate_transition(draining, unrelated_rewrite)

    def test_rotated_credential_can_be_verified_then_enabled(self) -> None:
        enabled_fixture = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        _, rotated = contracts.build_source_rotation(enabled_fixture)
        reserved = self._verification_reserved(
            rotated,
            event_id="sevt_0000000000002601",
            event_at="2026-09-02T09:31:00Z",
            lease_id="lease_0000000000002601",
            job_id="job_0000000000002601",
        )
        verified = self._verification_result(
            reserved,
            passed=True,
            event_id="sevt_0000000000002602",
            event_at="2026-09-02T09:32:00Z",
        )
        enabled = self._revision(
            verified,
            operation="enabled",
            to_state="enabled",
            event_id="sevt_0000000000002603",
            event_at="2026-09-02T09:33:00Z",
            actor=self.OWNER,
        )
        for prior, proposed in (
            (rotated, reserved),
            (reserved, verified),
            (verified, enabled),
        ):
            self._validate_transition(prior, proposed)

    def test_lifecycle_event_cannot_rewrite_scope_or_projection(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        draining, _ = contracts.build_source_rotation(source)
        changed_scope = copy.deepcopy(draining)
        changed_scope["allowedSchemas"] = ["unverified_sensitive_schema"]
        with self.assertRaisesRegex(ValueError, "changed outside edit/delete"):
            self._validate_transition(source, changed_scope)

        cleared = copy.deepcopy(draining)
        self._invalidate(cleared)
        with self.assertRaisesRegex(ValueError, "rewrites verification projection"):
            self._validate_transition(source, cleared)

    def test_operations_cannot_rewrite_unrelated_source_fields(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        leased, rotation_started, leases_drained = contracts.build_source_lease_drain(
            source
        )

        _, verified_disabled = self._verified_disabled()
        enabled = self._revision(
            verified_disabled,
            operation="enabled",
            to_state="enabled",
            event_id="sevt_0000000000002651",
            event_at="2026-09-02T09:35:00Z",
            actor=self.OWNER,
        )

        draft = self._draft()
        delete_started, tombstoned = self._delete_chain(draft, suffix="00000000000026")

        verification_reserved = self._verification_reserved(
            source,
            event_id="sevt_0000000000002661",
            event_at="2026-09-02T09:21:00Z",
            lease_id="lease_0000000000002661",
            job_id="job_0000000000002661",
        )
        verification_failure_started = self._verification_result(
            verification_reserved,
            passed=False,
            event_id="sevt_0000000000002662",
            event_at="2026-09-02T09:22:00Z",
        )
        verification_failed = self._revision(
            verification_failure_started,
            operation="verification_failed",
            to_state="verification_failed",
            event_id="sevt_0000000000002663",
            event_at="2026-09-02T09:23:00Z",
            actor=self.LIFECYCLE,
        )
        verification_failed["credentialLifecycle"] = {
            "state": "active",
            "activeLeaseCount": 0,
            "pendingOperation": None,
            "retireAfter": None,
        }

        cases = (
            ("enabled", verified_disabled, enabled, "name"),
            ("leases_updated", source, leased, "owner"),
            ("rotation_started", leased, rotation_started, "name"),
            ("leases_drained", rotation_started, leases_drained, "budgets"),
            ("delete_started", draft, delete_started, "name"),
            ("tombstoned", delete_started, tombstoned, "owner"),
            (
                "verification_failed completion",
                verification_failure_started,
                verification_failed,
                "name",
            ),
        )
        for label, prior, proposed, field in cases:
            with self.subTest(operation=label, positive=True):
                self._validate_transition(prior, proposed)

            rewritten = copy.deepcopy(proposed)
            if field == "owner":
                rewritten[field]["reference"] = "attacker-owned"
            elif field == "budgets":
                rewritten[field]["ratePerMinute"] += 1
            else:
                rewritten[field] = "越权改写"
            with (
                self.subTest(operation=label, field=field),
                self.assertRaisesRegex(
                    ValueError, "operation rewrites unrelated Source field"
                ),
            ):
                self._validate_transition(prior, rewritten)

    def test_source_revision_time_matches_its_state_audit(self) -> None:
        _, verified_disabled = self._verified_disabled()
        enabled = self._revision(
            verified_disabled,
            operation="enabled",
            to_state="enabled",
            event_id="sevt_0000000000002671",
            event_at="2026-09-02T09:35:00Z",
            actor=self.OWNER,
        )
        enabled["updatedAt"] = "2026-09-02T09:35:01Z"

        with self.assertRaisesRegex(ValueError, "updatedAt must match"):
            self._validate_transition(verified_disabled, enabled)

        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        source["createdAt"] = "2026-09-02T08:59:59Z"
        with self.assertRaisesRegex(ValueError, "createdAt must match"):
            contracts.validate_source_semantics(source, self._audit_resolver(source))

    def test_tombstone_clears_every_live_source_projection(self) -> None:
        draft = self._draft()
        draining, tombstoned = self._delete_chain(draft, suffix="00000000000031")
        source_schema = contracts.schema_validator("source-v1.schema.json")
        self.assertEqual(list(source_schema.iter_errors(tombstoned)), [])
        live_projection = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        cases = {
            "endpoint": {
                **tombstoned["endpoint"],
                "host": draft["endpoint"]["host"],
            },
            "auth": {**tombstoned["auth"], "expiresAt": "2027-01-01T00:00:00Z"},
            "associatedSourceIds": ["src_0000000000009999"],
            "allowedSchemas": ["sensitive_schema"],
            "version": copy.deepcopy(live_projection["version"]),
            "capabilities": copy.deepcopy(live_projection["capabilities"]),
        }
        for field, value in cases.items():
            unsafe = copy.deepcopy(tombstoned)
            unsafe[field] = value
            with self.subTest(field=field, boundary="json-schema"):
                self.assertTrue(list(source_schema.iter_errors(unsafe)))
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "metadata-only tombstone"),
            ):
                self._validate_transition(draining, unsafe)

    def test_zero_lease_draft_and_failed_sources_can_be_deleted(self) -> None:
        _, failed = self._failed_source()
        _, verified_disabled = self._verified_disabled()
        for source, suffix in (
            (self._draft(), "00000000000027"),
            (failed, "00000000000028"),
            (verified_disabled, "00000000000032"),
        ):
            draining, tombstone = self._delete_chain(source, suffix=suffix)
            self.assertEqual(draining["verification"], source["verification"])
            for prior, proposed in ((source, draining), (draining, tombstone)):
                contracts.schema_validator("source-v1.schema.json").validate(proposed)
                self._validate_transition(prior, proposed)

    def test_delete_drain_cannot_rewrite_failed_verification(self) -> None:
        _, failed = self._failed_source()
        draining, _ = self._delete_chain(failed, suffix="00000000000029")
        draining["verification"] = copy.deepcopy(self.NOT_RUN)
        with self.assertRaisesRegex(ValueError, "delete drain rewrites"):
            self._validate_transition(failed, draining)

    def test_standalone_delete_drain_cannot_invent_failed_verification(self) -> None:
        _, disabled = self._verified_disabled()
        draining, _ = self._delete_chain(disabled, suffix="00000000000030")
        draining["verification"] = {
            "status": "failed",
            "testedAt": draining["updatedAt"],
            "identityDigest": None,
            "errorCode": "SOURCE_IDENTITY_MISMATCH",
        }
        with self.assertRaisesRegex(ValueError, "delete drain failure must originate"):
            contracts.validate_source_semantics(draining)

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

    def test_reservation_revision_cannot_mix_acquisition_and_release(self) -> None:
        source = contracts.load(contracts.EXAMPLES / "source-v1.valid.json")
        leased, _, _ = contracts.build_source_lease_drain(source)
        poisoned = copy.deepcopy(leased)
        acquired = poisoned["leaseEvents"][-1]
        released = copy.deepcopy(acquired)
        released.update(
            eventId="levt_0000000000000998",
            operation="lease_released",
            fromLeaseCount=2,
            toLeaseCount=1,
            createdAt=self._one_second_before(poisoned["updatedAt"]),
            reason="同一 revision 取得并释放 reservation",
        )
        poisoned["leaseEvents"].append(released)
        poisoned["activeLeases"] = poisoned["activeLeases"][:1]
        poisoned["credentialLifecycle"]["activeLeaseCount"] = 1
        with self.assertRaisesRegex(ValueError, "cannot mix acquisition and release"):
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
