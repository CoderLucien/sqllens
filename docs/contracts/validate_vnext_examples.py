from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, RefResolver

ROOT = Path(__file__).parent
EXAMPLES = ROOT / "examples"
FORMAT_CHECKER = FormatChecker()
SCHEMA_NAMES = (
    "source-v1.schema.json",
    "evidence-v2.schema.json",
    "diagnosis-case-v2.schema.json",
    "diagnosis-report-v1.schema.json",
)
CASE_NAMES = (
    "diagnosis-case-v2.valid.json",
    "diagnosis-case-v2.statistics.valid.json",
    "diagnosis-case-v2.runtime-correlation.valid.json",
)
REPORT_NAMES = (
    "diagnosis-report-v1.index-access.review.json",
    "diagnosis-report-v1.statistics.review.json",
    "diagnosis-report-v1.runtime-correlation.review.json",
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
    "pending": {
        "pending",
        "validated_effective",
        "rolled_back",
        "evidence_insufficient",
        "risk_accepted",
    },
    "validated_effective": {"validated_effective"},
    "rolled_back": {"rolled_back"},
    "evidence_insufficient": {"evidence_insufficient"},
    "risk_accepted": {"risk_accepted"},
}
EVIDENCE_LEVELS = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4}
RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:"
    r"(?:[0-5]\d|60)(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


SCHEMAS = {name: load(ROOT / name) for name in SCHEMA_NAMES}
SCHEMA_STORE = {schema["$id"]: schema for schema in SCHEMAS.values()}


def parse_time(value: str) -> datetime:
    if not RFC3339_DATETIME.fullmatch(value):
        raise ValueError(f"invalid RFC 3339 date-time: {value!r}")
    normalized = value[:10] + "T" + value[11:]
    if normalized[-1] in {"Z", "z"}:
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized)


def schema_validator(name: str) -> Draft202012Validator:
    schema = SCHEMAS[name]
    Draft202012Validator.check_schema(schema)
    resolver = RefResolver.from_schema(schema, store=SCHEMA_STORE)
    return Draft202012Validator(
        schema,
        resolver=resolver,
        format_checker=FORMAT_CHECKER,
    )


def validate_schema(schema_name: str, example_names: list[str]) -> list[dict[str, Any]]:
    validator = schema_validator(schema_name)
    examples: list[dict[str, Any]] = []
    for name in example_names:
        example = load(EXAMPLES / name)
        validator.validate(example)
        examples.append(example)
    return examples


def require_unique(items: list[dict[str, Any]], field: str) -> set[str]:
    values = [str(item[field]) for item in items]
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {field}")
    return set(values)


def validate_source_semantics(source: dict[str, Any]) -> None:
    capability_names = [item["name"] for item in source["capabilities"]]
    if len(capability_names) != len(set(capability_names)):
        raise ValueError("duplicate Source capability name")
    if source["sourceId"] in source["associatedSourceIds"]:
        raise ValueError("Source cannot associate itself")

    required_by_type = {
        "tidb": {"version", "schema"},
        "prometheus": {"prom_query"},
        "tem": {"alert_read"},
        "alertmanager": {"alert_read"},
    }
    if source["state"] == "enabled":
        available = {
            item["name"]
            for item in source["capabilities"]
            if item["status"] == "available"
        }
        missing = required_by_type[source["type"]] - available
        if missing:
            raise ValueError(
                f"enabled Source lacks required capabilities: {sorted(missing)}"
            )

    lifecycle = source["credentialLifecycle"]
    if lifecycle["pendingOperation"] is not None and source["state"] != "draining":
        raise ValueError("pending credential operation requires draining Source")
    if lifecycle["state"] in {"rotating", "retiring"} and source["state"] != "draining":
        raise ValueError("credential retirement requires draining Source")
    if (
        lifecycle["state"] in {"rotating", "retiring"}
        and lifecycle["retireAfter"] is None
    ):
        raise ValueError("draining credential requires a retirement deadline")
    if lifecycle["pendingOperation"] == "rotate" and lifecycle["state"] != "rotating":
        raise ValueError("rotate operation requires rotating credential state")
    if (
        lifecycle["pendingOperation"] in {"disable", "delete"}
        and lifecycle["state"] != "retiring"
    ):
        raise ValueError("disable/delete operation requires retiring credential state")
    if lifecycle["state"] == "tombstoned":
        if source["state"] != "tombstoned" or lifecycle["activeLeaseCount"]:
            raise ValueError("tombstoned Source must have zero active leases")
        if source["auth"]["credentialRef"] is not None:
            raise ValueError("tombstoned Source cannot retain a credential reference")


def validate_evidence_semantics(
    evidence: dict[str, Any],
    case_id: str,
    source_revisions: set[str],
) -> None:
    if evidence["caseId"] != case_id:
        raise ValueError(f"evidence belongs to another case: {evidence['evidenceId']}")
    if parse_time(evidence["observedAt"]) > parse_time(evidence["collectedAt"]):
        raise ValueError(
            f"evidence observed after collection: {evidence['evidenceId']}"
        )
    source_ref = evidence["sourceRef"]
    if source_ref is not None:
        ref = f"{source_ref['sourceId']}@{source_ref['revision']}"
        if ref not in source_revisions:
            raise ValueError(f"evidence has unknown Source revision: {ref}")

    payload = evidence["payload"]
    collection = evidence["collection"]
    budget = collection["budget"]
    if payload["digest"] != evidence["integrityDigest"]:
        raise ValueError(
            f"evidence and payload digests differ: {evidence['evidenceId']}"
        )
    if payload["truncated"] != (collection["status"] == "truncated"):
        raise ValueError(f"evidence truncation state differs: {evidence['evidenceId']}")
    if budget["elapsedMs"] > budget["timeoutMs"]:
        raise ValueError(f"evidence exceeded timeout budget: {evidence['evidenceId']}")
    if budget["rowsRead"] > budget["maxRows"]:
        raise ValueError(f"evidence exceeded row budget: {evidence['evidenceId']}")
    if budget["bytesRead"] > budget["maxBytes"]:
        raise ValueError(f"evidence exceeded byte budget: {evidence['evidenceId']}")


def validate_transition_events(case: dict[str, Any]) -> None:
    require_unique(case["transitionEvents"], "eventId")
    created_at = parse_time(case["createdAt"])
    updated_at = parse_time(case["updatedAt"])
    previous_event_at: datetime | None = None
    workflow_current: str | None = None
    outcome_current = "pending"
    saw_workflow = False

    for event in case["transitionEvents"]:
        event_at = parse_time(event["createdAt"])
        if not created_at <= event_at <= updated_at:
            raise ValueError("transition event is outside the Case time window")
        if previous_event_at is not None and event_at < previous_event_at:
            raise ValueError("transition events must be chronological")
        if event["caseRevision"] > case["revision"]:
            raise ValueError("transition event references a future Case revision")
        previous_event_at = event_at

        if event["type"] == "workflow_state":
            source = event["fromWorkflowState"]
            target = event["toWorkflowState"]
            if not saw_workflow:
                if source is not None or target != "queued":
                    raise ValueError("workflow audit must start at null -> queued")
                saw_workflow = True
            else:
                if source != workflow_current:
                    raise ValueError("workflow transition chain is discontinuous")
                if target not in WORKFLOW_TRANSITIONS[source]:
                    raise ValueError(
                        f"illegal workflow transition: {source} -> {target}"
                    )
            workflow_current = target
        else:
            source = event["fromOutcome"]
            target = event["toOutcome"]
            if source != outcome_current:
                raise ValueError("outcome transition chain is discontinuous")
            if target not in OUTCOME_TRANSITIONS[source]:
                raise ValueError(f"illegal outcome transition: {source} -> {target}")
            outcome_current = target

    if workflow_current != case["workflowState"]:
        raise ValueError("latest workflow transition does not match Case state")
    if outcome_current != case["outcome"]:
        raise ValueError("latest outcome transition does not match Case outcome")
    if case["outcome"] != "pending" and not any(
        event["type"] == "outcome"
        and event["caseRevision"] == case["revision"]
        and event["toOutcome"] == case["outcome"]
        for event in case["transitionEvents"]
    ):
        raise ValueError(
            "terminal outcome requires a transition event in this revision"
        )


def validate_outcome_semantics(case: dict[str, Any]) -> None:
    outcome = case["outcome"]
    if outcome == "pending":
        return
    action_ids = {item["actionId"] for item in case["actions"]}
    evidence_by_id = {item["evidenceId"]: item for item in case["evidence"]}
    current_events = [
        event
        for event in case["transitionEvents"]
        if event["type"] == "outcome"
        and event["caseRevision"] == case["revision"]
        and event["toOutcome"] == outcome
    ]

    if outcome == "risk_accepted":
        reviews = [
            item
            for item in case["reviews"]
            if item["decision"] == "risk_accepted"
            and item["caseRevision"] == case["revision"]
            and set(item["actionIds"]) & action_ids
        ]
        if not reviews or not any(
            any(
                review["reviewId"] in event["reviewIds"]
                and bool(set(review["actionIds"]) & set(event["actionIds"]))
                for review in reviews
            )
            for event in current_events
        ):
            raise ValueError(
                "risk_accepted requires linked review and transition event"
            )
        return

    if outcome == "evidence_insufficient":
        feedback = [
            item
            for item in case["feedback"]
            if item["kind"] == outcome and item["caseRevision"] == case["revision"]
        ]
        if not feedback or not any(
            any(item["feedbackId"] in event["feedbackIds"] for item in feedback)
            for event in current_events
        ):
            raise ValueError(
                "evidence_insufficient requires feedback and transition event"
            )
        return

    terminal_kind = "validated" if outcome == "validated_effective" else "rolled_back"
    required_evidence = (
        {"effect_metric_comparison"}
        if outcome == "validated_effective"
        else {"effect_metric_comparison", "rollback_confirmation"}
    )
    for terminal in [
        item
        for item in case["feedback"]
        if item["kind"] == terminal_kind and item["caseRevision"] == case["revision"]
    ]:
        action_id = terminal["actionId"]
        if action_id not in action_ids:
            continue
        approvals = [
            item
            for item in case["reviews"]
            if item["decision"] == "approved" and action_id in item["actionIds"]
        ]
        implementations = [
            item
            for item in case["feedback"]
            if item["kind"] == "implemented" and item["actionId"] == action_id
        ]
        result_evidence = [
            evidence_by_id[evidence_id]
            for evidence_id in terminal["evidenceIds"]
            if evidence_id in evidence_by_id
        ]
        if required_evidence - {item["kind"] for item in result_evidence}:
            continue
        terminal_at = parse_time(terminal["createdAt"])
        causal_chain = any(
            parse_time(review["createdAt"])
            <= parse_time(implementation["createdAt"])
            <= min(parse_time(item["observedAt"]) for item in result_evidence)
            <= max(parse_time(item["collectedAt"]) for item in result_evidence)
            <= terminal_at
            for review in approvals
            for implementation in implementations
        )
        if causal_chain:
            for event in current_events:
                if (
                    action_id in event["actionIds"]
                    and set(terminal["evidenceIds"]) <= set(event["evidenceIds"])
                    and terminal["feedbackId"] in event["feedbackIds"]
                    and any(
                        review["reviewId"] in event["reviewIds"] for review in approvals
                    )
                    and any(
                        implementation["feedbackId"] in event["feedbackIds"]
                        for implementation in implementations
                    )
                ):
                    return
    raise ValueError(f"{outcome} lacks one linked, ordered outcome evidence chain")


def validate_case_references(case: dict[str, Any]) -> None:
    source_ids = require_unique(case["sourceSnapshots"], "sourceId")
    source_revisions = {
        f"{item['sourceId']}@{item['revision']}" for item in case["sourceSnapshots"]
    }
    evidence_ids = require_unique(case["evidence"], "evidenceId")
    evidence_by_id = {item["evidenceId"]: item for item in case["evidence"]}
    storage_refs = require_unique(
        [item["payload"] for item in case["evidence"]], "storageRef"
    )
    _ = storage_refs
    require_unique(case["facts"], "factId")
    rule_ids = require_unique(case["ruleFindings"], "ruleId")
    action_ids = require_unique(case["actions"], "actionId")
    review_ids = require_unique(case["reviews"], "reviewId")
    feedback_ids = require_unique(case["feedback"], "feedbackId")

    for evidence in case["evidence"]:
        validate_evidence_semantics(evidence, case["caseId"], source_revisions)
    for fact in case["facts"]:
        if not set(fact["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling fact evidence: {fact['factId']}")
    for finding in case["ruleFindings"]:
        if not set(finding["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling rule evidence: {finding['ruleId']}")
        if (
            finding["status"] == "hit"
            and EVIDENCE_LEVELS[finding["minimumEvidenceLevel"]]
            > EVIDENCE_LEVELS[case["evidenceLevel"]]
        ):
            raise ValueError(f"rule exceeds Case evidence ceiling: {finding['ruleId']}")
    for action in case["actions"]:
        if not set(action["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling action evidence: {action['actionId']}")
        if not set(action["ruleIds"]) <= rule_ids:
            raise ValueError(f"dangling action rule: {action['actionId']}")

    claim_ids: set[str] = set()
    synthesis = case["aiSynthesis"]
    if synthesis is not None:
        claim_ids = require_unique(synthesis["claims"], "claimId")
        for claim in synthesis["claims"]:
            if not set(claim["evidenceIds"]) <= evidence_ids:
                raise ValueError(f"dangling claim evidence: {claim['claimId']}")
            if not set(claim["ruleIds"]) <= rule_ids:
                raise ValueError(f"dangling claim rule: {claim['claimId']}")
    if case["effectiveMode"] == "rules_ai" and (
        synthesis is None or synthesis["status"] != "applied" or not claim_ids
    ):
        raise ValueError("rules_ai effective mode requires applied AI claims")
    if (
        case["effectiveMode"] == "rules"
        and synthesis is not None
        and synthesis["status"] == "applied"
    ):
        raise ValueError("rules effective mode cannot expose applied AI synthesis")

    decision = case["decision"]
    for summary in decision["evidenceSummary"]:
        if not set(summary["evidenceIds"]) <= evidence_ids:
            raise ValueError("decision summary contains dangling evidence")
    if not set(case["subject"]["businessEvidenceIds"]) <= evidence_ids:
        raise ValueError("business impact contains dangling evidence")
    business_evidence = [
        evidence_by_id[evidence_id]
        for evidence_id in case["subject"]["businessEvidenceIds"]
    ]
    if not any(
        item["kind"] == "business_observation"
        and item["summaryZh"] == case["subject"]["businessZh"]
        for item in business_evidence
    ):
        raise ValueError("business impact lacks a matching business observation")
    if not set(decision["evidenceIds"]) <= evidence_ids:
        raise ValueError("decision contains dangling evidence")
    if not set(decision["ruleIds"]) <= rule_ids:
        raise ValueError("decision contains dangling rules")
    if not set(decision["claimIds"]) <= claim_ids:
        raise ValueError("decision contains dangling AI claims")
    if not set(decision["actionIds"]) <= action_ids:
        raise ValueError("decision contains dangling actions")
    if not set(case["subject"]["businessEvidenceIds"]) <= set(decision["evidenceIds"]):
        raise ValueError("decision omits business-impact evidence")

    for review in case["reviews"]:
        if review["caseRevision"] > case["revision"]:
            raise ValueError(
                f"review references a future Case revision: {review['reviewId']}"
            )
        if not (
            parse_time(case["createdAt"])
            <= parse_time(review["createdAt"])
            <= parse_time(case["updatedAt"])
        ):
            raise ValueError(
                f"review is outside the Case time window: {review['reviewId']}"
            )
        if not set(review["actionIds"]) <= action_ids:
            raise ValueError(f"review contains dangling action: {review['reviewId']}")
    for feedback in case["feedback"]:
        if feedback["caseRevision"] > case["revision"]:
            raise ValueError(
                f"feedback references a future Case revision: {feedback['feedbackId']}"
            )
        if not (
            parse_time(case["createdAt"])
            <= parse_time(feedback["createdAt"])
            <= parse_time(case["updatedAt"])
        ):
            raise ValueError(
                f"feedback is outside the Case time window: {feedback['feedbackId']}"
            )
        if feedback["actionId"] is not None and feedback["actionId"] not in action_ids:
            raise ValueError(
                f"feedback contains dangling action: {feedback['feedbackId']}"
            )
        if not set(feedback["evidenceIds"]) <= evidence_ids:
            raise ValueError(
                f"feedback contains dangling evidence: {feedback['feedbackId']}"
            )
    for event in case["transitionEvents"]:
        if event["type"] == "outcome":
            if not set(event["reviewIds"]) <= review_ids:
                raise ValueError(
                    f"transition contains dangling review: {event['eventId']}"
                )
            if not set(event["feedbackIds"]) <= feedback_ids:
                raise ValueError(
                    f"transition contains dangling feedback: {event['eventId']}"
                )
            if not set(event["actionIds"]) <= action_ids:
                raise ValueError(
                    f"transition contains dangling action: {event['eventId']}"
                )
            if not set(event["evidenceIds"]) <= evidence_ids:
                raise ValueError(
                    f"transition contains dangling evidence: {event['eventId']}"
                )

    if not source_ids and case["inputMode"] == "managed_source":
        raise ValueError("managed-source Case requires a Source snapshot")
    validate_transition_events(case)
    validate_outcome_semantics(case)


def build_validated_case(case: dict[str, Any]) -> dict[str, Any]:
    validated = copy.deepcopy(case)
    validated["revision"] = 2
    validated["outcome"] = "validated_effective"
    validated["updatedAt"] = "2026-09-02T08:12:00Z"

    effect = copy.deepcopy(validated["evidence"][-1])
    effect.update(
        {
            "evidenceId": "ev_0000000000000005",
            "kind": "effect_metric_comparison",
            "observedAt": "2026-09-02T08:10:00Z",
            "collectedAt": "2026-09-02T08:11:00Z",
            "integrityDigest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            "summaryZh": "隔离环境验证显示扫描行数下降 94%，P95 降至 420 ms。",
        }
    )
    effect["payload"].update(
        {
            "schemaRevision": "effect-metric-comparison/v1",
            "storageRef": "payload_0000000000000005",
            "digest": effect["integrityDigest"],
        }
    )
    validated["evidence"].append(effect)
    validated["reviews"] = [
        {
            "reviewId": "rev_0000000000000001",
            "caseRevision": 1,
            "reviewer": {
                "kind": "user",
                "id": "owner",
                "displayName": "本机 Owner",
            },
            "decision": "approved",
            "actionIds": ["act_0000000000000001"],
            "createdAt": "2026-09-02T08:06:00Z",
            "comment": "批准隔离环境验证，不批准自动生产变更。",
        }
    ]
    validated["feedback"] = [
        {
            "feedbackId": "fb_0000000000000001",
            "caseRevision": 1,
            "actor": {"kind": "user", "id": "owner", "displayName": "本机 Owner"},
            "kind": "implemented",
            "actionId": "act_0000000000000001",
            "evidenceIds": [],
            "createdAt": "2026-09-02T08:07:00Z",
            "comment": "已在隔离环境创建并验证候选索引。",
        },
        {
            "feedbackId": "fb_0000000000000002",
            "caseRevision": 2,
            "actor": {"kind": "user", "id": "owner", "displayName": "本机 Owner"},
            "kind": "validated",
            "actionId": "act_0000000000000001",
            "evidenceIds": ["ev_0000000000000005"],
            "createdAt": "2026-09-02T08:12:00Z",
            "comment": "隔离环境验证达到预设收益阈值。",
        },
    ]
    validated["transitionEvents"].append(
        {
            "eventId": "evt_0000000000000005",
            "caseRevision": 2,
            "type": "outcome",
            "fromOutcome": "pending",
            "toOutcome": "validated_effective",
            "actor": {"kind": "user", "id": "owner", "displayName": "本机 Owner"},
            "createdAt": "2026-09-02T08:12:00Z",
            "reason": "隔离环境验证达到预设收益阈值",
            "reviewIds": ["rev_0000000000000001"],
            "feedbackIds": [
                "fb_0000000000000001",
                "fb_0000000000000002",
            ],
            "actionIds": ["act_0000000000000001"],
            "evidenceIds": ["ev_0000000000000005"],
        }
    )
    return validated


def projected_action(action: dict[str, Any], order: int) -> dict[str, Any]:
    return {
        "actionId": action["actionId"],
        "order": order,
        "titleZh": action["titleZh"],
        "rationaleZh": action["rationaleZh"],
        "ownerRole": action["ownerRole"],
        "risk": action["risk"],
        "prerequisitesZh": action["prerequisitesZh"],
        "stepsZh": action["stepsZh"],
        "validation": action["validation"],
        "rollbackZh": action["rollbackZh"],
    }


def validate_report_projection(report: dict[str, Any], case: dict[str, Any]) -> None:
    if report["caseId"] != case["caseId"] or report["caseRevision"] != case["revision"]:
        raise ValueError("report projection does not identify its source Case revision")
    decision = case["decision"]
    exact_fields = {
        "titleZh": decision["titleZh"],
        "priority": decision["priority"],
        "configuredMode": case["configuredMode"],
        "effectiveMode": case["effectiveMode"],
        "conclusionZh": decision["conclusionZh"],
        "impact": case["subject"],
        "evidenceSummary": decision["evidenceSummary"],
        "uncertainty": [item["descriptionZh"] for item in case["uncertainty"]],
    }
    for field, expected in exact_fields.items():
        if report[field] != expected:
            raise ValueError(f"report projection rewrites Case field: {field}")

    rules_by_id = {item["ruleId"]: item for item in case["ruleFindings"]}
    claims_by_id = {
        item["claimId"]: item for item in (case["aiSynthesis"] or {}).get("claims", [])
    }
    expected_rule_text = [
        rules_by_id[item]["conclusionZh"] for item in decision["ruleIds"]
    ]
    expected_ai_text = (
        "\n".join(claims_by_id[item]["textZh"] for item in decision["claimIds"])
        if decision["claimIds"]
        else None
    )
    synthesis = case["aiSynthesis"]
    expected_code = (
        synthesis["code"] if synthesis and synthesis["status"] == "degraded" else None
    )
    expected_degradation = synthesis["messageZh"] if expected_code else None
    if report["reasoning"] != {
        "ruleFindingsZh": expected_rule_text,
        "aiContributionZh": expected_ai_text,
        "degradationCode": expected_code,
        "degradationZh": expected_degradation,
    }:
        raise ValueError("report reasoning is not a Case projection")

    actions_by_id = {item["actionId"]: item for item in case["actions"]}
    expected_actions = [
        projected_action(actions_by_id[action_id], order)
        for order, action_id in enumerate(decision["actionIds"], start=1)
    ]
    if report["actions"] != expected_actions:
        raise ValueError("report actions are not a Case projection")

    expected_trace = {
        "evidenceLevel": case["evidenceLevel"],
        "evidenceIds": decision["evidenceIds"],
        "ruleIds": decision["ruleIds"],
        "claimIds": decision["claimIds"],
        "sourceRevisions": [
            f"{item['sourceId']}@{item['revision']}" for item in case["sourceSnapshots"]
        ],
        "pinnedRevisions": [
            value for value in case["pinnedRevisions"].values() if value is not None
        ],
    }
    if report["trace"] != expected_trace:
        raise ValueError("report trace is not the exact decision provenance")


def main() -> None:
    sources = validate_schema(
        "source-v1.schema.json",
        [
            "source-v1.valid.json",
            "source-v1.no-auth-draining.valid.json",
            "source-v1.tombstoned.valid.json",
        ],
    )
    evidence_examples = validate_schema(
        "evidence-v2.schema.json", ["evidence-v2.valid.json"]
    )
    cases = validate_schema("diagnosis-case-v2.schema.json", list(CASE_NAMES))
    reports = validate_schema("diagnosis-report-v1.schema.json", list(REPORT_NAMES))
    for source in sources:
        validate_source_semantics(source)
    for evidence in evidence_examples:
        if evidence["caseId"] != "case_0000000000000002":
            raise ValueError("standalone Evidence fixture has unexpected Case")
    cases_by_revision = {(case["caseId"], case["revision"]): case for case in cases}
    for case in cases:
        validate_case_references(case)
    terminal_case = build_validated_case(cases[0])
    schema_validator("diagnosis-case-v2.schema.json").validate(terminal_case)
    validate_case_references(terminal_case)
    for report in reports:
        key = (report["caseId"], report["caseRevision"])
        if key not in cases_by_revision:
            raise ValueError(f"report has no matching Case fixture: {key}")
        validate_report_projection(report, cases_by_revision[key])
    print(
        "vNext contract examples valid: "
        "3 sources, 1 standalone evidence, 3 cases, 1 terminal transition, "
        "3 reports"
    )


if __name__ == "__main__":
    main()
