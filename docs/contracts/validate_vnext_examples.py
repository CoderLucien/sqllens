from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).parent
EXAMPLES = ROOT / "examples"
FORMAT_CHECKER = FormatChecker()


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_schema(schema_name: str, example_names: list[str]) -> list[dict[str, Any]]:
    schema = load(ROOT / schema_name)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)
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


def validate_case_references(case: dict[str, Any]) -> None:
    source_ids = require_unique(case["sourceSnapshots"], "sourceId")
    evidence_ids = require_unique(case["evidence"], "evidenceId")
    fact_ids = require_unique(case["facts"], "factId")
    rule_ids = require_unique(case["ruleFindings"], "ruleId")
    action_ids = require_unique(case["actions"], "actionId")
    _ = fact_ids, action_ids

    for evidence in case["evidence"]:
        source_id = evidence["sourceId"]
        if source_id is not None and source_id not in source_ids:
            raise ValueError(f"dangling evidence source: {source_id}")
    for fact in case["facts"]:
        if not set(fact["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling fact evidence: {fact['factId']}")
    for finding in case["ruleFindings"]:
        if not set(finding["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling rule evidence: {finding['ruleId']}")
    for action in case["actions"]:
        if not set(action["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling action evidence: {action['actionId']}")
        if not set(action["ruleIds"]) <= rule_ids:
            raise ValueError(f"dangling action rule: {action['actionId']}")

    synthesis = case["aiSynthesis"]
    if synthesis is None:
        return
    claim_ids = require_unique(synthesis["claims"], "claimId")
    _ = claim_ids
    for claim in synthesis["claims"]:
        if not set(claim["evidenceIds"]) <= evidence_ids:
            raise ValueError(f"dangling claim evidence: {claim['claimId']}")
        if not set(claim["ruleIds"]) <= rule_ids:
            raise ValueError(f"dangling claim rule: {claim['claimId']}")


def validate_report_projection(report: dict[str, Any], case: dict[str, Any]) -> None:
    if report["caseId"] != case["caseId"] or report["caseRevision"] != case["revision"]:
        raise ValueError("report projection does not identify its source case revision")
    trace = report["trace"]
    evidence_ids = {item["evidenceId"] for item in case["evidence"]}
    rule_ids = {item["ruleId"] for item in case["ruleFindings"]}
    action_ids = {item["actionId"] for item in case["actions"]}
    claim_ids = {
        item["claimId"]
        for item in (case["aiSynthesis"] or {}).get("claims", [])
    }
    if not set(trace["evidenceIds"]) <= evidence_ids:
        raise ValueError("report contains evidence outside its case")
    if not set(trace["ruleIds"]) <= rule_ids:
        raise ValueError("report contains rules outside its case")
    if not set(trace["claimIds"]) <= claim_ids:
        raise ValueError("report contains AI claims outside its case")
    if not {item["actionId"] for item in report["actions"]} <= action_ids:
        raise ValueError("report contains actions outside its case")


def main() -> None:
    validate_schema("source-v1.schema.json", ["source-v1.valid.json"])
    cases = validate_schema(
        "diagnosis-case-v2.schema.json", ["diagnosis-case-v2.valid.json"]
    )
    reports = validate_schema(
        "diagnosis-report-v1.schema.json",
        [
            "diagnosis-report-v1.index-access.review.json",
            "diagnosis-report-v1.statistics.review.json",
            "diagnosis-report-v1.runtime-correlation.review.json",
        ],
    )
    validate_case_references(cases[0])
    validate_report_projection(reports[0], cases[0])
    print("vNext contract examples valid: 1 source, 1 case, 3 report fixtures")


if __name__ == "__main__":
    main()
