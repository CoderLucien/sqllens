# QA-003: DiagnosisCase Cannot Represent Approved Terminal Outcomes

Status: RESOLVED at contract layer; runtime integration retest pending
Severity: High
Detected against: `main@1c3c271`
Resolved in: `main@c7fbe83`
Owner: contract/domain owner (`#t8`), not QA
Regression tests: `tests/qa/test_diagnosis_case_contract.py`

## Requirement

The approved customer journey limits a completed diagnosis case to four
business outcomes:

- validated effective;
- ineffective and rolled back;
- evidence insufficient;
- risk accepted.

QA case `CASE-007` requires these outcomes to remain separate from workflow
processing state.

## Actual

`DiagnosisCaseV1.outcome` currently contains:

```text
not_reviewed, accepted, rejected, implemented, validated, rolled_back
```

It cannot persist `evidence_insufficient` or `risk_accepted`, and `validated`
does not say whether an implemented change was effective. Review decisions and
implementation milestones already have dedicated append-only records, so
encoding them as business outcomes also mixes process with result.

## Reproduction

```bash
python3 -m unittest \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_outcome_contract_can_represent_all_approved_terminal_states \
  -v
```

Expected: the schema can represent all four approved terminal results.

Actual at detection: the test reports missing `validated_effective`,
`evidence_insufficient`, and `risk_accepted`, and reports the review/
implementation process states still present in the outcome field.

## Independent Retest

On `main@c7fbe83`, QA verified all four terminal outcomes, all 25 outcome
transition pairs, same-revision trigger requirements and five non-mutating
legacy draft aliases. The focused test and independent adversarial matrix pass.
The production persistence/API path does not exist yet, so runtime acceptance
remains blocked.

## Required Disposition

Before contract freeze, product/domain owners must define outcome names,
transitions and prerequisites that preserve all four approved results. QA does
not require deleting legacy values needed to read an older case, but every
review/implementation process value retained in the schema must be explicitly
classified as read-only legacy and excluded from all new revision transition
targets. New cases and completed cases must use the unambiguous business-result
states, with process events in their dedicated review/feedback records.
