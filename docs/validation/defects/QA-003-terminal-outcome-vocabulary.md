# QA-003: DiagnosisCase Cannot Represent Approved Terminal Outcomes

**Status:** OPEN  
**Severity:** High  
**Release impact:** Blocks the `DiagnosisCaseV1` contract freeze and P0
acceptance.

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

Actual: the test reports missing `validated_effective`,
`evidence_insufficient`, and `risk_accepted`.

## Required Disposition

Before contract freeze, product/domain owners must define outcome names,
transitions and prerequisites that preserve all four approved results. QA does
not prescribe whether interim review/implementation milestones remain in this
field or move entirely to their existing review/feedback records, but every
completed case must be unambiguous and machine-validatable.
