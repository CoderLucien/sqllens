# QA-004: One Evidence Item Can Both Support And Contradict A Hypothesis

Status: RESOLVED at contract layer; runtime integration retest pending
Severity: High
Detected against: `main@1c3c271`
Resolved in: `main@c7fbe83`
Owner: contract/domain owner (`#t8`), not QA
Regression tests: `tests/qa/test_diagnosis_case_contract.py`

## Requirement

QA case `CASE-003` requires supporting and contradicting evidence to remain
distinct. The product is evidence-first, so a hypothesis cannot use one atomic
evidence ID as both positive and negative provenance without an explicit,
separately modeled interpretation.

## Actual

The schema makes each evidence-ID array unique internally, but
`validate_references()` does not reject overlap between the two arrays. A case
with the same ID in `supportingEvidenceIds` and `contradictingEvidenceIds`
passes domain reference validation.

## Reproduction

```bash
python3 -m unittest \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_one_evidence_item_cannot_both_support_and_contradict_a_hypothesis \
  -v
```

Expected: domain validation rejects the overlap.

Actual at detection: no exception is raised.

## Independent Retest

On `main@c7fbe83`, the unchanged QA regression rejects an evidence ID present
in both polarity arrays. The authoritative fixture command also exercises the
negative case. Runtime persistence remains blocked until executable code calls
the same reference and semantic validation atomically.

## Required Disposition

Reject the intersection at the authoritative domain boundary and add positive
and negative contract fixtures. If one source contains mixed signals, model
those signals as distinct evidence items or keep the hypothesis unresolved;
do not silently count one evidence ID on both sides.
