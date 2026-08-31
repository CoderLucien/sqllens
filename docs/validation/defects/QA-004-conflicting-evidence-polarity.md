# QA-004: One Evidence Item Can Both Support And Contradict A Hypothesis

**Status:** OPEN  
**Severity:** High  
**Release impact:** Blocks the evidence-integrity portion of the
`DiagnosisCaseV1` contract.

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

Actual: no exception is raised.

## Required Disposition

Reject the intersection at the authoritative domain boundary and add positive
and negative contract fixtures. If one source contains mixed signals, model
those signals as distinct evidence items or keep the hypothesis unresolved;
do not silently count one evidence ID on both sides.
