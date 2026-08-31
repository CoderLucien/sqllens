# QA-008: Decided Hypotheses Can Have No Evidence For Their Polarity

**Status:** OPEN  
**Severity:** High  
**Release impact:** Blocks evidence-first case conclusions.

## Requirement

Every favored root-cause conclusion must cite supporting evidence. Every
rejected competing cause must cite contradicting evidence. Evidence may remain
absent for a `candidate` or `unresolved` hypothesis, which is how the product
represents a question it cannot yet answer.

## Actual

Both evidence-ID arrays allow zero items, and domain validation only checks
uniqueness, overlap and dangling references. It accepts:

- `status=favored`, `confidence=1`, `supportingEvidenceIds=[]`;
- `status=rejected`, `confidence=1`, `contradictingEvidenceIds=[]`.

This allows an LLM or defective writer to persist an evidence-free root cause
as a decided conclusion.

## Reproduction

```bash
python3 -m unittest \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_decided_hypotheses_require_evidence_for_their_polarity \
  -v
```

Expected: both malformed hypotheses are rejected.

Actual: neither path raises an error.

## Required Disposition

At the authoritative domain boundary, require at least one supporting evidence
ID for `favored` and at least one contradicting evidence ID for `rejected`.
Retain the existing dangling-reference and no-overlap checks. Do not force
evidence onto `candidate`/`unresolved`; those states preserve honest abstention.
