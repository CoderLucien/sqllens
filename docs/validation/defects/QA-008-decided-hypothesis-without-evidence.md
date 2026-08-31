# QA-008: Decided Hypotheses Can Have No Evidence For Their Polarity

Status: RESOLVED at contract layer; runtime integration retest pending
Severity: High
Detected against: `main@1c3c271`
Resolved in: `main@c7fbe83`
Owner: contract/domain owner (`#t8`), not QA
Regression tests: `tests/qa/test_diagnosis_case_contract.py`

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

Actual at detection: neither path raises an error.

## Independent Retest

On `main@c7fbe83`, QA verified that `favored` requires supporting evidence and
`rejected` requires contradicting evidence, while candidate and unresolved
hypotheses retain their abstention behavior. Runtime model-output persistence
remains blocked.

## Required Disposition

At the authoritative domain boundary, require at least one supporting evidence
ID for `favored` and at least one contradicting evidence ID for `rejected`.
Retain the existing dangling-reference and no-overlap checks. Do not force
evidence onto `candidate`/`unresolved`; those states preserve honest abstention.
