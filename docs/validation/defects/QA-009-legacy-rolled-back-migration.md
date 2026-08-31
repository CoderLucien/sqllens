# QA-009: Legacy Rolled-Back Draft Cannot Be Imported

Status: RESOLVED at contract layer; runtime integration retest pending
Severity: Medium
Detected against: `main@c7fbe83`
Resolved in: `main@c0e99d6`
Owner: contract/domain owner (`#t8`), not QA
Regression tests: `tests/qa/test_diagnosis_case_contract.py`

## Impact

The pre-freeze and current contracts both use the literal `rolled_back`, but
the current contract gives it stronger effect-evidence and causal-chain
semantics. The declared draft migration handles the five renamed values only.
A valid old rolled-back draft is therefore left unchanged and rejected by the
current semantic validator.

This blocks the documented compatibility path for checked-in draft artifacts
and test data. It does not imply that released production data exists.

## Reproduction

Construct the `1c3c271` rolled-back case with an approved review plus
`implemented` and `rolled_back` feedback, but without the current result
evidence binding. The old schema, reference checks and semantics accept it.
After calling the current migration function, the outcome remains
`rolled_back`; current schema and references accept it, but current semantics
reject it for lacking the evidence-backed causal chain.

```bash
python3 -m unittest \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_legacy_rolled_back_is_normalized_without_downgrading_current_result \
  -v
```

Expected: a legacy rolled-back draft normalizes to `pending`, while an actual
current evidence-backed rolled-back result remains `rolled_back`.

Actual: the legacy draft remains `rolled_back`; the regression fails before
the current-result guard is reached.

## Required Disposition

Migration must distinguish the pre-freeze source from a current case through an
explicit, fail-closed source revision. The regression uses
`diagnosis-case/v1@1c3c271` for the old draft and
`diagnosis-case/v1@business-outcomes-v1` for the current contract; any unknown
source must be rejected. Normalize the old rolled-back process record to
`pending`, preserve its review and feedback history, and do not downgrade a
valid current terminal result. Document the rule and add positive and negative
fixtures. An unconditional string alias for `rolled_back` is not acceptable
because it would erase a current business result.

## Independent Retest

QA rebased the source-aware red test onto `main@c0e99d6` and verified:

- trusted `diagnosis-case/v1@1c3c271` input normalizes old `rolled_back` to
  `pending` while preserving audit records;
- `diagnosis-case/v1@business-outcomes-v1` keeps a valid current
  `rolled_back` unchanged;
- a damaged current rollback is not silently downgraded and is rejected by
  current semantic validation;
- missing and unknown source revisions fail closed.

The focused regression, all 19 contract tests and the 57-test QA suite pass.
Runtime import and persistence remain blocked until executable code exists.
