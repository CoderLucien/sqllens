# QA-009: Legacy Rolled-Back Draft Cannot Be Imported

Status: OPEN
Severity: Medium
Detected against: `main@c7fbe83`
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

Migration must distinguish the pre-freeze source from a current case, either
through explicit source-version context or an equally fail-closed discriminator.
Normalize the old rolled-back process record to `pending`, preserve its review
and feedback history, and do not downgrade a valid current terminal result.
Document the rule and add positive and negative fixtures. An unconditional
string alias for `rolled_back` is not acceptable because it would erase a
current business result.

