# QA-002: Case State Regression And Invalid Audit Time Pass Validation

Status: RESOLVED at contract layer; runtime integration retest pending
Detected against: `main@7c00fe0`
Resolved in: `main@1c3c271`
Owner: contract/domain owner (`#t8`), not QA
Regression tests: `tests/qa/test_diagnosis_case_contract.py`

## QA-002A: Completed Workflow Can Regress

Severity: High

Starting from the checked-in valid case, create revision 2, advance `updatedAt`,
and change `workflowState` from `ready` to `queued`. `validate_revision()` accepts
the revision because it has no workflow/outcome transition or cross-field
precondition rules.

Impact: a stale or defective writer can move a completed diagnosis backwards or
mark an outcome without the required review/feedback evidence. Append-only arrays
do not prevent invalid top-level state.

Expected: freeze explicit workflow and outcome transition tables plus review/
feedback prerequisites, reject illegal transitions, and add positive and
negative fixtures for every edge.

## QA-002B: Malformed Audit Date-Time Passes The Contract Command

Severity: Medium

Change `reviews[0].createdAt` in the valid fixture to `not-a-date`, then run the
checked-in contract command. It still exits zero because
`Draft202012Validator(schema)` is constructed without a format checker; JSON
Schema treats `format` as annotation unless format assertion is enabled.

Impact: malformed evidence/review/feedback timestamps can break freshness,
ordering, correlation and audit semantics after persistence.

Expected: the authoritative validation path enables date-time format assertion
and negative fixtures cover top-level, evidence, review and feedback timestamps.

## Minimum Reproduction

```bash
python3 -m unittest discover \
  -s tests/qa \
  -p 'test_diagnosis_case_contract.py' \
  -v
```

At detection, the five previously fixed integrity tests pass while the new state
regression and malformed-date tests fail.

## Independent Retest

QA rebased onto `main@1c3c271` and ran:

```bash
python3 docs/contracts/validate_examples.py
python3 -m unittest tests.qa.test_diagnosis_case_contract -v
```

The authoritative fixture command printed `contract fixtures passed`. The
`ready -> queued` regression and malformed review timestamp tests both passed,
so QA-002A and QA-002B are closed at the checked-in contract layer.

The full QA contract file reported seven passing tests and one separate failure,
QA-003 (approved terminal outcome vocabulary). QA-002 is not the cause of that
failure.

## Retest Scope

1. Run the focused QA contract suite above.
2. Run `python3 docs/contracts/validate_examples.py`.
3. Verify the production domain persistence path calls the same transition and
   format validation before committing a revision. This remains `BLOCKED`
   because the runtime slice does not exist yet.
4. Exercise legal and illegal transitions through the API after the runtime
   slice exists; documentation fixture validation alone is not release proof.
