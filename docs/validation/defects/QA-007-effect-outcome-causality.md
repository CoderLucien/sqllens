# QA-007: Effect Outcome Events Are Not One Causal Change Chain

Status: RESOLVED at contract layer; runtime integration retest pending
Severity: High
Detected against: `main@1c3c271`
Resolved in: `main@c7fbe83`
Owner: contract/domain owner (`#t8`), not QA
Regression tests: `tests/qa/test_diagnosis_case_contract.py`

## Requirement

The approved journey is a human-controlled change loop: a DBA approves one
recommendation, that recommendation is implemented, post-change evidence is
observed, and the result is validated or rolled back. The terminal result must
not be assembled from unrelated recommendations or pre-change metrics.

## Actual

The current outcome draft checks that an approved review, implemented feedback,
terminal feedback and allowed evidence kinds all exist. It does not require
them to reference the same recommendation. It also does not enforce causal time
ordering across reviews, feedback and result evidence.

Consequently, both of these cases pass the draft semantics:

- recommendation A is approved and implemented, while terminal validation and
  evidence are attached to recommendation B;
- implementation occurs before approval, or the effect metric is observed
  before implementation.

## Reproduction

```bash
python3 -m unittest \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_effect_outcome_events_must_reference_the_same_recommendation \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_effect_outcome_enforces_approval_and_evidence_causal_order \
  -v
```

Expected: both malformed change chains are rejected.

Actual at detection: no exception is raised by the contract semantics.

## Independent Retest

On `main@c7fbe83`, QA verified the same-recommendation constraint and the full
approval, implementation, observation, collection and terminal-feedback time
chain. Cross-recommendation and three out-of-order variants are rejected.
Runtime event creation and atomic persistence remain blocked.

## Required Disposition

For `validated_effective` and `rolled_back`, domain validation must identify at
least one recommendation for which all required events are linked and ordered:

```text
approved review <= implemented feedback <= result evidence observation
                <= terminal feedback <= case updatedAt
```

Result evidence collection must not precede its observation. When multiple
recommendations or pieces of evidence exist, unrelated records cannot satisfy
different parts of the same terminal-outcome prerequisite.
