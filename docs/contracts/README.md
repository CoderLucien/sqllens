# Contract Fixtures

`diagnosis-case-v1.schema.json` defines the serializable P0 case envelope.

The examples serve two different assertions:

- `examples/diagnosis-case-v1.valid.json` must validate.
- `examples/diagnosis-case-v1.invalid-missing-owner.json` must fail because a
  recommendation cannot omit its accountable owner.
- `examples/diagnosis-case-v1.invalid-reference.json` must pass JSON Schema but
  fail domain validation because it contains dangling evidence/recommendation
  references.

Run the local contract check with:

```bash
python3 docs/contracts/validate_examples.py
```

Contract validation has four mandatory layers:

1. Validate the JSON Schema with the exported RFC 3339 `FormatChecker`. Calling
   `Draft202012Validator(schema)` without a format checker is not equivalent and
   must not be used at a persistence boundary.
2. Run referential-integrity and unique-ID checks for evidence, hypotheses,
   recommendations, reviews, and feedback.
3. Run the single-revision outcome prerequisites below.
4. For an update, validate the prior and proposed revisions together, including
   immutable fields, append-only collections, monotonic time, legal state
   transitions, and a newly appended event for each outcome change.

JSON Schema alone cannot prove that referenced IDs exist in the same case or
that a transition from a prior revision is legal. `validate_examples.py`
contains the executable P0 domain contract. Production code must move the same
rules into the domain package and execute all four layers atomically before a
revision is persisted.

## Workflow State Machine

Self-transitions are allowed so evidence and audit records can be appended
without inventing a new lifecycle state.

| Current state | Allowed next states |
| --- | --- |
| `queued` | `queued`, `collecting`, `failed`, `cancelled` |
| `collecting` | `collecting`, `analyzing`, `failed`, `cancelled` |
| `analyzing` | `analyzing`, `ready`, `failed`, `cancelled` |
| `ready` | `ready` |
| `failed` | `failed` |
| `cancelled` | `cancelled` |

`ready`, `failed`, and `cancelled` are terminal workflow states. A retry or
re-analysis creates a new job/case instead of rewinding the audit history.

## Outcome State Machine

`workflowState` and `outcome` remain separate axes, but they are not arbitrary:
any outcome other than `not_reviewed` requires `workflowState=ready`.

| Current outcome | Allowed next outcomes |
| --- | --- |
| `not_reviewed` | `not_reviewed`, `accepted`, `rejected` |
| `accepted` | `accepted`, `rejected`, `implemented` |
| `rejected` | `rejected`, `accepted` |
| `implemented` | `implemented`, `validated`, `rolled_back` |
| `validated` | `validated`, `rolled_back` |
| `rolled_back` | `rolled_back` |

Outcome prerequisites are cumulative:

| Outcome | Required records in the case |
| --- | --- |
| `not_reviewed` | None |
| `accepted` | An `approved` review |
| `rejected` | A `rejected` review |
| `implemented` | An `approved` review and `implemented` feedback |
| `validated` | An `approved` review plus `implemented` and `validated` feedback |
| `rolled_back` | An `approved` review plus `implemented` and `rolled_back` feedback |

When the outcome changes, the proposed revision must append the corresponding
trigger in that same revision: an `approved`/`rejected` review or an
`implemented`/`validated`/`rolled_back` feedback record. A record copied from an
older revision cannot authorize a new transition. The fixture runner exhaustively
checks every allowed and forbidden pair in both state machines.
