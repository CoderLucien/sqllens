# Contract Fixtures

`diagnosis-case-v1.schema.json` defines the serializable P0 case envelope.

New SQL-layer cases include the optional `pinnedRevisions.parser` field. It
pins the exact parser, dialect, and version used for statement classification;
the field remains optional in v1 so previously frozen cases stay valid.

The examples serve different assertions:

- `examples/diagnosis-case-v1.valid.json` must validate.
- `examples/diagnosis-case-v1.invalid-missing-owner.json` must fail because a
  recommendation cannot omit its accountable owner.
- `examples/diagnosis-case-v1.invalid-reference.json` must pass JSON Schema but
  fail domain validation because it contains dangling evidence/recommendation
  references.
- `examples/diagnosis-case-v1.legacy-1c3c271-rolled-back.json` is a real
  pre-freeze rollback shape accepted by the `1c3c271` contract and must import
  as `pending`, not as a current evidence-backed rollback result.

Run the local contract check with:

```bash
python3 docs/contracts/validate_examples.py
```

Contract validation has four mandatory layers:

1. Validate the JSON Schema with the exported RFC 3339 `FormatChecker`. Calling
   `Draft202012Validator(schema)` without a format checker is not equivalent and
   must not be used at a persistence boundary.
2. Run referential-integrity and unique-ID checks for evidence, hypotheses,
   recommendations, reviews, and feedback. Supporting and contradicting
   evidence sets for one hypothesis must be disjoint. A `favored` hypothesis
   must cite supporting evidence, and a `rejected` hypothesis must cite
   contradicting evidence; `candidate` and `unresolved` may remain unproven.
3. Run the single-revision outcome prerequisites below.
4. For an update, validate the prior and proposed revisions together, including
   immutable fields, append-only collections, monotonic time, legal state
   transitions, audit-record time windows, and a newly appended event for each
   outcome change.

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

`workflowState` describes processing. `outcome` describes the business result;
review decisions and implementation milestones stay in append-only `reviews`
and `feedback`. Any outcome other than `pending` requires
`workflowState=ready`.

| Current outcome | Allowed next outcomes |
| --- | --- |
| `pending` | `pending`, `validated_effective`, `rolled_back`, `evidence_insufficient`, `risk_accepted` |
| `validated_effective` | `validated_effective` |
| `rolled_back` | `rolled_back` |
| `evidence_insufficient` | `evidence_insufficient` |
| `risk_accepted` | `risk_accepted` |

Outcome prerequisites are cumulative:

| Outcome | Required records in the case |
| --- | --- |
| `pending` | None |
| `validated_effective` | An `approved` review, `implemented` feedback, and linked `validated` feedback citing `effect_metric_comparison` evidence |
| `rolled_back` | An `approved` review, `implemented` feedback, and linked `rolled_back` feedback citing both `effect_metric_comparison` and `rollback_confirmation` evidence |
| `evidence_insufficient` | `insufficient` completeness, non-empty missing-evidence details, no recommendations, and `evidence_insufficient` feedback |
| `risk_accepted` | A `risk_accepted` review linked to at least one recommendation |

The four business outcomes are terminal; re-analysis creates a new case rather
than rewriting the completed result. A transition from `pending` must append its
trigger in that same revision: linked `validated`/`rolled_back` feedback,
`evidence_insufficient` feedback, or a linked `risk_accepted` review. A record
copied from an older revision cannot authorize a new transition, and an unbound
new record cannot reuse an older record's recommendation or evidence bindings.
The fixture runner exhaustively checks every allowed and forbidden pair in both
state machines.

Effect outcomes cannot be grounded only by a comment or recommendation ID.
Their terminal feedback has a non-empty `evidenceIds` binding; domain validation
rejects empty, dangling, or policy-inappropriate evidence kinds. The P0 policy
requires a metric comparison for both effect outcomes and separate rollback
confirmation for `rolled_back`.

Each effect result must form one causal chain for the same recommendation:

```text
approved review <= implemented feedback <= result evidence observedAt
                <= result evidence collectedAt <= terminal feedback
                <= case updatedAt
```

Records attached to different recommendations cannot be combined to satisfy a
terminal outcome. Only evidence kinds required by the result policy participate
in this causal-order check; other cited diagnostic evidence retains its own
observation time.

## Draft Compatibility

No P0 release persisted the earlier draft outcome vocabulary. For checked-in
draft artifacts and test data, `migrate_legacy_draft_outcome()` performs a
non-mutating import normalization before current-schema validation. The caller
must pass a trusted `source_contract_revision`; it comes from controlled bundle
metadata or import configuration, never from an untrusted field in the case.
Unknown sources fail closed.

| Source contract | Legacy draft value | Current value |
| --- | --- | --- |
| `diagnosis-case/v1@1c3c271` | `not_reviewed` | `pending` |
| `diagnosis-case/v1@1c3c271` | `accepted` | `pending` |
| `diagnosis-case/v1@1c3c271` | `rejected` | `pending` |
| `diagnosis-case/v1@1c3c271` | `implemented` | `pending` |
| `diagnosis-case/v1@1c3c271` | `validated` | `pending` |
| `diagnosis-case/v1@1c3c271` | `rolled_back` | `pending` |

Reviews and feedback remain intact, so approval and implementation history is
not lost. Process-only values are deliberately absent from the current enum and
cannot be written by a current client. The old and current contracts both use
`rolled_back`, but only the current value proves an effect-evidence causal
chain, so it is downgraded only when the trusted source is exactly `1c3c271`.
Passing `diagnosis-case/v1@business-outcomes-v1` is an identity operation and
must preserve a current valid rollback. This adapter is for pre-freeze import,
not permission to rewrite persisted revisions; any migration after a release
must create an explicit audited revision.

## Audit Time Window

For every new review or feedback record in revision `N`:

```text
revision[N-1].updatedAt < record.createdAt <= revision[N].updatedAt
```

The format checker and revision comparator share the same RFC 3339 parser,
including lower-case `t`/`z`. Evidence `observedAt` and `collectedAt` are not
forced into this window because imported evidence can legitimately predate the
case; its freshness, coverage, source, and integrity fields retain that
separate provenance meaning.
