# Contract Fixtures

## vNext contracts

The vNext product baseline adds:

- `source-v1.schema.json`: revisioned database/Prometheus/TEM/Alertmanager
  metadata, exact product/version/auth matrix, and append-only lifecycle audit;
  credentials are references, never values.
- `evidence-v2.schema.json`: standalone immutable evidence envelope with Case
  and Source revision bindings, payload digest, freshness, redaction revision,
  collector/query revision, and collection budgets.
- `diagnosis-case-v2.schema.json`: separates evidence, facts, rule findings,
  typed fact profiles, fully server-rendered decisions/AI claims/actions,
  uncertainty, transition audit, review/feedback, and labeled
  provider/model/prompt/payload/redaction pins.
- `diagnosis-report-v1.schema.json`: Chinese audience projection backed by one
  immutable Case revision.

Review fixtures:

- `examples/diagnosis-case-v2.valid.json`
- `examples/diagnosis-case-v2.statistics.valid.json`
- `examples/diagnosis-case-v2.runtime-correlation.valid.json`
- `examples/diagnosis-report-v1.index-access.review.json`
- `examples/diagnosis-report-v1.statistics.review.json`
- `examples/diagnosis-report-v1.runtime-correlation.review.json`

Validate the vNext drafts and their reference integrity with:

```bash
python3 -m unittest discover -s docs/contracts -p 'test_*.py' -v
python3 docs/contracts/validate_vnext_examples.py
python3 docs/contracts/validate_vnext_negative_examples.py
```

The positive validator checks all three Case/Report pairs, an explicit
non-invoked AI abstention, one complete Source lease-drain chain, complete
`validated_effective` and `rolled_back` transitions, and a separately rendered
actionless `evidence_insufficient` Case/Report path. A report must be an exact
projection of one Case revision for mode, conclusion, priority, business
impact, evidence summary, rule/AI reasoning, ordered actions, uncertainty, and
complete provenance. It cannot add an evidence ID, action, measurement, or
business impact that the Case did not bind.

The executable domain policy is deliberately split into independently tested
models instead of accumulating conditions in the fixture runner:

- `vnext_canonical_json.py` owns the restricted RFC 8785/JCS digest profile;
- `vnext_diagnosis_policy.py` owns versioned Evidence eligibility, typed
  Evidence -> Fact extraction, rule predicates/templates, and derived level,
  completeness, and uncertainty (`diagnosis-policy/v4`);
- `vnext_outcome_policy.py` owns the singular authorized outcome tuple and its
  causal/effect semantics;
- `vnext_source_ledger.py` performs one full-history replay of Source state and
  lease events.

DiagnosisCase/v2 records both workflow and business-outcome transition events.
A non-pending outcome requires `workflowState=ready` and exactly one first
`pending -> terminal` outcome event whose own references contain the complete
prerequisite chain; a later terminal self-transition cannot backfill it. Effect
claims require an ordered approval -> implementation -> result-evidence ->
terminal feedback -> outcome-event chain. The terminal event contains one
structured tuple and its legacy ID arrays must be its exact projection; records
from another tuple cannot collectively satisfy an outcome. Human approval is a
user actor bound through an opaque ID to a trusted, server-owned authorization
audit ledger; the public Case cannot manufacture or rehash this attestation.
The audit record binds the exact canonical Action snapshot as well as the Case,
revision, review, principal, permission, and policy revision. Its capture time
must fall between Case creation and the review; when a terminal revision is
validated against its prior revision, the capture must also be strictly later
than the prior revision's `updatedAt`, so an old role snapshot cannot be replayed.
Each Action template owns an ordered set of required metric codes, units,
thresholds, and comparison predicates. The outcome policy recomputes every
predicate from numeric result Evidence and rejects a missing measurement; no
persisted `passed` Boolean is authoritative. `validated_effective` requires
every predicate to hold; `rolled_back` requires a failed predicate plus
confirmed rollback for that same Action. Result Evidence must itself pass the
Evidence eligibility policy. Predicate names freeze boundary semantics:
`*_below` is strict and rejects equality, while `*_at_most` is inclusive. These
comparisons use
`effect-metric-comparison/v2`. The global event replay requires the
workflow to be ready, rejects records created after the event, and requires all
evidence used by the frozen diagnosis to have been collected no later than the
ready event and that Case revision's `updatedAt`. Prior/proposed Case validation
keeps old collections append-only and freezes the ready diagnosis.
`risk_accepted` and `evidence_insufficient` have separate, explicit audit
records and cannot be inferred from status text.

Source/v1 lifecycle validation treats a Source revision and credential revision
as separate immutable identities. Admission pins both and acquires a lease.
Rotation, disable, and delete stop new admission and enter `draining`; normal
retirement waits for zero leases. The authoritative lease ledger starts with a
runtime-emitted acquisition event and exposes an exact active `leaseId`/`jobId`
snapshot; the numeric count is only a derived cross-check. Every loaded snapshot
is replayed from revision 1 by one combined state/lease model before it may be
used as a prior revision. Admission may occur only in an enabled
`leases_updated` revision strictly before its state snapshot; release/cancel
events must belong to an allowed lease revision and also be strictly earlier
than its state snapshot. Equal timestamps do not establish causal order and are
rejected; multiple lease events in one revision are also strictly ordered.
Entering drain preserves the active set. Each later normal release or forced
cancellation names an acquired lease and job, removes exactly that identity,
and appends an immutable lease event;
forced cancellation also binds a prior Owner approval. The Source state event
cannot precede the lease events recorded by the same revision. Delete removes
the usable credential and retains only a non-queryable metadata tombstone. Every
Source revision appends a chronological state event. Prior/proposed validation
rejects audit rewrite, revision or credentialRevision rollback, invented or
silently erased leases in every state, operation/pending-operation mismatch,
contradictory verification state, and drain completion that does not match its
pending operation.

AI text, the customer-facing decision, and customer actions are not free-form
persistence fields. The model may select only an allowlisted template and typed
parameters. Decision parameters reference typed facts bound to exact evidence
roles, kinds, schema revision, extraction revision, and typed payload fields;
the validator verifies a canonical typed-payload digest, rebuilds fact
parameters from those fields, then evaluates the database-version-selected rule
pack. Predicate/threshold, status, severity, minimum evidence level, Chinese
conclusion, evidence roles, and document references are one deterministic rule
projection. Only a `hit` rule may support a Decision, Claim, or Action. The
service then re-renders the fact and every customer-visible decision field
(including priority and evidence summary), claim, action, and uncertainty and
rejects any mismatch. Ratios and display-scale values are derived from typed raw
measurements rather than accepted as independent parameters. An applied or
failed/degraded invocation carries labeled
provider, model, prompt, redacted-payload, payload digest, and redaction
revisions. A policy abstention records a code and Chinese reason without
invocation pins. `rules_ai -> rules` must use one of those two explicit paths,
while `rules -> rules` must be `not_requested` with no invocation or provider
pins. Reports project every AI status, server-owned code, and server-owned
Chinese reason exactly.

Standalone Evidence fixtures run the same observation/collection time, Source
binding, digest, truncation, and budget semantics as Evidence embedded in a Case.

Typed payload digests pin `rfc8785-safe-integer/v1`, a restricted RFC
8785-compatible canonical form:
object keys use UTF-16 ordering and measurements use integer base units within
the IEEE-754 safe range. Every JSON ingress rejects duplicate object members
before parsing can collapse them. NaN, Infinity, fractional typed
measurements, and language-dependent number rendering are rejected; strict
JSON serialization uses `allow_nan=False`.

Evidence qualification is not inferred from a valid digest alone. The pinned
policy checks kind-specific freshness, coverage, collection completion,
truncation, record count, and rows read for every required Fact/rule role.
`evidenceLevel` is computed only from those supporting roles, so unrelated
Evidence cannot raise the ceiling. `evidenceCompleteness` is the percentage of
eligible required roles, and uncertainty text is a server-owned code/template
projection rather than caller-authored prose. Incomplete Evidence is retained
as an explicit typed gap Fact with per-role eligibility and reasons. It may
produce an actionless `evidence_insufficient` decision and terminal outcome,
but it cannot support a ready rule hit or Action. Role selection is also
server-owned: a role cannot be marked `MISSING_EVIDENCE` while a matching Case
Evidence candidate exists, and an ineligible candidate cannot be selected when
an eligible candidate for that role is available. “Matching” means both the
required kind and the dependency registry's shared typed profile fields agree;
same-kind Evidence whose declared table/object fields conflict is not a
candidate, and all bound roles must form one compatible profile.
The selected role's declared shared identity fields remain the candidate
anchor even when its corroborating role is missing.

These fixtures are product-review baselines, not claims that the current
runtime can generate them.

## Historical v1 contract

Everything below this heading describes the historical DiagnosisCase/v1
contract and validator. It does not override the vNext Source/Evidence/Case/
Report rules above.

`diagnosis-case-v1.schema.json` defines the serializable P0 case envelope.

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
| `validated_effective` | An `approved` review, `implemented` feedback, and linked `validated` feedback citing the complete Action-owned metric set whose predicates are recomputed as satisfied |
| `rolled_back` | An `approved` review, `implemented` feedback, and linked `rolled_back` feedback citing the complete Action-owned metric set with at least one failed predicate plus `rollback_confirmation` evidence |
| `evidence_insufficient` | A typed gap Fact, derived sub-100 completeness and evidence ceiling, no rule hit/Action/Claim, and `evidence_insufficient` feedback |
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
requires the complete versioned Action measurement set for both effect outcomes
and separate rollback confirmation for `rolled_back`. It derives the result
from the measurements rather than accepting a writable success flag.

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
