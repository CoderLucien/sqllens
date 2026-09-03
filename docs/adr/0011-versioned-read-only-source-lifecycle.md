# ADR 0011: Versioned Read-Only Source Lifecycle

Status: Accepted for vNext P0
Date: 2026-09-02
Last updated: 2026-09-03

## Context

The product needs database, Prometheus, TEM, and Alertmanager evidence. A single
setup form is insufficient: customers must understand where credentials come
from, what they permit, how they are tested, and how they are revoked. Sources
must also be editable in daily operation without rewriting historical cases.

TiDB v8.5.x and PingKaiDB v7.1.x differ in supported fields and operational
context. Prometheus authentication depends on deployment topology. TEM public
documentation confirms API Key lifecycle but does not guarantee a fine-grained
read-only scope in every version.

## Decision

Source/v1 is a revisioned domain object. Public metadata and encrypted
credentials are stored separately. Every enabled revision records product,
version, endpoint identity, capability matrix, allowed scope, query budgets,
credential owner, expiry, last test, and audit events.

Source/v1 JSON is a projection, not an authorization authority. Runtime
validation resolves every embedded state and reservation event ID from a
server-owned transactional audit ledger. That record binds the canonical event
digest, authenticated principal/service permission, captured time, and—for
every state revision—the complete immutable Source state snapshot plus its
digest. State and reservation event arrays remain separately attested rather
than recursively embedded in each private snapshot. Full replay resolves all
revision snapshots, not only the latest one; the loaded current snapshot must
equal the final trusted digest. A missing resolver/record/revision,
caller-authored Owner or service identity, unaudited verification result, or
rewritten endpoint/scope/credential fails closed. The checked-in example
resolver and `source-v1.audit-state-history.json` are test-only models of that
private store and must never be populated from an API request.

The Web UI supports add, test, edit, enable, disable, rotate, and delete.
Diagnosis admission snapshots the source revision. Later edits affect only new
jobs; historical cases retain immutable source/evidence provenance without a
usable credential.

Job admission also pins the credential revision and acquires a lease before a
connector query begins. Rotation creates a new credential revision, stops new
admission against the old revision, and lets existing leased jobs drain. The
old secret is destroyed only after the authoritative active lease set is empty;
new jobs never fall back to it.

The authoritative record is an append-only reservation/lease ledger, not the
numeric count. Every acquisition is a system event with a never-reused
`leaseId`, `jobId`, `purpose` (`diagnosis` or `verification`), credential
revision, verification-input binding digest, source revision, and timestamp.
Both purposes count toward `maxConcurrency`; one Source may hold at most one
verification reservation. Each Source revision exposes the exact active set
obtained by replaying that ledger; `activeLeaseCount` must equal the set size
and is only a consistency check. Lease snapshot/release/completion events are
runtime-authored; user-authored events are limited to explicit Owner
registration, edit, enable, and drain-admission decisions.

A Source snapshot is trusted only after one full-history replay combines state
and lease ledgers by `sourceRevision` and timestamp. The replay starts at
revision 1, requires exactly one trusted state snapshot per revision, and
derives the active lease set after each event. At every revision it compares
that set and the concurrency budget with the trusted immutable snapshot, and
reapplies both the complete non-recursive Source snapshot semantics and the
same closed transition/mutation policy used for a live commit. Thus every
historical projection is checked independently and every adjacent pair is
checked as a transition; a later repair cannot make an invalid intermediate
revision trustworthy. `validate_source_semantics` is the only
authorization-grade replay entry point: it resolves the complete trusted
snapshot map, validates every snapshot and pairwise mutation, and only then
invokes the internal ledger replay primitive. Direct raw replay fails closed;
the separately named structural replay helper checks ledger shape only and
must never authorize a Source or reservation.
Diagnosis acquisition is legal only when that exact historical revision is
enabled and its credential revision plus verification-input digest equal a
prior trusted PASS. Released reservations remain subject to the same historical
check; a later PASS cannot authorize earlier work. Verification reservation is legal in
`draft`, `enabled`, `disabled`, or `verification_failed`; both use a
state-preserving `leases_updated` revision and must be strictly earlier than
that revision's state snapshot. Release/cancel is legal only in its declared
lease revision and must also be strictly earlier than the snapshot. Equal
timestamps across the two arrays are ambiguous and fail closed; lease events
within one revision are strictly ordered as well. A single revision cannot mix
reservation acquisition and release, so every committed acquisition remains
visible in its state snapshot before a later revision can release it. A
verifier result must be the immediate next Source revision after its exact
reservation and must match that reservation's lease/job, credential and
binding; any intervening edit makes publication invalid. Any
`draining -> disabled|verification_failed|tombstoned` completion requires the
replayed active set to be empty in that completion revision—later releases
cannot repair an already unsafe completion.
Prior/proposed validation
never accepts an already poisoned prior merely because the newest transition
is locally valid.

Disable and delete use the same admission barrier. A normal operation enters
`draining`, records the pending operation and retirement deadline, rejects new
jobs, preserves the current active-lease identities in that admission revision,
and waits for the authoritative set to become empty. Every later normal release
names an acquired lease and matching job, removes exactly that identity, and
appends an immutable lease event.
An explicit force operation follows the same count chain but must name the job,
bind an Owner approval captured strictly after the committed drain-admission
event and no later than the cancellation event, and emit a separate
forced-cancel lease event. Delete then destroys the credential and writes a
metadata-only `tombstoned` Source revision. A zero-lease `draft` or `verification_failed`
Source may use the same Owner-authored delete drain, so a mistyped first-time
Source never becomes an undeletable record. A failed verification snapshot is
immutable while that delete drain is active; the terminal tombstone clears the
live verification projection but retains the append-only failure and deletion
audit. Tombstones cannot be enabled or queried and retain no usable endpoint
credential. Hard deletion while a lease exists is forbidden.

The terminal tombstone is an exact projection rather than a best-effort
redaction. It replaces the endpoint host with `deleted.invalid` and clears its
path; clears every authentication field including expiry; empties source
associations, allowed schemas, capabilities, active leases, and live
verification; and resets detected version support to `unknown`/unsupported.
Only non-queryable identity and operational metadata (source identity/type,
display name, product, endpoint scheme/port/TLS mode, budgets, owner, timestamps,
and append-only audit ledgers) remain.

The lifecycle transitions are:

- Source `enabled -> draining -> disabled` while its credential moves
  `active -> rotating -> active` for rotation. The new credential revision is
  not admitted until it receives a fresh verification and an explicit Owner
  enable;
- Source `enabled -> draining -> disabled` while its credential moves
  `active -> retiring -> active` for disable (the disabled Source retains the
  credential for a later explicit re-enable);
- Source `draft/enabled/disabled/verification_failed -> draining -> tombstoned`
  for delete. Every admitted delete has zero leases before completion and moves
  any present credential from `active -> retiring -> tombstoned`.

Every Source write API also requires a server-side idempotency receipt; CAS is
not treated as idempotency. The receipt scope is authenticated Owner principal,
method, canonical route, and a digest of `Idempotency-Key`; it binds source/path,
expected revision, and canonical request intent without storing a raw key or
secret. Because that intent can contain a low-entropy password/token, its
persisted digest is HMAC-SHA-256 under a dedicated server-held key rather than
an unkeyed offline-guessing oracle. That key lives in the secrets volume rather
than the receipt database or logs and remains resolvable for at least the full
lifetime of every receipt it signed (a rotating implementation retains the old
key in a bounded keyring). The receipt stores only the closed, server-generated
`SourceWriteResult/v1` response DTO plus its integrity digest—never a full
Source/v1 projection, request body, connector object, or free-form connector,
event-reason, name, or error text—so an exact retry can actually be replayed
without persisting secrets. The six-field result contains only schema revision,
service-generated opaque Source ID, numeric revision, lifecycle state, pending
operation, and latest state operation; clients fetch the complete Source
separately after a successful write.
Every Source HTTP-write transaction atomically commits its Source, reservation,
or credential mutation with the matching receipt state and audit record.
Background diagnosis/lifecycle events retain their own unique trusted ledger
records and do not invent or reuse an HTTP request receipt. A verifier request
first commits its in-progress receipt, Source reservation, and audit before
external execution; its completion transaction atomically commits the result,
reservation release, final receipt, and audit. The same key and intent replays
the original status and redacted result without re-executing any side effect; a
different intent returns `IDEMPOTENCY_KEY_REUSED`, and a still-running first
attempt returns `IDEMPOTENCY_IN_PROGRESS`. Receipts survive Source deletion and
are retained for at least 24 hours. All trusted audit records belonging to one
verifier execution reference the same receipt ID, and one receipt cannot
authorize two Owner intents or two verifier jobs; Source/v1 does not expose the
receipt body.

Receipt IDs and their bound Owner-intent/verifier-job subjects are globally
unique in the transactional receipt store, not merely within one Source
projection. A runtime Source-audit resolver may return a record only after
joining that record to the matching committed receipt and enforcing this
global uniqueness constraint. The receipt writer computes its response digest
only after `source_idempotency_public_response` has projected the committed
Source into `SourceWriteResult/v1`. `source_idempotency_response_digest`
validates the exact HTTP method, canonical route, status, route Source identity,
operation/state/pending-operation tuple, and closed result DTO before
persistence. Its canonical integrity input binds `{responseRevision, method,
canonicalRoute, httpStatus, resultSourceId, resultRevision, body}`; replay
invokes the same validator and recomputes that complete context before returning
the stored body. Undeclared or free-form fields are not part of the result
schema; the recursive sensitive-key scan is defense in depth, not the response
schema or serializer.

An `in_progress` receipt is never deleted or treated as permission to rerun the
connector after a crash. Recovery first proves the original process/isolated
worker has terminated, then atomically releases its reservation and commits a
stable `VERIFICATION_INTERRUPTED` result plus the final receipt. The Owner may
start a new test only with a new key. This trades automatic retry for an auditable
at-most-once external verification boundary.

A force-cancel ledger record carries two independent trusted references: the
idempotency receipt for that Owner force-cancel command and the authenticated
Owner approval attestation. If the cancelled work is a verifier, its original
test-execution receipt remains a third, distinct correlation; cancellation may
close that execution but cannot rewrite its original intent.

Every Source revision appends a typed, chronological state event; prior events
are immutable. Revision and credentialRevision are monotonic, and the
prior/proposed validator rejects old-event rewrites, skipped revisions, lease
growth or silent lease erasure in any state, invented lease/job identities,
discontinuous ledger counts, state events that precede their revision's lease
events, operation/pending-operation mismatch, contradictory state/verification
pairs, and completion
inconsistent with the pending operation. A drain starts only through an explicit
Owner action; lease release revisions and completion remain separate. Crash
recovery resumes the recorded pending operation; it never guesses whether a
secret was retired.

Each operation has a closed top-level field-mutation allowlist. Besides
`revision`, `updatedAt`, and the one appended state event, an operation may
change only the fields its semantics explicitly own; for example a lease
revision cannot rewrite owner/name, and a lifecycle completion cannot rewrite
budgets or scope. `createdAt` equals the registration event timestamp and
`updatedAt` equals the latest state-event timestamp, preventing unaudited
timestamp drift.

A verifier must atomically persist its reservation before decrypting a
credential or calling an external connector. The reservation binds the exact
Source revision and credential revision plus endpoint, allowed-schema scope,
auth identity, and credential reference/revision. A normal PASS/FAIL revision
atomically releases that same reservation and may publish only when no
intervening Source revision has committed. If another revision or a concurrent
disable/delete/rotation won the CAS, the terminated verifier may only release
its reservation and may not overwrite the newer projection. A crash, timeout,
or force-cancel record may release a reservation only after the execution or
isolated worker is confirmed terminated; deleting a key file is not proof that
plaintext is no longer in memory.

A verification failure on an enabled Source also stops new admission. Its
result revision atomically releases the verification reservation, enters a
`verification_failure` drain, and preserves all diagnosis leases and the active
credential. Only after the remaining set is empty may the runtime publish the
terminal `verification_failed` revision. It cannot erase active work by
changing the verification snapshot.

Verification is bound to the endpoint, allowed-schema scope, authentication
kind and username, and exact credential reference/revision. A disabled Source
may be retested without being admitted: success appends a verifier-authored
`verified: disabled -> disabled` revision, while failure appends
`verification_failed: disabled -> verification_failed`. Both results are fresh
snapshots and an old `passed` result cannot be replayed. A successful retest
still requires a later explicit Owner enable. A successful enabled retest stays
enabled. A failed enabled retest atomically releases the verifier reservation,
starts the diagnosis-lease drain, and records the failure time once; the later
`draining -> verification_failed` completion is lifecycle work and cannot
rewrite that verifier result.

Changing the endpoint or `allowedSchemas` in any non-enabled editable state
invalidates version, capabilities, and verification. An edit from
`verification_failed` returns to `draft` so that the cleared projection is
representable. An enabled Source must be disabled before either input can
change. Metadata-only edits (name, owner, budgets, or associations) preserve the
existing verification projection exactly. `allowedSchemas` is a unique set, so
reordering it is not a material change. Credential rotation similarly
invalidates the old credential's projection: rotation completion switches the
credential revision but remains `disabled` and `not_run`; only a fresh test of
that new revision can make it eligible for Owner enable.

Every connector supplies an in-product acquisition guide:

1. identify the responsible customer role;
2. obtain or create a dedicated credential;
3. apply the minimum required permission;
4. paste the secret only into the local UI;
5. run a bounded capability test;
6. record owner, expiry, rotation, and revoke instructions.

Database PROCESS is optional and explicitly sensitive. Refusal activates a
visible degraded mode. Prometheus modes are trusted internal access, Basic
Auth, or gateway Token/mTLS. TEM permissions are capability-tested; an
over-broad key requires explicit customer risk acceptance or a safer fallback.

Unknown database versions, missing required capabilities, endpoint redirects,
TLS failures, or source/cluster identity mismatches fail closed. Connector tests
report granular capabilities and do not silently request broader access.

## Consequences

- Initialization can register several sources, while daily operation owns their
  lifecycle.
- Connector and source contracts must precede implementation work.
- Credential changes require optimistic concurrency and active-job protection.
- Rotation, disable, and delete require lease/drain/cancel/tombstone tests.
- Documentation and copyable scripts become versioned product assets and test
  fixtures, not prose maintained outside the application.

## Security References

- Python `hmac` keyed-hashing API: https://docs.python.org/3/library/hmac.html
- OWASP Secrets Management Cheat Sheet (including HMAC key management):
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
