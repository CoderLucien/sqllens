# ADR 0011: Versioned Read-Only Source Lifecycle

Status: Accepted for vNext P0
Date: 2026-09-02

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

The Web UI supports add, test, edit, enable, disable, rotate, and delete.
Diagnosis admission snapshots the source revision. Later edits affect only new
jobs; historical cases retain immutable source/evidence provenance without a
usable credential.

Job admission also pins the credential revision and acquires a lease before a
connector query begins. Rotation creates a new credential revision, stops new
admission against the old revision, and lets existing leased jobs drain. The
old secret is destroyed only after its lease count reaches zero; new jobs never
fall back to it.

Disable and delete use the same admission barrier. A normal operation enters
`draining`, records the pending operation and retirement deadline, rejects new
jobs, preserves the current active-lease count in that admission revision, and
waits for leases to reach zero. Every later normal release names its lease and
job, decrements the count by exactly one, and appends an immutable lease event.
An explicit force operation follows the same count chain but must name the job,
bind an Owner approval created no later than the cancellation event, and emit a
separate forced-cancel lease event. Delete then destroys the credential and
writes a metadata-only `tombstoned` Source revision. Tombstones cannot be enabled
or queried and retain no usable endpoint credential. Hard deletion while a
lease exists is forbidden.

The lifecycle transitions are:

- Source `enabled -> draining -> enabled` while its credential moves
  `active -> rotating -> active` for rotation;
- Source `enabled -> draining -> disabled` while its credential moves
  `active -> retiring -> active` for disable (the disabled Source retains the
  credential for a later explicit re-enable);
- Source `enabled/disabled -> draining -> tombstoned` while its credential moves
  `active -> retiring -> tombstoned` for delete.

Each transition uses optimistic revision checks and is idempotent. Every Source
revision appends a typed, chronological state event; prior events are immutable.
Revision and credentialRevision are monotonic, and the prior/proposed validator
rejects old-event rewrites, skipped revisions, lease growth or silent lease
erasure while draining, discontinuous per-lease counts, operation/pending-
operation mismatch, contradictory state/verification pairs, and completion
inconsistent with the pending operation. A drain starts only through an explicit
Owner action; lease release revisions and completion remain separate. Crash
recovery resumes the recorded pending operation; it never guesses whether a
secret was retired.

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
