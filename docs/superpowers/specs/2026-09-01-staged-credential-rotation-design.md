# Durable Staged Credential Rotation

## Scope

This design closes the credential-key orphan window in the authenticated
external-provider rotation path. It does not add multi-process or multi-replica
support. The P0 runtime remains one `web-api` process and one Compose replica.

The invariant is:

> The active credential reference always has an existing, safe, decryptable
> key file. Every non-active key file has exactly one durable staged or
> retirement-pending reference. After recovery, the directory contains only
> the active key.

No API key plaintext or key bytes are stored in SQLite. A losing request may
generate an ephemeral in-memory rotation plan, but that plan must never be
written to disk, SQLite, or logs unless the request first wins the durable
staged mutation.

## State Machine

The only valid rotation sequence is:

1. `idle(active=A)`
2. Generate an ephemeral in-memory rotation plan containing random key bytes
   and a deterministic version/path. No file exists yet, and losing the staged
   CAS leaves no persistent state.
3. Atomically write `staged_rotation(B, token, expected_active=A,
   expected_setup_epoch)` after checking that no credential operation or
   diagnosis lease exists.
4. Materialize B with `O_EXCL`, mode `0600`, and `fsync` both the file and its
   parent directory.
5. In one SQLite CAS transaction, check `operation=staged_rotation`, token,
   expected active, setup epoch, and the absence of a diagnosis lease; then
   change `active=A + staged=B` to `active=B + retirement_pending=A`. If A does
   not exist, clear pending.
6. Idempotently retire A.
7. CAS-clear the retirement record.

The staged token is operation-specific. Generic retirement completion must not
complete a staged rotation. Owner abort is a token-matched CAS. Diagnosis
admission provides the reverse exclusion: its lease transaction rejects every
staged or retirement-pending credential operation, even if the request already
passed middleware.

## Recovery

Recovery is deliberately split:

- Before a new process accepts traffic, it unconditionally aborts any inherited
  staged rotation by retiring its exact durable version and CAS-clearing the
  staged record. A missing file is already retired. A partial file at the exact
  staged identifier path is safe to delete without validating its content
  digest when the credential directory is trusted and the object is a current
  uid, mode `0600` regular file reached without following symlinks. Unknown
  names, identifier mismatches, unsafe ownership or permissions, symlinks, and
  special files are not touched and fail startup; the process must not accept
  traffic. Active keys still require full version/digest validation and must be
  decryptable.
- During normal operation, a non-owner request that observes a staged rotation
  returns a retryable fail-closed response. It must not invoke generic
  retirement recovery or delete the staged key.
- The owning rotation request aborts its own staged version on a controlled
  error or cancellation. Cleanup failure leaves the durable staged record for
  startup recovery.
- Old-active retirement remains retryable by ordinary requests because the
  active switch has already committed and the pending version is detached.

Supporting more than one process or replica requires a future owner-liveness or
lease protocol. Startup cleanup is safe only under the current single-process,
single-replica contract.

## Failure Semantics

The implementation must converge from these crash points:

1. Before the staged database transaction: no key and no state change.
2. After staging but before materialization: startup clears the missing staged
   version and preserves A.
3. After materialization and directory `fsync`, before active CAS: startup
   removes B and preserves A.
4. After active CAS, before retiring A: B remains active and A remains durable
   retirement-pending.
5. After deleting A, before phase-two CAS: missing A is treated as idempotently
   retired and the pending record is cleared.

CAS conflict, key unlink failure, phase-two failure, and cancellation must
leave a retryable durable state. At no point may the active row reference a
missing or already-retired key. A staged reference may temporarily have no file
before materialization, and a retirement-pending reference may temporarily have
no file after unlink and before phase-two CAS. Those states are idempotent and
must converge on restart.

## Tests

Automated barriers and fault injection cover:

- Two rotations passing provider probe concurrently; only one may win the
  durable staged mutation and materialize a key file. A losing ephemeral plan
  leaves no file, database row, or log residue.
- A first request paused after staging or materialization while a second
  rotation and an unrelated API request fail closed without clearing B.
- A diagnosis request paused before admission cannot acquire a lease after a
  credential operation is staged; conversely, staging cannot begin while a
  diagnosis lease exists.
- Every crash point above followed by a simulated process restart.
- CAS loser, unlink failure, phase-two failure, and cancellation recovery.
- At each intermediate state, active has one existing safe file, and every
  non-active file belongs to exactly one durable staged/retirement-pending
  reference. The two allowed reference-without-file states are staged before
  materialization and retirement-pending after unlink.
- Final convergence leaves exactly one decryptable active key.
