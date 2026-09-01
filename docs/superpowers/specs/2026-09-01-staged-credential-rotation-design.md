# Durable Staged Credential Rotation

## Scope

This design closes the credential-key orphan window in the authenticated
external-provider rotation path. It does not add multi-process or multi-replica
support. The P0 runtime remains one `web-api` process and one Compose replica.

The invariant is:

> Every credential key file has exactly one durable database reference as the
> active version or as a staged/retirement-pending version. After recovery, the
> directory contains only the decryptable active key.

No API key plaintext or key bytes are stored in SQLite.

## State Machine

The only valid rotation sequence is:

1. `idle(active=A)`
2. Generate an in-memory rotation plan containing random key bytes and a
   deterministic version/path. No file exists yet.
3. Atomically write `staged_rotation(B, token, expected_active=A,
   expected_setup_epoch)` after checking that no credential operation or
   diagnosis lease exists.
4. Materialize B with `O_EXCL`, mode `0600`, and `fsync` both the file and its
   parent directory.
5. In one SQLite CAS transaction, change `active=A + staged=B` to
   `active=B + retirement_pending=A`. If A does not exist, clear pending.
6. Idempotently retire A.
7. CAS-clear the retirement record.

The staged token is operation-specific. Generic retirement completion must not
complete a staged rotation.

## Recovery

Recovery is deliberately split:

- Before a new process accepts traffic, it unconditionally aborts any inherited
  staged rotation by retiring its exact durable version and CAS-clearing the
  staged record. A missing file is already retired. Unsafe ownership, type,
  permissions, symlinks, or special files fail closed.
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
missing or already-retired key.

## Tests

Automated barriers and fault injection cover:

- Two rotations passing provider probe concurrently; only one may create key
  material or a file.
- A first request paused after staging or materialization while a second
  rotation and an unrelated API request fail closed without clearing B.
- Every crash point above followed by a simulated process restart.
- CAS loser, unlink failure, phase-two failure, and cancellation recovery.
- At each intermediate state, filesystem versions equal the disjoint union of
  active and durable staged/retirement-pending versions.
- Final convergence leaves exactly one decryptable active key.

