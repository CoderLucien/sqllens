# ADR 0005: External Provider Credential Vault

Status: Accepted for P0 runtime
Date: 2026-09-01

## Context

External-model mode must survive an application restart without asking for the
provider API key again. The key must not appear in SQLite as plaintext, image
layers, environment variables, process arguments, application logs, or support
diagnostics. Missing or damaged key material must not leave the UI reporting a
usable external model.

## Decision

SQLLens uses the pinned `cryptography` AES-GCM implementation instead of custom
cryptography. SQLite stores only the authenticated ciphertext, key version, and
non-secret provider metadata. A separate container volume stores 32-byte key
files; its mount root is owned by runtime UID 10001 with mode `0700`, and each
key file has mode `0600`. Associated data binds ciphertext to the SQLLens
provider-credential format.

External setup becomes ready only after a bounded provider probe succeeds, the
ciphertext commits, and the stored credential can be decrypted. An authenticated
Owner request with CSRF protection may rotate a missing, damaged, or valid key.
Rotation first creates an ephemeral in-memory plan, then atomically records its
version, operation token, expected active credential, and setup epoch as
`staged_rotation` in SQLite. Only the winning request may materialize the
versioned key with `O_EXCL`, mode `0600`, and file-plus-directory `fsync`. A
second transaction atomically switches the active reference and converts the
old version into retirement state. The service then removes that old key
idempotently outside SQLite and a compare-and-swap transaction clears the
pending state. No key file may be created before it has a durable staged
reference.

P0 permits one API process and one Compose replica. On startup, inherited staged
work is aborted before traffic: a missing file is already clean, while an exact
safe partial file is removed by its durable identifier without trusting its
content digest. Live non-owner requests never resume or delete staged work and
instead fail closed. Diagnosis admission and credential mutation reject each
other inside their SQLite transactions. Recovery, rules finalization, rotation,
and deletion use the same operation-aware cleanup boundary. These rules prevent
an active database reference from pointing at a deleted key and make write,
unlink, commit, and process-crash failures retryable.

Normal reads never create or replace key material. Symlinks, non-regular files,
wrong ownership, unexpected modes, invalid lengths, malformed ciphertext, and
authentication failures all fail closed. Startup also rejects any credential
key file outside the active or durable staged/retirement closure without
deleting it. These failures produce the explicit
`model_recovery_required` state while deterministic rules diagnosis remains
available to the authenticated Owner.

## Consequences

- The credential volume is part of backup and restore as a separate security
  asset from the data volume; either part alone cannot recover the API key.
- Release diagnostics must exclude both volumes and all container environment
  values.
- Real-container tests must cover non-root ownership and modes, setup, restart,
  damaged-key rotation, deletion, and plaintext canary scans.
- Multi-owner access, remote administration, and external key-management
  services remain outside P0.
