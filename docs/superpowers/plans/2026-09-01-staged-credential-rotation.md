# Durable Staged Credential Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure every versioned provider credential key is durably staged before file creation and converges safely across concurrency, errors, and process crashes.

**Architecture:** Reuse the single credential-operation slot with an operation-aware `staged_rotation` state and token. A vault rotation plan is ephemeral until SetupStore wins a transactional staged CAS; only then is its deterministic key path materialized, followed by an atomic active/pending switch. Startup aborts inherited staged operations before traffic, while live non-owner requests fail closed.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy Core, SQLite, `cryptography` AES-GCM, pytest/TestClient.

## Global Constraints

- P0 supports one `web-api` process and one Compose replica only.
- No API key plaintext or key bytes may enter SQLite, logs, errors, or diagnostics.
- Active credential references always have an existing, safe, digest-matching, decryptable key.
- A staged partial file may be deleted only by its durable identifier/token and exact safe path; unknown or unsafe files are never touched.
- Diagnosis admission and credential mutation are transactionally mutually exclusive.
- Do not modify `apps/api/Dockerfile`, Python dependency locks, or wheelhouse files; RD2 owns those paths.

---

### Task 1: Ephemeral Rotation Plan And Durable File Materialization

**Files:**
- Modify: `apps/api/src/sqllens_api/credentials.py`
- Test: `tests/api/test_credentials.py`

**Interfaces:**
- Produces: `CredentialRotationPlan(identifier: str, key_version: str, key: bytes)` with secret-safe repr.
- Produces: `CredentialVault.plan_rotation(previous: EncryptedCredential | None) -> CredentialRotationPlan`.
- Produces: `CredentialVault.materialize_rotation(plaintext: str, plan: CredentialRotationPlan) -> EncryptedCredential`.
- Produces: `CredentialVault.retire_staged_version(version: str) -> None`, which authorizes deletion by the staged identifier/path and safe filesystem metadata, not content digest.

- [ ] **Step 1: Write RED vault tests**

```python
def test_rotation_plan_is_ephemeral_until_materialized(tmp_path: Path) -> None:
    key_path = tmp_path / "secrets" / "credential.key"
    vault = CredentialVault(key_path)
    active = vault.encrypt("old")
    before = set(key_path.parent.iterdir())
    plan = vault.plan_rotation(active)
    assert plan.key_version not in repr(plan)
    assert plan.key.hex() not in repr(plan)
    assert set(key_path.parent.iterdir()) == before

    encrypted = vault.materialize_rotation("new", plan)

    assert encrypted.key_version == plan.key_version
    assert vault.decrypt(encrypted) == "new"


def test_staged_retirement_removes_a_safe_partial_file_without_digest_match(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "secrets" / "credential.key"
    vault = CredentialVault(key_path)
    active = vault.encrypt("old")
    plan = vault.plan_rotation(active)
    staged_path = key_path.with_name(
        f"{key_path.stem}.file-v1-{plan.identifier}{key_path.suffix}"
    )
    staged_path.write_bytes(b"partial")
    staged_path.chmod(0o600)

    vault.retire_staged_version(plan.key_version)

    assert not staged_path.exists()
```

Add a separate `os.fsync` spy test that records `os.fstat(fd).st_mode` and
asserts one regular-file call followed by one directory call. Add parameterized
symlink, FIFO, and mode-0644 staged-path cases that raise
`CredentialUnavailableError` and leave the object untouched.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `.venv/bin/python -m pytest -q tests/api/test_credentials.py`

Expected: FAIL because the plan/materialize/staged-retire interfaces do not exist.

- [ ] **Step 3: Implement the minimal vault lifecycle**

```python
@dataclass(frozen=True, slots=True, repr=False)
class CredentialRotationPlan:
    identifier: str
    key_version: str
    key: bytes

def plan_rotation(
    self, previous: EncryptedCredential | None
) -> CredentialRotationPlan:
    self._validate_rotation_source_for(previous)
    identifier = secrets.token_hex(16)
    key = secrets.token_bytes(32)
    return CredentialRotationPlan(
        identifier=identifier,
        key_version=self._versioned_key_version(identifier, key),
        key=key,
    )

def materialize_rotation(
    self, plaintext: str, plan: CredentialRotationPlan
) -> EncryptedCredential:
    self._write_planned_key(plan)
    return self._encrypt_with_key(plaintext, plan.key, plan.key_version)
```

`retire_staged_version(version)` parses the versioned identifier, opens the
trusted parent directory with `O_DIRECTORY | O_NOFOLLOW`, inspects the exact
identifier-derived basename with `follow_symlinks=False`, accepts missing as
success, and unlinks only a current-uid regular file with mode `0600`.

Materialization uses `O_EXCL | O_NOFOLLOW`, mode `0600`, `fsync(file)`, and `fsync(parent_dir)`. It does not erase a partial file with an untracked best-effort path; the already-durable staged state owns recovery.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `.venv/bin/python -m pytest -q tests/api/test_credentials.py`

Expected: all credential tests pass.

- [ ] **Step 5: Commit the vault unit**

```bash
git add apps/api/src/sqllens_api/credentials.py tests/api/test_credentials.py
git commit -m "feat: stage credential keys before materialization"
```

### Task 2: Operation-Aware SQLite Staged Rotation

**Files:**
- Modify: `apps/api/src/sqllens_api/setup.py`
- Test: `tests/api/test_owner_auth.py`
- Test: `tests/api/test_setup_gate.py`

**Interfaces:**
- Consumes: `CredentialRotationPlan.key_version` from Task 1.
- Produces: `SetupSnapshot.credential_retirement_token: str | None`.
- Produces: `SetupStore.begin_staged_rotation(staged_version: str, token: str, expected_credential: EncryptedCredential | None, expected_setup_epoch: int, now: datetime) -> bool`.
- Produces: `SetupStore.commit_staged_rotation(request: ProviderProbeRequest, result: ProviderProbeResult, credential: EncryptedCredential, token: str, now: datetime) -> bool`.
- Produces: `SetupStore.abort_staged_rotation(version: str, token: str, now: datetime) -> bool`.
- Changes: `complete_credential_retirement` rejects `staged_rotation`.

- [ ] **Step 1: Write RED store tests for legal transitions**

Add five named tests:

1. `test_staged_rotation_cas_records_token_version_expected_active_and_epoch`
   reads the raw setup row and asserts every durable field.
2. `test_only_one_concurrent_staged_rotation_wins` starts two threads against
   the same expected active credential and asserts results `[False, True]`.
3. `test_commit_atomically_switches_active_and_moves_old_version_to_retirement`
   asserts active B and pending A are visible in one post-commit snapshot.
4. `test_abort_requires_matching_version_and_token` proves wrong token/version
   cannot clear staged state and the exact pair can.
5. `test_generic_retirement_completion_rejects_staged_rotation` calls the
   generic phase-two method and asserts staged state is unchanged.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `.venv/bin/python -m pytest -q tests/api/test_owner_auth.py tests/api/test_setup_gate.py`

Expected: FAIL on missing staged state/token interfaces.

- [ ] **Step 3: Add schema migration and CAS methods**

Add nullable columns for the operation token, expected active ciphertext/version,
and staged setup epoch. `begin_staged_rotation` checks finalized state, setup
epoch, expected active, no existing credential operation, and no diagnosis
lease. `commit_staged_rotation` checks operation, token, staged version,
expected active, epoch, and no diagnosis lease in one update. `abort` clears only
the exact staged version/token. Neither method stores plan key bytes.

- [ ] **Step 4: Run focused store tests and verify GREEN**

Run: `.venv/bin/python -m pytest -q tests/api/test_owner_auth.py tests/api/test_setup_gate.py`

Expected: all setup/owner tests pass.

- [ ] **Step 5: Commit the store unit**

```bash
git add apps/api/src/sqllens_api/setup.py tests/api/test_owner_auth.py tests/api/test_setup_gate.py
git commit -m "feat: persist staged credential rotation state"
```

### Task 3: API Ownership, Startup Recovery, And Diagnosis Exclusion

**Files:**
- Modify: `apps/api/src/sqllens_api/app.py`
- Modify: `apps/api/src/sqllens_api/diagnosis.py`
- Modify: `docs/adr/0005-external-provider-credential-vault.md`
- Test: `tests/api/test_owner_auth.py`
- Test: `tests/api/test_sql_diagnosis.py`

**Interfaces:**
- Consumes: Task 1 vault plan/materialize/retire methods.
- Consumes: Task 2 begin/commit/abort CAS methods.
- Changes: rotation endpoint returns retryable 409 before file materialization when staged state is occupied.
- Changes: diagnosis reservation raises capacity/fail-closed before parsing or egress whenever credential staged/retirement state exists.

- [ ] **Step 1: Write RED barriers and crash tests**

Add these exact tests:

- `test_concurrent_rotations_create_only_one_durable_stage_and_key_file`
- `test_non_owner_request_cannot_resume_or_delete_live_staged_rotation`
- `test_diagnosis_admission_and_staged_rotation_are_bidirectionally_exclusive`
- `test_restart_recovers_stage_before_materialization`
- `test_restart_recovers_materialized_stage_before_active_cas`
- `test_restart_recovers_safe_partial_write_or_fsync_file`
- `test_restart_finishes_old_key_retirement_before_and_after_unlink`
- `test_unsafe_or_unknown_staged_path_prevents_startup_without_deletion`

The concurrency tests use `threading.Barrier` and `threading.Event` around the
probe, staged CAS, and materialization boundaries. The restart tests construct a
new `create_app(settings=settings, clock=clock)` after each injected crash point and assert the
active/pending/file-set invariant before and after recovery.

- [ ] **Step 2: Run the named tests and verify RED**

Run: `.venv/bin/python -m pytest -q tests/api/test_owner_auth.py tests/api/test_sql_diagnosis.py -k 'staged or rotation or credential_operation'`

Expected: failures reproduce concurrent orphaning, missing startup recovery, and one-way diagnosis exclusion.

- [ ] **Step 3: Implement owner-only live cleanup and startup convergence**

After provider probe, the endpoint creates an ephemeral plan, wins
`begin_staged_rotation`, materializes, and calls `commit_staged_rotation` without
an intervening `await`. Controlled error/cancellation retires only the matching
staged version and token. Startup cleans inherited staged state before returning
the FastAPI app; a cleanup safety error aborts app creation. Middleware never
generic-resumes a live `staged_rotation`.

- [ ] **Step 4: Add reverse exclusion to diagnosis reservation**

Inside the existing `BEGIN IMMEDIATE`, reject setup rows whose
`credential_retirement_pending_version` is non-null before inserting a job or
admission lease. Existing-key replay remains first and does not create egress.

- [ ] **Step 5: Run named tests and verify GREEN**

Run: `.venv/bin/python -m pytest -q tests/api/test_owner_auth.py tests/api/test_sql_diagnosis.py -k 'staged or rotation or credential_operation'`

Expected: all named concurrency and recovery tests pass.

- [ ] **Step 6: Update ADR and commit the integration unit**

```bash
git add apps/api/src/sqllens_api/app.py apps/api/src/sqllens_api/diagnosis.py \
  tests/api/test_owner_auth.py tests/api/test_sql_diagnosis.py \
  docs/adr/0005-external-provider-credential-vault.md
git commit -m "fix: make credential rotation crash recoverable"
```

### Task 4: Full Verification And Fixed Handoff

**Files:**
- Verify all modified files from Tasks 1-3.

**Interfaces:**
- Produces: one clean fixed commit for Reviewer, QA, and integration.

- [ ] **Step 1: Repeat the high-risk barrier set five times**

Run:

```bash
for i in 1 2 3 4 5; do
  .venv/bin/python -m pytest -q tests/api/test_credentials.py \
    tests/api/test_owner_auth.py tests/api/test_sql_diagnosis.py \
    -k 'staged or rotation or credential_operation'
done
```

Expected: every iteration passes with no orphan key files.

- [ ] **Step 2: Run all project gates**

Run: `make test && make lint && make typecheck && make build && git diff --check`

Expected: API, Web, lint, typecheck, production build, wheel, and diff checks pass.

- [ ] **Step 3: Verify scope and clean commit**

Run:

```bash
git status --short
git diff 40f1b7bb1c3addac423851667e284baa343a9a13..HEAD -- \
  apps/api/Dockerfile requirements
```

Expected: worktree clean after commit; no Dockerfile or dependency-lock changes.

- [ ] **Step 4: Refresh task checkpoints and review context**

Record the exact head, named test counts, full gate results, and remaining
RD2-owned supply-chain integration work in `#t10/#t11`. Add review context for
the main reply thread; if the review API fails, state that explicitly.
