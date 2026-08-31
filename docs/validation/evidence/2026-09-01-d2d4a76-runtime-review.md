# QA Run: `d2d4a76` First-Run Runtime Review

## Run Identity

- Run ID: `QA-RUN-20260901-D2D4A76`
- Test case IDs: `SETUP-003`, `SETUP-004`, `SETUP-006`, `SETUP-010`,
  `SETUP-011`, `DEPLOY-005`, `DEPLOY-006`, `SEC-001`, `SEC-002`, `SEC-003`
- End time: `2026-09-01T01:08:12+08:00`
- QA owner: `swat-qa`
- Source: detached clean worktree at
  `d2d4a76168e11937179141830965a66237bd5e66`
- Result: `FAIL`
- Defects: `QA-016` through `QA-020`

## Environment

- Environment: Ubuntu 24.04, `x86_64`
- Host: 4 CPU, 3,904,184,320 bytes RAM
- Docker Engine: `29.1.3`
- Compose: `2.40.3+ds1-0ubuntu1~24.04.1`
- QA image: `sqllens-web-api:qa-d2d4a76`
- Image ID:
  `sha256:d10ef031e87ed1fc3d8cebb4fff30b22522fae1970fe70310ce736a6af5615c8`
- Effective image user: `10001:10001`
- Mac, arm64, Windows, TiDB, Prometheus and GPU were not available in this
  run and remain unverified.

## Reproducible Baseline Commands

```bash
make bootstrap
make test
make lint
make typecheck
make build
docker build -f apps/api/Dockerfile -t sqllens-web-api:qa-d2d4a76 .
cd apps/web && npm audit --omit=dev --json && npm audit --json
```

Fresh results:

- API: 11/11 passed, with one upstream TestClient deprecation warning.
- Web: 2/2 passed.
- Ruff, mypy and both TypeScript checks passed.
- Vite build and Python wheel build passed.
- Docker image build passed.
- Both npm audits reported zero known vulnerabilities across the lockfile at
  run time.
- `pip check` reported no broken requirements.

Lockfile hashes:

```text
c88c2f043bbd6d1e98a2cf7eb5e4908c8d920100464a709d882e51cb89bb4a65  apps/web/package-lock.json
d9910548a7876eea6fafc87711668ea9af6d59302573b60fec7300cfd9941bf7  requirements/runtime.lock
e182f43a51cad671990ef54f7961da154fcb9c0ad1b0ac743539cb3586b66def  requirements/dev.lock
```

These passes prove build and local unit behavior only. They do not override
the integrated failures below.

## Adversarial Results

### Secret delivery

A root-owned `0600` host secret mounted read-only into the exact image was
owned by `0:0` in-container. UID 10001 received `Permission denied`. The
default launcher/runtime combination cannot ingest the bootstrap verifier.
See `QA-016` for the exact command and disposition.

### Setup recovery

After accepting the code, QA expired the setup session before policy commit:

```text
expired session PUT security-policy = 401 SETUP_SESSION_REQUIRED
fresh client bootstrap replay        = 401 BOOTSTRAP_INVALID
persisted setup state                = security_policy_required
initialized                          = false
```

No supported recovery route exists. See `QA-017`.

### External credential lifecycle

An external probe and finalize both returned 200. Restart then reported
`initialized=true` and `model_mode=external`, but SQLite contained only the
`setup_state` table and no credential-like column or reference. The canary was
not present in plaintext, but no recoverable encrypted credential existed.
See `QA-018`.

### Owner authentication

After rules finalization, a new anonymous client reached the Case handler:

```text
anonymous POST /api/v1/cases/sql = 501 FEATURE_NOT_IMPLEMENTED
auth/login/logout/user/session routes = []
```

No first Owner, password verifier, login, logout, application session, or RBAC
boundary exists. See `QA-019`.

### Provider response budget

The exact gateway accepted and fully parsed a fake 25,001-entry model list,
returning `verified`. There is no total deadline, byte, entry, field, or
nesting limit. See `QA-020`.

## Explicitly Missing Gates

The checked-in commands accurately fail closed rather than claiming coverage:

```text
make test-e2e       -> exit 2: Browser E2E is not implemented
make benchmark-2c4g -> exit 2: 2C4G qualification is not implemented
```

The `/api/v1/cases/sql` endpoint remains a `501` placeholder and is a separate
`#t11` morning-release blocker.

## Security And Resource Disposition

- The provider credential canary was absent from API bodies, logs used by the
  tests, and persistent files inspected in the isolated run.
- Node lockfile audits were clean at run time. No image vulnerability scan,
  SBOM/provenance verification, secret scan of the final release, or signed
  artifact was available, so `SEC-008` is not passed.
- No formal 2C4G latency, RSS, CPU, disk, queue, fuse or OOM measurement was
  possible because the benchmark and runnable Compose integration were not
  present.
- QA blocks `d2d4a76` as an integrated release candidate. Retest requires the
  exact regression scope documented in `QA-016` through `QA-020`, followed by
  real Compose, browser E2E, 2C4G and Mac execution.
