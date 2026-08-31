# QA Run: Bootstrap, Recovery, And Preview Packaging

## Run Identity

- Run ID: `QA-RUN-20260901-E1059C1`
- Test case IDs: `SETUP-004`, `SETUP-010`, `DEPLOY-005`, `DEPLOY-006`,
  `PLAT-013`, `PLAT-014`
- End time: `2026-09-01T01:50:00+08:00`
- QA owner: `swat-qa`
- Runtime/package source: detached clean worktree at
  `e1059c10a882cd49623efa835f905443be246511`
- Recovery source: detached clean worktree at
  `31985839c283108f19c8a7ed9efd544576db42e0`
- Result: `FAIL` overall; `QA-016` resolved, `QA-017` remains open

## Environment

- Ubuntu 24.04, amd64
- Python 3.12.3, Node 22.22.1, npm 10.9.4
- Docker Engine 29.1.3
- Compose `2.40.3+ds1-0ubuntu1~24.04.1`
- Runtime image: `sqllens-qa:e1059c1`
- Runtime image ID:
  `sha256:8b4ad1811f585b212b2e9f5ad152066142069b2a67d37cc139fb7e3711c10b43`
- Effective image user: `10001:10001`
- No Mac, arm64, Windows, TiDB, Prometheus or GPU runner was available.

## Baseline Verification

At `e1059c1`:

```text
make test                         API 16/16; Web 2/2
make lint                         passed
make typecheck                    passed
make build                        passed
SQLLENS_RUN_DOCKER_TESTS=1
  python -m unittest discover
  -s tests/release -v             44/44
docker build ...                  passed
```

At `3198583`:

```text
make test                         API 17/17; Web 3/3
make lint                         passed
make typecheck                    passed
make build                        passed
```

Both API runs emitted one upstream Starlette TestClient deprecation warning.

## Real Compose Bootstrap Lifecycle

QA rendered the exact Compose service and changed only the project and named
volume identifiers so the run could not overwrite another agent's Docker
state. The test used a private mode-0600 host fixture, ran `migrate`, piped the
fixture to `bootstrap-ingest`, scrubbed the host file, and started the
long-running service.

Observed results:

```text
default service                   = web-api only
container health                  = healthy
container UID/GID                 = 10001:10001
long-running mounts               = isolated named volume -> /data
runtime bootstrap-secret path     = absent
host secret bytes after ingest    = 0
bootstrap_hash_persisted          = true
plaintext in logs                 = no
plaintext in inspect/env/cmd      = no
plaintext in data volume          = no
first bootstrap use               = HTTP 200
immediate replay                  = HTTP 401 BOOTSTRAP_INVALID
replay after container restart    = HTTP 401 BOOTSTRAP_INVALID
```

The isolated container, network and volume were removed after evidence was
captured. This closes the concrete UID/permission failure in `QA-016` without
claiming the rest of `SETUP-010` passed.

## Recovery Epoch And CAS

An independent adversarial script at `3198583` verified:

- cookie loss produces `setup_session_missing` and a `bootstrap-reissue`
  recovery action;
- reissue increments the setup epoch and invalidates both the old code and old
  setup session;
- a replacement code remains usable after application reconstruction;
- expired codes produce `bootstrap_expired`;
- an old code already computing its scrypt hash cannot commit after reissue;
- a stale provider probe cannot commit across the epoch/policy boundary;
- the Web test renders the recovery command and hides the bootstrap input.

The integrated package at `e1059c1` has no `recover-setup` launcher action.
`QA-017` therefore remains open: the UI points to a command the user cannot
execute from the current Release.

## Preview Artifact Inspection

With `SOURCE_DATE_EPOCH=1788200000`, QA built the package twice using:

```text
python3 scripts/release/build_release.py \
  --source . --output <empty-dir> \
  --version 0.1.0-dev.1 --revision e1059c1 --skip-dmg
```

Both runs produced identical `SHA256SUMS`. The first run contained:

```text
2cf47cdcb76905660a07a3f2bc45a84977c14b0dbb7b6c297f37a00c195aceaa  sqllens-0.1.0-dev.1-macos-preview.app.zip
3b047d67b1a5c8dfb758752bd9e1cd88ef195b100190d9183db28906f1e13e41  sqllens-0.1.0-dev.1-source.tar.gz
```

`sha256sum -c` passed. QA additionally verified:

- archive paths were relative, regular files only, with no traversal;
- CLI and App-embedded release trees were byte-identical;
- the staged launcher, Compose, Dockerfile, entrypoint, API, Web, locks and
  project metadata matched the fixed source;
- `.git`, `.venv`, `node_modules`, egg-info, env files and bytecode were absent;
- ZIP metadata and native `unzip` preserved mode 0755 for the App executable
  and launchers;
- metadata honestly says unsigned, not notarized, and macOS unverified;
- the extracted CLI and App release passed read-only preflight without creating
  setup state;
- the extracted CLI independently built image
  `sha256:070ec88719ffb2714f357480b9785c0b87c8297ba9ede8662b3f0c3373fd3116`
  as UID 10001;
- a bounded secret-pattern scan outside test fixtures found no key material.

No DMG was generated because this Linux host lacks `hdiutil`. App launch,
Docker Desktop behavior, filesystem semantics and Gatekeeper interaction were
not run on macOS. They remain `unverified`, not PASS.

## Disposition

- Close `QA-016` on `e1059c1`.
- Keep `QA-017` open until the launcher implements and independently passes a
  local `recover-setup` flow against the integrated runtime.
- Do not mark `SETUP-010`, `DEPLOY-005`, `PLAT-013` or `PLAT-014` PASS from this
  partial run.
- Do not describe the App ZIP or a future DMG as Mac-validated until a clean
  real Mac executes the three-step flow.
