# QA-016: Bootstrap Secret Permissions Block The Non-Root Runtime

Status: RESOLVED on `integration/morning-rc@e1059c1`
Severity: High
Detected against: `feature/p0-runtime@d2d4a76` and
`feature/cross-platform-release@7bbb8da`
Fixed by runtime behavior `40bf68b`, independently retested through
`integration/morning-rc@e1059c1`
Owner: runtime and cross-platform release owners (`#t10`, `#t16`), not QA
Regression tests: required as a real-Compose cold-start test

## Impact

The runtime image executes as `10001:10001`. The launcher creates the host
bootstrap file as `0600`, owned by the host user (root on the QA host).
Docker preserves those ownership and mode bits for the file-secret bind mount.
The runtime therefore raises `PermissionError` while reading
`/run/secrets/bootstrap_code` and exits before it can persist the verifier or
serve the Web setup flow.

This is the default cross-line configuration, so the one-command installation
cannot cold start. Running the application as root or making the plaintext
secret generally readable would weaken an explicit security boundary and is
not an acceptable default workaround.

## Reproduction

QA built the exact runtime commit and mounted a root-owned `0600` fixture:

```bash
printf '%s\n' 0123456789abcdef0123456789abcdef > "$secret"
chmod 0600 "$secret"
docker run --rm \
  --mount "type=bind,src=$secret,dst=/run/secrets/bootstrap_code,readonly" \
  --entrypoint sh sqllens-web-api:qa-d2d4a76 \
  -c 'id; ls -ln /run/secrets/bootstrap_code; cat /run/secrets/bootstrap_code'
```

Actual evidence:

```text
uid=10001(sqllens) gid=10001(sqllens)
-rw------- 1 0 0 ... /run/secrets/bootstrap_code
cat: /run/secrets/bootstrap_code: Permission denied
```

Expected: the host secret remains private from other host users, while the
non-root runtime can read it exactly long enough to commit its verifier.

## Independent Retest

QA built the exact integration head into image
`sha256:8b4ad1811f585b212b2e9f5ad152066142069b2a67d37cc139fb7e3711c10b43`
and ran a clean, isolated real-Compose lifecycle on Ubuntu 24.04 amd64. The
launcher/runtime contract now sends the mode-0600 host code once through
stdin to a short-lived `bootstrap-ingest` container. It does not mount that
file into the long-running service.

Observed results:

```text
image and runtime UID/GID          = 10001:10001
host bootstrap mode before ingest = 0600
bootstrap-ingest output            = Bootstrap hash persisted.
host bytes after ingest            = 0
long-running mounts                = named volume at /data only
/run/secrets/bootstrap_code        = absent
bootstrap_hash_persisted           = true
first use / replay / restart replay = 200 / 401 / 401
plaintext in logs/inspect/volume   = no / no / no
```

The QA run used a separately named project and data volume to avoid touching
another agent's Docker state. The only harness change was the isolated
project/volume name; the image, commands, endpoints, UID and data mount were
the exact `e1059c1` implementation. The full command record is in
`docs/validation/evidence/2026-09-01-e1059c1-bootstrap-recovery-packaging.md`.

## Required Disposition

- Freeze one Mac/Linux-compatible secret-delivery mechanism that preserves
  host privacy and gives only the intended non-root container reader access.
- Keep the steady-state application non-root and do not broaden the secret to
  a generally readable file as the product default.
- Add a real Compose cold-start assertion for effective container UID/GID,
  host ownership/mode, successful verifier transaction, and post-handshake
  plaintext removal in both host and container views.
- Retain replay, restart, logs, environment, command-line, data-volume, and
  diagnostic-bundle canary checks.

The original permission mismatch is closed. Diagnostic-bundle canary coverage,
concurrent HTTP consumption and full setup completion remain part of
`SETUP-010`; this defect closure does not mark that broader case PASS.
