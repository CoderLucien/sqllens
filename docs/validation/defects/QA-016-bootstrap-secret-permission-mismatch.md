# QA-016: Bootstrap Secret Permissions Block The Non-Root Runtime

Status: OPEN
Severity: High
Detected against: `feature/p0-runtime@d2d4a76` and
`feature/cross-platform-release@7bbb8da`
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

This finding blocks the first runnable release candidate.
