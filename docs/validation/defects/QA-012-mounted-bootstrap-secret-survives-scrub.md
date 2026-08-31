# QA-012: Mounted Bootstrap Secret Survives Host Scrub

Status: OPEN
Severity: High
Detected against: `feature/cross-platform-release@7bbb8da`
Owner: cross-platform release owner (`#t16`), not QA
Regression tests: required as a real-container integration test

## Impact

After the runtime confirms that the bootstrap verifier is committed,
`scrub_bootstrap_secret()` atomically replaces the host secret path with a new
empty file. Compose mounts the original file into the container. A bind mount
continues to reference that original inode, so replacing the host pathname
does not clear the bytes visible at `/run/secrets/bootstrap_code`.

The launcher therefore reports a successful cleanup while the full one-time
code remains readable inside the running application container. This violates
the frozen secret-lifecycle and plaintext-exclusion requirements.

## Reproduction

QA reproduced the underlying mechanism on the Ubuntu Docker host with the
checked-in Compose file-secret semantics:

```bash
printf '%s\n' 0123456789abcdef0123456789abcdef > "$secret"
docker run --rm -d --mount "type=bind,src=$secret,dst=/run/secret,readonly" \
  busybox sleep 60
printf '' > "$replacement"
mv -f "$replacement" "$secret"
wc -c < "$secret"
docker exec <container> cat /run/secret
```

Expected: the host path and container mount no longer expose the plaintext.

Actual: the host path is `0` bytes, but the container still returns the full
32-character code. A control using in-place truncation made both views zero
bytes.

## Required Disposition

- Make the confirmed cleanup operate on the inode mounted by the running
  container, or safely recreate the service with an empty secret mount.
- Add a real Docker test that reads the container secret after the handshake
  and proves it is empty or inaccessible.
- Retain the runtime gates that one initialization succeeds and replay,
  concurrent reuse, and reuse after restart fail.
- Prove the code is absent from host files, container files, logs,
  environment, command line, persistent data, and diagnostic archives.

This finding blocks the integrated release candidate.
