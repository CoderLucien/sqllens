# QA-013: Compose Build Context Escapes The Release Root

Status: OPEN
Severity: High
Detected against: `feature/cross-platform-release@7bbb8da`
Owner: cross-platform release owner (`#t16`), not QA
Regression tests: required in the release contract suite

## Impact

The launcher passes the repository root as Compose's `--project-directory`,
while `deploy/compose.json` declares build context `..`. Compose therefore
resolves the build context to the parent of the release, not the release root.
On the current worktree it resolves to `/root` and looks for
`/root/apps/api/Dockerfile` instead of the frozen
`<release>/apps/api/Dockerfile`.

The default one-command start cannot build the runtime image. A broad parent
context would also risk sending unrelated host files to the builder if a
matching Dockerfile happened to exist.

## Reproduction

```bash
SQLLENS_BOOTSTRAP_FILE=/dev/null docker compose \
  --project-directory "$PWD" -f deploy/compose.json config --format json
SQLLENS_BOOTSTRAP_FILE=/dev/null docker compose \
  --project-directory "$PWD" -f deploy/compose.json build web-api
```

Expected: build context is the release root and Dockerfile is
`<release>/apps/api/Dockerfile`.

Actual: the resolved context is `/root`; the build fails with
`lstat /root/apps: no such file or directory`.

## Required Disposition

- Resolve every build context and Dockerfile within the extracted release
  root, independent of the caller's working directory.
- Add a real `docker compose config` assertion for the canonical path and a
  clean image build from a release directory whose parent has no project
  files.
- Keep a restrictive `.dockerignore` and fail if the effective build context
  is broader than the release root.

This finding blocks the first runnable Docker integration.
