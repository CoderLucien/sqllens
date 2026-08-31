# QA-010: Read-Only Preflight Truncates Bootstrap Secret

Status: RESOLVED in launcher scope on `feature/cross-platform-release@7bbb8da`
Severity: High
Detected against: `feature/cross-platform-release@cbfd26e`
Owner: cross-platform release owner (`#t16`), not QA
Regression tests: required in `tests/release/test_launch_sh.py`

## Impact

`launch.sh check` is documented as a preflight that does not change
application state. The launcher nevertheless calls `prepare_bootstrap_file`
before dispatching the action. That function creates the state directory and
truncates `bootstrap-code`; the exit trap truncates it again.

A check run while an instance is starting can therefore erase the source
secret before the application has read and persisted its verifier. The port
check does not protect this path because the truncation happens before port
validation. Concurrent or repeated `start` calls also share the same unlocked
path, overwrite each other's code and can present a user with a code that does
not match the verifier ultimately persisted by the runtime. Even outside that
race, a successful preflight mutates a clean host and destroys a pre-existing
code contrary to its public contract.

## Reproduction

On the Ubuntu QA host, with Docker available and port 18082 free:

```bash
state=$(mktemp -d)
printf '%s\n' 'qa-preexisting-bootstrap-sentinel' > "$state/bootstrap-code"
chmod 600 "$state/bootstrap-code"
SQLLENS_STATE_DIR="$state" SQLLENS_PORT=18082 ./launch.sh check
wc -c < "$state/bootstrap-code"
```

Expected: the command succeeds without creating, modifying or deleting state;
the final size remains 34 bytes.

Actual: the command succeeds and the final size is `0`.

## Required Disposition

- `check` must not create the state directory or bootstrap file and must not
  install a cleanup trap that mutates existing state.
- Bootstrap creation and cleanup must be scoped to `start` only.
- `start` must use a portable exclusive lock plus atomic secret creation;
  concurrent starts must not produce competing codes, and an already running
  or initialized installation must return its URL without rotating bootstrap
  state.
- Add regressions proving both successful and failed `check` leave an existing
  secret byte-for-byte unchanged and do not create state on a clean host. Add
  concurrent double-start and repeated-start regressions as well.
- Retain the separate container integration gate: `start` may clear the host
  secret only after `GET /api/v1/setup/status` returns HTTP 200 with JSON
  boolean `bootstrap_hash_persisted` strictly equal to `true`; one bootstrap
  succeeds and replay fails after cleanup and restart.

This finding blocked `cbfd26e` from entering the integrated release candidate.
It did not invalidate the independently passing Compose contract or static
preflight tests.

## Resolution Evidence

QA independently reran the original sentinel reproduction against `7bbb8da`.
Successful and failed `check` calls left the existing file unchanged, and a
successful check on a clean path did not create the state directory. The
release suite also passed 28/28 including concurrent and retained-secret
cases.

The later Docker bind-mount cleanup defect is tracked separately as QA-012;
closing this finding does not sign off the container secret lifecycle.
