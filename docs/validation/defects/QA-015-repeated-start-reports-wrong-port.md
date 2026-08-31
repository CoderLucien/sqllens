# QA-015: Repeated Start Reports An Unpublished Port

Status: OPEN
Severity: Medium
Detected against: `feature/cross-platform-release@7bbb8da`
Owner: cross-platform release owner (`#t16`), not QA
Regression tests: required in `tests/release/test_launch_sh.py`

## Impact

When a managed container is already running, preflight accepts it before
checking whether the requested `SQLLENS_PORT` matches the existing published
port. The launcher then formats the URL from the new environment value. A
repeat start can exit successfully while directing the user to a port where no
application is listening.

## Reproduction

With a managed instance published on 8080:

```bash
SQLLENS_PORT=18001 ./launch.sh start
```

Expected: report the actual published URL or reject the mismatch with an
executable remediation.

Actual: the launcher reports `http://127.0.0.1:18001` without changing the
container mapping.

## Required Disposition

Read and validate the actual loopback published port for a managed instance,
or fail closed when it differs from the requested port. Add repeated-start
tests for matching and mismatched port values.
