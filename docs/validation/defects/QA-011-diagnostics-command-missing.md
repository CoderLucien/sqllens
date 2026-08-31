# QA-011: Launcher Recommends Missing Diagnostics Command

Status: RESOLVED in launcher scope on `feature/cross-platform-release@7bbb8da`
Severity: Medium
Detected against: `feature/cross-platform-release@cbfd26e`
Owner: cross-platform release owner (`#t16`), not QA
Regression tests: required in `tests/release/test_launch_sh.py`

## Impact

The health-check failure and timeout paths tell the user to run
`./launch.sh diagnostics`, but argument parsing accepts only `start` and
`check`. The prescribed remediation therefore fails with `unknown action` at
the exact point where the installation needs actionable recovery. This
violates the three-step deployment requirement that failures remain within the
current step and provide executable remediation.

## Reproduction

```bash
./launch.sh diagnostics
```

Expected: a bounded, redacted diagnostic report containing the effective
Compose summary and allowlisted container status without application logs,
container environment, credentials, or user data.

Actual: the launcher exits non-zero with `unknown action: diagnostics`.

## Required Disposition

Implement the documented action or replace every failure message with an
existing, safe command before the release candidate. Add launcher regressions
for both unhealthy and timeout paths that execute the exact suggested command
and verify that its output contains no bootstrap code, provider token or raw
SQL.

This finding blocked `cbfd26e` from entering the integrated release candidate.
It did not invalidate the Compose contract.

## Resolution Evidence

QA executed `./launch.sh diagnostics` against a real Ubuntu Docker daemon. The
action created a readable archive. Independent canaries for the bootstrap code
and a provider token were absent from the extracted content, while the source
bootstrap file remained unchanged. Runtime logs and application-level
redaction remain separate integrated-RC gates.
