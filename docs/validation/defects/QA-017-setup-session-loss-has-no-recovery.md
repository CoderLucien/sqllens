# QA-017: Setup Session Loss Has No Recovery Path

Status: OPEN
Severity: High
Detected against: `feature/p0-runtime@d2d4a76`
Owner: runtime owner (`#t10`), not QA
Regression tests: required at API, container-restart, and Web E2E layers

## Impact

A valid bootstrap code is consumed before the remaining Web setup steps. If
the browser loses its cookie or the 30-minute setup session expires, the
database remains at `security_policy_required`, but the consumed code cannot
be replayed and there is no route to issue or authorize a replacement.

The same dead end occurs when an unconsumed code expires or reaches the failed
attempt limit: the verifier remains marked as persisted, so the launcher has
no supported reason to create another code. Recovery requires deleting state
or using an undocumented internal operation, violating the resumable
three-step installation contract.

## Reproduction

Using the exact commit with a one-second setup-session TTL, QA accepted the
bootstrap, advanced the injected clock, and retried from both the original and
a fresh client:

```text
expired session PUT security-policy = 401 SETUP_SESSION_REQUIRED
fresh client bootstrap replay        = 401 BOOTSTRAP_INVALID
persisted setup state                = security_policy_required
initialized                          = false
```

The route table contains no reissue, recovery, or setup re-authentication
endpoint.

## Required Disposition

- Provide a local, explicitly authorized, idempotent recovery flow for code
  expiry, failed-attempt lockout, consumed-code cookie loss, session expiry,
  process interruption, and container restart.
- Reject every old code after replacement and never reopen an already
  finalized installation remotely.
- Keep recovery inside the launch/Web setup step; do not require a destructive
  data purge, hidden CLI, database edit, or extra deployment step.
- Add API and Web E2E regressions for every interrupted state, including
  concurrent recovery requests and restart persistence.

This finding blocks the three-step setup journey.
