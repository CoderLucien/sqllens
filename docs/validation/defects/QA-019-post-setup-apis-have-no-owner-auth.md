# QA-019: Post-Setup APIs Have No Owner Authentication Boundary

Status: OPEN
Severity: High
Detected against: `feature/p0-runtime@d2d4a76`
Owner: runtime owner (`#t10`), not QA
Regression tests: required at API and browser E2E layers

## Impact

The `#t10` acceptance criteria require initialization to create one Owner
identity and require every post-setup API except health, login, and necessary
static resources to reject anonymous requests. The current runtime creates
only a setup cookie. It has no Owner record, password verifier, login, logout,
or authenticated application session routes.

After rules-mode finalization, a fresh anonymous client reaches the SQL Case
handler and receives its current `501 FEATURE_NOT_IMPLEMENTED` result instead
of an authentication error. Once Layer 1 replaces that placeholder, the same
middleware would expose diagnosis/case data and mutations anonymously.

## Reproduction

QA finalized rules mode, discarded the setup client, and used a fresh client:

```text
anonymous POST /api/v1/cases/sql = 501 FEATURE_NOT_IMPLEMENTED
auth/login/logout/user/session routes = []
```

Expected: setup creates the single Owner, and a fresh client is rejected by
the authentication layer before the Case handler runs.

## Required Disposition

- Create the initial Owner with a memory-hard password verifier during setup.
- Add login, logout, idle/absolute expiry, restart-persistent session handling,
  CSRF enforcement, authentication throttling, and the P0 Owner authorization
  policy.
- Make diagnosis, case, connector, import, review, and settings APIs default
  deny for anonymous callers before invoking their handlers.
- Add regressions for wrong password, rate limits, session fixation, logout,
  expiry, restart, CSRF, and anonymous/object-level access.

This finding blocks `#t10` acceptance and the morning Layer 1 release candidate.
