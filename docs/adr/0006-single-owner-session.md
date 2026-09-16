# ADR 0006: Single-Owner Session Boundary

Status: Accepted for P0 runtime
Date: 2026-09-01

## Context

Loopback binding limits network exposure but does not authenticate browser or
local-process requests. After initialization, diagnosis and settings APIs need
an explicit identity boundary that survives container restart without expanding
P0 into a multi-user RBAC system.

## Decision

The final setup transaction creates one Owner password verifier with scrypt and
advances a persistent session epoch. It also replaces the setup cookie with a
new, purpose-bound Owner cookie. The cookie is `HttpOnly` and `SameSite=Strict`;
TLS deployments additionally set `Secure`. The supported P0 launcher remains
loopback-only HTTP, and remote exposure remains unsupported without TLS.

`POST /api/v1/auth/login` issues an absolute-expiry Owner session after a
generic, globally rate-limited password check. `GET /api/v1/auth/session`
reports only authentication state and the session-bound CSRF token.
`POST /api/v1/auth/logout` requires that CSRF token and advances the persisted
epoch, invalidating captured cookies before and after restart. Setup recovery
also advances the setup and session epochs.

After finalization, product APIs deny anonymous requests by default. Setup
endpoints remain outside the Owner middleware, but their stage, epoch, and
setup-session checks reject every finalized mutation. Every authenticated
mutation, including diagnosis, credential rotation, deletion, and logout, also
requires the Owner CSRF token. Health, login/session status, setup status, and
static assets remain public.

## Consequences

- Losing the Owner password requires a future explicit reset workflow; P0 does
  not provide a remote bypass or hidden recovery credential.
- Logout revokes all current Owner sessions because P0 has exactly one Owner.
- Multi-user accounts, roles, SSO, remote administration, and idle-session
  tracking remain outside P0.
- API and browser tests must cover anonymous denial, wrong-password limits,
  CSRF, expiry, logout replay, restart persistence, and credential redaction.
