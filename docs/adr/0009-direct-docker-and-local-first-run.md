# ADR 0009: Direct Docker Image And Local First Run

Status: Accepted for vNext P0
Date: 2026-09-02
Supersedes: ADR 0004 customer happy-path deployment

## Context

The first P0 implementation spent substantial effort on release archives,
launchers, terminal bootstrap codes, cross-platform gates, and supply-chain
closure before the diagnostic customer journey had product value. Customers
expect an official image they can run directly, not a source build or a release
toolchain they must understand.

The approved vNext journey is one copied command followed by
http://localhost:18080. P0 does not need a release archive, Compose selection,
platform selector, or terminal bootstrap exchange.

## Decision

The normal P0 customer receives one official OCI image with linux/amd64 and
linux/arm64 manifests. The published installation page renders one docker run
command pinned by digest. The command fixes:

- loopback binding at 127.0.0.1:18080;
- named data and secrets volumes;
- non-root image user;
- read-only root filesystem;
- no-new-privileges and all capabilities dropped;
- a bounded noexec/nosuid temporary filesystem;
- restart behavior.

Docker selects the matching architecture. Customers do not compile source,
edit environment files, run migrations, choose an override, or enter product
parameters before opening the Web UI.

An empty instance accepts Owner creation only through the canonical browser
origin `http://localhost:18080` and only while no Owner exists. Creation is
atomic and closes the first-run endpoint. There is no default password and no
terminal bootstrap code in the happy path. Local recovery remains explicit,
audited, and separate.

Remote/LAN binding, custom ports, offline packages, Kubernetes, source builds,
upgrade orchestration, signatures, SBOM, and provenance remain release or P1
concerns. The UI prototype uses a deliberately invalid image placeholder until
the release gate publishes a real signed digest.

## Security Conditions

- Docker's loopback port publication limits network exposure; it does not prove
  caller identity. Container peer IP is never used as a localhost trust signal
  because Docker NAT commonly makes a host browser appear as a bridge peer.
- The server accepts the exact `Host: localhost:18080` and exact
  `Origin: http://localhost:18080` for first-run mutation. It rejects IP-literal,
  alternate-host, forwarded-host, missing-origin, cross-origin, and malformed
  forms. CORS is disabled and `Forwarded`/`X-Forwarded-*` never influence trust.
- A pre-auth status GET using the canonical Host issues a short-lived,
  single-use setup nonce bound to an HttpOnly, SameSite=Strict setup cookie.
  Owner creation requires that cookie, the nonce in a dedicated CSRF header,
  and the exact Origin. Success or expiry consumes the nonce; replay fails.
- The first-run check and Owner creation occur in one database transaction.
- A second concurrent creation attempt fails without changing credentials.
- Rate limits apply before password hashing and are keyed independently of
  proxy-controlled headers.
- Setup endpoints other than status and Owner creation remain unavailable
  before authentication.
- Secrets never enter image layers, command arguments, logs, or responses.
- Port publication remains loopback-only unless a later reviewed ADR defines
  authenticated remote deployment.

## Local Host Trust Assumption

The no-code happy path cannot cryptographically distinguish the intended human
browser from another process already controlling the same operating-system
account, Docker daemon, browser profile, or localhost. Such local processes
can obtain the same setup nonce. P0 therefore trusts the local host and Docker
administrator during empty-instance first run. Protecting against a malicious
local peer requires an out-of-band secret, client identity, or operating-system
integration and is outside this ADR. Tests must demonstrate this limitation
rather than claiming bridge-peer attribution is possible.

Security tests cover hostile Origin, DNS-rebinding Host, forwarded-header
spoofing, missing/mismatched nonce and cookie, nonce replay, rate limits, and
concurrent Owner creation. A bridge-peer request with all canonical browser
proofs remains inside the declared local-host trust boundary.

## Consequences

- The first product-value slice is simpler to install and test.
- Previous bootstrap-ingest and launcher behavior becomes migration/recovery
  code or is removed from the customer path.
- Formal multi-platform clean-room and supply-chain gates occur after Human
  product acceptance rather than before it.
- ADR 0004 remains historical context for a future packaged release, but its
  launcher and terminal-code journey is not the vNext P0 default.
