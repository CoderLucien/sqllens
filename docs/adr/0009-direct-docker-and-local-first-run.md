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

An empty instance accepts Owner creation only from loopback and only while no
Owner exists. Creation is atomic and closes the first-run endpoint. There is no
default password and no terminal bootstrap code in the happy path. Local
recovery remains explicit, audited, and separate.

Remote/LAN binding, custom ports, offline packages, Kubernetes, source builds,
upgrade orchestration, signatures, SBOM, and provenance remain release or P1
concerns. The UI prototype uses a deliberately invalid image placeholder until
the release gate publishes a real signed digest.

## Security Conditions

- Proxy headers cannot turn a remote request into a loopback request.
- The first-run check and Owner creation occur in one database transaction.
- A second concurrent creation attempt fails without changing credentials.
- Setup endpoints other than status and Owner creation remain unavailable
  before authentication.
- Secrets never enter image layers, command arguments, logs, or responses.
- Port publication remains loopback-only unless a later reviewed ADR defines
  authenticated remote deployment.

## Consequences

- The first product-value slice is simpler to install and test.
- Previous bootstrap-ingest and launcher behavior becomes migration/recovery
  code or is removed from the customer path.
- Formal multi-platform clean-room and supply-chain gates occur after Human
  product acceptance rather than before it.
- ADR 0004 remains historical context for a future packaged release, but its
  launcher and terminal-code journey is not the vNext P0 default.
