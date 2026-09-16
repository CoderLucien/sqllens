# ADR 0002: Evidence Acquisition Boundaries

Status: Accepted safety boundary; active Plan Replayer capture deferred for vNext P0
Date: 2026-08-31
Clarified by: ADR 0010, ADR 0011, and Evidence/v2
Superseded in scope by: SQLLens vNext Product Spec sections B1 and M3

## Context

The service promises useful diagnosis while staying outside the production
request path. TiDB metadata queries, Prometheus requests, ordinary `EXPLAIN`,
Plan Replayer capture, slow-log parsing, and Clinic access do not have identical
impact or privilege. Calling all of them "zero impact" would be inaccurate.

Clinic documentation provides supported SSO and upload flows but no verified
public contract for reading a diagnostic package by URL and username/password.
Plan Replayer capture is an active production operation, and replay only
reconstructs optimizer inputs; it cannot prove runtime performance.

## Decision

P0 has three explicit evidence levels:

1. SQL-only: no connector and no production action. Results are hypotheses.
2. Controlled read-only: versioned allowlist queries to TiDB and Prometheus,
   with least privilege, time/row/point/concurrency budgets, cancellation,
   auditing, and a kill switch.
3. Imported historical evidence: an existing Clinic package/report or Plan
   Replayer archive is processed in a bounded local workspace.

P0 never performs DML, `EXPLAIN ANALYZE`, recommendation execution, or automatic
Plan Replayer capture. Ordinary `EXPLAIN` is rejected when the relevant TiDB
version or SQL construct may execute work during optimization.

The earlier design approved one-click Plan Replayer generation as a separate
privileged P0 workflow. **That approval is historical and is not an active
vNext P0 capability.** The vNext P0 page provides version-aware, copyable steps
for the customer to generate and download a package using TiDB/PingKaiDB tools,
then accepts the uploaded archive through the bounded imported-evidence path.
SQLLens does not hold a capture credential or invoke Plan Replayer generation.

Reintroducing service-triggered capture requires a new ADR, Human scope gate,
runtime contract, and security review. Any future proposal must present:

- the exact operation and target statement digest;
- the metadata/statistics categories and identifiers that may enter the archive;
- required TiDB privileges and the authenticated operator;
- execution timeout, concurrency, temporary disk, and archive-size budgets;
- the cancellation and kill-switch behavior;
- the sensitivity warning and destination/retention policy.

Only an authorized DBA/Admin could confirm such an immutable preflight revision.
Any future job must be bounded, cancellable, fully audited, and fail closed on
version, privilege, policy, or budget mismatch. It must never run as an LLM tool
call or an automatic response to a diagnosis. These are future admission
conditions, not proof that a capture endpoint or job exists in vNext P0.

If a future ADR ever approves service-triggered capture, that future design
would also need opaque job IDs, single-use short-TTL download tokens, integrity
digests, identifier-safe filenames, bounded retention, idempotent audited
cleanup, and log redaction for tokens and package paths. **No capture job,
download token, archive response, or temporary-package lifecycle described by
these future conditions exists in vNext P0.**

Clinic URL reading is disabled until an official read API, supported auth scope,
and test environment are available. Browser automation, SSO credential storage,
and generic arbitrary-URL fetching are prohibited.

Plan Replayer validation is reported as plan reproducibility, not performance
validation. Runtime claims require representative workload evidence in an
isolated environment.

## Measurable Language

The product uses "business-path zero intrusion" and "bounded incremental
collection impact," never an absolute physical zero-impact claim. Layer 2 must
pass an enabled/disabled A/B baseline and automatically stop when configured
noise or resource thresholds are exceeded.

## Consequences

- Layer and evidence completeness are visible in every case.
- Missing or stale evidence lowers confidence or forces abstention.
- vNext P0 provides Plan Replayer generation guidance and upload/import only;
  active capture remains deferred until a new scope and review are approved.
- Clinic URL mode remains outside P0.
