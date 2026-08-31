# ADR 0002: Evidence Acquisition Boundaries

Status: Accepted for P0 baseline
Date: 2026-08-31

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

P0 retains the approved one-click Plan Replayer generation capability as a
separate privileged workflow. It is not part of default diagnosis collection.
Before execution, the UI and API must present:

- the exact operation and target statement digest;
- the metadata/statistics categories and identifiers that may enter the archive;
- required TiDB privileges and the authenticated operator;
- execution timeout, concurrency, temporary disk, and archive-size budgets;
- the cancellation and kill-switch behavior;
- the sensitivity warning and destination/retention policy.

Only an authorized DBA/Admin can confirm the immutable preflight revision. The
job is bounded, cancellable, fully audited, and fails closed on any version,
privilege, policy, or budget mismatch. It never runs as an LLM tool call or an
automatic response to a diagnosis. The captured archive then crosses into the
same bounded imported-evidence boundary as an uploaded archive.

The completed archive is addressed by an opaque job ID, not a filesystem path.
Download requires a single-use, short-TTL token scoped to that archive and
authenticated operator. The response includes an integrity digest and a
content-disposition filename with no cluster identifiers. The temporary package
is deleted on cancellation/failure, after successful single-use download, or at
the configured short retention deadline, whichever happens first; cleanup is
idempotent and audited. Tokens and package paths never enter normal logs.

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
- The approved Plan Replayer capture requires the separate privileged workflow;
  any other active collection feature requires a new scope and review.
- Clinic URL mode remains outside P0.
