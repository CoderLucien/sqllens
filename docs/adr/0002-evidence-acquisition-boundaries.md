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
- Active collection features require a separate privileged workflow and review.
- Clinic URL mode and production Plan Replayer capture remain outside P0.
