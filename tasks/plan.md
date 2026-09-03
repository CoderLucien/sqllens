# SQLLens vNext Delivery Plan

## Goal

Deliver customer-visible diagnosis value before release engineering. The first
vertical slice is:

one Docker command -> localhost Owner setup -> one managed source -> one
abnormal SQL -> evidence-bound Chinese decision report.

The governing specification is
docs/superpowers/specs/2026-09-02-sqllens-vnext-product-spec.md.

## Delivery Order

~~~text
#t17 product, ADR, UI and contracts
  -> #t18 install/setup/source shell
     -> #t20 versioned rules + AI synthesis + Chinese report
  -> #t19 TiDB/PingKaiDB evidence connector
     -> integrate #t19 evidence into #t20 report
        -> Human product review
           -> #t22 one frozen QA acceptance
           -> #t23 high-risk review as needed
              -> #t21 Plan Replayer/manual ingress
                 -> release qualification
~~~

## Current Code Decision

### Retain

- Python 3.12, FastAPI, React, sqlglot classification, and typed API errors.
- Credential vault and key rotation foundations.
- Single-Owner session, CSRF, existing job idempotency/persistent lease
  foundations, restart recovery, and provider timeout/byte budgets.
- Evidence identifiers, integrity digests, revision pinning, and rules fallback.

### Refactor Incrementally

- apps/api/src/sqllens_api/setup.py: preserve atomic state and credential
  semantics, remove the legacy bootstrap trust path in favor of localhost-only
  Owner creation, then move source/model steps behind explicit services.
- Source writes: add server-owned idempotency receipts and audit attestations;
  unify diagnosis and verification reservations before treating Source/v1 as
  an authorization-safe projection.
- apps/api/src/sqllens_api/app.py: extract route groups and dependency
  boundaries while touching each vertical slice; do not perform a broad rewrite.
- apps/api/src/sqllens_api/diagnosis.py: replace SQL-structure-only fixed output
  with Evidence, Rule, Synthesis, and Report interfaces.
- apps/api/src/sqllens_api/provider.py: keep transport/egress/budget controls,
  replace ranking-only schemas with ADR 0010 synthesis schemas.
- apps/web/src/App.tsx: split first-run setup from authenticated daily shell.
- apps/web/src/DiagnosisWorkspace.tsx: replace internal-ID-first rendering with
  the approved Chinese report and trace drawer.

### Remove From vNext P0

- terminal bootstrap-ingest/reissue, bootstrap API/state, recovery-code UI, and
  one-time code entry (including hidden compatibility paths);
- fixed 20 percent evidence completeness and English cannot-determine
  hypotheses;
- model-only hypothesis-ID ranking as the claimed AI diagnosis capability;
- release archive/launcher, cross-platform clean-room, and full release gates
  before Human product acceptance.

## Task #t17: Product And Contract Freeze

Owner: swat-mgr
Status: in progress

Deliver:

- vNext specification and ADR 0009-0011;
- clickable customer-journey HTML;
- Source/v1, standalone Evidence/v2, DiagnosisCase/v2, and
  DiagnosisReport/v1 contract drafts;
- three approved Chinese report fixtures: index access, statistics/estimation,
  and runtime/resource correlation;
- code retain/refactor/remove map and task ledger.

Verification:

~~~bash
python3 docs/contracts/validate_examples.py
python3 -m unittest discover -s docs/contracts -p 'test_*.py' -v
python3 docs/contracts/validate_vnext_examples.py
python3 docs/contracts/validate_vnext_negative_examples.py
git diff --check
~~~

Exit: Reviewer gives a baseline finding set; unresolved contract blockers remain
visible before runtime work.

## Task #t18: Install, First Run, And Sources

Owner: swat-rd
Dependency: #t17 contracts
Maximum first iteration: one focused implementation cycle before checkpoint.

Slice A:

- replace bootstrap-code happy path with atomic localhost Owner creation;
- tests for exact Host/Origin, DNS rebinding, proxy spoofing, cookie-bound setup
  nonce expiry/replay, concurrency, and restart; Docker peer IP is not identity.

Slice B:

- separate setup shell and daily shell;
- Source/v1 CRUD with encrypted credential reference and immutable revision;
- server-owned Source-write idempotency receipts and audit attestations;
- one persisted concurrency/drain barrier for diagnosis and verifier execution.

Slice C:

- database, Prometheus, and TEM/Alertmanager acquisition guides and capability
  tests matching the approved HTML.

Verification:

~~~bash
make lint
make typecheck
make test
make test-e2e
make build
~~~

Exit: a frozen commit demonstrates first run and source lifecycle without a
published release claim.

## Task #t19: Versioned TiDB Evidence

Owner: swat-rd2
Dependency: #t17 Source/Evidence contracts
Integration boundary: no shared UI/setup files with #t18.

Slices:

1. version/capability preflight for TiDB v8.5.x and PingKaiDB v7.1.x;
2. Statement Summary and Slow Query collectors;
3. schema/index/statistics and ordinary-plan collectors;
4. bounded correlation record for Prometheus/TEM evidence.

Every query is server-owned, parser-validated, versioned, budgeted, and covered
by positive, denied-permission, unknown-version, timeout, and truncation tests.

Exit: recorded fixtures produce Evidence/v2 objects without a Web dependency.

## Task #t20: Rules, AI, And Chinese Report

Owner: swat-rd
Dependency: #t18 interface stable; integrates #t19 evidence when available

Slices:

1. freeze three Chinese report fixtures before changing the runtime;
2. add versioned rule-card schema and first official-document-backed rules;
3. replace ranking-only output with evidence-bound AI synthesis;
4. validate claim/rule/evidence/action references and degrade to rules;
5. implement DBA/SRE, developer, and incident-owner report projections.

No rule is complete without positive, negative, missing-evidence, and
version-boundary fixtures.

Exit: Human can inspect one representative abnormal SQL and identify impact,
cause, action, validation, rollback, evidence, rule source, and AI contribution.

## Task #t21: Alternative Evidence Entry

Owner: swat-rd2
Dependency: #t19/#t20 main path plus Human product acceptance

Implement Plan Replayer upload and manual SQL/schema/plan/stats/runtime input.
Both paths must emit the same Case/Report contracts. Archive protections cover
paths, links, file count, compression ratio, bytes, time, disk, cancellation,
and cleanup.

This task remains todo until the main abnormal-SQL path is accepted.

## Task #t22: QA Acceptance

Owner: swat-qa

QA authors traceability after #t17, but executes only when mgr freezes one
commit/image. The matrix checks customer actions and report usefulness, not only
HTTP status, job completion, or persistence.

Results are PASS, FAIL, BLOCKED, or UNVERIFIED with raw evidence. One bounded
retest may close a defect. New non-blocking scope goes to a later iteration.

## Task #t23: High-Risk Review

Owner: swat-reviwer

Review #t17 now, then only high-risk diffs:

- first-run/Owner concurrency and recovery;
- credential lifecycle and privilege boundaries;
- collector allowlists and budgets;
- model egress, schema, references, and degradation;
- archive parsing and immutable history.

Reviewer does not rerun QA's full product matrix.

## Product Gate Before Release Gate

Release engineering may start only after all are true:

- Human accepts the actual first-run and abnormal-SQL customer journey;
- a Chinese report is useful to DBA/SRE and consistent for developer/manager;
- evidence/rule/AI provenance is visible;
- #t22 signs the frozen slice;
- #t23 has no unresolved critical/high finding.

Only then schedule multi-architecture publication, clean-machine validation,
SBOM, signing/provenance, 2C4G benchmark, upgrade, rollback, and RC review.

## Working Limits

- Each checkpoint identifies exact commit/files, commands, results, failures,
  known limits, and next dependency.
- RD and RD2 modify shared contracts only through mgr-coordinated order.
- QA is the only acceptance signer. Reviewer is risk-based and on demand.
- Each iteration has at most one evidence follow-up round; contract drift
  returns to #t17 instead of adding tests indefinitely.
