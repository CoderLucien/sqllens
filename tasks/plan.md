# SQLLens M0 Private Preview Delivery Plan

## Governing Decision

On 2026-09-03 the Human selected **方案 2**: deliver one bounded local
abnormal-SQL journey before continuing platform construction. M0 is a private
preview, not the earlier complete vNext P0.

Source of truth, in precedence order:

1. `docs/adr/0012-m0-private-preview-vertical-slice.md`;
2. `docs/superpowers/specs/2026-09-03-sqllens-m0-private-preview-spec.md`;
3. `docs/superpowers/plans/2026-09-03-sqllens-m0-private-preview.md`;
4. this task ledger.

The 2026-09-02 vNext spec and ADR 0011 remain historical/future design records.
They do not authorize a persistent Source, multi-source, AI, Prometheus/TEM,
Plan Replayer, or release capability in M0.

## M0 Outcome

~~~text
one Docker command bound to 127.0.0.1
  -> create/login one persistent local Owner
  -> enter one TiDB v8.5.x credential (process memory only)
  -> choose one SQL digest and paste its single-table SELECT
  -> bounded read-only evidence collection
  -> rules-only Chinese actionable report
~~~

The report contains conclusion, technical impact, evidence, rule reasoning,
ordered action, validation, rollback, and uncertainty. Missing or invalid
evidence produces an actionless `observe` result. User SQL is never executed;
only a server-bound ordinary EXPLAIN over a validated SELECT is allowed.

## Active Dependency Graph

~~~text
#t7 M0 contract SHA
  ├─ #t20 typed projectors -> three rules/reports -> clickable HTML -> HUMAN GATE
  └─ #t18 CLI/Owner -> ephemeral connection -> authorized collectors

HUMAN GATE + #t18 collector readiness
  -> #t18 browser/runtime integration
  -> freeze one commit + one sha256 image ID
  -> #t23 one high-risk review
  -> #t22 one QA execution
  -> M0 private-preview decision
~~~

Before the Human gate, `#t18` and `#t20` run in parallel only through the frozen
interfaces. They do not edit the same files. After the Human gate, `#t18`
cherry-picks the accepted `#t20` commits and becomes the only integration owner.

## Task Ledger

### #t7 — M0 scope, contract, order, and stop decision

Owner: `swat-mgr`
Status: in progress until the exact contract SHA is pushed
Worktree: `/root/sqllens-m0-spec`

Deliver only the ADR, spec, implementation plan, ownership guide, task ledger,
timeboxes, and freeze decisions. `swat-mgr` does not implement runtime code.

Exit: exact remote SHA, clean worktree, contract validators passing, and
`#t18/#t20/#t22` instructed to consume that SHA.

### #t17 — persistent Source/lifecycle contract line

Owner: `swat-rd2`
Status: todo; explicitly deferred to M2
Worktree with preserved WIP: `/root/sqllens`

The four-file `db4cecf`-based WIP is preserved as unverified future work. It is
not M0 code, not a candidate, and not a blocker once persistent Source routes,
receipts, audit replay, migrations, and lifecycle APIs are unregistered and
return 404. Do not continue its patch chain during M0.

### #t18 — localhost single-TiDB runtime and vertical integration

Owner: `swat-rd`
Status: in progress
Worktree: `/root/sqllens-rd`

Owns:

- default/`web-api`-only CLI, `/data`-only container state, and deferred-route
  removal;
- two-state Owner/auth flow and logout cleanup hook;
- one process-memory-only TiDB connection using `asyncmy==0.2.14`;
- one non-queuing normal-operation lease (`409 M0_BUSY`) plus a distinct
  idempotent logout/shutdown cleanup that always cancels and closes;
- an exact-version adapter that clears/verifies the driver's multi-statement
  flag before network I/O and its reconnectable password fields after the
  handshake, failing closed on any layout or read-back mismatch;
- query registry, registered ordinary-EXPLAIN binder, parameter binding,
  time/row/byte budgets, cancellation, and sanitized errors;
- candidate discovery, digest verification, real evidence envelopes, runtime
  integration, and Web journey.

Does not edit `#t20` schemas/projectors/rules/report files before their accepted
commits. Exit: one author-verified commit and one locally built `sha256:` image
ID after the Human report gate; it is not QA or Reviewer acceptance.

### #t19 — reusable versioned connector baseline

Owner: `swat-rd2`
Status: done at `4478da5` for its recorded scope; M0 compatibility unverified

The existing TiDB 8.5 connector types, safe query validation, Slow Query, and
Statement Summary baseline may be consumed by `#t18`. “Done” does not prove the
new M0 connection, statistics, index, ordinary-plan, browser, or real-TiDB path.

### #t20 — three rules and Chinese reports

Owner: `swat-rd2`
Status: in progress
Worktree: `/root/sqllens-rd2`

Owns:

- backward-compatible `statistics-health/v1` and `statement-summary/v3` typed
  Evidence schema increments;
- pure `QueryResult -> closed typed payload` projectors only;
- three deterministic TiDB 8.5 rule cards and pure report builder;
- three explicitly fixture-labelled schema-valid JSON reports and one
  standalone clickable HTML preview.

Does not create `CollectedEvidence`, edit
`evidence_connector/queries.py`, add collection SQL, or modify auth, routes,
driver, connection, or Web runtime. Exit: Human accepts or rejects the three
report journeys. Fixture examples are never called real TiDB evidence.

### #t21 — Plan Replayer/manual entry

Owner: `swat-rd2`
Status: todo; deferred to M4

No M0 implementation, route, upload parser, UI, or test is authorized.

### #t22 — M0 acceptance matrix

Owner: `swat-qa`
Status: in progress for matrix authoring; formal execution count remains zero
Worktree: `/root/sqllens-qa`

Freeze traceability now. Execute exactly once only after the Human accepts the
reports, `#t23` passes, and one commit/image identity is frozen. Cover one real
Chromium journey, three real TiDB 8.5 scenarios, read-only rejection, credential
and SQL non-persistence/non-logging, timeout cleanup, loopback exposure, Owner
survival across `/data` restart, TiDB re-entry after restart, and deferred-route
404. Report PASS/FAIL/BLOCKED/UNVERIFIED per row; HTTP 200 is not product value.

### #t23 — one narrow high-risk review

Owner: `swat-reviwer`
Status: todo until a candidate is frozen

Review only the frozen M0 diff/image: authorized read-only query execution,
ordinary-EXPLAIN binding, secret lifetime, timeout cleanup, canonical localhost
Owner proof, CLI surface, `/data`/no-`/secrets`, and deferred-route 404. Do not
review dormant ADR 0011 internals or repeat QA. Publish one PASS or reproducible
BLOCKED result; one correction SHA may receive one targeted recheck.

## Timeboxes And Stop Conditions

- Gate A: three JSON reports plus one HTML within four hours of the Human
  decision; runtime integration cannot precede Human acceptance.
- Gate B: target one real TiDB 8.5 candidate within 24 hours.
- Gate C: Reviewer and QA decision by 36 hours maximum, with at most one bounded
  correction/retest.
- A missing real TiDB environment is BLOCKED, never fixture-PASS.
- Human rejection, a missed timebox, a second correction request, a newly
  requested deferred capability, or a same-severity cross-domain design defect
  stops the iteration and returns it to scope/design.

Deadlines never permit bypassing a failing security or product gate. At a stop,
preserve exact commits/evidence and report what remains unverified.

## Explicitly Not M0

No AI/provider request, persistent or multiple Source, credential rotation,
audit ledger, idempotency receipt, Prometheus/TEM, PingKaiDB, Plan Replayer,
manual upload, background job, old Case/job route, remote/LAN hosting,
cross-platform matrix, archive, SBOM, provenance, signing, RC, or production
release. These capabilities must be unregistered and inaccessible, not merely
hidden in the UI.
