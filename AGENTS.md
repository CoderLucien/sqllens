# SQLLens M0 Private Preview Agent Guide

## Active Product State

The Human selected **方案 2** on 2026-09-03. The active delivery is one bounded
M0 local private preview, not the earlier complete vNext P0. The repository also
contains an older security/runtime skeleton and dormant platform contracts;
none of those documents or tests prove M0 runtime or product acceptance.

Public use of the `SQLLens` name remains blocked pending a naming/brand decision.
Use it only as the working code name.

## Source Of Truth

For M0, read only what the assigned task needs, in this precedence order:

1. `docs/adr/0012-m0-private-preview-vertical-slice.md`;
2. `docs/superpowers/specs/2026-09-03-sqllens-m0-private-preview-spec.md`;
3. `docs/superpowers/plans/2026-09-03-sqllens-m0-private-preview.md`;
4. `tasks/plan.md`;
5. active task acceptance criteria/checkpoints.

The 2026-09-02 vNext spec, ADR 0010, and ADR 0011 remain historical or future
records. They are dormant for M0 wherever they add AI, persistent/multiple
Source, rotation/deletion, audit replay, leases, idempotency receipts,
Prometheus/TEM, PingKaiDB, Plan Replayer, or release qualification. ADR 0009
still governs the canonical localhost Owner proof. ADR 0002 still prohibits
unsafe SQL and `EXPLAIN ANALYZE`.

If implementation and an active M0 document conflict, stop and escalate. Change
the decision/specification first; do not silently choose an interpretation.
`#t20` may start from the published report/evidence core SHA. `#t18` connection
work must additionally consume the published runtime-adapter addendum SHA.

## Frozen M0 Boundary

The only product journey is:

~~~text
one Docker command on 127.0.0.1:18080
  -> create/login one persistent Owner
  -> enter one TiDB v8.5.x credential
  -> select one digest and paste one single-base-table SELECT
  -> bounded read-only evidence
  -> rules-only Chinese report
~~~

- `/data` is the only named writable volume and contains Owner SQLite/session
  material only. The image has no `/secrets` path or secret-file fallback.
- The TiDB credential, connection metadata required to reconnect, SQL text,
  Evidence, Case, and report are not persisted. Logout, disconnect, socket loss,
  or restart closes/forgets the live connection and requires credential re-entry.
- The CLI accepts only its default or `web-api`. Explicit migration and legacy
  bootstrap/recovery commands are unavailable.
- Registered APIs are limited to health, Owner setup/auth, M0 connection,
  candidate discovery, and synchronous diagnosis. Deferred routes must be truly
  unregistered and return 404; UI hiding is insufficient.
- User SQL is required, locally parsed, digest-verified, and never executed. The
  only plan operation is a registered-binder ordinary EXPLAIN over the validated
  SELECT. DML, DDL, control statements, locking reads, outfile, multiple
  statements, user-supplied EXPLAIN, and `EXPLAIN ANALYZE` fail closed.
- There is no AI/provider request, Prometheus/TEM, PingKaiDB, Plan Replayer,
  upload, background job, old Case/job API, LAN hosting, cross-platform gate,
  artifact archive, SBOM/provenance/signing, RC, or production release in M0.

Never report a documented, fixture, simulated, legacy, or author-tested
capability as a verified real-TiDB or accepted M0 result.

## Ownership And Worktrees

- `swat-mgr`: task `#t7`; decisions, ADR/spec/plan, dependency order, freeze and
  stop decision only on `/root/sqllens-m0-spec`, branch
  `docs/m0-private-preview`. It does not implement runtime code.
- `swat-rd`: task `#t18`; CLI/container, Owner/auth, ephemeral connection, query
  registry and ordinary-EXPLAIN binder, real collectors, Web journey, and final
  integration on `/root/sqllens-rd`, branch `feature/p0-runtime`.
- `swat-rd2`: task `#t20`; Evidence schema increments, pure typed projectors,
  rules/report builder, three JSON examples, and standalone HTML on
  `/root/sqllens-rd2`, branch `feature/m0-rules-reports`. It must not edit
  `evidence_connector/queries.py`, add collection SQL, create
  `CollectedEvidence`, or change auth/routes/driver/Web runtime.
- `swat-qa`: task `#t22`; QA-owned matrix/evidence on `/root/sqllens-qa`, branch
  `test/p0-acceptance`. It executes zero formal runs until Human report
  acceptance, Reviewer PASS, and one commit/image identity are frozen.
- `swat-reviwer`: task `#t23`; one read-only high-risk review of the exact frozen
  M0 diff/image. It neither implements fixes nor repeats QA.
- `/root/sqllens` contains preserved `#t17` persistent-Source WIP owned by
  `swat-rd2`. It is deferred to M2, unverified, and outside M0. No other owner
  may modify, clean, commit, or discard it.

Do not edit another owner's worktree. Before parallel work, compare the file
lists in the active implementation plan. `#t18` and `#t20` meet only at the
frozen projector/report interfaces; integration occurs after Human report
acceptance by cherry-picking accepted `#t20` commits into `#t18`.

## Technology And Dependency Boundary

- Python 3.12, FastAPI 0.141.1, Pydantic 2.13.5, sqlglot 30.17.0,
  SQLAlchemy 2.0.52, and pinned `asyncmy==0.2.14` for the M0 live connection.
- React 19, TypeScript strict mode, Vite, Node.js 22.
- Pytest, Vitest, Playwright/Chromium, Ruff, and strict mypy.
- Python runtime dependencies are declared in `pyproject.toml` and pinned in
  `requirements/runtime.lock`; `requirements/dev.lock` includes the runtime
  lock.

Do not add another runtime dependency, route, persistence record, worker, or
state machine without a new Human scope decision.

## Engineering And Security Rules

- Work in atomic RED -> GREEN increments; record exact SHA, files, commands,
  results, known failures, and environment limits.
- Validate every HTTP request, driver result, Evidence object, and report at a
  closed typed boundary. Treat database rows as untrusted.
- Static collection queries require exact immutable-registry equality. The one
  dynamic ordinary EXPLAIN requires exact reconstruction by its registered
  binder at executor and Evidence boundaries.
- Parameter-bind values/identifiers through the approved interface; never expose
  a generic user-selected query executor.
- Enforce per-query and aggregate timeout, row, byte, and concurrency budgets.
  Cancellation/timeout closes and awaits the socket before the connection slot
  is reusable.
- Normal connect/disconnect/candidate/diagnosis work shares one non-queuing
  operation lease and returns `409 M0_BUSY` on contention. Logout/shutdown use
  the separate idempotent lifecycle close: revoke, cancel active probes/queries,
  await or force-abort every socket, clear references, and never return busy.
- With `asyncmy==0.2.14`, configure `connect_timeout=5` and `read_timeout=5`
  plus a 5-second outer `asyncio.timeout()` for each I/O; do not invent a
  `write_timeout` argument.
- Use the exact-version connection adapter: before network I/O clear and verify
  `_client_flag & CLIENT_MULTI_STATEMENTS == 0`; immediately after the
  handshake clear and verify `_password=b""` and `_password_creator=None`.
  Any version/field/read-back mismatch fails closed, reconnect is forbidden,
  and driver methods are never monkey-patched.
- Never log or persist credential values, SQL text, row content, DSNs, driver
  exceptions, or sensitive representations. Error responses use closed codes
  and templates.
- Render browser content through React text nodes only; no `innerHTML`, secret
  URL/query/analytics/console/browser-storage use, or external preview assets.
- Missing, stale, truncated, low-coverage, mismatched, unsupported, or
  integrity-invalid evidence produces an actionless `observe` report, never a
  widened conclusion or invented business impact.
- Actions are recommendations for named humans; the product never executes
  recommendations, DDL, DML, statistics refresh, or rollback.

## Delivery Gates And Stop Line

- Gate A: three schema-valid fixture-labelled reports plus one standalone HTML
  within four hours; Human accepts product value before runtime integration.
- Gate B: target one real TiDB v8.5.x candidate within 24 hours, frozen by exact
  commit and local `sha256:` image ID.
- Gate C: one Reviewer decision and one QA run by 36 hours maximum, with at most
  one targeted correction/retest.

Stop and return to scope/design if the Human rejects report value, the real TiDB
environment is unavailable, a timebox is missed, a second correction would be
needed, a deferred capability is requested, or a same-severity cross-domain
finding shows the state space is not bounded. A deadline never permits skipping
a failing gate.

## Handoff Contract

Every implementation checkpoint distinguishes completed, in progress, blocked,
and unverified work. Author tests are not independent acceptance. QA reports
PASS/FAIL/BLOCKED/UNVERIFIED per requirement with raw evidence. Reviewer
findings identify the exact triggering input, observed result, file/line,
impact, and minimal closure. A final PASS means only “M0 local private preview,”
not complete P0, production-ready, multi-source, unattended, or released.
