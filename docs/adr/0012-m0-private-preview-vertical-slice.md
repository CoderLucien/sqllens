# ADR 0012: M0 Private Preview Vertical Slice

Status: Accepted for M0
Date: 2026-09-03

## Context

The 2026-09-02 vNext baseline combined a customer-value experiment with a
production-grade platform: persistent multi-Source lifecycle, credential
rotation and deletion, audit replay, leases, idempotency receipts, optional AI,
multiple evidence systems, and release qualification. The security findings in
`#t17` were valid, but their repeated appearance showed that this state space
was not a bounded first-delivery task. More importantly, completing that
platform would still not demonstrate that a customer receives a useful TiDB
diagnosis.

On 2026-09-03 the Human selected the smaller delivery route: validate one real
abnormal-SQL journey first, then add platform capabilities as independent
increments. The first result is a private preview, not the vNext P0 promised by
the earlier specification.

## Decision

M0 is one local, single-Owner, single-TiDB v8.5.x, rules-only vertical slice:

~~~text
one Docker command
  -> http://localhost:18080
  -> create/login local Owner
  -> enter one TiDB credential
  -> select one SQL Digest and provide its single-base-table SELECT text
  -> bounded read-only evidence collection
  -> Chinese actionable report
~~~

The TiDB credential exists only in process memory. It is never written to the
SQLite database, a volume, a file, an environment variable, a log, an HTTP
response, browser storage, or rendered DOM. The application retains one live
connection rather than a reconnectable password. Logout, explicit disconnect,
connection failure, or process exit closes that connection and requires the
credential to be entered again. Python and the database driver cannot promise
cryptographic zeroization of every temporary memory copy; M0 therefore claims
no such guarantee.

Normal connect, disconnect, candidate, and diagnosis requests share one
non-queuing operation lease and return a closed busy response on contention.
Logout and process shutdown do not call the ordinary disconnect operation:
after revoking the session they use an idempotent lifecycle cleanup that
cancels active database work, awaits socket closure, and cannot return busy.

The selected pinned driver constructor forces `CLIENT_MULTI_STATEMENTS` and its
connection object initially keeps authentication fields. M0 uses an exact-
version compatibility adapter: before network I/O it clears and verifies the
multi-statement bit in `_client_flag`; after the handshake it clears and
verifies `_password` plus `_password_creator`. Any version, field, write, or
read-back mismatch fails closed. The adapter does not replace driver methods,
reconnect is forbidden, and the executor still requires an exactly
reconstructed, exactly one-statement registry/binder query. This three-field
private shim requires the narrow Reviewer gate and redesign before production.

Only the following API families are registered:

- `/healthz`;
- `/api/v1/setup/status` and `/api/v1/setup/owner`;
- `/api/v1/auth/session`, `/api/v1/auth/login`, and `/api/v1/auth/logout`;
- `/api/v1/m0/connection`;
- `/api/v1/m0/sql-candidates`;
- `/api/v1/m0/diagnoses`.

Legacy bootstrap, model/settings, persistent Source CRUD and lifecycle,
Prometheus/TEM, PingKaiDB, Plan Replayer, old case/job APIs, and release APIs are
not registered and return the framework's normal 404 response. This is a
compile-time composition decision for the M0 application, not a UI-only hide or
a runtime flag that can expose unfinished routes.

Owner authentication state may remain in the existing local SQLite store. TiDB
credentials, Evidence payloads, Diagnosis Cases, and reports are ephemeral for
M0. A browser refresh may lose the last report; a process restart always loses
the TiDB connection. The one named writable volume is mounted at `/data` and
contains only Owner SQLite/session material. M0 has no `/secrets` mount or
file-backed TiDB credential fallback.

The service never executes the submitted SQL. It parses one bounded SELECT
statement locally, verifies its TiDB digest using a registered parameterized
read-only function query, and uses only registered server-owned metadata,
observation, and ordinary-plan queries. For the index rule, the server creates
exactly one `EXPLAIN FORMAT='brief'` whose child is the canonical serialization
of the already parsed single SELECT; the submitted SQL itself is never executed. DML, DDL,
ADMIN/control statements, multiple statements, locking reads,
`SELECT ... INTO OUTFILE`, user-supplied `EXPLAIN`, and `EXPLAIN ANALYZE` fail
closed.

The first rules-only report pack covers three bounded findings:

1. access-path/index-coverage risk supported by SQL structure, a real ordinary
   plan whose access path is `table_full_scan`, index metadata, and measured
   scan amplification;
2. statistics-health risk supported only by real `SHOW STATS_HEALTHY` output—
   never by an ordinary-plan marker or a fabricated `actualRows` value;
3. repeated heavy scanning supported by one Statement Summary window's exact
   execution count and derived `AVG_TOTAL_KEYS * EXEC_COUNT` weighted key count,
   plus matching Slow Query scan/return measurements. The weighted count is not
   described as an exact sum of raw per-execution keys.

SQL text is mandatory for the diagnosis endpoint. If it is absent, the browser
does not call the endpoint and the API returns a closed validation error; an
`observe` report is reserved for a valid SQL request whose evidence is missing,
stale, truncated, mismatched, unsupported, or integrity-invalid. M0 has no
business-impact input, so reports use an empty business-evidence list and the
fixed statement “未提供业务影响证据，仅说明数据库技术影响” rather than inventing
a business observation.

A missing, stale, truncated, mismatched, unsupported, or integrity-invalid role
produces an actionless `observe` report with explicit uncertainty. It never
widens a conclusion. SQL-level evidence is correlated by SQL digest and window;
table-level evidence is correlated to a table declared by SQL structure. M0
does not require unlike roles to share one `profileObjectRef`. M0 makes no AI
call and records `configuredMode=rules`, `effectiveMode=rules`,
`aiStatus=not_requested`, and null AI pins.

## Relationship To Earlier ADRs

- ADR 0009 still governs the canonical localhost Owner proof and one-command
  first run. M0 removes its later source/model wizard phases.
- ADR 0010 is dormant in M0. Its evidence-bound AI constraints remain binding
  when AI is introduced in a later increment.
- ADR 0011 remains the design record for a possible later persistent Source
  platform, but no ADR 0011 lifecycle or receipt is reachable in M0. The current
  `#t17` work is preserved for reference rather than completed by accumulating
  more patches.

This ADR narrows those decisions for M0; it does not delete their history or
claim their full behavior is implemented.

## Consequences

### Positive

- The first delivery has one measurable customer outcome and a finite route,
  state, concurrency, and failure space.
- Removing persistence eliminates the credential rotation, deletion, lease,
  audit-replay, and receipt state machines from the M0 security boundary.
- Rules and report quality can be reviewed before more platform investment.
- A failure at the report gate costs hours rather than days of additional
  infrastructure work.

### Negative

- M0 is not suitable for shared, remote, unattended, or long-running use.
- The user must reconnect after logout, connection loss, or restart.
- Only TiDB v8.5.x and three bounded rule categories are supported.
- There is no AI, Prometheus/TEM correlation, Plan Replayer, PingKaiDB,
  cross-platform qualification, or production release claim.
- Some code built for the broader platform is intentionally not shipped and may
  need redesign rather than direct reuse.
- The pinned async driver needs an exact-version three-field private
  compatibility shim to suppress multi-statements before the handshake and to
  remove reconnectable password fields afterward. It is accepted only for the
  bounded localhost preview, with fail-closed tests and explicit review.

## Delivery And Stop Conditions

- Within four hours of the decision, deliver three schema-valid report JSON
  examples and one clickable HTML report for Human review.
- Do not execute the formal QA matrix until the Human accepts those reports and
  one implementation commit/image digest is frozen.
- Target one real TiDB v8.5.x candidate within 24 hours and allow at most one
  bounded correction round, ending by 36 hours.
- Reviewer performs one narrow pass over read-only enforcement, secret
  handling, timeouts/cleanup, localhost exposure, and deferred-route 404s.
- A new same-severity cross-domain defect, missed timebox, or request to add a
  deferred feature causes scope reduction or redesign; it does not authorize
  another open-ended patch cycle.

## Later Increments

Later work is separately approved and estimated:

1. M1: evidence-constrained optional AI;
2. M2a: persistent single Source;
3. M2b: multi-Source isolation;
4. M2c: rotation/deletion and bounded recovery;
5. M2d: audit/idempotency only where the threat model requires it;
6. M3: Prometheus/alert correlation;
7. M4: Plan Replayer and formal release qualification.
