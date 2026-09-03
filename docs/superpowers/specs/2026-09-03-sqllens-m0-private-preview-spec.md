# SQLLens M0 Private Preview Specification

Status: Report/evidence slice approved; runtime adapter addendum pending
Decision record: `docs/adr/0012-m0-private-preview-vertical-slice.md`

Freeze split: this revision makes sections 6–8 and implementation-plan Tasks
2–4 normative for `#t20`. Runtime sections remain non-authoritative until the
separate `#t18` adapter addendum records the pinned-driver/TLS facts. Runtime
implementation must consume both SHAs; a runtime-only addendum may not change
the report/evidence interfaces frozen here.

## 1. Objective

Deliver the smallest stable product slice that can answer one question: **can a
TiDB operator use one locally generated Chinese report to decide what to check
or change next for one abnormal SQL?**

The target user is a DBA/SRE with a TiDB v8.5.x diagnostic account and access to
the exact SQL text and digest. Success is three useful evidence-bound reports
and one real browser-to-TiDB path. M0 is explicitly a local private preview; it
is not complete vNext P0, a production deployment, or a multi-user service.

## 2. Frozen Product Boundary

### 2.1 Included

- one Docker command exposing only `127.0.0.1:18080` on the host;
- one persistent local Owner account and cookie session;
- exactly one live TiDB v8.5.x connection at a time;
- TiDB credential entry in the browser and process-memory-only use;
- abnormal SQL candidate discovery without returning raw SQL text;
- one chosen SQL digest plus user-supplied exact, single-base-table SELECT text;
- server-registered, parameterized, bounded, read-only evidence queries plus
  one registered ordinary-EXPLAIN binder for the validated SELECT;
- three deterministic TiDB v8.5.x rule cards;
- one Chinese `diagnosis-report/v1` response and report page;
- explicit missing-evidence/unsupported/timeout behavior.

### 2.2 Excluded And Unreachable

The M0 application does not register these capabilities or route families:

- legacy `bootstrap-ingest`, `bootstrap-reissue`, bootstrap code/state/API/UI,
  and an explicit `migrate` CLI;
- setup security-policy, model-probe/finalize, model settings, provider calls;
- persistent or multiple Source CRUD, Source/v1 lifecycle, credential
  rotation/deletion, Source audit ledger, reservation ledger, or idempotency
  receipt;
- Prometheus, TEM, Alertmanager, PingKaiDB, Plan Replayer, manual upload;
- old `/api/v1/cases/sql`, job polling, stored Case/report history;
- remote/LAN hosting, multi-user access, Kubernetes, Compose selection;
- cross-platform clean-room, SBOM/provenance/signing, formal RC or release.

For every excluded API path, an HTTP request receives the normal 404 response.
No environment variable, query parameter, or feature flag can register it in an
M0 image. The container entrypoint accepts only its default or explicit
`web-api` command; any other argument exits `64` without importing or invoking
legacy bootstrap/recovery code. Owner SQLite migration is an internal,
idempotent Web-startup step, not a second user command.

## 3. Customer Journey

1. Run the frozen M0 image:

   ~~~bash
   docker run --rm --name sqllens-m0 \
     -p 127.0.0.1:18080:8080 \
     --read-only \
     --security-opt no-new-privileges \
     --cap-drop ALL \
     --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
     --mount type=volume,src=sqllens-m0-data,dst=/data \
     "$M0_IMAGE_DIGEST"
   ~~~

   `M0_IMAGE_DIGEST` denotes the exact immutable digest recorded at Gate B. The
   customer-facing command published with a candidate inlines that value rather
   than asking the user to select an image. The process listens on the container
   interface required by Docker, while Docker publishes it only on host
   loopback.

2. Open `http://localhost:18080`. The canonical page creates the only Owner.
   Owner creation moves directly to `ready` with rules-only mode; there is no
   model or Source wizard.
3. Enter host, port, database, username, password, and TLS mode. A successful
   TiDB identity probe atomically installs one ephemeral live connection. The
   password field is cleared immediately after submission.
4. Choose one candidate digest from the last 5–60 minutes, then paste the exact
   SELECT text for that digest. The UI states that the SQL is parsed and hashed,
   not executed.
5. Start diagnosis. The service verifies the selected digest, collects bounded
   evidence, applies the rules, and returns one report synchronously.
6. Read conclusion, impact, evidence, reasoning, ordered action, validation,
   rollback, and uncertainty. Internal IDs appear only in a collapsed trace.
7. Logout or disconnect closes the live TiDB connection. Restarting the
   container always requires credential re-entry.

If the user does not possess the SQL text, M0 may still show candidate metrics,
but the Web client does not call the diagnosis endpoint and displays the fixed
Chinese instruction “请粘贴与所选 SQL Digest 对应的完整 SELECT 文本后再诊断”。 A
missing or empty `sql_text` sent directly to the API returns
`422 VALIDATION_ERROR`; it never produces a report. `observe` is reserved for
a valid SQL request whose required evidence is missing, stale, truncated,
mismatched, unsupported, or integrity-invalid.

## 4. Runtime State Model

M0 has two setup states and three connection states:

~~~text
setup:      owner_required -> ready
connection: disconnected -> connecting -> ready
                              |            |
                              +--failure---+-> disconnected
ready -- disconnect/logout/socket failure/process exit -> disconnected
~~~

There is no Source state machine. A successful connection creates an opaque,
random `connection_id`, an opaque ephemeral `source_id`, revision `1`, one live
driver connection, safe product/version metadata, and one non-queuing operation
lease. It does not create Source/v1.

Normal `PUT`, `DELETE`, candidate collection, and diagnosis all acquire that
same operation lease with a single immediate attempt. If another normal
operation holds it, the request returns `409 M0_BUSY`; it is never queued. A
replacement `PUT` holds the lease while it probes the new connection and while
it performs the short atomic swap. A failed probe closes the new socket and
leaves the prior ready connection usable. No automatic reconnect is allowed
because the pinned adapter clears the driver's reconnectable password fields
immediately after authentication and no code calls a reconnecting driver API.

Logout and process shutdown use a separate idempotent lifecycle cleanup path,
not the ordinary `DELETE` path. Logout first commits session revocation, then
cancels any active probe/query, closes and awaits every pending or installed
socket, and clears all connection references before returning. Shutdown has no
HTTP busy response: it performs the same cleanup and must leave every socket
closed. This lifecycle path never returns `M0_BUSY` and is safe to invoke more
than once.

Persisted state is limited to the Owner password hash/salt, session epoch, setup
state, and timestamps already required by local authentication. Evidence,
SQL text, candidate lists, reports, connection metadata, socket state, and TiDB
credentials are not persisted. `/data` is the only writable named volume. The
M0 image neither declares nor creates a `/secrets` path, and no TiDB credential
code may fall back to a file-backed vault.

## 5. HTTP Interface

All JSON request models reject unknown fields. All API responses set
`Cache-Control: no-store` and existing security headers. Mutating authenticated
routes require the Owner cookie and `X-CSRF-Token`. Errors use the existing
closed envelope:

~~~json
{
  "error": {
    "version": "1",
    "code": "M0_CONNECTION_REQUIRED",
    "message": "A live TiDB connection is required.",
    "request_id": "server-generated-id"
  }
}
~~~

Error messages never include a credential, SQL text, driver error, DSN, host,
username, or row content.

### 5.1 Registered Route Allowlist

| Method | Route | Auth | CSRF | Purpose |
|---|---|---:|---:|---|
| GET | `/healthz` | no | no | liveness and M0 edition only |
| GET | `/api/v1/setup/status` | no | no | two-state setup and browser proof |
| POST | `/api/v1/setup/owner` | no | setup nonce | create the only Owner |
| GET | `/api/v1/auth/session` | no | no | report current Owner session |
| POST | `/api/v1/auth/login` | no | no | establish Owner session |
| POST | `/api/v1/auth/logout` | yes | yes | revoke session and close TiDB |
| GET | `/api/v1/m0/connection` | yes | no | safe live-connection status |
| PUT | `/api/v1/m0/connection` | yes | yes | probe and replace live TiDB |
| DELETE | `/api/v1/m0/connection` | yes | yes | close and forget live TiDB |
| GET | `/api/v1/m0/sql-candidates` | yes | no | bounded digest candidates |
| POST | `/api/v1/m0/diagnoses` | yes | yes | one synchronous rules report |

Static `/` and `/app` routes serve the Web application and are not API
capabilities. `/docs`, `/redoc`, and `/openapi.json` remain disabled.

### 5.2 Setup And Auth DTOs

`GET /api/v1/setup/status` returns:

~~~json
{
  "edition": "m0_private_preview",
  "state": "owner_required",
  "initialized": false,
  "owner_configured": false,
  "configured_mode": "rules",
  "csrf_token": null,
  "setup_nonce": "short-lived-single-use-proof"
}
~~~

`setup_nonce` is present only when the request has exactly
`Host: localhost:18080`, has no Forwarded/X-Forwarded headers, the Owner does not
exist, and a bound HttpOnly `SameSite=Strict` setup cookie was issued. Owner
creation additionally requires exactly `Origin: http://localhost:18080`, the
matching header nonce, the cookie, expiry, and single consumption.

`POST /api/v1/setup/owner` accepts only:

~~~json
{"password":"12-to-128-Unicode-characters"}
~~~

On success it moves directly to `ready` and returns status `201`:

~~~json
{
  "edition": "m0_private_preview",
  "state": "ready",
  "authenticated": true,
  "configured_mode": "rules",
  "csrf_token": "owner-csrf-proof"
}
~~~

Session/login/logout retain the existing closed password, cookie, rate-limit,
CSRF, expiry, and revocation behavior. Logout also invokes connection cleanup
before returning `{"authenticated":false}`.

### 5.3 Ephemeral Connection

`PUT /api/v1/m0/connection` accepts at most 4096 body bytes:

~~~json
{
  "host": "tidb.internal.example",
  "port": 4000,
  "database": "shop",
  "username": "sqllens_ro",
  "password": "entered-once",
  "tls_mode": "verify_ca"
}
~~~

Constraints:

- `host`: 1–253 ASCII characters; DNS name or IP literal only; no scheme,
  slash, userinfo, whitespace, NUL, or Unix socket;
- `port`: integer 1–65535;
- `database` and `username`: 1–64 characters, no control characters;
- `password`: 1–512 Unicode characters, represented as a secret field and
  excluded from `repr`;
- `tls_mode`: exactly `verify_ca` or `disabled`; the UI defaults to
  `verify_ca`, and `disabled` requires a visible warning; there is no
  skip-verification mode.

Implementation uses the pinned asynchronous MySQL driver `asyncmy==0.2.14`, one
connection, `echo=False`, no pool, no driver query callback, UTF-8, autocommit
enabled, `local_infile=False`, `init_command=None`, and no reconnect or generic
execute surface. It sets the driver's `connect_timeout=5` and `read_timeout=5`.
Because this release has no `write_timeout` parameter, each connect,
execute/read, and asynchronous close operation also runs inside a 5-second
`asyncio.timeout()` total I/O deadline; timeout or cancellation enters
lifecycle cleanup and invalidates the live slot. If graceful socket
finalization reaches its deadline, cleanup aborts the transport rather than
retaining a reusable slot.

The pinned driver's public constructor unconditionally adds the MySQL
`CLIENT_MULTI_STATEMENTS` capability and retains `_password` plus
`_password_creator`. M0 therefore uses one exact-version compatibility adapter,
not the convenience `asyncmy.connect()` function. Before any network I/O, the
adapter constructs `asyncmy.connection.Connection`, verifies the package
version and all three expected private fields, clears the
`MULTI_STATEMENTS` bit from `_client_flag`, and reads the bit back as zero. Any
mismatch fails before `Connection.connect()` is called. Immediately after the
TLS/authentication handshake—on both later success and failure paths—and before
the identity probe, it overwrites `_password` and `_password_creator` with
`b""` and `None` and reads them back. A missing, unwritable, or nonempty field
closes the socket and fails the connection.

This shim neither replaces driver methods nor supports another driver version.
The store never retains the request DTO or password, and reconnect is
forbidden. Exact registry/binder reconstruction, a final exactly-one-statement
parse, bound values, and no generic cursor/execute API remain defense in depth.
This is not a general zeroization claim; Python temporary-copy limitations
remain as stated in the ADR.

For `tls_mode=verify_ca`, the server constructs and passes an
`ssl.create_default_context()` instance with `CERT_REQUIRED` and hostname
checking enabled. It never passes `ssl=True`, because this driver disables
certificate verification when no CA is present in its mapping path.
`tls_mode=disabled` passes no TLS context and remains visibly warned in the UI.

The driver dependency and lockfile change are reviewed with the implementation.
Official references:
https://pypi.org/project/asyncmy/0.2.14/ and
https://github.com/long2ice/asyncmy/blob/dev/CHANGELOG.md.

The service runs registered `server.identity` and accepts only a parsed TiDB
version `>=8.5.0,<8.6.0`. Unknown, PingKaiDB, MySQL, MariaDB, and other TiDB
versions fail closed without installing the connection.

Success status `200` contains only safe metadata:

~~~json
{
  "schema_version": "m0-connection/v1",
  "connection_id": "conn_4f0c0a5ec04b42cc",
  "state": "ready",
  "product": "tidb",
  "version": "8.5.4",
  "database": "shop",
  "tls_mode": "verify_ca",
  "connected_at": "2026-09-03T05:30:00Z"
}
~~~

It contains no password, username, host, DSN, driver representation, or server
banner. `GET` returns the same safe projection or
`{"schema_version":"m0-connection/v1","state":"disconnected"}`. Ordinary
`DELETE` is idempotent and returns `204` after the socket and references are
cleared, or `409 M0_BUSY` when another normal operation owns the lease. Logout
and shutdown never delegate to this HTTP operation; they use the mandatory
lifecycle cleanup defined in section 4.

### 5.4 Candidate Discovery

`GET /api/v1/m0/sql-candidates?window_minutes=30` accepts an integer from 5 to
60 and uses the connected database. It executes one registered current-user
query with a 5-second, 20-row, 262144-byte limit. It returns no SQL text,
plan text, literals, rows, host, or username:

~~~json
{
  "schema_version": "m0-sql-candidates/v1",
  "window_minutes": 30,
  "collected_at": "2026-09-03T05:35:00Z",
  "truncated": false,
  "items": [
    {
      "sql_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "execution_count": 18,
      "p95_ms": 1400,
      "average_scan_rows": 120000,
      "average_return_rows": 8,
      "last_seen": "2026-09-03T05:34:12Z"
    }
  ]
}
~~~

No rows produces an empty list, not synthetic evidence. Permission denial,
timeout, disconnect, invalid fields, or a result over budget produces a stable
error code and invalidates a broken live connection when appropriate.

### 5.5 Diagnosis

`POST /api/v1/m0/diagnoses` accepts at most 34816 body bytes:

~~~json
{
  "sql_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "sql_text": "SELECT id, state FROM orders WHERE customer_id = 42",
  "window_minutes": 30
}
~~~

- `sql_digest` is exactly 64 lowercase hexadecimal characters.
- `sql_text` is required, 1–32768 UTF-8 bytes, and exactly one locally parsed
  SELECT or WITH-SELECT over exactly one base table. A missing/empty field,
  join, multi-table reference, derived-table-only query, control/mutating
  statement, lock, outfile, multiple statements, or any user-supplied EXPLAIN
  returns `422 VALIDATION_ERROR` with no collection and no report.
- The SQL is never executed. A registered parameterized
  `SELECT TIDB_ENCODE_SQL_DIGEST(:sql_text)` query must equal `sql_digest`.
- The only query containing the validated SQL syntax is a server-created
  `EXPLAIN FORMAT='brief'` statement whose child is the canonical serialization
  of that validated SELECT, used to collect
  `ordinary-plan/v2`. It is separately parsed and must contain exactly one
  ordinary EXPLAIN over that same SELECT; `ANALYZE` is forbidden.
- `window_minutes` is an integer from 5 to 60.
- The request body and parsed AST are request-local, excluded from logs and
  persistence, and cleared from the Web form after the response.

The service issues exactly the needed subset of at most six authorized evidence
queries—digest, Slow Query, Statement Summary, ordinary plan, index metadata,
and statistics health—sequentially. Five are immutable registry entries. The
ordinary plan is created only by `bind_m0_ordinary_explain(validated_select)`,
the registered binder that serializes the already validated single-table SELECT
and prepends `EXPLAIN FORMAT='brief'`; executor and Evidence construction each
rebuild the bound query and require exact equality. No generic SQL execution
method accepts a caller-created `ServerQuery`. Collection runs with
an overall 30-second deadline, at most 1000 rows and 2 MiB across all results.
Every query independently retains its stricter registry budget. Failure of one
optional role becomes a typed gap; identity/digest mismatch, version mismatch,
or connection loss fails the request safely. The response is one schema-valid
`diagnosis-report/v1` object; there is no job, polling, retry receipt, or stored
Case endpoint.

## 6. Evidence Boundary

### 6.1 Shared Integration Objects

`#t18` and `#t20` integrate through two pure typed projectors, the existing
managed-Evidence builder, and a pure report function. `#t20` publishes:

~~~python
def project_statistics_health_v1(
    result: QueryResult,
    *,
    database: str,
    table_name: str,
    profile_subject_ref: str,
    profile_object_ref: str,
) -> dict[str, JsonValue]: ...


def project_statement_summary_v3(
    result: QueryResult,
    *,
    database: str,
    sql_digest: str,
    window_start: datetime,
    window_end: datetime,
    profile_subject_ref: str,
    profile_object_ref: str,
) -> dict[str, JsonValue]: ...


@dataclass(frozen=True, slots=True)
class M0ReportInput:
    case_id: str
    database: str
    sql_digest: str
    window_start: datetime
    window_end: datetime
    evidence: tuple[CollectedEvidence, ...] = field(repr=False)


def build_m0_rules_report(value: M0ReportInput) -> bytes:
    """Return canonical UTF-8 JSON conforming to diagnosis-report/v1."""
~~~

`#t18` owns the only dynamic query interface:

~~~python
@dataclass(frozen=True, slots=True)
class ValidatedM0Select:
    canonical_sql: str = field(repr=False)
    sql_digest: str
    database: str
    table_name: str


def bind_m0_ordinary_explain(value: ValidatedM0Select) -> ServerQuery:
    """Reparse, revalidate, and bind one ordinary EXPLAIN query."""
~~~

The binder reparses `canonical_sql`, rechecks the single-table read-only SELECT
boundary, requires the already server-verified digest and database/table
identity, and returns a fixed-ID/fixed-budget query whose SQL field is excluded
from representation and logging. Both executor and Evidence wrapper call the
binder independently and compare the entire frozen `ServerQuery` before use.

The projectors validate exact expected column tuples, identity/window values,
numeric types/ranges, and safe-integer arithmetic, then return only closed typed
payload dictionaries. They do not accept `ServerQuery` and cannot create an
Evidence envelope, collector/query identity, budget, storage digest, or
`CollectedEvidence`.

After the Human report gate, `#t18` registers and executes each `ServerQuery`.
Only after the M0 managed-Evidence wrapper proves exact immutable-registry
equality, or exact registered-binder reconstruction for ordinary EXPLAIN, plus
result columns, budget, truncation, canonical raw digest, and context may it
call one projector and assemble `CollectedEvidence`. A projector result that
did not pass through that wrapper is ineligible for a runtime report.

The report builder validates strict JSON, Evidence/v2 schema, role-specific
identity, freshness, coverage, collection completion, typed digest, and raw
storage digest before evaluating a rule. It reads only typed payload fields. It
does not import FastAPI, a database driver, the credential slot, or a model SDK.

Each connection creates random ephemeral `src_*@1`, `case_*`, `subject_*`,
`ev_*`, and `payload_*` identifiers satisfying existing contract patterns. They
provide within-response trace identity only and are never persisted or exposed
as a Source management resource.

### 6.2 Allowed Evidence/v2 Increment

M0 may add only these backward-compatible typed variants to Evidence/v2:

**`statistics-health/v1`** (kind remains `statistics`):

~~~json
{
  "kind": "statistics",
  "profileSubjectRef": "subject_0123456789abcdef",
  "profileObjectRef": "orders",
  "tableName": "orders",
  "healthyPercent": 42
}
~~~

`healthyPercent` is an integer 0–100 from real bounded `SHOW STATS_HEALTHY`
evidence. This variant has no `planStats`, `estimatedRows`, or `actualRows`;
ordinary-plan text cannot silently widen a statistics-health conclusion.
The projector accepts exactly the declared four-column tuple
`(db_name, table_name, partition_name, healthy)` and exactly one total row,
which must be the requested non-partitioned table. An empty result, any extra
row, a different database/table, a non-empty partition name, an unexpected
column, or a value outside the integer range 0–100 produces an evidence gap
rather than a typed payload. `SHOW STATS_HEALTHY` semantics and the `Healthy`
range are sourced
from the official TiDB reference:
https://docs.pingcap.com/tidb/stable/sql-statement-show-stats-healthy/.

**`statement-summary/v3`** (kind remains `statement_summary`):

~~~json
{
  "kind": "statement_summary",
  "profileSubjectRef": "subject_0123456789abcdef",
  "profileObjectRef": "sql:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "windowMinutes": 30,
  "executionCount": 18,
  "averageTotalKeys": 120000,
  "averageProcessedKeys": 119000,
  "weightedTotalKeys": 2160000,
  "sqlStability": "plan_and_scan_stable"
}
~~~

All numeric fields are safe non-negative integers derived exactly from the
selected Statement Summary aggregate rows. `executionCount` is the checked sum
of `EXEC_COUNT`. `weightedTotalKeys` is the checked sum of
`EXEC_COUNT * AVG_TOTAL_KEYS`. `averageTotalKeys` and
`averageProcessedKeys` are their respective checked weighted sums divided by
`executionCount` and rounded to an integer with decimal `ROUND_HALF_UP`; exact
`.5` values round away from zero. Each intermediate and final value must remain
within `0..9007199254740991`.

`sqlStability` reuses the existing v2 algorithm: group rows by exact summary
window, select the two chronologically latest distinct windows, require them to
be non-overlapping and adjacent in the selected ordered sequence, require one
identical non-null plan digest within and across both windows, then compare the
two exact rational weighted averages for total and processed keys by integer
cross multiplication. Matching ratios produce `plan_and_scan_stable`; a
different single plan digest produces `plan_changed`; insufficient, overlapping,
mixed-plan, or otherwise incomparable windows produce `unknown`. Rows from
different instances in the same time window are one bucket and never count as
two windows.

`weightedTotalKeys` is explicitly a weighted derivation from aggregate fields,
not an exact sum of raw per-execution key counts and not returned rows. Existing
Statement Summary and Statistics variants remain valid for non-M0 historical
examples. The official field meanings for `EXEC_COUNT` and `AVG_TOTAL_KEYS` are
defined by the TiDB Statement Summary reference:
https://docs.pingcap.com/tidb/stable/statement-summary-tables/.

## 7. Frozen Rule Pack

Rule pack revision is `tidb-8.5-m0-rules/v1`. Every eligible role has the same
case, ephemeral source revision, and `profileSubjectRef`, a supported version,
complete collection, `fresh` status, coverage at least `0.80`, no truncation,
and verified payload digests. Identity correlation is role-specific rather than
forcing unrelated roles to share one `profileObjectRef`:

- SQL-level `sql_structure`, `slow_query`, and `statement_summary` evidence use
  `profileObjectRef` equal to the literal `sql:` prefix followed by the selected
  64-character digest; the last two also match the selected window exactly;
- table-level `ordinary_plan`, `index`, and `statistics` evidence use the plain
  `tableName` as `profileObjectRef`, and that table must be the single table in
  the eligible SQL-structure payload;
- where a typed payload carries subject/object identity, it must equal its
  Evidence envelope identity.

A rule is evaluated only after all of its role-specific correlations pass.

### 7.1 `TIDB85_INDEX_SCAN_RISK`

Required roles: `sql_structure`, `ordinary_plan`, `index`, and `slow_query` for
the correlated SQL/table identity above. Positive predicate:

- `ordinary_plan.accessPath == table_full_scan`;
- `indexCoverage == no_matching_composite_index`;
- `averageScanRows >= 10000`;
- `averageScanRows / max(averageReturnRows, 1) >= 100`;
- `callCount >= 3`.

The conclusion is limited to “the measured SQL has high scan amplification and
no matching composite index was found for the parsed filter-column prefix.” It
does not claim that creating an index is always correct. The first action is to
review an ordinary `EXPLAIN` and existing indexes; any DDL remains manual,
requires Human approval, has before/after latency and scan-row validation, and
rolls back by removing only the newly created index after confirming no other
workload depends on it.

### 7.2 `TIDB85_STATISTICS_HEALTH_RISK`

Required roles: `sql_structure` and `statistics-health/v1` for the single
referenced table. The sole positive predicate is `healthyPercent < 80`.

The 80-percent boundary is an M0 conservative product threshold, not a TiDB
vendor guarantee. The conclusion is limited to “statistics quality can affect
optimizer estimates and should be verified.” It never claims a measured
estimated/actual row mismatch. The action is to inspect stats metadata and, if
operationally appropriate, run an approved targeted statistics refresh outside
SQLLens; validation compares plan choice and latency on a safe representative
workload, and rollback restores the prior statistics/binding procedure owned by
the operator.

### 7.3 `TIDB85_REPEATED_HEAVY_SCAN`

Required roles: `statement-summary/v3` and `slow_query` for the same digest and
window. Positive predicate:

- `executionCount >= 10`;
- `weightedTotalKeys >= 1000000`;
- `averageScanRows >= 10000`;
- `averageScanRows / max(averageReturnRows, 1) >= 100`.

The conclusion is limited to “repeated execution multiplied a measured heavy
scan into a workload hotspot.” It does not infer CPU, I/O, lock, or business
impact without corresponding evidence. The action is to reduce call frequency
or fix the access path in a controlled canary; validation compares execution
count, p95 latency, and scanned rows over the same window; rollback restores the
prior application/query configuration.

### 7.4 Negative And Missing Evidence

A predicate that is false is a negative rule result, not a diagnosis. An absent,
stale, truncated, low-coverage, identity-mismatched, unsupported, or invalid
required role produces an actionless `priority=observe` report. The report names
which role is missing and how the operator can collect it. It must not emit a
rule ID, a root cause, a confidence number, a claimed gain, or an action.

When more than one rule hits, order is repeated-heavy-scan, index-scan-risk,
then statistics-health-risk. Publish at most three actions after deduplicating
identical operator steps.

## 8. Report Contract And Sample Gate

M0 reuses `docs/contracts/diagnosis-report-v1.schema.json`:

- `configuredMode=rules`, `effectiveMode=rules`;
- `reasoning.aiContributionZh=null`;
- `reasoning.aiStatus=not_requested`;
- `reasoning.aiCode=null`, `reasoning.aiReasonZh=null`;
- `trace.aiInvocation=null`;
- provider/model/prompt/payload pins are null;
- `trace.pinnedRevisions.rulePack=tidb-8.5-m0-rules/v1`;
- `impact.businessEvidenceIds=[]` is allowed; when empty,
  `impact.businessZh` is exactly “未提供业务影响证据，仅说明数据库技术影响”.
  M0 never creates a synthetic `business_observation` merely to satisfy the
  report schema;
- for a positive report, evidence completeness is the leading finding's eligible
  required-role count divided by its required-role count, rounded down to an
  integer percentage;
- for an `observe` report with no finding, evidence completeness is the maximum
  eligible-required/required percentage across the three rules; a tie uses the
  fixed order repeated-heavy-scan, index-scan-risk, statistics-health-risk;
- a positive report defaults to `P2`. It becomes `P1` only when an eligible Slow
  Query role supplies `p95Ms >= 5000` and an eligible Statement Summary role
  supplies `executionCount >= 20` for the exact same selected digest and window;
  absence of either metric cannot upgrade priority. A report with no eligible
  hit uses `observe`;
- actions never execute automatically and always include owner, risk,
  prerequisites, validation target, and rollback.

Before runtime integration, `#t20` delivers:

- `docs/contracts/examples/diagnosis-report-v1.m0-index-scan.review.json`;
- `docs/contracts/examples/diagnosis-report-v1.m0-statistics-health.review.json`;
- `docs/contracts/examples/diagnosis-report-v1.m0-repeated-scan.review.json`;
- `docs/product/sqllens-m0-report-preview.html`.

The standalone HTML displays the three reports with a scenario switcher at
390px and desktop widths. It contains no external asset, network call, secret,
or claim that the examples are live results. Human acceptance asks:

1. Can the user identify the measured problem and its evidence?
2. Is the conclusion narrower than the evidence?
3. Is the next action executable by its named owner?
4. Are success criteria and rollback unambiguous?
5. Is missing evidence visible rather than hidden by confidence prose?

A “no” stops runtime expansion and returns to the report/rule wording only.

## 9. Threat Boundaries And Abuse Cases

| Boundary / asset | Abuse case | M0 control |
|---|---|---|
| first Owner | remote caller or proxy spoof creates Owner | exact Host/Origin, reject forwarding headers, cookie-bound one-use nonce, rate limit |
| TiDB password | secret reaches SQLite, volume, log, response, DOM, env, traceback | secret type/no repr, live connection only, closed DTOs/errors, log capture tests, filesystem snapshot tests, form clear |
| TiDB target | malformed DSN/socket or unexpected product | structured host/port fields, no URI/socket, identity query, strict 8.5.x range |
| pinned driver | constructor forces `CLIENT_MULTI_STATEMENTS`, retains reconnect fields, or private layout drifts | exact-version adapter clears and verifies `_client_flag` before network I/O, scrubs and verifies `_password`/`_password_creator` after handshake, forbids reconnect; exact single-statement executor remains defense in depth; Reviewer inspects the shim |
| SQL text | missing/unsupported SQL or DML/control/multiple statement reaches execution | required single-table SELECT boundary; API 422 before collection; submitted SQL never executes; only its value is bound to the digest function and its validated syntax is wrapped by the server-owned ordinary EXPLAIN |
| collector | user chooses arbitrary query or exceeds budget | immutable registry plus one exact-reconstruction ordinary-EXPLAIN binder, parameter binding, AST validation, per-query and aggregate budgets, single concurrency |
| evidence | row or digest tampering creates a finding | strict result columns, canonical digests, schema and identity validation, fail closed |
| browser | secret remains visible or confidential text becomes HTML | controlled inputs, React escaping, no `innerHTML`, clear fields, CSP, no browser storage |
| denial of service | slow connection/query/request blocks service | body caps, driver connect/read bounds plus 5-second total I/O deadlines, 30-second run bound, one non-queuing operation lease, lifecycle cancellation/close |
| hidden platform | unfinished old route remains callable | positive route allowlist plus explicit 404 test table |

## 10. Ownership And Parallel Boundary

- `swat-mgr` owns only this decision/specification, dependency order, timebox,
  and stop decision. It does not implement runtime code.
- `swat-rd` owns `#t18` in `/root/sqllens-rd`: Owner/auth composition,
  ephemeral connection, query registry/parameter binding, registered ordinary-
  EXPLAIN binder, fixed collectors, Web journey, and runtime integration.
- `swat-rd2` owns `#t20` in `/root/sqllens-rd2`: the two bounded Evidence/v2
  schemas and pure `QueryResult -> closed typed payload` projectors, three rule
  cards, pure report builder, three JSON reports, and HTML. It does not create
  a `CollectedEvidence`, edit `evidence_connector/queries.py`, or add collection
  SQL.
- `swat-qa` owns `#t22`: freezes a traceability matrix now and executes only
  after Human report acceptance and one commit/image digest are frozen.
- `swat-reviwer` owns `#t23`: one narrow review of the final M0 security diff;
  it does not repeat QA or revive ADR 0011 scope.

`#t18` does not edit report/rule/projection files before `#t20` publishes its
commit. `#t20` does not edit FastAPI routes, auth, driver, query registry, Web
runtime, or connection files. Integration cherry-picks `#t20` into `#t18` only
after the sample gate.

## 11. Verification And Delivery Gates

### Gate A — within four hours

- three schema-valid rules-only JSON reports;
- one standalone responsive HTML preview;
- focused rule tests including positive, negative, missing-evidence, identity,
  version, truncation, and digest cases;
- Human explicitly accepts or rejects report value.

### Gate B — within 24 hours, only after Gate A acceptance

- frozen implementation commit and one locally built image digest;
- real TiDB v8.5.x identity, candidate discovery, and all three scenario
  evidence paths;
- RD focused tests, lint, typecheck, Web tests/build, and one Chromium smoke;
- zero known credential persistence/log/DOM findings.

### Gate C — by 36 hours maximum

- one Reviewer high-risk PASS or reproducible BLOCKED result;
- one QA execution against the same commit and image digest;
- at most one targeted correction/retest;
- explicit private-preview limitation and rollback instructions.

If the TiDB v8.5.x environment is unavailable, Gate B is `BLOCKED`, never
fixture-PASS. If a same-severity cross-domain defect remains after one correction
or a timebox is missed, reduce rule coverage or stop; do not reintroduce
persistent Source, AI, extra evidence systems, or release work.

## 12. Commands And Repository Locations

Technology remains Python 3.12, FastAPI 0.141.1, Pydantic 2.13.5, sqlglot
30.17.0, React 19, TypeScript strict, Vite, Pytest, Vitest, Playwright, Ruff,
and mypy. M0 adds only pinned `asyncmy==0.2.14` to the runtime dependency set.

Implementation files live under `apps/api/src/sqllens_api/` and
`apps/web/src/`. Rule fixtures live under `docs/contracts/examples/` and
`tests/fixtures/m0/`; the Human preview lives under `docs/product/`.

Focused work uses exact test files from the implementation plan. Before a
candidate is frozen, RD runs:

~~~bash
make lint
make typecheck
make test
npm --prefix apps/web test -- --run
npm --prefix apps/web run build
python3 docs/contracts/validate_vnext_examples.py
python3 -m unittest discover -s docs/contracts -p 'test_*.py' -v
git diff --check
~~~

QA/Reviewer do not infer PASS from these author-run commands; they preserve
their independent evidence and statuses.

## 13. Boundaries

Always:

- validate every HTTP, driver-result, evidence, and report boundary;
- use parameter binding and registry-owned collection queries;
- show `rules-only` and `private preview` in the UI;
- render uncertainty when evidence does not support a conclusion;
- record exact commit, image digest, command, result, and environment.

Ask the Human before:

- changing the three rule categories or report meaning;
- requiring a stronger TiDB privilege than the frozen diagnostic account;
- adding another runtime dependency, route, state, background job, or persisted
  record;
- changing the 4/24/36-hour gates.

Never:

- persist or log TiDB credentials or SQL text;
- execute submitted SQL, DML, DDL, control statements, recommendations,
  user-supplied EXPLAIN, or `EXPLAIN ANALYZE`; the only plan query is the
  server-created ordinary EXPLAIN over a validated SELECT;
- make an AI/network-provider call;
- expose deferred routes behind a hidden switch;
- call fixture/simulated evidence a real TiDB PASS;
- describe M0 as production-ready, complete P0, multi-source, or unattended.

## 14. No Open Scope Questions

The Human selected this route on 2026-09-03. Any newly discovered ambiguity is
resolved in favor of the smaller, fail-closed behavior above; expanding scope
requires a separate Human decision.
