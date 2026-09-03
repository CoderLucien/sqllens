# SQLLens M0 Private Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship one localhost, single-Owner, single-TiDB v8.5.x, rules-only abnormal-SQL diagnosis journey whose Chinese report is accepted before any broader platform work.

**Architecture:** The M0 FastAPI composition registers only Owner/auth and three ephemeral diagnostic resource groups. One live async TiDB connection and all evidence/report data remain in memory; fixed read-only query results become immutable Evidence/v2 values, then a pure rules/report module returns DiagnosisReport/v1 JSON. Report/rule work and runtime work proceed in separate worktrees and meet only through the frozen `M0ReportInput -> bytes` interface after Human sample approval.

**Tech Stack:** Python 3.12, FastAPI 0.141.1, Pydantic 2.13.5, sqlglot 30.17.0, asyncmy 0.2.14, React 19, TypeScript strict, Vite, Pytest, Vitest, Playwright, Ruff, mypy, Docker.

**Split freeze:** Tasks 2–4 are executable from the first report/evidence SHA.
Tasks 5–9 require that SHA plus the later runtime-adapter addendum SHA. The
addendum may tighten driver/TLS/lifecycle behavior but may not change the typed
payload, Evidence, rule, report, or `M0ReportInput -> bytes` interfaces.

## Global Constraints

- Product label is `M0 私有试用版 / rules-only`; never claim full P0 or production readiness.
- Host exposure is exactly Docker publish `127.0.0.1:18080:8080`; do not bind a host LAN interface.
- One persistent Owner is allowed; TiDB credential, SQL text, Evidence, Case, and report persistence is forbidden.
- TiDB support is exactly `>=8.5.0,<8.6.0`; other products/versions fail closed.
- User SQL is required, parsed, single-base-table, and digest-verified but never
  executed; DML, DDL, control statements, locking reads, outfile, multiple
  statements, user-supplied EXPLAIN, and `EXPLAIN ANALYZE` are rejected. The
  only plan query prefixes `EXPLAIN FORMAT='brief'` to the validated SELECT's
  canonical serialization.
- No AI/provider request, Prometheus/TEM, PingKaiDB, Plan Replayer, persistent/multi-Source, job queue, receipt, release, or cross-platform work.
- Deferred API routes are unregistered and return 404; a hidden UI or disabled button is insufficient.
- The sample gate is four hours, real candidate gate 24 hours, and one correction/final gate 36 hours.
- Human report acceptance precedes runtime integration; Reviewer gets one high-risk review; QA executes one frozen matrix plus at most one targeted retest.

---

### Task 1: Publish And Consume The M0 Contract

**Owner:** `swat-mgr`

**Files:**
- Create: `docs/adr/0012-m0-private-preview-vertical-slice.md`
- Create: `docs/superpowers/specs/2026-09-03-sqllens-m0-private-preview-spec.md`
- Create: `docs/superpowers/plans/2026-09-03-sqllens-m0-private-preview.md`
- Modify: `AGENTS.md`
- Modify: `tasks/plan.md`

**Interfaces:**
- Consumes: Human decision “方案 2” and tasks `#t18/#t20/#t22/#t23`.
- Produces: route allowlist, DTOs, Evidence variants, rule predicates, ownership, and stop gates used by every later task.

- [ ] **Step 1: Add ADR 0012 and the M0 specification**

Record the approved scope and exact API/report boundaries. ADR 0009 remains
active for first-Owner proof; ADR 0010 is dormant; ADR 0011 is deferred and
unreachable in M0.

- [ ] **Step 2: Replace the delivery plan and update agent guidance**

Make `tasks/plan.md` point to the 2026-09-03 M0 spec. In `AGENTS.md`, state that
M0 supersedes the earlier vNext baseline only for the private-preview branch,
list exact worktree ownership, and forbid implementation by `swat-mgr`.

- [ ] **Step 3: Verify documentation consistency**

Run:

~~~bash
grep -R "M0_IMAGE_DIGEST\|M0_BUSY\|statistics-health/v1\|statement-summary/v3" \
  docs/adr/0012-m0-private-preview-vertical-slice.md \
  docs/superpowers/specs/2026-09-03-sqllens-m0-private-preview-spec.md \
  docs/superpowers/plans/2026-09-03-sqllens-m0-private-preview.md
git diff --check
~~~

Expected: all frozen terms are present; `git diff --check` exits 0.

- [ ] **Step 4: Commit and publish the contract**

~~~bash
git add AGENTS.md tasks/plan.md docs/adr/0012-m0-private-preview-vertical-slice.md \
  docs/superpowers/specs/2026-09-03-sqllens-m0-private-preview-spec.md \
  docs/superpowers/plans/2026-09-03-sqllens-m0-private-preview.md
git commit -m "docs: freeze M0 private preview vertical slice"
git push -u origin docs/m0-private-preview
~~~

Checkpoint `#t7` with the exact SHA and instruct `#t18/#t20/#t22` to consume it.

---

### Task 2: Add The Narrow M0 Report And Evidence Contract Increments

**Owner:** `swat-rd2` (`#t20`, `/root/sqllens-rd2`)

**Files:**
- Modify: `docs/contracts/diagnosis-report-v1.schema.json`
- Modify: `docs/contracts/evidence-v2.schema.json`
- Create: `apps/api/src/sqllens_api/m0_evidence_projection.py`
- Create: `tests/api/test_m0_evidence_projection.py`
- Modify: `docs/contracts/validate_vnext_examples.py`

**Interfaces:**
- Consumes: `QueryResult` only as an untrusted row container plus explicit
  identity/window arguments from the M0 specification.
- Produces: `project_statistics_health_v1(...) -> dict[str, JsonValue]`,
  `project_statement_summary_v3(...) -> dict[str, JsonValue]`, the two closed
  Evidence/v2 typed schemas, and the backward-compatible empty-business-
  evidence report boundary.
- Does not consume `ServerQuery` or `ManagedEvidenceContext`; does not create
  `CollectedEvidence`; does not own collection SQL, the query registry, the
  database driver, or an HTTP route.

- [ ] **Step 1: Write RED projector tests for statistics health**

Construct `QueryResult` with the exact column tuple
`("db_name", "table_name", "partition_name", "healthy")`. Accept exactly one
total row for database `shop`, table `orders`, and an empty partition name.
Reject an empty result, any additional row, a partition row, mismatched
database/table, wrong/missing/extra columns, `truncated=True`,
booleans/floats/strings for `healthy`, and an integer outside 0–100. The
accepted typed payload is exactly:

~~~python
expected_typed = {
    "kind": "statistics",
    "profileSubjectRef": SUBJECT_ID,
    "profileObjectRef": "orders",
    "tableName": "orders",
    "healthyPercent": 42,
}
~~~

Run:

~~~bash
pytest -q tests/api/test_m0_evidence_projection.py -k statistics_health
~~~

Expected: FAIL because the new typed variant does not exist.

- [ ] **Step 2: Write RED projector tests for Statement Summary aggregates**

Require this exact input column tuple, matching the existing reviewed TiDB 8.5
query projection:

~~~python
STATEMENT_SUMMARY_COLUMNS = (
    "instance", "summary_begin_time", "summary_end_time", "schema_name",
    "digest", "plan_digest", "exec_count", "sum_latency", "avg_latency",
    "max_latency", "sum_errors", "avg_mem", "max_mem", "avg_disk",
    "max_disk", "avg_total_keys", "avg_processed_keys", "first_seen",
    "last_seen",
)
~~~

Use two chronologically distinct, non-overlapping summary windows inside the
exact requested window, with two instance rows in each, and assert their checked
aggregation produces:

~~~python
{
    "kind": "statement_summary",
    "profileSubjectRef": SUBJECT_ID,
    "profileObjectRef": PROFILE_OBJECT_REF,
    "windowMinutes": 30,
    "executionCount": 18,
    "averageTotalKeys": 120000,
    "averageProcessedKeys": 119000,
    "weightedTotalKeys": 2160000,
    "sqlStability": "plan_and_scan_stable",
}
~~~

Add empty, truncated, wrong-column, wrong-database, wrong-digest, partial/
outside-window, negative, boolean, non-integral, and safe-integer overflow
cases. Assert `weightedTotalKeys` is the sum of each row's
`exec_count * avg_total_keys`, never `avg_processed_keys`, returned rows, or a
claimed raw per-execution total. Assert `averageTotalKeys` and
`averageProcessedKeys` divide their respective weighted sums by the summed
execution count with decimal `ROUND_HALF_UP`, including `.5` and non-integral
boundaries. Assert `sqlStability` compares the latest two distinct windows with
the existing v2 exact-ratio algorithm; two instance rows in one window do not
constitute two windows. Run the same focused test file and confirm RED.

- [ ] **Step 3: Implement the backward-compatible report and evidence schemas**

Change only `impact.businessEvidenceIds.minItems` from `1` to `0`; retain the
required array, uniqueness, maximum, and ID pattern. Extend the contract
validator so an empty list is valid only with the exact fixed
`businessZh="未提供业务影响证据，仅说明数据库技术影响"`; a non-empty list keeps
the existing business-observation reference checks.

Keep the historical Statistics and Statement Summary shapes valid. Add closed
`oneOf` variants keyed by `payload.schemaRevision` values
`statistics-health/v1` and `statement-summary/v3`. Both variants retain
`additionalProperties:false`; the new Statistics variant omits
`estimatedRows/actualRows` entirely.

- [ ] **Step 4: Implement the two pure typed projectors**

Add focused functions with these signatures:

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
~~~

Both functions validate their exact column tuple, identity, row types, and
`truncated=False`, then return only the closed typed dictionary. Statistics
requires exactly one total row and verifies that it is the target non-partition
table. Statement Summary requires every row to match database, digest, and the
requested window; calculates `executionCount` and `weightedTotalKeys` with
checked integer addition/multiplication; calculates both weighted averages with
decimal `ROUND_HALF_UP`; and rejects any intermediate or result beyond
`9007199254740991`. Its `sqlStability` groups same-window instance rows and
compares only the two latest distinct non-overlapping windows using one plan
digest and exact rational cross multiplication. Neither function accepts
caller-supplied aggregates or emits query, collector, budget, storage, envelope,
or persistence fields.

- [ ] **Step 5: Run focused and contract gates**

~~~bash
pytest -q tests/api/test_m0_evidence_projection.py
python3 docs/contracts/validate_vnext_examples.py
python3 -m unittest discover -s docs/contracts -p 'test_*.py' -v
ruff check apps/api/src/sqllens_api/m0_evidence_projection.py tests/api/test_m0_evidence_projection.py
mypy apps/api/src/sqllens_api/m0_evidence_projection.py
git diff --check
~~~

Expected: all PASS.

- [ ] **Step 6: Commit the evidence increment**

~~~bash
git add docs/contracts/diagnosis-report-v1.schema.json \
  docs/contracts/evidence-v2.schema.json \
  apps/api/src/sqllens_api/m0_evidence_projection.py \
  tests/api/test_m0_evidence_projection.py \
  docs/contracts/validate_vnext_examples.py
git commit -m "feat: add bounded M0 evidence projections"
~~~

---

### Task 3: Build The Pure Rule Pack And Three Human Reports

**Owner:** `swat-rd2` (`#t20`)

**Files:**
- Create: `apps/api/src/sqllens_api/m0_report.py`
- Create: `tests/api/test_m0_report.py`
- Create: `tests/fixtures/m0/report-inputs.json`
- Create: `docs/contracts/examples/diagnosis-report-v1.m0-index-scan.review.json`
- Create: `docs/contracts/examples/diagnosis-report-v1.m0-statistics-health.review.json`

**Interfaces:**
- Consumes: `M0ReportInput` containing immutable `CollectedEvidence` values.
- Produces: `build_m0_rules_report(value: M0ReportInput) -> bytes` and two of the three sample reports.

- [ ] **Step 1: Write RED rule tests**

Define `M0ReportInput` exactly as frozen:

~~~python
@dataclass(frozen=True, slots=True)
class M0ReportInput:
    case_id: str
    database: str
    sql_digest: str
    window_start: datetime
    window_end: datetime
    evidence: tuple[CollectedEvidence, ...] = field(repr=False)
~~~

Test the exact thresholds for `TIDB85_INDEX_SCAN_RISK` and
`TIDB85_STATISTICS_HEALTH_RISK`, plus one-below-boundary negatives. Assert no
positive report when an Evidence role is stale, truncated, below `0.80`, wrong
identity, wrong digest, wrong version, or has a bad raw/typed digest.
The index positive requires all four correlated roles—`sql_structure`,
`ordinary_plan`, `index`, and `slow_query`—and
`ordinary_plan.accessPath=table_full_scan`. SQL-level roles use
the `sql:` prefix followed by the selected digest as `profileObjectRef`;
table-level roles use the plain `tableName`, which must be the table declared by
SQL structure. The statistics positive depends only on a real
`healthyPercent < 80`; reject `planStats` and any pseudo-plan shortcut.

Run:

~~~bash
pytest -q tests/api/test_m0_report.py -k 'index or statistics'
~~~

Expected: FAIL because `m0_report` does not exist.

- [ ] **Step 2: Implement the closed rule cards**

Use frozen constant records, not configuration:

~~~python
RULE_PACK_REVISION = "tidb-8.5-m0-rules/v1"
INDEX_RULE_ID = "TIDB85_INDEX_SCAN_RISK"
STATISTICS_RULE_ID = "TIDB85_STATISTICS_HEALTH_RISK"
REPEATED_SCAN_RULE_ID = "TIDB85_REPEATED_HEAVY_SCAN"
MIN_COVERAGE_BASIS_POINTS = 8_000
~~~

Validate all required evidence before comparing values. Build deterministic
Chinese text from closed templates and typed numbers; do not copy free-form
connector errors or row text.

- [ ] **Step 3: Generate and validate the index/statistics report JSON**

Both reports must set rules-only/AI-null fields,
`impact.businessEvidenceIds=[]`, and the exact fixed no-business-evidence copy;
they contain a bounded action, validation target, rollback, uncertainty,
evidence IDs, rule ID, and exact pinned rule pack. Validate against
`diagnosis-report-v1.schema.json` and the M0 projection checks added to
`validate_vnext_examples.py`.

- [ ] **Step 4: Commit the first two reports**

~~~bash
git add apps/api/src/sqllens_api/m0_report.py tests/api/test_m0_report.py \
  tests/fixtures/m0/report-inputs.json \
  docs/contracts/examples/diagnosis-report-v1.m0-index-scan.review.json \
  docs/contracts/examples/diagnosis-report-v1.m0-statistics-health.review.json
git commit -m "feat: render M0 index and statistics reports"
~~~

---

### Task 4: Complete Repeated-Scan Report And Standalone Preview

**Owner:** `swat-rd2` (`#t20`)

**Files:**
- Modify: `apps/api/src/sqllens_api/m0_report.py`
- Modify: `tests/api/test_m0_report.py`
- Create: `docs/contracts/examples/diagnosis-report-v1.m0-repeated-scan.review.json`
- Create: `docs/product/sqllens-m0-report-preview.html`
- Modify: `docs/contracts/validate_vnext_examples.py`

**Interfaces:**
- Consumes: exact Statement Summary v3 and Slow Query evidence.
- Produces: complete three-rule pack and Human-reviewable report preview.

- [ ] **Step 1: Write RED repeated-scan and abstention tests**

Positive input has `executionCount=10`, `weightedTotalKeys=1000000`,
`averageScanRows=10000`, and scan/return ratio `100`. Each one-below-boundary
case is negative. A missing role returns `priority=observe`, zero actions, zero
rule IDs, and names the missing evidence role in `uncertainty`.

- [ ] **Step 2: Implement repeated-scan ordering and deduplication**

When multiple rules hit, order findings by repeated scan, index scan, then
statistics health. Deduplicate identical action templates and keep at most
three actions. For a positive report, compute completeness from the leading
finding's eligible required roles divided by its required roles. With no
finding, use the maximum ratio across the three rules and break ties in the same
fixed rule order. A positive report is P2 unless eligible same-window Slow Query
and Statement Summary roles prove both `p95Ms >= 5000` and
`executionCount >= 20`; only then is it P1.

- [ ] **Step 3: Generate the third JSON and standalone HTML**

Embed the three JSON documents in the standalone HTML as escaped JSON script
data. Use a three-button scenario switcher, semantic headings, keyboard focus,
390px responsive layout, no `innerHTML`, no external assets, and a permanent
“示例 / rules-only / 私有试用版” label.

- [ ] **Step 4: Run the sample gate**

~~~bash
pytest -q tests/api/test_m0_report.py
python3 docs/contracts/validate_vnext_examples.py
python3 -m unittest discover -s docs/contracts -p 'test_*.py' -v
ruff check apps/api/src/sqllens_api/m0_report.py tests/api/test_m0_report.py
mypy apps/api/src/sqllens_api/m0_report.py
python3 - <<'PY'
from pathlib import Path
p = Path('docs/product/sqllens-m0-report-preview.html')
s = p.read_text()
assert 'https://' not in s and 'http://' not in s
assert 'innerHTML' not in s
assert '私有试用版' in s and 'rules-only' in s
PY
git diff --check
~~~

Expected: all PASS.

- [ ] **Step 5: Commit and request Human product review**

~~~bash
git add apps/api/src/sqllens_api/m0_report.py tests/api/test_m0_report.py \
  docs/contracts/examples/diagnosis-report-v1.m0-repeated-scan.review.json \
  docs/product/sqllens-m0-report-preview.html \
  docs/contracts/validate_vnext_examples.py
git commit -m "feat: complete M0 rules-only report preview"
~~~

Upload the HTML and three JSON files to the authorized Loop thread. Report
actual command results and SHA; do not call fixture examples live TiDB evidence.
Stop here until the Human accepts the report value.

---

### Task 5: Compose The M0 CLI, Route Allowlist, And Minimal Owner Flow

**Owner:** `swat-rd` (`#t18`, parallel with Tasks 2–4)

**Files:**
- Modify: `apps/api/src/sqllens_api/main.py`
- Modify: `apps/api/entrypoint.sh`
- Modify: `apps/api/Dockerfile`
- Modify: `apps/api/src/sqllens_api/app.py`
- Modify: `apps/api/src/sqllens_api/setup.py`
- Modify: `apps/web/src/api.ts`
- Create: `tests/api/test_m0_cli.py`
- Modify: `tests/api/test_first_run_owner.py`
- Modify: `tests/api/test_m0_security_boundary.py`

**Interfaces:**
- Consumes: registered-route table, CLI table, `/data` persistence boundary,
  and setup/auth DTOs from the M0 spec.
- Produces: default/`web-api`-only entrypoint and two-state Owner/auth
  application composition; no TiDB connection or report route yet.

- [ ] **Step 1: Write the RED CLI and image-layout tests**

Assert Python CLI and `apps/api/entrypoint.sh` accept only no argument or
`web-api`. Assert `migrate`, `bootstrap-ingest`, `bootstrap-reissue`, and any
unknown argument exit `64` without importing legacy bootstrap/recovery code.
Assert `apps/api/Dockerfile` defines only `SQLLENS_DATA_DIR=/data`, creates only
`/data`, and contains no `/secrets`, `SQLLENS_SECRETS_DIR`, or credential-file
fallback. Run `pytest -q tests/api/test_m0_cli.py` and confirm RED before the
legacy branches are removed.

- [ ] **Step 2: Remove deferred CLI capabilities and freeze `/data`**

Keep database migration as an idempotent internal Web-startup action. Remove
the three explicit CLI commands and their imports. The final entrypoint invokes
only the Web API. The sole named writable volume is `/data`; it stores Owner
SQLite/session material only and never TiDB connection data.

- [ ] **Step 3: Correct the RED route-table test**

The required set is:

~~~python
REQUIRED_API_ROUTES = {
    ("GET", "/healthz"),
    ("GET", "/api/v1/setup/status"),
    ("POST", "/api/v1/setup/owner"),
    ("GET", "/api/v1/auth/session"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/logout"),
}
~~~

The deferred set contains bootstrap, model/settings, Source, old case/job,
Prometheus/TEM, PingKaiDB, and Plan Replayer paths. Run the test and confirm RED
if Owner/auth was removed with the deferred routes.

- [ ] **Step 4: Restore only Owner/auth and simplify setup to two states**

Reuse the already tested canonical Host/Origin, Forwarded-header rejection,
one-use nonce, cookie, password hash, login rate limit, session epoch, CSRF, and
revocation code. Change successful Owner creation to `state=ready` and
`configured_mode=rules`; do not call or register policy/model/finalize code.

- [ ] **Step 5: Add logout cleanup hook without connection knowledge**

`create_app` owns an async callback initialized to a no-op:

~~~python
async def clear_m0_connection() -> None:
    return None

app.state.clear_m0_connection = clear_m0_connection
~~~

Logout commits session revocation and then awaits the hook before returning.
Task 6 replaces the hook with the connection store's lifecycle `force_close`
method, avoiding imports from setup/auth to the driver. The hook is not the
ordinary HTTP `DELETE` path and must never return `M0_BUSY`.

- [ ] **Step 6: Run focused CLI, Owner, and route gates**

~~~bash
pytest -q tests/api/test_m0_cli.py tests/api/test_first_run_owner.py \
  tests/api/test_m0_security_boundary.py
ruff check apps/api/src/sqllens_api/main.py apps/api/src/sqllens_api/app.py \
  apps/api/src/sqllens_api/setup.py tests/api/test_m0_cli.py \
  tests/api/test_first_run_owner.py tests/api/test_m0_security_boundary.py
mypy apps/api/src/sqllens_api
npm --prefix apps/web test -- --run App.test.tsx
npm --prefix apps/web run build
git diff --check
~~~

Expected: all PASS and the registered API set equals the M0 subset built so far.

- [ ] **Step 7: Commit the minimal composition**

~~~bash
git add apps/api/src/sqllens_api/main.py apps/api/entrypoint.sh \
  apps/api/Dockerfile apps/api/src/sqllens_api/app.py \
  apps/api/src/sqllens_api/setup.py apps/web/src/api.ts \
  tests/api/test_m0_cli.py tests/api/test_first_run_owner.py \
  tests/api/test_m0_security_boundary.py
git commit -m "refactor: compose minimal M0 owner application"
~~~

---

### Task 6: Implement The Ephemeral TiDB Connection

**Owner:** `swat-rd` (`#t18`)

**Files:**
- Create: `apps/api/src/sqllens_api/m0_connection.py`
- Create: `apps/api/src/sqllens_api/m0_routes.py`
- Create: `tests/api/test_m0_connection.py`
- Modify: `apps/api/src/sqllens_api/app.py`
- Modify: `pyproject.toml`
- Modify: `requirements/runtime.lock`

**Interfaces:**
- Consumes: `ReadOnlyQueryClient`, server identity query, Owner dependency, and connection DTO from the spec.
- Produces: one `M0ConnectionStore` with safe projection, a non-queuing normal-
  operation lease, ordinary disconnect, and mandatory lifecycle cleanup;
  registers GET/PUT/DELETE connection routes.

- [ ] **Step 1: Write RED secret-lifetime and DTO tests**

Assert successful PUT returns only the eight frozen safe fields; the unique test
password is absent from `repr`, response bytes, captured logs, SQLite files,
the `/data` volume, `/proc/self/environ`, and subsequent GET. Assert that the
image has no `/secrets` path or secret-file fallback. Assert bad
version/probe/timeout does not replace a previously ready connection. Assert
normal PUT/DELETE/use contention returns `409 M0_BUSY` without queuing. Assert
ordinary DELETE closes when idle. Assert logout first revokes the session and
then cancels an active probe/query, closes/awaits pending and installed sockets,
and clears the slot without returning busy; assert shutdown and repeated
lifecycle cleanup do the same. A graceful-close deadline must abort the
transport rather than preserve a reusable slot. Driver loss must also close and
clear the slot. With the unique test password, assert the post-handshake adapter
sets driver `_password == b""` and `_password_creator is None` before identity
I/O. Assert it clears and reads back
`_client_flag & CLIENT_MULTI_STATEMENTS == 0` before calling the driver's
network connect method. A wrong version or missing, unwritable, or nonconforming
field must fail before network I/O or close an already-created socket. Assert
`ssl.create_default_context()` supplies `CERT_REQUIRED` plus hostname checking
for `verify_ca`, while `ssl=True` is never passed.

- [ ] **Step 2: Add and lock the asynchronous driver**

Add exactly `asyncmy==0.2.14` to `pyproject.toml` and
`requirements/runtime.lock`; `requirements/dev.lock` already includes the
runtime lock through `-r runtime.lock` and is not edited. Create a clean Python
3.12 virtual environment, install `requirements/dev.lock`, install the project
with `--no-deps -e .`, and run `pip check`. Verify the lock diff contains only
the new pinned direct dependency. Do not enable driver logging, query callbacks,
pool, local infile, or an init command. Configure only the driver's supported
`connect_timeout=5` and `read_timeout=5`; do not pass a nonexistent
`write_timeout`. Wrap connect, probe I/O, and asynchronous close in a 5-second
`asyncio.timeout()` total deadline. Pin tests to the known driver facts:
`client_flag=0` still advertises `CLIENT_MULTI_STATEMENTS`, and the initial
connection object keeps `_password`/`_password_creator`. The compatibility
adapter must deliberately mutate and verify those three data fields; it must
not replace or monkey-patch driver methods, accept another version/layout, or
claim the public API provides these guarantees.

- [ ] **Step 3: Implement the in-memory store**

Use these public types:

~~~python
@dataclass(frozen=True, slots=True)
class M0ConnectionView:
    connection_id: str
    state: Literal["ready"]
    product: Literal["tidb"]
    version: str
    database: str
    tls_mode: Literal["verify_ca", "disabled"]
    connected_at: datetime


class M0ConnectionStore:
    async def replace(self, value: M0ConnectionInput) -> M0ConnectionView: ...
    async def view(self) -> M0ConnectionView | None: ...
    def use(self) -> AsyncContextManager[ReadOnlyQueryClient]: ...
    async def disconnect(self) -> None: ...
    async def force_close(self) -> None: ...
~~~

Secret fields use Pydantic `SecretStr` or dataclass `field(repr=False)`. Probe a
new connection while holding the one non-queuing operation lease. Connect with
`ssl.create_default_context()` (`CERT_REQUIRED`, hostname checking) for
`verify_ca`; never pass `ssl=True`. Construct the public
`asyncmy.connection.Connection` through an adapter that first asserts exact
package version/field layout, clears the `MULTI_STATEMENTS` bit in
`_client_flag`, reads the bit back as zero, and only then calls
`Connection.connect()`. As soon as authentication returns—also on every later
failure path—the adapter must set `_password=b""` and
`_password_creator=None`, read both values back, and fail closed while closing
if the invariant cannot be proved. Perform the identity probe only after that
scrub, then the short atomic swap; close the rejected/new or replaced/old socket
on every path. `replace`,
`disconnect`, and `use` make one immediate lease attempt and raise the internal
busy signal rather than waiting. Do not retain the input DTO/password and never
call a reconnecting driver method. `force_close` is a distinct idempotent
lifecycle primitive: it cancels the active probe/query, closes and awaits every
pending or installed socket, force-aborts a transport that exceeds the close
deadline, clears all references, never raises the busy signal, and is safe
during shutdown or after session revocation.

- [ ] **Step 4: Register routes and the logout/shutdown cleanup hook**

Validate body size/fields before connection. Use only stable error codes:
`AUTH_REQUIRED`, `CSRF_INVALID`, `VALIDATION_ERROR`, `M0_BUSY`,
`M0_TIDB_UNAVAILABLE`, `M0_TIDB_TIMEOUT`, and
`M0_TIDB_VERSION_UNSUPPORTED`. Sanitize all driver exceptions. Wire ordinary
DELETE to `disconnect`; wire the post-revocation logout hook and application
shutdown to `force_close`. Neither lifecycle caller invokes the DELETE route.

- [ ] **Step 5: Run focused connection gates**

~~~bash
pytest -q tests/api/test_m0_connection.py tests/api/test_first_run_owner.py tests/api/test_m0_security_boundary.py
ruff check apps/api/src/sqllens_api/m0_connection.py apps/api/src/sqllens_api/m0_routes.py tests/api/test_m0_connection.py
mypy apps/api/src/sqllens_api
python -m pip check
git diff --check
~~~

Expected: all PASS.

- [ ] **Step 6: Commit the connection slice**

~~~bash
git add pyproject.toml apps/api/src/sqllens_api/m0_connection.py \
  apps/api/src/sqllens_api/m0_routes.py apps/api/src/sqllens_api/app.py \
  tests/api/test_m0_connection.py requirements/runtime.lock
git commit -m "feat: add ephemeral M0 TiDB connection"
~~~

---

### Task 7: Add Candidate Discovery And Bounded Evidence Collection

**Owner:** `swat-rd` (`#t18`, after consuming the `#t19` connector)

**Files:**
- Create: `apps/api/src/sqllens_api/m0_diagnosis.py`
- Create: `tests/api/test_m0_diagnosis.py`
- Modify: `apps/api/src/sqllens_api/m0_routes.py`
- Modify: `apps/api/src/sqllens_api/evidence_connector/queries.py`
- Modify: `apps/api/src/sqllens_api/evidence_connector/client.py`
- Modify: `apps/api/src/sqllens_api/evidence_connector/evidence.py`
- Modify: `tests/api/test_evidence_connector_queries.py`
- Modify: `tests/api/test_evidence_connector_evidence.py`

**Interfaces:**
- Consumes: live `M0ConnectionStore`, immutable query registry, the registered
  `bind_m0_ordinary_explain(ValidatedM0Select) -> ServerQuery` binder, Task 2's
  two pure typed projectors, Evidence/v2 builders, and exact SQL/digest input.
- Produces: `/m0/sql-candidates`, an in-memory `M0ReportInput`, and a temporary
  stub report callback until Task 8.

- [ ] **Step 1: Write RED API and query-boundary tests**

Cover candidate 5/60-minute boundaries, 20-row/262144-byte cap, empty result,
wrong columns, permission denial, timeout, disconnect, and no raw SQL. Cover
diagnosis SQL byte/digest validation, missing SQL as `422 VALIDATION_ERROR`,
join/multiple-table/derived-only/DML/lock/outfile/user-EXPLAIN rejection,
`TIDB_ENCODE_SQL_DIGEST` mismatch, one concurrency slot, six-query/1000-row/2
MiB/30-second aggregate caps, and optional-evidence gaps. Assert an injected
registered-query value containing a second parsed statement is rejected before
driver I/O. Also assert the executor never receives a connection whose
`CLIENT_MULTI_STATEMENTS` bit remains set.

- [ ] **Step 2: Add exact immutable registry entries**

Add `tidb-8.5` cards named `sql_candidates.current_user`,
`sql_digest.encode`, `slow_query.current_user`,
`statement_summary.cross_user`, `index.current_table`, and
`statistics.health.current_table`. Candidate discovery reads at most 200
current-user Slow Query observations and derives at most 20 digest summaries
without returning SQL/plan text. The digest card binds SQL text only as the
argument to `TIDB_ENCODE_SQL_DIGEST`. The index card binds database/table and
projects exactly `table_schema`, `table_name`, `non_unique`, `key_name`,
`seq_in_index`, `column_name`, and `is_visible` from
`information_schema.tidb_indexes`. The statistics card uses
`SHOW STATS_HEALTHY` with bound database/table/non-partition filters and
projects exactly the four columns frozen in Task 2. Each card declares exact
parameters, timeout, rows, and bytes; parser validation rejects mutation,
wildcards, undeclared columns, multiple statements, and unbounded results. The
registry exposes no generic execute method to routes. The index source is
specified by the official TiDB reference:
https://docs.pingcap.com/tidb/stable/information-schema-tidb-indexes/.

- [ ] **Step 3: Implement the only dynamic query binder**

Define immutable `ValidatedM0Select` and
`bind_m0_ordinary_explain(value: ValidatedM0Select) -> ServerQuery` in
`queries.py`. The binder reparses the canonical SQL, rechecks exactly one
non-locking single-base-table SELECT and its database/table/digest identity,
then returns fixed query ID `ordinary_plan.validated_select`, fixed revision
`tidb-8.5/ordinary_plan.validated_select-v1`, fixed 5-second/200-row/524288-byte
budget, and SQL `EXPLAIN FORMAT='brief'` over that exact validated child. The
SQL field remains `repr=False`. Both executor and Evidence wrapper independently
rebuild the query and require full dataclass equality; direct caller-created
dynamic `ServerQuery` values are rejected.

- [ ] **Step 4: Implement the asyncmy query client**

Map named registry parameters to driver placeholders without interpolating
values or identifiers. Use the one live connection sequentially. Keep the
driver `read_timeout=5` and wrap each execute/read in a 5-second
`asyncio.timeout()` total I/O deadline; there is no `write_timeout` argument in
the pinned driver. Reparse the final driver-bound query and require exactly one
statement immediately before I/O; the adapter-cleared capability bit and this
parse are independent controls. On cancellation or timeout, enter
`force_close`, await socket termination, invalidate the connection slot, and
return a sanitized error; never leave a background query running.

- [ ] **Step 5: Build the request-local evidence bundle**

Parse SQL locally, require exactly one base table, compare its server-produced
digest, extract that table and the bounded filter-column prefix, then collect
only the authorized roles. Extend the M0 managed-Evidence wrapper so immutable
queries require exact registry equality and ordinary EXPLAIN requires exact
binder reconstruction before it can create an envelope. Only then call Task
2's typed projectors. Use random ephemeral IDs, one consistent
case/digest/window identity, role-specific `profileObjectRef` values, canonical
result bytes, and `CollectedEvidence`. Do not persist the body, AST, rows,
Evidence, or gaps.

- [ ] **Step 6: Run focused collector/API gates**

~~~bash
pytest -q tests/api/test_m0_diagnosis.py tests/api/test_m0_connection.py \
  tests/api/test_evidence_connector_queries.py \
  tests/api/test_evidence_connector_evidence.py \
  tests/api/test_m0_evidence_projection.py
ruff check apps/api/src/sqllens_api/m0_diagnosis.py \
  apps/api/src/sqllens_api/evidence_connector tests/api/test_m0_diagnosis.py
mypy apps/api/src/sqllens_api
python3 docs/contracts/validate_vnext_examples.py
git diff --check
~~~

Expected: all PASS.

- [ ] **Step 7: Commit the evidence path**

~~~bash
git add apps/api/src/sqllens_api/m0_diagnosis.py \
  apps/api/src/sqllens_api/m0_routes.py \
  apps/api/src/sqllens_api/evidence_connector/queries.py \
  apps/api/src/sqllens_api/evidence_connector/client.py \
  apps/api/src/sqllens_api/evidence_connector/evidence.py \
  tests/api/test_m0_diagnosis.py \
  tests/api/test_evidence_connector_queries.py \
  tests/api/test_evidence_connector_evidence.py
git commit -m "feat: collect bounded M0 TiDB evidence"
~~~

---

### Task 8: Integrate Reports And Build The Browser Journey

**Owner:** `swat-rd` (`#t18`, only after Human accepts Task 4)

**Files:**
- Modify: `apps/api/src/sqllens_api/app.py`
- Modify: `apps/api/src/sqllens_api/m0_routes.py`
- Modify: `apps/web/src/App.tsx`
- Create: `apps/web/src/M0Workspace.tsx`
- Modify: `apps/web/src/App.test.tsx` and create `apps/web/src/M0Workspace.test.tsx`

**Interfaces:**
- Consumes: cherry-picked `build_m0_rules_report`, M0 routes, and accepted report layout/copy.
- Produces: one end-to-end Owner -> connection -> candidate -> diagnosis -> report browser flow.

- [ ] **Step 1: Cherry-pick the two accepted `#t20` commits**

Resolve only expected connector/report files. Re-run `#t20` focused tests before
changing integration code. Stop if the cherry-pick touches auth, FastAPI route,
driver, or Web runtime files.

- [ ] **Step 2: Replace the stub report callback**

`POST /api/v1/m0/diagnoses` constructs `M0ReportInput`, calls
`build_m0_rules_report`, and returns its canonical JSON with `no-store`. It does
not create a job or persist a case.

- [ ] **Step 3: Write RED Web tests**

Test Owner setup/login, secret input clearing after connection, TLS warning,
disconnected/error states, candidate selection, SQL text clearing after
submission, all Chinese report sections, collapsed trace, rules-only/private
preview labels, and no old setup/model/source/job navigation. When SQL text is
missing, assert the fixed instruction
`请粘贴与所选 SQL Digest 对应的完整 SELECT 文本后再诊断`, no diagnosis request,
and no synthetic `observe` report. Assert no secret is present in rendered DOM
or browser storage after submit.

- [ ] **Step 4: Implement `M0Workspace`**

Use React text rendering only; never `innerHTML`. Keep password and SQL in
component state only until submit settles, then assign empty strings in a
`finally` block. Fetch with same-origin cookies and CSRF. Do not put secrets in
URLs, analytics, errors, console calls, localStorage, sessionStorage, IndexedDB,
or service-worker caches. Disable the diagnosis submission until both a digest
and non-empty SQL text exist and render the fixed instruction locally; the
client never calls the endpoint merely to obtain an abstention for missing SQL.

- [ ] **Step 5: Run API/Web integration gates**

~~~bash
pytest -q tests/api/test_m0_diagnosis.py tests/api/test_m0_connection.py \
  tests/api/test_first_run_owner.py tests/api/test_m0_security_boundary.py
npm --prefix apps/web test -- --run
npm --prefix apps/web run build
ruff check apps/api/src/sqllens_api tests/api/test_m0_*.py
mypy apps/api/src/sqllens_api
git diff --check
~~~

Expected: all PASS.

- [ ] **Step 6: Commit the vertical integration**

~~~bash
git add apps/api/src/sqllens_api/app.py apps/api/src/sqllens_api/m0_routes.py \
  apps/web/src/App.tsx apps/web/src/App.test.tsx \
  apps/web/src/M0Workspace.tsx apps/web/src/M0Workspace.test.tsx
git commit -m "feat: integrate M0 abnormal SQL journey"
~~~

---

### Task 9: Freeze One Real Candidate

**Owner:** `swat-rd` with `swat-mgr` freeze decision

**Files:**
- Create or modify: `tests/e2e/test_m0_private_preview.py`
- Modify only if needed: `apps/api/Dockerfile`
- Modify only if needed: `Makefile`
- No release archive, SBOM, provenance, signing, or platform matrix files

**Interfaces:**
- Consumes: accepted report integration and an available TiDB v8.5.x environment.
- Produces: one exact commit, one local image digest, and author-run evidence for Reviewer/QA.

- [ ] **Step 1: Add RED real-browser assertions**

The Playwright/Chromium test covers canonical Owner creation, login, one-time
connection, candidate selection, SQL/digest match, all report sections, logout
cleanup, 390px no page-wide overflow, clean console, secret absence, and every
deferred route returning 404. A container restart with the same `/data` volume
retains the Owner but reports the TiDB connection as disconnected and requires
credential re-entry; the image contains no `/secrets` path. It is skipped with
a precise environment reason when real TiDB is unavailable; fixtures cannot
make it PASS.

- [ ] **Step 2: Run the complete author gate once**

~~~bash
make lint
make typecheck
make test
npm --prefix apps/web test -- --run
npm --prefix apps/web run build
python3 docs/contracts/validate_vnext_examples.py
python3 -m unittest discover -s docs/contracts -p 'test_*.py' -v
make build
pytest -q tests/e2e/test_m0_private_preview.py
git diff --check
git status --short
~~~

Expected: all PASS, worktree clean, and the E2E identifies a real TiDB 8.5.x
version. If not, report FAIL/BLOCKED exactly.

- [ ] **Step 3: Freeze commit and image identity**

Record:

~~~bash
git rev-parse HEAD
docker build --tag sqllens-m0:candidate -f apps/api/Dockerfile .
M0_IMAGE_DIGEST="$(docker image inspect sqllens-m0:candidate --format '{{.Id}}')"
printf '%s\n' "$M0_IMAGE_DIGEST"
test "${M0_IMAGE_DIGEST#sha256:}" != "$M0_IMAGE_DIGEST"
~~~

Use the exact returned commit and `sha256:` image ID in the `#t18` checkpoint
and inline that ID in the published `docker run` command. `swat-mgr` then sets
`#t23` to in-progress and authorizes exactly that object; no code changes occur
while review/QA run.

---

### Task 10: Perform One High-Risk Review

**Owner:** `swat-reviwer` (`#t23`)

**Files:**
- Read-only review of the frozen M0 diff and artifact
- No implementation changes

**Interfaces:**
- Consumes: frozen commit/image and author evidence.
- Produces: one PASS or reproducible BLOCKED decision limited to M0 high-risk boundaries.

- [ ] **Step 1: Verify object identity and scope**

Confirm local/remote SHA, clean worktree, image digest, exact diff, route table,
and absence of deferred runtime composition.

- [ ] **Step 2: Independently challenge five boundaries**

Review and reproduce: registered-query read-only enforcement; secret absence and
cleanup; timeout query termination; loopback-only publication/canonical Owner;
and deferred-route 404. Construct fresh malformed SQL/result/driver-error and
concurrent connect/diagnosis cases. Do not review ADR 0011 internals or repeat
the full product matrix.

- [ ] **Step 3: Publish the one review result**

PASS only if no critical/high finding remains. BLOCKED findings include exact
request/input, observed result, file/line, release impact, and minimal closure.
One correction SHA may receive one targeted recheck; new lower-priority scope is
deferred.

---

### Task 11: Execute The Frozen QA Matrix Once

**Owner:** `swat-qa` (`#t22`, after Human report acceptance and Reviewer PASS)

**Files:**
- QA-owned matrix/evidence under `/root/sqllens-qa/tests/`
- No product implementation changes

**Interfaces:**
- Consumes: the same frozen commit and image digest reviewed in Task 10.
- Produces: final M0 PASS/FAIL/BLOCKED/UNVERIFIED matrix and reproducible evidence.

- [ ] **Step 1: Prove artifact identity and environment**

Record commit, image digest, CPU architecture, browser version, Docker binding,
and actual TiDB product/version. Stop BLOCKED on any mismatch.

- [ ] **Step 2: Execute one Chromium journey and three real scenarios**

Use the accepted index-scan, statistics-health, and repeated-heavy-scan data
scenarios. Compare the API report, displayed report, and raw Evidence IDs and
measurements. A scenario passes only when the conclusion is supported and its
action/validation/rollback are usable; HTTP 200 or job completion is
insufficient.

- [ ] **Step 3: Execute the bounded negative matrix**

Verify read-only rejection, digest mismatch, wrong version, denied permission,
stale/truncated/missing evidence, credential/SQL absence from persistence/logs/
DOM/browser storage, timeout cleanup, loopback exposure, restart requiring
re-entry, and all deferred routes returning 404.

- [ ] **Step 4: Publish final status**

Report each requirement as PASS, FAIL, BLOCKED, or UNVERIFIED with raw evidence.
Allow one targeted retest only for the single correction SHA. A PASS means only
“M0 local private preview,” not P0, production, multi-source, or release-ready.

---

## Dependency Graph And Stop Line

~~~text
Task 1 contract
  ├─ Task 2 evidence variants -> Task 3 rules -> Task 4 samples -> HUMAN GATE
  └─ Task 5 route/Owner -> Task 6 connection -> Task 7 collection

HUMAN GATE + Task 7
  -> Task 8 integration
  -> Task 9 frozen real candidate
  -> Task 10 one Reviewer pass
  -> Task 11 one QA execution
~~~

Parallel work is allowed only before the Human gate and only across the frozen
file/interface boundary. The first of these conditions stops the iteration:

- Human rejects report usefulness;
- no real TiDB v8.5.x environment is available;
- the 24/36-hour gate is missed;
- a second correction round would be required;
- a requested change adds an excluded capability;
- a critical/high cross-domain defect shows the M0 design is still not bounded.

At the stop line, preserve commits and evidence, mark the exact task status, and
return to scope/design. Do not convert the deadline into permission to skip a
failing gate or to call unverified work complete.
