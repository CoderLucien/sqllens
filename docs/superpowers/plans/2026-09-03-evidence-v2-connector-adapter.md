# Evidence/v2 Connector Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the existing TiDB v8.5.x and PingKaiDB v7.1.x bounded
Statement Summary and Slow Query collection results into immutable managed
Source `Evidence/v2` records without introducing a Web, Case, Report, or Source
persistence dependency.

**Architecture:** Keep the query registry and replaceable client as the database
boundary. Add a pure adapter that validates result shape and observed budget
usage, derives only contract-approved typed fields, produces the exact
Evidence/v2 envelope, and returns the canonical confidential storage payload
separately. A local canonical-JSON implementation is locked to the frozen
`b5795e6` test vectors so runtime code does not import executable files from
`docs/contracts`.

**Tech Stack:** Python 3.12, frozen dataclasses, `Decimal`, `hashlib`, strict
standard-library JSON, SQLGlot 30.17.0, pytest 9.1.1.

## Global Constraints

- Treat `b5795e6` as a read-only contract baseline; do not modify
  `docs/contracts`, Case/Report/UI/routes, or Source persistence.
- Emit only `origin=managed_source` Evidence bound to an exact Source revision.
- Never include SQL text, credentials, arbitrary query parameters, or raw rows
  in the Evidence envelope; confidential normalized rows remain in the returned
  storage payload behind `payload.storageRef`.
- Fail closed on unknown query IDs, mismatched columns/rows, unsupported values,
  non-finite numbers, empty evidence, or any timeout/row/byte budget violation.
- A saturated row/byte budget is marked truncated even if a client forgets to
  set its truncation flag; downstream evidence policy can then abstain.
- `profileSubjectRef` and `profileObjectRef` are supplied through an explicitly
  server-owned context and projected identically into the envelope and typed
  payload.
- Recorded TiDB/PingKaiDB fixtures remain
  `documentation-derived-normalized` and `runtimeVerified=false`.
- No new runtime dependency or database driver is added.

---

### Task 1: Align The Feature Branch To The Frozen Contract

**Files:**
- Merge only; no hand-edited product files.

**Interfaces:**
- Consumes: connector HEAD `841242e` and frozen contract SHA `b5795e6`.
- Produces: a feature branch where `b5795e6` is an ancestor.

- [x] **Step 1: Verify the feature worktree is isolated and clean**

Run: `git status --short --branch`

Expected: `feature/vnext-evidence-connector` with no working-tree changes.

- [x] **Step 2: Merge the frozen baseline without editing its contract files**

Run: `git merge --no-ff b5795e6 -m 'merge: align connector with frozen vnext contracts'`

Expected: a conflict-free merge.

- [x] **Step 3: Re-run the existing connector suite**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_versioning.py tests/api/test_evidence_connector_capabilities.py tests/api/test_evidence_connector_queries.py`

Expected: `44 passed`.

### Task 2: Make Query Results Budget-Auditable

**Files:**
- Modify: `apps/api/src/sqllens_api/evidence_connector/client.py`
- Modify: `apps/api/src/sqllens_api/evidence_connector/queries.py`
- Modify: `tests/api/test_evidence_connector_queries.py`
- Modify: `tests/fixtures/evidence_connector/tidb-8.5.4.json`
- Modify: `tests/fixtures/evidence_connector/pingkaidb-7.1.8.json`

**Interfaces:**
- Consumes: `ServerQuery`, its immutable `QueryBudget`, and a driver-produced
  `QueryResult`.
- Produces: `QueryResult.elapsed_ms`, the existing `observed_bytes`, and Slow
  Query rows containing official `result_rows` metadata.

- [x] **Step 1: Add failing query/result contract tests**

```python
def test_query_result_records_elapsed_budget_usage() -> None:
    result = QueryResult(
        columns=("value",),
        rows=({"value": 1},),
        truncated=False,
        observed_bytes=8,
        elapsed_ms=4,
    )
    assert result.elapsed_ms == 4

def test_slow_query_registry_collects_result_rows() -> None:
    for pack_id in ("tidb-8.5", "pingkaidb-7.1"):
        query = query_pack(pack_id)["slow_query.current_user"]
        assert "result_rows" in query.result_columns
        assert query.query_revision.endswith("-v2")
```

- [x] **Step 2: Run RED**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_queries.py`

Expected: failures because `QueryResult` has no `elapsed_ms` and the query does
not project `result_rows`.

- [x] **Step 3: Add elapsed usage and bump immutable query revisions**

Add required `elapsed_ms: int` to `QueryResult`. Add `result_rows` to both Slow
Query projections, advance each changed Slow Query revision to `v2`, and
advance the containing pack revision to `queries-v2` while preserving unchanged
query revisions at `v1`.

- [x] **Step 4: Update documentation-derived recordings**

Add integer `result_rows` values and update fixture revisions to `connector-v2`.
Do not add query text, SQL literals, credentials, hostnames, or customer data.

- [x] **Step 5: Run GREEN and focused static gates**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_queries.py`

Run: `.venv/bin/python -m ruff check apps/api/src/sqllens_api/evidence_connector tests/api/test_evidence_connector_queries.py`

Run: `.venv/bin/python -m mypy apps/api/src/sqllens_api/evidence_connector`

### Task 3: Build Contract-Exact Managed Evidence

**Files:**
- Create: `apps/api/src/sqllens_api/evidence_connector/canonical.py`
- Create: `apps/api/src/sqllens_api/evidence_connector/evidence.py`
- Create: `tests/api/test_evidence_connector_evidence.py`
- Modify: `apps/api/src/sqllens_api/evidence_connector/__init__.py`

**Interfaces:**
- Consumes: `ServerQuery`, `QueryResult`, and `ManagedEvidenceContext` containing
  service-allocated IDs, identity, exact Source revision, observation window,
  freshness, coverage basis points, collection time, and storage reference.
- Produces: `CollectedEvidence(document, storage_payload)` through
  `build_managed_evidence(query, result, context)`.

- [x] **Step 1: Write canonical and envelope RED tests**

Tests must assert:

```python
assert canonical_sha256(contract_typed_slow_query) == (
    "sha256:9b10ce079c8610618e4ac8959b580ecc67b3d180df4ca475d176533677d417a7"
)
assert evidence.document["schemaVersion"] == "evidence/v2"
assert evidence.document["sourceRef"] == {
    "sourceId": "src_0000000000000001",
    "revision": 3,
}
assert evidence.document["payload"]["typed"]["kind"] == "slow_query"
assert evidence.document["collection"]["budget"] == {
    "timeoutMs": query.budget.timeout_ms,
    "maxRows": query.budget.max_rows,
    "maxBytes": query.budget.max_bytes,
    "elapsedMs": result.elapsed_ms,
    "rowsRead": len(result.rows),
    "bytesRead": result.observed_bytes,
}
```

Also assert identity is duplicated exactly into the typed payload, raw rows are
absent from the envelope, and `payload.digest` equals the SHA-256 digest of the
returned storage payload.

- [x] **Step 2: Run RED**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_evidence.py`

Expected: collection fails because the canonical and Evidence adapter modules
do not exist.

- [x] **Step 3: Implement restricted canonical JSON**

Implement the frozen `rfc8785-safe-integer/v1` profile: UTF-16 object-key
ordering, strict JSON strings, finite values only, integer typed measurements
inside the IEEE-754 safe range, and SHA-256 with the `sha256:` prefix. Keep this
module independent of the documentation validator.

- [x] **Step 4: Implement the managed collection context and result boundary**

Validate every ID and timestamp against Evidence/v2, require a whole-minute
window in `[1, 1440]`, require coverage basis points in `[0, 10000]`, validate
the exact result columns and row keys, and reject over-budget results.

- [x] **Step 5: Implement Slow Query typed extraction**

Use the official Slow Query metadata only: nearest-rank P95 of `query_time`
converted from seconds to integer milliseconds, rounded integer averages of
`total_keys` and `result_rows`, and row count as `callCount`. Reject missing,
Boolean, non-finite, fractional row-count, out-of-window, cross-schema, or
cross-digest values rather than coercing them.

- [x] **Step 6: Implement conservative Statement Summary extraction**

Emit `unknown` unless at least two complete comparison windows make an exact
plan/scan classification possible. Exact plan-digest difference emits
`plan_changed`; identical plan digest plus identical average total/processed
keys emits `plan_and_scan_stable`; other scan differences remain `unknown`
because the frozen contract defines no connector-side regression threshold.

- [x] **Step 7: Render contract-owned summaries and envelope metadata**

Use `slow-query/v2` or `statement-summary/v2`,
`evidence-extractor/v1`, `rfc8785-safe-integer/v1`,
`evidence-redaction/v2`, and a versioned connector collector ID/revision.
Derive truncation from the client flag or row/byte saturation, and mirror it in
both payload and collection status.

- [x] **Step 8: Run GREEN and adversarial tests**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_evidence.py`

Expected: tests cover valid TiDB/PingKaiDB recordings plus wrong query ID,
wrong columns, row-key mismatch, empty rows, NaN/Infinity, timeout/row/byte
overflow, truncation saturation, identity/time/coverage errors, and invalid raw
numeric types.

### Task 4: Prove Frozen Contract Compatibility

**Files:**
- Modify: `tests/api/test_evidence_connector_evidence.py`
- No changes: `docs/contracts/**`

**Interfaces:**
- Consumes: generated `CollectedEvidence.document` records.
- Produces: unit-test and frozen semantic-validator evidence for the handoff.

- [x] **Step 1: Add recorded-fixture compatibility tests**

For both supported packs, load the `runtimeVerified=false` Slow Query recording,
build an Evidence document, and assert exact field sets, schema revisions,
deterministic summaries/digests, Source revision, and budget usage.

- [x] **Step 2: Run all connector tests**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_*.py`

- [x] **Step 3: Run the API regression and static suites**

Run: `.venv/bin/python -m pytest -q tests/api`

Run: `.venv/bin/python -m ruff format --check apps/api/src/sqllens_api/evidence_connector tests/api/test_evidence_connector_*.py`

Run: `.venv/bin/python -m ruff check apps/api/src tests/api`

Run: `.venv/bin/python -m mypy apps/api/src`

- [x] **Step 4: Run frozen contract validation without editing it**

Run: `python3 docs/contracts/validate_vnext_examples.py`

Run: `python3 docs/contracts/validate_vnext_negative_examples.py`

Expected: frozen positive fixtures pass and all frozen adversarial examples are
rejected.

- [x] **Step 5: Review scope and sensitive data**

Run: `git diff --check 60ba008..HEAD`

Run: `git diff --stat 60ba008..HEAD`

Run: `git diff --quiet b5795e6 -- docs/contracts`

Run: `git diff 60ba008..HEAD -- tests/fixtures/evidence_connector | rg -n -i 'password|api[_-]?key|access[_-]?token|query_sample_text|digest_text|select |insert |update |delete '`

Expected: no sensitive or SQL-literal additions.

- [ ] **Step 6: Commit, push, checkpoint, and request review**

Create the remaining adapter behavior commit after the existing budget-audit
commit, push
`feature/vnext-evidence-connector`, checkpoint #t19 with exact evidence and
`runtimeVerified=false`, and request #t23 review only the connector diff. Do not
start #t18 integration, QA, deployment, or release work.
