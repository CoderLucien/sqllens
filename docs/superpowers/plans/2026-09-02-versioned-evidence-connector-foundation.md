# Versioned Evidence Connector Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the contract-independent foundation for TiDB v8.5.x and PingKaiDB v7.1.x version recognition, capability degradation, and parser-validated server-owned collection queries.

**Architecture:** A pure Python connector package exposes immutable domain values and a replaceable `ReadOnlyQueryClient` protocol. Recorded, redacted fixtures drive tests without a database driver. Evidence/v2 and DiagnosisCase/v2 projection remain outside this plan until the shared evidence contract is frozen.

**Tech Stack:** Python 3.12, dataclasses, typing `Protocol`, SQLGlot 30.17.0, pytest 9.1.1.

## Global Constraints

- Support only TiDB v8.5.x and PingKaiDB v7.1.x; fail closed for ambiguous or unsupported identities.
- Treat PROCESS as optional-sensitive; denial degrades cross-user discovery without invalidating required schema-scoped access.
- Execute only server-owned, versioned, single-statement SELECT/SHOW/DESC queries in this checkpoint.
- Parser validation rejects DML, DDL, ADMIN, SET GLOBAL, multi-statement input, and EXPLAIN ANALYZE.
- Fixtures contain no credentials, customer SQL text, or row data.
- Do not modify setup, UI, FastAPI routes, Source/v1, Evidence/v2, or DiagnosisCase/v2.

---

### Task 1: Version Fingerprints And Recorded Fixtures

**Files:**
- Create: `apps/api/src/sqllens_api/evidence_connector/__init__.py`
- Create: `apps/api/src/sqllens_api/evidence_connector/versioning.py`
- Create: `tests/api/test_evidence_connector_versioning.py`
- Create: `tests/fixtures/evidence_connector/tidb-8.5.4.json`
- Create: `tests/fixtures/evidence_connector/pingkaidb-7.1.8.json`

**Interfaces:**
- Consumes: normalized results from the server-owned `server.identity` query.
- Produces: `VersionFingerprint`, `DetectedDatabaseVersion`, and `detect_database_version(fingerprint)`.

- [ ] **Step 1: Write failing fixture-driven tests**

```python
def test_detects_supported_recorded_versions(recorded_identity: dict[str, str]) -> None:
    detected = detect_database_version(VersionFingerprint(**recorded_identity))
    assert detected.pack_id in {"tidb-8.5", "pingkaidb-7.1"}
    assert detected.is_supported is True

def test_fails_closed_for_ambiguous_and_unsupported_identity() -> None:
    detected = detect_database_version(
        VersionFingerprint(version="5.7.25-TiDB-v7.1.6", version_comment="TiDB", build="")
    )
    assert detected.is_supported is False
    assert detected.pack_id is None
```

- [ ] **Step 2: Run RED**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_versioning.py`

Expected: collection fails because `sqllens_api.evidence_connector` does not exist.

- [ ] **Step 3: Implement conservative identity detection**

```python
@dataclass(frozen=True, slots=True)
class VersionFingerprint:
    version: str
    version_comment: str
    build: str

def detect_database_version(fingerprint: VersionFingerprint) -> DetectedDatabaseVersion:
    combined = "\n".join((fingerprint.version, fingerprint.version_comment, fingerprint.build))
    # PingKaiDB requires an explicit vendor marker and v7.1.x vendor version.
    # Community TiDB requires a TiDB marker and v8.5.x release version.
```

- [ ] **Step 4: Run GREEN and static checks**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_versioning.py`

Run: `.venv/bin/python -m ruff check apps/api/src/sqllens_api/evidence_connector tests/api/test_evidence_connector_versioning.py`

Run: `.venv/bin/python -m mypy apps/api/src/sqllens_api/evidence_connector`

- [ ] **Step 5: Commit the version slice**

```bash
git add apps/api/src/sqllens_api/evidence_connector tests/api/test_evidence_connector_versioning.py tests/fixtures/evidence_connector
git commit -m "feat: detect supported database version packs"
```

### Task 2: Capability Matrix And PROCESS Degradation

**Files:**
- Create: `apps/api/src/sqllens_api/evidence_connector/capabilities.py`
- Create: `tests/api/test_evidence_connector_capabilities.py`
- Modify: `apps/api/src/sqllens_api/evidence_connector/__init__.py`

**Interfaces:**
- Consumes: a supported `pack_id` plus bounded probe outcomes.
- Produces: `CapabilityDefinition`, `CapabilityOutcome`, and `evaluate_capabilities(pack_id, probe_outcomes)`.

- [ ] **Step 1: Write failing required/optional-sensitive tests**

```python
def test_process_denial_is_visible_degradation_not_permission_expansion() -> None:
    result = evaluate_capabilities("tidb-8.5", {"schema_metadata": "available", "process": "denied"})
    assert result.source_usable is True
    assert result.discovery_scope == "current_user"
    assert result.denied_optional == ("process",)
    assert result.requested_privilege_expansion is False

def test_required_capability_denial_fails_closed() -> None:
    result = evaluate_capabilities("pingkaidb-7.1", {"schema_metadata": "denied", "process": "available"})
    assert result.source_usable is False
```

- [ ] **Step 2: Run RED**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_capabilities.py`

Expected: import failure for `capabilities`.

- [ ] **Step 3: Implement immutable per-pack matrices**

```python
class CapabilityClass(StrEnum):
    REQUIRED = "required"
    OPTIONAL_SENSITIVE = "optional_sensitive"

@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    capability_id: str
    capability_class: CapabilityClass
    denied_behavior: str
```

The matrix must mark PROCESS optional-sensitive and encode current-user-only Statement Summary/Slow Query discovery as the denied behavior.

- [ ] **Step 4: Run GREEN and static checks**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_capabilities.py`

Run: `.venv/bin/python -m ruff check apps/api/src/sqllens_api/evidence_connector tests/api/test_evidence_connector_capabilities.py`

Run: `.venv/bin/python -m mypy apps/api/src/sqllens_api/evidence_connector`

- [ ] **Step 5: Commit the capability slice**

```bash
git add apps/api/src/sqllens_api/evidence_connector tests/api/test_evidence_connector_capabilities.py
git commit -m "feat: define evidence source capability degradation"
```

### Task 3: Versioned Query Registry And Fail-Closed Validation

**Files:**
- Create: `apps/api/src/sqllens_api/evidence_connector/queries.py`
- Create: `apps/api/src/sqllens_api/evidence_connector/client.py`
- Create: `tests/api/test_evidence_connector_queries.py`
- Modify: `apps/api/src/sqllens_api/evidence_connector/__init__.py`
- Modify: `tests/fixtures/evidence_connector/tidb-8.5.4.json`
- Modify: `tests/fixtures/evidence_connector/pingkaidb-7.1.8.json`

**Interfaces:**
- Consumes: a supported `pack_id` and fixed query ID.
- Produces: `ReadOnlyQueryClient`, `QueryBudget`, `ServerQuery`, `query_pack(pack_id)`, and `validate_server_query(query)`.

- [ ] **Step 1: Write failing registry and adversarial parser tests**

```python
@pytest.mark.parametrize("unsafe_sql", [
    "DELETE FROM t",
    "CREATE TABLE t(a INT)",
    "ADMIN SHOW DDL JOBS",
    "SET GLOBAL tidb_mem_quota_query = 1",
    "SELECT 1; SELECT 2",
    "EXPLAIN ANALYZE SELECT 1",
])
def test_registry_rejects_unsafe_server_query(unsafe_sql: str) -> None:
    with pytest.raises(UnsafeServerQueryError):
        validate_server_query(server_query(sql=unsafe_sql))

def test_every_builtin_query_is_versioned_validated_and_budgeted() -> None:
    for pack_id in ("tidb-8.5", "pingkaidb-7.1"):
        for query in query_pack(pack_id).values():
            validate_server_query(query)
            assert query.query_revision.startswith(f"{pack_id}/")
            assert query.budget.timeout_ms > 0
            assert query.budget.max_rows > 0
            assert query.budget.kill_switch_required is True
```

- [ ] **Step 2: Run RED**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_queries.py`

Expected: import failure for `queries` and `client`.

- [ ] **Step 3: Implement protocol, budgets, built-in packs, and SQLGlot validation**

```python
class ReadOnlyQueryClient(Protocol):
    async def execute(self, query: ServerQuery, parameters: Mapping[str, object]) -> QueryRows: ...

@dataclass(frozen=True, slots=True)
class QueryBudget:
    timeout_ms: int
    max_rows: int
    max_bytes: int
    concurrency_cost: int
    kill_switch_required: bool = True
```

Registry construction validates every query with strict MySQL parsing. Only one SELECT, SHOW, or DESC statement is admitted in this checkpoint; no arbitrary SQL argument is exposed.

- [ ] **Step 4: Run GREEN, fixture secrecy checks, and static checks**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_queries.py`

Run: `rg -n -i 'password|api[_-]?key|token|select .+ from|insert|update|delete' tests/fixtures/evidence_connector`

Expected: no matches.

Run: `.venv/bin/python -m ruff check apps/api/src/sqllens_api/evidence_connector tests/api/test_evidence_connector_*.py`

Run: `.venv/bin/python -m mypy apps/api/src/sqllens_api/evidence_connector`

- [ ] **Step 5: Run the API regression suite and commit**

Run: `.venv/bin/python -m pytest -q tests/api`

```bash
git add apps/api/src/sqllens_api/evidence_connector tests/api/test_evidence_connector_queries.py tests/fixtures/evidence_connector
git commit -m "feat: validate versioned evidence query packs"
```

### Task 4: Checkpoint Verification

**Files:**
- No product file changes.

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: reviewable commit range and exact verification evidence for #t19.

- [ ] **Step 1: Verify focused behavior**

Run: `.venv/bin/python -m pytest -q tests/api/test_evidence_connector_*.py`

- [ ] **Step 2: Verify repository gates relevant to the connector**

Run: `.venv/bin/python -m ruff check apps/api/src tests/api`

Run: `.venv/bin/python -m mypy apps/api/src`

Run: `.venv/bin/python -m pytest -q tests/api`

- [ ] **Step 3: Review scope and secrets**

Run: `git diff --check beb535d..HEAD`

Run: `git diff --stat beb535d..HEAD`

Run: `git status --short`

- [ ] **Step 4: Create Loop review context and checkpoint #t19**

Run: `loop exec review add '{"path":"/root/sqllens-rd2","head":"HEAD"}'`

The checkpoint reports commits/files, exact commands/results, unknown-version and PROCESS-denial behavior, and the explicit Evidence/v2 projection blocker.
