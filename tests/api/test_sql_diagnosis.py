from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqllens_api.app import create_app
from sqllens_api.bootstrap import issue_bootstrap_code
from sqllens_api.config import Settings
from sqllens_api.provider import ProviderProbeRequest, ProviderProbeResult

OWNER_PASSWORD = "correct-horse-battery-staple"


@dataclass(frozen=True)
class FixedClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


class VerifiedProviderGateway:
    async def probe(self, request: ProviderProbeRequest) -> ProviderProbeResult:
        return ProviderProbeResult(
            status="verified",
            provider="openai-compatible",
            model=request.model or "demo-model",
            latency_ms=8,
        )


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(datetime(2026, 9, 1, 0, 30, tzinfo=UTC))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        cookie_secure=False,
    )


def complete_setup(
    client: TestClient,
    settings: Settings,
    clock: FixedClock,
    *,
    mode: str = "rules",
) -> str:
    code = issue_bootstrap_code(settings, now=clock())
    bootstrap = client.post("/api/v1/setup/bootstrap", json={"code": code})
    assert bootstrap.status_code == 200
    setup_csrf = bootstrap.json()["csrf_token"]

    external = mode == "external"
    policy = client.put(
        "/api/v1/setup/security-policy",
        headers={"X-CSRF-Token": setup_csrf},
        json={
            "external_model_egress": external,
            "allowed_provider_hosts": ["api.example.com"] if external else [],
            "send_sql_text": False,
        },
    )
    assert policy.status_code == 200

    if external:
        probe = client.post(
            "/api/v1/setup/model-probes",
            headers={"X-CSRF-Token": setup_csrf},
            json={
                "mode": "external",
                "base_url": "https://api.example.com/v1",
                "api_key": "probe-only-secret",
                "model": "demo-model",
            },
        )
        assert probe.status_code == 200

    finalized = client.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": setup_csrf},
        json={"mode": mode, "owner_password": OWNER_PASSWORD},
    )
    assert finalized.status_code == 200
    return str(finalized.json()["owner_csrf_token"])


def login(client: TestClient) -> str:
    response = client.post("/api/v1/auth/login", json={"password": OWNER_PASSWORD})
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


def create_case(
    client: TestClient,
    sql: str,
    owner_csrf: str,
    *,
    idempotency_key: str = "diagnosis-1",
) -> tuple[dict[str, object], dict[str, object]]:
    created = client.post(
        "/api/v1/cases/sql",
        headers={
            "Idempotency-Key": idempotency_key,
            "X-CSRF-Token": owner_csrf,
        },
        json={"sql": sql},
    )
    assert created.status_code == 202, created.text
    job = created.json()
    assert job["status"] == "completed"
    fetched = client.get(f"/api/v1/cases/{job['caseId']}")
    assert fetched.status_code == 200
    return job, fetched.json()


def test_sql_input_creates_auditable_persisted_job_and_case(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    owner_csrf = complete_setup(client, settings, clock)
    raw_sql = (
        "SELECT account_id, COUNT(*) FROM payments "
        "WHERE status = 'sensitive-literal' GROUP BY account_id"
    )

    job, case = create_case(client, raw_sql, owner_csrf)

    assert re.fullmatch(r"job_[a-z0-9]{16,64}", str(job["jobId"]))
    assert re.fullmatch(r"case_[a-z0-9]{16,64}", str(job["caseId"]))
    assert job["explanation"] == {"status": "not_requested", "code": None}
    assert case["schemaVersion"] == "diagnosis-case/v1"
    assert case["sourceLayer"] == "sql"
    assert case["workflowState"] == "ready"
    assert case["outcome"] == "pending"
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", str(case["inputFingerprint"]))
    assert case["evidenceCompleteness"] == {
        "score": 0.2,
        "classification": "insufficient",
        "missing": ["tidb_version", "schema", "statistics", "ordinary_plan", "runtime_metrics"],
    }
    assert case["evidence"]
    assert case["hypotheses"]
    assert case["recommendations"]

    evidence_ids = {item["evidenceId"] for item in case["evidence"]}
    for hypothesis in case["hypotheses"]:
        assert set(hypothesis["supportingEvidenceIds"]) <= evidence_ids
        assert hypothesis["confidence"] <= 0.35
    for recommendation in case["recommendations"]:
        assert set(recommendation["evidenceIds"]) <= evidence_ids
        assert recommendation["risk"] in {"low", "medium", "high", "critical"}
        assert recommendation["validation"]
        assert recommendation["rollback"]
        assert recommendation["requiresHumanApproval"] is True

    serialized = str(case).lower()
    assert "sensitive-literal" not in serialized
    assert "payments" not in serialized
    assert "account_id" not in serialized
    assert "create index" not in serialized
    assert "alter table" not in serialized
    assert "will improve" not in serialized
    assert raw_sql.encode() not in settings.database_path.read_bytes()
    assert case["pinnedRevisions"] == {
        "ruleSet": "sql-rules/v1",
        "parser": "sqlglot/mysql@30.17.0",
        "policy": "policy/v1",
        "redaction": "sql-structure/v1",
        "provider": None,
        "model": None,
        "modelArtifact": None,
        "prompt": None,
    }

    fetched_job = client.get(f"/api/v1/jobs/{job['jobId']}")
    assert fetched_job.status_code == 200
    assert fetched_job.json() == job

    restarted = TestClient(create_app(settings=settings, clock=clock))
    login(restarted)
    assert restarted.get(f"/api/v1/jobs/{job['jobId']}").json() == job
    assert restarted.get(f"/api/v1/cases/{job['caseId']}").json() == case


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 'quoted;semicolon' /* comment;semicolon */",
        "WITH recent AS (SELECT id FROM orders WHERE created_at > '2026-01-01') "
        "SELECT COUNT(*) FROM recent",
        "SELECT id FROM orders UNION ALL SELECT id FROM archived_orders",
        "EXPLAIN FORMAT=JSON SELECT * FROM orders WHERE id = 42",
    ],
)
def test_parser_accepts_read_only_mysql_structures_without_splitting_on_text(
    settings: Settings,
    clock: FixedClock,
    sql: str,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    owner_csrf = complete_setup(client, settings, clock)

    job, case = create_case(client, sql, owner_csrf, idempotency_key="read-only-variant")

    assert job["status"] == "completed"
    assert case["workflowState"] == "ready"
    assert sql.encode() not in settings.database_path.read_bytes()


@pytest.mark.parametrize(
    ("sql", "code"),
    [
        ("SELECT FROM", "SQL_INPUT_INVALID"),
        ("SELECT 1; SELECT 2", "SQL_INPUT_MULTIPLE_STATEMENTS"),
        ("UPDATE accounts SET balance = 0", "SQL_INPUT_NOT_READ_ONLY"),
        ("DELETE FROM accounts", "SQL_INPUT_NOT_READ_ONLY"),
        ("CREATE INDEX idx_a ON accounts(a)", "SQL_INPUT_NOT_READ_ONLY"),
        (
            "WITH deleted AS (DELETE FROM accounts RETURNING *) SELECT * FROM deleted",
            "SQL_INPUT_NOT_READ_ONLY",
        ),
        ("SELECT * INTO OUTFILE '/tmp/export' FROM accounts", "SQL_INPUT_NOT_READ_ONLY"),
        ("SELECT * FROM accounts FOR UPDATE", "SQL_INPUT_NOT_READ_ONLY"),
        ("EXPLAIN ANALYZE SELECT * FROM accounts", "SQL_INPUT_NOT_READ_ONLY"),
        ("ADMIN SHOW DDL JOBS", "SQL_INPUT_UNSUPPORTED"),
        ("SHOW TABLES", "SQL_INPUT_UNSUPPORTED"),
    ],
)
def test_invalid_or_unsafe_sql_is_rejected_without_creating_a_job(
    settings: Settings,
    clock: FixedClock,
    sql: str,
    code: str,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    owner_csrf = complete_setup(client, settings, clock)

    response = client.post(
        "/api/v1/cases/sql",
        headers={"Idempotency-Key": "unsafe-case", "X-CSRF-Token": owner_csrf},
        json={"sql": sql},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == code
    assert sql not in response.text


def test_oversized_sql_and_missing_or_invalid_idempotency_keys_are_explicit(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    owner_csrf = complete_setup(client, settings, clock)

    missing_key = client.post(
        "/api/v1/cases/sql",
        headers={"X-CSRF-Token": owner_csrf},
        json={"sql": "SELECT 1"},
    )
    invalid_key = client.post(
        "/api/v1/cases/sql",
        headers={"Idempotency-Key": "x" * 129, "X-CSRF-Token": owner_csrf},
        json={"sql": "SELECT 1"},
    )
    too_large = client.post(
        "/api/v1/cases/sql",
        headers={"Idempotency-Key": "large-case", "X-CSRF-Token": owner_csrf},
        json={"sql": "SELECT '" + ("x" * 65_536) + "'"},
    )

    assert missing_key.status_code == 428
    assert missing_key.json()["error"]["code"] == "IDEMPOTENCY_KEY_REQUIRED"
    assert invalid_key.status_code == 422
    assert invalid_key.json()["error"]["code"] == "IDEMPOTENCY_KEY_INVALID"
    assert too_large.status_code == 413
    assert too_large.json()["error"]["code"] == "SQL_INPUT_TOO_LARGE"


def test_idempotency_reuses_the_original_job_and_rejects_key_conflicts(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    owner_csrf = complete_setup(client, settings, clock)
    headers = {"Idempotency-Key": "stable-key", "X-CSRF-Token": owner_csrf}

    first = client.post("/api/v1/cases/sql", headers=headers, json={"sql": "SELECT * FROM orders"})
    replay = client.post("/api/v1/cases/sql", headers=headers, json={"sql": "SELECT * FROM orders"})
    conflict = client.post(
        "/api/v1/cases/sql",
        headers=headers,
        json={"sql": "SELECT * FROM customers"},
    )

    assert first.status_code == 202
    assert replay.status_code == 202
    assert replay.json() == first.json()
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_KEY_CONFLICT"


def test_external_model_unavailability_degrades_to_deterministic_evidence(
    settings: Settings,
    clock: FixedClock,
) -> None:
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=VerifiedProviderGateway(),
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    settings.credential_key_path.unlink()

    degraded = TestClient(create_app(settings=settings, clock=clock))
    owner_csrf = login(degraded)
    job, case = create_case(degraded, "SELECT * FROM orders", owner_csrf)

    assert job["status"] == "completed"
    assert job["explanation"] == {
        "status": "degraded",
        "code": "MODEL_CREDENTIAL_UNAVAILABLE",
    }
    assert case["workflowState"] == "ready"
    assert case["evidence"]
    assert case["pinnedRevisions"]["provider"] == "openai-compatible"
    assert case["pinnedRevisions"]["model"] == "demo-model"
