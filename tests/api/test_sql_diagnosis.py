from __future__ import annotations

import asyncio
import re
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqllens_api import app as app_module
from sqllens_api import diagnosis as diagnosis_module
from sqllens_api.app import create_app
from sqllens_api.bootstrap import issue_bootstrap_code
from sqllens_api.config import Settings
from sqllens_api.diagnosis import (
    DiagnosisStore,
    SqlDiagnosisError,
    build_case,
    parse_sql_structure,
    request_fingerprint,
)
from sqllens_api.provider import (
    ModelExplanationRequest,
    ModelExplanationResult,
    ProviderProbeRequest,
    ProviderProbeResult,
)

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


class ReverseModelExplanationGateway:
    def __init__(self) -> None:
        self.requests: list[ModelExplanationRequest] = []

    async def explain(self, request: ModelExplanationRequest) -> ModelExplanationResult:
        self.requests.append(request)
        hypothesis_ids = [item.hypothesis_id for item in request.payload.hypotheses]
        return ModelExplanationResult(
            status="applied",
            ranked_hypothesis_ids=list(reversed(hypothesis_ids)),
        )


class FixedModelExplanationGateway:
    def __init__(self, result: ModelExplanationResult) -> None:
        self.result = result
        self.requests: list[ModelExplanationRequest] = []

    async def explain(self, request: ModelExplanationRequest) -> ModelExplanationResult:
        self.requests.append(request)
        return self.result


class BlockingModelExplanationGateway:
    def __init__(self) -> None:
        self.calls = 0
        self.active = 0
        self.peak_active = 0
        self.requests: list[ModelExplanationRequest] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()

    async def explain(self, request: ModelExplanationRequest) -> ModelExplanationResult:
        with self._lock:
            self.calls += 1
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            self.requests.append(request)
        self.entered.set()
        try:
            assert await asyncio.to_thread(self.release.wait, 5)
            return ModelExplanationResult(
                status="applied",
                ranked_hypothesis_ids=[
                    item.hypothesis_id for item in request.payload.hypotheses
                ],
            )
        finally:
            with self._lock:
                self.active -= 1


class RaisingModelExplanationGateway:
    def __init__(self) -> None:
        self.calls = 0

    async def explain(self, _request: ModelExplanationRequest) -> ModelExplanationResult:
        self.calls += 1
        raise RuntimeError("provider failure must not escape")


class CancellingModelExplanationGateway:
    async def explain(self, _request: ModelExplanationRequest) -> ModelExplanationResult:
        raise asyncio.CancelledError


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
    assert job["explanation"] == {
        "status": "not_requested",
        "code": None,
        "policy": "rules-only/v1",
        "payloadSchema": None,
        "payloadDigest": None,
    }
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


def test_declared_oversized_request_body_is_rejected_before_sql_parsing(
    settings: Settings,
    clock: FixedClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def parser_must_not_run(_sql: str) -> object:
        raise AssertionError("SQL parser must not run for an oversized request body")

    monkeypatch.setattr(app_module, "parse_sql_structure", parser_must_not_run)
    client = TestClient(create_app(settings=settings, clock=clock))

    response = client.post(
        "/api/v1/cases/sql",
        content=b"x" * 70_000,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "SQL_INPUT_TOO_LARGE"


def test_chunked_oversized_request_body_is_rejected_before_sql_parsing(
    settings: Settings,
    clock: FixedClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def parser_must_not_run(_sql: str) -> object:
        raise AssertionError("SQL parser must not run for an oversized request body")

    monkeypatch.setattr(app_module, "parse_sql_structure", parser_must_not_run)
    app = create_app(settings=settings, clock=clock)
    sent: list[dict[str, object]] = []
    chunks = iter(
        [
            {"type": "http.request", "body": b"x" * 40_000, "more_body": True},
            {"type": "http.request", "body": b"y" * 40_000, "more_body": False},
        ]
    )

    async def receive() -> dict[str, object]:
        return next(chunks)

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    asyncio.run(
        app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/api/v1/cases/sql",
                "raw_path": b"/api/v1/cases/sql",
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
                "client": ("127.0.0.1", 12345),
                "server": ("127.0.0.1", 8080),
                "state": {},
            },
            receive,
            send,
        )
    )

    response_start = next(message for message in sent if message["type"] == "http.response.start")
    assert response_start["status"] == 413
    body = b"".join(
        message.get("body", b"")
        for message in sent
        if message["type"] == "http.response.body"
    )
    assert b"SQL_INPUT_TOO_LARGE" in body


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


def test_concurrent_idempotent_requests_have_one_model_owner_and_no_duplicate_egress(
    settings: Settings,
    clock: FixedClock,
) -> None:
    ranker = BlockingModelExplanationGateway()
    app = create_app(
        settings=settings,
        clock=clock,
        provider_gateway=VerifiedProviderGateway(),
        explanation_gateway=ranker,
    )
    owner = TestClient(app)
    owner_csrf = complete_setup(owner, settings, clock, mode="external")
    follower = TestClient(app)
    follower_csrf = login(follower)
    headers = {
        "Idempotency-Key": "concurrent-external",
        "X-CSRF-Token": owner_csrf,
    }
    follower_headers = {
        "Idempotency-Key": "concurrent-external",
        "X-CSRF-Token": follower_csrf,
    }
    responses: dict[str, Response] = {}

    def post_owner() -> None:
        responses["owner"] = owner.post(
            "/api/v1/cases/sql",
            headers=headers,
            json={"sql": "SELECT * FROM orders"},
        )

    def post_follower() -> None:
        responses["follower"] = follower.post(
            "/api/v1/cases/sql",
            headers=follower_headers,
            json={"sql": "SELECT * FROM orders"},
        )

    owner_request = threading.Thread(target=post_owner)
    follower_request = threading.Thread(target=post_follower)
    owner_request.start()
    assert ranker.entered.wait(timeout=5)
    follower_request.start()
    follower_request.join(timeout=2)
    follower_finished_before_owner = not follower_request.is_alive()
    conflict = None
    if follower_finished_before_owner:
        conflict = follower.post(
            "/api/v1/cases/sql",
            headers=follower_headers,
            json={"sql": "SELECT * FROM customers"},
        )
    ranker.release.set()
    owner_request.join(timeout=5)
    follower_request.join(timeout=5)

    assert follower_finished_before_owner is True
    assert not owner_request.is_alive()
    assert not follower_request.is_alive()
    assert ranker.calls == 1
    owner_response = responses["owner"]
    follower_response = responses["follower"]
    assert owner_response.status_code == 202
    assert follower_response.status_code == 202
    assert owner_response.json()["status"] == "completed"
    assert follower_response.json()["status"] == "in_progress"
    assert follower_response.json()["jobId"] == owner_response.json()["jobId"]
    assert conflict is not None
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_KEY_CONFLICT"
    assert owner.get(f"/api/v1/jobs/{owner_response.json()['jobId']}").json() == (
        owner_response.json()
    )


def test_unique_jobs_are_admitted_one_at_a_time_before_sql_parse_or_model_egress(
    settings: Settings,
    clock: FixedClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ranker = BlockingModelExplanationGateway()
    parser_calls = 0
    parser_lock = threading.Lock()
    original_parser = app_module.parse_sql_structure

    def recording_parser(sql: str) -> object:
        nonlocal parser_calls
        with parser_lock:
            parser_calls += 1
        return original_parser(sql)

    monkeypatch.setattr(app_module, "parse_sql_structure", recording_parser)
    app = create_app(
        settings=settings,
        clock=clock,
        provider_gateway=VerifiedProviderGateway(),
        explanation_gateway=ranker,
    )
    configured = TestClient(app)
    complete_setup(configured, settings, clock, mode="external")
    clients = [TestClient(app) for _ in range(6)]
    csrf_tokens = [login(client) for client in clients]
    start = threading.Barrier(len(clients))
    responses: list[Response] = []
    responses_lock = threading.Lock()

    def submit(index: int) -> None:
        start.wait(timeout=5)
        response = clients[index].post(
            "/api/v1/cases/sql",
            headers={
                "Idempotency-Key": f"unique-job-{index}",
                "X-CSRF-Token": csrf_tokens[index],
            },
            json={"sql": f"SELECT * FROM orders WHERE shard = {index}"},
        )
        with responses_lock:
            responses.append(response)

    workers = [threading.Thread(target=submit, args=(index,)) for index in range(6)]
    for worker in workers:
        worker.start()
    assert ranker.entered.wait(timeout=5)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with responses_lock:
            if len(responses) >= 5:
                break
        if ranker.calls > 1:
            break
        time.sleep(0.01)
    ranker.release.set()
    for worker in workers:
        worker.join(timeout=5)

    assert all(not worker.is_alive() for worker in workers)
    statuses = [response.status_code for response in responses]
    assert statuses.count(202) == 1
    assert statuses.count(429) == 5
    rejected = [response for response in responses if response.status_code == 429]
    assert all(response.headers["Retry-After"] == "1" for response in rejected)
    assert all(
        response.json()["error"]["code"] == "DIAGNOSIS_CAPACITY_EXCEEDED"
        for response in rejected
    )
    assert parser_calls == 1
    assert ranker.calls == 1
    assert ranker.peak_active == 1


def test_admitted_job_pins_provider_and_blocks_rotation_or_delete_until_terminal(
    settings: Settings,
    clock: FixedClock,
) -> None:
    ranker = BlockingModelExplanationGateway()
    app = create_app(
        settings=settings,
        clock=clock,
        provider_gateway=VerifiedProviderGateway(),
        explanation_gateway=ranker,
    )
    configured = TestClient(app)
    complete_setup(configured, settings, clock, mode="external")
    worker_client = TestClient(app)
    worker_csrf = login(worker_client)
    settings_client = TestClient(app)
    settings_csrf = login(settings_client)
    response_holder: list[Response] = []

    def submit() -> None:
        response_holder.append(
            worker_client.post(
                "/api/v1/cases/sql",
                headers={
                    "Idempotency-Key": "provider-provenance",
                    "X-CSRF-Token": worker_csrf,
                },
                json={"sql": "SELECT * FROM orders"},
            )
        )

    worker = threading.Thread(target=submit)
    worker.start()
    assert ranker.entered.wait(timeout=5)

    blocked_rotation = settings_client.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": settings_csrf},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "rotated-provider-secret",
            "model": "rotated-model",
        },
    )
    blocked_delete = settings_client.delete(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": settings_csrf},
    )

    assert blocked_rotation.status_code == 409
    assert blocked_rotation.json()["error"]["code"] == "MODEL_CONFIGURATION_IN_USE"
    assert blocked_delete.status_code == 409
    assert blocked_delete.json()["error"]["code"] == "MODEL_CONFIGURATION_IN_USE"

    ranker.release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    created = response_holder[0]
    assert created.status_code == 202
    case_id = created.json()["caseId"]
    case = settings_client.get(f"/api/v1/cases/{case_id}").json()
    request = ranker.requests[0]
    assert request.provider.model == "demo-model"
    assert request.provider.api_key is not None
    assert request.provider.api_key.get_secret_value() == "probe-only-secret"
    assert case["pinnedRevisions"]["model"] == request.provider.model
    assert case["pinnedRevisions"]["provider"].startswith(
        "openai-compatible@sha256:"
    )

    rotated = settings_client.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": settings_csrf},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "rotated-provider-secret",
            "model": "rotated-model",
        },
    )
    assert rotated.status_code == 200


def test_admission_lock_prevents_rotation_between_provider_snapshot_and_lease(
    settings: Settings,
    clock: FixedClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot_read = threading.Event()
    continue_reservation = threading.Event()
    ranker = BlockingModelExplanationGateway()
    original_snapshot = diagnosis_module._provider_configuration_from_setup

    def block_after_snapshot(row: object) -> object:
        configuration = original_snapshot(row)  # type: ignore[arg-type]
        snapshot_read.set()
        assert continue_reservation.wait(timeout=5)
        return configuration

    monkeypatch.setattr(
        diagnosis_module,
        "_provider_configuration_from_setup",
        block_after_snapshot,
    )
    app = create_app(
        settings=settings,
        clock=clock,
        provider_gateway=VerifiedProviderGateway(),
        explanation_gateway=ranker,
    )
    owner = TestClient(app)
    complete_setup(owner, settings, clock, mode="external")
    owner_csrf = login(owner)
    settings_client = TestClient(app)
    settings_csrf = login(settings_client)
    diagnosis_responses: list[Response] = []
    rotation_responses: list[Response] = []

    diagnosis_thread = threading.Thread(
        target=lambda: diagnosis_responses.append(
            owner.post(
                "/api/v1/cases/sql",
                headers={
                    "Idempotency-Key": "snapshot-lease-race",
                    "X-CSRF-Token": owner_csrf,
                },
                json={"sql": "SELECT * FROM orders"},
            )
        )
    )
    diagnosis_thread.start()
    assert snapshot_read.wait(timeout=5)

    rotation_thread = threading.Thread(
        target=lambda: rotation_responses.append(
            settings_client.put(
                "/api/v1/settings/model",
                headers={"X-CSRF-Token": settings_csrf},
                json={
                    "mode": "external",
                    "base_url": "https://api.example.com/v1",
                    "api_key": "rotated-provider-secret",
                    "model": "rotated-model",
                },
            )
        )
    )
    rotation_thread.start()
    time.sleep(0.05)
    continue_reservation.set()

    assert ranker.entered.wait(timeout=5)
    rotation_thread.join(timeout=5)
    assert not rotation_thread.is_alive()
    assert rotation_responses[0].status_code == 409
    assert rotation_responses[0].json()["error"]["code"] == "MODEL_CONFIGURATION_IN_USE"

    ranker.release.set()
    diagnosis_thread.join(timeout=5)
    assert not diagnosis_thread.is_alive()
    assert diagnosis_responses[0].status_code == 202
    assert ranker.requests[0].provider.model == "demo-model"


def test_model_owner_failure_is_a_replayable_terminal_job_without_second_egress(
    settings: Settings,
    clock: FixedClock,
) -> None:
    ranker = RaisingModelExplanationGateway()
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=VerifiedProviderGateway(),
            explanation_gateway=ranker,
        )
    )
    owner_csrf = complete_setup(client, settings, clock, mode="external")
    headers = {
        "Idempotency-Key": "provider-owner-failure",
        "X-CSRF-Token": owner_csrf,
    }

    failed = client.post(
        "/api/v1/cases/sql",
        headers=headers,
        json={"sql": "SELECT * FROM orders"},
    )
    replay = client.post(
        "/api/v1/cases/sql",
        headers=headers,
        json={"sql": "SELECT * FROM orders"},
    )
    next_job = client.post(
        "/api/v1/cases/sql",
        headers={
            "Idempotency-Key": "provider-owner-failure-next",
            "X-CSRF-Token": owner_csrf,
        },
        json={"sql": "SELECT * FROM customers"},
    )

    assert failed.status_code == 202
    assert failed.json()["status"] == "failed"
    assert failed.json()["error"] == {
        "code": "DIAGNOSIS_PROCESSING_FAILED",
        "retryable": True,
    }
    assert replay.status_code == 202
    assert replay.json() == failed.json()
    assert next_job.status_code == 202
    assert next_job.json()["status"] == "failed"
    assert ranker.calls == 2


def test_cancelled_model_owner_releases_admission_for_the_next_job(
    settings: Settings,
    clock: FixedClock,
) -> None:
    app = create_app(
        settings=settings,
        clock=clock,
        provider_gateway=VerifiedProviderGateway(),
        explanation_gateway=CancellingModelExplanationGateway(),
    )
    client = TestClient(app, raise_server_exceptions=False)
    owner_csrf = complete_setup(client, settings, clock, mode="external")

    client.post(
        "/api/v1/cases/sql",
        headers={
            "Idempotency-Key": "cancelled-owner",
            "X-CSRF-Token": owner_csrf,
        },
        json={"sql": "SELECT * FROM orders"},
    )

    cancelled = app.state.diagnosis_store.resolve_idempotency(
        "cancelled-owner",
        request_fingerprint("SELECT * FROM orders"),
    )
    assert cancelled is not None
    assert cancelled["status"] == "failed"
    assert cancelled["error"] == {"code": "REQUEST_CANCELLED", "retryable": True}
    assert app.state.diagnosis_store.has_active_lease() is False
    next_reservation = app.state.diagnosis_store.reserve_job(
        idempotency_key="after-cancelled-owner",
        fingerprint=request_fingerprint("SELECT * FROM customers"),
        now=clock(),
    )
    assert next_reservation.owner is True
    app.state.diagnosis_store.cancel_job(next_reservation)


def test_invalid_sql_releases_admission_before_returning_a_deterministic_error(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    owner_csrf = complete_setup(client, settings, clock)

    rejected = client.post(
        "/api/v1/cases/sql",
        headers={
            "Idempotency-Key": "invalid-sql-admission",
            "X-CSRF-Token": owner_csrf,
        },
        json={"sql": "DELETE FROM orders"},
    )

    assert rejected.status_code == 422
    assert rejected.json()["error"]["code"] == "SQL_INPUT_NOT_READ_ONLY"
    assert client.app.state.diagnosis_store.has_active_lease() is False
    accepted, _case = create_case(
        client,
        "SELECT * FROM orders",
        owner_csrf,
        idempotency_key="valid-after-rejected-sql",
    )
    assert accepted["status"] == "completed"


def test_concurrent_same_key_invalid_sql_converges_to_a_persisted_failed_job(
    settings: Settings,
    clock: FixedClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocked_rejection(_sql: str) -> object:
        entered.set()
        assert release.wait(timeout=5)
        raise SqlDiagnosisError(
            422,
            "SQL_INPUT_NOT_READ_ONLY",
            "Only read-only SQL is accepted.",
        )

    monkeypatch.setattr(app_module, "parse_sql_structure", blocked_rejection)
    app = create_app(settings=settings, clock=clock)
    owner = TestClient(app)
    owner_csrf = complete_setup(owner, settings, clock)
    follower = TestClient(app)
    follower_csrf = login(follower)
    owner_responses: list[Response] = []

    def submit_owner() -> None:
        owner_responses.append(
            owner.post(
                "/api/v1/cases/sql",
                headers={
                    "Idempotency-Key": "concurrent-invalid",
                    "X-CSRF-Token": owner_csrf,
                },
                json={"sql": "DELETE FROM orders"},
            )
        )

    owner_thread = threading.Thread(target=submit_owner)
    owner_thread.start()
    assert entered.wait(timeout=5)
    follower_response = follower.post(
        "/api/v1/cases/sql",
        headers={
            "Idempotency-Key": "concurrent-invalid",
            "X-CSRF-Token": follower_csrf,
        },
        json={"sql": "DELETE FROM orders"},
    )
    assert follower_response.status_code == 202
    assert follower_response.json()["status"] == "in_progress"

    release.set()
    owner_thread.join(timeout=5)
    assert not owner_thread.is_alive()
    assert owner_responses[0].status_code == 422
    job_id = follower_response.json()["jobId"]
    terminal = follower.get(f"/api/v1/jobs/{job_id}")
    assert terminal.status_code == 200
    assert terminal.json()["status"] == "failed"
    assert terminal.json()["error"] == {
        "code": "SQL_INPUT_NOT_READ_ONLY",
        "retryable": False,
    }


@pytest.mark.parametrize("failure_point", ["parse", "build"])
def test_unexpected_post_admission_failure_releases_capacity(
    settings: Settings,
    clock: FixedClock,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    original_parser = app_module.parse_sql_structure
    original_builder = app_module.build_case
    calls = 0

    if failure_point == "parse":

        def flaky_parser(sql: str) -> object:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("forced parser failure")
            return original_parser(sql)

        monkeypatch.setattr(app_module, "parse_sql_structure", flaky_parser)
    else:

        def flaky_builder(**kwargs: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("forced case builder failure")
            return original_builder(**kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(app_module, "build_case", flaky_builder)

    client = TestClient(
        create_app(settings=settings, clock=clock),
        raise_server_exceptions=False,
    )
    owner_csrf = complete_setup(client, settings, clock)
    failed = client.post(
        "/api/v1/cases/sql",
        headers={
            "Idempotency-Key": f"unexpected-{failure_point}",
            "X-CSRF-Token": owner_csrf,
        },
        json={"sql": "SELECT * FROM orders"},
    )

    assert failed.status_code == 202
    assert failed.json()["status"] == "failed"
    assert failed.json()["error"] == {
        "code": "DIAGNOSIS_PROCESSING_FAILED",
        "retryable": True,
    }
    assert client.app.state.diagnosis_store.has_active_lease() is False
    accepted, _case = create_case(
        client,
        "SELECT * FROM customers",
        owner_csrf,
        idempotency_key=f"after-unexpected-{failure_point}",
    )
    assert accepted["status"] == "completed"


def test_restart_recovers_an_interrupted_job_without_replaying_external_work(
    settings: Settings,
    clock: FixedClock,
) -> None:
    configured = TestClient(create_app(settings=settings, clock=clock))
    complete_setup(configured, settings, clock)
    store = DiagnosisStore(configured.app.state.setup_store.engine)
    sql = "SELECT * FROM orders"
    case_payload = build_case(
        sql=sql,
        structure=parse_sql_structure(sql),
        now=clock(),
        provider=None,
        model=None,
        prompt=None,
    )
    reservation = store.reserve_job(
        idempotency_key="interrupted-job",
        fingerprint=request_fingerprint(sql),
        case_id=str(case_payload["caseId"]),
        now=clock(),
    )
    assert reservation.owner is True
    assert reservation.job["status"] == "in_progress"
    assert store.has_active_lease() is True

    restarted = TestClient(create_app(settings=settings, clock=clock))
    restarted_csrf = login(restarted)
    recovered = restarted.get(f"/api/v1/jobs/{reservation.job['jobId']}")
    replay = restarted.post(
        "/api/v1/cases/sql",
        headers={
            "Idempotency-Key": "interrupted-job",
            "X-CSRF-Token": restarted_csrf,
        },
        json={"sql": sql},
    )

    assert recovered.status_code == 200
    assert recovered.json()["status"] == "failed"
    assert recovered.json()["error"] == {
        "code": "PROCESS_INTERRUPTED",
        "retryable": True,
    }
    assert replay.status_code == 202
    assert replay.json() == recovered.json()
    assert restarted.app.state.diagnosis_store.has_active_lease() is False
    new_attempt, _case = create_case(
        restarted,
        sql,
        restarted_csrf,
        idempotency_key="interrupted-job-retry",
    )
    assert new_attempt["status"] == "completed"


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
        "policy": "model-egress/metadata-only-v1",
        "payloadSchema": "sqllens-model-ranking-request/v1",
        "payloadDigest": job["explanation"]["payloadDigest"],
    }
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", str(job["explanation"]["payloadDigest"]))
    assert case["workflowState"] == "ready"
    assert case["evidence"]
    assert case["pinnedRevisions"]["provider"].startswith(
        "openai-compatible@sha256:"
    )
    assert case["pinnedRevisions"]["model"] == "demo-model"
    assert case["pinnedRevisions"]["prompt"] == "sql-hypothesis-rank/v1"


def test_external_model_ranks_only_redacted_hypotheses_and_idempotency_avoids_replay(
    settings: Settings,
    clock: FixedClock,
) -> None:
    ranker = ReverseModelExplanationGateway()
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=VerifiedProviderGateway(),
            explanation_gateway=ranker,
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=VerifiedProviderGateway(),
            explanation_gateway=ranker,
        )
    )
    owner_csrf = login(client)
    sql = (
        "SELECT customer_id, COUNT(*) FROM secret_orders "
        "JOIN secret_accounts USING (customer_id) "
        "WHERE status = 'top-secret-literal' GROUP BY customer_id"
    )

    first_job, first_case = create_case(
        client,
        sql,
        owner_csrf,
        idempotency_key="external-ranked",
    )
    replay_job, replay_case = create_case(
        client,
        sql,
        owner_csrf,
        idempotency_key="external-ranked",
    )

    assert replay_job == first_job
    assert replay_case == first_case
    assert len(ranker.requests) == 1
    request = ranker.requests[0]
    outbound = request.payload.model_dump_json()
    assert "secret_orders" not in outbound
    assert "secret_accounts" not in outbound
    assert "customer_id" not in outbound
    assert "top-secret-literal" not in outbound
    assert "probe-only-secret" not in outbound
    assert all(item.sensitivity == "metadata" for item in request.payload.evidence)
    original_ids = [item.hypothesis_id for item in request.payload.hypotheses]
    assert [item["hypothesisId"] for item in first_case["hypotheses"]] == list(
        reversed(original_ids)
    )
    assert first_job["explanation"]["status"] == "applied"
    assert first_job["explanation"]["code"] is None
    assert re.fullmatch(
        r"sha256:[a-f0-9]{64}",
        str(first_job["explanation"]["payloadDigest"]),
    )
    assert first_case["pinnedRevisions"]["prompt"] == "sql-hypothesis-rank/v1"


@pytest.mark.parametrize(
    "code",
    [
        "MODEL_TIMEOUT",
        "MODEL_RATE_LIMITED",
        "MODEL_RESPONSE_LIMIT_EXCEEDED",
        "MODEL_OUTPUT_INVALID",
        "MODEL_UNAVAILABLE",
    ],
)
def test_external_model_failures_keep_deterministic_case(
    settings: Settings,
    clock: FixedClock,
    code: str,
) -> None:
    ranker = FixedModelExplanationGateway(
        ModelExplanationResult(status="degraded", code=code)
    )
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=VerifiedProviderGateway(),
            explanation_gateway=ranker,
        )
    )
    owner_csrf = complete_setup(client, settings, clock, mode="external")

    job, case = create_case(
        client,
        "SELECT * FROM orders WHERE state = 'pending'",
        owner_csrf,
        idempotency_key=f"degraded-{code}",
    )

    assert job["status"] == "completed"
    assert job["explanation"]["status"] == "degraded"
    assert job["explanation"]["code"] == code
    assert case["workflowState"] == "ready"
    assert case["evidenceCompleteness"]["classification"] == "insufficient"
    assert all(item["status"] == "candidate" for item in case["hypotheses"])


def test_unknown_model_hypothesis_id_is_rejected_without_changing_case(
    settings: Settings,
    clock: FixedClock,
) -> None:
    ranker = FixedModelExplanationGateway(
        ModelExplanationResult(
            status="applied",
            ranked_hypothesis_ids=["hyp_0000000000000000"],
        )
    )
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=VerifiedProviderGateway(),
            explanation_gateway=ranker,
        )
    )
    owner_csrf = complete_setup(client, settings, clock, mode="external")

    job, case = create_case(client, "SELECT * FROM orders", owner_csrf)

    assert job["explanation"]["status"] == "degraded"
    assert job["explanation"]["code"] == "MODEL_OUTPUT_INVALID"
    assert all(item["status"] == "candidate" for item in case["hypotheses"])
