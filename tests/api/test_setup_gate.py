from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqllens_api.app import create_app
from sqllens_api.bootstrap import issue_bootstrap_code
from sqllens_api.config import Settings
from sqllens_api.provider import ProviderProbeRequest, ProviderProbeResult
from sqllens_api.setup import SetupStore


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


class FakeProviderGateway:
    def __init__(self, result: ProviderProbeResult | None = None) -> None:
        self.result = result or ProviderProbeResult(
            status="verified",
            provider="openai-compatible",
            model="demo-model",
            latency_ms=12,
        )
        self.requests: list[ProviderProbeRequest] = []

    async def probe(self, request: ProviderProbeRequest) -> ProviderProbeResult:
        self.requests.append(request)
        return self.result


@pytest.fixture
def clock() -> MutableClock:
    return MutableClock(datetime(2026, 8, 31, 15, 30, tzinfo=UTC))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        bootstrap_ttl_seconds=600,
        setup_session_ttl_seconds=1_800,
        cookie_secure=False,
    )


def bootstrap_session(
    client: TestClient,
    settings: Settings,
    clock: MutableClock,
) -> tuple[str, str]:
    code = issue_bootstrap_code(settings, now=clock())
    response = client.post("/api/v1/setup/bootstrap", json={"code": code})

    assert response.status_code == 200
    assert response.json()["state"] == "security_policy_required"
    return code, response.json()["csrf_token"]


def commit_external_policy(client: TestClient, csrf_token: str) -> None:
    response = client.put(
        "/api/v1/setup/security-policy",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "external_model_egress": True,
            "allowed_provider_hosts": ["api.example.com"],
            "send_sql_text": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["state"] == "model_required"


def test_health_is_public_but_diagnosis_api_fails_closed_before_setup(
    settings: Settings,
    clock: MutableClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))

    assert client.get("/healthz").json() == {"status": "ok"}
    response = client.post(
        "/api/v1/cases/sql",
        headers={"Idempotency-Key": "case-1"},
        json={"sql": "select 1"},
    )

    assert response.status_code == 423
    assert response.json()["error"]["version"] == "1"
    assert response.json()["error"]["code"] == "SETUP_REQUIRED"
    assert response.headers["cache-control"] == "no-store"


def test_status_reports_local_model_as_unavailable_without_claiming_gpu_detection(
    settings: Settings,
    clock: MutableClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))

    status = client.get("/api/v1/setup/status").json()

    assert status["state"] == "bootstrap_required"
    assert status["initialized"] is False
    assert status["bootstrap_hash_persisted"] is False
    assert status["local_model"] == {
        "available": False,
        "verified": False,
        "code": "LOCAL_RUNTIME_UNAVAILABLE",
        "message": "No qualified local model runtime is exposed to this service.",
    }


def test_bootstrap_ingest_reads_bounded_stdin_and_is_idempotent(
    settings: Settings,
    clock: MutableClock,
) -> None:
    code = "ABCD-EFGH-JKLM-NPQR"
    replacement = "WXYZ-2345-6789-ABCD"
    environment = {**os.environ, "SQLLENS_DATA_DIR": str(settings.data_dir)}

    first = subprocess.run(
        [sys.executable, "-m", "sqllens_api.main", "bootstrap-ingest"],
        input=f"{code}\n",
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )
    repeated = subprocess.run(
        [sys.executable, "-m", "sqllens_api.main", "bootstrap-ingest"],
        input=f"{replacement}\n",
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert first.returncode == 0
    assert repeated.returncode == 0
    assert code not in first.stdout + first.stderr
    assert replacement not in repeated.stdout + repeated.stderr
    assert "persisted" in first.stdout.lower()
    assert "already persisted" in repeated.stdout.lower()
    assert SetupStore(settings).snapshot().bootstrap_persisted is True
    assert code.encode("utf-8") not in settings.database_path.read_bytes()

    restarted = TestClient(create_app(settings=settings, clock=clock))
    assert restarted.get("/api/v1/setup/status").json()["bootstrap_hash_persisted"] is True
    accepted = restarted.post("/api/v1/setup/bootstrap", json={"code": code})
    assert accepted.status_code == 200
    rejected_replacement = restarted.post(
        "/api/v1/setup/bootstrap", json={"code": replacement}
    )
    assert rejected_replacement.status_code == 401

    replay_after_restart = TestClient(create_app(settings=settings, clock=clock)).post(
        "/api/v1/setup/bootstrap", json={"code": code}
    )
    assert replay_after_restart.status_code == 401
    assert replay_after_restart.json()["error"]["code"] == "BOOTSTRAP_INVALID"


def test_bootstrap_ingest_rejects_oversized_or_invalid_stdin_without_leaking_it(
    settings: Settings,
) -> None:
    oversized = "Z" * 257
    environment = {**os.environ, "SQLLENS_DATA_DIR": str(settings.data_dir)}

    result = subprocess.run(
        [sys.executable, "-m", "sqllens_api.main", "bootstrap-ingest"],
        input=oversized,
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert result.returncode == 64
    assert oversized not in result.stdout + result.stderr
    assert "invalid" in result.stderr.lower()
    assert SetupStore(settings).snapshot().bootstrap_persisted is False


def test_web_runtime_never_reads_the_plaintext_bootstrap_file(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SQLLENS_BOOTSTRAP_CODE_FILE", "/unreadable/bootstrap-code")

    client = TestClient(create_app(settings=settings, clock=clock))

    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/api/v1/setup/status").json()["bootstrap_hash_persisted"] is False


def test_bootstrap_code_is_short_lived_single_use_and_never_returned_or_logged(
    settings: Settings,
    clock: MutableClock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = create_app(settings=settings, clock=clock)
    first_client = TestClient(app)
    code = issue_bootstrap_code(settings, now=clock())

    response = first_client.post("/api/v1/setup/bootstrap", json={"code": code})

    assert response.status_code == 200
    assert code not in response.text
    assert code not in caplog.text
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]

    replay = TestClient(app).post("/api/v1/setup/bootstrap", json={"code": code})
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "BOOTSTRAP_INVALID"
    assert code not in replay.text


def test_expired_bootstrap_code_fails_with_a_generic_error(
    settings: Settings,
    clock: MutableClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    code = issue_bootstrap_code(settings, now=clock())
    clock.advance(seconds=settings.bootstrap_ttl_seconds + 1)

    response = client.post("/api/v1/setup/bootstrap", json={"code": code})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "BOOTSTRAP_INVALID"
    assert "expired" not in response.text.lower()


def test_setup_mutations_require_session_and_csrf(
    settings: Settings,
    clock: MutableClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))

    no_session = client.put(
        "/api/v1/setup/security-policy",
        json={"external_model_egress": False, "allowed_provider_hosts": []},
    )
    assert no_session.status_code == 401
    assert no_session.json()["error"]["code"] == "SETUP_SESSION_REQUIRED"

    _, csrf_token = bootstrap_session(client, settings, clock)
    no_csrf = client.put(
        "/api/v1/setup/security-policy",
        json={"external_model_egress": False, "allowed_provider_hosts": []},
    )
    assert no_csrf.status_code == 403
    assert no_csrf.json()["error"]["code"] == "CSRF_INVALID"

    accepted = client.put(
        "/api/v1/setup/security-policy",
        headers={"X-CSRF-Token": csrf_token},
        json={"external_model_egress": False, "allowed_provider_hosts": []},
    )
    assert accepted.status_code == 200


def test_security_policy_is_committed_before_any_external_probe(
    settings: Settings,
    clock: MutableClock,
) -> None:
    gateway = FakeProviderGateway()
    client = TestClient(create_app(settings=settings, clock=clock, provider_gateway=gateway))
    _, csrf_token = bootstrap_session(client, settings, clock)

    response = client.post(
        "/api/v1/setup/model-probes",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "probe-secret-canary",
            "model": "demo-model",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "POLICY_REQUIRED"
    assert gateway.requests == []
    assert "probe-secret-canary" not in response.text


def test_external_probe_is_allowlisted_and_redacts_credentials(
    settings: Settings,
    clock: MutableClock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    gateway = FakeProviderGateway()
    client = TestClient(create_app(settings=settings, clock=clock, provider_gateway=gateway))
    _, csrf_token = bootstrap_session(client, settings, clock)
    commit_external_policy(client, csrf_token)

    blocked = client.post(
        "/api/v1/setup/model-probes",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "mode": "external",
            "base_url": "https://other.example/v1",
            "api_key": "blocked-secret-canary",
            "model": "demo-model",
        },
    )
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "PROVIDER_HOST_NOT_ALLOWED"
    assert gateway.requests == []

    verified = client.post(
        "/api/v1/setup/model-probes",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "probe-secret-canary",
            "model": "demo-model",
        },
    )
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"
    assert "probe-secret-canary" not in verified.text
    assert "probe-secret-canary" not in caplog.text
    assert len(gateway.requests) == 1


def test_local_probe_fails_closed_and_provider_failure_can_degrade_to_rules(
    settings: Settings,
    clock: MutableClock,
) -> None:
    gateway = FakeProviderGateway(
        ProviderProbeResult(
            status="unavailable",
            provider="openai-compatible",
            model="demo-model",
            code="PROVIDER_UNAVAILABLE",
            message="Provider did not pass the bounded health check.",
        )
    )
    client = TestClient(create_app(settings=settings, clock=clock, provider_gateway=gateway))
    _, csrf_token = bootstrap_session(client, settings, clock)
    commit_external_policy(client, csrf_token)

    local = client.post(
        "/api/v1/setup/model-probes",
        headers={"X-CSRF-Token": csrf_token},
        json={"mode": "local"},
    )
    assert local.status_code == 409
    assert local.json()["error"]["code"] == "LOCAL_MODEL_UNAVAILABLE"

    unavailable = client.post(
        "/api/v1/setup/model-probes",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "probe-secret-canary",
            "model": "demo-model",
        },
    )
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "PROVIDER_UNAVAILABLE"

    fallback = client.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": csrf_token},
        json={"mode": "rules"},
    )
    assert fallback.status_code == 200
    assert fallback.json() == {"state": "ready", "model_mode": "rules"}


def test_successful_external_setup_persists_across_app_restart(
    settings: Settings,
    clock: MutableClock,
) -> None:
    gateway = FakeProviderGateway()
    client = TestClient(create_app(settings=settings, clock=clock, provider_gateway=gateway))
    _, csrf_token = bootstrap_session(client, settings, clock)
    commit_external_policy(client, csrf_token)
    probe = client.post(
        "/api/v1/setup/model-probes",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "probe-secret-canary",
            "model": "demo-model",
        },
    )
    assert probe.status_code == 200

    finalized = client.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": csrf_token},
        json={"mode": "external"},
    )
    assert finalized.status_code == 200

    restarted = TestClient(create_app(settings=settings, clock=clock))
    status = restarted.get("/api/v1/setup/status")
    assert status.json()["state"] == "ready"
    assert status.json()["initialized"] is True
    assert status.json()["model_mode"] == "external"

    post_setup = restarted.post(
        "/api/v1/cases/sql",
        headers={"Idempotency-Key": "case-1"},
        json={"sql": "select 1"},
    )
    assert post_setup.status_code == 501
    assert post_setup.json()["error"]["code"] == "FEATURE_NOT_IMPLEMENTED"


def test_finalized_setup_rejects_every_setup_mutation_without_state_regression(
    settings: Settings,
    clock: MutableClock,
) -> None:
    gateway = FakeProviderGateway()
    client = TestClient(create_app(settings=settings, clock=clock, provider_gateway=gateway))
    _, csrf_token = bootstrap_session(client, settings, clock)
    commit_external_policy(client, csrf_token)
    provider_payload = {
        "mode": "external",
        "base_url": "https://api.example.com/v1",
        "api_key": "probe-secret-canary",
        "model": "demo-model",
    }
    assert (
        client.post(
            "/api/v1/setup/model-probes",
            headers={"X-CSRF-Token": csrf_token},
            json=provider_payload,
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/setup/finalize",
            headers={"X-CSRF-Token": csrf_token},
            json={"mode": "external"},
        ).status_code
        == 200
    )

    responses = [
        client.put(
            "/api/v1/setup/security-policy",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "external_model_egress": True,
                "allowed_provider_hosts": ["api.example.com"],
                "send_sql_text": False,
            },
        ),
        client.post(
            "/api/v1/setup/model-probes",
            headers={"X-CSRF-Token": csrf_token},
            json=provider_payload,
        ),
        client.post(
            "/api/v1/setup/finalize",
            headers={"X-CSRF-Token": csrf_token},
            json={"mode": "external"},
        ),
    ]

    assert [response.status_code for response in responses] == [409, 409, 409]
    assert {
        response.json()["error"]["code"] for response in responses
    } == {"SETUP_ALREADY_FINALIZED"}
    assert len(gateway.requests) == 1
    status = client.get("/api/v1/setup/status").json()
    assert status["state"] == "ready"
    assert status["initialized"] is True
