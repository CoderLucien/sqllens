from __future__ import annotations

import asyncio
import io
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqllens_api import app as app_module
from sqllens_api import setup as setup_state_module
from sqllens_api.app import create_app
from sqllens_api.bootstrap import issue_bootstrap_code
from sqllens_api.config import Settings
from sqllens_api.credentials import CredentialUnavailableError, CredentialVault
from sqllens_api.main import ingest_bootstrap_stdin
from sqllens_api.provider import ProviderProbeRequest, ProviderProbeResult
from sqllens_api.setup import SETUP_COOKIE_NAME, SetupStore


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


def probe_external_credential(
    client: TestClient,
    csrf_token: str,
    *,
    api_key: str = "probe-secret-canary",
) -> None:
    response = client.post(
        "/api/v1/setup/model-probes",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": api_key,
            "model": "demo-model",
        },
    )
    assert response.status_code == 200


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


def test_global_api_body_budget_rejects_oversized_login_and_setup_before_validation(
    settings: Settings,
    clock: MutableClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    oversized = b"x" * 140_000

    login = client.post(
        "/api/v1/auth/login",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )
    setup = client.post(
        "/api/v1/setup/bootstrap",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )

    assert login.status_code == 413
    assert setup.status_code == 413
    assert login.json()["error"]["code"] == "REQUEST_BODY_TOO_LARGE"
    assert setup.json()["error"]["code"] == "REQUEST_BODY_TOO_LARGE"
    assert SetupStore(settings).snapshot().bootstrap_persisted is False


def test_global_api_body_budget_rejects_unbounded_empty_chunks(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "_REQUEST_BODY_MESSAGE_LIMIT", 3)
    app = create_app(settings=settings, clock=clock)
    sent: list[dict[str, object]] = []
    chunks = iter(
        [
            {"type": "http.request", "body": b"", "more_body": True},
            {"type": "http.request", "body": b"", "more_body": True},
            {"type": "http.request", "body": b"", "more_body": True},
        ]
    )

    async def receive() -> dict[str, object]:
        return next(chunks)

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    asyncio.run(
        app(
            _api_scope("/api/v1/auth/login"),
            receive,
            send,
        )
    )

    start = next(message for message in sent if message["type"] == "http.response.start")
    assert start["status"] == 413


def test_global_api_body_budget_rejects_slow_chunk_streams(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app_module, "_REQUEST_BODY_READ_TIMEOUT_SECONDS", 0.01)
    app = create_app(settings=settings, clock=clock)
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        await asyncio.sleep(0.05)
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    asyncio.run(app(_api_scope("/api/v1/setup/bootstrap"), receive, send))

    start = next(message for message in sent if message["type"] == "http.response.start")
    assert start["status"] == 413


def _api_scope(path: str) -> dict[str, object]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8080),
        "state": {},
    }


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


def test_concurrent_invalid_bootstrap_codes_atomically_reach_attempt_limit(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SetupStore(settings)
    valid_code = store.issue_bootstrap_code(clock(), code="ABCD-EFGH-JKLM-NPQR")
    invalid_code = "WRONG-CODE-2345"
    request_count = settings.bootstrap_max_attempts * 2
    hashing_barrier = threading.Barrier(request_count)
    original_derive = setup_state_module._derive_code_hash

    def synchronized_derive(code: str, salt: bytes) -> str:
        if setup_state_module.normalize_bootstrap_code(code) == (
            setup_state_module.normalize_bootstrap_code(invalid_code)
        ):
            hashing_barrier.wait(timeout=5)
        return original_derive(code, salt)

    monkeypatch.setattr(setup_state_module, "_derive_code_hash", synchronized_derive)
    results: list[int | None] = []
    requests = [
        threading.Thread(
            target=lambda: results.append(store.consume_bootstrap_code(invalid_code, clock()))
        )
        for _ in range(request_count)
    ]

    for request in requests:
        request.start()
    for request in requests:
        request.join(timeout=10)

    assert all(not request.is_alive() for request in requests)
    assert results == [None] * request_count
    assert store.snapshot().bootstrap_failed_attempts == settings.bootstrap_max_attempts
    assert store.consume_bootstrap_code(valid_code, clock()) is None


def run_bootstrap_command(
    settings: Settings,
    command: str,
    code: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sqllens_api.main", command],
        input=f"{code}\n",
        capture_output=True,
        check=False,
        env={**os.environ, "SQLLENS_DATA_DIR": str(settings.data_dir)},
        text=True,
    )


def test_local_reissue_recovers_expired_or_attempt_limited_codes(
    settings: Settings,
    clock: MutableClock,
) -> None:
    old_code = issue_bootstrap_code(settings, now=clock())
    clock.advance(seconds=settings.bootstrap_ttl_seconds + 1)
    expired_client = TestClient(create_app(settings=settings, clock=clock))
    assert expired_client.post(
        "/api/v1/setup/bootstrap", json={"code": old_code}
    ).status_code == 401
    assert expired_client.get("/api/v1/setup/status").json()["recovery"] == {
        "required": True,
        "action": "bootstrap-reissue",
        "reason": "bootstrap_expired",
    }

    replacement = "WXYZ-2345-6789-ABCD"
    reissued = run_bootstrap_command(settings, "bootstrap-reissue", replacement)
    assert reissued.returncode == 0
    assert replacement not in reissued.stdout + reissued.stderr
    recovered = TestClient(create_app(settings=settings, clock=clock))
    assert recovered.post(
        "/api/v1/setup/bootstrap", json={"code": old_code}
    ).status_code == 401
    assert recovered.post(
        "/api/v1/setup/bootstrap", json={"code": replacement}
    ).status_code == 200

    locked_settings = Settings(data_dir=settings.data_dir.parent / "locked")
    locked_code = issue_bootstrap_code(locked_settings, now=clock())
    locked_client = TestClient(create_app(settings=locked_settings, clock=clock))
    for _ in range(locked_settings.bootstrap_max_attempts):
        assert locked_client.post(
            "/api/v1/setup/bootstrap", json={"code": "WRONG-CODE-2345"}
        ).status_code == 401
    status = locked_client.get("/api/v1/setup/status").json()
    assert status["recovery"]["reason"] == "attempt_limit_reached"
    assert run_bootstrap_command(
        locked_settings, "bootstrap-reissue", replacement
    ).returncode == 0
    after_reissue = TestClient(create_app(settings=locked_settings, clock=clock))
    assert after_reissue.post(
        "/api/v1/setup/bootstrap", json={"code": locked_code}
    ).status_code == 401
    assert after_reissue.post(
        "/api/v1/setup/bootstrap", json={"code": replacement}
    ).status_code == 200


def test_reissue_after_cookie_loss_resets_partial_setup_and_invalidates_old_session(
    settings: Settings,
    clock: MutableClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    old_code, old_csrf = bootstrap_session(client, settings, clock)
    sessionless = TestClient(create_app(settings=settings, clock=clock))
    assert sessionless.get("/api/v1/setup/status").json()["recovery"] == {
        "required": True,
        "action": "bootstrap-reissue",
        "reason": "setup_session_missing",
    }

    replacement = "WXYZ-2345-6789-ABCD"
    assert run_bootstrap_command(settings, "bootstrap-reissue", replacement).returncode == 0
    stale_session = client.put(
        "/api/v1/setup/security-policy",
        headers={"X-CSRF-Token": old_csrf},
        json={"external_model_egress": False, "allowed_provider_hosts": []},
    )
    assert stale_session.status_code == 401
    assert stale_session.json()["error"]["code"] == "SETUP_SESSION_REQUIRED"

    restarted = TestClient(create_app(settings=settings, clock=clock))
    assert restarted.post(
        "/api/v1/setup/bootstrap", json={"code": old_code}
    ).status_code == 401
    assert restarted.post(
        "/api/v1/setup/bootstrap", json={"code": replacement}
    ).status_code == 200


def test_reissue_wins_against_an_old_code_request_already_computing_its_hash(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SetupStore(settings)
    old_code = store.issue_bootstrap_code(clock(), code="ABCD-EFGH-JKLM-NPQR")
    old_epoch = store.snapshot().setup_epoch
    replacement = "WXYZ-2345-6789-ABCD"
    hashing_started = threading.Event()
    allow_old_hash_to_finish = threading.Event()
    original_derive = setup_state_module._derive_code_hash

    def controlled_derive(code: str, salt: bytes) -> str:
        if setup_state_module.normalize_bootstrap_code(code) == (
            setup_state_module.normalize_bootstrap_code(old_code)
        ):
            hashing_started.set()
            assert allow_old_hash_to_finish.wait(timeout=5)
        return original_derive(code, salt)

    monkeypatch.setattr(setup_state_module, "_derive_code_hash", controlled_derive)
    consumed_epochs: list[int | None] = []
    old_request = threading.Thread(
        target=lambda: consumed_epochs.append(store.consume_bootstrap_code(old_code, clock()))
    )
    old_request.start()
    assert hashing_started.wait(timeout=5)

    assert store.reissue_bootstrap_code(replacement, clock()) is True
    allow_old_hash_to_finish.set()
    old_request.join(timeout=5)

    assert not old_request.is_alive()
    assert consumed_epochs == [None]
    assert store.consume_bootstrap_code(replacement, clock()) == old_epoch + 1


def test_reissue_fails_closed_after_setup_is_finalized(
    settings: Settings,
    clock: MutableClock,
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock))
    _, csrf = bootstrap_session(client, settings, clock)
    assert client.put(
        "/api/v1/setup/security-policy",
        headers={"X-CSRF-Token": csrf},
        json={"external_model_egress": False, "allowed_provider_hosts": []},
    ).status_code == 200
    assert client.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": csrf},
        json={"mode": "rules", "owner_password": "owner-password-123"},
    ).status_code == 200

    replacement = "WXYZ-2345-6789-ABCD"
    refused = run_bootstrap_command(settings, "bootstrap-reissue", replacement)

    assert refused.returncode == 73
    assert replacement not in refused.stdout + refused.stderr
    assert TestClient(create_app(settings=settings, clock=clock)).get(
        "/api/v1/setup/status"
    ).json()["state"] == "ready"


def test_external_setup_reissue_retires_old_key_and_creates_a_new_version(
    settings: Settings,
    clock: MutableClock,
) -> None:
    gateway = FakeProviderGateway()
    client = TestClient(create_app(settings=settings, clock=clock, provider_gateway=gateway))
    _, csrf = bootstrap_session(client, settings, clock)
    commit_external_policy(client, csrf)
    probe_external_credential(client, csrf, api_key="old-provider-secret")
    old_credential = SetupStore(settings).snapshot().provider_credential
    assert old_credential is not None
    vault = CredentialVault(settings.credential_key_path)
    assert vault.decrypt(old_credential) == "old-provider-secret"

    replacement = "WXYZ-2345-6789-ABCD"
    assert ingest_bootstrap_stdin(
        settings,
        io.BytesIO(f"{replacement}\n".encode()),
        now=clock(),
        replace_existing=True,
    ) is True

    recovered = SetupStore(settings).snapshot()
    assert recovered.stage == "bootstrap_required"
    assert recovered.provider_credential is None
    assert recovered.credential_retirement_pending_version is None
    assert list(settings.credential_key_path.parent.glob("credential*.key")) == []
    with pytest.raises(CredentialUnavailableError):
        vault.decrypt(old_credential)

    restarted = TestClient(
        create_app(settings=settings, clock=clock, provider_gateway=FakeProviderGateway())
    )
    bootstrap = restarted.post("/api/v1/setup/bootstrap", json={"code": replacement})
    assert bootstrap.status_code == 200
    new_csrf = bootstrap.json()["csrf_token"]
    commit_external_policy(restarted, new_csrf)
    probe_external_credential(restarted, new_csrf, api_key="new-provider-secret")
    new_credential = SetupStore(settings).snapshot().provider_credential
    assert new_credential is not None
    assert new_credential.key_version != old_credential.key_version
    finalized = restarted.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": new_csrf},
        json={"mode": "external", "owner_password": "owner-password-123"},
    )
    assert finalized.status_code == 200
    assert CredentialVault(settings.credential_key_path).decrypt(new_credential) == (
        "new-provider-secret"
    )


def test_reissue_retirement_failure_is_observable_and_retryable(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=FakeProviderGateway(),
        )
    )
    _, csrf = bootstrap_session(client, settings, clock)
    commit_external_policy(client, csrf)
    probe_external_credential(client, csrf, api_key="retirement-failure-secret")
    old_credential = SetupStore(settings).snapshot().provider_credential
    assert old_credential is not None
    replacement = "WXYZ-2345-6789-ABCD"
    original_retire = CredentialVault.retire_version

    def fail_retirement(_vault: CredentialVault, _version: str) -> None:
        raise CredentialUnavailableError("forced unlink failure")

    monkeypatch.setattr(CredentialVault, "retire_version", fail_retirement)
    with pytest.raises(CredentialUnavailableError):
        ingest_bootstrap_stdin(
            settings,
            io.BytesIO(f"{replacement}\n".encode()),
            now=clock(),
            replace_existing=True,
        )

    pending = SetupStore(settings).snapshot()
    assert pending.provider_credential is None
    assert pending.credential_retirement_pending_version == old_credential.key_version
    assert CredentialVault(settings.credential_key_path).decrypt(old_credential) == (
        "retirement-failure-secret"
    )

    monkeypatch.setattr(CredentialVault, "retire_version", original_retire)
    assert ingest_bootstrap_stdin(
        settings,
        io.BytesIO(f"{replacement}\n".encode()),
        now=clock(),
        replace_existing=True,
    ) is True
    assert SetupStore(settings).snapshot().credential_retirement_pending_version is None
    with pytest.raises(CredentialUnavailableError):
        CredentialVault(settings.credential_key_path).decrypt(old_credential)


def test_reissue_resumes_after_key_deletion_but_before_phase_two_commit(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=FakeProviderGateway(),
        )
    )
    _, csrf = bootstrap_session(client, settings, clock)
    commit_external_policy(client, csrf)
    probe_external_credential(client, csrf, api_key="phase-two-secret")
    old_credential = SetupStore(settings).snapshot().provider_credential
    assert old_credential is not None
    replacement = "WXYZ-2345-6789-ABCD"
    original_complete = SetupStore.complete_credential_retirement

    def fail_phase_two(
        _store: SetupStore,
        _expected_version: str,
        _now: datetime,
    ) -> bool:
        return False

    monkeypatch.setattr(SetupStore, "complete_credential_retirement", fail_phase_two)
    with pytest.raises(RuntimeError, match="retirement"):
        ingest_bootstrap_stdin(
            settings,
            io.BytesIO(f"{replacement}\n".encode()),
            now=clock(),
            replace_existing=True,
        )

    interrupted = SetupStore(settings).snapshot()
    assert interrupted.provider_credential is None
    assert interrupted.credential_retirement_pending_version == old_credential.key_version
    with pytest.raises(CredentialUnavailableError):
        CredentialVault(settings.credential_key_path).decrypt(old_credential)

    monkeypatch.setattr(SetupStore, "complete_credential_retirement", original_complete)
    assert ingest_bootstrap_stdin(
        settings,
        io.BytesIO(f"{replacement}\n".encode()),
        now=clock(),
        replace_existing=True,
    ) is True
    converged = SetupStore(settings).snapshot()
    assert converged.stage == "bootstrap_required"
    assert converged.credential_retirement_pending_version is None


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
    assert client.get("/api/v1/setup/status").json()["external_model"] == {
        "credential_available": False,
        "egress_enabled": False,
    }


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
        json={"mode": "rules", "owner_password": "owner-password-123"},
    )
    assert fallback.status_code == 200
    assert fallback.json()["state"] == "ready"
    assert fallback.json()["model_mode"] == "rules"
    assert fallback.json()["authenticated"] is True


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
        json={"mode": "external", "owner_password": "owner-password-123"},
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
    assert post_setup.status_code == 401
    assert post_setup.json()["error"]["code"] == "AUTH_REQUIRED"


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
    captured_setup_cookie = client.cookies.get(SETUP_COOKIE_NAME)
    assert captured_setup_cookie is not None
    assert (
        client.post(
            "/api/v1/setup/finalize",
            headers={"X-CSRF-Token": csrf_token},
            json={"mode": "external", "owner_password": "owner-password-123"},
        ).status_code
        == 200
    )
    assert SETUP_COOKIE_NAME not in client.cookies
    client.cookies.set(
        SETUP_COOKIE_NAME,
        captured_setup_cookie,
        path="/api/v1/setup",
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
            json={"mode": "external", "owner_password": "owner-password-123"},
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
