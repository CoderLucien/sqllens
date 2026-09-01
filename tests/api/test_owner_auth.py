from __future__ import annotations

import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqllens_api.app import create_app
from sqllens_api.bootstrap import issue_bootstrap_code
from sqllens_api.config import Settings
from sqllens_api.provider import ProviderProbeRequest, ProviderProbeResult
from sqllens_api.setup import OWNER_COOKIE_NAME, SETUP_COOKIE_NAME, SetupStore

OWNER_PASSWORD = "correct-horse-battery-staple"


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


class RecordingProviderGateway:
    def __init__(self) -> None:
        self.requests: list[ProviderProbeRequest] = []

    async def probe(self, request: ProviderProbeRequest) -> ProviderProbeResult:
        self.requests.append(request)
        return ProviderProbeResult(
            status="verified",
            provider="openai-compatible",
            model=request.model or "demo-model",
            latency_ms=4,
        )


@pytest.fixture
def clock() -> MutableClock:
    return MutableClock(datetime(2026, 9, 1, 1, 0, tzinfo=UTC))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        owner_session_ttl_seconds=300,
        cookie_secure=False,
    )


def complete_setup(
    client: TestClient,
    settings: Settings,
    clock: MutableClock,
    *,
    mode: str = "rules",
) -> dict[str, object]:
    code = issue_bootstrap_code(settings, now=clock())
    bootstrap = client.post("/api/v1/setup/bootstrap", json={"code": code})
    assert bootstrap.status_code == 200
    csrf = bootstrap.json()["csrf_token"]
    external = mode == "external"
    assert client.put(
        "/api/v1/setup/security-policy",
        headers={"X-CSRF-Token": csrf},
        json={
            "external_model_egress": external,
            "allowed_provider_hosts": ["api.example.com"] if external else [],
            "send_sql_text": False,
        },
    ).status_code == 200
    if external:
        assert client.post(
            "/api/v1/setup/model-probes",
            headers={"X-CSRF-Token": csrf},
            json={
                "mode": "external",
                "base_url": "https://api.example.com/v1",
                "api_key": "initial-provider-secret",
                "model": "demo-model",
            },
        ).status_code == 200
    finalized = client.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": csrf},
        json={"mode": mode, "owner_password": OWNER_PASSWORD},
    )
    assert finalized.status_code == 200
    return finalized.json()


def login(client: TestClient, password: str = OWNER_PASSWORD) -> dict[str, object]:
    response = client.post("/api/v1/auth/login", json={"password": password})
    assert response.status_code == 200
    return response.json()


def test_finalize_creates_owner_and_all_product_apis_default_to_authenticated(
    settings: Settings,
    clock: MutableClock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    owner = TestClient(create_app(settings=settings, clock=clock))
    finalized = complete_setup(owner, settings, clock)
    owner_csrf = finalized["owner_csrf_token"]

    assert finalized["state"] == "ready"
    assert finalized["authenticated"] is True
    assert SETUP_COOKIE_NAME not in owner.cookies
    assert OWNER_PASSWORD not in str(finalized)
    assert OWNER_PASSWORD.encode() not in settings.database_path.read_bytes()
    assert OWNER_PASSWORD not in caplog.text

    anonymous = TestClient(create_app(settings=settings, clock=clock))
    assert anonymous.get("/healthz").status_code == 200
    assert anonymous.get("/api/v1/auth/session").json() == {
        "authenticated": False,
        "csrf_token": None,
    }
    denied = anonymous.post(
        "/api/v1/cases/sql",
        headers={"Idempotency-Key": "anonymous-case"},
        json={"sql": "SELECT 1"},
    )
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "AUTH_REQUIRED"

    missing_csrf = owner.post(
        "/api/v1/cases/sql",
        headers={"Idempotency-Key": "owner-case"},
        json={"sql": "SELECT 1"},
    )
    assert missing_csrf.status_code == 403
    assert missing_csrf.json()["error"]["code"] == "CSRF_INVALID"
    authorized = owner.post(
        "/api/v1/cases/sql",
        headers={"Idempotency-Key": "owner-case", "X-CSRF-Token": str(owner_csrf)},
        json={"sql": "SELECT 1"},
    )
    assert authorized.status_code == 202
    assert authorized.json()["status"] == "completed"


def test_login_is_generic_rate_limited_and_recovers_after_the_window(
    settings: Settings,
    clock: MutableClock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    setup_client = TestClient(create_app(settings=settings, clock=clock))
    complete_setup(setup_client, settings, clock)
    client = TestClient(create_app(settings=settings, clock=clock))
    wrong_password = "wrong-password-canary"

    for _ in range(settings.owner_login_max_attempts):
        response = client.post("/api/v1/auth/login", json={"password": wrong_password})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTH_INVALID"
        assert wrong_password not in response.text
    limited = client.post("/api/v1/auth/login", json={"password": OWNER_PASSWORD})
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "AUTH_TEMPORARILY_UNAVAILABLE"
    assert wrong_password not in caplog.text

    clock.advance(seconds=settings.owner_login_lock_seconds + 1)
    authenticated = client.post("/api/v1/auth/login", json={"password": OWNER_PASSWORD})
    assert authenticated.status_code == 200
    assert authenticated.json()["authenticated"] is True
    cookie = authenticated.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie


def test_concurrent_wrong_passwords_cannot_bypass_the_login_limit(
    settings: Settings,
    clock: MutableClock,
) -> None:
    setup_client = TestClient(create_app(settings=settings, clock=clock))
    complete_setup(setup_client, settings, clock)
    store = SetupStore(settings)

    with ThreadPoolExecutor(max_workers=settings.owner_login_max_attempts) as executor:
        results = list(
            executor.map(
                lambda _index: store.authenticate_owner("wrong-password", clock()),
                range(settings.owner_login_max_attempts),
            )
        )

    assert all(result.status == "invalid" for result in results)
    assert store.snapshot().owner_failed_attempts == settings.owner_login_max_attempts
    assert store.authenticate_owner(OWNER_PASSWORD, clock()).status == "limited"


def test_owner_session_expiry_logout_revocation_and_restart_persistence(
    settings: Settings,
    clock: MutableClock,
) -> None:
    setup_client = TestClient(create_app(settings=settings, clock=clock))
    complete_setup(setup_client, settings, clock)

    client = TestClient(create_app(settings=settings, clock=clock))
    csrf = login(client)["csrf_token"]
    captured_cookie = client.cookies.get(OWNER_COOKIE_NAME)
    assert captured_cookie is not None
    restarted_app = create_app(settings=settings, clock=clock)
    restarted = TestClient(restarted_app)
    restarted.cookies.update(client.cookies)
    assert restarted.get("/api/v1/auth/session").json()["authenticated"] is True

    no_csrf = restarted.post("/api/v1/auth/logout")
    assert no_csrf.status_code == 403
    logged_out = restarted.post(
        "/api/v1/auth/logout", headers={"X-CSRF-Token": str(csrf)}
    )
    assert logged_out.status_code == 200
    assert logged_out.json() == {"authenticated": False}
    assert restarted.get("/api/v1/auth/session").json()["authenticated"] is False

    replayed = TestClient(create_app(settings=settings, clock=clock))
    replayed.cookies.set(OWNER_COOKIE_NAME, captured_cookie, path="/api/v1")
    assert replayed.get("/api/v1/auth/session").json()["authenticated"] is False

    csrf_after_login = login(restarted)["csrf_token"]
    assert csrf_after_login
    clock.advance(seconds=settings.owner_session_ttl_seconds + 1)
    assert restarted.get("/api/v1/auth/session").json()["authenticated"] is False


def test_external_provider_credential_is_encrypted_rotatable_and_restart_safe(
    settings: Settings,
    clock: MutableClock,
) -> None:
    initial_gateway = RecordingProviderGateway()
    setup_client = TestClient(
        create_app(settings=settings, clock=clock, provider_gateway=initial_gateway)
    )
    complete_setup(setup_client, settings, clock, mode="external")

    database = settings.database_path.read_bytes()
    assert b"initial-provider-secret" not in database
    assert settings.credential_key_path.is_file()
    assert stat.S_IMODE(settings.credential_key_path.stat().st_mode) == 0o600
    key_material = settings.credential_key_path.read_bytes()
    assert key_material not in database

    restarted_gateway = RecordingProviderGateway()
    restarted = TestClient(
        create_app(settings=settings, clock=clock, provider_gateway=restarted_gateway)
    )
    csrf = login(restarted)["csrf_token"]
    verify = restarted.post(
        "/api/v1/settings/model/verify",
        headers={"X-CSRF-Token": str(csrf)},
    )
    assert verify.status_code == 200
    assert restarted_gateway.requests[-1].api_key is not None
    assert (
        restarted_gateway.requests[-1].api_key.get_secret_value()
        == "initial-provider-secret"
    )

    rotated = restarted.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": str(csrf)},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "rotated-provider-secret",
            "model": "demo-model",
        },
    )
    assert rotated.status_code == 200
    assert b"rotated-provider-secret" not in settings.database_path.read_bytes()
    assert not settings.credential_key_path.exists()
    assert len(list(settings.credential_key_path.parent.glob("credential.file-v1-*.key"))) == 1

    second_restart_gateway = RecordingProviderGateway()
    second_restart = TestClient(
        create_app(settings=settings, clock=clock, provider_gateway=second_restart_gateway)
    )
    second_csrf = login(second_restart)["csrf_token"]
    assert second_restart.post(
        "/api/v1/settings/model/verify",
        headers={"X-CSRF-Token": str(second_csrf)},
    ).status_code == 200
    assert second_restart_gateway.requests[-1].api_key is not None
    assert (
        second_restart_gateway.requests[-1].api_key.get_secret_value()
        == "rotated-provider-secret"
    )

    deleted = second_restart.delete(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": str(second_csrf)},
    )
    assert deleted.status_code == 200
    assert deleted.json() == {"model_mode": "rules", "credential_available": False}
    assert list(settings.credential_key_path.parent.glob("credential*.key")) == []
    deleted_snapshot = SetupStore(settings).snapshot()
    assert deleted_snapshot.provider_status is None
    assert deleted_snapshot.provider_base_url is None
    assert deleted_snapshot.provider_model is None
    assert deleted_snapshot.provider_credential is None


def test_rules_finalize_discards_a_previously_verified_external_credential(
    settings: Settings,
    clock: MutableClock,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    code = issue_bootstrap_code(settings, now=clock())
    bootstrap = client.post("/api/v1/setup/bootstrap", json={"code": code})
    csrf = bootstrap.json()["csrf_token"]
    assert client.put(
        "/api/v1/setup/security-policy",
        headers={"X-CSRF-Token": csrf},
        json={
            "external_model_egress": True,
            "allowed_provider_hosts": ["api.example.com"],
            "send_sql_text": False,
        },
    ).status_code == 200
    assert client.post(
        "/api/v1/setup/model-probes",
        headers={"X-CSRF-Token": csrf},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "discarded-provider-secret",
            "model": "demo-model",
        },
    ).status_code == 200
    assert settings.credential_key_path.exists()

    finalized = client.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": csrf},
        json={"mode": "rules", "owner_password": OWNER_PASSWORD},
    )

    assert finalized.status_code == 200
    snapshot = SetupStore(settings).snapshot()
    assert snapshot.model_mode == "rules"
    assert snapshot.provider_status is None
    assert snapshot.provider_base_url is None
    assert snapshot.provider_model is None
    assert snapshot.provider_credential is None
    assert list(settings.credential_key_path.parent.glob("credential*.key")) == []


@pytest.mark.parametrize("damage", ["missing", "invalid-length"])
def test_authenticated_rotation_recovers_an_unreadable_credential_key(
    settings: Settings,
    clock: MutableClock,
    damage: str,
) -> None:
    setup_client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(setup_client, settings, clock, mode="external")
    if damage == "missing":
        settings.credential_key_path.unlink()
    else:
        settings.credential_key_path.write_bytes(b"corrupt")
        settings.credential_key_path.chmod(0o600)

    gateway = RecordingProviderGateway()
    recovery = TestClient(
        create_app(settings=settings, clock=clock, provider_gateway=gateway)
    )
    assert recovery.get("/api/v1/setup/status").json()["state"] == (
        "model_recovery_required"
    )
    csrf = login(recovery)["csrf_token"]
    rotated = recovery.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": str(csrf)},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "recovered-provider-secret",
            "model": "demo-model",
        },
    )
    assert rotated.status_code == 200
    assert not settings.credential_key_path.exists()

    restarted_gateway = RecordingProviderGateway()
    restarted = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=restarted_gateway,
        )
    )
    restarted_csrf = login(restarted)["csrf_token"]
    assert restarted.post(
        "/api/v1/settings/model/verify",
        headers={"X-CSRF-Token": str(restarted_csrf)},
    ).status_code == 200
    assert restarted_gateway.requests[-1].api_key is not None
    assert (
        restarted_gateway.requests[-1].api_key.get_secret_value()
        == "recovered-provider-secret"
    )
