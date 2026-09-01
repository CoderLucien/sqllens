from __future__ import annotations

import asyncio
import os
import stat
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event

import pytest
import sqllens_api.credentials as credentials_module
from fastapi.testclient import TestClient
from httpx import Response
from sqllens_api.app import create_app
from sqllens_api.bootstrap import issue_bootstrap_code
from sqllens_api.config import Settings
from sqllens_api.credentials import (
    CredentialRotationPlan,
    CredentialUnavailableError,
    CredentialVault,
    EncryptedCredential,
)
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


@pytest.mark.parametrize("unsafe_kind", ["symlink", "fifo", "mode"])
def test_unsafe_active_key_prevents_startup_without_touching_it(
    settings: Settings,
    clock: MutableClock,
    unsafe_kind: str,
) -> None:
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    active_path = settings.credential_key_path
    if unsafe_kind == "symlink":
        outside = settings.data_dir / "outside.key"
        outside.write_bytes(b"x" * 32)
        outside.chmod(0o600)
        active_path.unlink()
        active_path.symlink_to(outside)
    elif unsafe_kind == "fifo":
        active_path.unlink()
        os.mkfifo(active_path, 0o600)
    else:
        active_path.chmod(0o644)

    with pytest.raises(CredentialUnavailableError):
        create_app(settings=settings, clock=clock)

    assert active_path.exists() or active_path.is_symlink()
    metadata = active_path.lstat()
    if unsafe_kind == "symlink":
        assert stat.S_ISLNK(metadata.st_mode)
    elif unsafe_kind == "fifo":
        assert stat.S_ISFIFO(metadata.st_mode)
    else:
        assert stat.S_IMODE(metadata.st_mode) == 0o644


def test_rotation_retirement_failure_is_observable_and_resumes_before_model_use(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(client, settings, clock, mode="external")
    old_credential = SetupStore(settings).snapshot().provider_credential
    assert old_credential is not None
    csrf = login(client)["csrf_token"]
    original_retire = CredentialVault.retire_version

    def fail_retirement(_vault: CredentialVault, _version: str) -> None:
        raise CredentialUnavailableError("forced unlink failure")

    monkeypatch.setattr(CredentialVault, "retire_version", fail_retirement)
    failed = client.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": str(csrf)},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "replacement-provider-secret",
            "model": "demo-model",
        },
    )

    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "CREDENTIAL_RETIREMENT_PENDING"
    pending = SetupStore(settings).snapshot()
    assert pending.provider_credential is not None
    assert pending.provider_credential != old_credential
    assert pending.credential_retirement_pending_version == old_credential.key_version
    assert CredentialVault(settings.credential_key_path).decrypt(old_credential) == (
        "initial-provider-secret"
    )

    monkeypatch.setattr(CredentialVault, "retire_version", original_retire)
    verified = client.post(
        "/api/v1/settings/model/verify",
        headers={"X-CSRF-Token": str(csrf)},
    )
    assert verified.status_code == 200
    assert SetupStore(settings).snapshot().credential_retirement_pending_version is None
    with pytest.raises(CredentialUnavailableError):
        CredentialVault(settings.credential_key_path).decrypt(old_credential)


def test_delete_retirement_failure_detaches_active_credential_and_is_retryable(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(client, settings, clock, mode="external")
    old_credential = SetupStore(settings).snapshot().provider_credential
    assert old_credential is not None
    csrf = login(client)["csrf_token"]
    original_retire = CredentialVault.retire_version

    def fail_retirement(_vault: CredentialVault, _version: str) -> None:
        raise CredentialUnavailableError("forced unlink failure")

    monkeypatch.setattr(CredentialVault, "retire_version", fail_retirement)
    failed = client.delete(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": str(csrf)},
    )

    assert failed.status_code == 503
    pending = SetupStore(settings).snapshot()
    assert pending.provider_credential is None
    assert pending.model_mode == "rules"
    assert pending.credential_retirement_pending_version == old_credential.key_version

    monkeypatch.setattr(CredentialVault, "retire_version", original_retire)
    retried = client.delete(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": str(csrf)},
    )
    assert retried.status_code == 200
    assert SetupStore(settings).snapshot().credential_retirement_pending_version is None
    with pytest.raises(CredentialUnavailableError):
        CredentialVault(settings.credential_key_path).decrypt(old_credential)


def test_rules_finalize_retirement_failure_resumes_before_owner_login(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
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
            "api_key": "rules-retirement-secret",
            "model": "demo-model",
        },
    ).status_code == 200
    old_credential = SetupStore(settings).snapshot().provider_credential
    assert old_credential is not None
    original_retire = CredentialVault.retire_version

    def fail_retirement(_vault: CredentialVault, _version: str) -> None:
        raise CredentialUnavailableError("forced unlink failure")

    monkeypatch.setattr(CredentialVault, "retire_version", fail_retirement)
    failed = client.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": csrf},
        json={"mode": "rules", "owner_password": OWNER_PASSWORD},
    )

    assert failed.status_code == 503
    pending = SetupStore(settings).snapshot()
    assert pending.initialized is True
    assert pending.model_mode == "rules"
    assert pending.provider_credential is None
    assert pending.credential_retirement_pending_version == old_credential.key_version

    monkeypatch.setattr(CredentialVault, "retire_version", original_retire)
    recovered = TestClient(create_app(settings=settings, clock=clock))
    assert login(recovered)["authenticated"] is True
    assert SetupStore(settings).snapshot().credential_retirement_pending_version is None
    with pytest.raises(CredentialUnavailableError):
        CredentialVault(settings.credential_key_path).decrypt(old_credential)


def test_failed_staged_commit_persists_cleanup_until_restart_recovers(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(client, settings, clock, mode="external")
    active = SetupStore(settings).snapshot().provider_credential
    assert active is not None
    csrf = login(client)["csrf_token"]
    original_commit = SetupStore.commit_staged_rotation
    original_retire_staged = CredentialVault.retire_staged_version

    monkeypatch.setattr(SetupStore, "commit_staged_rotation", lambda *_args, **_kwargs: False)

    def fail_staged_retirement(_vault: CredentialVault, _version: str) -> None:
        raise CredentialUnavailableError("forced staged unlink failure")

    monkeypatch.setattr(
        CredentialVault,
        "retire_staged_version",
        fail_staged_retirement,
    )
    failed = client.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": str(csrf)},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "orphaned-provider-secret",
            "model": "demo-model",
        },
    )

    assert failed.status_code == 503
    pending = SetupStore(settings).snapshot()
    assert pending.provider_credential == active
    assert pending.credential_retirement_operation == "staged_rotation"
    assert pending.credential_retirement_pending_version is not None
    assert pending.credential_retirement_token is not None
    assert len(list(settings.credential_key_path.parent.glob("credential*.key"))) == 2

    monkeypatch.setattr(SetupStore, "commit_staged_rotation", original_commit)
    monkeypatch.setattr(
        CredentialVault,
        "retire_staged_version",
        original_retire_staged,
    )
    create_app(settings=settings, clock=clock)
    converged = SetupStore(settings).snapshot()
    assert converged.provider_credential == active
    assert converged.credential_retirement_pending_version is None
    assert list(settings.credential_key_path.parent.glob("credential*.key")) == [
        settings.credential_key_path
    ]


def test_commit_exception_after_durable_switch_never_deletes_new_active_key(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(client, settings, clock, mode="external")
    before = SetupStore(settings).snapshot()
    assert before.provider_credential is not None
    csrf = str(login(client)["csrf_token"])
    original_commit = SetupStore.commit_staged_rotation

    def commit_then_raise(
        store: SetupStore,
        *args: object,
        **kwargs: object,
    ) -> bool:
        assert original_commit(store, *args, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("forced ambiguous post-commit failure")

    monkeypatch.setattr(SetupStore, "commit_staged_rotation", commit_then_raise)

    rotated = client.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": csrf},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "replacement-provider-secret",
            "model": "replacement-model",
        },
    )

    assert rotated.status_code == 200
    after = SetupStore(settings).snapshot()
    assert after.provider_credential is not None
    assert after.provider_credential != before.provider_credential
    assert after.credential_retirement_pending_version is None
    vault = CredentialVault(settings.credential_key_path)
    assert vault.decrypt(after.provider_credential) == "replacement-provider-secret"
    with pytest.raises(CredentialUnavailableError):
        vault.decrypt(before.provider_credential)
    assert len(list(settings.credential_key_path.parent.glob("credential*.key"))) == 1


def test_commit_exception_before_durable_switch_aborts_owned_stage(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(client, settings, clock, mode="external")
    before = SetupStore(settings).snapshot()
    assert before.provider_credential is not None
    csrf = str(login(client)["csrf_token"])

    def fail_before_commit(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("forced pre-commit failure")

    monkeypatch.setattr(SetupStore, "commit_staged_rotation", fail_before_commit)

    failed = client.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": csrf},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "replacement-provider-secret",
            "model": "replacement-model",
        },
    )

    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "CREDENTIAL_ROTATION_IN_PROGRESS"
    after = SetupStore(settings).snapshot()
    assert after.provider_credential == before.provider_credential
    assert after.credential_retirement_pending_version is None
    assert after.credential_retirement_token is None
    assert CredentialVault(settings.credential_key_path).decrypt(
        after.provider_credential
    ) == "initial-provider-secret"
    assert list(settings.credential_key_path.parent.glob("credential*.key")) == [
        settings.credential_key_path
    ]


def test_rotation_cancellation_aborts_only_its_owned_stage(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(client, settings, clock, mode="external")
    before = SetupStore(settings).snapshot()
    assert before.provider_credential is not None
    csrf = str(login(client)["csrf_token"])

    def cancel_materialization(
        _vault: CredentialVault,
        _plaintext: str,
        _plan: CredentialRotationPlan,
    ) -> EncryptedCredential:
        raise asyncio.CancelledError

    monkeypatch.setattr(
        CredentialVault,
        "materialize_rotation",
        cancel_materialization,
    )

    with pytest.raises(RuntimeError, match="No response returned"):
        client.put(
            "/api/v1/settings/model",
            headers={"X-CSRF-Token": csrf},
            json={
                "mode": "external",
                "base_url": "https://api.example.com/v1",
                "api_key": "replacement-provider-secret",
                "model": "replacement-model",
            },
        )

    after = SetupStore(settings).snapshot()
    assert after.provider_credential == before.provider_credential
    assert after.credential_retirement_pending_version is None
    assert after.credential_retirement_token is None
    assert list(settings.credential_key_path.parent.glob("credential*.key")) == [
        settings.credential_key_path
    ]


def test_staged_rotation_cas_records_token_version_expected_active_and_epoch(
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
    complete_setup(client, settings, clock, mode="external")
    store = SetupStore(settings)
    snapshot = store.snapshot()
    assert snapshot.provider_credential is not None
    staged_version = f"file-v1:{'b' * 32}:{'c' * 32}"
    token = "rotation-token-a"

    assert store.begin_staged_rotation(
        staged_version=staged_version,
        token=token,
        expected_credential=snapshot.provider_credential,
        expected_setup_epoch=snapshot.setup_epoch,
        now=clock(),
    )

    with store.engine.connect() as connection:
        row = connection.exec_driver_sql(
            """
            SELECT credential_retirement_pending_version,
                   credential_retirement_operation,
                   credential_retirement_token,
                   credential_staged_expected_ciphertext,
                   credential_staged_expected_key_version,
                   credential_staged_setup_epoch
              FROM setup_state
             WHERE id = 1
            """
        ).mappings().one()
    assert row == {
        "credential_retirement_pending_version": staged_version,
        "credential_retirement_operation": "staged_rotation",
        "credential_retirement_token": token,
        "credential_staged_expected_ciphertext": (
            snapshot.provider_credential.ciphertext
        ),
        "credential_staged_expected_key_version": (
            snapshot.provider_credential.key_version
        ),
        "credential_staged_setup_epoch": snapshot.setup_epoch,
    }


def test_only_one_concurrent_staged_rotation_wins(
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
    complete_setup(client, settings, clock, mode="external")
    store = SetupStore(settings)
    snapshot = store.snapshot()
    assert snapshot.provider_credential is not None
    barrier = Barrier(2)
    attempts = [
        (f"file-v1:{identifier * 32}:{digest * 32}", f"rotation-token-{identifier}")
        for identifier, digest in (("b", "c"), ("d", "e"))
    ]

    def begin(attempt: tuple[str, str]) -> bool:
        barrier.wait(timeout=5)
        staged_version, token = attempt
        return store.begin_staged_rotation(
            staged_version=staged_version,
            token=token,
            expected_credential=snapshot.provider_credential,
            expected_setup_epoch=snapshot.setup_epoch,
            now=clock(),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(begin, attempts))

    assert sorted(results) == [False, True]
    winner_index = results.index(True)
    persisted = store.snapshot()
    assert persisted.credential_retirement_pending_version == attempts[winner_index][0]
    assert persisted.credential_retirement_token == attempts[winner_index][1]


def test_commit_atomically_switches_active_and_moves_old_version_to_retirement(
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
    complete_setup(client, settings, clock, mode="external")
    store = SetupStore(settings)
    before = store.snapshot()
    assert before.provider_credential is not None
    replacement = EncryptedCredential(
        ciphertext="aesgcm-v1:replacement-ciphertext",
        key_version=f"file-v1:{'b' * 32}:{'c' * 32}",
    )
    token = "rotation-token-a"
    assert store.begin_staged_rotation(
        staged_version=replacement.key_version,
        token=token,
        expected_credential=before.provider_credential,
        expected_setup_epoch=before.setup_epoch,
        now=clock(),
    )

    request = ProviderProbeRequest(
        mode="external",
        base_url="https://api.example.com/v1",
        api_key="replacement-provider-secret",
        model="replacement-model",
    )
    result = ProviderProbeResult(
        status="verified",
        provider="openai-compatible",
        model="replacement-model",
        latency_ms=5,
    )
    assert store.commit_staged_rotation(
        request,
        result,
        replacement,
        token=token,
        now=clock(),
    )

    committed = store.snapshot()
    assert committed.provider_credential == replacement
    assert (
        committed.credential_retirement_pending_version
        == before.provider_credential.key_version
    )
    assert committed.credential_retirement_operation == "rotation"
    assert committed.credential_retirement_token is None


def test_abort_requires_matching_version_and_token(
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
    complete_setup(client, settings, clock, mode="external")
    store = SetupStore(settings)
    snapshot = store.snapshot()
    assert snapshot.provider_credential is not None
    staged_version = f"file-v1:{'b' * 32}:{'c' * 32}"
    token = "rotation-token-a"
    assert store.begin_staged_rotation(
        staged_version=staged_version,
        token=token,
        expected_credential=snapshot.provider_credential,
        expected_setup_epoch=snapshot.setup_epoch,
        now=clock(),
    )

    assert not store.abort_staged_rotation(staged_version, "wrong-token", clock())
    assert not store.abort_staged_rotation(
        f"file-v1:{'d' * 32}:{'e' * 32}", token, clock()
    )
    assert store.snapshot().credential_retirement_pending_version == staged_version
    assert store.abort_staged_rotation(staged_version, token, clock())
    aborted = store.snapshot()
    assert aborted.credential_retirement_pending_version is None
    assert aborted.credential_retirement_operation is None
    assert aborted.credential_retirement_token is None


def test_generic_retirement_completion_rejects_staged_rotation(
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
    complete_setup(client, settings, clock, mode="external")
    store = SetupStore(settings)
    snapshot = store.snapshot()
    assert snapshot.provider_credential is not None
    staged_version = f"file-v1:{'b' * 32}:{'c' * 32}"
    token = "rotation-token-a"
    assert store.begin_staged_rotation(
        staged_version=staged_version,
        token=token,
        expected_credential=snapshot.provider_credential,
        expected_setup_epoch=snapshot.setup_epoch,
        now=clock(),
    )

    assert not store.complete_credential_retirement(staged_version, clock())
    pending = store.snapshot()
    assert pending.credential_retirement_pending_version == staged_version
    assert pending.credential_retirement_operation == "staged_rotation"
    assert pending.credential_retirement_token == token


def test_concurrent_rotations_create_only_one_durable_stage_and_key_file(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    probe_barrier = Barrier(2)

    class ConcurrentProviderGateway:
        async def probe(self, request: ProviderProbeRequest) -> ProviderProbeResult:
            await asyncio.to_thread(probe_barrier.wait, 5)
            return ProviderProbeResult(
                status="verified",
                provider="openai-compatible",
                model=request.model or "demo-model",
                latency_ms=5,
            )

    app = create_app(
        settings=settings,
        clock=clock,
        provider_gateway=ConcurrentProviderGateway(),
    )
    clients = [TestClient(app), TestClient(app)]
    csrf_tokens = [str(login(client)["csrf_token"]) for client in clients]
    original_materialize = CredentialVault.materialize_rotation
    materialized_versions: list[str] = []
    owner_materializing = Event()
    release_owner = Event()

    def record_materialization(
        vault: CredentialVault,
        plaintext: str,
        plan: CredentialRotationPlan,
    ) -> EncryptedCredential:
        staged = SetupStore(settings).snapshot()
        assert staged.credential_retirement_operation == "staged_rotation"
        assert staged.credential_retirement_pending_version == plan.key_version
        assert staged.credential_retirement_token is not None
        materialized_versions.append(plan.key_version)
        owner_materializing.set()
        assert release_owner.wait(5)
        return original_materialize(vault, plaintext, plan)

    monkeypatch.setattr(CredentialVault, "materialize_rotation", record_materialization)

    def rotate(index: int) -> Response:
        return clients[index].put(
            "/api/v1/settings/model",
            headers={"X-CSRF-Token": csrf_tokens[index]},
            json={
                "mode": "external",
                "base_url": "https://api.example.com/v1",
                "api_key": f"replacement-provider-secret-{index}",
                "model": f"replacement-model-{index}",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(rotate, index) for index in range(2)]
        try:
            assert owner_materializing.wait(5)
            completed, _pending = wait(
                futures,
                timeout=5,
                return_when=FIRST_COMPLETED,
            )
            assert len(completed) == 1
            loser = next(iter(completed)).result()
            assert loser.status_code == 409
            blocked = TestClient(app).get("/api/v1/setup/status")
            assert blocked.status_code == 503
            assert blocked.json()["error"]["code"] == "CREDENTIAL_ROTATION_IN_PROGRESS"
        finally:
            release_owner.set()
        responses = [future.result(timeout=5) for future in futures]

    assert sorted(response.status_code for response in responses) == [200, 409]
    assert len(materialized_versions) == 1
    snapshot = SetupStore(settings).snapshot()
    assert snapshot.provider_credential is not None
    assert snapshot.credential_retirement_pending_version is None
    assert CredentialVault(settings.credential_key_path).decrypt(
        snapshot.provider_credential
    ).startswith("replacement-provider-secret-")
    assert len(list(settings.credential_key_path.parent.glob("credential*.key"))) == 1


def test_partial_materialization_failure_is_owner_aborted_without_orphan(
    settings: Settings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(client, settings, clock, mode="external")
    before = SetupStore(settings).snapshot()
    assert before.provider_credential is not None
    csrf = str(login(client)["csrf_token"])
    original_write = credentials_module.os.write
    write_calls = 0

    def partial_then_fail(descriptor: int, value: object) -> int:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            return original_write(descriptor, bytes(value)[:7])  # type: ignore[arg-type]
        raise OSError("forced partial credential write")

    monkeypatch.setattr(credentials_module.os, "write", partial_then_fail)

    failed = client.put(
        "/api/v1/settings/model",
        headers={"X-CSRF-Token": csrf},
        json={
            "mode": "external",
            "base_url": "https://api.example.com/v1",
            "api_key": "replacement-provider-secret",
            "model": "replacement-model",
        },
    )

    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "CREDENTIAL_STORE_UNAVAILABLE"
    recovered = SetupStore(settings).snapshot()
    assert recovered.provider_credential == before.provider_credential
    assert recovered.credential_retirement_pending_version is None
    assert recovered.credential_retirement_token is None
    assert list(settings.credential_key_path.parent.glob("credential*.key")) == [
        settings.credential_key_path
    ]


def test_non_owner_request_cannot_resume_or_delete_live_staged_rotation(
    settings: Settings,
    clock: MutableClock,
) -> None:
    app = create_app(
        settings=settings,
        clock=clock,
        provider_gateway=RecordingProviderGateway(),
    )
    client = TestClient(app)
    complete_setup(client, settings, clock, mode="external")
    store = SetupStore(settings)
    snapshot = store.snapshot()
    assert snapshot.provider_credential is not None
    vault = CredentialVault(settings.credential_key_path)
    plan = vault.plan_rotation(snapshot.provider_credential)
    token = "live-owner-token"
    assert store.begin_staged_rotation(
        staged_version=plan.key_version,
        token=token,
        expected_credential=snapshot.provider_credential,
        expected_setup_epoch=snapshot.setup_epoch,
        now=clock(),
    )
    vault.materialize_rotation("staged-provider-secret", plan)
    staged_path = settings.credential_key_path.with_name(
        f"{settings.credential_key_path.stem}.file-v1-{plan.identifier}"
        f"{settings.credential_key_path.suffix}"
    )

    blocked = client.get("/api/v1/auth/session")

    assert blocked.status_code == 503
    assert blocked.json()["error"]["code"] == "CREDENTIAL_ROTATION_IN_PROGRESS"
    assert staged_path.exists()
    still_staged = store.snapshot()
    assert still_staged.credential_retirement_pending_version == plan.key_version
    assert still_staged.credential_retirement_token == token


def test_restart_recovers_stage_before_materialization(
    settings: Settings,
    clock: MutableClock,
) -> None:
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    store = SetupStore(settings)
    before = store.snapshot()
    assert before.provider_credential is not None
    vault = CredentialVault(settings.credential_key_path)
    plan = vault.plan_rotation(before.provider_credential)
    assert store.begin_staged_rotation(
        staged_version=plan.key_version,
        token="crashed-owner-token",
        expected_credential=before.provider_credential,
        expected_setup_epoch=before.setup_epoch,
        now=clock(),
    )

    create_app(settings=settings, clock=clock)

    recovered = SetupStore(settings).snapshot()
    assert recovered.provider_credential == before.provider_credential
    assert recovered.credential_retirement_pending_version is None
    assert CredentialVault(settings.credential_key_path).decrypt(
        recovered.provider_credential
    ) == "initial-provider-secret"


def test_restart_recovers_materialized_stage_before_active_cas(
    settings: Settings,
    clock: MutableClock,
) -> None:
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    store = SetupStore(settings)
    before = store.snapshot()
    assert before.provider_credential is not None
    vault = CredentialVault(settings.credential_key_path)
    plan = vault.plan_rotation(before.provider_credential)
    assert store.begin_staged_rotation(
        staged_version=plan.key_version,
        token="crashed-owner-token",
        expected_credential=before.provider_credential,
        expected_setup_epoch=before.setup_epoch,
        now=clock(),
    )
    vault.materialize_rotation("staged-provider-secret", plan)
    staged_path = settings.credential_key_path.with_name(
        f"{settings.credential_key_path.stem}.file-v1-{plan.identifier}"
        f"{settings.credential_key_path.suffix}"
    )
    assert staged_path.exists()

    create_app(settings=settings, clock=clock)

    recovered = SetupStore(settings).snapshot()
    assert recovered.provider_credential == before.provider_credential
    assert recovered.credential_retirement_pending_version is None
    assert not staged_path.exists()


def test_restart_recovers_safe_partial_write_or_fsync_file(
    settings: Settings,
    clock: MutableClock,
) -> None:
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    store = SetupStore(settings)
    before = store.snapshot()
    assert before.provider_credential is not None
    vault = CredentialVault(settings.credential_key_path)
    plan = vault.plan_rotation(before.provider_credential)
    assert store.begin_staged_rotation(
        staged_version=plan.key_version,
        token="crashed-owner-token",
        expected_credential=before.provider_credential,
        expected_setup_epoch=before.setup_epoch,
        now=clock(),
    )
    staged_path = settings.credential_key_path.with_name(
        f"{settings.credential_key_path.stem}.file-v1-{plan.identifier}"
        f"{settings.credential_key_path.suffix}"
    )
    staged_path.write_bytes(b"partial")
    staged_path.chmod(0o600)

    create_app(settings=settings, clock=clock)

    assert not staged_path.exists()
    assert SetupStore(settings).snapshot().credential_retirement_pending_version is None


@pytest.mark.parametrize("unlink_before_restart", [False, True])
def test_restart_finishes_old_key_retirement_before_and_after_unlink(
    settings: Settings,
    clock: MutableClock,
    unlink_before_restart: bool,
) -> None:
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    store = SetupStore(settings)
    before = store.snapshot()
    assert before.provider_credential is not None
    vault = CredentialVault(settings.credential_key_path)
    plan = vault.plan_rotation(before.provider_credential)
    token = "restart-retirement-token"
    assert store.begin_staged_rotation(
        staged_version=plan.key_version,
        token=token,
        expected_credential=before.provider_credential,
        expected_setup_epoch=before.setup_epoch,
        now=clock(),
    )
    replacement = vault.materialize_rotation("replacement-provider-secret", plan)
    request = ProviderProbeRequest(
        mode="external",
        base_url="https://api.example.com/v1",
        api_key="replacement-provider-secret",
        model="replacement-model",
    )
    result = ProviderProbeResult(
        status="verified",
        provider="openai-compatible",
        model="replacement-model",
        latency_ms=5,
    )
    assert store.commit_staged_rotation(
        request,
        result,
        replacement,
        token=token,
        now=clock(),
    )
    if unlink_before_restart:
        vault.retire_version(before.provider_credential.key_version)

    create_app(settings=settings, clock=clock)

    recovered = SetupStore(settings).snapshot()
    assert recovered.provider_credential == replacement
    assert recovered.credential_retirement_pending_version is None
    assert vault.decrypt(replacement) == "replacement-provider-secret"
    with pytest.raises(CredentialUnavailableError):
        vault.decrypt(before.provider_credential)


@pytest.mark.parametrize(
    "unsafe_kind",
    ["symlink", "mode", "unknown-version", "unknown-name"],
)
def test_unsafe_or_unknown_staged_path_prevents_startup_without_deletion(
    settings: Settings,
    clock: MutableClock,
    unsafe_kind: str,
) -> None:
    configured = TestClient(
        create_app(
            settings=settings,
            clock=clock,
            provider_gateway=RecordingProviderGateway(),
        )
    )
    complete_setup(configured, settings, clock, mode="external")
    store = SetupStore(settings)
    before = store.snapshot()
    assert before.provider_credential is not None
    vault = CredentialVault(settings.credential_key_path)
    plan = vault.plan_rotation(before.provider_credential)
    token = "crashed-owner-token"
    assert store.begin_staged_rotation(
        staged_version=plan.key_version,
        token=token,
        expected_credential=before.provider_credential,
        expected_setup_epoch=before.setup_epoch,
        now=clock(),
    )
    staged_path = settings.credential_key_path.with_name(
        f"{settings.credential_key_path.stem}.file-v1-{plan.identifier}"
        f"{settings.credential_key_path.suffix}"
    )
    if unsafe_kind == "symlink":
        staged_path.symlink_to(settings.credential_key_path)
        unsafe_path = staged_path
    elif unsafe_kind == "mode":
        staged_path.write_bytes(b"partial")
        staged_path.chmod(0o644)
        unsafe_path = staged_path
    elif unsafe_kind == "unknown-version":
        unsafe_path = settings.credential_key_path.with_name(
            f"{settings.credential_key_path.stem}.file-v1-{'f' * 32}"
            f"{settings.credential_key_path.suffix}"
        )
        unsafe_path.write_bytes(b"unknown-key")
        unsafe_path.chmod(0o600)
    else:
        unsafe_path = settings.credential_key_path.parent / "unrecognized-secret"
        unsafe_path.write_bytes(b"unknown-key")
        unsafe_path.chmod(0o600)

    with pytest.raises(CredentialUnavailableError):
        create_app(settings=settings, clock=clock)

    assert unsafe_path.exists() or unsafe_path.is_symlink()
    pending = SetupStore(settings).snapshot()
    assert pending.credential_retirement_pending_version == plan.key_version
    assert pending.credential_retirement_token == token
