from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from sqllens_api import main as main_module
from sqllens_api.app import create_app
from sqllens_api.config import Settings
from sqllens_api.setup import OWNER_COOKIE_NAME, SETUP_COOKIE_NAME, SetupStore

OWNER_PASSWORD = "correct-horse-battery-staple"
LOCAL_ORIGIN = "http://localhost:18080"


@dataclass
class FixedClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(datetime(2026, 9, 2, 10, 0, tzinfo=UTC))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        first_owner_nonce_ttl_seconds=60,
        first_owner_max_attempts=3,
        first_owner_rate_window_seconds=60,
        owner_session_ttl_seconds=300,
        cookie_secure=False,
    )


def local_client(app: FastAPI) -> TestClient:
    return TestClient(app, base_url=LOCAL_ORIGIN)


def create_owner(
    client: TestClient,
    password: str = OWNER_PASSWORD,
    *,
    nonce: str | None = None,
) -> Response:
    if nonce is None:
        status = client.get("/api/v1/setup/status")
        assert status.status_code == 200
        nonce = str(status.json()["setup_nonce"])
    return client.post(
        "/api/v1/setup/owner",
        headers={"Origin": LOCAL_ORIGIN, "X-Setup-Nonce": nonce},
        json={"password": password},
    )


def test_fresh_instance_starts_with_local_owner_creation(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = local_client(create_app(settings=settings, clock=clock))

    response = client.get("/api/v1/setup/status")

    assert response.status_code == 200
    body = response.json()
    setup_nonce = body.pop("setup_nonce")
    assert isinstance(setup_nonce, str)
    assert len(setup_nonce) >= 32
    assert body == {
        "state": "owner_required",
        "initialized": False,
        "owner_configured": False,
        "bootstrap_hash_persisted": False,
        "model_mode": None,
        "external_model": {
            "credential_available": False,
            "egress_enabled": False,
        },
        "csrf_token": None,
        "recovery": {"required": False, "action": None, "reason": None},
        "local_model": {
            "available": False,
            "verified": False,
            "code": "LOCAL_RUNTIME_UNAVAILABLE",
            "message": "No qualified local model runtime is exposed to this service.",
        },
    }
    assert client.cookies.get(SETUP_COOKIE_NAME) is not None
    set_cookie = response.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/api/v1/setup" in set_cookie


def test_local_owner_creation_issues_session_and_protects_remaining_setup(
    settings: Settings,
    clock: FixedClock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = local_client(create_app(settings=settings, clock=clock))

    response = create_owner(client)

    assert response.status_code == 201
    assert response.json() == {
        "state": "security_policy_required",
        "authenticated": True,
        "csrf_token": response.json()["csrf_token"],
    }
    assert response.json()["csrf_token"]
    assert client.cookies.get(OWNER_COOKIE_NAME) is not None
    set_cookie = response.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/api/v1" in set_cookie
    assert OWNER_PASSWORD not in response.text
    assert OWNER_PASSWORD not in caplog.text
    assert OWNER_PASSWORD.encode() not in settings.database_path.read_bytes()

    missing_csrf = client.put(
        "/api/v1/setup/security-policy",
        json={
            "external_model_egress": False,
            "allowed_provider_hosts": [],
            "send_sql_text": False,
        },
    )
    assert missing_csrf.status_code == 403
    assert missing_csrf.json()["error"]["code"] == "CSRF_INVALID"

    csrf_token = response.json()["csrf_token"]
    accepted = client.put(
        "/api/v1/setup/security-policy",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "external_model_egress": False,
            "allowed_provider_hosts": [],
            "send_sql_text": False,
        },
    )
    assert accepted.status_code == 200
    assert accepted.json() == {"state": "model_required"}


def test_setup_mutations_other_than_owner_are_unavailable_before_authentication(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = local_client(create_app(settings=settings, clock=clock))

    policy = client.put(
        "/api/v1/setup/security-policy",
        json={
            "external_model_egress": False,
            "allowed_provider_hosts": [],
            "send_sql_text": False,
        },
    )
    model = client.post(
        "/api/v1/setup/model-probes",
        json={"mode": "local", "model": "untrusted"},
    )
    finalize = client.post("/api/v1/setup/finalize", json={"mode": "rules"})

    assert [policy.status_code, model.status_code, finalize.status_code] == [401, 401, 401]
    assert policy.json()["error"]["code"] == "SETUP_SESSION_REQUIRED"
    assert SetupStore(settings).snapshot().stage == "owner_required"


def test_existing_owner_finalizes_without_reentering_or_replacing_password(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = local_client(create_app(settings=settings, clock=clock))
    created = create_owner(client)
    csrf = created.json()["csrf_token"]
    assert (
        client.put(
            "/api/v1/setup/security-policy",
            headers={"X-CSRF-Token": csrf},
            json={
                "external_model_egress": False,
                "allowed_provider_hosts": [],
                "send_sql_text": False,
            },
        ).status_code
        == 200
    )

    finalized = client.post(
        "/api/v1/setup/finalize",
        headers={"X-CSRF-Token": csrf},
        json={"mode": "rules"},
    )

    assert finalized.status_code == 200
    assert finalized.json()["state"] == "ready"
    store = SetupStore(settings)
    assert store.authenticate_owner(OWNER_PASSWORD, clock()).status == "authenticated"
    assert store.authenticate_owner("replacement-password-123", clock()).status == "invalid"


def test_first_owner_requires_matching_cookie_bound_nonce(
    settings: Settings,
    clock: FixedClock,
) -> None:
    app = create_app(settings=settings, clock=clock)
    intended = local_client(app)
    other_browser = local_client(app)
    nonce = intended.get("/api/v1/setup/status").json()["setup_nonce"]
    other_browser.get("/api/v1/setup/status")

    missing = intended.post(
        "/api/v1/setup/owner",
        headers={"Origin": LOCAL_ORIGIN},
        json={"password": OWNER_PASSWORD},
    )
    mismatch = other_browser.post(
        "/api/v1/setup/owner",
        headers={"Origin": LOCAL_ORIGIN, "X-Setup-Nonce": nonce},
        json={"password": OWNER_PASSWORD},
    )

    assert missing.status_code == 403
    assert mismatch.status_code == 403
    assert missing.json()["error"]["code"] == "SETUP_NONCE_INVALID"
    assert mismatch.json()["error"]["code"] == "SETUP_NONCE_INVALID"
    assert SetupStore(settings).snapshot().owner_configured is False

    # A mismatch does not turn the nonce into an oracle or consume the correct proof.
    accepted = create_owner(intended, nonce=nonce)
    assert accepted.status_code == 201


def test_expired_first_owner_nonce_is_consumed_and_cannot_be_replayed(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = local_client(create_app(settings=settings, clock=clock))
    nonce = client.get("/api/v1/setup/status").json()["setup_nonce"]
    clock.advance(seconds=settings.first_owner_nonce_ttl_seconds + 1)

    expired = create_owner(client, nonce=nonce)
    replay = create_owner(client, nonce=nonce)

    assert expired.status_code == 403
    assert replay.status_code == 403
    assert expired.json()["error"]["code"] == "SETUP_NONCE_INVALID"
    assert replay.json()["error"]["code"] == "SETUP_NONCE_INVALID"
    assert SetupStore(settings).snapshot().owner_configured is False


def test_first_owner_rate_limit_is_global_and_checked_before_password_hash(
    settings: Settings,
    clock: FixedClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = local_client(create_app(settings=settings, clock=clock))
    nonce = client.get("/api/v1/setup/status").json()["setup_nonce"]
    for bad_nonce in ("wrong-proof-one", "wrong-proof-two", "wrong-proof-three"):
        denied = create_owner(client, nonce=bad_nonce)
        assert denied.status_code == 403

    password_hash_calls = 0

    def forbidden_hash(_password: str, _salt: bytes) -> str:
        nonlocal password_hash_calls
        password_hash_calls += 1
        raise AssertionError("rate-limited request reached password hashing")

    monkeypatch.setattr("sqllens_api.setup._derive_password_hash", forbidden_hash)
    limited = create_owner(client, nonce=nonce)

    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "FIRST_OWNER_RATE_LIMITED"
    assert password_hash_calls == 0

    monkeypatch.undo()
    clock.advance(seconds=settings.first_owner_rate_window_seconds + 1)
    fresh_nonce = client.get("/api/v1/setup/status").json()["setup_nonce"]
    assert create_owner(client, nonce=fresh_nonce).status_code == 201


def test_noncanonical_status_never_issues_first_owner_proof(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = TestClient(
        create_app(settings=settings, clock=clock),
        base_url="http://127.0.0.1:18080",
    )

    response = client.get("/api/v1/setup/status")

    assert response.status_code == 200
    assert response.json()["state"] == "owner_required"
    assert response.json()["setup_nonce"] is None
    assert SETUP_COOKIE_NAME not in client.cookies


@pytest.mark.parametrize(
    ("base_url", "headers"),
    [
        (
            "http://sqllens.internal:18080",
            {"Origin": "http://sqllens.internal:18080"},
        ),
        (
            LOCAL_ORIGIN,
            {"Origin": "https://attacker.example"},
        ),
        (
            LOCAL_ORIGIN,
            {"Origin": LOCAL_ORIGIN, "X-Forwarded-For": "127.0.0.1"},
        ),
        (
            LOCAL_ORIGIN,
            {"Origin": LOCAL_ORIGIN, "Forwarded": "for=127.0.0.1;host=localhost"},
        ),
        (
            LOCAL_ORIGIN,
            {"Origin": LOCAL_ORIGIN, "X-Forwarded-Host": "localhost:18080"},
        ),
        (
            LOCAL_ORIGIN,
            {},
        ),
    ],
)
def test_first_owner_rejects_remote_origin_and_proxy_spoofing(
    settings: Settings,
    clock: FixedClock,
    base_url: str,
    headers: dict[str, str],
) -> None:
    client = TestClient(create_app(settings=settings, clock=clock), base_url=base_url)
    client.cookies.set(SETUP_COOKIE_NAME, "untrusted-cookie", path="/api/v1/setup")

    response = client.post(
        "/api/v1/setup/owner",
        headers={**headers, "X-Setup-Nonce": "untrusted-nonce"},
        json={"password": OWNER_PASSWORD},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FIRST_RUN_LOCALHOST_REQUIRED"
    assert SetupStore(settings).snapshot().owner_configured is False


def test_concurrent_owner_creation_has_exactly_one_winner(
    settings: Settings,
    clock: FixedClock,
) -> None:
    app = create_app(settings=settings, clock=clock)
    barrier = Barrier(2)
    passwords = ("winner-candidate-alpha", "winner-candidate-bravo")

    def attempt(password: str) -> tuple[str, int, str | None]:
        client = local_client(app)
        nonce = client.get("/api/v1/setup/status").json()["setup_nonce"]
        barrier.wait(timeout=5)
        response = create_owner(client, password, nonce=nonce)
        return password, response.status_code, client.cookies.get(OWNER_COOKIE_NAME)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, passwords))

    assert sorted(status for _, status, _ in results) == [201, 409]
    winner = next(password for password, status, _ in results if status == 201)
    loser = next(password for password, status, _ in results if status == 409)
    assert next(cookie for _, status, cookie in results if status == 201) is not None
    assert next(cookie for _, status, cookie in results if status == 409) is None

    store = SetupStore(settings)
    assert store.authenticate_owner(winner, clock()).status == "authenticated"
    assert store.authenticate_owner(loser, clock()).status == "invalid"
    assert store.snapshot().owner_session_epoch == 1


def test_owner_creation_replay_cannot_replace_password_or_session_epoch(
    settings: Settings,
    clock: FixedClock,
) -> None:
    client = local_client(create_app(settings=settings, clock=clock))
    nonce = client.get("/api/v1/setup/status").json()["setup_nonce"]
    created = create_owner(client, nonce=nonce)
    cookie = client.cookies.get(OWNER_COOKIE_NAME)
    before = SetupStore(settings).snapshot()

    replay = create_owner(client, "replacement-password-123", nonce=nonce)

    assert created.status_code == 201
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "OWNER_ALREADY_CONFIGURED"
    assert "set-cookie" not in replay.headers
    assert client.cookies.get(OWNER_COOKIE_NAME) == cookie
    after = SetupStore(settings).snapshot()
    assert after.stage == "security_policy_required"
    assert after.owner_session_epoch == before.owner_session_epoch
    assert (
        SetupStore(settings).authenticate_owner(OWNER_PASSWORD, clock()).status == "authenticated"
    )
    assert (
        SetupStore(settings).authenticate_owner("replacement-password-123", clock()).status
        == "invalid"
    )


def test_owner_login_survives_restart_before_setup_is_complete(
    settings: Settings,
    clock: FixedClock,
) -> None:
    first = local_client(create_app(settings=settings, clock=clock))
    assert create_owner(first).status_code == 201

    restarted = local_client(create_app(settings=settings, clock=clock))
    login = restarted.post("/api/v1/auth/login", json={"password": OWNER_PASSWORD})

    assert login.status_code == 200
    assert login.json()["authenticated"] is True
    status = restarted.get("/api/v1/setup/status")
    assert status.json()["state"] == "security_policy_required"
    assert status.json()["initialized"] is False
    assert status.json()["owner_configured"] is True
    assert status.json()["csrf_token"] == login.json()["csrf_token"]
    replay = create_owner(restarted, "replacement-password-123")
    assert replay.status_code == 409


def test_runtime_disables_proxy_header_trust(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel_app = FastAPI()
    observed: dict[str, object] = {}

    monkeypatch.setattr(main_module, "create_app", lambda settings: sentinel_app)
    monkeypatch.setattr(
        main_module.uvicorn,
        "run",
        lambda app, **kwargs: observed.update({"app": app, **kwargs}),
    )

    main_module.run()

    assert observed["app"] is sentinel_app
    assert observed["proxy_headers"] is False
    assert observed["forwarded_allow_ips"] == ""
