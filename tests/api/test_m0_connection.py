from __future__ import annotations

import asyncio
import os
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest
from asyncmy.connection import Connection
from asyncmy.constants import CLIENT
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqllens_api.app import create_app
from sqllens_api.config import Settings
from sqllens_api.m0_connection import (
    ASYNCMY_VERSION,
    CLIENT_MULTI_STATEMENTS,
    AsyncmyM0Connector,
    M0BusyError,
    M0ConnectionInput,
    M0ConnectionStore,
    M0DriverInvariantError,
    M0TidbTimeoutError,
    M0TidbUnavailableError,
    M0TidbVersionUnsupportedError,
    _prepare_private_driver_fields,
    _scrub_private_password_fields,
)

TEST_PASSWORD = "TiDB-密碼-only-in-memory"


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.description = (
            ("version", None, None, None, None, None, None),
            ("version_comment", None, None, None, None, None, None),
            ("tidb_version", None, None, None, None, None, None),
            ("autocommit", None, None, None, None, None, None),
        )

    async def __aenter__(self) -> FakeCursor:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def execute(self, sql: str, parameters: object = None) -> None:
        self.connection.identity_password = self.connection._password
        self.connection.identity_password_creator = self.connection._password_creator
        self.connection.identity_client_flag = self.connection._client_flag
        self.connection.executed.append((sql, parameters))

    async def fetchmany(self, size: int) -> list[tuple[object, ...]]:
        assert size == 2
        return list(self.connection.identity_rows)


class FakeConnection:
    instances: ClassVar[list[FakeConnection]] = []
    identity_rows_default: ClassVar[tuple[tuple[object, ...], ...]] = (
        (
            "8.0.11-TiDB-v8.5.4",
            "TiDB Server (Apache License 2.0) Community Edition, MySQL 8.0 compatible",
            "Release Version: v8.5.4",
            1,
        ),
    )
    connect_effect: ClassVar[BaseException | None] = None
    connect_waiter: ClassVar[asyncio.Event | None] = None

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self._client_flag = int(kwargs["client_flag"]) | CLIENT_MULTI_STATEMENTS
        self._password = kwargs["password"]
        self._password_creator: object | None = object()
        self.server_status = 0
        self.identity_rows = self.identity_rows_default
        self.connect_client_flag: int | None = None
        self.connect_password: object = None
        self.identity_password: object = None
        self.identity_password_creator: object = object()
        self.identity_client_flag: int | None = None
        self.executed: list[tuple[str, object]] = []
        self.ensure_closed_calls = 0
        self.close_calls = 0
        type(self).instances.append(self)

    async def connect(self) -> None:
        self.connect_client_flag = self._client_flag
        self.connect_password = self._password
        if self.connect_waiter is not None:
            await self.connect_waiter.wait()
        if self.connect_effect is not None:
            raise self.connect_effect

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    async def ensure_closed(self) -> None:
        self.ensure_closed_calls += 1

    def close(self) -> None:
        self.close_calls += 1


@pytest.fixture(autouse=True)
def reset_fake_connection() -> None:
    FakeConnection.instances = []
    FakeConnection.identity_rows_default = (
        (
            "8.0.11-TiDB-v8.5.4",
            "TiDB Server (Apache License 2.0) Community Edition, MySQL 8.0 compatible",
            "Release Version: v8.5.4",
            1,
        ),
    )
    FakeConnection.connect_effect = None
    FakeConnection.connect_waiter = None


def valid_input(**overrides: object) -> M0ConnectionInput:
    values: dict[str, object] = {
        "host": "tidb.internal.example",
        "port": 4000,
        "database": "shop",
        "username": "sqllens_ro",
        "password": TEST_PASSWORD,
        "tls_mode": "verify_ca",
    }
    values.update(overrides)
    return M0ConnectionInput.model_validate(values)


def connector(
    *,
    version: str = ASYNCMY_VERSION,
    factory: Callable[..., Any] = FakeConnection,
    io_timeout_seconds: float = 5.0,
) -> AsyncmyM0Connector:
    return AsyncmyM0Connector(
        connection_factory=factory,
        version_reader=lambda _distribution: version,
        io_timeout_seconds=io_timeout_seconds,
    )


def test_connection_input_is_closed_and_hides_the_secret() -> None:
    value = valid_input()

    assert TEST_PASSWORD not in repr(value)
    assert value.password.get_secret_value() == TEST_PASSWORD

    with pytest.raises(ValidationError):
        valid_input(extra="forbidden")
    with pytest.raises(ValidationError):
        valid_input(host="https://tidb.example")
    with pytest.raises(ValidationError):
        valid_input(host="tidb.example/path")
    with pytest.raises(ValidationError):
        valid_input(host="tidb example")
    with pytest.raises(ValidationError):
        valid_input(database="shop\nproduction")
    with pytest.raises(ValidationError):
        valid_input(password="密" * 171)


@pytest.mark.asyncio
async def test_exact_asyncmy_layout_supports_the_frozen_compatibility_shim() -> None:
    raw = Connection(
        host="localhost",
        port=4000,
        database="shop",
        user="sqllens_ro",
        password=TEST_PASSWORD.encode("utf-8"),
        client_flag=0,
        charset="utf8mb4",
        autocommit=None,
        local_infile=False,
        init_command=None,
        read_default_file=None,
        unix_socket=None,
        sock=None,
        echo=False,
        query_callback=None,
        connect_timeout=5,
        read_timeout=5,
        ssl=None,
    )

    assert raw._client_flag & int(CLIENT.MULTI_STATEMENTS)
    assert raw._password == TEST_PASSWORD.encode("utf-8")
    assert raw._password_creator is None

    _prepare_private_driver_fields(raw)
    _scrub_private_password_fields(raw)

    assert raw._client_flag & int(CLIENT.MULTI_STATEMENTS) == 0
    assert raw._password == b""
    assert raw._password_creator is None


@pytest.mark.asyncio
async def test_connector_clears_capability_and_scrubs_password_before_identity() -> None:
    pending: list[object] = []
    value = valid_input()

    live = await connector().connect(value, register_pending=pending.append)

    raw = FakeConnection.instances[0]
    assert pending == [live]
    assert raw.connect_client_flag is not None
    assert raw.connect_client_flag & CLIENT_MULTI_STATEMENTS == 0
    assert raw.connect_password == TEST_PASSWORD.encode("utf-8")
    assert raw._password == b""
    assert raw._password_creator is None
    assert raw.identity_password == b""
    assert raw.identity_password_creator is None
    assert raw.identity_client_flag is not None
    assert raw.identity_client_flag & CLIENT_MULTI_STATEMENTS == 0
    assert len(raw.executed) == 1
    identity_sql, identity_parameters = raw.executed[0]
    assert "@@autocommit" in identity_sql.lower()
    assert TEST_PASSWORD not in identity_sql
    assert identity_parameters in (None, (), {})
    assert live.version == "8.5.4"
    assert live.database == "shop"
    assert TEST_PASSWORD not in repr(live)

    tls_context = raw.kwargs["ssl"]
    assert isinstance(tls_context, ssl.SSLContext)
    assert tls_context.verify_mode is ssl.CERT_REQUIRED
    assert tls_context.check_hostname is True
    assert tls_context is not True
    assert raw.kwargs["autocommit"] is None
    assert raw.kwargs["echo"] is False
    assert raw.kwargs["local_infile"] is False
    assert raw.kwargs["init_command"] is None
    assert raw.kwargs["query_callback"] is None
    assert raw.kwargs["connect_timeout"] == 5
    assert raw.kwargs["read_timeout"] == 5
    assert "write_timeout" not in raw.kwargs


@pytest.mark.asyncio
async def test_connector_passes_no_tls_context_only_for_disabled_mode() -> None:
    await connector().connect(valid_input(tls_mode="disabled"), register_pending=lambda _: None)

    assert FakeConnection.instances[0].kwargs["ssl"] is None


@pytest.mark.asyncio
async def test_wrong_driver_version_fails_before_connection_construction() -> None:
    factory_calls = 0

    def forbidden_factory(**_kwargs: object) -> FakeConnection:
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("wrong driver version reached the connection constructor")

    with pytest.raises(M0DriverInvariantError, match="driver invariant"):
        await connector(version="0.2.13", factory=forbidden_factory).connect(
            valid_input(), register_pending=lambda _: None
        )

    assert factory_calls == 0


@pytest.mark.asyncio
async def test_driver_version_probe_failure_is_closed_before_construction() -> None:
    factory_calls = 0

    def broken_version_reader(_distribution: str) -> str:
        raise RuntimeError(f"metadata leaked {TEST_PASSWORD}")

    def forbidden_factory(**_kwargs: object) -> FakeConnection:
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("metadata failure reached the connection constructor")

    adapter = AsyncmyM0Connector(
        connection_factory=forbidden_factory,
        version_reader=broken_version_reader,
    )
    with pytest.raises(M0DriverInvariantError) as raised:
        await adapter.connect(valid_input(), register_pending=lambda _: None)

    assert factory_calls == 0
    assert TEST_PASSWORD not in str(raised.value)


@pytest.mark.asyncio
async def test_tls_context_creation_failure_is_sanitized_before_construction() -> None:
    factory_calls = 0

    def broken_ssl_context() -> ssl.SSLContext:
        raise RuntimeError(f"TLS leaked {TEST_PASSWORD}")

    def forbidden_factory(**_kwargs: object) -> FakeConnection:
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("TLS context failure reached the connection constructor")

    adapter = AsyncmyM0Connector(
        connection_factory=forbidden_factory,
        version_reader=lambda _distribution: ASYNCMY_VERSION,
        ssl_context_factory=broken_ssl_context,
    )
    with pytest.raises(M0TidbUnavailableError) as raised:
        await adapter.connect(valid_input(), register_pending=lambda _: None)

    assert factory_calls == 0
    assert TEST_PASSWORD not in str(raised.value)


@pytest.mark.asyncio
async def test_missing_private_field_fails_before_network_io_and_closes_candidate() -> None:
    class MissingFieldConnection(FakeConnection):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)
            del self._password_creator

    with pytest.raises(M0DriverInvariantError, match="driver invariant"):
        await connector(factory=MissingFieldConnection).connect(
            valid_input(), register_pending=lambda _: None
        )

    raw = MissingFieldConnection.instances[0]
    assert raw.connect_client_flag is None
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_unwritable_capability_field_fails_before_network_io() -> None:
    class StickyCapabilityConnection(FakeConnection):
        def __init__(self, **kwargs: object) -> None:
            self.refuse_capability_clear = False
            super().__init__(**kwargs)
            self.refuse_capability_clear = True

        def __setattr__(self, name: str, value: object) -> None:
            if name == "_client_flag" and getattr(self, "refuse_capability_clear", False):
                value = int(value) | CLIENT_MULTI_STATEMENTS
            super().__setattr__(name, value)

    with pytest.raises(M0DriverInvariantError, match="driver invariant"):
        await connector(factory=StickyCapabilityConnection).connect(
            valid_input(), register_pending=lambda _: None
        )

    raw = StickyCapabilityConnection.instances[0]
    assert raw.connect_client_flag is None
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_failed_password_field_scrub_closes_before_identity() -> None:
    class UnscrubbablePasswordConnection(FakeConnection):
        def __init__(self, **kwargs: object) -> None:
            self.refuse_scrub = False
            super().__init__(**kwargs)
            self.refuse_scrub = True

        def __setattr__(self, name: str, value: object) -> None:
            if getattr(self, "refuse_scrub", False) and (
                (name == "_password" and value == b"")
                or (name == "_password_creator" and value is None)
            ):
                return
            super().__setattr__(name, value)

    with pytest.raises(M0DriverInvariantError, match="driver invariant"):
        await connector(factory=UnscrubbablePasswordConnection).connect(
            valid_input(), register_pending=lambda _: None
        )

    raw = UnscrubbablePasswordConnection.instances[0]
    assert raw.connect_client_flag is not None
    assert raw.executed == []
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_private_capability_layout_drift_after_connect_fails_closed() -> None:
    class DriftingLayoutConnection(FakeConnection):
        async def connect(self) -> None:
            await super().connect()
            del self._client_flag

    with pytest.raises(M0DriverInvariantError):
        await connector(factory=DriftingLayoutConnection).connect(
            valid_input(), register_pending=lambda _: None
        )

    raw = DriftingLayoutConnection.instances[0]
    assert raw.executed == []
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_connect_failure_scrubs_secret_closes_socket_and_sanitizes_error() -> None:
    FakeConnection.connect_effect = RuntimeError(f"driver leaked {TEST_PASSWORD}")

    with pytest.raises(M0TidbUnavailableError) as raised:
        await connector().connect(valid_input(), register_pending=lambda _: None)

    raw = FakeConnection.instances[0]
    assert TEST_PASSWORD not in str(raised.value)
    assert raw._password == b""
    assert raw._password_creator is None
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_connect_timeout_scrubs_and_invalidates_candidate() -> None:
    FakeConnection.connect_waiter = asyncio.Event()

    with pytest.raises(M0TidbTimeoutError):
        await connector(io_timeout_seconds=0.01).connect(
            valid_input(), register_pending=lambda _: None
        )

    raw = FakeConnection.instances[0]
    assert raw._password == b""
    assert raw._password_creator is None
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_connect_cancellation_scrubs_and_invalidates_candidate() -> None:
    FakeConnection.connect_waiter = asyncio.Event()
    operation = asyncio.create_task(
        connector().connect(valid_input(), register_pending=lambda _: None)
    )
    while not FakeConnection.instances or FakeConnection.instances[0].connect_client_flag is None:
        await asyncio.sleep(0)

    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation

    raw = FakeConnection.instances[0]
    assert raw._password == b""
    assert raw._password_creator is None
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "identity_rows",
    [
        (("8.0.36", "MySQL Community Server", "", 1),),
        (("8.0.11-TiDB-v8.5.4", "TiDB Server", "Release Version: v8.5.4", 0),),
        (("8.0.11-TiDB-v8.4.0", "TiDB Server", "Release Version: v8.4.0", 1),),
        (),
    ],
)
async def test_unsupported_or_invalid_identity_never_installs(
    identity_rows: tuple[tuple[object, ...], ...],
) -> None:
    FakeConnection.identity_rows_default = identity_rows

    with pytest.raises(M0TidbVersionUnsupportedError):
        await connector().connect(valid_input(), register_pending=lambda _: None)

    raw = FakeConnection.instances[0]
    assert raw.ensure_closed_calls + raw.close_calls >= 1


@pytest.mark.asyncio
async def test_identity_result_columns_are_fail_closed() -> None:
    class WrongColumnsCursor(FakeCursor):
        def __init__(self, connection: FakeConnection) -> None:
            super().__init__(connection)
            self.description = (("server_banner", None, None, None, None, None, None),)

    class WrongColumnsConnection(FakeConnection):
        def cursor(self) -> FakeCursor:
            return WrongColumnsCursor(self)

    with pytest.raises(M0TidbVersionUnsupportedError):
        await connector(factory=WrongColumnsConnection).connect(
            valid_input(), register_pending=lambda _: None
        )

    raw = WrongColumnsConnection.instances[0]
    assert raw.ensure_closed_calls + raw.close_calls >= 1


class StoreLiveConnection:
    def __init__(self, database: str, version: str = "8.5.4") -> None:
        self.database = database
        self.version = version
        self.close_calls = 0
        self.abort_calls = 0
        self.close_waiter: asyncio.Event | None = None

    async def close(self) -> None:
        self.close_calls += 1
        if self.close_waiter is not None:
            await self.close_waiter.wait()

    def abort(self) -> None:
        self.abort_calls += 1


class StoreConnector:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release: asyncio.Event | None = None
        self.error: BaseException | None = None
        self.created: list[StoreLiveConnection] = []

    async def connect(
        self,
        value: M0ConnectionInput,
        *,
        register_pending: Callable[[StoreLiveConnection], None],
    ) -> StoreLiveConnection:
        live = StoreLiveConnection(value.database)
        self.created.append(live)
        register_pending(live)
        self.started.set()
        if self.release is not None:
            await self.release.wait()
        if self.error is not None:
            raise self.error
        return live


def store_with(
    fake: StoreConnector,
    *,
    clock: Callable[[], datetime] = lambda: datetime(2026, 9, 3, 6, 0, tzinfo=UTC),
) -> M0ConnectionStore:
    return M0ConnectionStore(
        connector=fake,
        clock=clock,
        connection_id_factory=lambda: "conn_0123456789abcdef",
    )


@pytest.mark.asyncio
async def test_store_replaces_atomically_and_exposes_only_safe_projection() -> None:
    fake = StoreConnector()
    store = store_with(fake)

    assert await store.view() is None
    first = await store.replace(valid_input(database="first"))
    second = await store.replace(valid_input(database="second", username="another_user"))

    assert first.database == "first"
    assert second == await store.view()
    assert second.connection_id == "conn_0123456789abcdef"
    assert second.state == "ready"
    assert second.product == "tidb"
    assert second.version == "8.5.4"
    assert second.database == "second"
    assert second.tls_mode == "verify_ca"
    assert second.connected_at == datetime(2026, 9, 3, 6, 0, tzinfo=UTC)
    assert TEST_PASSWORD not in repr(second)
    assert fake.created[0].close_calls == 1
    assert fake.created[1].close_calls == 0


@pytest.mark.asyncio
async def test_failed_replacement_preserves_the_prior_ready_connection() -> None:
    fake = StoreConnector()
    store = store_with(fake)
    prior = await store.replace(valid_input(database="prior"))
    fake.error = M0TidbUnavailableError()

    with pytest.raises(M0TidbUnavailableError):
        await store.replace(valid_input(database="rejected"))

    assert await store.view() == prior
    assert fake.created[0].close_calls == 0
    assert fake.created[1].close_calls >= 1


@pytest.mark.asyncio
async def test_normal_operations_try_once_and_never_queue() -> None:
    fake = StoreConnector()
    fake.release = asyncio.Event()
    store = store_with(fake)
    replacement = asyncio.create_task(store.replace(valid_input()))
    await fake.started.wait()

    with pytest.raises(M0BusyError):
        await store.replace(valid_input(database="other"))
    with pytest.raises(M0BusyError):
        await store.disconnect()
    with pytest.raises(M0BusyError):
        async with store.use():
            raise AssertionError("busy use unexpectedly entered")

    fake.release.set()
    await replacement


@pytest.mark.asyncio
async def test_use_holds_the_same_lease_and_disconnect_is_idempotent() -> None:
    fake = StoreConnector()
    store = store_with(fake)
    await store.replace(valid_input())

    async with store.use() as client:
        assert client is fake.created[0]
        with pytest.raises(M0BusyError):
            await store.disconnect()

    await store.disconnect()
    await store.disconnect()

    assert await store.view() is None
    assert fake.created[0].close_calls == 1


@pytest.mark.asyncio
async def test_force_close_cancels_pending_generation_and_is_idempotent() -> None:
    fake = StoreConnector()
    fake.release = asyncio.Event()
    store = store_with(fake)
    replacement = asyncio.create_task(store.replace(valid_input()))
    await fake.started.wait()

    await store.force_close()
    await store.force_close()

    with pytest.raises(asyncio.CancelledError):
        await replacement
    assert await store.view() is None
    assert fake.created[0].close_calls >= 1


@pytest.mark.asyncio
async def test_force_close_clears_an_installed_connection_without_busy() -> None:
    fake = StoreConnector()
    store = store_with(fake)
    await store.replace(valid_input())

    await store.force_close()

    assert await store.view() is None
    assert fake.created[0].close_calls == 1


@pytest.mark.asyncio
async def test_force_close_deadline_aborts_a_stuck_transport() -> None:
    fake = StoreConnector()
    store = M0ConnectionStore(
        connector=fake,
        connection_id_factory=lambda: "conn_0123456789abcdef",
        cleanup_timeout_seconds=0.01,
    )
    await store.replace(valid_input())
    fake.created[0].close_waiter = asyncio.Event()

    cleanup = asyncio.create_task(store.force_close())
    await asyncio.sleep(0.03)
    completed_within_deadline = cleanup.done()
    if not cleanup.done():
        cleanup.cancel()
    await asyncio.gather(cleanup, return_exceptions=True)

    assert completed_within_deadline
    assert fake.created[0].abort_calls == 1
    assert await store.view() is None


@pytest.mark.asyncio
async def test_normal_operation_cannot_enter_during_lifecycle_cleanup() -> None:
    fake = StoreConnector()
    store = store_with(fake)
    await store.replace(valid_input())
    close_release = asyncio.Event()
    fake.created[0].close_waiter = close_release

    cleanup = asyncio.create_task(store.force_close())
    while fake.created[0].close_calls == 0:
        await asyncio.sleep(0)

    with pytest.raises(M0BusyError):
        await store.replace(valid_input(database="late"))

    close_release.set()
    await cleanup
    assert len(fake.created) == 1
    assert await store.view() is None


@pytest.mark.asyncio
async def test_use_without_a_live_connection_fails_closed_and_releases_lease() -> None:
    fake = StoreConnector()
    store = store_with(fake)

    with pytest.raises(M0TidbUnavailableError):
        async with store.use():
            raise AssertionError("disconnected use unexpectedly entered")

    await store.disconnect()


LOCAL_ORIGIN = "http://localhost:18080"
OWNER_PASSWORD = "correct-horse-battery-staple"


def authenticated_client(
    settings: Settings,
    store: M0ConnectionStore,
) -> tuple[TestClient, str]:
    client = TestClient(
        create_app(
            settings=settings,
            clock=lambda: datetime(2026, 9, 3, 6, 0, tzinfo=UTC),
            m0_connection_store=store,
        ),
        base_url=LOCAL_ORIGIN,
    )
    status = client.get("/api/v1/setup/status")
    owner = client.post(
        "/api/v1/setup/owner",
        headers={"Origin": LOCAL_ORIGIN, "X-Setup-Nonce": status.json()["setup_nonce"]},
        json={"password": OWNER_PASSWORD},
    )
    assert owner.status_code == 201
    return client, str(owner.json()["csrf_token"])


def connection_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "host": "tidb.internal.example",
        "port": 4000,
        "database": "shop",
        "username": "sqllens_ro",
        "password": TEST_PASSWORD,
        "tls_mode": "verify_ca",
    }
    payload.update(overrides)
    return payload


def test_connection_routes_require_owner_and_csrf(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", web_dist_dir=None)
    store = store_with(StoreConnector())
    anonymous = TestClient(
        create_app(settings=settings, m0_connection_store=store),
        base_url=LOCAL_ORIGIN,
    )

    assert anonymous.get("/api/v1/m0/connection").status_code == 401
    assert anonymous.put("/api/v1/m0/connection", json=connection_payload()).status_code == 401
    assert anonymous.delete("/api/v1/m0/connection").status_code == 401

    client, csrf = authenticated_client(settings, store)
    missing_csrf = client.put("/api/v1/m0/connection", json=connection_payload())
    wrong_csrf = client.delete("/api/v1/m0/connection", headers={"X-CSRF-Token": f"wrong-{csrf}"})

    assert missing_csrf.status_code == 403
    assert missing_csrf.json()["error"]["code"] == "CSRF_INVALID"
    assert wrong_csrf.status_code == 403
    assert wrong_csrf.json()["error"]["code"] == "CSRF_INVALID"


def test_put_get_delete_expose_only_safe_connection_metadata(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = Settings(data_dir=tmp_path / "data", web_dist_dir=None)
    fake = StoreConnector()
    store = store_with(fake)
    client, csrf = authenticated_client(settings, store)

    created = client.put(
        "/api/v1/m0/connection",
        headers={"X-CSRF-Token": csrf},
        json=connection_payload(),
    )

    assert created.status_code == 200
    assert created.json() == {
        "schema_version": "m0-connection/v1",
        "connection_id": "conn_0123456789abcdef",
        "state": "ready",
        "product": "tidb",
        "version": "8.5.4",
        "database": "shop",
        "tls_mode": "verify_ca",
        "connected_at": "2026-09-03T06:00:00Z",
    }
    serialized = created.content + repr(awaited_view(store)).encode()
    assert TEST_PASSWORD.encode() not in serialized
    assert b"sqllens_ro" not in serialized
    assert b"tidb.internal.example" not in serialized
    assert TEST_PASSWORD not in caplog.text
    assert TEST_PASSWORD not in os.environ.values()
    assert all(
        TEST_PASSWORD.encode() not in path.read_bytes()
        for path in settings.data_dir.rglob("*")
        if path.is_file()
    )
    assert client.get("/api/v1/m0/connection").json() == created.json()

    deleted = client.delete("/api/v1/m0/connection", headers={"X-CSRF-Token": csrf})
    repeated = client.delete("/api/v1/m0/connection", headers={"X-CSRF-Token": csrf})

    assert deleted.status_code == 204
    assert deleted.content == b""
    assert repeated.status_code == 204
    assert client.get("/api/v1/m0/connection").json() == {
        "schema_version": "m0-connection/v1",
        "state": "disconnected",
    }


def test_application_shutdown_force_closes_the_live_connection(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", web_dist_dir=None)
    fake = StoreConnector()
    store = store_with(fake)
    app = create_app(
        settings=settings,
        clock=lambda: datetime(2026, 9, 3, 6, 0, tzinfo=UTC),
        m0_connection_store=store,
    )

    with TestClient(app, base_url=LOCAL_ORIGIN) as client:
        status = client.get("/api/v1/setup/status")
        owner = client.post(
            "/api/v1/setup/owner",
            headers={"Origin": LOCAL_ORIGIN, "X-Setup-Nonce": status.json()["setup_nonce"]},
            json={"password": OWNER_PASSWORD},
        )
        connected = client.put(
            "/api/v1/m0/connection",
            headers={"X-CSRF-Token": owner.json()["csrf_token"]},
            json=connection_payload(),
        )
        assert connected.status_code == 200
        assert fake.created[0].close_calls == 0

    assert fake.created[0].close_calls == 1
    assert awaited_view(store) is None


def awaited_view(store: M0ConnectionStore) -> object:
    return asyncio.run(store.view())


def test_connection_route_rejects_oversized_or_open_bodies_before_connect(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", web_dist_dir=None)
    fake = StoreConnector()
    store = store_with(fake)
    client, csrf = authenticated_client(settings, store)

    oversized = client.put(
        "/api/v1/m0/connection",
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
        content=b'{"password":"' + b"x" * 5000 + b'"}',
    )
    extra = client.put(
        "/api/v1/m0/connection",
        headers={"X-CSRF-Token": csrf},
        json=connection_payload(source_id="forbidden"),
    )

    assert oversized.status_code == 422
    assert oversized.json()["error"]["code"] == "VALIDATION_ERROR"
    assert extra.status_code == 422
    assert extra.json()["error"]["code"] == "VALIDATION_ERROR"
    assert fake.created == []


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (M0BusyError(), 409, "M0_BUSY"),
        (M0TidbUnavailableError(), 502, "M0_TIDB_UNAVAILABLE"),
        (M0TidbTimeoutError(), 504, "M0_TIDB_TIMEOUT"),
        (M0TidbVersionUnsupportedError(), 422, "M0_TIDB_VERSION_UNSUPPORTED"),
        (M0DriverInvariantError(), 502, "M0_TIDB_UNAVAILABLE"),
    ],
)
def test_connection_route_maps_only_closed_error_codes(
    tmp_path: Path,
    error: BaseException,
    status: int,
    code: str,
) -> None:
    settings = Settings(data_dir=tmp_path / "data", web_dist_dir=None)
    fake = StoreConnector()
    fake.error = error
    store = store_with(fake)
    client, csrf = authenticated_client(settings, store)

    response = client.put(
        "/api/v1/m0/connection",
        headers={"X-CSRF-Token": csrf},
        json=connection_payload(),
    )

    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert response.json()["error"].keys() == {"version", "code", "message", "request_id"}
    assert TEST_PASSWORD not in response.text
