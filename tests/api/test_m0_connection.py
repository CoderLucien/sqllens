from __future__ import annotations

import asyncio
import ssl
from collections.abc import Callable
from typing import Any, ClassVar

import pytest
from asyncmy.connection import Connection
from asyncmy.constants import CLIENT
from pydantic import ValidationError
from sqllens_api.m0_connection import (
    ASYNCMY_VERSION,
    CLIENT_MULTI_STATEMENTS,
    AsyncmyM0Connector,
    M0ConnectionInput,
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
