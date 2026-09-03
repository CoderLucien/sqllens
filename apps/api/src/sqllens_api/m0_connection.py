from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import metadata
from typing import Literal, Protocol, cast

from asyncmy.connection import Connection as AsyncmyConnection
from asyncmy.constants import CLIENT
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from sqllens_api.evidence_connector import (
    DatabaseProduct,
    DetectionStatus,
    QueryResult,
    VersionFingerprint,
    detect_database_version,
    query_pack,
    validate_server_query,
)

ASYNCMY_VERSION = "0.2.14"
CLIENT_MULTI_STATEMENTS = int(CLIENT.MULTI_STATEMENTS)
M0_IO_TIMEOUT_SECONDS = 5.0
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class M0ConnectionInput(BaseModel):
    """Closed, secret-safe request model for the one ephemeral TiDB connection."""

    model_config = ConfigDict(extra="forbid", strict=True)

    host: str
    port: int = Field(ge=1, le=65_535)
    database: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr
    tls_mode: Literal["verify_ca", "disabled"]

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if not 1 <= len(value) <= 253 or not value.isascii() or value != value.strip():
            raise ValueError("host must be an ASCII DNS name or IP literal")
        if any(character in value for character in ("/", "@", "\x00", "[", "]")):
            raise ValueError("host must be an ASCII DNS name or IP literal")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            labels = value.split(".")
            if any(not _DNS_LABEL.fullmatch(label) for label in labels):
                raise ValueError("host must be an ASCII DNS name or IP literal") from None
        return value

    @field_validator("database", "username")
    @classmethod
    def validate_identifier_text(cls, value: str) -> str:
        if value != value.strip() or any(
            unicodedata.category(character).startswith("C") for character in value
        ):
            raise ValueError("identifier contains whitespace padding or control characters")
        return value

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, value: SecretStr) -> SecretStr:
        byte_length = len(value.get_secret_value().encode("utf-8"))
        if not 1 <= byte_length <= 512:
            raise ValueError("password must encode to between 1 and 512 UTF-8 bytes")
        return value


class M0DriverInvariantError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("The pinned TiDB driver invariant could not be verified.")


class M0TidbUnavailableError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("The TiDB connection is unavailable.")


class M0TidbTimeoutError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("The TiDB connection timed out.")


class M0TidbVersionUnsupportedError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("The database is not a supported TiDB 8.5.x server.")


class _DriverCursor(Protocol):
    description: tuple[tuple[object, ...], ...] | None

    async def __aenter__(self) -> _DriverCursor: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None: ...

    async def execute(self, query: str, args: object = None) -> object: ...

    async def fetchmany(self, size: int | None = None) -> list[tuple[object, ...]]: ...


class _DriverConnection(Protocol):
    _client_flag: int
    _password: object
    _password_creator: object

    async def connect(self) -> None: ...

    def cursor(self) -> _DriverCursor: ...

    async def ensure_closed(self) -> None: ...

    def close(self) -> None: ...


type _ConnectionFactory = Callable[..., _DriverConnection]
type _VersionReader = Callable[[str], str]
type _PendingRegistrar = Callable[[M0LiveConnection], None]
_DEFAULT_CONNECTION_FACTORY = cast(_ConnectionFactory, AsyncmyConnection)


@dataclass(slots=True)
class M0LiveConnection:
    """A connected socket with only safe metadata visible to its owner."""

    database: str
    _raw: _DriverConnection = field(repr=False)
    _io_timeout_seconds: float = field(repr=False)
    version: str | None = None
    _closed: bool = field(default=False, init=False, repr=False)
    _close_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def close(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            try:
                async with asyncio.timeout(self._io_timeout_seconds):
                    await self._raw.ensure_closed()
            except BaseException:
                self._raw.close()
            finally:
                self._closed = True

    def abort(self) -> None:
        if not self._closed:
            self._raw.close()
            self._closed = True

    async def probe_identity(self) -> str:
        query = query_pack("tidb-8.5")["server.identity"]
        validate_server_query(query)
        if self._raw._client_flag & CLIENT_MULTI_STATEMENTS:
            raise M0DriverInvariantError
        try:
            async with asyncio.timeout(self._io_timeout_seconds):
                async with self._raw.cursor() as cursor:
                    await cursor.execute(query.sql)
                    rows = await cursor.fetchmany(query.budget.max_rows + 1)
                    columns = _cursor_columns(cursor.description)
        except TimeoutError:
            raise M0TidbTimeoutError from None
        except asyncio.CancelledError:
            raise
        except M0DriverInvariantError:
            raise
        except BaseException:
            raise M0TidbUnavailableError from None

        result = QueryResult(
            columns=columns,
            rows=_normalize_rows(columns, rows),
            truncated=len(rows) > query.budget.max_rows,
            observed_bytes=0,
            elapsed_ms=0,
        )
        if (
            columns != query.result_columns
            or len(rows) != 1
            or len(result.rows) != 1
            or result.truncated
        ):
            raise M0TidbVersionUnsupportedError
        row = result.rows[0]
        version = row.get("version")
        version_comment = row.get("version_comment")
        tidb_version = row.get("tidb_version")
        autocommit = row.get("autocommit")
        if (
            not isinstance(version, str)
            or not isinstance(version_comment, str)
            or not isinstance(tidb_version, str)
            or type(autocommit) is not int
            or autocommit != 1
        ):
            raise M0TidbVersionUnsupportedError
        detected = detect_database_version(
            VersionFingerprint(
                version=version,
                version_comment=version_comment,
                tidb_version=tidb_version,
            )
        )
        if (
            detected.status is not DetectionStatus.SUPPORTED
            or detected.product is not DatabaseProduct.TIDB
            or detected.pack_id != "tidb-8.5"
            or detected.version is None
        ):
            raise M0TidbVersionUnsupportedError
        self.version = detected.version
        return detected.version


def _cursor_columns(description: tuple[tuple[object, ...], ...] | None) -> tuple[str, ...]:
    if description is None:
        return ()
    columns: list[str] = []
    for item in description:
        if not item or not isinstance(item[0], str):
            return ()
        columns.append(item[0].lower())
    return tuple(columns)


def _normalize_rows(
    columns: tuple[str, ...],
    rows: list[tuple[object, ...]],
) -> tuple[dict[str, str | int | float | bool | None], ...]:
    normalized: list[dict[str, str | int | float | bool | None]] = []
    for row in rows:
        if len(row) != len(columns) or any(
            value is not None and not isinstance(value, (str, int, float, bool))
            for value in row
        ):
            continue
        values = cast(tuple[str | int | float | bool | None, ...], row)
        normalized.append(dict(zip(columns, values, strict=True)))
    return tuple(normalized)


class AsyncmyM0Connector:
    """Exact-version compatibility adapter frozen by runtime addendum fe1440b."""

    def __init__(
        self,
        *,
        connection_factory: _ConnectionFactory = _DEFAULT_CONNECTION_FACTORY,
        version_reader: _VersionReader = metadata.version,
        ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
        io_timeout_seconds: float = M0_IO_TIMEOUT_SECONDS,
    ) -> None:
        self._connection_factory = connection_factory
        self._version_reader = version_reader
        self._ssl_context_factory = ssl_context_factory
        self._io_timeout_seconds = io_timeout_seconds

    async def connect(
        self,
        value: M0ConnectionInput,
        *,
        register_pending: _PendingRegistrar,
    ) -> M0LiveConnection:
        if self._version_reader("asyncmy") != ASYNCMY_VERSION:
            raise M0DriverInvariantError

        password_bytes = value.password.get_secret_value().encode("utf-8")
        tls_context: ssl.SSLContext | None = None
        if value.tls_mode == "verify_ca":
            tls_context = self._ssl_context_factory()
            if (
                not isinstance(tls_context, ssl.SSLContext)
                or tls_context.verify_mode is not ssl.CERT_REQUIRED
                or tls_context.check_hostname is not True
            ):
                raise M0DriverInvariantError

        raw: _DriverConnection | None = None
        live: M0LiveConnection | None = None
        try:
            raw = self._connection_factory(
                host=value.host,
                port=value.port,
                database=value.database,
                user=value.username,
                password=password_bytes,
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
                ssl=tls_context,
            )
            _prepare_private_driver_fields(raw)
            live = M0LiveConnection(
                database=value.database,
                _raw=raw,
                _io_timeout_seconds=self._io_timeout_seconds,
            )
            register_pending(live)
        except M0DriverInvariantError:
            if raw is not None:
                await _close_untrusted_driver(raw, self._io_timeout_seconds)
            raise
        except asyncio.CancelledError:
            if live is not None:
                await live.close()
            raise
        except BaseException:
            if raw is not None:
                await _close_untrusted_driver(raw, self._io_timeout_seconds)
            raise M0TidbUnavailableError from None

        connect_error: BaseException | None = None
        try:
            async with asyncio.timeout(self._io_timeout_seconds):
                await raw.connect()
        except BaseException as error:
            connect_error = error
        try:
            _scrub_private_password_fields(raw)
        except M0DriverInvariantError:
            await live.close()
            raise

        if connect_error is not None:
            await live.close()
            if isinstance(connect_error, asyncio.CancelledError):
                raise connect_error
            if isinstance(connect_error, TimeoutError):
                raise M0TidbTimeoutError from None
            raise M0TidbUnavailableError from None

        try:
            await live.probe_identity()
        except BaseException:
            await live.close()
            raise
        return live


def _prepare_private_driver_fields(connection: _DriverConnection) -> None:
    try:
        client_flag = connection._client_flag
        password = connection._password
        password_creator = connection._password_creator
        connection._password = password
        connection._password_creator = password_creator
        if connection._password != password or connection._password_creator is not password_creator:
            raise M0DriverInvariantError
        connection._client_flag = client_flag & ~CLIENT_MULTI_STATEMENTS
        if connection._client_flag & CLIENT_MULTI_STATEMENTS:
            raise M0DriverInvariantError
    except M0DriverInvariantError:
        raise
    except BaseException:
        raise M0DriverInvariantError from None


def _scrub_private_password_fields(connection: _DriverConnection) -> None:
    try:
        connection._password = b""
        connection._password_creator = None
        if connection._password != b"" or connection._password_creator is not None:
            raise M0DriverInvariantError
    except M0DriverInvariantError:
        raise
    except BaseException:
        raise M0DriverInvariantError from None


async def _close_untrusted_driver(
    connection: _DriverConnection,
    timeout_seconds: float,
) -> None:
    try:
        async with asyncio.timeout(timeout_seconds):
            await connection.ensure_closed()
    except BaseException:
        connection.close()
