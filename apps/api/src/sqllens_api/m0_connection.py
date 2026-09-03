from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import secrets
import ssl
import time
import unicodedata
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from importlib import metadata
from typing import Literal, Protocol, cast

from asyncmy.connection import Connection as AsyncmyConnection
from asyncmy.constants import CLIENT, SERVER_STATUS
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from sqllens_api.evidence_connector import (
    MAX_SAFE_INTEGER,
    DatabaseProduct,
    DetectionStatus,
    JsonValue,
    QueryResult,
    QueryValue,
    ReadOnlyQueryClient,
    ServerQuery,
    UnsafeServerQueryError,
    ValidatedM0Select,
    VersionFingerprint,
    bind_m0_ordinary_explain,
    detect_database_version,
    query_pack,
    strict_json_bytes,
    validate_server_query,
)
from sqllens_api.evidence_connector.queries import _validate_bound_server_query

ASYNCMY_VERSION = "0.2.14"
CLIENT_MULTI_STATEMENTS = int(CLIENT.MULTI_STATEMENTS)
SERVER_STATUS_NO_BACKSLASH_ESCAPES = int(SERVER_STATUS.SERVER_STATUS_NO_BACKSLASH_ESCAPES)
M0_IO_TIMEOUT_SECONDS = 5.0
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_EXECUTION_ID = re.compile(r"^exec_[a-f0-9]{16,64}$")
_NAMED_PARAMETER = re.compile(r":([a-z][a-z0-9_]*)\b")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


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


class M0BusyError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Another M0 database operation is already running.")


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

    def mogrify(self, query: str, args: object = None) -> str: ...

    async def fetchmany(self, size: int | None = None) -> list[tuple[object, ...]]: ...


class _DriverConnection(Protocol):
    _client_flag: int
    _password: object
    _password_creator: object
    server_status: int

    async def connect(self) -> None: ...

    def cursor(self) -> _DriverCursor: ...

    async def ensure_closed(self) -> None: ...

    def close(self) -> None: ...


type _ConnectionFactory = Callable[..., _DriverConnection]
type _VersionReader = Callable[[str], str]
type _PendingRegistrar = Callable[[M0LiveConnection], None]
_DEFAULT_CONNECTION_FACTORY = cast(_ConnectionFactory, AsyncmyConnection)


class _ManagedConnection(Protocol):
    database: str
    version: str | None

    async def close(self) -> None: ...

    def abort(self) -> None: ...


class _ManagedConnector(Protocol):
    async def connect(
        self,
        value: M0ConnectionInput,
        *,
        register_pending: Callable[[_ManagedConnection], None],
    ) -> _ManagedConnection: ...


@dataclass(frozen=True, slots=True)
class M0ConnectionView:
    connection_id: str
    state: Literal["ready"]
    product: Literal["tidb"]
    version: str
    database: str
    tls_mode: Literal["verify_ca", "disabled"]
    connected_at: datetime


@dataclass(slots=True)
class M0LiveConnection:
    """A connected socket with only safe metadata visible to its owner."""

    database: str
    _raw: _DriverConnection = field(repr=False)
    _io_timeout_seconds: float = field(repr=False)
    version: str | None = None
    _closed: bool = field(default=False, init=False, repr=False)
    _close_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _active_execution_id: str | None = field(default=None, init=False, repr=False)

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
        _require_single_statement_capability(self._raw)
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

    async def execute(
        self,
        *,
        execution_id: str,
        query: ServerQuery,
        parameters: Mapping[str, QueryValue],
    ) -> QueryResult:
        """Execute one exact immutable query card with bound values."""

        try:
            registered = query_pack("tidb-8.5").get(query.query_id)
            validate_server_query(query)
        except (TypeError, ValueError, UnsafeServerQueryError):
            raise M0DriverInvariantError from None
        if registered != query:
            raise M0DriverInvariantError
        return await self._execute_bound(
            execution_id=execution_id,
            query=query,
            parameters=parameters,
        )

    async def execute_ordinary_explain(
        self,
        *,
        execution_id: str,
        value: ValidatedM0Select,
    ) -> QueryResult:
        """Execute only the ordinary EXPLAIN rebuilt by the frozen binder."""

        if value.database != self.database:
            raise M0DriverInvariantError
        try:
            query = bind_m0_ordinary_explain(value)
        except (TypeError, ValueError, UnsafeServerQueryError):
            raise M0DriverInvariantError from None
        return await self._execute_bound(
            execution_id=execution_id,
            query=query,
            parameters={},
        )

    async def cancel(self, execution_id: str) -> None:
        """Abort the socket when the exact active execution is cancelled."""

        if execution_id == self._active_execution_id:
            self.abort()

    async def _execute_bound(
        self,
        *,
        execution_id: str,
        query: ServerQuery,
        parameters: Mapping[str, QueryValue],
    ) -> QueryResult:
        template, arguments = _bind_driver_parameters(query, parameters)
        if not _EXECUTION_ID.fullmatch(execution_id) or self._active_execution_id is not None:
            raise M0DriverInvariantError
        if self._closed:
            raise M0TidbUnavailableError

        self._active_execution_id = execution_id
        started = time.monotonic_ns()
        try:
            _require_single_statement_capability(self._raw)
            timeout_seconds = min(
                self._io_timeout_seconds,
                query.budget.timeout_ms / 1_000,
            )
            async with asyncio.timeout(timeout_seconds):
                async with self._raw.cursor() as cursor:
                    bound_sql = cursor.mogrify(template, arguments or None)
                    _validate_driver_bound_sql(
                        query,
                        bound_sql,
                        backslash_escapes=_driver_uses_backslash_escapes(self._raw),
                    )
                    _require_single_statement_capability(self._raw)
                    await cursor.execute(template, arguments or None)
                    rows = await cursor.fetchmany(query.budget.max_rows + 1)
                    columns = _cursor_columns(cursor.description)
            elapsed_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
            return _build_query_result(
                query=query,
                columns=columns,
                rows=rows,
                elapsed_ms=elapsed_ms,
            )
        except TimeoutError:
            await self.close()
            raise M0TidbTimeoutError from None
        except asyncio.CancelledError:
            self.abort()
            raise
        except M0DriverInvariantError:
            await self.close()
            raise
        except BaseException:
            await self.close()
            raise M0TidbUnavailableError from None
        finally:
            self._active_execution_id = None


def _bind_driver_parameters(
    query: ServerQuery,
    parameters: Mapping[str, QueryValue],
) -> tuple[str, tuple[QueryValue, ...]]:
    if not isinstance(parameters, Mapping) or set(parameters) != set(query.parameters):
        raise M0DriverInvariantError
    ordered_names: list[str] = []

    def replace_parameter(match: re.Match[str]) -> str:
        ordered_names.append(match.group(1))
        return "%s"

    template = _NAMED_PARAMETER.sub(replace_parameter, query.sql)
    if tuple(ordered_names) != query.parameters:
        raise M0DriverInvariantError
    arguments: list[QueryValue] = []
    for name in ordered_names:
        value = parameters[name]
        if value is not None and type(value) not in (str, int, float, bool):
            raise M0DriverInvariantError
        if isinstance(value, float) and not math.isfinite(value):
            raise M0DriverInvariantError
        arguments.append(value)
    return template, tuple(arguments)


def _validate_driver_bound_sql(
    query: ServerQuery,
    bound_sql: str,
    *,
    backslash_escapes: bool,
) -> None:
    try:
        _validate_bound_server_query(
            query,
            bound_sql,
            backslash_escapes=backslash_escapes,
        )
    except UnsafeServerQueryError:
        raise M0DriverInvariantError from None


def _driver_uses_backslash_escapes(raw: _DriverConnection) -> bool:
    try:
        server_status = raw.server_status
    except (AttributeError, RuntimeError):
        raise M0DriverInvariantError from None
    if type(server_status) is not int or server_status < 0:
        raise M0DriverInvariantError
    return not bool(server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES)


def _build_query_result(
    *,
    query: ServerQuery,
    columns: tuple[str, ...],
    rows: list[tuple[object, ...]],
    elapsed_ms: int,
) -> QueryResult:
    if columns != query.result_columns or len(rows) > query.budget.max_rows + 1:
        raise M0TidbUnavailableError
    normalized_rows: list[dict[str, QueryValue]] = []
    for row in rows[: query.budget.max_rows]:
        if not isinstance(row, tuple) or len(row) != len(columns):
            raise M0TidbUnavailableError
        normalized_rows.append(
            {
                column: _normalize_query_value(value)
                for column, value in zip(columns, row, strict=True)
            }
        )
    try:
        observed_bytes = len(
            strict_json_bytes(
                cast(
                    JsonValue,
                    {
                        "columns": list(columns),
                        "rows": normalized_rows,
                    },
                )
            )
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise M0TidbUnavailableError from None
    if observed_bytes > query.budget.max_bytes:
        raise M0TidbUnavailableError
    return QueryResult(
        columns=columns,
        rows=tuple(normalized_rows),
        truncated=len(rows) > query.budget.max_rows,
        observed_bytes=observed_bytes,
        elapsed_ms=elapsed_ms,
    )


def _normalize_query_value(value: object) -> QueryValue:
    if value is None or type(value) in (str, bool):
        return cast(QueryValue, value)
    if type(value) is int:
        integer = value
        if abs(integer) > MAX_SAFE_INTEGER:
            raise M0TidbUnavailableError
        return integer
    if type(value) is float:
        number = value
        if not math.isfinite(number):
            raise M0TidbUnavailableError
        return number
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise M0TidbUnavailableError
        if value == value.to_integral_value():
            integer = int(value)
            if abs(integer) > MAX_SAFE_INTEGER:
                raise M0TidbUnavailableError
            return integer
        number = float(value)
        if not math.isfinite(number):
            raise M0TidbUnavailableError
        return number
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise M0TidbUnavailableError
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    raise M0TidbUnavailableError


def _cursor_columns(description: tuple[tuple[object, ...], ...] | None) -> tuple[str, ...]:
    if description is None:
        return ()
    columns: list[str] = []
    for item in description:
        if not item or not isinstance(item[0], str):
            return ()
        raw_name = item[0].strip()
        normalized = _CAMEL_BOUNDARY.sub("_", raw_name).lower().replace(" ", "_")
        columns.append(normalized)
    return tuple(columns)


def _normalize_rows(
    columns: tuple[str, ...],
    rows: list[tuple[object, ...]],
) -> tuple[dict[str, str | int | float | bool | None], ...]:
    normalized: list[dict[str, str | int | float | bool | None]] = []
    for row in rows:
        if len(row) != len(columns) or any(
            value is not None and not isinstance(value, (str, int, float, bool)) for value in row
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
        try:
            installed_version = self._version_reader("asyncmy")
        except Exception:
            raise M0DriverInvariantError from None
        if installed_version != ASYNCMY_VERSION:
            raise M0DriverInvariantError

        password_bytes = value.password.get_secret_value().encode("utf-8")
        tls_context: ssl.SSLContext | None = None
        if value.tls_mode == "verify_ca":
            try:
                tls_context = self._ssl_context_factory()
            except Exception:
                raise M0TidbUnavailableError from None
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
        finally:
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


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _connection_id() -> str:
    return f"conn_{secrets.token_hex(8)}"


class M0ConnectionStore:
    """Own exactly one live, process-local TiDB connection."""

    def __init__(
        self,
        *,
        connector: _ManagedConnector | None = None,
        clock: Callable[[], datetime] = _utc_now,
        connection_id_factory: Callable[[], str] = _connection_id,
        cleanup_timeout_seconds: float = M0_IO_TIMEOUT_SECONDS,
    ) -> None:
        self._connector = connector or cast(_ManagedConnector, AsyncmyM0Connector())
        self._clock = clock
        self._connection_id_factory = connection_id_factory
        self._cleanup_timeout_seconds = cleanup_timeout_seconds
        self._generation = 0
        self._busy = False
        self._active_task: asyncio.Task[object] | None = None
        self._pending: _ManagedConnection | None = None
        self._live: _ManagedConnection | None = None
        self._view: M0ConnectionView | None = None
        self._lifecycle_closing = False
        self._lifecycle_lock = asyncio.Lock()

    async def replace(self, value: M0ConnectionInput) -> M0ConnectionView:
        task, generation = self._claim_operation()
        try:

            def register_pending(connection: _ManagedConnection) -> None:
                if generation != self._generation:
                    raise asyncio.CancelledError
                self._pending = connection

            candidate = await self._connector.connect(
                value,
                register_pending=register_pending,
            )
            if generation != self._generation:
                await _safe_close(candidate, self._cleanup_timeout_seconds)
                raise asyncio.CancelledError
            if candidate.version is None:
                await _safe_close(candidate, self._cleanup_timeout_seconds)
                raise M0TidbUnavailableError

            connected_at = self._clock()
            if connected_at.tzinfo is None:
                await _safe_close(candidate, self._cleanup_timeout_seconds)
                raise M0DriverInvariantError
            view = M0ConnectionView(
                connection_id=self._connection_id_factory(),
                state="ready",
                product="tidb",
                version=candidate.version,
                database=candidate.database,
                tls_mode=value.tls_mode,
                connected_at=connected_at.astimezone(UTC),
            )
            replaced = self._live
            self._live = candidate
            self._view = view
            if self._pending is candidate:
                self._pending = None
            if replaced is not None and replaced is not candidate:
                await _safe_close(replaced, self._cleanup_timeout_seconds)
            return view
        finally:
            pending = self._pending
            if pending is not None and pending is not self._live:
                self._pending = None
                await _safe_close(pending, self._cleanup_timeout_seconds)
            self._release_operation(task)

    async def view(self) -> M0ConnectionView | None:
        return self._view

    @asynccontextmanager
    async def use(self) -> AsyncIterator[ReadOnlyQueryClient]:
        task, _generation = self._claim_operation()
        try:
            if self._live is None:
                raise M0TidbUnavailableError
            yield cast(ReadOnlyQueryClient, self._live)
        finally:
            self._release_operation(task)

    async def disconnect(self) -> None:
        task, _generation = self._claim_operation()
        try:
            live = self._live
            self._live = None
            self._view = None
            if live is not None:
                await _safe_close(live, self._cleanup_timeout_seconds)
        finally:
            self._release_operation(task)

    async def force_close(self) -> None:
        async with self._lifecycle_lock:
            self._lifecycle_closing = True
            try:
                self._generation += 1
                current = asyncio.current_task()
                active = self._active_task
                pending = self._pending
                live = self._live
                self._pending = None
                self._live = None
                self._view = None

                if active is not None and active is not current and not active.done():
                    active.cancel()
                resources = {id(resource): resource for resource in (pending, live) if resource}
                for resource in resources.values():
                    await _safe_close(resource, self._cleanup_timeout_seconds)

                if active is not None and active is not current and not active.done():
                    try:
                        async with asyncio.timeout(self._cleanup_timeout_seconds):
                            await active
                    except BaseException:
                        active.cancel()
                if self._active_task is active:
                    self._active_task = None
                    self._busy = False
            finally:
                self._lifecycle_closing = False

    def _claim_operation(self) -> tuple[asyncio.Task[object], int]:
        if self._busy or self._lifecycle_closing:
            raise M0BusyError
        task = asyncio.current_task()
        if task is None:
            raise M0DriverInvariantError
        self._busy = True
        self._active_task = cast(asyncio.Task[object], task)
        return cast(asyncio.Task[object], task), self._generation

    def _release_operation(self, task: asyncio.Task[object]) -> None:
        if self._active_task is task:
            self._active_task = None
            self._busy = False


async def _safe_close(
    connection: _ManagedConnection,
    timeout_seconds: float = M0_IO_TIMEOUT_SECONDS,
) -> None:
    try:
        async with asyncio.timeout(timeout_seconds):
            await connection.close()
    except asyncio.CancelledError:
        connection.abort()
        raise
    except BaseException:
        connection.abort()


def _prepare_private_driver_fields(connection: _DriverConnection) -> None:
    try:
        client_flag = connection._client_flag
        password = connection._password
        password_creator = connection._password_creator
        connection._password = password
        connection._password_creator = password_creator
        if connection._password != password or connection._password_creator is not password_creator:
            raise M0DriverInvariantError
        expected_client_flag = client_flag & ~CLIENT_MULTI_STATEMENTS
        connection._client_flag = expected_client_flag
        if (
            connection._client_flag != expected_client_flag
            or connection._client_flag & CLIENT_MULTI_STATEMENTS
        ):
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


def _require_single_statement_capability(connection: _DriverConnection) -> None:
    try:
        client_flag = connection._client_flag
    except Exception:
        raise M0DriverInvariantError from None
    if type(client_flag) is not int or client_flag & CLIENT_MULTI_STATEMENTS:
        raise M0DriverInvariantError


async def _close_untrusted_driver(
    connection: _DriverConnection,
    timeout_seconds: float,
) -> None:
    try:
        async with asyncio.timeout(timeout_seconds):
            await connection.ensure_closed()
    except BaseException:
        connection.close()
