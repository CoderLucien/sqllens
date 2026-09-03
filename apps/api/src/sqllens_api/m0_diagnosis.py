from __future__ import annotations

import asyncio
import re
import secrets
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import cast

from sqllens_api.evidence_connector import MAX_SAFE_INTEGER, JsonValue, QueryResult, query_pack
from sqllens_api.m0_connection import (
    M0BusyError,
    M0ConnectionStore,
    M0DriverInvariantError,
    M0TidbTimeoutError,
    M0TidbUnavailableError,
)

M0_MIN_WINDOW_MINUTES = 5
M0_MAX_WINDOW_MINUTES = 60
_SQL_DIGEST = re.compile(r"^[0-9a-f]{64}$")

type Clock = Callable[[], datetime]
type ExecutionIdFactory = Callable[[], str]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _execution_id() -> str:
    return f"exec_{secrets.token_hex(8)}"


class M0ConnectionRequiredError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("A live TiDB connection is required.")


class M0DiagnosisService:
    """Request-local candidate discovery and diagnosis orchestration."""

    def __init__(
        self,
        *,
        store: M0ConnectionStore,
        clock: Clock = _utc_now,
        execution_id_factory: ExecutionIdFactory = _execution_id,
    ) -> None:
        self._store = store
        self._clock = clock
        self._execution_id_factory = execution_id_factory

    async def list_candidates(self, window_minutes: int) -> dict[str, JsonValue]:
        if (
            isinstance(window_minutes, bool)
            or not isinstance(window_minutes, int)
            or not M0_MIN_WINDOW_MINUTES <= window_minutes <= M0_MAX_WINDOW_MINUTES
        ):
            raise ValueError("candidate window is invalid")
        collected_at = _aware_utc(self._clock())
        window_start = collected_at - timedelta(minutes=window_minutes)
        query = query_pack("tidb-8.5")["sql_candidates.current_user"]
        parameters = {
            "window_start": _format_time(window_start),
            "window_end": _format_time(collected_at),
            "schema_name": "",
        }
        try:
            view = await self._store.view()
            if view is None:
                raise M0ConnectionRequiredError
            async with self._store.use() as client:
                leased_view = await self._store.view()
                if leased_view is None:
                    raise M0TidbUnavailableError
                parameters["schema_name"] = leased_view.database
                result = await client.execute(
                    execution_id=self._execution_id_factory(),
                    query=query,
                    parameters=parameters,
                )
            items = _project_candidates(
                result,
                query=query,
                window_start=window_start,
                window_end=collected_at,
            )
        except M0BusyError:
            raise
        except M0ConnectionRequiredError:
            raise
        except asyncio.CancelledError:
            await asyncio.shield(self._store.force_close())
            raise
        except M0TidbTimeoutError:
            await self._store.force_close()
            raise
        except (M0DriverInvariantError, M0TidbUnavailableError):
            await self._store.force_close()
            raise M0TidbUnavailableError from None
        return {
            "schema_version": "m0-sql-candidates/v1",
            "window_minutes": window_minutes,
            "collected_at": _format_time(collected_at),
            "truncated": (
                result.truncated
                or len(result.rows) == query.budget.max_rows
                or result.observed_bytes == query.budget.max_bytes
            ),
            "items": items,
        }


def _project_candidates(
    result: QueryResult,
    *,
    query: object,
    window_start: datetime,
    window_end: datetime,
) -> list[JsonValue]:
    registered = query_pack("tidb-8.5")["sql_candidates.current_user"]
    if query != registered:
        raise M0DriverInvariantError
    if (
        result.columns != registered.result_columns
        or not isinstance(result.truncated, bool)
        or not _bounded_integer(result.elapsed_ms, lower=0, upper=registered.budget.timeout_ms)
        or not _bounded_integer(
            result.observed_bytes,
            lower=1,
            upper=registered.budget.max_bytes,
        )
        or len(result.rows) > registered.budget.max_rows
    ):
        raise M0TidbUnavailableError

    items: list[JsonValue] = []
    seen_digests: set[str] = set()
    expected_columns = set(registered.result_columns)
    for row in result.rows:
        if not isinstance(row, Mapping) or set(row) != expected_columns:
            raise M0TidbUnavailableError
        digest = row["sql_digest"]
        if not isinstance(digest, str) or not _SQL_DIGEST.fullmatch(digest):
            raise M0TidbUnavailableError
        if digest in seen_digests:
            raise M0TidbUnavailableError
        seen_digests.add(digest)
        execution_count = _required_integer(row["execution_count"], lower=1)
        p95_ms = _required_integer(row["p95_ms"], lower=0)
        average_scan_rows = _required_integer(row["average_scan_rows"], lower=0)
        average_return_rows = _required_integer(row["average_return_rows"], lower=0)
        last_seen_ms = _required_integer(row["last_seen"], lower=0)
        try:
            last_seen = datetime.fromtimestamp(last_seen_ms / 1_000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            raise M0TidbUnavailableError from None
        if not window_start <= last_seen <= window_end:
            raise M0TidbUnavailableError
        items.append(
            {
                "sql_digest": digest,
                "execution_count": execution_count,
                "p95_ms": p95_ms,
                "average_scan_rows": average_scan_rows,
                "average_return_rows": average_return_rows,
                "last_seen": _format_time(last_seen),
            }
        )
    return items


def _required_integer(value: object, *, lower: int) -> int:
    if not _bounded_integer(value, lower=lower, upper=MAX_SAFE_INTEGER):
        raise M0TidbUnavailableError
    return cast(int, value)


def _bounded_integer(value: object, *, lower: int, upper: int) -> bool:
    return type(value) is int and lower <= value <= upper


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise M0DriverInvariantError
    return value.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
