from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Header, Request
from pydantic import ValidationError
from starlette.responses import JSONResponse, Response

from sqllens_api.errors import ApiError
from sqllens_api.m0_connection import (
    M0BusyError,
    M0ConnectionInput,
    M0ConnectionStore,
    M0ConnectionView,
    M0DriverInvariantError,
    M0TidbTimeoutError,
    M0TidbUnavailableError,
    M0TidbVersionUnsupportedError,
)

M0_CONNECTION_BODY_LIMIT = 4096

type RequireOwner = Callable[[Request], str]
type RequireOwnerCsrf = Callable[[Request, str | None], str]


def register_m0_connection_routes(
    app: FastAPI,
    *,
    store: M0ConnectionStore,
    require_owner: RequireOwner,
    require_owner_csrf: RequireOwnerCsrf,
) -> None:
    """Register only the bounded M0 ephemeral-connection surface."""

    @app.get("/api/v1/m0/connection")
    async def get_m0_connection(request: Request) -> JSONResponse:
        require_owner(request)
        return JSONResponse(content=_connection_payload(await store.view()))

    @app.put("/api/v1/m0/connection")
    async def put_m0_connection(
        request: Request,
        x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    ) -> JSONResponse:
        require_owner_csrf(request, x_csrf_token)
        value = await _parse_connection_input(request)
        try:
            view = await store.replace(value)
        except M0BusyError:
            raise ApiError(409, "M0_BUSY", "Another M0 operation is already running.") from None
        except M0TidbVersionUnsupportedError:
            raise ApiError(
                422,
                "M0_TIDB_VERSION_UNSUPPORTED",
                "The database is not a supported TiDB 8.5.x server.",
            ) from None
        except M0TidbTimeoutError:
            raise ApiError(504, "M0_TIDB_TIMEOUT", "The TiDB connection timed out.") from None
        except (M0DriverInvariantError, M0TidbUnavailableError):
            raise ApiError(
                502,
                "M0_TIDB_UNAVAILABLE",
                "The TiDB connection is unavailable.",
            ) from None
        return JSONResponse(content=_connection_payload(view))

    @app.delete("/api/v1/m0/connection", status_code=204)
    async def delete_m0_connection(
        request: Request,
        x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    ) -> Response:
        require_owner_csrf(request, x_csrf_token)
        try:
            await store.disconnect()
        except M0BusyError:
            raise ApiError(409, "M0_BUSY", "Another M0 operation is already running.") from None
        return Response(status_code=204)


async def _parse_connection_input(request: Request) -> M0ConnectionInput:
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > M0_CONNECTION_BODY_LIMIT:
                raise _validation_error()
            body.extend(chunk)
        parsed = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(parsed, dict):
            raise _validation_error()
        return M0ConnectionInput.model_validate(parsed)
    except ApiError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError, TypeError):
        raise _validation_error() from None
    finally:
        body.clear()


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _validation_error() -> ApiError:
    return ApiError(
        422,
        "VALIDATION_ERROR",
        "The request did not match the expected schema.",
    )


def _connection_payload(view: M0ConnectionView | None) -> dict[str, object]:
    if view is None:
        return {"schema_version": "m0-connection/v1", "state": "disconnected"}
    return {
        "schema_version": "m0-connection/v1",
        "connection_id": view.connection_id,
        "state": view.state,
        "product": view.product,
        "version": view.version,
        "database": view.database,
        "tls_mode": view.tls_mode,
        "connected_at": view.connected_at.isoformat().replace("+00:00", "Z"),
    }
