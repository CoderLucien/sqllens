from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.responses import Response

from sqllens_api.config import Settings
from sqllens_api.errors import ApiError, error_response
from sqllens_api.m0_connection import M0ConnectionStore
from sqllens_api.m0_diagnosis import M0DiagnosisService
from sqllens_api.m0_routes import register_m0_connection_routes
from sqllens_api.setup import (
    OWNER_COOKIE_NAME,
    SETUP_COOKIE_NAME,
    SetupSessionSigner,
    SetupStore,
)

Clock = Callable[[], datetime]


class FirstOwnerInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: SecretStr = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: SecretStr = Field(min_length=1, max_length=128)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _secure_response(response: Response, *, api_response: bool = True) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    )
    if api_response:
        response.headers["Cache-Control"] = "no-store"
    return response


def create_app(
    *,
    settings: Settings | None = None,
    clock: Clock = _utc_now,
    m0_connection_store: M0ConnectionStore | None = None,
    m0_diagnosis_service: M0DiagnosisService | None = None,
) -> FastAPI:
    """Create the bounded M0 private-preview application."""

    runtime_settings = settings or Settings()
    store = SetupStore(runtime_settings)
    connection_store = m0_connection_store or M0ConnectionStore(clock=clock)
    diagnosis_service = m0_diagnosis_service or M0DiagnosisService(
        store=connection_store,
        clock=clock,
    )
    signer = SetupSessionSigner(runtime_settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await application.state.clear_m0_connection()

    app = FastAPI(
        title="SQLLens M0 Private Preview API",
        version="0.1.0-m0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = runtime_settings
    app.state.setup_store = store
    app.state.m0_connection_store = connection_store
    app.state.clear_m0_connection = connection_store.force_close

    def current_owner_token(request: Request) -> str | None:
        snapshot = store.snapshot()
        cookie = request.cookies.get(OWNER_COOKIE_NAME)
        if cookie is None or not snapshot.owner_configured:
            return None
        return signer.verify_owner(
            cookie,
            clock(),
            expected_setup_epoch=snapshot.setup_epoch,
            expected_session_epoch=snapshot.owner_session_epoch,
        )

    def require_owner_authenticated(request: Request) -> str:
        token = current_owner_token(request)
        if token is None:
            raise ApiError(401, "AUTH_REQUIRED", "Owner authentication is required.")
        return token

    def require_owner_session(request: Request, x_csrf_token: str | None = None) -> str:
        token = require_owner_authenticated(request)
        if not signer.verify_csrf(token, x_csrf_token):
            raise ApiError(403, "CSRF_INVALID", "The owner request could not be verified.")
        return token

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        supplied_request_id = request.headers.get("X-Request-ID", "")
        request.state.request_id = (
            supplied_request_id
            if 1 <= len(supplied_request_id) <= 100 and supplied_request_id.isascii()
            else uuid.uuid4().hex
        )
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return _secure_response(response, api_response=request.url.path.startswith("/api/"))

    @app.exception_handler(ApiError)
    async def handle_api_error(request: Request, error: ApiError) -> JSONResponse:
        return error_response(
            request,
            status_code=error.status_code,
            code=error.code,
            message=error.message,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        _error: RequestValidationError,
    ) -> JSONResponse:
        return error_response(
            request,
            status_code=422,
            code="VALIDATION_ERROR",
            message="The request did not match the expected schema.",
        )

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok", "edition": "m0-private-preview"}

    def has_canonical_first_run_headers(request: Request, *, require_origin: bool) -> bool:
        raw_headers = request.scope.get("headers", [])
        host_values = [value for key, value in raw_headers if key.lower() == b"host"]
        origin_values = [value for key, value in raw_headers if key.lower() == b"origin"]
        has_forwarded_header = any(
            key.lower() == b"forwarded" or key.lower().startswith(b"x-forwarded-")
            for key, _value in raw_headers
        )
        if host_values != [b"localhost:18080"] or has_forwarded_header:
            return False
        return not require_origin or origin_values == [b"http://localhost:18080"]

    @app.get("/api/v1/setup/status")
    async def setup_status(request: Request) -> Response:
        snapshot = store.snapshot()
        owner_token = current_owner_token(request)
        first_owner_proof = (
            store.issue_first_owner_nonce(clock())
            if snapshot.stage == "owner_required"
            and not snapshot.owner_configured
            and not snapshot.initialized
            and has_canonical_first_run_headers(request, require_origin=False)
            else None
        )
        content: dict[str, object] = {
            "edition": "m0_private_preview",
            "state": "ready" if snapshot.initialized else "owner_required",
            "initialized": snapshot.initialized,
            "owner_configured": snapshot.owner_configured,
            "configured_mode": "rules",
            "csrf_token": signer.csrf_for(owner_token) if owner_token is not None else None,
            "setup_nonce": first_owner_proof[1] if first_owner_proof else None,
        }
        response = JSONResponse(content=content)
        if first_owner_proof is not None:
            response.set_cookie(
                SETUP_COOKIE_NAME,
                first_owner_proof[0],
                max_age=runtime_settings.first_owner_nonce_ttl_seconds,
                httponly=True,
                secure=runtime_settings.cookie_secure,
                samesite="strict",
                path="/api/v1/setup",
            )
        return response

    @app.post("/api/v1/setup/owner", status_code=201)
    async def create_first_owner(
        payload: FirstOwnerInput,
        request: Request,
        x_setup_nonce: Annotated[str | None, Header(alias="X-Setup-Nonce")] = None,
    ) -> Response:
        if not has_canonical_first_run_headers(request, require_origin=True):
            raise ApiError(
                403,
                "FIRST_RUN_LOCALHOST_REQUIRED",
                "First-run Owner creation is available only from the canonical localhost UI.",
            )
        result = store.create_first_owner(
            password=payload.password.get_secret_value(),
            cookie=request.cookies.get(SETUP_COOKIE_NAME),
            nonce=x_setup_nonce,
            now=clock(),
        )
        if result.status == "limited":
            raise ApiError(
                429,
                "FIRST_OWNER_RATE_LIMITED",
                "First-run Owner creation is temporarily unavailable. Try again later.",
            )
        if result.status == "already_configured":
            raise ApiError(409, "OWNER_ALREADY_CONFIGURED", "The local Owner already exists.")
        if result.status == "unavailable":
            raise ApiError(
                409,
                "FIRST_RUN_UNAVAILABLE",
                "First-run Owner creation is unavailable in the current setup state.",
            )
        if result.status != "created" or result.setup_epoch is None or result.session_epoch is None:
            raise ApiError(
                403,
                "SETUP_NONCE_INVALID",
                "The first-run browser proof is invalid or unavailable.",
            )
        owner_cookie, owner_csrf = signer.issue_owner(
            clock(),
            setup_epoch=result.setup_epoch,
            session_epoch=result.session_epoch,
        )
        response = JSONResponse(
            status_code=201,
            content={
                "edition": "m0_private_preview",
                "state": "ready",
                "authenticated": True,
                "configured_mode": "rules",
                "csrf_token": owner_csrf,
            },
        )
        response.set_cookie(
            OWNER_COOKIE_NAME,
            owner_cookie,
            max_age=runtime_settings.owner_session_ttl_seconds,
            httponly=True,
            secure=runtime_settings.cookie_secure,
            samesite="strict",
            path="/api/v1",
        )
        response.delete_cookie(SETUP_COOKIE_NAME, path="/api/v1/setup")
        return response

    @app.get("/api/v1/auth/session")
    async def owner_session(request: Request) -> dict[str, object]:
        token = current_owner_token(request)
        return {
            "authenticated": token is not None,
            "csrf_token": signer.csrf_for(token) if token else None,
        }

    @app.post("/api/v1/auth/login")
    async def owner_login(payload: LoginInput) -> Response:
        authentication = store.authenticate_owner(payload.password.get_secret_value(), clock())
        if authentication.status == "limited":
            raise ApiError(
                429,
                "AUTH_TEMPORARILY_UNAVAILABLE",
                "Authentication is temporarily unavailable. Try again later.",
            )
        if (
            authentication.status != "authenticated"
            or authentication.setup_epoch is None
            or authentication.session_epoch is None
        ):
            raise ApiError(401, "AUTH_INVALID", "The owner credentials are invalid.")
        cookie, csrf = signer.issue_owner(
            clock(),
            setup_epoch=authentication.setup_epoch,
            session_epoch=authentication.session_epoch,
        )
        response = JSONResponse(content={"authenticated": True, "csrf_token": csrf})
        response.set_cookie(
            OWNER_COOKIE_NAME,
            cookie,
            max_age=runtime_settings.owner_session_ttl_seconds,
            httponly=True,
            secure=runtime_settings.cookie_secure,
            samesite="strict",
            path="/api/v1",
        )
        return response

    @app.post("/api/v1/auth/logout")
    async def owner_logout(
        request: Request,
        x_csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    ) -> Response:
        require_owner_session(request, x_csrf_token)
        snapshot = store.snapshot()
        revoked = store.revoke_owner_sessions(
            setup_epoch=snapshot.setup_epoch,
            session_epoch=snapshot.owner_session_epoch,
            now=clock(),
        )
        await app.state.clear_m0_connection()
        if not revoked:
            raise ApiError(409, "SESSION_STATE_CHANGED", "The owner session already changed.")
        response = JSONResponse(content={"authenticated": False})
        response.delete_cookie(OWNER_COOKIE_NAME, path="/api/v1")
        return response

    register_m0_connection_routes(
        app,
        store=connection_store,
        diagnosis_service=diagnosis_service,
        require_owner=require_owner_authenticated,
        require_owner_csrf=require_owner_session,
    )

    web_dist = runtime_settings.web_dist_dir
    if isinstance(web_dist, Path) and (web_dist / "index.html").is_file():
        index_path = web_dist / "index.html"

        @app.get("/app", include_in_schema=False)
        @app.get("/app/{path:path}", include_in_schema=False)
        async def web_shell() -> FileResponse:
            return FileResponse(
                index_path,
                media_type="text/html",
                headers={"Cache-Control": "no-cache"},
            )

        app.mount("/", StaticFiles(directory=web_dist, html=True), name="web")
    else:

        @app.get("/")
        async def root() -> dict[str, str]:
            return {"service": "sqllens-m0", "status": "web-build-missing"}

    return app
