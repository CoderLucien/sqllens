import ipaddress
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.responses import Response

from sqllens_api.config import Settings
from sqllens_api.errors import ApiError, error_response
from sqllens_api.provider import (
    HttpxProviderGateway,
    ProviderGateway,
    ProviderProbeRequest,
)
from sqllens_api.setup import SETUP_COOKIE_NAME, SetupSessionSigner, SetupStore

Clock = Callable[[], datetime]
_HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")


class BootstrapInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=12, max_length=80)


class SecurityPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_model_egress: bool
    allowed_provider_hosts: list[str] = Field(default_factory=list, max_length=20)
    send_sql_text: bool = False

    @field_validator("allowed_provider_hosts")
    @classmethod
    def normalize_hosts(cls, hosts: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw_host in hosts:
            host = raw_host.strip().rstrip(".").lower()
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError as error:
                raise ValueError("provider host is invalid") from error
            if not host or not _HOST_PATTERN.fullmatch(host) or ".." in host:
                raise ValueError("provider host is invalid")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise ValueError("provider host must be a DNS name")
            normalized.append(host)
        return sorted(set(normalized))

    @model_validator(mode="after")
    def validate_egress_policy(self) -> Self:
        if self.external_model_egress and not self.allowed_provider_hosts:
            raise ValueError("external egress requires at least one provider host")
        if not self.external_model_egress and self.allowed_provider_hosts:
            raise ValueError("provider hosts require external egress")
        if self.send_sql_text:
            raise ValueError("sending SQL text is not supported in this release")
        return self


class FinalizeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["external", "local", "rules"]


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
    provider_gateway: ProviderGateway | None = None,
) -> FastAPI:
    runtime_settings = settings or Settings()
    store = SetupStore(runtime_settings)
    signer = SetupSessionSigner(runtime_settings)
    gateway = provider_gateway or HttpxProviderGateway()

    app = FastAPI(
        title="SQLLens P0 API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = runtime_settings
    app.state.setup_store = store

    @app.middleware("http")
    async def security_and_setup_gate(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        supplied_request_id = request.headers.get("X-Request-ID", "")
        request.state.request_id = (
            supplied_request_id
            if 1 <= len(supplied_request_id) <= 100 and supplied_request_id.isascii()
            else uuid.uuid4().hex
        )
        is_setup_api = request.url.path.startswith("/api/v1/setup/")
        response: Response
        if request.url.path.startswith("/api/v1/") and not is_setup_api and not store.is_ready():
            response = error_response(
                request,
                status_code=423,
                code="SETUP_REQUIRED",
                message="Complete setup before using diagnosis APIs.",
            )
        else:
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
        request: Request, _error: RequestValidationError
    ) -> JSONResponse:
        return error_response(
            request,
            status_code=422,
            code="VALIDATION_ERROR",
            message="The request did not match the expected schema.",
        )

    def require_setup_session(
        request: Request,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ) -> str:
        cookie = request.cookies.get(SETUP_COOKIE_NAME)
        token = signer.verify(cookie, clock()) if cookie else None
        if token is None:
            raise ApiError(
                401,
                "SETUP_SESSION_REQUIRED",
                "A valid setup session is required.",
            )
        if not signer.verify_csrf(token, x_csrf_token):
            raise ApiError(403, "CSRF_INVALID", "The setup request could not be verified.")
        return token

    def require_setup_stage(required: str) -> None:
        snapshot = store.snapshot()
        if snapshot.initialized:
            raise ApiError(
                409,
                "SETUP_ALREADY_FINALIZED",
                "Setup is finalized and cannot be changed through the setup API.",
            )
        if snapshot.stage != required:
            raise ApiError(
                409,
                "SETUP_STATE_INVALID",
                "This setup operation is not valid in the current stage.",
            )

    @app.get("/healthz")
    async def health() -> Response:
        return JSONResponse(content={"status": "ok"})

    @app.get("/api/v1/setup/status")
    async def setup_status(request: Request) -> dict[str, object]:
        snapshot = store.snapshot()
        cookie = request.cookies.get(SETUP_COOKIE_NAME)
        session_token = signer.verify(cookie, clock()) if cookie else None
        return {
            "state": snapshot.stage,
            "initialized": snapshot.initialized,
            "bootstrap_hash_persisted": snapshot.bootstrap_persisted,
            "model_mode": snapshot.model_mode,
            "csrf_token": signer.csrf_for(session_token) if session_token else None,
            "local_model": {
                "available": False,
                "verified": False,
                "code": "LOCAL_RUNTIME_UNAVAILABLE",
                "message": "No qualified local model runtime is exposed to this service.",
            },
        }

    @app.post("/api/v1/setup/bootstrap")
    async def bootstrap(payload: BootstrapInput) -> Response:
        if not store.consume_bootstrap_code(payload.code, clock()):
            raise ApiError(
                401,
                "BOOTSTRAP_INVALID",
                "The initialization code is invalid or unavailable.",
            )
        cookie, csrf_token = signer.issue(clock())
        response = JSONResponse(
            content={"state": "security_policy_required", "csrf_token": csrf_token}
        )
        response.set_cookie(
            SETUP_COOKIE_NAME,
            cookie,
            max_age=runtime_settings.setup_session_ttl_seconds,
            httponly=True,
            secure=runtime_settings.cookie_secure,
            samesite="strict",
            path="/api/v1/setup",
        )
        return response

    @app.put("/api/v1/setup/security-policy")
    async def save_security_policy(
        payload: SecurityPolicyInput,
        _session: Annotated[str, Depends(require_setup_session)],
    ) -> dict[str, str]:
        require_setup_stage("security_policy_required")
        try:
            store.save_policy(
                external_model_egress=payload.external_model_egress,
                allowed_provider_hosts=payload.allowed_provider_hosts,
                send_sql_text=payload.send_sql_text,
                now=clock(),
            )
        except RuntimeError as error:
            raise ApiError(
                409,
                "BOOTSTRAP_REQUIRED",
                "Bootstrap must be completed first.",
            ) from error
        return {"state": "model_required"}

    @app.post("/api/v1/setup/model-probes")
    async def probe_model(
        payload: ProviderProbeRequest,
        _session: Annotated[str, Depends(require_setup_session)],
    ) -> Response:
        snapshot = store.snapshot()
        if snapshot.initialized:
            raise ApiError(
                409,
                "SETUP_ALREADY_FINALIZED",
                "Setup is finalized and cannot be changed through the setup API.",
            )
        if snapshot.policy_committed_at is None:
            raise ApiError(
                409,
                "POLICY_REQUIRED",
                "Commit the security and egress policy before probing a provider.",
            )
        require_setup_stage("model_required")
        if payload.mode == "local":
            raise ApiError(
                409,
                "LOCAL_MODEL_UNAVAILABLE",
                "No qualified local model runtime is exposed to this service.",
            )
        if not snapshot.external_model_egress:
            raise ApiError(403, "EXTERNAL_EGRESS_DISABLED", "External model egress is disabled.")
        if payload.provider_host not in snapshot.allowed_provider_hosts:
            raise ApiError(
                403,
                "PROVIDER_HOST_NOT_ALLOWED",
                "The provider host is not allowed by the active security policy.",
            )
        result = await gateway.probe(payload)
        if result.status != "verified":
            raise ApiError(
                503,
                result.code or "PROVIDER_UNAVAILABLE",
                result.message or "Provider did not pass the bounded health check.",
            )
        store.save_provider_probe(payload, result, clock())
        return JSONResponse(content=result.model_dump(exclude_none=True))

    @app.post("/api/v1/setup/finalize")
    async def finalize_setup(
        payload: FinalizeInput,
        _session: Annotated[str, Depends(require_setup_session)],
    ) -> dict[str, str]:
        require_setup_stage("model_required")
        if payload.mode == "local":
            raise ApiError(
                409,
                "LOCAL_MODEL_UNAVAILABLE",
                "No qualified local model runtime is exposed to this service.",
            )
        try:
            store.finalize(payload.mode, clock())
        except RuntimeError as error:
            raise ApiError(
                409,
                "SETUP_PREREQUISITE_MISSING",
                "Setup prerequisites have not been verified.",
            ) from error
        return {"state": "ready", "model_mode": payload.mode}

    @app.post("/api/v1/cases/sql")
    async def create_sql_case() -> Response:
        raise ApiError(
            501,
            "FEATURE_NOT_IMPLEMENTED",
            "SQL diagnosis is not part of this runtime checkpoint.",
        )

    web_dist = runtime_settings.web_dist_dir
    if isinstance(web_dist, Path) and (web_dist / "index.html").is_file():
        app.mount("/", StaticFiles(directory=web_dist, html=True), name="web")
    else:

        @app.get("/")
        async def root() -> dict[str, str]:
            return {"service": "sqllens", "status": "web-build-missing"}

    return app
