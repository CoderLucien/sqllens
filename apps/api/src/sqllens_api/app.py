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
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from starlette.responses import Response

from sqllens_api.config import Settings
from sqllens_api.credentials import CredentialUnavailableError, CredentialVault
from sqllens_api.diagnosis import (
    DiagnosisStore,
    IdempotencyConflictError,
    SqlDiagnosisError,
    build_case,
    parse_sql_structure,
    request_fingerprint,
    validate_idempotency_key,
)
from sqllens_api.errors import ApiError, error_response
from sqllens_api.provider import (
    HttpxProviderGateway,
    ProviderGateway,
    ProviderProbeRequest,
)
from sqllens_api.setup import (
    OWNER_COOKIE_NAME,
    SETUP_COOKIE_NAME,
    SetupSessionSigner,
    SetupStore,
)

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
            if len(raw_host) > 253:
                raise ValueError("provider host is invalid")
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
    owner_password: SecretStr = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr = Field(min_length=1, max_length=128)


class SqlCaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sql: str


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
    vault = CredentialVault(runtime_settings.credential_key_path)
    diagnosis_store = DiagnosisStore(store.engine)

    app = FastAPI(
        title="SQLLens P0 API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = runtime_settings
    app.state.setup_store = store

    def current_owner_token(request: Request) -> str | None:
        snapshot = store.snapshot()
        cookie = request.cookies.get(OWNER_COOKIE_NAME)
        if cookie is None or not snapshot.initialized or not snapshot.owner_configured:
            return None
        return signer.verify_owner(
            cookie,
            clock(),
            expected_setup_epoch=snapshot.setup_epoch,
            expected_session_epoch=snapshot.owner_session_epoch,
        )

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
        is_public_auth_api = request.url.path in {
            "/api/v1/auth/login",
            "/api/v1/auth/session",
        }
        is_logout_api = request.url.path == "/api/v1/auth/logout"
        response: Response
        if (
            request.url.path.startswith("/api/v1/")
            and not is_setup_api
            and not is_public_auth_api
            and not is_logout_api
            and not store.is_ready()
        ):
            response = error_response(
                request,
                status_code=423,
                code="SETUP_REQUIRED",
                message="Complete setup before using diagnosis APIs.",
            )
        elif (
            request.url.path.startswith("/api/v1/")
            and not is_setup_api
            and not is_public_auth_api
            and current_owner_token(request) is None
        ):
            response = error_response(
                request,
                status_code=401,
                code="AUTH_REQUIRED",
                message="Owner authentication is required.",
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
        token = (
            signer.verify(cookie, clock(), expected_epoch=store.snapshot().setup_epoch)
            if cookie
            else None
        )
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

    def require_owner_auth(request: Request) -> str:
        token = current_owner_token(request)
        if token is None:
            raise ApiError(401, "AUTH_REQUIRED", "Owner authentication is required.")
        return token

    def require_owner_session(
        request: Request,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ) -> str:
        token = require_owner_auth(request)
        if not signer.verify_csrf(token, x_csrf_token):
            raise ApiError(403, "CSRF_INVALID", "The owner request could not be verified.")
        return token

    def provider_credential_available() -> bool:
        snapshot = store.snapshot()
        if snapshot.provider_credential is None:
            return False
        try:
            vault.decrypt(snapshot.provider_credential)
        except CredentialUnavailableError:
            return False
        return True

    def stored_provider_request() -> ProviderProbeRequest:
        snapshot = store.snapshot()
        if (
            snapshot.provider_credential is None
            or snapshot.provider_base_url is None
            or snapshot.provider_model is None
        ):
            raise ApiError(
                503,
                "MODEL_CREDENTIAL_UNAVAILABLE",
                "The external model credential is unavailable and must be rotated.",
            )
        try:
            api_key = vault.decrypt(snapshot.provider_credential)
        except CredentialUnavailableError as error:
            raise ApiError(
                503,
                "MODEL_CREDENTIAL_UNAVAILABLE",
                "The external model credential is unavailable and must be rotated.",
            ) from error
        return ProviderProbeRequest(
            mode="external",
            base_url=snapshot.provider_base_url,
            api_key=SecretStr(api_key),
            model=snapshot.provider_model,
        )

    @app.get("/healthz")
    async def health() -> Response:
        return JSONResponse(content={"status": "ok"})

    @app.get("/api/v1/setup/status")
    async def setup_status(request: Request) -> dict[str, object]:
        snapshot = store.snapshot()
        cookie = request.cookies.get(SETUP_COOKIE_NAME)
        session_token = (
            signer.verify(cookie, clock(), expected_epoch=snapshot.setup_epoch)
            if cookie
            else None
        )
        now_value = clock().astimezone(UTC).timestamp()
        recovery_reason: str | None = None
        if not snapshot.initialized and snapshot.stage == "bootstrap_required":
            if (
                snapshot.bootstrap_expires_at is not None
                and snapshot.bootstrap_expires_at < now_value
            ):
                recovery_reason = "bootstrap_expired"
            elif snapshot.bootstrap_failed_attempts >= runtime_settings.bootstrap_max_attempts:
                recovery_reason = "attempt_limit_reached"
        elif not snapshot.initialized and session_token is None:
            recovery_reason = "setup_session_missing"
        credential_available = provider_credential_available()
        reported_state = (
            "model_recovery_required"
            if snapshot.initialized
            and snapshot.model_mode == "external"
            and not credential_available
            else snapshot.stage
        )
        return {
            "state": reported_state,
            "initialized": snapshot.initialized,
            "bootstrap_hash_persisted": snapshot.bootstrap_persisted,
            "model_mode": snapshot.model_mode,
            "external_model": {
                "credential_available": credential_available,
                "egress_enabled": snapshot.external_model_egress is True,
            },
            "csrf_token": signer.csrf_for(session_token) if session_token else None,
            "recovery": {
                "required": recovery_reason is not None,
                "action": "bootstrap-reissue" if recovery_reason is not None else None,
                "reason": recovery_reason,
            },
            "local_model": {
                "available": False,
                "verified": False,
                "code": "LOCAL_RUNTIME_UNAVAILABLE",
                "message": "No qualified local model runtime is exposed to this service.",
            },
        }

    @app.post("/api/v1/setup/bootstrap")
    async def bootstrap(payload: BootstrapInput) -> Response:
        consumed_epoch = store.consume_bootstrap_code(payload.code, clock())
        if consumed_epoch is None:
            raise ApiError(
                401,
                "BOOTSTRAP_INVALID",
                "The initialization code is invalid or unavailable.",
            )
        cookie, csrf_token = signer.issue(clock(), epoch=consumed_epoch)
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
        assert payload.api_key is not None
        try:
            encrypted = vault.encrypt(payload.api_key.get_secret_value())
            store.save_provider_probe(payload, result, encrypted, clock())
        except CredentialUnavailableError as error:
            raise ApiError(
                503,
                "CREDENTIAL_STORE_UNAVAILABLE",
                "The provider credential could not be stored safely.",
            ) from error
        except RuntimeError as error:
            raise ApiError(
                409,
                "SETUP_STATE_CHANGED",
                "Setup state changed while the provider was being verified.",
            ) from error
        return JSONResponse(content=result.model_dump(exclude_none=True))

    @app.post("/api/v1/setup/finalize")
    async def finalize_setup(
        payload: FinalizeInput,
        _session: Annotated[str, Depends(require_setup_session)],
    ) -> Response:
        require_setup_stage("model_required")
        snapshot = store.snapshot()
        if payload.mode == "local":
            raise ApiError(
                409,
                "LOCAL_MODEL_UNAVAILABLE",
                "No qualified local model runtime is exposed to this service.",
            )
        if payload.mode == "external":
            if snapshot.provider_credential is None:
                raise ApiError(
                    409,
                    "SETUP_PREREQUISITE_MISSING",
                    "A recoverable external provider credential is required.",
                )
            try:
                vault.decrypt(snapshot.provider_credential)
            except CredentialUnavailableError as error:
                raise ApiError(
                    409,
                    "SETUP_PREREQUISITE_MISSING",
                    "A recoverable external provider credential is required.",
                ) from error
        try:
            setup_epoch, owner_epoch = store.finalize(
                payload.mode,
                payload.owner_password.get_secret_value(),
                clock(),
            )
        except RuntimeError as error:
            raise ApiError(
                409,
                "SETUP_PREREQUISITE_MISSING",
                "Setup prerequisites have not been verified.",
            ) from error
        if payload.mode == "rules":
            vault.retire(snapshot.provider_credential)
        owner_cookie, owner_csrf = signer.issue_owner(
            clock(),
            setup_epoch=setup_epoch,
            session_epoch=owner_epoch,
        )
        response = JSONResponse(
            content={
                "state": "ready",
                "model_mode": payload.mode,
                "authenticated": True,
                "owner_csrf_token": owner_csrf,
            }
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
        _owner: Annotated[str, Depends(require_owner_session)],
    ) -> Response:
        snapshot = store.snapshot()
        if not store.revoke_owner_sessions(
            setup_epoch=snapshot.setup_epoch,
            session_epoch=snapshot.owner_session_epoch,
            now=clock(),
        ):
            raise ApiError(409, "SESSION_STATE_CHANGED", "The owner session already changed.")
        response = JSONResponse(content={"authenticated": False})
        response.delete_cookie(OWNER_COOKIE_NAME, path="/api/v1")
        return response

    @app.post("/api/v1/settings/model/verify")
    async def verify_stored_model(
        _owner: Annotated[str, Depends(require_owner_session)],
    ) -> Response:
        result = await gateway.probe(stored_provider_request())
        if result.status != "verified":
            raise ApiError(
                503,
                result.code or "PROVIDER_UNAVAILABLE",
                result.message or "Provider did not pass the bounded health check.",
            )
        return JSONResponse(content=result.model_dump(exclude_none=True))

    @app.put("/api/v1/settings/model")
    async def rotate_model_credential(
        payload: ProviderProbeRequest,
        _owner: Annotated[str, Depends(require_owner_session)],
    ) -> Response:
        snapshot = store.snapshot()
        if payload.mode != "external":
            raise ApiError(422, "VALIDATION_ERROR", "Only external provider rotation is supported.")
        if not snapshot.external_model_egress:
            raise ApiError(403, "EXTERNAL_EGRESS_DISABLED", "External model egress is disabled.")
        if payload.provider_host not in snapshot.allowed_provider_hosts:
            raise ApiError(403, "PROVIDER_HOST_NOT_ALLOWED", "The provider host is not allowed.")
        result = await gateway.probe(payload)
        if result.status != "verified":
            raise ApiError(
                503,
                result.code or "PROVIDER_UNAVAILABLE",
                result.message or "Provider did not pass the bounded health check.",
            )
        assert payload.api_key is not None
        try:
            encrypted = vault.rotate(
                payload.api_key.get_secret_value(),
                previous=snapshot.provider_credential,
            )
        except CredentialUnavailableError as error:
            raise ApiError(
                503,
                "CREDENTIAL_STORE_UNAVAILABLE",
                "Credential storage failed.",
            ) from error
        if not store.replace_provider_credential(
            payload,
            result,
            encrypted,
            expected_credential=snapshot.provider_credential,
            expected_setup_epoch=snapshot.setup_epoch,
            now=clock(),
        ):
            vault.discard_rotation(encrypted)
            raise ApiError(409, "SETTINGS_STATE_CHANGED", "Model settings changed concurrently.")
        vault.retire(snapshot.provider_credential)
        return JSONResponse(content={"model_mode": "external", "credential_available": True})

    @app.delete("/api/v1/settings/model")
    async def delete_model_credential(
        _owner: Annotated[str, Depends(require_owner_session)],
    ) -> dict[str, object]:
        snapshot = store.snapshot()
        if not store.delete_provider_credential(
            expected_credential=snapshot.provider_credential,
            expected_setup_epoch=snapshot.setup_epoch,
            now=clock(),
        ):
            raise ApiError(409, "SETTINGS_STATE_CHANGED", "Model settings changed concurrently.")
        vault.retire(snapshot.provider_credential)
        return {"model_mode": "rules", "credential_available": False}

    @app.post("/api/v1/cases/sql")
    async def create_sql_case(
        payload: SqlCaseInput,
        _owner: Annotated[str, Depends(require_owner_session)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> Response:
        try:
            safe_idempotency_key = validate_idempotency_key(idempotency_key)
            structure = parse_sql_structure(payload.sql)
        except SqlDiagnosisError as error:
            raise ApiError(error.status_code, error.code, error.message) from error

        snapshot = store.snapshot()
        provider = "openai-compatible" if snapshot.model_mode == "external" else None
        model = snapshot.provider_model if snapshot.model_mode == "external" else None
        explanation = {"status": "not_requested", "code": None}
        if snapshot.model_mode == "external" and not provider_credential_available():
            explanation = {
                "status": "degraded",
                "code": "MODEL_CREDENTIAL_UNAVAILABLE",
            }
        case_payload = build_case(
            sql=payload.sql,
            structure=structure,
            now=clock(),
            provider=provider,
            model=model,
        )
        fingerprint = request_fingerprint(payload.sql)
        try:
            job = diagnosis_store.create_or_get(
                idempotency_key=safe_idempotency_key,
                fingerprint=fingerprint,
                case_payload=case_payload,
                explanation=explanation,
                now=clock(),
            )
        except IdempotencyConflictError:
            raise ApiError(
                409,
                "IDEMPOTENCY_KEY_CONFLICT",
                "The Idempotency-Key was already used for another request.",
            ) from None
        return JSONResponse(status_code=202, content=job)

    @app.get("/api/v1/jobs/{job_id}")
    async def get_job(
        job_id: str,
        _owner: Annotated[str, Depends(require_owner_auth)],
    ) -> Response:
        job = diagnosis_store.get_job(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "The diagnosis job was not found.")
        return JSONResponse(content=job)

    @app.get("/api/v1/cases/{case_id}")
    async def get_case(
        case_id: str,
        _owner: Annotated[str, Depends(require_owner_auth)],
    ) -> Response:
        case_payload = diagnosis_store.get_case(case_id)
        if case_payload is None:
            raise ApiError(404, "CASE_NOT_FOUND", "The diagnosis case was not found.")
        return JSONResponse(content=case_payload)

    web_dist = runtime_settings.web_dist_dir
    if isinstance(web_dist, Path) and (web_dist / "index.html").is_file():
        app.mount("/", StaticFiles(directory=web_dist, html=True), name="web")
    else:

        @app.get("/")
        async def root() -> dict[str, str]:
            return {"service": "sqllens", "status": "web-build-missing"}

    return app
