import asyncio
import ipaddress
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sqllens_api.config import Settings
from sqllens_api.credentials import (
    CredentialUnavailableError,
    CredentialVault,
    EncryptedCredential,
)
from sqllens_api.diagnosis import (
    MAX_SQL_BYTES,
    DiagnosisCapacityError,
    DiagnosisStore,
    IdempotencyConflictError,
    ProviderConfiguration,
    SqlDiagnosisError,
    apply_model_ranking,
    build_case,
    build_model_ranking_payload,
    parse_sql_structure,
    request_fingerprint,
    validate_idempotency_key,
)
from sqllens_api.errors import ApiError, error_response
from sqllens_api.provider import (
    MODEL_EGRESS_POLICY,
    MODEL_PROMPT_REVISION,
    MODEL_RANKING_REQUEST_SCHEMA,
    HttpxProviderGateway,
    ModelExplanationGateway,
    ModelExplanationRequest,
    ProviderGateway,
    ProviderProbeRequest,
    UnavailableModelExplanationGateway,
)
from sqllens_api.setup import (
    OWNER_COOKIE_NAME,
    SETUP_COOKIE_NAME,
    STAGED_CREDENTIAL_OPERATIONS,
    SetupSessionSigner,
    SetupSnapshot,
    SetupStore,
)

Clock = Callable[[], datetime]
_HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_SQL_REQUEST_BODY_BYTES = MAX_SQL_BYTES + 1_024
_API_REQUEST_BODY_BYTES = 131_072
_REQUEST_BODY_MESSAGE_LIMIT = 128
_REQUEST_BODY_READ_TIMEOUT_SECONDS = 2.0


class ApiRequestBodyLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        api_body_bytes: int,
        sql_body_bytes: int,
        message_limit: int,
        read_timeout_seconds: float,
    ) -> None:
        self.app = app
        self.api_body_bytes = api_body_bytes
        self.sql_body_bytes = sql_body_bytes
        self.message_limit = message_limit
        self.read_timeout_seconds = read_timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        method = str(scope.get("method", ""))
        if (
            scope["type"] != "http"
            or not path.startswith("/api/")
            or method
            not in {
                "POST",
                "PUT",
                "PATCH",
            }
        ):
            await self.app(scope, receive, send)
            return

        is_sql_request = path == "/api/v1/cases/sql"
        max_body_bytes = self.sql_body_bytes if is_sql_request else self.api_body_bytes

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        declared_length = headers.get(b"content-length")
        if declared_length is not None:
            try:
                too_large = int(declared_length) > max_body_bytes
            except ValueError:
                too_large = True
            if too_large:
                await self._reject(scope, receive, send, sql=is_sql_request)
                return

        buffered = bytearray()
        disconnected = False
        try:
            async with asyncio.timeout(self.read_timeout_seconds):
                for _message_number in range(self.message_limit):
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        disconnected = True
                        break
                    if message["type"] != "http.request":
                        continue
                    buffered.extend(message.get("body", b""))
                    if len(buffered) > max_body_bytes:
                        await self._reject(scope, receive, send, sql=is_sql_request)
                        return
                    if not message.get("more_body", False):
                        break
                else:
                    await self._reject(scope, receive, send, sql=is_sql_request)
                    return
        except TimeoutError:
            await self._reject(scope, receive, send, sql=is_sql_request)
            return

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                if disconnected:
                    return {"type": "http.disconnect"}
                return {"type": "http.request", "body": bytes(buffered), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        sql: bool,
    ) -> None:
        supplied_request_id = next(
            (
                value.decode("ascii", errors="ignore")
                for key, value in scope.get("headers", [])
                if key.lower() == b"x-request-id"
            ),
            "",
        )
        request_id = (
            supplied_request_id
            if 1 <= len(supplied_request_id) <= 100 and supplied_request_id.isascii()
            else uuid.uuid4().hex
        )
        response = JSONResponse(
            status_code=413,
            content={
                "error": {
                    "version": "1",
                    "code": "SQL_INPUT_TOO_LARGE" if sql else "REQUEST_BODY_TOO_LARGE",
                    "message": "The request exceeds the accepted size or time budget.",
                    "request_id": request_id,
                }
            },
            headers={"Cache-Control": "no-store", "X-Request-ID": request_id},
        )
        await _secure_response(response)(scope, receive, send)


class BootstrapInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=12, max_length=80)


class FirstOwnerInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr = Field(min_length=12, max_length=128)


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
    owner_password: SecretStr | None = Field(default=None, min_length=12, max_length=128)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr = Field(min_length=1, max_length=128)


class SqlCaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sql: str = Field(max_length=MAX_SQL_BYTES)


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
    explanation_gateway: ModelExplanationGateway | None = None,
) -> FastAPI:
    runtime_settings = settings or Settings()
    store = SetupStore(runtime_settings)
    signer = SetupSessionSigner(runtime_settings)
    default_gateway = HttpxProviderGateway() if provider_gateway is None else None
    gateway = provider_gateway or default_gateway
    assert gateway is not None
    model_gateway = explanation_gateway or default_gateway or UnavailableModelExplanationGateway()
    vault = CredentialVault(runtime_settings.credential_key_path)
    diagnosis_store = DiagnosisStore(store.engine)
    diagnosis_store.recover_interrupted_jobs()

    app = FastAPI(
        title="SQLLens P0 API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = runtime_settings
    app.state.setup_store = store
    app.state.diagnosis_store = diagnosis_store

    def credential_versions_for(snapshot: SetupSnapshot) -> set[str]:
        versions: set[str] = set()
        provider_credential = snapshot.provider_credential
        pending_version = snapshot.credential_retirement_pending_version
        if provider_credential is not None:
            versions.add(provider_credential.key_version)
        if pending_version is not None:
            versions.add(pending_version)
        return versions

    def resume_credential_retirement() -> None:
        snapshot = store.snapshot()
        pending_version = snapshot.credential_retirement_pending_version
        if pending_version is None:
            return
        if snapshot.credential_retirement_operation in STAGED_CREDENTIAL_OPERATIONS:
            raise ApiError(
                503,
                "CREDENTIAL_ROTATION_IN_PROGRESS",
                "Credential rotation is in progress and must be retried.",
            )
        try:
            vault.retire_version(pending_version)
        except CredentialUnavailableError as error:
            raise ApiError(
                503,
                "CREDENTIAL_RETIREMENT_PENDING",
                "Credential cleanup is pending and must be retried.",
            ) from error
        if (
            not store.complete_credential_retirement(pending_version, clock())
            and store.snapshot().credential_retirement_pending_version is not None
        ):
            raise ApiError(
                503,
                "CREDENTIAL_RETIREMENT_PENDING",
                "Credential cleanup is pending and must be retried.",
            )

    def recover_credential_state_before_traffic() -> None:
        snapshot = store.snapshot()
        vault.assert_key_file_closure(credential_versions_for(snapshot))
        pending_version = snapshot.credential_retirement_pending_version
        if pending_version is None:
            return
        if snapshot.credential_retirement_operation in STAGED_CREDENTIAL_OPERATIONS:
            token = snapshot.credential_retirement_token
            if token is None:
                raise CredentialUnavailableError("staged credential rotation token is unavailable")
            vault.retire_staged_version(pending_version)
            operation = snapshot.credential_retirement_operation
            aborted = (
                store.abort_staged_rotation(pending_version, token, clock())
                if operation == "staged_rotation"
                else store.abort_staged_setup_probe(pending_version, token, clock())
            )
            if not aborted:
                raise CredentialUnavailableError(
                    "staged credential rotation changed during startup recovery"
                )
        else:
            vault.retire_version(pending_version)
            if not store.complete_credential_retirement(pending_version, clock()):
                raise CredentialUnavailableError(
                    "credential retirement changed during startup recovery"
                )
        recovered = store.snapshot()
        vault.assert_key_file_closure(credential_versions_for(recovered))

    recover_credential_state_before_traffic()

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
        retirement_error: ApiError | None = None
        retirement_snapshot = store.snapshot() if request.url.path.startswith("/api/v1/") else None
        if (
            retirement_snapshot is not None
            and retirement_snapshot.credential_retirement_pending_version is not None
            and (
                request.url.path != "/api/v1/setup/status"
                or retirement_snapshot.credential_retirement_operation
                in STAGED_CREDENTIAL_OPERATIONS
            )
        ):
            try:
                resume_credential_retirement()
            except ApiError as error:
                retirement_error = error
        if retirement_error is not None:
            response = error_response(
                request,
                status_code=retirement_error.status_code,
                code=retirement_error.code,
                message=retirement_error.message,
            )
        elif (
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
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        if any(
            item.get("type") == "string_too_long" and tuple(item.get("loc", ())) == ("body", "sql")
            for item in error.errors()
        ):
            return error_response(
                request,
                status_code=413,
                code="SQL_INPUT_TOO_LARGE",
                message="The SQL request exceeds the accepted size limit.",
            )
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

    def require_setup_authorization(
        request: Request,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ) -> str:
        snapshot = store.snapshot()
        if snapshot.initialized:
            raise ApiError(
                409,
                "SETUP_ALREADY_FINALIZED",
                "Setup is finalized and cannot be changed through the setup API.",
            )
        if snapshot.owner_configured:
            token = current_owner_token(request)
            if token is None:
                raise ApiError(401, "AUTH_REQUIRED", "Owner authentication is required.")
            if not signer.verify_csrf(token, x_csrf_token):
                raise ApiError(403, "CSRF_INVALID", "The owner request could not be verified.")
            return token
        return require_setup_session(request, x_csrf_token)

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
        if (
            snapshot.provider_credential is None
            or snapshot.credential_retirement_pending_version is not None
        ):
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
            or snapshot.credential_retirement_pending_version is not None
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

    def admitted_provider_request(
        configuration: ProviderConfiguration,
    ) -> ProviderProbeRequest:
        if (
            configuration.mode != "external"
            or configuration.credential is None
            or configuration.base_url is None
            or configuration.model is None
        ):
            raise CredentialUnavailableError("admitted provider configuration is incomplete")
        api_key = vault.decrypt(configuration.credential)
        return ProviderProbeRequest(
            mode="external",
            base_url=configuration.base_url,
            api_key=SecretStr(api_key),
            model=configuration.model,
        )

    @app.get("/healthz")
    async def health() -> Response:
        return JSONResponse(content={"status": "ok"})

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
        cookie = request.cookies.get(SETUP_COOKIE_NAME)
        session_token = (
            signer.verify(cookie, clock(), expected_epoch=snapshot.setup_epoch) if cookie else None
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
        elif (
            not snapshot.initialized
            and not snapshot.owner_configured
            and session_token is None
            and snapshot.stage != "owner_required"
        ):
            recovery_reason = "setup_session_missing"
        if snapshot.credential_retirement_pending_version is not None:
            recovery_reason = "credential_retirement_pending"
        credential_available = provider_credential_available()
        reported_state = (
            "model_recovery_required"
            if snapshot.initialized
            and snapshot.model_mode == "external"
            and not credential_available
            else snapshot.stage
        )
        owner_token = current_owner_token(request)
        first_owner_proof = (
            store.issue_first_owner_nonce(clock())
            if snapshot.stage == "owner_required"
            and not snapshot.owner_configured
            and has_canonical_first_run_headers(request, require_origin=False)
            else None
        )
        active_session_token = owner_token or session_token
        content: dict[str, object] = {
            "state": reported_state,
            "initialized": snapshot.initialized,
            "owner_configured": snapshot.owner_configured,
            "bootstrap_hash_persisted": snapshot.bootstrap_persisted,
            "model_mode": snapshot.model_mode,
            "external_model": {
                "credential_available": credential_available,
                "egress_enabled": snapshot.external_model_egress is True,
            },
            "csrf_token": (
                signer.csrf_for(active_session_token) if active_session_token is not None else None
            ),
            "setup_nonce": first_owner_proof[1] if first_owner_proof else None,
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
                "state": "security_policy_required",
                "authenticated": True,
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
        _session: Annotated[str, Depends(require_setup_authorization)],
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
        _session: Annotated[str, Depends(require_setup_authorization)],
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
            plan = vault.plan_rotation(snapshot.provider_credential)
        except CredentialUnavailableError as error:
            raise ApiError(
                503,
                "CREDENTIAL_STORE_UNAVAILABLE",
                "The provider credential could not be stored safely.",
            ) from error
        token = uuid.uuid4().hex
        assert snapshot.policy_committed_at is not None
        if not store.begin_staged_setup_probe(
            staged_version=plan.key_version,
            token=token,
            expected_credential=snapshot.provider_credential,
            expected_setup_epoch=snapshot.setup_epoch,
            expected_policy_committed_at=snapshot.policy_committed_at,
            now=clock(),
        ):
            observed = store.snapshot()
            if observed.credential_retirement_operation in STAGED_CREDENTIAL_OPERATIONS:
                raise ApiError(
                    409,
                    "CREDENTIAL_SETUP_IN_PROGRESS",
                    "Another credential setup operation is already in progress.",
                )
            raise ApiError(
                409,
                "SETUP_STATE_CHANGED",
                "Setup state changed while the provider was being verified.",
            )

        def stage_is_still_owned(observed: SetupSnapshot) -> bool:
            return (
                observed.provider_credential == snapshot.provider_credential
                and observed.setup_epoch == snapshot.setup_epoch
                and observed.credential_retirement_pending_version == plan.key_version
                and observed.credential_retirement_operation == "staged_setup_probe"
                and observed.credential_retirement_token == token
            )

        def abort_owned_stage() -> None:
            try:
                vault.retire_staged_version(plan.key_version)
            except CredentialUnavailableError as error:
                raise ApiError(
                    503,
                    "CREDENTIAL_SETUP_IN_PROGRESS",
                    "Credential setup cleanup is pending and must be retried.",
                ) from error
            if not store.abort_staged_setup_probe(plan.key_version, token, clock()):
                raise ApiError(
                    503,
                    "CREDENTIAL_SETUP_IN_PROGRESS",
                    "Credential setup cleanup is pending and must be retried.",
                )

        def commit_is_durable(
            observed: SetupSnapshot,
            encrypted_credential: EncryptedCredential,
        ) -> bool:
            old_version = (
                snapshot.provider_credential.key_version
                if snapshot.provider_credential is not None
                else None
            )
            retirement_matches = (
                observed.credential_retirement_pending_version is None
                and observed.credential_retirement_operation is None
            )
            if old_version is not None:
                retirement_matches = retirement_matches or (
                    observed.credential_retirement_pending_version == old_version
                    and observed.credential_retirement_operation == "setup_probe_replacement"
                )
            return (
                observed.provider_credential == encrypted_credential
                and observed.credential_retirement_token is None
                and retirement_matches
            )

        try:
            encrypted = vault.materialize_rotation(payload.api_key.get_secret_value(), plan)
        except BaseException as error:
            abort_owned_stage()
            if not isinstance(error, CredentialUnavailableError):
                raise
            raise ApiError(
                503,
                "CREDENTIAL_STORE_UNAVAILABLE",
                "The provider credential could not be stored safely.",
            ) from error

        try:
            committed = store.commit_staged_setup_probe(
                payload,
                result,
                encrypted,
                token=token,
                now=clock(),
            )
        except BaseException as error:
            observed = store.snapshot()
            if commit_is_durable(observed, encrypted):
                committed = True
                if not isinstance(error, Exception):
                    resume_credential_retirement()
                    raise
            elif stage_is_still_owned(observed):
                abort_owned_stage()
                if not isinstance(error, Exception):
                    raise
                raise ApiError(
                    503,
                    "CREDENTIAL_SETUP_IN_PROGRESS",
                    "Credential setup did not commit and was safely aborted.",
                ) from error
            else:
                if not isinstance(error, Exception):
                    raise
                raise ApiError(
                    503,
                    "CREDENTIAL_SETUP_STATE_UNCERTAIN",
                    "Credential setup state changed and must be recovered before retrying.",
                ) from error
        if not committed:
            observed = store.snapshot()
            if commit_is_durable(observed, encrypted):
                committed = True
            elif stage_is_still_owned(observed):
                abort_owned_stage()
                raise ApiError(
                    409,
                    "SETUP_STATE_CHANGED",
                    "Setup state changed while the provider was being stored.",
                )
            else:
                raise ApiError(
                    503,
                    "CREDENTIAL_SETUP_STATE_UNCERTAIN",
                    "Credential setup state changed and must be recovered before retrying.",
                )
        resume_credential_retirement()
        return JSONResponse(content=result.model_dump(exclude_none=True))

    @app.post("/api/v1/setup/finalize")
    async def finalize_setup(
        payload: FinalizeInput,
        _session: Annotated[str, Depends(require_setup_authorization)],
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
                (
                    payload.owner_password.get_secret_value()
                    if payload.owner_password is not None
                    else None
                ),
                clock(),
            )
        except RuntimeError as error:
            raise ApiError(
                409,
                "SETUP_PREREQUISITE_MISSING",
                "Setup prerequisites have not been verified.",
            ) from error
        if payload.mode == "rules":
            resume_credential_retirement()
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
        if diagnosis_store.has_active_lease():
            raise ApiError(
                409,
                "MODEL_CONFIGURATION_IN_USE",
                "Model settings cannot change while a diagnosis job is running.",
            )
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
            plan = vault.plan_rotation(snapshot.provider_credential)
        except CredentialUnavailableError as error:
            raise ApiError(
                503,
                "CREDENTIAL_STORE_UNAVAILABLE",
                "Credential storage failed.",
            ) from error
        token = uuid.uuid4().hex
        if not store.begin_staged_rotation(
            staged_version=plan.key_version,
            token=token,
            expected_credential=snapshot.provider_credential,
            expected_setup_epoch=snapshot.setup_epoch,
            now=clock(),
        ):
            if diagnosis_store.has_active_lease():
                raise ApiError(
                    409,
                    "MODEL_CONFIGURATION_IN_USE",
                    "Model settings cannot change while a diagnosis job is running.",
                )
            if store.snapshot().credential_retirement_operation == "staged_rotation":
                raise ApiError(
                    409,
                    "CREDENTIAL_ROTATION_IN_PROGRESS",
                    "Another credential rotation is already in progress.",
                )
            raise ApiError(409, "SETTINGS_STATE_CHANGED", "Model settings changed concurrently.")

        def abort_owned_stage() -> None:
            try:
                vault.retire_staged_version(plan.key_version)
            except CredentialUnavailableError as error:
                raise ApiError(
                    503,
                    "CREDENTIAL_ROTATION_IN_PROGRESS",
                    "Credential rotation cleanup is pending and must be retried.",
                ) from error
            if not store.abort_staged_rotation(plan.key_version, token, clock()):
                raise ApiError(
                    503,
                    "CREDENTIAL_ROTATION_IN_PROGRESS",
                    "Credential rotation cleanup is pending and must be retried.",
                )

        def commit_is_durable(observed: SetupSnapshot) -> bool:
            old_version = (
                snapshot.provider_credential.key_version
                if snapshot.provider_credential is not None
                else None
            )
            retirement_matches = observed.credential_retirement_pending_version is None
            retirement_matches = retirement_matches and (
                observed.credential_retirement_operation is None
            )
            if old_version is not None:
                retirement_matches = retirement_matches or (
                    observed.credential_retirement_pending_version == old_version
                    and observed.credential_retirement_operation == "rotation"
                )
            return (
                observed.provider_credential == encrypted
                and observed.credential_retirement_token is None
                and retirement_matches
            )

        def stage_is_still_owned(observed: SetupSnapshot) -> bool:
            return (
                observed.provider_credential == snapshot.provider_credential
                and observed.setup_epoch == snapshot.setup_epoch
                and observed.credential_retirement_pending_version == plan.key_version
                and observed.credential_retirement_operation == "staged_rotation"
                and observed.credential_retirement_token == token
            )

        try:
            encrypted = vault.materialize_rotation(payload.api_key.get_secret_value(), plan)
        except BaseException as error:
            abort_owned_stage()
            if not isinstance(error, CredentialUnavailableError):
                raise
            raise ApiError(
                503,
                "CREDENTIAL_STORE_UNAVAILABLE",
                "Credential storage failed.",
            ) from error
        try:
            committed = store.commit_staged_rotation(
                payload,
                result,
                encrypted,
                token=token,
                now=clock(),
            )
        except BaseException as error:
            observed = store.snapshot()
            if commit_is_durable(observed):
                committed = True
                if not isinstance(error, Exception):
                    resume_credential_retirement()
                    raise
            elif stage_is_still_owned(observed):
                abort_owned_stage()
                if not isinstance(error, Exception):
                    raise
                raise ApiError(
                    503,
                    "CREDENTIAL_ROTATION_IN_PROGRESS",
                    "Credential rotation did not commit and was safely aborted.",
                ) from error
            else:
                if not isinstance(error, Exception):
                    raise
                raise ApiError(
                    503,
                    "CREDENTIAL_ROTATION_STATE_UNCERTAIN",
                    "Credential rotation state changed and must be inspected before retrying.",
                ) from error
        if not committed:
            configuration_in_use = diagnosis_store.has_active_lease()
            abort_owned_stage()
            raise ApiError(
                409,
                (
                    "MODEL_CONFIGURATION_IN_USE"
                    if configuration_in_use
                    else "SETTINGS_STATE_CHANGED"
                ),
                (
                    "Model settings cannot change while a diagnosis job is running."
                    if configuration_in_use
                    else "Model settings changed concurrently."
                ),
            )
        resume_credential_retirement()
        return JSONResponse(content={"model_mode": "external", "credential_available": True})

    @app.delete("/api/v1/settings/model")
    async def delete_model_credential(
        _owner: Annotated[str, Depends(require_owner_session)],
    ) -> dict[str, object]:
        if diagnosis_store.has_active_lease():
            raise ApiError(
                409,
                "MODEL_CONFIGURATION_IN_USE",
                "Model settings cannot change while a diagnosis job is running.",
            )
        snapshot = store.snapshot()
        if not store.delete_provider_credential(
            expected_credential=snapshot.provider_credential,
            expected_setup_epoch=snapshot.setup_epoch,
            now=clock(),
        ):
            if diagnosis_store.has_active_lease():
                raise ApiError(
                    409,
                    "MODEL_CONFIGURATION_IN_USE",
                    "Model settings cannot change while a diagnosis job is running.",
                )
            raise ApiError(409, "SETTINGS_STATE_CHANGED", "Model settings changed concurrently.")
        resume_credential_retirement()
        return {"model_mode": "rules", "credential_available": False}

    @app.post("/api/v1/cases/sql")
    async def create_sql_case(
        request: Request,
        payload: SqlCaseInput,
        _owner: Annotated[str, Depends(require_owner_session)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> Response:
        try:
            safe_idempotency_key = validate_idempotency_key(idempotency_key)
        except SqlDiagnosisError as error:
            raise ApiError(error.status_code, error.code, error.message) from error

        fingerprint = request_fingerprint(payload.sql)
        try:
            reservation = diagnosis_store.reserve_job(
                idempotency_key=safe_idempotency_key,
                fingerprint=fingerprint,
                now=clock(),
            )
        except IdempotencyConflictError:
            raise ApiError(
                409,
                "IDEMPOTENCY_KEY_CONFLICT",
                "The Idempotency-Key was already used for another request.",
            ) from None
        except DiagnosisCapacityError:
            response = error_response(
                request,
                status_code=429,
                code="DIAGNOSIS_CAPACITY_EXCEEDED",
                message="Diagnosis capacity is busy. Retry after the active job finishes.",
            )
            response.headers["Retry-After"] = "1"
            return response
        if not reservation.owner:
            return JSONResponse(status_code=202, content=reservation.job)

        try:
            configuration = reservation.provider_configuration
            if configuration is None:
                raise RuntimeError("admitted provider configuration is unavailable")
            try:
                structure = parse_sql_structure(payload.sql)
            except SqlDiagnosisError as error:
                diagnosis_store.fail_job(
                    reservation,
                    code=error.code,
                    retryable=False,
                )
                raise ApiError(error.status_code, error.code, error.message) from error

            external_mode = configuration.mode == "external"
            case_payload = build_case(
                sql=payload.sql,
                structure=structure,
                now=clock(),
                provider=configuration.revision if external_mode else None,
                model=configuration.model if external_mode else None,
                prompt=MODEL_PROMPT_REVISION if external_mode else None,
                case_id=str(reservation.job["caseId"]),
            )
            explanation: dict[str, str | None] = {
                "status": "not_requested",
                "code": None,
                "policy": "rules-only/v1",
                "payloadSchema": None,
                "payloadDigest": None,
            }
            if external_mode:
                ranking_payload = build_model_ranking_payload(case_payload)
                explanation = {
                    "status": "degraded",
                    "code": "MODEL_CREDENTIAL_UNAVAILABLE",
                    "policy": MODEL_EGRESS_POLICY,
                    "payloadSchema": MODEL_RANKING_REQUEST_SCHEMA,
                    "payloadDigest": ranking_payload.digest(),
                }
                try:
                    provider_request = admitted_provider_request(configuration)
                except CredentialUnavailableError:
                    explanation["code"] = "MODEL_CREDENTIAL_UNAVAILABLE"
                else:
                    if (
                        configuration.external_model_egress is not True
                        or provider_request.provider_host
                        not in configuration.allowed_provider_hosts
                    ):
                        explanation["code"] = "MODEL_EGRESS_POLICY_DENIED"
                    else:
                        model_result = await model_gateway.explain(
                            ModelExplanationRequest(
                                provider=provider_request,
                                payload=ranking_payload,
                            )
                        )
                        if model_result.status == "applied" and apply_model_ranking(
                            case_payload,
                            model_result.ranked_hypothesis_ids,
                        ):
                            explanation["status"] = "applied"
                            explanation["code"] = None
                        else:
                            explanation["code"] = model_result.code or "MODEL_OUTPUT_INVALID"
            job = diagnosis_store.complete_job(
                reservation,
                case_payload=case_payload,
                explanation=explanation,
                now=clock(),
            )
        except asyncio.CancelledError:
            diagnosis_store.cancel_job(reservation)
            raise
        except ApiError:
            raise
        except Exception:
            job = diagnosis_store.fail_job(
                reservation,
                code="DIAGNOSIS_PROCESSING_FAILED",
            )
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
        index_path = web_dist / "index.html"

        @app.get("/setup", include_in_schema=False)
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
            return {"service": "sqllens", "status": "web-build-missing"}

    app.add_middleware(
        ApiRequestBodyLimitMiddleware,
        api_body_bytes=_API_REQUEST_BODY_BYTES,
        sql_body_bytes=_SQL_REQUEST_BODY_BYTES,
        message_limit=_REQUEST_BODY_MESSAGE_LIMIT,
        read_timeout_seconds=_REQUEST_BODY_READ_TIMEOUT_SECONDS,
    )
    return app
