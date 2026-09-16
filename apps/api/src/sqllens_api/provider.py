from __future__ import annotations

import asyncio
import hashlib
import json
from time import monotonic
from typing import Literal, Protocol, Self
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

MODEL_RANKING_REQUEST_SCHEMA: Literal["sqllens-model-ranking-request/v1"] = (
    "sqllens-model-ranking-request/v1"
)
MODEL_RANKING_RESPONSE_SCHEMA: Literal["sqllens-model-ranking-response/v1"] = (
    "sqllens-model-ranking-response/v1"
)
MODEL_PROMPT_REVISION = "sql-hypothesis-rank/v1"
MODEL_EGRESS_POLICY = "model-egress/metadata-only-v1"


class ProviderProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["external", "local"]
    base_url: str | None = Field(default=None, min_length=1, max_length=2_048)
    api_key: SecretStr | None = Field(default=None, min_length=1, max_length=4_096)
    model: str | None = Field(default=None, min_length=1, max_length=200)

    @model_validator(mode="after")
    def validate_mode_fields(self) -> ProviderProbeRequest:
        if self.mode == "external":
            if self.base_url is None or self.api_key is None or self.model is None:
                raise ValueError("external mode requires base_url, api_key, and model")
            parsed = urlparse(self.base_url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError("base_url must be an HTTPS origin without user info")
            if parsed.query or parsed.fragment:
                raise ValueError("base_url cannot contain a query or fragment")
        return self

    @property
    def provider_host(self) -> str:
        if self.base_url is None:
            return ""
        return (urlparse(self.base_url).hostname or "").rstrip(".").lower()


class ProviderProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["verified", "unavailable"]
    provider: str
    model: str
    latency_ms: int | None = Field(default=None, ge=0)
    code: str | None = None
    message: str | None = None


class ModelEvidenceCompleteness(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0, le=1)
    classification: Literal["insufficient", "partial", "sufficient"]
    missing: list[str] = Field(max_length=64)


class ModelEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(pattern=r"^ev_[a-z0-9]{16,64}$")
    kind: str = Field(min_length=1, max_length=64)
    sensitivity: Literal["metadata"]
    summary: str = Field(min_length=1, max_length=4_096)


class ModelHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str = Field(pattern=r"^hyp_[a-z0-9]{16,64}$")
    statement: str = Field(min_length=1, max_length=2_048)
    confidence: float = Field(ge=0, le=0.35)
    evidence_ids: list[str] = Field(min_length=1, max_length=128)


class ModelRankingPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["sqllens-model-ranking-request/v1"] = MODEL_RANKING_REQUEST_SCHEMA
    evidence_completeness: ModelEvidenceCompleteness
    evidence: list[ModelEvidence] = Field(min_length=1, max_length=32)
    hypotheses: list[ModelHypothesis] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        evidence_ids = {item.evidence_id for item in self.evidence}
        hypothesis_ids = [item.hypothesis_id for item in self.hypotheses]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("hypothesis IDs must be unique")
        if any(not set(item.evidence_ids) <= evidence_ids for item in self.hypotheses):
            raise ValueError("hypothesis evidence references must resolve")
        return self

    def digest(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


class ModelExplanationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: ProviderProbeRequest
    payload: ModelRankingPayload

    @model_validator(mode="after")
    def require_external_provider(self) -> Self:
        if self.provider.mode != "external":
            raise ValueError("model explanation requires an external provider")
        return self


class ModelExplanationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["applied", "degraded"]
    ranked_hypothesis_ids: list[str] = Field(default_factory=list, max_length=32)
    code: str | None = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.status == "applied" and (
            not self.ranked_hypothesis_ids or self.code is not None
        ):
            raise ValueError("applied model output requires a ranking and no error code")
        if self.status == "degraded" and (
            self.ranked_hypothesis_ids or self.code is None
        ):
            raise ValueError("degraded model output requires an error code and no ranking")
        return self


class ProviderGateway(Protocol):
    async def probe(self, request: ProviderProbeRequest) -> ProviderProbeResult: ...


class ModelExplanationGateway(Protocol):
    async def explain(self, request: ModelExplanationRequest) -> ModelExplanationResult: ...


class UnavailableModelExplanationGateway:
    async def explain(self, _request: ModelExplanationRequest) -> ModelExplanationResult:
        return ModelExplanationResult(
            status="degraded",
            code="MODEL_GATEWAY_UNAVAILABLE",
        )


class HttpxProviderGateway:
    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        total_timeout_seconds: float = 5.0,
        max_response_bytes: int = 256 * 1024,
        max_models: int = 500,
        model_timeout_seconds: float = 8.0,
        max_model_response_bytes: int = 64 * 1024,
    ) -> None:
        self._transport = transport
        self._total_timeout_seconds = total_timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._max_models = max_models
        self._model_timeout_seconds = model_timeout_seconds
        self._max_model_response_bytes = max_model_response_bytes

    async def probe(self, request: ProviderProbeRequest) -> ProviderProbeResult:
        assert request.base_url is not None
        assert request.api_key is not None
        assert request.model is not None
        started = monotonic()
        try:
            async with asyncio.timeout(self._total_timeout_seconds):
                async with httpx.AsyncClient(
                    transport=self._transport,
                    timeout=httpx.Timeout(3.0, connect=3.0),
                    follow_redirects=False,
                    trust_env=False,
                ) as client, client.stream(
                    "GET",
                    f"{request.base_url.rstrip('/')}/models",
                    headers={
                        "Authorization": f"Bearer {request.api_key.get_secret_value()}",
                        "Accept": "application/json",
                    },
                ) as response:
                    response.raise_for_status()
                    declared_size = response.headers.get("Content-Length")
                    if (
                        declared_size is not None
                        and int(declared_size) > self._max_response_bytes
                    ):
                        raise ProviderResponseLimitError
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self._max_response_bytes:
                            raise ProviderResponseLimitError
                model_ids = await asyncio.to_thread(
                    _parse_model_ids,
                    bytes(body),
                    self._max_models,
                )
                if request.model not in model_ids:
                    raise ValueError("configured model was not listed by provider")
        except TimeoutError:
            return ProviderProbeResult(
                status="unavailable",
                provider="openai-compatible",
                model=request.model,
                code="PROVIDER_TIMEOUT",
                message="Provider did not respond within the bounded deadline.",
            )
        except ProviderResponseLimitError:
            return ProviderProbeResult(
                status="unavailable",
                provider="openai-compatible",
                model=request.model,
                code="PROVIDER_RESPONSE_LIMIT_EXCEEDED",
                message="Provider response exceeded the configured safety budget.",
            )
        except (httpx.HTTPError, ValueError, TypeError, RecursionError):
            return ProviderProbeResult(
                status="unavailable",
                provider="openai-compatible",
                model=request.model,
                code="PROVIDER_UNAVAILABLE",
                message="Provider did not pass the bounded health check.",
            )
        return ProviderProbeResult(
            status="verified",
            provider="openai-compatible",
            model=request.model,
            latency_ms=round((monotonic() - started) * 1_000),
        )

    async def explain(self, request: ModelExplanationRequest) -> ModelExplanationResult:
        provider = request.provider
        assert provider.base_url is not None
        assert provider.api_key is not None
        try:
            async with asyncio.timeout(self._model_timeout_seconds):
                async with httpx.AsyncClient(
                    transport=self._transport,
                    timeout=httpx.Timeout(5.0, connect=3.0),
                    follow_redirects=False,
                    trust_env=False,
                ) as client, client.stream(
                    "POST",
                    f"{provider.base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {provider.api_key.get_secret_value()}",
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    json=_model_request_body(request),
                ) as response:
                    if response.status_code == 429:
                        return _model_degraded("MODEL_RATE_LIMITED")
                    response.raise_for_status()
                    body = await _read_bounded_body(
                        response,
                        self._max_model_response_bytes,
                    )
                ranked_ids = await asyncio.to_thread(
                    _parse_model_ranking,
                    body,
                    [item.hypothesis_id for item in request.payload.hypotheses],
                )
        except TimeoutError:
            return _model_degraded("MODEL_TIMEOUT")
        except ModelResponseLimitError:
            return _model_degraded("MODEL_RESPONSE_LIMIT_EXCEEDED")
        except ModelOutputError:
            return _model_degraded("MODEL_OUTPUT_INVALID")
        except (httpx.HTTPError, ValueError, TypeError, RecursionError):
            return _model_degraded("MODEL_UNAVAILABLE")
        return ModelExplanationResult(
            status="applied",
            ranked_hypothesis_ids=ranked_ids,
        )


class ProviderResponseLimitError(ValueError):
    pass


class ModelResponseLimitError(ValueError):
    pass


class ModelOutputError(ValueError):
    pass


class _ModelRankingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["sqllens-model-ranking-response/v1"]
    ranked_hypothesis_ids: list[str] = Field(min_length=1, max_length=32)


def _model_request_body(request: ModelExplanationRequest) -> dict[str, object]:
    response_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "ranked_hypothesis_ids"],
        "properties": {
            "schema_version": {
                "type": "string",
                "enum": [MODEL_RANKING_RESPONSE_SCHEMA],
            },
            "ranked_hypothesis_ids": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
    }
    return {
        "model": request.provider.model,
        "temperature": 0,
        "max_tokens": 256,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "sqllens_model_ranking",
                "strict": True,
                "schema": response_schema,
            },
        },
        "messages": [
            {
                "role": "system",
                "content": (
                    "Rank only the supplied hypothesis IDs using only their linked evidence. "
                    "Return every supplied ID exactly once. Do not add facts, evidence, advice, "
                    "SQL, tools, URLs, or identifiers."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    request.payload.model_dump(mode="json"),
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            },
        ],
    }


async def _read_bounded_body(response: httpx.Response, max_bytes: int) -> bytes:
    declared_size = response.headers.get("Content-Length")
    if declared_size is not None:
        try:
            if int(declared_size) > max_bytes:
                raise ModelResponseLimitError
        except ValueError:
            raise ModelResponseLimitError from None
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise ModelResponseLimitError
    return bytes(body)


def _parse_model_ranking(body: bytes, expected_ids: list[str]) -> list[str]:
    try:
        envelope = json.loads(body)
        if not isinstance(envelope, dict) or len(envelope) > 64:
            raise ModelOutputError
        choices = envelope.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise ModelOutputError
        choice = choices[0]
        if (
            not isinstance(choice, dict)
            or len(choice) > 16
            or choice.get("finish_reason") != "stop"
        ):
            raise ModelOutputError
        message = choice.get("message")
        if not isinstance(message, dict) or len(message) > 16:
            raise ModelOutputError
        content = message.get("content")
        if not isinstance(content, str) or len(content.encode("utf-8")) > 16_384:
            raise ModelOutputError
        parsed = _ModelRankingResponse.model_validate_json(content)
    except (json.JSONDecodeError, ValueError, TypeError, RecursionError):
        raise ModelOutputError from None
    ranked_ids = parsed.ranked_hypothesis_ids
    if len(ranked_ids) != len(expected_ids) or set(ranked_ids) != set(expected_ids):
        raise ModelOutputError
    return ranked_ids


def _model_degraded(code: str) -> ModelExplanationResult:
    return ModelExplanationResult(status="degraded", code=code)


def _parse_model_ids(body: bytes, max_models: int) -> set[str]:
    payload = json.loads(body)
    models = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        raise ValueError("provider returned an invalid model list")
    if len(models) > max_models:
        raise ProviderResponseLimitError

    model_ids: set[str] = set()
    for item in models:
        if not isinstance(item, dict) or len(item) > 16:
            raise ProviderResponseLimitError
        for field_name, field_value in item.items():
            if not isinstance(field_name, str) or len(field_name) > 100:
                raise ProviderResponseLimitError
            if isinstance(field_value, str) and len(field_value) > 1_024:
                raise ProviderResponseLimitError
        model_id = item.get("id")
        if not isinstance(model_id, str) or not 1 <= len(model_id) <= 200:
            raise ProviderResponseLimitError
        model_ids.add(model_id)
    return model_ids
