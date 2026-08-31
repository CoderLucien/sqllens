from __future__ import annotations

import asyncio
import json
from time import monotonic
from typing import Literal, Protocol
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


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


class ProviderGateway(Protocol):
    async def probe(self, request: ProviderProbeRequest) -> ProviderProbeResult: ...


class HttpxProviderGateway:
    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        total_timeout_seconds: float = 5.0,
        max_response_bytes: int = 256 * 1024,
        max_models: int = 500,
    ) -> None:
        self._transport = transport
        self._total_timeout_seconds = total_timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._max_models = max_models

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


class ProviderResponseLimitError(ValueError):
    pass


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
