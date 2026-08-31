from __future__ import annotations

from time import monotonic
from typing import Literal, Protocol
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class ProviderProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["external", "local"]
    base_url: str | None = None
    api_key: SecretStr | None = None
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
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    async def probe(self, request: ProviderProbeRequest) -> ProviderProbeResult:
        assert request.base_url is not None
        assert request.api_key is not None
        assert request.model is not None
        started = monotonic()
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=httpx.Timeout(5.0, connect=3.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get(
                    f"{request.base_url.rstrip('/')}/models",
                    headers={
                        "Authorization": f"Bearer {request.api_key.get_secret_value()}",
                        "Accept": "application/json",
                    },
                )
                response.raise_for_status()
                payload = response.json()
                models = payload.get("data") if isinstance(payload, dict) else None
                if not isinstance(models, list):
                    raise ValueError("provider returned an invalid model list")
                model_ids = {
                    item.get("id") for item in models if isinstance(item, dict) and item.get("id")
                }
                if request.model not in model_ids:
                    raise ValueError("configured model was not listed by provider")
        except (httpx.HTTPError, ValueError, TypeError):
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
