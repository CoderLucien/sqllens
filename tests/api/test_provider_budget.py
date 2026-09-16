from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
from pydantic import ValidationError
from sqllens_api.provider import HttpxProviderGateway, ProviderProbeRequest


def request() -> ProviderProbeRequest:
    return ProviderProbeRequest(
        mode="external",
        base_url="https://api.example.com/v1",
        api_key="provider-secret",
        model="target-model",
    )


@pytest.mark.asyncio
async def test_provider_model_list_rejects_excessive_bytes_items_and_fields() -> None:
    payloads = [
        b'{"data":' + (b" " * (256 * 1024)) + b"[]}",
        json.dumps({"data": [{"id": f"model-{index}"} for index in range(501)]}).encode(),
        json.dumps({"data": [{"id": "x" * 201}]}).encode(),
    ]

    for payload in payloads:
        gateway = HttpxProviderGateway(
            transport=httpx.MockTransport(
                lambda _request, body=payload: httpx.Response(200, content=body)
            )
        )
        result = await gateway.probe(request())
        assert result.status == "unavailable"
        assert result.code == "PROVIDER_RESPONSE_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_provider_rejects_twenty_five_thousand_models() -> None:
    payload = json.dumps(
        {"data": [{"id": f"model-{index}"} for index in range(25_001)]}
    ).encode()
    gateway = HttpxProviderGateway(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, content=payload)
        ),
        max_response_bytes=len(payload) + 1,
    )

    result = await gateway.probe(request())

    assert result.status == "unavailable"
    assert result.code == "PROVIDER_RESPONSE_LIMIT_EXCEEDED"


class SlowStream(httpx.AsyncByteStream):
    async def __aiter__(self):  # type: ignore[no-untyped-def]
        await asyncio.sleep(0.05)
        yield b'{"data":[{"id":"target-model"}]}'


@pytest.mark.asyncio
async def test_provider_probe_has_a_total_deadline() -> None:
    gateway = HttpxProviderGateway(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, stream=SlowStream())
        ),
        total_timeout_seconds=0.01,
    )

    result = await gateway.probe(request())

    assert result.status == "unavailable"
    assert result.code == "PROVIDER_TIMEOUT"


@pytest.mark.asyncio
async def test_provider_json_parsing_is_inside_the_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_loads = json.loads

    def slow_loads(value: bytes | bytearray) -> object:
        time.sleep(0.05)
        return real_loads(value)

    monkeypatch.setattr("sqllens_api.provider.json.loads", slow_loads)
    gateway = HttpxProviderGateway(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                content=b'{"data":[{"id":"target-model"}]}',
            )
        ),
        total_timeout_seconds=0.01,
    )

    result = await gateway.probe(request())

    assert result.status == "unavailable"
    assert result.code == "PROVIDER_TIMEOUT"


def test_provider_api_key_is_bounded_at_the_request_boundary() -> None:
    with pytest.raises(ValidationError):
        ProviderProbeRequest(
            mode="external",
            base_url="https://api.example.com/v1",
            api_key="x" * 4_097,
            model="target-model",
        )
    with pytest.raises(ValidationError):
        ProviderProbeRequest(
            mode="external",
            base_url=f"https://api.example.com/{'x' * 2_048}",
            api_key="provider-secret",
            model="target-model",
        )
