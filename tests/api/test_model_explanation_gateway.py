from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
from sqllens_api.provider import (
    HttpxProviderGateway,
    ModelEvidence,
    ModelEvidenceCompleteness,
    ModelExplanationRequest,
    ModelHypothesis,
    ModelRankingPayload,
    ProviderProbeRequest,
)

EVIDENCE_ID = "ev_0123456789abcdef"
HYPOTHESIS_IDS = ["hyp_0123456789abcdef", "hyp_fedcba9876543210"]


def ranking_request() -> ModelExplanationRequest:
    return ModelExplanationRequest(
        provider=ProviderProbeRequest(
            mode="external",
            base_url="https://api.example.com/v1",
            api_key="provider-secret-canary",
            model="demo-model",
        ),
        payload=ModelRankingPayload(
            evidence_completeness=ModelEvidenceCompleteness(
                score=0.2,
                classification="insufficient",
                missing=["schema", "statistics", "ordinary_plan"],
            ),
            evidence=[
                ModelEvidence(
                    evidence_id=EVIDENCE_ID,
                    kind="sql_structure",
                    sensitivity="metadata",
                    summary="One parsed query structure with one predicate.",
                )
            ],
            hypotheses=[
                ModelHypothesis(
                    hypothesis_id=hypothesis_id,
                    statement="A bounded deterministic hypothesis.",
                    confidence=0.2,
                    evidence_ids=[EVIDENCE_ID],
                )
                for hypothesis_id in HYPOTHESIS_IDS
            ],
        ),
    )


def completion(ranked_ids: list[str]) -> dict[str, object]:
    return {
        "id": "chatcmpl-test",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "schema_version": "sqllens-model-ranking-response/v1",
                            "ranked_hypothesis_ids": ranked_ids,
                        }
                    ),
                },
            }
        ],
    }


@pytest.mark.asyncio
async def test_model_gateway_sends_only_bounded_redacted_payload() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=completion(list(reversed(HYPOTHESIS_IDS))))

    gateway = HttpxProviderGateway(transport=httpx.MockTransport(handler))

    result = await gateway.explain(ranking_request())

    assert result.status == "applied"
    assert result.ranked_hypothesis_ids == list(reversed(HYPOTHESIS_IDS))
    assert len(captured) == 1
    sent = captured[0]
    assert str(sent.url) == "https://api.example.com/v1/chat/completions"
    assert sent.headers["authorization"] == "Bearer provider-secret-canary"
    body = json.loads(sent.content)
    serialized = json.dumps(body)
    assert "provider-secret-canary" not in serialized
    assert body["model"] == "demo-model"
    assert body["temperature"] == 0
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert "tools" not in body
    user_payload = json.loads(body["messages"][1]["content"])
    assert user_payload["schema_version"] == "sqllens-model-ranking-request/v1"
    assert {item["sensitivity"] for item in user_payload["evidence"]} == {"metadata"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "code"),
    [
        (httpx.Response(429), "MODEL_RATE_LIMITED"),
        (httpx.Response(503), "MODEL_UNAVAILABLE"),
        (httpx.Response(200, content=b"{"), "MODEL_OUTPUT_INVALID"),
        (
            httpx.Response(200, json=completion(["hyp_0000000000000000"])),
            "MODEL_OUTPUT_INVALID",
        ),
    ],
)
async def test_model_gateway_degrades_on_http_or_malformed_output(
    response: httpx.Response,
    code: str,
) -> None:
    gateway = HttpxProviderGateway(
        transport=httpx.MockTransport(lambda _request: response)
    )

    result = await gateway.explain(ranking_request())

    assert result.status == "degraded"
    assert result.code == code
    assert result.ranked_hypothesis_ids == []


class SlowModelStream(httpx.AsyncByteStream):
    async def __aiter__(self):  # type: ignore[no-untyped-def]
        await asyncio.sleep(0.05)
        yield json.dumps(completion(HYPOTHESIS_IDS)).encode()


@pytest.mark.asyncio
async def test_model_gateway_has_total_deadline_and_response_byte_limit() -> None:
    slow = HttpxProviderGateway(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, stream=SlowModelStream())
        ),
        model_timeout_seconds=0.01,
    )
    oversized = HttpxProviderGateway(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, content=b"x" * 1025)
        ),
        max_model_response_bytes=1024,
    )

    slow_result = await slow.explain(ranking_request())
    oversized_result = await oversized.explain(ranking_request())

    assert slow_result.status == "degraded"
    assert slow_result.code == "MODEL_TIMEOUT"
    assert oversized_result.status == "degraded"
    assert oversized_result.code == "MODEL_RESPONSE_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_model_gateway_json_parsing_is_inside_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_loads = json.loads

    def slow_loads(value: str | bytes | bytearray) -> object:
        time.sleep(0.05)
        return real_loads(value)

    monkeypatch.setattr("sqllens_api.provider.json.loads", slow_loads)
    gateway = HttpxProviderGateway(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json=completion(HYPOTHESIS_IDS))
        ),
        model_timeout_seconds=0.01,
    )

    result = await gateway.explain(ranking_request())

    assert result.status == "degraded"
    assert result.code == "MODEL_TIMEOUT"
