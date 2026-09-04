from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import FastAPI, Request
from pydantic import ValidationError
from starlette.responses import JSONResponse

from sqllens_api.errors import ApiError
from sqllens_api.v4_ai import (  # noqa: F401（AiConfigInput/_headers 等供探测路由与既有测试复用）
    _RETRYABLE_PATH_STATUSES,
    AiConfigInput,
    _candidate_urls,
    _classify,
    _headers,
    augment_report_with_ai,
)
from sqllens_api.v4_diagnosis import diagnose_v4

V4_BODY_LIMIT = 2 * 1024 * 1024
AI_TEST_TIMEOUT_SECONDS = 10.0

_DIAGNOSE_REQUIRED = frozenset(
    {"schema_version", "sql", "runtime", "plan", "stats", "schema"}
)


def register_v4_routes(app: FastAPI) -> None:
    """Register the bounded v4 two-screen tool endpoints (loopback MVP, no owner auth)."""

    @app.post("/api/v1/v4/diagnose")
    async def v4_diagnose(request: Request) -> JSONResponse:
        evidence = await _parse_json_body(request, V4_BODY_LIMIT)
        ai_raw = evidence.pop("ai_config", None)
        _validate_evidence(evidence)
        report = diagnose_v4(evidence, mode="rules")
        if ai_raw is not None:
            if not isinstance(ai_raw, dict):
                raise ApiError(422, "VALIDATION_ERROR", "ai_config 必须是 JSON 对象。")
            try:
                config = AiConfigInput.model_validate(ai_raw)
            except ValidationError:
                raise ApiError(422, "VALIDATION_ERROR", "AI 配置请求不满足约束。") from None
            report = await augment_report_with_ai(report, evidence, config)
        return JSONResponse(content=report)

    @app.post("/api/v1/v4/ai/test")
    async def v4_ai_test(request: Request) -> JSONResponse:
        body = await _parse_json_body(request, 16 * 1024)
        try:
            config = AiConfigInput.model_validate(body)
        except ValidationError:
            raise ApiError(422, "VALIDATION_ERROR", "AI 配置请求不满足约束。") from None
        result = await _probe_ai(config)
        return JSONResponse(content=result)

    @app.post("/api/v1/v4/ai/models")
    async def v4_ai_models(request: Request) -> JSONResponse:
        body = await _parse_json_body(request, 16 * 1024)
        try:
            config = AiConfigInput.model_validate(body)
        except ValidationError:
            raise ApiError(422, "VALIDATION_ERROR", "AI 配置请求不满足约束。") from None
        models = await _list_models(config)
        return JSONResponse(content=models)


def _validate_evidence(evidence: dict[str, Any]) -> None:
    missing = _DIAGNOSE_REQUIRED - set(evidence)
    if missing:
        raise ApiError(422, "VALIDATION_ERROR", f"证据缺少字段：{', '.join(sorted(missing))}。")
    if evidence.get("schema_version") != "evidence/v3":
        raise ApiError(422, "VALIDATION_ERROR", "schema_version 必须为 evidence/v3。")
    runtime = evidence.get("runtime")
    if not isinstance(runtime, dict) or not isinstance(runtime.get("exec_count"), int):
        raise ApiError(422, "VALIDATION_ERROR", "runtime.exec_count 必须为整数。")


async def _parse_json_body(request: Request, limit: int) -> dict[str, Any]:
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > limit:
                raise ApiError(413, "BODY_TOO_LARGE", "请求体超出限制。")
            body.extend(chunk)
        parsed = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(parsed, dict):
            raise ApiError(422, "VALIDATION_ERROR", "请求体必须是 JSON 对象。")
        return parsed
    except ApiError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        raise ApiError(422, "VALIDATION_ERROR", "请求体不是合法 JSON。") from None
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


_PROBE_PAYLOAD: dict[str, Any] = {
    "max_tokens": 1,
    "messages": [{"role": "user", "content": "ping"}],
}


async def _probe_ai(
    config: AiConfigInput, *, transport: httpx.AsyncBaseTransport | None = None
) -> dict[str, Any]:
    base = config.base_url.rstrip("/")
    if config.protocol == "anthropic":
        urls = [f"{base}/v1/messages"]
    else:
        urls = _candidate_urls(base, "/chat/completions")
    payload = {"model": config.model, **_PROBE_PAYLOAD}
    async with httpx.AsyncClient(timeout=AI_TEST_TIMEOUT_SECONDS, transport=transport) as client:
        for index, url in enumerate(urls):
            try:
                response = await client.post(url, headers=_headers(config), json=payload)
            except httpx.HTTPError as exc:
                return _classify(exc)
            if 200 <= response.status_code < 300:
                return {
                    "ok": True,
                    "code": "OK",
                    "message_zh": "连接成功：模型可达，最小诊断请求通过。已可保存启用。",
                    "model": config.model,
                }
            if not (
                index < len(urls) - 1 and response.status_code in _RETRYABLE_PATH_STATUSES
            ):
                return _classify(
                    httpx.HTTPStatusError(
                        "probe failed", request=response.request, response=response
                    )
                )
    return {"ok": False, "code": "UNKNOWN", "message_zh": "探测未产生结果。"}


async def _list_models(
    config: AiConfigInput, *, transport: httpx.AsyncBaseTransport | None = None
) -> dict[str, Any]:
    base = config.base_url.rstrip("/")
    if config.protocol == "anthropic":
        urls = [f"{base}/v1/models"]
    else:
        urls = _candidate_urls(base, "/models")
    async with httpx.AsyncClient(timeout=AI_TEST_TIMEOUT_SECONDS, transport=transport) as client:
        for index, url in enumerate(urls):
            try:
                response = await client.get(url, headers=_headers(config))
            except httpx.HTTPError as exc:
                result = _classify(exc)
                result["models"] = []
                return result
            if 200 <= response.status_code < 300:
                data = response.json()
                ids = sorted(
                    {
                        str(item.get("id", ""))
                        for item in data.get("data", [])
                        if isinstance(item, dict) and item.get("id")
                    }
                )
                return {"ok": True, "code": "OK", "models": ids, "message_zh": f"识别到 {len(ids)} 个可用模型。"}
            if not (
                index < len(urls) - 1 and response.status_code in _RETRYABLE_PATH_STATUSES
            ):
                result = _classify(
                    httpx.HTTPStatusError(
                        "list failed", request=response.request, response=response
                    )
                )
                result["models"] = []
                return result
    return {"ok": False, "code": "UNKNOWN", "message_zh": "未识别到可用模型。", "models": []}
