from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.responses import JSONResponse

from sqllens_api.errors import ApiError
from sqllens_api.v4_diagnosis import diagnose_v4

V4_BODY_LIMIT = 2 * 1024 * 1024
AI_TEST_TIMEOUT_SECONDS = 10.0

# 路径未实现类状态：Base URL 缺 /v1 时补全重试一次（rd2 实测：裸域 501、/v1 下端点真实存在）。
_RETRYABLE_PATH_STATUSES = frozenset({404, 501})

_DIAGNOSE_REQUIRED = frozenset(
    {"schema_version", "sql", "runtime", "plan", "stats", "schema"}
)


class AiConfigInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(min_length=1, max_length=2048)
    api_key: str = Field(min_length=1, max_length=4096)
    model: str = Field(min_length=1, max_length=256)
    protocol: str = Field(default="openai", pattern="^(openai|anthropic)$")


def register_v4_routes(app: FastAPI) -> None:
    """Register the bounded v4 two-screen tool endpoints (loopback MVP, no owner auth)."""

    @app.post("/api/v1/v4/diagnose")
    async def v4_diagnose(request: Request) -> JSONResponse:
        evidence = await _parse_json_body(request, V4_BODY_LIMIT)
        _validate_evidence(evidence)
        report = diagnose_v4(evidence, mode="rules")
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


def _headers(config: AiConfigInput) -> dict[str, str]:
    if config.protocol == "anthropic":
        return {
            "x-api-key": config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
    return {"Authorization": f"Bearer {config.api_key}", "Content-Type": "application/json"}


def _classify(exc: httpx.HTTPError) -> dict[str, Any]:
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout)):
        return {
            "ok": False,
            "code": "NETWORK_UNREACHABLE",
            "message_zh": "网络不可达 / 超时：请检查 Base URL 与本机网络（防火墙 / 代理）。",
        }
    response = getattr(exc, "response", None)
    if response is None:
        return {"ok": False, "code": "UNKNOWN", "message_zh": f"未知错误：{exc.__class__.__name__}"}
    status = response.status_code
    if status == 401:
        return {"ok": False, "code": "AUTH_INVALID", "message_zh": "401：API Key 无效。请检查 Key 后重试。"}
    if status == 403:
        return {"ok": False, "code": "AUTH_FORBIDDEN", "message_zh": "403：Key 权限不足，请确认该 Key 具有模型调用权限。"}
    if status == 404:
        return {"ok": False, "code": "MODEL_NOT_FOUND", "message_zh": "模型不存在：未找到该模型名，请用「识别模型」从可用列表选择。"}
    if status == 501:
        return {
            "ok": False,
            "code": "PROTOCOL_INCOMPATIBLE",
            "message_zh": (
                "协议不兼容：端点返回 HTTP 501（该路径未实现）。"
                "请确认 Base URL 为服务的 OpenAI/Anthropic 兼容根地址——"
                "若网关路由在 /v1 下，请在末尾补 /v1 后重试（如 https://api.deepseek.com/v1）。"
            ),
        }
    if status >= 400:
        return {
            "ok": False,
            "code": "PROTOCOL_INCOMPATIBLE",
            "message_zh": f"协议不兼容：端点返回 HTTP {status}，请确认网关适配层兼容 OpenAI/Anthropic 约束接口。",
        }
    return {"ok": False, "code": "UNKNOWN", "message_zh": f"未预期状态：HTTP {status}"}


def _candidate_urls(base: str, suffix: str) -> list[str]:
    """OpenAI 兼容路由可能在裸域或 /v1 下；裸域 404/501 时补 /v1 重试一次。"""
    urls = [f"{base}{suffix}"]
    if not urlsplit(base).path.rstrip("/").endswith("/v1"):
        urls.append(f"{base}/v1{suffix}")
    return urls


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
