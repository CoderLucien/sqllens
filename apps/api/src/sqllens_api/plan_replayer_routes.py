"""Plan Replayer 离线上传接口（v4 loopback MVP，无鉴权）。

``POST /api/v1/v4/plan-replayer`` 接收 zip 诊断包，解析为 evidence/v3 结构，
仅驻留会话内存（不写磁盘、不写日志、不写响应原文）。与 v4 诊断内核
（``POST /api/v1/v4/diagnose``）共用同一入口契约。
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response

from sqllens_api.errors import ApiError
from sqllens_api.plan_replayer import (
    PlanReplayerBundle,
    PlanReplayerError,
    bundle_to_evidence_v3,
    parse_plan_replayer_zip,
    plan_replayer_summary,
)

_UPLOAD_BODY_LIMIT = 32 * 1024 * 1024  # 与解析器总上限一致


class PlanReplayerStore:
    """会话内存内的 Plan Replayer evidence/v3 视图，仅保留最近一次上传。"""

    def __init__(self) -> None:
        self._bundle: PlanReplayerBundle | None = None

    async def replace(self, bundle: PlanReplayerBundle) -> PlanReplayerBundle:
        self._bundle = bundle
        return bundle

    async def view(self) -> PlanReplayerBundle | None:
        return self._bundle

    async def clear(self) -> None:
        self._bundle = None


def register_plan_replayer_routes(
    app: FastAPI,
    *,
    store: PlanReplayerStore,
) -> None:
    """注册 Plan Replayer 离线上传接口（只读、会话内存、无鉴权 loopback MVP）。"""

    @app.post("/api/v1/v4/plan-replayer")
    async def upload_plan_replayer(request: Request) -> JSONResponse:
        body = await _read_upload_body(request)
        try:
            bundle = parse_plan_replayer_zip(body)
        except PlanReplayerError as exc:
            raise ApiError(422, "PLAN_REPLAYER_INVALID", str(exc)) from None

        await store.replace(bundle)
        # 返回 evidence/v3 结构（供诊断内核 / 前端继续消费），另附轻量摘要。
        payload = bundle_to_evidence_v3(bundle)
        payload["_summary"] = plan_replayer_summary(bundle)
        return JSONResponse(content=payload)

    @app.get("/api/v1/v4/plan-replayer")
    async def get_plan_replayer() -> JSONResponse:
        bundle = await store.view()
        if bundle is None:
            return JSONResponse(content={"available": False})
        payload = bundle_to_evidence_v3(bundle)
        payload["_summary"] = plan_replayer_summary(bundle)
        return JSONResponse(content=payload)

    @app.delete("/api/v1/v4/plan-replayer", status_code=204)
    async def clear_plan_replayer() -> Response:
        await store.clear()
        return Response(status_code=204)


async def _read_upload_body(request: Request) -> bytes:
    """读取原始请求体并施加字节上限，避免大包压垮进程。"""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > _UPLOAD_BODY_LIMIT:
                raise ApiError(
                    413,
                    "PLAN_REPLAYER_TOO_LARGE",
                    f"诊断包超过 {_UPLOAD_BODY_LIMIT} 字节上限",
                )
        except ValueError:
            pass
    body = await request.body()
    if len(body) > _UPLOAD_BODY_LIMIT:
        raise ApiError(
            413,
            "PLAN_REPLAYER_TOO_LARGE",
            f"诊断包超过 {_UPLOAD_BODY_LIMIT} 字节上限",
        )
    return body
