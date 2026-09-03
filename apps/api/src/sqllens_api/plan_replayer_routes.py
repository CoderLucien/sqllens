"""Plan Replayer 离线上传接口。

``POST /api/v1/m0/plan-replayer`` 接收 zip 诊断包，解析后仅驻留会话内存
（不写磁盘、不写日志、不写响应原文），返回不含 SQL 原文的轻量摘要。
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI, Header, Request
from starlette.responses import JSONResponse, Response

from sqllens_api.errors import ApiError
from sqllens_api.plan_replayer import (
    PlanReplayerBundle,
    PlanReplayerError,
    parse_plan_replayer_zip,
    plan_replayer_summary,
)

_UPLOAD_BODY_LIMIT = 32 * 1024 * 1024  # 与解析器总上限一致

type RequireOwnerSession = Callable[[Request, str | None], str]


class PlanReplayerStore:
    """会话内存内的 Plan Replayer 证据视图，仅保留最近一次上传。"""

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
    require_owner_session: RequireOwnerSession,
) -> None:
    """注册 Plan Replayer 离线上传接口（只读、会话内存）。"""

    @app.post("/api/v1/m0/plan-replayer")
    async def upload_plan_replayer(
        request: Request,
        x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    ) -> JSONResponse:
        require_owner_session(request, x_csrf_token)

        body = await _read_upload_body(request)
        try:
            bundle = parse_plan_replayer_zip(body)
        except PlanReplayerError as exc:
            raise ApiError(422, "PLAN_REPLAYER_INVALID", str(exc)) from None

        await store.replace(bundle)
        return JSONResponse(content=plan_replayer_summary(bundle))

    @app.get("/api/v1/m0/plan-replayer")
    async def get_plan_replayer(request: Request) -> JSONResponse:
        require_owner_session(request, None)
        bundle = await store.view()
        if bundle is None:
            return JSONResponse(content={"available": False})
        return JSONResponse(content=plan_replayer_summary(bundle))

    @app.delete("/api/v1/m0/plan-replayer", status_code=204)
    async def clear_plan_replayer(
        request: Request,
        x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    ) -> Response:
        require_owner_session(request, x_csrf_token)
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
