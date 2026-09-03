from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from sqllens_api.config import Settings
from sqllens_api.errors import error_response


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


def create_app(*, settings: Settings | None = None) -> FastAPI:
    """Create the deliberately small M0 private-preview application.

    Platform setup, persistent credentials, model settings, multi-Source lifecycle,
    and legacy diagnosis routes are intentionally not registered in M0.
    """

    runtime_settings = settings or Settings()
    app = FastAPI(
        title="SQLLens M0 Private Preview API",
        version="0.1.0-m0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = runtime_settings

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        supplied_request_id = request.headers.get("X-Request-ID", "")
        request.state.request_id = (
            supplied_request_id
            if 1 <= len(supplied_request_id) <= 100 and supplied_request_id.isascii()
            else uuid.uuid4().hex
        )
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return _secure_response(response, api_response=request.url.path.startswith("/api/"))

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        _error: RequestValidationError,
    ) -> JSONResponse:
        return error_response(
            request,
            status_code=422,
            code="VALIDATION_ERROR",
            message="The request did not match the expected schema.",
        )

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok", "edition": "m0-private-preview"}

    web_dist = runtime_settings.web_dist_dir
    if isinstance(web_dist, Path) and (web_dist / "index.html").is_file():
        index_path = web_dist / "index.html"

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
            return {"service": "sqllens-m0", "status": "web-build-missing"}

    return app
