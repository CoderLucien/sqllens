from __future__ import annotations

from pathlib import Path

from fastapi.routing import APIRoute
from sqllens_api.app import create_app
from sqllens_api.config import Settings

DEFERRED_API_ROUTES = {
    "/api/v1/setup/status",
    "/api/v1/setup/owner",
    "/api/v1/setup/bootstrap",
    "/api/v1/setup/security-policy",
    "/api/v1/setup/model-probes",
    "/api/v1/setup/finalize",
    "/api/v1/auth/session",
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/settings/model/verify",
    "/api/v1/settings/model",
    "/api/v1/cases/sql",
    "/api/v1/jobs/{job_id}",
    "/api/v1/cases/{case_id}",
    "/api/v1/sources",
    "/api/v1/sources/{source_id}",
    "/api/v1/sources/{source_id}/tests",
    "/api/v1/sources/{source_id}/credentials",
    "/api/v1/prometheus",
    "/api/v1/tem",
    "/api/v1/plan-replayer",
    "/api/v1/pingkaidb",
}


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        web_dist_dir=None,
    )


def test_m0_does_not_register_deferred_platform_routes(tmp_path: Path) -> None:
    app = create_app(settings=_settings(tmp_path))

    registered = {route.path for route in app.routes if isinstance(route, APIRoute)}

    assert registered.isdisjoint(DEFERRED_API_ROUTES)
