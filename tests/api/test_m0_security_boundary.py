from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqllens_api.app import create_app
from sqllens_api.config import Settings

DEFERRED_EXACT_ROUTES = {
    "/api/v1/setup/bootstrap",
    "/api/v1/setup/security-policy",
    "/api/v1/setup/model-probes",
    "/api/v1/setup/finalize",
    "/api/v1/settings/model/verify",
    "/api/v1/settings/model",
    "/api/v1/cases/sql",
    "/api/v1/jobs/{job_id}",
    "/api/v1/cases/{case_id}",
}

DEFERRED_ROUTE_PREFIXES = {
    "/api/v1/sources",
    "/api/v1/prometheus",
    "/api/v1/tem",
    "/api/v1/plan-replayer",
    "/api/v1/pingkaidb",
}

DEFERRED_HTTP_OPERATIONS = (
    ("POST", "/api/v1/setup/bootstrap"),
    ("PUT", "/api/v1/setup/security-policy"),
    ("POST", "/api/v1/setup/model-probes"),
    ("POST", "/api/v1/setup/finalize"),
    ("POST", "/api/v1/settings/model/verify"),
    ("PUT", "/api/v1/settings/model"),
    ("DELETE", "/api/v1/settings/model"),
    ("POST", "/api/v1/cases/sql"),
    ("GET", "/api/v1/jobs/job_deferred"),
    ("GET", "/api/v1/cases/case_deferred"),
    ("GET", "/api/v1/sources"),
    ("POST", "/api/v1/sources"),
    ("GET", "/api/v1/sources/src_deferred"),
    ("DELETE", "/api/v1/sources/src_deferred"),
    ("POST", "/api/v1/sources/src_deferred/tests"),
    ("PUT", "/api/v1/sources/src_deferred/credentials"),
    ("GET", "/api/v1/prometheus"),
    ("GET", "/api/v1/tem"),
    ("POST", "/api/v1/plan-replayer"),
    ("GET", "/api/v1/pingkaidb"),
)

M0_OWNER_API_ROUTES = {
    ("GET", "/healthz"),
    ("GET", "/api/v1/setup/status"),
    ("POST", "/api/v1/setup/owner"),
    ("GET", "/api/v1/auth/session"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/logout"),
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

    assert registered.isdisjoint(DEFERRED_EXACT_ROUTES)
    assert not {
        path
        for path in registered
        if any(
            path == prefix or path.startswith(f"{prefix}/") for prefix in DEFERRED_ROUTE_PREFIXES
        )
    }


@pytest.mark.parametrize(("method", "path"), DEFERRED_HTTP_OPERATIONS)
def test_m0_deferred_operations_return_404(
    tmp_path: Path,
    method: str,
    path: str,
) -> None:
    with TestClient(create_app(settings=_settings(tmp_path))) as client:
        response = client.request(method, path, json={})

    assert response.status_code == 404


def test_m0_registers_only_the_required_owner_session_routes(tmp_path: Path) -> None:
    app = create_app(settings=_settings(tmp_path))

    registered = {
        (method, route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods
        if route.path == "/healthz" or route.path.startswith("/api/")
    }

    assert registered == M0_OWNER_API_ROUTES
