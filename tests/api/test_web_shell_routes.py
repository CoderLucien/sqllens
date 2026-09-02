from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqllens_api.app import create_app
from sqllens_api.config import Settings


def test_static_web_shell_serves_setup_and_daily_deep_links(tmp_path: Path) -> None:
    web_dist = tmp_path / "web"
    web_dist.mkdir()
    (web_dist / "index.html").write_text("<main>SQLLens shell</main>", encoding="utf-8")
    settings = Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        web_dist_dir=web_dist,
    )
    client = TestClient(create_app(settings=settings))

    for path in ("/setup", "/app", "/app/login", "/app/workbench", "/app/settings/model"):
        response = client.get(path)

        assert response.status_code == 200, path
        assert response.text == "<main>SQLLens shell</main>", path
        assert response.headers["content-type"].startswith("text/html"), path
