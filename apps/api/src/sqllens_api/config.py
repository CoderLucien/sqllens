from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_data_dir() -> Path:
    return Path(os.environ.get("SQLLENS_DATA_DIR", ".data"))


def _default_web_dist_dir() -> Path | None:
    configured = os.environ.get("SQLLENS_WEB_DIST_DIR")
    if configured:
        return Path(configured)
    candidate = Path(__file__).resolve().parents[4] / "apps" / "web" / "dist"
    return candidate if candidate.exists() else None


def _default_bootstrap_code_file() -> Path | None:
    configured = os.environ.get("SQLLENS_BOOTSTRAP_CODE_FILE")
    return Path(configured) if configured else None


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path = field(default_factory=_default_data_dir)
    bootstrap_ttl_seconds: int = 600
    bootstrap_max_attempts: int = 5
    setup_session_ttl_seconds: int = 1_800
    cookie_secure: bool = False
    web_dist_dir: Path | None = field(default_factory=_default_web_dist_dir)
    bootstrap_code_file: Path | None = field(default_factory=_default_bootstrap_code_file)
    bind_host: str = field(default_factory=lambda: os.environ.get("SQLLENS_BIND_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("SQLLENS_PORT", "8080")))

    @property
    def database_path(self) -> Path:
        return self.data_dir / "sqllens.db"

    @property
    def session_key_path(self) -> Path:
        return self.data_dir / "setup-session.key"
