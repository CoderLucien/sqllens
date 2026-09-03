from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_m0_image_has_one_persistent_data_path_and_no_secrets_path() -> None:
    dockerfile = (REPOSITORY_ROOT / "apps/api/Dockerfile").read_text(encoding="utf-8")

    assert "SQLLENS_DATA_DIR=/data" in dockerfile
    assert "SQLLENS_SECRETS_DIR" not in dockerfile
    assert "/secrets" not in dockerfile
    assert 'CMD ["web-api"]' in dockerfile
