from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqllens_api.evidence_connector import (
    DatabaseProduct,
    DetectionStatus,
    VersionFingerprint,
    detect_database_version,
)

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "evidence_connector"


@pytest.mark.parametrize(
    ("fixture_name", "product", "version", "pack_id", "upstream_version"),
    [
        ("tidb-8.5.4.json", DatabaseProduct.TIDB, "8.5.4", "tidb-8.5", None),
        (
            "pingkaidb-7.1.8.json",
            DatabaseProduct.PINGKAIDB,
            "7.1.8-5.4",
            "pingkaidb-7.1",
            "8.5.4",
        ),
    ],
)
def test_detects_supported_recorded_versions(
    fixture_name: str,
    product: DatabaseProduct,
    version: str,
    pack_id: str,
    upstream_version: str | None,
) -> None:
    fixture = json.loads((FIXTURE_DIR / fixture_name).read_text(encoding="utf-8"))

    detected = detect_database_version(VersionFingerprint(**fixture["identity"]))

    assert detected.status is DetectionStatus.SUPPORTED
    assert detected.product is product
    assert detected.version == version
    assert detected.pack_id == pack_id
    assert detected.upstream_version == upstream_version
    assert detected.is_supported is True


def test_community_tidb_7_1_is_not_misclassified_as_pingkaidb() -> None:
    detected = detect_database_version(
        VersionFingerprint(
            version="5.7.25-TiDB-v7.1.6",
            version_comment="TiDB Server Community Edition",
            tidb_version="Release Version: v7.1.6\nEdition: Community",
        )
    )

    assert detected.status is DetectionStatus.UNSUPPORTED
    assert detected.product is DatabaseProduct.TIDB
    assert detected.pack_id is None
    assert detected.is_supported is False


def test_pingkaidb_requires_an_explicit_vendor_version() -> None:
    detected = detect_database_version(
        VersionFingerprint(
            version="5.7.25-TiDB-v8.5.4",
            version_comment="PingKaiDB Server",
            tidb_version="Open-Core Version: v8.5.4\nEdition: PingKaiDB Enterprise",
        )
    )

    assert detected.status is DetectionStatus.UNSUPPORTED
    assert detected.product is DatabaseProduct.PINGKAIDB
    assert detected.version is None
    assert detected.pack_id is None


def test_conflicting_release_versions_fail_closed_as_ambiguous() -> None:
    detected = detect_database_version(
        VersionFingerprint(
            version="5.7.25-TiDB-v8.5.4",
            version_comment="TiDB Server Community Edition",
            tidb_version="Release Version: v8.5.5\nEdition: Community",
        )
    )

    assert detected.status is DetectionStatus.AMBIGUOUS
    assert detected.product is DatabaseProduct.TIDB
    assert detected.version is None
    assert detected.pack_id is None


def test_unrecognized_product_fails_closed() -> None:
    detected = detect_database_version(
        VersionFingerprint(
            version="8.5.4",
            version_comment="MySQL compatible database",
            tidb_version="",
        )
    )

    assert detected.status is DetectionStatus.UNKNOWN
    assert detected.product is DatabaseProduct.UNKNOWN
    assert detected.version is None
    assert detected.pack_id is None
