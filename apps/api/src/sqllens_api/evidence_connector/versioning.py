from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class DatabaseProduct(StrEnum):
    TIDB = "tidb"
    PINGKAIDB = "pingkaidb"
    UNKNOWN = "unknown"


class DetectionStatus(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class VersionFingerprint:
    version: str
    version_comment: str
    tidb_version: str


@dataclass(frozen=True, slots=True)
class DetectedDatabaseVersion:
    status: DetectionStatus
    product: DatabaseProduct
    version: str | None
    pack_id: str | None
    upstream_version: str | None
    reason_code: str

    @property
    def is_supported(self) -> bool:
        return self.status is DetectionStatus.SUPPORTED


_PINGKAI_MARKER = re.compile(r"(?:\bpingkai(?:db)?\b|平凯数据库)", re.IGNORECASE)
_TIDB_MARKER = re.compile(r"\btidb\b", re.IGNORECASE)
_PINGKAI_71_VERSION = re.compile(r"(?<![0-9])v?(7\.1\.[0-9]+(?:-[0-9.]+)?)(?![0-9])", re.IGNORECASE)
_TIDB_85_VERSION = re.compile(r"(?<![0-9])v?(8\.5\.[0-9]+)(?![0-9])", re.IGNORECASE)


def detect_database_version(fingerprint: VersionFingerprint) -> DetectedDatabaseVersion:
    fields = (fingerprint.version, fingerprint.version_comment, fingerprint.tidb_version)
    combined = "\n".join(fields)

    if _PINGKAI_MARKER.search(combined):
        return _detect_pingkaidb(fields)
    if _TIDB_MARKER.search(combined):
        return _detect_tidb(fields)
    return DetectedDatabaseVersion(
        status=DetectionStatus.UNKNOWN,
        product=DatabaseProduct.UNKNOWN,
        version=None,
        pack_id=None,
        upstream_version=None,
        reason_code="DATABASE_PRODUCT_UNKNOWN",
    )


def _detect_pingkaidb(fields: tuple[str, str, str]) -> DetectedDatabaseVersion:
    vendor_versions = _versions(_PINGKAI_71_VERSION, fields)
    upstream_versions = _versions(_TIDB_85_VERSION, fields)
    if len(vendor_versions) > 1 or len(upstream_versions) > 1:
        return _ambiguous(DatabaseProduct.PINGKAIDB)
    if not vendor_versions:
        return _unsupported(DatabaseProduct.PINGKAIDB)
    return DetectedDatabaseVersion(
        status=DetectionStatus.SUPPORTED,
        product=DatabaseProduct.PINGKAIDB,
        version=next(iter(vendor_versions)),
        pack_id="pingkaidb-7.1",
        upstream_version=next(iter(upstream_versions), None),
        reason_code="DATABASE_VERSION_SUPPORTED",
    )


def _detect_tidb(fields: tuple[str, str, str]) -> DetectedDatabaseVersion:
    versions = _versions(_TIDB_85_VERSION, fields)
    if len(versions) > 1:
        return _ambiguous(DatabaseProduct.TIDB)
    if not versions:
        return _unsupported(DatabaseProduct.TIDB)
    return DetectedDatabaseVersion(
        status=DetectionStatus.SUPPORTED,
        product=DatabaseProduct.TIDB,
        version=next(iter(versions)),
        pack_id="tidb-8.5",
        upstream_version=None,
        reason_code="DATABASE_VERSION_SUPPORTED",
    )


def _versions(pattern: re.Pattern[str], fields: tuple[str, str, str]) -> set[str]:
    return {match for field in fields for match in pattern.findall(field)}


def _ambiguous(product: DatabaseProduct) -> DetectedDatabaseVersion:
    return DetectedDatabaseVersion(
        status=DetectionStatus.AMBIGUOUS,
        product=product,
        version=None,
        pack_id=None,
        upstream_version=None,
        reason_code="DATABASE_VERSION_AMBIGUOUS",
    )


def _unsupported(product: DatabaseProduct) -> DetectedDatabaseVersion:
    return DetectedDatabaseVersion(
        status=DetectionStatus.UNSUPPORTED,
        product=product,
        version=None,
        pack_id=None,
        upstream_version=None,
        reason_code="DATABASE_VERSION_UNSUPPORTED",
    )
