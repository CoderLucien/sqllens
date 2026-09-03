"""Executable contract for Source write idempotency receipts.

The HTTP Idempotency-Key is never stored verbatim.  A server-owned receipt is
looked up by its authenticated Owner/method/route/key scope, binds a digest of
the complete canonical intent, and is committed in the same transaction as the
Source mutation and authorization audit record.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timedelta
from typing import Any, Literal

from vnext_canonical_json import canonical_json_bytes, canonical_sha256

SOURCE_IDEMPOTENCY_RECEIPT_REVISION = "source-idempotency-receipt/v1"
SOURCE_IDEMPOTENCY_RETENTION = timedelta(hours=24)
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
RECEIPT_ID = re.compile(r"^idem_[a-z0-9]{16,64}$")
SOURCE_ID = re.compile(r"^src_[a-z0-9]{16,64}$")
SHA256_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
HMAC_SHA256_DIGEST = re.compile(r"^hmac-sha256:[a-f0-9]{64}$")
SENSITIVE_RESPONSE_MARKERS = {
    "apikey",
    "authorization",
    "clientsecret",
    "cookie",
    "password",
    "privatekey",
    "secret",
    "setcookie",
    "token",
}


def _is_canonical_source_route(route: str) -> bool:
    if not isinstance(route, str):
        return False
    prefix = "/api/v1/sources"
    if route == prefix:
        return True
    if not route.startswith(prefix + "/") or route.endswith("/"):
        return False
    if any(character in route for character in "?#%\\") or any(
        character.isspace() for character in route
    ):
        return False
    segments = route[len(prefix) + 1 :].split("/")
    return bool(segments) and all(
        segment not in {"", ".", ".."} for segment in segments
    )


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        # Stored receipt corruption uses the same stable contract error as bad syntax.
        raise ValueError("invalid Source idempotency receipt time")  # noqa: TRY004
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except (OverflowError, ValueError) as exc:
        raise ValueError("invalid Source idempotency receipt time") from exc
    if parsed.tzinfo is None:
        raise ValueError("Source idempotency receipt time lacks a timezone")
    return parsed


def idempotency_key_digest(key: str) -> str:
    if not isinstance(key, str) or not IDEMPOTENCY_KEY.fullmatch(key):
        raise ValueError("invalid Idempotency-Key")
    return f"sha256:{hashlib.sha256(key.encode('utf-8')).hexdigest()}"


def source_write_scope_digest(
    *,
    owner_principal_id: str,
    method: str,
    canonical_route: str,
    idempotency_key: str,
) -> str:
    if not (
        isinstance(owner_principal_id, str)
        and bool(owner_principal_id)
        and isinstance(method, str)
        and isinstance(idempotency_key, str)
        and bool(IDEMPOTENCY_KEY.fullmatch(idempotency_key))
        and _is_canonical_source_route(canonical_route)
    ):
        raise ValueError("invalid Source idempotency scope")
    normalized_method = method.upper()
    if normalized_method not in {"POST", "PATCH", "DELETE"}:
        raise ValueError("unsupported Source write method")
    return canonical_sha256(
        {
            "scopeRevision": "source-idempotency-scope/v1",
            "ownerPrincipalId": owner_principal_id,
            "method": normalized_method,
            "canonicalRoute": canonical_route,
            "idempotencyKeyDigest": idempotency_key_digest(idempotency_key),
        }
    )


def source_write_intent_digest(
    *,
    source_id: str | None,
    expected_revision: int | None,
    request_body: dict[str, Any],
    digest_key: bytes,
) -> str:
    """Return a keyed digest so low-entropy request secrets are not an oracle."""

    if not isinstance(digest_key, bytes) or len(digest_key) < 32:
        raise ValueError("Source intent digest key must contain at least 32 bytes")
    create_intent = source_id is None and expected_revision is None
    mutation_intent = (
        isinstance(source_id, str)
        and bool(SOURCE_ID.fullmatch(source_id))
        and isinstance(expected_revision, int)
        and not isinstance(expected_revision, bool)
        and expected_revision >= 1
    )
    if not isinstance(request_body, dict) or not (create_intent or mutation_intent):
        raise ValueError("invalid Source write intent")
    intent = {
        "intentRevision": "source-write-intent/v1",
        "sourceId": source_id,
        "expectedRevision": expected_revision,
        "request": request_body,
    }
    return (
        "hmac-sha256:"
        + hmac.digest(digest_key, canonical_json_bytes(intent), "sha256").hex()
    )


def _validate_redacted_response(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                # Receipt validation deliberately exposes one stable corruption class.
                raise ValueError(  # noqa: TRY004
                    f"Source idempotency redacted response has a non-string key at {path}"
                )
            normalized = key.casefold().replace("_", "").replace("-", "")
            if any(marker in normalized for marker in SENSITIVE_RESPONSE_MARKERS):
                raise ValueError(
                    f"Source idempotency redacted response contains {path}.{key}"
                )
            _validate_redacted_response(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_redacted_response(child, f"{path}[{index}]")


def evaluate_source_idempotency_receipt(
    receipt: dict[str, Any] | None,
    *,
    scope_digest: str,
    intent_digest: str,
) -> Literal["reserve", "replay"]:
    """Return the only safe action for a Source write attempt.

    ``reserve`` means the caller may atomically insert an in-progress receipt.
    ``replay`` means the caller must return the stored status/body and must not
    execute any Source, credential, reservation, or verifier side effect.
    Stable ValueError messages are the corresponding public conflict codes.
    """

    if receipt is None:
        return "reserve"

    allowed_fields = {
        "receiptRevision",
        "receiptId",
        "scopeDigest",
        "intentDigest",
        "state",
        "httpStatus",
        "responseDigest",
        "responseBody",
        "resultSourceId",
        "resultRevision",
        "createdAt",
        "expiresAt",
    }
    if not isinstance(receipt, dict) or set(receipt) != allowed_fields:
        raise ValueError("invalid Source idempotency receipt shape")
    if receipt["receiptRevision"] != SOURCE_IDEMPOTENCY_RECEIPT_REVISION:
        raise ValueError("unsupported Source idempotency receipt revision")
    if not isinstance(receipt["receiptId"], str) or not RECEIPT_ID.fullmatch(
        receipt["receiptId"]
    ):
        raise ValueError("invalid Source idempotency receipt ID")
    if not (
        isinstance(scope_digest, str)
        and SHA256_DIGEST.fullmatch(scope_digest)
        and isinstance(intent_digest, str)
        and HMAC_SHA256_DIGEST.fullmatch(intent_digest)
    ):
        raise ValueError("invalid Source idempotency digest")
    if not isinstance(receipt["scopeDigest"], str) or not SHA256_DIGEST.fullmatch(
        receipt["scopeDigest"]
    ):
        raise ValueError("invalid Source idempotency receipt scope digest")
    if not isinstance(receipt["intentDigest"], str) or not HMAC_SHA256_DIGEST.fullmatch(
        receipt["intentDigest"]
    ):
        raise ValueError("invalid Source idempotency receipt intent digest")
    if not hmac.compare_digest(receipt["scopeDigest"], scope_digest):
        raise ValueError("IDEMPOTENCY_KEY_REUSED")
    if not hmac.compare_digest(receipt["intentDigest"], intent_digest):
        raise ValueError("IDEMPOTENCY_KEY_REUSED")

    created_at = _parse_time(receipt["createdAt"])
    expires_at = _parse_time(receipt["expiresAt"])
    if expires_at - created_at < SOURCE_IDEMPOTENCY_RETENTION:
        raise ValueError("Source idempotency receipt retention is below 24 hours")

    state = receipt["state"]
    result_fields = (
        receipt["httpStatus"],
        receipt["responseDigest"],
        receipt["responseBody"],
        receipt["resultSourceId"],
        receipt["resultRevision"],
    )
    if state == "in_progress":
        if any(value is not None for value in result_fields):
            raise ValueError("in-progress Source idempotency receipt has a result")
        raise ValueError("IDEMPOTENCY_IN_PROGRESS")
    if state != "committed":
        raise ValueError("invalid Source idempotency receipt state")
    if not (
        isinstance(receipt["httpStatus"], int)
        and not isinstance(receipt["httpStatus"], bool)
        and 200 <= receipt["httpStatus"] <= 299
        and isinstance(receipt["responseDigest"], str)
        and SHA256_DIGEST.fullmatch(receipt["responseDigest"])
        and isinstance(receipt["responseBody"], dict)
        and isinstance(receipt["resultSourceId"], str)
        and SOURCE_ID.fullmatch(receipt["resultSourceId"])
        and isinstance(receipt["resultRevision"], int)
        and not isinstance(receipt["resultRevision"], bool)
        and receipt["resultRevision"] >= 1
    ):
        raise ValueError("committed Source idempotency receipt lacks a replay result")
    _validate_redacted_response(receipt["responseBody"])
    try:
        expected_response_digest = canonical_sha256(receipt["responseBody"])
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("invalid Source idempotency receipt response body") from exc
    if not hmac.compare_digest(receipt["responseDigest"], expected_response_digest):
        raise ValueError("Source idempotency response digest mismatch")
    if (
        receipt["responseBody"].get("sourceId") != receipt["resultSourceId"]
        or receipt["responseBody"].get("revision") != receipt["resultRevision"]
    ):
        raise ValueError("Source idempotency replay result differs from response body")
    return "replay"
