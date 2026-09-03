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
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from vnext_canonical_json import (
    canonical_json_bytes,
    canonical_sha256,
    strict_json_loads,
)
from vnext_source_audit import validate_source_state_event_transition

SOURCE_IDEMPOTENCY_RECEIPT_REVISION = "source-idempotency-receipt/v1"
SOURCE_WRITE_RESULT_REVISION = "source-write-result/v1"
SOURCE_IDEMPOTENCY_RETENTION = timedelta(hours=24)
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
RECEIPT_ID = re.compile(r"^idem_[a-z0-9]{16,64}$")
SOURCE_ID = re.compile(r"^src_[a-z0-9]{16,64}$")
SHA256_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
HMAC_SHA256_DIGEST = re.compile(r"^hmac-sha256:[a-f0-9]{64}$")
SOURCE_MEMBER_ROUTE = re.compile(
    r"^/api/v1/sources/(?P<source_id>src_[a-z0-9]{16,64})"
    r"(?:/(?P<action>tests|enablements|disablements|credential-rotations|lease-cancellations))?$"
)
SOURCE_SCHEMA = strict_json_loads(
    Path(__file__).with_name("source-v1.schema.json").read_text(encoding="utf-8")
)
if not isinstance(SOURCE_SCHEMA, dict):
    raise TypeError("Source/v1 schema must be a JSON object")
Draft202012Validator.check_schema(SOURCE_SCHEMA)
SOURCE_RESPONSE_VALIDATOR = Draft202012Validator(
    SOURCE_SCHEMA, format_checker=FormatChecker()
)
SOURCE_WRITE_RESULT_SCHEMA = strict_json_loads(
    Path(__file__)
    .with_name("source-write-result-v1.schema.json")
    .read_text(encoding="utf-8")
)
if not isinstance(SOURCE_WRITE_RESULT_SCHEMA, dict):
    raise TypeError("Source write result schema must be a JSON object")
Draft202012Validator.check_schema(SOURCE_WRITE_RESULT_SCHEMA)
SOURCE_WRITE_RESULT_VALIDATOR = Draft202012Validator(SOURCE_WRITE_RESULT_SCHEMA)
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
SOURCE_WRITE_RESULT_FIELDS = {
    "schemaVersion",
    "sourceId",
    "revision",
    "state",
    "pendingOperation",
    "stateOperation",
}
SOURCE_STATES = {
    "draft",
    "enabled",
    "disabled",
    "draining",
    "verification_failed",
    "tombstoned",
}
SOURCE_PENDING_OPERATIONS = {
    None,
    "rotate",
    "disable",
    "delete",
    "verification_failure",
}
SOURCE_STATE_OPERATIONS = {
    "registered",
    "verified",
    "enabled",
    "edited",
    "leases_updated",
    "rotation_started",
    "rotation_completed",
    "disable_started",
    "disabled",
    "delete_started",
    "leases_drained",
    "tombstoned",
    "verification_failure_started",
    "verification_failed",
}
SOURCE_WRITE_OPERATION_SIGNATURES: dict[
    str, frozenset[tuple[int, str, str | None, str]]
] = {
    "create": frozenset({(201, "draft", None, "registered")}),
    "edit": frozenset(
        (200, state, None, "edited")
        for state in ("draft", "enabled", "disabled", "verification_failed")
    ),
    "tests": frozenset(
        {
            (200, "draft", None, "verified"),
            (200, "enabled", None, "verified"),
            (200, "disabled", None, "verified"),
            (200, "verification_failed", None, "verification_failed"),
            (
                202,
                "draining",
                "verification_failure",
                "verification_failure_started",
            ),
        }
    ),
    "enablements": frozenset({(200, "enabled", None, "enabled")}),
    "disablements": frozenset(
        {
            (202, "draining", "disable", "disable_started"),
            (200, "disabled", None, "disabled"),
        }
    ),
    "credential-rotations": frozenset(
        {
            (202, "draining", "rotate", "rotation_started"),
            (200, "disabled", None, "rotation_completed"),
        }
    ),
    "lease-cancellations": frozenset(
        {
            *(
                (202, "draining", pending, "leases_drained")
                for pending in (
                    "rotate",
                    "disable",
                    "delete",
                    "verification_failure",
                )
            ),
            (200, "disabled", None, "disabled"),
            (200, "disabled", None, "rotation_completed"),
            (200, "tombstoned", None, "tombstoned"),
            (200, "verification_failed", None, "verification_failed"),
        }
    ),
    "delete": frozenset(
        {
            (202, "draining", "delete", "delete_started"),
            (200, "tombstoned", None, "tombstoned"),
        }
    ),
}


def _source_write_route(method: str, route: str) -> tuple[str | None, str]:
    if not isinstance(method, str) or not isinstance(route, str):
        raise TypeError("invalid Source idempotency scope")
    if any(character in route for character in "?#%\\") or any(
        character.isspace() for character in route
    ):
        raise ValueError("invalid Source idempotency scope")
    normalized_method = method.upper()
    if route == "/api/v1/sources":
        if normalized_method != "POST":
            raise ValueError("unsupported Source write route")
        return None, "create"
    match = SOURCE_MEMBER_ROUTE.fullmatch(route)
    if match is None:
        raise ValueError("invalid Source idempotency scope")
    source_id = match.group("source_id")
    action = match.group("action")
    if action is None:
        if normalized_method not in {"PATCH", "DELETE"}:
            raise ValueError("unsupported Source write route")
        return source_id, "edit" if normalized_method == "PATCH" else "delete"
    if normalized_method != "POST":
        raise ValueError("unsupported Source write route")
    return source_id, action


def _validate_closed_source_response(
    *, method: str, canonical_route: str, http_status: int, body: dict[str, Any]
) -> None:
    source_id, operation = _source_write_route(method, canonical_route)
    error = (
        "invalid Source idempotency receipt response body: "
        "not the closed Source write result DTO"
    )
    if (
        not isinstance(http_status, int)
        or isinstance(http_status, bool)
        or set(body) != SOURCE_WRITE_RESULT_FIELDS
    ):
        raise ValueError(error)
    try:
        SOURCE_WRITE_RESULT_VALIDATOR.validate(body)
    except ValidationError as exc:
        raise ValueError(error) from exc
    if not (
        isinstance(body["sourceId"], str)
        and SOURCE_ID.fullmatch(body["sourceId"])
        and body["state"] in SOURCE_STATES
        and body["pendingOperation"] in SOURCE_PENDING_OPERATIONS
        and body["stateOperation"] in SOURCE_STATE_OPERATIONS
    ):
        raise ValueError(error)
    if source_id is not None and body["sourceId"] != source_id:
        raise ValueError(error)

    signature = (
        http_status,
        body["state"],
        body["pendingOperation"],
        body["stateOperation"],
    )
    if signature not in SOURCE_WRITE_OPERATION_SIGNATURES[operation]:
        raise ValueError(error)
    if (operation == "create") != (body["revision"] == 1):
        raise ValueError(error)


def source_idempotency_public_response(
    *,
    method: str,
    canonical_route: str,
    http_status: int,
    source: dict[str, Any],
) -> dict[str, Any]:
    """Project a committed Source into the only receipt-safe public result DTO."""

    try:
        SOURCE_RESPONSE_VALIDATOR.validate(source)
        latest_event = source["transitionEvents"][-1]
        if not (
            latest_event["sourceRevision"] == source["revision"]
            and latest_event["toState"] == source["state"]
            and source["credentialLifecycle"]["pendingOperation"]
            in SOURCE_PENDING_OPERATIONS
        ):
            raise ValueError
        result = {
            "schemaVersion": SOURCE_WRITE_RESULT_REVISION,
            "sourceId": source["sourceId"],
            "revision": source["revision"],
            "state": source["state"],
            "pendingOperation": source["credentialLifecycle"]["pendingOperation"],
            "stateOperation": latest_event["operation"],
        }
    except (IndexError, KeyError, TypeError, ValidationError, ValueError) as exc:
        raise ValueError(
            "invalid Source idempotency receipt response body: "
            "cannot project the closed Source write result DTO"
        ) from exc
    try:
        validate_source_state_event_transition(latest_event)
    except ValueError as exc:
        raise ValueError(
            "invalid Source idempotency receipt response body: "
            f"cannot project the closed Source write result DTO: {exc}"
        ) from exc
    _validate_closed_source_response(
        method=method,
        canonical_route=canonical_route,
        http_status=http_status,
        body=result,
    )
    return result


def source_idempotency_response_digest(
    *,
    method: str,
    canonical_route: str,
    http_status: int,
    response_body: dict[str, Any],
) -> str:
    """Validate and hash the exact public DTO stored in a committed receipt.

    Receipt writers call this after ``source_idempotency_public_response``;
    replay validation calls this function again. The integrity value binds the
    complete method/route/status/result context, not only the body.
    """

    if not isinstance(response_body, dict):
        raise TypeError("invalid Source idempotency receipt response body")
    _validate_redacted_response(response_body)
    _validate_closed_source_response(
        method=method,
        canonical_route=canonical_route,
        http_status=http_status,
        body=response_body,
    )
    try:
        return canonical_sha256(
            {
                "responseRevision": SOURCE_WRITE_RESULT_REVISION,
                "method": method.upper(),
                "canonicalRoute": canonical_route,
                "httpStatus": http_status,
                "resultSourceId": response_body["sourceId"],
                "resultRevision": response_body["revision"],
                "body": response_body,
            }
        )
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("invalid Source idempotency receipt response body") from exc


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
        and isinstance(canonical_route, str)
        and isinstance(idempotency_key, str)
        and bool(IDEMPOTENCY_KEY.fullmatch(idempotency_key))
    ):
        raise ValueError("invalid Source idempotency scope")
    normalized_method = method.upper()
    if normalized_method not in {"POST", "PATCH", "DELETE"}:
        raise ValueError("unsupported Source write method")
    _source_write_route(normalized_method, canonical_route)
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
    method: str,
    canonical_route: str,
) -> Literal["reserve", "replay"]:
    """Return the only safe action for a Source write attempt.

    ``reserve`` means the caller may atomically insert an in-progress receipt.
    ``replay`` means the caller must return the stored status/body and must not
    execute any Source, credential, reservation, or verifier side effect.
    Stable ValueError messages are the corresponding public conflict codes.
    """

    _source_write_route(method, canonical_route)
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
    expected_response_digest = source_idempotency_response_digest(
        method=method,
        canonical_route=canonical_route,
        http_status=receipt["httpStatus"],
        response_body=receipt["responseBody"],
    )
    if not hmac.compare_digest(receipt["responseDigest"], expected_response_digest):
        raise ValueError("Source idempotency response digest mismatch")
    if (
        receipt["responseBody"].get("sourceId") != receipt["resultSourceId"]
        or receipt["responseBody"].get("revision") != receipt["resultRevision"]
    ):
        raise ValueError("Source idempotency replay result differs from response body")
    return "replay"
