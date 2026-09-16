"""Frozen canonical JSON primitives for Evidence/v2 typed digests."""

from __future__ import annotations

import hashlib
import json
import math
from typing import cast

MAX_SAFE_INTEGER = 9_007_199_254_740_991

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None


def reject_non_finite_json(value: JsonValue, path: str = "$") -> None:
    """Reject non-finite JSON numbers recursively before serialization."""

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite JSON number at {path}")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"non-string JSON object key at {path}")
            reject_non_finite_json(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            reject_non_finite_json(child, f"{path}[{index}]")
        return
    if value is None or isinstance(value, (bool, int, str)):
        return
    raise ValueError(f"unsupported JSON value at {path}: {type(value).__name__}")


def strict_json_bytes(value: JsonValue) -> bytes:
    """Serialize standard JSON deterministically and reject non-finite values."""

    reject_non_finite_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def strict_json_loads(source: str | bytes) -> JsonValue:
    """Load standard JSON while rejecting duplicate keys and non-finite values."""

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object member: {key}")
            result[key] = value
        return result

    loaded = cast(
        JsonValue,
        json.loads(
            source,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        ),
    )
    reject_non_finite_json(loaded)
    return loaded


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16be", errors="surrogatepass")


def _canonical(value: JsonValue, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"typed integer exceeds JCS safe range at {path}")
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite typed number at {path}")
        raise TypeError(f"typed payload numbers must use integer base units at {path}")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, allow_nan=False)
    if isinstance(value, list):
        return (
            "["
            + ",".join(_canonical(child, f"{path}[{index}]") for index, child in enumerate(value))
            + "]"
        )
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError(f"typed JSON object has a non-string key at {path}")
        members = []
        for key in sorted(value, key=_utf16_sort_key):
            encoded_key = json.dumps(key, ensure_ascii=False, allow_nan=False)
            members.append(f"{encoded_key}:{_canonical(value[key], f'{path}.{key}')}")
        return "{" + ",".join(members) + "}"
    raise ValueError(f"unsupported typed JSON value at {path}: {type(value).__name__}")


def canonical_json_bytes(value: JsonValue) -> bytes:
    """Return the frozen ``rfc8785-safe-integer/v1`` representation."""

    reject_non_finite_json(value)
    json.dumps(value, ensure_ascii=False, allow_nan=False)
    return _canonical(value, "$").encode("utf-8")


def canonical_sha256(value: JsonValue) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"
