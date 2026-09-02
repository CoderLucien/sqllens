"""Canonical JSON primitives for vNext evidence digests.

The contract uses a deliberately small RFC 8785-compatible profile: object
keys and strings follow JCS ordering/escaping, while numbers inside typed
evidence payloads must be IEEE-754 safe integers.  Restricting measurements to
integer base units (milliseconds, rows, bytes, basis points, and so on) avoids
language-specific decimal rendering while retaining deterministic digests.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

MAX_SAFE_INTEGER = 9_007_199_254_740_991


def reject_non_finite_json(value: Any, path: str = "$") -> None:
    """Reject NaN/Infinity recursively before schema or semantic processing."""

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite JSON number at {path}")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError(f"non-string JSON object key at {path}")
            reject_non_finite_json(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            reject_non_finite_json(child, f"{path}[{index}]")


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16be", errors="surrogatepass")


def _canonical(value: Any, path: str) -> str:
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
            + ",".join(
                _canonical(child, f"{path}[{index}]")
                for index, child in enumerate(value)
            )
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


def canonical_json_bytes(value: Any) -> bytes:
    """Return the restricted RFC 8785 canonical UTF-8 representation."""

    reject_non_finite_json(value)
    # Exercise the strict standard-JSON encoder as a preflight as well as the
    # profile-specific serializer below. This makes the NaN/Infinity boundary
    # explicit even if callers bypass the JSON file loader.
    json.dumps(value, ensure_ascii=False, allow_nan=False)
    return _canonical(value, "$").encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"
