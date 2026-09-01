#!/usr/bin/env python3
"""Print a deterministic fingerprint of the runtime dependency and app payload."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import pathlib
import stat
import subprocess
import sys

ROOTS = (
    pathlib.Path("/app"),
    pathlib.Path("/usr/local/bin/sqllens-api"),
    pathlib.Path("/usr/local/bin/sqllens-entrypoint"),
    pathlib.Path("/usr/local/lib/python3.12/site-packages"),
)


def update_path(digest: hashlib._Hash, path: pathlib.Path) -> None:
    metadata = path.lstat()
    digest.update(str(path).encode())
    digest.update(f"\0{stat.S_IMODE(metadata.st_mode)}\0{metadata.st_uid}\0{metadata.st_gid}\0".encode())
    if path.is_symlink():
        digest.update(b"link\0" + os.readlink(path).encode())
    elif path.is_file():
        digest.update(b"file\0")
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    elif path.is_dir():
        digest.update(b"dir\0")
    else:
        raise RuntimeError(f"unexpected runtime payload type: {path}")


def main() -> int:
    digest = hashlib.sha256()
    for root in ROOTS:
        if not root.exists() and not root.is_symlink():
            raise RuntimeError(f"missing runtime payload: {root}")
        update_path(digest, root)
        if root.is_dir():
            for path in sorted(root.rglob("*"), key=lambda item: str(item)):
                update_path(digest, path)

    dependencies = sorted(
        f"{distribution.metadata['Name']}=={distribution.version}"
        for distribution in importlib.metadata.distributions()
    )
    os_packages = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}=${Version}\\n"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()
    result = {
        "dependencies": dependencies,
        "dependencies_sha256": hashlib.sha256(
            ("\n".join(dependencies) + "\n").encode()
        ).hexdigest(),
        "filesystem_sha256": digest.hexdigest(),
        "os_packages_count": len(os_packages),
        "os_packages_sha256": hashlib.sha256(
            ("\n".join(sorted(os_packages)) + "\n").encode()
        ).hexdigest(),
        "python": sys.version.split()[0],
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
