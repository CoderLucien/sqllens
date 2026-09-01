#!/usr/bin/env python3
"""Generate the two-platform Python wheel hash locks and artifact evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

from packaging.utils import canonicalize_name, parse_wheel_filename

PLATFORMS = {
    "linux/amd64": ("manylinux_2_28_x86_64", "manylinux2014_x86_64"),
    "linux/arm64/v8": ("manylinux_2_28_aarch64", "manylinux2014_aarch64"),
}
PIN_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)$")
PYPI_INDEX = "https://pypi.org/simple"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    return parser.parse_args()


def read_pins(path: pathlib.Path) -> list[tuple[str, str]]:
    pins: list[tuple[str, str]] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"{path}: requirement must be an exact pin: {line!r}")
        pins.append((match.group(1), match.group(2)))
    if not pins:
        raise ValueError(f"{path}: no requirements")
    return pins


def download(
    requirements: pathlib.Path,
    destination: pathlib.Path,
    platform_tags: tuple[str, ...] | None,
) -> None:
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--disable-pip-version-check",
        "--only-binary=:all:",
        "--index-url",
        PYPI_INDEX,
        "--dest",
        str(destination),
    ]
    if platform_tags is not None:
        for platform_tag in platform_tags:
            command.extend(("--platform", platform_tag))
        command.extend(("--python-version", "312", "--implementation", "cp", "--abi", "cp312"))
    command.extend(("-r", str(requirements)))
    subprocess.run(command, check=True)


def artifact(path: pathlib.Path, kind: str, platforms: set[str]) -> dict[str, object]:
    distribution, version, _, _ = parse_wheel_filename(path.name)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "kind": kind,
        "requirement": f"{distribution}=={version}",
        "filename": path.name,
        "sha256": digest,
        "platforms": sorted(platforms),
    }


def collect_runtime_artifacts(
    pins: list[tuple[str, str]],
    downloads: dict[str, pathlib.Path],
) -> list[dict[str, object]]:
    expected = {canonicalize_name(name): version for name, version in pins}
    found: dict[tuple[str, str], set[str]] = defaultdict(set)
    paths: dict[tuple[str, str], pathlib.Path] = {}
    seen_by_platform: dict[str, set[str]] = defaultdict(set)

    for platform, directory in downloads.items():
        for path in sorted(directory.glob("*.whl")):
            distribution, version, _, _ = parse_wheel_filename(path.name)
            name = canonicalize_name(distribution)
            if expected.get(name) != str(version):
                raise ValueError(f"unexpected artifact for {platform}: {path.name}")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            key = (path.name, digest)
            paths[key] = path
            found[key].add(platform)
            seen_by_platform[platform].add(name)

    for platform in PLATFORMS:
        missing = sorted(set(expected) - seen_by_platform[platform])
        if missing:
            raise ValueError(f"missing {platform} wheels: {', '.join(missing)}")

    return [
        artifact(paths[key], "runtime", platforms)
        for key, platforms in sorted(found.items())
    ]


def collect_build_artifacts(
    pins: list[tuple[str, str]], directory: pathlib.Path
) -> list[dict[str, object]]:
    expected = {canonicalize_name(name): version for name, version in pins}
    artifacts: list[dict[str, object]] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.whl")):
        distribution, version, _, _ = parse_wheel_filename(path.name)
        name = canonicalize_name(distribution)
        if expected.get(name) != str(version):
            raise ValueError(f"unexpected build artifact: {path.name}")
        seen.add(name)
        artifacts.append(artifact(path, "build", set(PLATFORMS)))
    missing = sorted(set(expected) - seen)
    if missing:
        raise ValueError(f"missing build wheels: {', '.join(missing)}")
    return artifacts


def write_lock(
    output: pathlib.Path,
    pins: list[tuple[str, str]],
    artifacts: list[dict[str, object]],
    kind: str,
) -> None:
    hashes_by_requirement: dict[str, set[str]] = defaultdict(set)
    for item in artifacts:
        if item["kind"] == kind:
            requirement = str(item["requirement"]).split("==", 1)[0]
            hashes_by_requirement[canonicalize_name(requirement)].add(str(item["sha256"]))

    lines = [
        "# Generated by scripts/release/update_python_locks.py.",
        "# Only reviewed CPython 3.12 wheels for linux/amd64 and linux/arm64/v8 are allowed.",
    ]
    for name, version in pins:
        hashes = sorted(hashes_by_requirement[canonicalize_name(name)])
        if not hashes:
            raise ValueError(f"no hashes for {name}=={version}")
        lines.append(f"{name}=={version} \\")
        for index, digest in enumerate(hashes):
            suffix = " \\" if index < len(hashes) - 1 else ""
            lines.append(f"    --hash=sha256:{digest}{suffix}")
    output.write_text("\n".join(lines) + "\n")


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    runtime_input = root / "requirements" / "runtime.in"
    build_input = root / "requirements" / "build.in"
    runtime_pins = read_pins(runtime_input)
    build_pins = read_pins(build_input)

    with tempfile.TemporaryDirectory(prefix="sqllens-python-locks-") as temp:
        temp_root = pathlib.Path(temp)
        runtime_downloads: dict[str, pathlib.Path] = {}
        for platform, platform_tags in PLATFORMS.items():
            destination = temp_root / platform.replace("/", "-")
            destination.mkdir()
            download(runtime_input, destination, platform_tags)
            runtime_downloads[platform] = destination

        build_destination = temp_root / "build"
        build_destination.mkdir()
        download(build_input, build_destination, None)

        runtime_artifacts = collect_runtime_artifacts(runtime_pins, runtime_downloads)
        build_artifacts = collect_build_artifacts(build_pins, build_destination)
        artifacts = sorted(
            runtime_artifacts + build_artifacts,
            key=lambda item: (str(item["kind"]), str(item["filename"])),
        )

        write_lock(root / "requirements" / "runtime.lock", runtime_pins, artifacts, "runtime")
        write_lock(root / "requirements" / "build.lock", build_pins, artifacts, "build")
        evidence = {
            "schema_version": 1,
            "generator": "scripts/release/update_python_locks.py",
            "index": PYPI_INDEX,
            "python": "CPython 3.12",
            "platform_tags": {key: list(value) for key, value in PLATFORMS.items()},
            "artifacts": artifacts,
        }
        (root / "requirements" / "python-artifacts.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
