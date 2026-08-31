#!/usr/bin/env python3
"""Build deterministic SQLLens developer-preview release artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

TOKEN_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$")
VERSION_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
REQUIRED_PATHS = (
    "launch.sh",
    "deploy/compose.json",
    "apps/api/Dockerfile",
    "apps/web",
    "requirements",
    "pyproject.toml",
)
RELEASE_PATHS = (
    "launch.sh",
    "deploy",
    "apps",
    "requirements",
    "pyproject.toml",
    ".dockerignore",
    "Makefile",
    "packages",
)
EXCLUDED_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "playwright-report",
    "test-results",
}
ZIP_MIN_EPOCH = 315532800
ZIP_MAX_EPOCH = 4354819198


class BuildError(RuntimeError):
    """A release cannot be built without violating its contract."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument(
        "--skip-dmg",
        action="store_true",
        help="Do not invoke hdiutil even when building on macOS",
    )
    return parser.parse_args()


def validate_token(value: str, label: str) -> None:
    if not TOKEN_PATTERN.fullmatch(value) or ".." in value:
        raise BuildError(f"invalid {label}: {value!r}")


def macos_bundle_version(version: str) -> str:
    match = VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise BuildError(f"invalid version: {version!r}")
    return ".".join(match.groups())


def validate_source(source: pathlib.Path) -> pathlib.Path:
    try:
        resolved = source.resolve(strict=True)
    except FileNotFoundError as exc:
        raise BuildError(f"source directory does not exist: {source}") from exc
    if not resolved.is_dir():
        raise BuildError(f"source is not a directory: {source}")

    for relative in REQUIRED_PATHS:
        candidate = resolved / relative
        if not candidate.exists() or candidate.is_symlink():
            raise BuildError(
                f"release source is incomplete or unsafe: missing {relative}"
            )
    return resolved


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        return int(dt.datetime.now(tz=dt.UTC).timestamp())
    try:
        value = int(raw)
    except ValueError as exc:
        raise BuildError("SOURCE_DATE_EPOCH must be a non-negative integer") from exc
    if value < 0:
        raise BuildError("SOURCE_DATE_EPOCH must be a non-negative integer")
    return value


def should_exclude(relative: pathlib.PurePath) -> bool:
    for part in relative.parts:
        if part in EXCLUDED_NAMES or part.endswith(".egg-info"):
            return True
        if part == ".env" or part.startswith(".env."):
            return True
    name = relative.name
    return name.endswith((".pyc", ".pyo", ".tsbuildinfo"))


def normalized_mode(path: pathlib.Path) -> int:
    return 0o755 if path.stat().st_mode & 0o111 else 0o644


def copy_release_path(
    source: pathlib.Path,
    destination: pathlib.Path,
    relative: pathlib.PurePath,
) -> None:
    if should_exclude(relative):
        return
    if source.is_symlink():
        raise BuildError(f"release source contains a symbolic link: {relative}")
    if source.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        destination.chmod(0o755)
        for child in sorted(source.iterdir(), key=lambda item: item.name):
            copy_release_path(child, destination / child.name, relative / child.name)
        return
    if not source.is_file():
        raise BuildError(f"release source contains a special file: {relative}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(normalized_mode(source))


def stage_release(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.mkdir(parents=True)
    for relative_text in RELEASE_PATHS:
        source_path = source / relative_text
        if not source_path.exists():
            continue
        relative = pathlib.PurePath(relative_text)
        copy_release_path(source_path, destination / relative, relative)


def write_text(path: pathlib.Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(mode)


def write_metadata(
    release_root: pathlib.Path,
    version: str,
    revision: str,
    epoch: int,
) -> None:
    timestamp = dt.datetime.fromtimestamp(epoch, tz=dt.UTC).replace(microsecond=0)
    metadata = {
        "build_timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "platform_validation": {
            "linux_amd64": "requires-release-smoke",
            "linux_arm64": "unverified",
            "macos": "unverified",
        },
        "release_kind": "unsigned-developer-preview",
        "signing": {"code_signed": False, "notarized": False},
        "source_revision": revision,
        "version": version,
    }
    write_text(
        release_root / "build-metadata.json",
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
    )


def write_release_notes(release_root: pathlib.Path, version: str) -> None:
    write_text(
        release_root / "RELEASE-NOTES.txt",
        f"""SQLLens Developer Preview {version}

This preview is unsigned, not notarized, and has not been validated on macOS.

macOS: double-click SQLLens.app. If Gatekeeper blocks the unsigned preview,
right-click the app and choose Open. Docker Desktop must already be running.

Command-line lifecycle:
  ./launch.sh start
  ./launch.sh stop
  ./launch.sh diagnostics
  ./launch.sh uninstall
  ./launch.sh uninstall --purge-data

The default uninstall retains the sqllens-data Docker volume. The explicit
--purge-data option permanently removes application data and local setup state.
""",
    )


def write_launch_command(release_root: pathlib.Path) -> None:
    write_text(
        release_root / "launch.command",
        """#!/bin/sh
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT" || exit 1

status=0
./launch.sh start || status=$?
if [ "$status" -eq 0 ]; then
  /usr/bin/open "http://127.0.0.1:${SQLLENS_PORT:-8080}" >/dev/null 2>&1 || true
fi

printf '\nPress Return to close this window.\n'
IFS= read -r _answer || true
exit "$status"
""",
        0o755,
    )


def write_app_bundle(
    release_root: pathlib.Path,
    app_root: pathlib.Path,
    version: str,
) -> None:
    contents = app_root / "Contents"
    resources = contents / "Resources" / "release"
    shutil.copytree(release_root, resources)

    executable = contents / "MacOS" / "SQLLens"
    write_text(
        executable,
        """#!/bin/sh
set -eu

CONTENTS=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMAND="$CONTENTS/Resources/release/launch.command"

/usr/bin/osascript - "$COMMAND" <<'APPLESCRIPT'
on run argv
  set launcherPath to item 1 of argv
  tell application "Terminal"
    activate
    do script quoted form of launcherPath
  end tell
end run
APPLESCRIPT
""",
        0o755,
    )

    bundle_version = macos_bundle_version(version)
    plist = {
        "CFBundleDisplayName": "SQLLens Developer Preview",
        "CFBundleExecutable": "SQLLens",
        "CFBundleIdentifier": "dev.sqllens.preview",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "SQLLens",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": bundle_version,
        "CFBundleVersion": bundle_version,
        "LSMinimumSystemVersion": "12.0",
        "NSHighResolutionCapable": True,
        "SQLLensReleaseVersion": version,
    }
    plist_path = contents / "Info.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    with plist_path.open("wb") as stream:
        plistlib.dump(plist, stream, sort_keys=True)
    plist_path.chmod(0o644)


def iter_regular_files(root: pathlib.Path) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise BuildError(
                f"staged release contains a symbolic link: {path.relative_to(root)}"
            )
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise BuildError(
                f"staged release contains a special file: {path.relative_to(root)}"
            )
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    bounded = min(max(epoch, ZIP_MIN_EPOCH), ZIP_MAX_EPOCH)
    value = dt.datetime.fromtimestamp(bounded, tz=dt.UTC)
    return value.year, value.month, value.day, value.hour, value.minute, value.second


def create_zip(
    source_root: pathlib.Path, destination: pathlib.Path, epoch: int
) -> None:
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in iter_regular_files(source_root):
            relative = path.relative_to(source_root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=zip_timestamp(epoch))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | (path.stat().st_mode & 0o777)) << 16
            archive.writestr(
                info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED
            )


def create_tar_gz(
    release_root: pathlib.Path,
    destination: pathlib.Path,
    archive_root: str,
    epoch: int,
) -> None:
    with (
        destination.open("wb") as raw_stream,
        gzip.GzipFile(
            filename="", mode="wb", fileobj=raw_stream, mtime=epoch
        ) as gzip_stream,
        tarfile.open(
            fileobj=gzip_stream, mode="w", format=tarfile.PAX_FORMAT
        ) as archive,
    ):
        for path in iter_regular_files(release_root):
            relative = path.relative_to(release_root).as_posix()
            info = tarfile.TarInfo(f"{archive_root}/{relative}")
            info.size = path.stat().st_size
            info.mode = path.stat().st_mode & 0o777
            info.mtime = epoch
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            with path.open("rb") as stream:
                archive.addfile(info, stream)


def create_dmg(app_root: pathlib.Path, destination: pathlib.Path) -> bool:
    if platform.system() != "Darwin" or shutil.which("hdiutil") is None:
        return False

    dmg_root = destination.parent / "dmg-root"
    dmg_root.mkdir()
    shutil.copytree(app_root, dmg_root / app_root.name)
    subprocess.run(
        [
            "hdiutil",
            "create",
            "-volname",
            "SQLLens",
            "-srcfolder",
            str(dmg_root),
            "-ov",
            "-format",
            "UDZO",
            str(destination),
        ],
        check=True,
    )
    return True


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(
    source: pathlib.Path,
    output: pathlib.Path,
    version: str,
    revision: str,
    *,
    skip_dmg: bool = False,
) -> list[pathlib.Path]:
    macos_bundle_version(version)
    validate_token(revision, "revision")
    source = validate_source(source)
    epoch = source_date_epoch()

    output = output.expanduser().resolve()
    if output.exists():
        if not output.is_dir():
            raise BuildError(f"output is not a directory: {output}")
        if next(output.iterdir(), None) is not None:
            raise BuildError(
                "output already contains release artifacts; use an empty output directory"
            )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".sqllens-release-", dir=output.parent
    ) as raw_stage:
        stage = pathlib.Path(raw_stage)
        release_root = stage / f"sqllens-{version}"
        stage_release(source, release_root)
        write_metadata(release_root, version, revision, epoch)
        write_release_notes(release_root, version)
        write_launch_command(release_root)

        app_stage = stage / "macos-app"
        app_root = app_stage / "SQLLens.app"
        write_app_bundle(release_root, app_root, version)

        app_zip = stage / f"sqllens-{version}-macos-preview.app.zip"
        cli_archive = stage / f"sqllens-{version}-source.tar.gz"
        dmg = stage / f"sqllens-{version}-macos-preview.dmg"
        create_zip(app_stage, app_zip, epoch)
        create_tar_gz(release_root, cli_archive, release_root.name, epoch)

        artifacts = [app_zip, cli_archive]
        if not skip_dmg and create_dmg(app_root, dmg):
            artifacts.append(dmg)
        elif skip_dmg:
            print("DMG not generated: disabled by --skip-dmg")
        else:
            print("DMG not generated: hdiutil unavailable on this host")

        checksums = stage / "SHA256SUMS"
        write_text(
            checksums,
            "".join(f"{sha256(path)}  {path.name}\n" for path in sorted(artifacts)),
        )

        output.mkdir(parents=True, exist_ok=True)
        delivered: list[pathlib.Path] = []
        for path in [*artifacts, checksums]:
            destination = output / path.name
            os.replace(path, destination)
            delivered.append(destination)
        return delivered


def main() -> int:
    args = parse_args()
    try:
        artifacts = build(
            args.source,
            args.output,
            args.version,
            args.revision,
            skip_dmg=args.skip_dmg,
        )
    except (BuildError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    for artifact in artifacts:
        print(f"Built {artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
