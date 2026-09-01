#!/usr/bin/env python3
"""Build deterministic SQLLens developer-preview release artifacts."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
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
from collections.abc import Iterator

REVISION_PATTERN = re.compile(r"^[0-9a-f]{7,40}$")
GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
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
BUILDER_RELATIVE_PATH = pathlib.PurePosixPath(
    "scripts/release/build_release.py"
)


class BuildError(RuntimeError):
    """A release cannot be built without violating its contract."""


@dataclasses.dataclass(frozen=True)
class SourceIdentity:
    revision: str
    git_tree: str
    builder_git_blob: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--revision",
        required=True,
        help="Expected 7-40 character Git HEAD; metadata always records the verified full SHA",
    )
    parser.add_argument(
        "--skip-dmg",
        action="store_true",
        help="Do not invoke hdiutil even when building on macOS",
    )
    return parser.parse_args()


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


def git_output(source: pathlib.Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise BuildError(f"release source is not a usable Git worktree: {detail}")
    return result.stdout.strip()


def verified_source_revision(source: pathlib.Path, expected: str) -> str:
    if REVISION_PATTERN.fullmatch(expected) is None:
        raise BuildError("revision must be a 7-40 character lowercase Git SHA")

    top_level = pathlib.Path(git_output(source, "rev-parse", "--show-toplevel")).resolve()
    if top_level != source:
        raise BuildError("release source must be the Git worktree root")

    revision = git_output(source, "rev-parse", "--verify", "HEAD^{commit}")
    if REVISION_PATTERN.fullmatch(revision) is None or len(revision) != 40:
        raise BuildError("source HEAD did not resolve to a full Git commit SHA")
    if not revision.startswith(expected):
        raise BuildError(
            f"expected revision {expected} does not match source HEAD {revision}"
        )
    return revision


def ensure_release_source_clean(source: pathlib.Path) -> None:
    status = git_output(
        source,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status:
        first_change = status.splitlines()[0]
        raise BuildError(f"release source has uncommitted changes: {first_change}")


def git_object_id(source: pathlib.Path, expression: str) -> str:
    object_id = git_output(source, "rev-parse", "--verify", expression)
    if GIT_OBJECT_PATTERN.fullmatch(object_id) is None:
        raise BuildError(f"Git object did not resolve to a full object ID: {expression}")
    return object_id


def source_identity(
    source: pathlib.Path,
    expected_revision: str,
    *,
    require_running_builder: bool,
) -> SourceIdentity:
    revision = verified_source_revision(source, expected_revision)
    ensure_release_source_clean(source)
    git_tree = git_object_id(source, f"{revision}^{{tree}}")
    builder_git_blob = git_object_id(
        source, f"{revision}:{BUILDER_RELATIVE_PATH.as_posix()}"
    )

    builder = source / BUILDER_RELATIVE_PATH
    if builder.is_symlink() or not builder.is_file():
        raise BuildError("release builder is missing or unsafe")
    working_builder_blob = git_output(
        source,
        "hash-object",
        "--no-filters",
        str(builder),
    )
    if working_builder_blob != builder_git_blob:
        raise BuildError("release builder does not match the declared source revision")
    if require_running_builder and pathlib.Path(__file__).resolve() != builder.resolve():
        raise BuildError("release builder must execute from the declared source worktree")

    return SourceIdentity(
        revision=revision,
        git_tree=git_tree,
        builder_git_blob=builder_git_blob,
    )


def assert_source_identity(
    source: pathlib.Path,
    identity: SourceIdentity,
    *,
    require_running_builder: bool,
) -> None:
    actual = source_identity(
        source,
        identity.revision,
        require_running_builder=require_running_builder,
    )
    if actual != identity:
        raise BuildError("release source identity changed during the build")


@contextlib.contextmanager
def isolated_source_checkout(
    source: pathlib.Path, identity: SourceIdentity
) -> Iterator[pathlib.Path]:
    with tempfile.TemporaryDirectory(prefix="sqllens-release-source-") as raw_checkout:
        checkout = pathlib.Path(raw_checkout) / "source"
        result = subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-checkout",
                "--no-hardlinks",
                str(source),
                str(checkout),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "git clone failed"
            raise BuildError(f"could not create isolated release checkout: {detail}")
        git_output(checkout, "checkout", "--detach", "--quiet", identity.revision)
        assert_source_identity(checkout, identity, require_running_builder=False)
        try:
            yield checkout
        finally:
            assert_source_identity(checkout, identity, require_running_builder=False)


def source_date_epoch(source: pathlib.Path, revision: str) -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        raw = git_output(source, "show", "-s", "--format=%ct", revision)
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


def ensure_no_ignored_release_inputs(source: pathlib.Path) -> None:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
            *RELEASE_PATHS,
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = os.fsdecode(result.stderr).strip() or "git ls-files failed"
        raise BuildError(f"could not validate ignored release inputs: {detail}")
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = pathlib.PurePath(os.fsdecode(raw_path))
        if not should_exclude(relative):
            raise BuildError(
                f"release input is not tracked by source revision: {relative}"
            )


def normalized_mode(path: pathlib.Path) -> int:
    return 0o755 if path.stat().st_mode & 0o111 else 0o644


def copy_release_path(
    source: pathlib.Path,
    destination: pathlib.Path,
    relative: pathlib.PurePath,
    tracked_files: set[str],
    staged_files: set[str],
) -> None:
    if should_exclude(relative):
        return
    if source.is_symlink():
        if relative.as_posix() not in tracked_files:
            raise BuildError(
                f"release input is not tracked by source revision: {relative}"
            )
        raise BuildError(f"release source contains a symbolic link: {relative}")
    if source.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        destination.chmod(0o755)
        for child in sorted(source.iterdir(), key=lambda item: item.name):
            copy_release_path(
                child,
                destination / child.name,
                relative / child.name,
                tracked_files,
                staged_files,
            )
        return
    if relative.as_posix() not in tracked_files:
        raise BuildError(f"release input is not tracked by source revision: {relative}")
    if not source.is_file():
        raise BuildError(f"release source contains a special file: {relative}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(normalized_mode(source))
    staged_files.add(relative.as_posix())


def tracked_release_files(source: pathlib.Path) -> set[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "ls-files",
            "-z",
            "-v",
            "--stage",
            "--cached",
            "--",
            *RELEASE_PATHS,
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = os.fsdecode(result.stderr).strip() or "git ls-files failed"
        raise BuildError(f"could not enumerate tracked release inputs: {detail}")
    tracked_files: set[str] = set()
    for raw_entry in result.stdout.split(b"\0"):
        if not raw_entry:
            continue
        try:
            raw_metadata, raw_path = raw_entry.split(b"\t", 1)
            state, raw_mode, _object_id, raw_stage = raw_metadata.split()
        except ValueError as exc:
            raise BuildError("git ls-files returned an invalid release entry") from exc

        relative = os.fsdecode(raw_path)
        tracked_files.add(relative)
        if should_exclude(pathlib.PurePath(relative)):
            continue

        index_state = os.fsdecode(state)
        if index_state != "H" or raw_stage != b"0":
            raise BuildError(
                "release input is not fully materialized from source revision: "
                f"{relative!r} (index state {index_state!r})"
            )
        mode = os.fsdecode(raw_mode)
        if mode == "120000":
            raise BuildError(f"release source contains a symbolic link: {relative}")
        if mode not in {"100644", "100755"}:
            raise BuildError(f"release source contains a special file: {relative}")
    return tracked_files


def stage_release(source: pathlib.Path, destination: pathlib.Path) -> None:
    tracked_files = tracked_release_files(source)
    expected_files = {
        relative
        for relative in tracked_files
        if not should_exclude(pathlib.PurePath(relative))
    }
    staged_files: set[str] = set()
    destination.mkdir(parents=True)
    for relative_text in RELEASE_PATHS:
        source_path = source / relative_text
        if not source_path.exists() and not source_path.is_symlink():
            continue
        relative = pathlib.PurePath(relative_text)
        copy_release_path(
            source_path,
            destination / relative,
            relative,
            tracked_files,
            staged_files,
        )

    missing = expected_files - staged_files
    extra = staged_files - expected_files
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {sorted(missing)[0]!r}")
        if extra:
            details.append(f"extra {sorted(extra)[0]!r}")
        raise BuildError(
            "release source is not fully materialized from source revision: "
            + "; ".join(details)
        )


def write_text(path: pathlib.Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(mode)


def write_metadata(
    release_root: pathlib.Path,
    version: str,
    identity: SourceIdentity,
    source_tree_sha256: str,
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
        "release_builder_git_blob": identity.builder_git_blob,
        "source_git_tree": identity.git_tree,
        "source_revision": identity.revision,
        "source_tree_sha256": source_tree_sha256,
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

This preview is unsigned and not notarized. Verified platform results must be
read from the release report for this exact build; macOS, linux/arm64, CentOS,
and Windows remain unverified until an exact-host smoke result is recorded.

Before extracting, verify every downloaded artifact from its download directory:
  macOS: shasum -a 256 -c SHA256SUMS
  Linux: sha256sum -c SHA256SUMS

macOS: double-click SQLLens.app. If Gatekeeper blocks the unsigned preview,
right-click the app and choose Open. Docker Desktop must already be running.

Start and validate:
  ./launch.sh start
  ./release-smoke.sh

Read-only preflight and interrupted-setup recovery:
  ./launch.sh check
  ./launch.sh recover-setup

Support and lifecycle:
  ./launch.sh stop
  ./launch.sh diagnostics
  ./launch.sh uninstall
  ./launch.sh uninstall --purge-data

Stop and the default uninstall retain both sqllens-data and sqllens-secrets.
The explicit --purge-data option permanently removes application data,
encrypted-provider key material, and local setup state.
""",
    )


def write_release_smoke(release_root: pathlib.Path) -> None:
    write_text(
        release_root / "release-smoke.sh",
        """#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
COMPOSE_FILE="$ROOT/deploy/compose.json"

fail() {
  printf 'ERROR: %s\\n' "$*" >&2
  exit 1
}

compose() {
  docker compose --project-directory "$ROOT" -f "$COMPOSE_FILE" "$@"
}

"$ROOT/launch.sh" check
container_id=$(compose ps -q web-api 2>/dev/null | sed -n '1p')
[ -n "$container_id" ] ||
  fail "Web App is not running; run ./launch.sh start, then retry ./release-smoke.sh"

running=$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)
[ "$running" = true ] ||
  fail "Web App container is not running; run ./launch.sh diagnostics"
health=$(docker inspect --format '{{.State.Health.Status}}' "$container_id" 2>/dev/null || true)
[ "$health" = healthy ] ||
  fail "Web App container is not healthy; run ./launch.sh diagnostics"

docker exec "$container_id" python -c '
import json
import urllib.request

def load(path):
    with urllib.request.urlopen("http://127.0.0.1:8080" + path, timeout=3) as response:
        raw = response.read(65_537)
    if len(raw) > 65_536:
        raise RuntimeError("local response exceeded smoke budget")
    return json.loads(raw)

health = load("/healthz")
status = load("/api/v1/setup/status")
if health != {"status": "ok"}:
    raise RuntimeError("health contract failed")
if not isinstance(status.get("state"), str):
    raise RuntimeError("setup state contract failed")
if not isinstance(status.get("initialized"), bool):
    raise RuntimeError("setup initialized contract failed")
if not isinstance(status.get("bootstrap_hash_persisted"), bool):
    raise RuntimeError("bootstrap persistence contract failed")
' >/dev/null || fail "bounded local API smoke failed; run ./launch.sh diagnostics"

printf 'Release smoke passed: container healthy and local API contracts valid.\\n'
""",
        0o755,
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
  url=$(./launch.sh url) || status=$?
fi
if [ "$status" -eq 0 ]; then
  port=${url#http://127.0.0.1:}
  case "$port" in
    ''|*[!0-9]*)
      printf 'ERROR: launcher returned an invalid local URL; run ./launch.sh diagnostics\n' >&2
      status=1
      ;;
    *) /usr/bin/open "$url" >/dev/null 2>&1 || true ;;
  esac
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


def release_tree_sha256(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in iter_regular_files(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        mode = path.stat().st_mode & 0o777
        content = path.read_bytes()
        for value in (relative, f"{mode:o}".encode("ascii"), content):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
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
    source = validate_source(source)
    identity = source_identity(source, revision, require_running_builder=True)
    tracked_release_files(source)
    ensure_no_ignored_release_inputs(source)
    epoch = source_date_epoch(source, identity.revision)

    output = output.expanduser().resolve()
    if output.exists():
        if not output.is_dir():
            raise BuildError(f"output is not a directory: {output}")
        if next(output.iterdir(), None) is not None:
            raise BuildError(
                "output already contains release artifacts; use an empty output directory"
            )
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        isolated_source_checkout(source, identity) as build_source,
        tempfile.TemporaryDirectory(
            prefix=".sqllens-release-", dir=output.parent
        ) as raw_stage,
    ):
        stage = pathlib.Path(raw_stage)
        release_root = stage / f"sqllens-{version}"
        stage_release(build_source, release_root)
        assert_source_identity(build_source, identity, require_running_builder=False)
        source_tree_digest = release_tree_sha256(release_root)
        write_metadata(release_root, version, identity, source_tree_digest, epoch)
        write_release_notes(release_root, version)
        write_release_smoke(release_root)
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
            "".join(
                f"{sha256(path)}  {path.name}\n" for path in sorted(artifacts)
            ),
        )

        publish = stage / "publish"
        publish.mkdir()
        for path in [*artifacts, checksums]:
            path.rename(publish / path.name)

        assert_source_identity(build_source, identity, require_running_builder=False)
        assert_source_identity(source, identity, require_running_builder=True)
        if output.exists():
            output.rmdir()
        os.replace(publish, output)
        return [output / path.name for path in [*artifacts, checksums]]


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
