import hashlib
import json
import os
import pathlib
import plistlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from scripts.release import build_release

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "release" / "build_release.py"


class ReleaseBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp = pathlib.Path(self.temp_dir.name)
        self.source = self.temp / "source"
        self.output = self.temp / "dist"
        self._write_fixture_source()

    def _write_fixture_source(self) -> None:
        files = {
            "launch.sh": "#!/bin/sh\nprintf 'launch\\n'\n",
            "deploy/compose.json": '{"name":"sqllens","services":{}}\n',
            "apps/api/Dockerfile": "FROM scratch\n",
            "apps/api/app.py": "print('api')\n",
            "apps/web/package.json": '{"name":"web"}\n',
            "apps/web/src/main.ts": "export {};\n",
            "requirements/runtime.txt": "\n",
            "pyproject.toml": "[project]\nname='sqllens'\nversion='0.1.0'\n",
            ".dockerignore": "node_modules\n",
            "Makefile": "smoke:\n\t@true\n",
            "apps/web/node_modules/ignored/package.json": "{}\n",
        }
        for relative, content in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (self.source / "launch.sh").chmod(0o755)
        git_env = os.environ.copy()
        git_env.update(
            {
                "GIT_AUTHOR_DATE": "2026-09-01T00:00:00+08:00",
                "GIT_COMMITTER_DATE": "2026-09-01T00:00:00+08:00",
            }
        )
        subprocess.run(["git", "init", "-q"], cwd=self.source, check=True)
        subprocess.run(
            ["git", "config", "user.name", "SQLLens Release Test"],
            cwd=self.source,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "release-test@sqllens.invalid"],
            cwd=self.source,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=self.source, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "fixture"],
            cwd=self.source,
            env=git_env,
            check=True,
        )
        self.revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.source,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()

    def _build(
        self,
        output: pathlib.Path | None = None,
        revision: str | None = None,
        source_date_epoch: str | None = "1788192000",
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if source_date_epoch is None:
            env.pop("SOURCE_DATE_EPOCH", None)
        else:
            env["SOURCE_DATE_EPOCH"] = source_date_epoch
        return subprocess.run(
            [
                sys.executable,
                str(BUILDER),
                "--source",
                str(self.source),
                "--output",
                str(output or self.output),
                "--version",
                "0.1.0-dev.1",
                "--revision",
                revision or self.revision[:12],
                "--skip-dmg",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_builds_app_zip_cli_archive_and_checksums(self) -> None:
        result = self._build()

        self.assertEqual(result.returncode, 0, result.stderr)
        app_zip = self.output / "sqllens-0.1.0-dev.1-macos-preview.app.zip"
        cli_archive = self.output / "sqllens-0.1.0-dev.1-source.tar.gz"
        checksums = self.output / "SHA256SUMS"
        self.assertTrue(app_zip.is_file())
        self.assertTrue(cli_archive.is_file())
        self.assertTrue(checksums.is_file())
        self.assertIn("DMG not generated", result.stdout)

        expected = {
            app_zip.name: hashlib.sha256(app_zip.read_bytes()).hexdigest(),
            cli_archive.name: hashlib.sha256(cli_archive.read_bytes()).hexdigest(),
        }
        actual = {
            line.split("  ", 1)[1]: line.split("  ", 1)[0]
            for line in checksums.read_text().splitlines()
        }
        self.assertEqual(actual, expected)

    def test_app_bundle_contains_the_same_compose_and_a_double_click_launcher(
        self,
    ) -> None:
        result = self._build()
        self.assertEqual(result.returncode, 0, result.stderr)
        app_zip = self.output / "sqllens-0.1.0-dev.1-macos-preview.app.zip"

        with zipfile.ZipFile(app_zip) as archive:
            names = set(archive.namelist())
            prefix = "SQLLens.app/Contents"
            self.assertTrue(all(name.startswith("SQLLens.app/") for name in names))
            self.assertIn(f"{prefix}/Info.plist", names)
            self.assertIn(f"{prefix}/MacOS/SQLLens", names)
            self.assertIn(f"{prefix}/Resources/release/launch.command", names)
            self.assertIn(f"{prefix}/Resources/release/launch.sh", names)
            self.assertIn(f"{prefix}/Resources/release/RELEASE-NOTES.txt", names)
            self.assertIn(f"{prefix}/Resources/release/deploy/compose.json", names)
            self.assertFalse(any("node_modules" in name for name in names))
            self.assertFalse(any("/.git/" in name for name in names))

            compose = archive.read(f"{prefix}/Resources/release/deploy/compose.json")
            self.assertEqual(
                compose, (self.source / "deploy/compose.json").read_bytes()
            )
            plist = plistlib.loads(archive.read(f"{prefix}/Info.plist"))
            self.assertEqual(plist["CFBundleShortVersionString"], "0.1.0")
            self.assertEqual(plist["CFBundleVersion"], "0.1.0")
            self.assertEqual(plist["SQLLensReleaseVersion"], "0.1.0-dev.1")
            self.assertIn("Developer Preview", plist["CFBundleDisplayName"])

            app_mode = archive.getinfo(f"{prefix}/MacOS/SQLLens").external_attr >> 16
            command_mode = (
                archive.getinfo(
                    f"{prefix}/Resources/release/launch.command"
                ).external_attr
                >> 16
            )
            self.assertTrue(app_mode & 0o111)
            self.assertTrue(command_mode & 0o111)
            self.assertIn(
                b"osascript",
                archive.read(f"{prefix}/MacOS/SQLLens"),
            )
            launch_command = archive.read(
                f"{prefix}/Resources/release/launch.command"
            )
            self.assertIn(b"./launch.sh url", launch_command)
            self.assertNotIn(b"SQLLENS_PORT:-8080", launch_command)

    def test_source_archive_carries_honest_preview_metadata(self) -> None:
        result = self._build()
        self.assertEqual(result.returncode, 0, result.stderr)
        cli_archive = self.output / "sqllens-0.1.0-dev.1-source.tar.gz"

        with tarfile.open(cli_archive, "r:gz") as archive:
            metadata_member = next(
                member
                for member in archive.getmembers()
                if member.name.endswith("build-metadata.json")
            )
            metadata_stream = archive.extractfile(metadata_member)
            if metadata_stream is None:
                self.fail("build metadata is not a regular archive member")
            metadata = json.load(metadata_stream)
            names = {member.name for member in archive.getmembers()}

        self.assertEqual(metadata["source_revision"], self.revision)
        self.assertRegex(metadata["source_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(metadata["release_kind"], "unsigned-developer-preview")
        self.assertEqual(metadata["platform_validation"]["macos"], "unverified")
        self.assertEqual(
            metadata["signing"], {"code_signed": False, "notarized": False}
        )
        self.assertFalse(any("node_modules" in name for name in names))
        self.assertFalse(any("/.git/" in name for name in names))

        extracted = self.temp / "metadata-source"
        with tarfile.open(cli_archive, "r:gz") as archive:
            archive.extractall(extracted, filter="data")
        release_root = extracted / "sqllens-0.1.0-dev.1"
        for generated_name in (
            "build-metadata.json",
            "RELEASE-NOTES.txt",
            "release-smoke.sh",
            "launch.command",
        ):
            (release_root / generated_name).unlink()
        self.assertEqual(
            metadata["source_tree_sha256"],
            build_release.release_tree_sha256(release_root),
        )

    def test_end_user_archive_replaces_developer_make_targets_with_bounded_smoke(
        self,
    ) -> None:
        result = self._build()
        self.assertEqual(result.returncode, 0, result.stderr)
        cli_archive = self.output / "sqllens-0.1.0-dev.1-source.tar.gz"

        with tarfile.open(cli_archive, "r:gz") as archive:
            members = {member.name: member for member in archive.getmembers()}
            prefix = "sqllens-0.1.0-dev.1"
            smoke_name = f"{prefix}/release-smoke.sh"
            notes_name = f"{prefix}/RELEASE-NOTES.txt"
            self.assertIn(smoke_name, members)
            self.assertTrue(members[smoke_name].mode & 0o111)
            self.assertNotIn(f"{prefix}/Makefile", members)
            self.assertFalse(any("/tests/" in name for name in members))
            notes_stream = archive.extractfile(members[notes_name])
            if notes_stream is None:
                self.fail("release notes are not a regular archive member")
            notes = notes_stream.read().decode()

        for command in (
            "shasum -a 256 -c SHA256SUMS",
            "sha256sum -c SHA256SUMS",
            "./launch.sh check",
            "./launch.sh recover-setup",
            "./launch.sh diagnostics",
            "./release-smoke.sh",
            "./launch.sh uninstall --purge-data",
        ):
            self.assertIn(command, notes)
        self.assertIn("sqllens-secrets", notes)
        self.assertIn("unverified", notes.lower())

    def test_release_smoke_checks_only_bounded_local_runtime_state(self) -> None:
        result = self._build()
        self.assertEqual(result.returncode, 0, result.stderr)
        cli_archive = self.output / "sqllens-0.1.0-dev.1-source.tar.gz"
        extracted = self.temp / "extracted"
        with tarfile.open(cli_archive, "r:gz") as archive:
            archive.extractall(extracted, filter="data")
        release = extracted / "sqllens-0.1.0-dev.1"
        fake_bin = self.temp / "fake-bin"
        fake_bin.mkdir()
        docker_log = self.temp / "docker.log"
        docker = fake_bin / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$*\" >> {docker_log}\n"
            'case "$*" in\n'
            "  *\" ps -q web-api\") printf '%s\\n' container-id ;;\n"
            "  \"inspect --format {{.State.Running}} container-id\") printf '%s\\n' true ;;\n"
            "  \"inspect --format {{.State.Health.Status}} container-id\") printf '%s\\n' healthy ;;\n"
            '  "exec container-id python -c "*) exit 0 ;;\n'
            "esac\n"
        )
        docker.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

        smoke = subprocess.run(
            [str(release / "release-smoke.sh")],
            cwd=release,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(smoke.returncode, 0, smoke.stderr)
        self.assertIn("Release smoke passed", smoke.stdout)
        commands = docker_log.read_text()
        self.assertIn("ps -q web-api", commands)
        self.assertIn(".State.Running", commands)
        self.assertIn(".State.Health.Status", commands)
        self.assertIn("/healthz", commands)
        self.assertIn("/api/v1/setup/status", commands)
        self.assertNotIn("logs", commands)
        self.assertNotIn("env", commands)

    def test_build_is_reproducible_with_source_date_epoch(self) -> None:
        first_output = self.temp / "first"
        second_output = self.temp / "second"
        first = self._build(first_output)
        second = self._build(second_output)

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(
            (first_output / "SHA256SUMS").read_text(),
            (second_output / "SHA256SUMS").read_text(),
        )

    def test_default_build_epoch_is_the_verified_commit_timestamp(self) -> None:
        result = self._build(source_date_epoch=None)

        self.assertEqual(result.returncode, 0, result.stderr)
        cli_archive = self.output / "sqllens-0.1.0-dev.1-source.tar.gz"
        with tarfile.open(cli_archive, "r:gz") as archive:
            metadata_member = next(
                member
                for member in archive.getmembers()
                if member.name.endswith("build-metadata.json")
            )
            metadata_stream = archive.extractfile(metadata_member)
            if metadata_stream is None:
                self.fail("build metadata is not a regular archive member")
            metadata = json.load(metadata_stream)

        self.assertEqual(metadata["build_timestamp"], "2026-08-31T16:00:00Z")

    def test_revision_must_match_the_clean_source_git_head(self) -> None:
        mismatch = "0000000" if not self.revision.startswith("0000000") else "1111111"
        result = self._build(revision=mismatch)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match source HEAD", result.stderr)
        self.assertFalse(self.output.exists())

    def test_dirty_release_source_cannot_claim_the_git_revision(self) -> None:
        (self.source / "apps" / "api" / "app.py").write_text("print('changed')\n")

        result = self._build()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release source has uncommitted changes", result.stderr)
        self.assertFalse(self.output.exists())

    def test_git_ignored_file_in_a_packaged_path_fails_closed(self) -> None:
        exclude = self.source / ".git" / "info" / "exclude"
        exclude.write_text(exclude.read_text() + "\n*.release-canary\n")
        canary = self.source / "apps" / "api" / "credential.release-canary"
        canary.write_text("must-not-ship\n")

        result = self._build()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not tracked by source revision", result.stderr)
        self.assertFalse(self.output.exists())

    def test_skip_worktree_cannot_silently_omit_a_tracked_release_file(self) -> None:
        relative = "apps/api/app.py"
        subprocess.run(
            ["git", "update-index", "--skip-worktree", relative],
            cwd=self.source,
            check=True,
        )
        (self.source / relative).unlink()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--", relative],
            cwd=self.source,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(status.stdout, "")

        result = self._build()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not fully materialized from source revision", result.stderr)
        self.assertFalse(self.output.exists())

    def test_publish_failure_never_exposes_a_partial_output_directory(self) -> None:
        with mock.patch.dict(
            os.environ, {"SOURCE_DATE_EPOCH": "1788192000"}, clear=False
        ):
            with mock.patch.object(
                build_release.os,
                "replace",
                side_effect=OSError("simulated atomic publish failure"),
            ):
                with self.assertRaisesRegex(
                    OSError, "simulated atomic publish failure"
                ):
                    build_release.build(
                        self.source,
                        self.output,
                        "0.1.0-dev.1",
                        self.revision[:12],
                        skip_dmg=True,
                    )

        self.assertFalse(self.output.exists())

    def test_missing_runtime_dockerfile_fails_closed(self) -> None:
        (self.source / "apps" / "api" / "Dockerfile").unlink()

        result = self._build()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("apps/api/Dockerfile", result.stderr)
        self.assertFalse(self.output.exists())

    def test_version_cannot_escape_the_output_directory(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(BUILDER),
                "--source",
                str(self.source),
                "--output",
                str(self.output),
                "--version",
                "../outside",
                "--revision",
                "7bbb8da",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid version", result.stderr)
        self.assertFalse((self.temp / "outside").exists())

    def test_symbolic_links_are_rejected_instead_of_followed(self) -> None:
        outside = self.temp / "outside-secret"
        outside.write_text("do-not-package")
        (self.source / "apps" / "api" / "linked-secret").symlink_to(outside)
        subprocess.run(
            ["git", "add", "apps/api/linked-secret"], cwd=self.source, check=True
        )
        subprocess.run(
            ["git", "commit", "-qm", "add unsafe link"], cwd=self.source, check=True
        )
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.source,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()

        result = self._build(revision=revision[:12])

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic link", result.stderr)
        self.assertFalse(self.output.exists())

    def test_existing_release_artifacts_are_not_silently_mixed_or_overwritten(
        self,
    ) -> None:
        self.output.mkdir()
        stale_dmg = self.output / "sqllens-0.1.0-dev.1-macos-preview.dmg"
        stale_dmg.write_text("stale")

        result = self._build()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output already contains release artifacts", result.stderr)
        self.assertEqual(stale_dmg.read_text(), "stale")
        self.assertFalse((self.output / "SHA256SUMS").exists())


if __name__ == "__main__":
    unittest.main()
