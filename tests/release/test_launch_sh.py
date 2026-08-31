import os
import pathlib
import stat
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "launch.sh"


class PosixLauncherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp = pathlib.Path(self.temp_dir.name)
        self.bin_dir = self.temp / "bin"
        self.bin_dir.mkdir()
        self.command_log = self.temp / "docker.log"
        self.running_file = self.temp / "running"
        self.migrate_started_file = self.temp / "migrate-started"
        self.release_migrate_file = self.temp / "release-migrate"
        self.handshake_started_file = self.temp / "handshake-started"
        self.release_handshake_file = self.temp / "release-handshake"
        self.openssl_counter_file = self.temp / "openssl-called"
        self.state_dir = self.temp / "state"

        self._write_executable(
            "docker",
            f"""
            #!/bin/sh
            printf '%s\\n' "$*" >> {self.command_log}
            case "$*" in
              "version --format {{{{.Server.Version}}}}") printf '%s\\n' '27.1.1' ;;
              "compose version --short") printf '%s\\n' '2.29.1' ;;
              *" run --rm web-api migrate")
                if [ "${{SQLLENS_FAKE_BLOCK_MIGRATE:-0}}" = 1 ]; then
                  : > {self.migrate_started_file}
                  while [ ! -f {self.release_migrate_file} ]; do /bin/sleep 0.01; done
                fi
                ;;
              *" up -d --build") : > {self.running_file} ;;
              *" ps -q web-api")
                [ ! -f {self.running_file} ] || printf '%s\\n' 'container-id'
                ;;
              "inspect --format {{{{.State.Health.Status}}}} container-id")
                printf '%s\\n' "${{SQLLENS_FAKE_HEALTH:-healthy}}"
                ;;
              "inspect --format {{{{.State.Running}}}} container-id") printf '%s\\n' 'true' ;;
              "exec container-id python -c "*)
                if [ "${{SQLLENS_FAKE_BLOCK_HANDSHAKE:-0}}" = 1 ]; then
                  : > {self.handshake_started_file}
                  while [ ! -f {self.release_handshake_file} ]; do /bin/sleep 0.01; done
                fi
                [ "${{SQLLENS_FAKE_BOOTSTRAP_PERSISTED:-1}}" = 1 ]
                ;;
            esac
            """,
        )
        self._write_executable(
            "df",
            """
            #!/bin/sh
            printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'
            printf '%s\n' '/dev/disk 20000000 1000 19999000 1% /'
            """,
        )
        self._write_executable(
            "openssl",
            f"""
            #!/bin/sh
            if [ -f {self.openssl_counter_file} ]; then
              printf '%s\\n' 'fedcba9876543210fedcba9876543210'
            else
              : > {self.openssl_counter_file}
              printf '%s\\n' '0123456789abcdef0123456789abcdef'
            fi
            """,
        )
        self._write_executable("sleep", "#!/bin/sh\nexit 0\n")

    def _write_executable(self, name: str, body: str) -> None:
        path = self.bin_dir / name
        path.write_text(textwrap.dedent(body).lstrip())
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _write_uname(self, system: str, machine: str) -> None:
        self._write_executable(
            "uname",
            f"""
            #!/bin/sh
            if [ "$1" = "-s" ]; then
              printf '%s\\n' '{system}'
            else
              printf '%s\\n' '{machine}'
            fi
            """,
        )

    def _write_lsof(self, port_is_busy: bool) -> None:
        exit_code = 0 if port_is_busy else 1
        self._write_executable("lsof", f"#!/bin/sh\nexit {exit_code}\n")

    def _environment(self, extra_env: dict[str, str] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.bin_dir}:{env['PATH']}"
        env["SQLLENS_STATE_DIR"] = str(self.state_dir)
        if extra_env:
            env.update(extra_env)
        return env

    def _run(
        self,
        *args: str,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(LAUNCHER), *args],
            cwd=ROOT,
            env=self._environment(extra_env),
            text=True,
            capture_output=True,
            check=False,
        )

    def _popen(
        self,
        *args: str,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [str(LAUNCHER), *args],
            cwd=ROOT,
            env=self._environment(extra_env),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_check_accepts_apple_silicon_external_model_path(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)

        result = self._run("check")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Platform: macOS/arm64", result.stdout)
        self.assertIn("Docker: 27.1.1", result.stdout)
        self.assertIn("Compose: 2.29.1", result.stdout)
        self.assertIn("Preflight passed", result.stdout)

    def test_check_rejects_an_unsupported_architecture(self) -> None:
        self._write_uname("Darwin", "riscv64")
        self._write_lsof(port_is_busy=False)

        result = self._run("check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported architecture: riscv64", result.stderr)

    def test_check_reports_a_busy_port_with_remediation(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=True)

        result = self._run("check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("port 8080 is already in use", result.stderr)
        self.assertIn("SQLLENS_PORT", result.stderr)

    def test_successful_check_preserves_an_existing_bootstrap_secret(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)
        self.state_dir.mkdir()
        bootstrap_file = self.state_dir / "bootstrap-code"
        bootstrap_file.write_text("sentinel")

        result = self._run("check")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(bootstrap_file.read_text(), "sentinel")

    def test_failed_check_preserves_an_existing_bootstrap_secret(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=True)
        self.state_dir.mkdir()
        bootstrap_file = self.state_dir / "bootstrap-code"
        bootstrap_file.write_text("sentinel")

        result = self._run("check")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(bootstrap_file.read_text(), "sentinel")

    def test_successful_check_does_not_create_a_state_directory(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)

        result = self._run("check")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state_dir.exists())

    def test_failed_check_does_not_create_a_state_directory(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=True)

        result = self._run("check")

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.state_dir.exists())

    def test_local_mode_on_mac_fails_closed_with_external_fallback(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)

        result = self._run("check", "--mode", "local")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("local GPU mode is not qualified on macOS", result.stderr)
        self.assertIn("--mode external", result.stderr)

    def test_start_runs_migration_then_compose_and_scrubs_bootstrap_file(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)

        result = self._run("start")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("http://127.0.0.1:8080", result.stdout)
        self.assertIn("0123456789abcdef0123456789abcdef", result.stdout)
        commands = self.command_log.read_text()
        self.assertIn("run --rm web-api migrate", commands)
        self.assertIn("up -d --build", commands)
        self.assertIn("/api/v1/setup/status", commands)
        self.assertIn("bootstrap_hash_persisted", commands)
        self.assertIn("is True", commands)
        self.assertLess(commands.index("run --rm web-api migrate"), commands.index("up -d --build"))
        self.assertNotIn("0123456789abcdef0123456789abcdef", commands)
        bootstrap_file = self.state_dir / "bootstrap-code"
        self.assertTrue(bootstrap_file.exists())
        self.assertEqual(bootstrap_file.read_text(), "")
        self.assertEqual(stat.S_IMODE(bootstrap_file.stat().st_mode), 0o600)

    def test_repeated_start_reuses_the_managed_container(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)
        first = self._run("start")
        self._write_lsof(port_is_busy=True)

        second = self._run("start")

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("already running", second.stdout)
        commands = self.command_log.read_text()
        self.assertEqual(commands.count("up -d --build"), 1)
        self.assertEqual(commands.count("run --rm web-api migrate"), 1)

    def test_concurrent_start_does_not_replace_the_first_bootstrap_code(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)
        first = self._popen("start", extra_env={"SQLLENS_FAKE_BLOCK_MIGRATE": "1"})
        for _ in range(200):
            if self.migrate_started_file.exists():
                break
            import time

            time.sleep(0.01)
        else:
            first.kill()
            self.fail("first launcher did not reach migration")

        second = self._run("start")
        secret_during_first_start = (self.state_dir / "bootstrap-code").read_text().strip()
        self.release_migrate_file.touch()
        first_stdout, first_stderr = first.communicate(timeout=5)

        self.assertEqual(first.returncode, 0, first_stderr)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("startup is already in progress", second.stderr)
        self.assertEqual(secret_during_first_start, "0123456789abcdef0123456789abcdef")
        self.assertIn(secret_during_first_start, first_stdout)
        self.assertEqual(self.command_log.read_text().count("up -d --build"), 1)

    def test_concurrent_start_is_blocked_after_the_container_is_running(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)
        first = self._popen("start", extra_env={"SQLLENS_FAKE_BLOCK_HANDSHAKE": "1"})
        for _ in range(200):
            if self.handshake_started_file.exists():
                break
            import time

            time.sleep(0.01)
        else:
            first.kill()
            self.fail("first launcher did not reach bootstrap handshake")
        self._write_lsof(port_is_busy=True)

        second = self._run("start")
        self.release_handshake_file.touch()
        _, first_stderr = first.communicate(timeout=5)

        self.assertEqual(first.returncode, 0, first_stderr)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("startup is already in progress", second.stderr)
        self.assertEqual(self.command_log.read_text().count("up -d --build"), 1)

    def test_stale_start_lock_is_recovered(self) -> None:
        self._write_uname("Linux", "x86_64")
        self._write_lsof(port_is_busy=False)
        lock_dir = self.state_dir / "start.lock"
        lock_dir.mkdir(parents=True)
        (lock_dir / "owner-pid").write_text("99999999\n")

        result = self._run("start")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(lock_dir.exists())

    def test_failed_bootstrap_handshake_keeps_the_secret_for_recovery(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)

        result = self._run(
            "start",
            extra_env={"SQLLENS_FAKE_BOOTSTRAP_PERSISTED": "0"},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bootstrap hash persistence", result.stderr)
        bootstrap_file = self.state_dir / "bootstrap-code"
        self.assertEqual(bootstrap_file.read_text().strip(), "0123456789abcdef0123456789abcdef")
        self.assertEqual(stat.S_IMODE(bootstrap_file.stat().st_mode), 0o600)

    def test_repeated_start_recovers_a_retained_bootstrap_secret(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)
        first = self._run(
            "start",
            extra_env={"SQLLENS_FAKE_BOOTSTRAP_PERSISTED": "0"},
        )
        self._write_lsof(port_is_busy=True)

        second = self._run("start")

        self.assertNotEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("0123456789abcdef0123456789abcdef", second.stdout)
        self.assertEqual((self.state_dir / "bootstrap-code").read_text(), "")
        commands = self.command_log.read_text()
        self.assertEqual(commands.count("run --rm web-api migrate"), 1)
        self.assertEqual(commands.count("up -d --build"), 1)

    def test_stopped_retry_reuses_the_retained_bootstrap_secret(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)
        first = self._run(
            "start",
            extra_env={"SQLLENS_FAKE_BOOTSTRAP_PERSISTED": "0"},
        )
        self.running_file.unlink()

        second = self._run("start")

        self.assertNotEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("0123456789abcdef0123456789abcdef", second.stdout)
        self.assertNotIn("fedcba9876543210fedcba9876543210", second.stdout)
        self.assertEqual((self.state_dir / "bootstrap-code").read_text(), "")

    def test_start_rejects_a_world_readable_retained_secret(self) -> None:
        self._write_uname("Linux", "x86_64")
        self._write_lsof(port_is_busy=False)
        self.state_dir.mkdir()
        bootstrap_file = self.state_dir / "bootstrap-code"
        bootstrap_file.write_text("0123456789abcdef0123456789abcdef\n")
        bootstrap_file.chmod(0o644)

        result = self._run("start")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mode 0600", result.stderr)
        self.assertEqual(bootstrap_file.read_text().strip(), "0123456789abcdef0123456789abcdef")

    def test_start_rejects_a_malformed_retained_secret(self) -> None:
        self._write_uname("Linux", "x86_64")
        self._write_lsof(port_is_busy=False)
        self.state_dir.mkdir()
        bootstrap_file = self.state_dir / "bootstrap-code"
        bootstrap_file.write_text("not-a-valid-code\n")
        bootstrap_file.chmod(0o600)

        result = self._run("start")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid", result.stderr)
        self.assertEqual(bootstrap_file.read_text().strip(), "not-a-valid-code")

    def test_stop_retains_the_named_data_volume(self) -> None:
        self._write_uname("Linux", "x86_64")
        self._write_lsof(port_is_busy=False)

        result = self._run("stop")

        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.command_log.read_text()
        self.assertIn("down --remove-orphans", commands)
        self.assertNotIn("--volumes", commands)
        self.assertIn("Data retained", result.stdout)

    def test_uninstall_only_removes_data_with_explicit_purge_flag(self) -> None:
        self._write_uname("Linux", "x86_64")
        self._write_lsof(port_is_busy=False)

        retained = self._run("uninstall")
        purged = self._run("uninstall", "--purge-data")

        self.assertEqual(retained.returncode, 0, retained.stderr)
        self.assertEqual(purged.returncode, 0, purged.stderr)
        commands = self.command_log.read_text()
        self.assertIn("down --remove-orphans --rmi local", commands)
        self.assertIn("down --remove-orphans --volumes --rmi local", commands)
        self.assertIn("Data retained", retained.stdout)
        self.assertIn("Data volume removed", purged.stdout)

    def test_diagnostics_archive_excludes_logs_and_environment(self) -> None:
        self._write_uname("Darwin", "arm64")
        self._write_lsof(port_is_busy=False)
        self.running_file.touch()
        self.state_dir.mkdir()
        bootstrap_file = self.state_dir / "bootstrap-code"
        bootstrap_file.write_text("0123456789abcdef0123456789abcdef\n")

        result = self._run("diagnostics")

        self.assertEqual(result.returncode, 0, result.stderr)
        archives = list((self.state_dir / "diagnostics").glob("*.tar.gz"))
        self.assertEqual(len(archives), 1)
        with tarfile.open(archives[0], "r:gz") as archive:
            names = set(archive.getnames())
            self.assertTrue(any(name.endswith("system.txt") for name in names))
            self.assertTrue(any(name.endswith("containers.txt") for name in names))
            self.assertTrue(any(name.endswith("compose.txt") for name in names))
            self.assertFalse(any(name.endswith("logs.txt") for name in names))
            self.assertFalse(any(name.endswith("environment.txt") for name in names))
            contents = b"".join(
                archive.extractfile(member).read()
                for member in archive.getmembers()
                if member.isfile()
            )
        self.assertNotIn(b"0123456789abcdef0123456789abcdef", contents)
        self.assertEqual(bootstrap_file.read_text().strip(), "0123456789abcdef0123456789abcdef")


if __name__ == "__main__":
    unittest.main()
