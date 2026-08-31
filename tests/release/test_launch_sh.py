import os
import pathlib
import stat
import subprocess
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
        self.state_dir = self.temp / "state"

        self._write_executable(
            "docker",
            f"""
            #!/bin/sh
            printf '%s\\n' "$*" >> {self.command_log}
            case "$*" in
              "version --format {{{{.Server.Version}}}}") printf '%s\\n' '27.1.1' ;;
              "compose version --short") printf '%s\\n' '2.29.1' ;;
              *" ps -q web-api") printf '%s\\n' 'container-id' ;;
              "inspect --format {{{{.State.Health.Status}}}} container-id") printf '%s\\n' 'healthy' ;;
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
            """
            #!/bin/sh
            printf '%s\n' '0123456789abcdef0123456789abcdef'
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

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.bin_dir}:{env['PATH']}"
        env["SQLLENS_STATE_DIR"] = str(self.state_dir)
        return subprocess.run(
            [str(LAUNCHER), *args],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
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
        self.assertLess(commands.index("run --rm web-api migrate"), commands.index("up -d --build"))
        self.assertNotIn("0123456789abcdef0123456789abcdef", commands)
        bootstrap_file = self.state_dir / "bootstrap-code"
        self.assertTrue(bootstrap_file.exists())
        self.assertEqual(bootstrap_file.read_text(), "")
        self.assertEqual(stat.S_IMODE(bootstrap_file.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
