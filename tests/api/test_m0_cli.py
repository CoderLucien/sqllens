from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqllens_api import main as main_module


@pytest.mark.parametrize("command", ["migrate", "bootstrap-ingest", "bootstrap-reissue"])
def test_m0_python_cli_rejects_every_non_web_command(
    command: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_side_effect(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a removed M0 command reached legacy implementation")

    monkeypatch.setattr(sys, "argv", ["sqllens-runtime", command])
    monkeypatch.setattr(main_module, "SetupStore", forbidden_side_effect, raising=False)
    monkeypatch.setattr(
        main_module,
        "ingest_bootstrap_stdin",
        forbidden_side_effect,
        raising=False,
    )

    with pytest.raises(SystemExit) as raised:
        main_module.cli()

    assert raised.value.code == 2


@pytest.mark.parametrize("command", ["migrate", "bootstrap-ingest", "bootstrap-reissue"])
def test_m0_entrypoint_rejects_removed_commands_without_invoking_python(
    tmp_path: Path,
    command: str,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    invocation = tmp_path / "python-invocation"
    fake_python = fake_bin / "python"
    fake_python.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$SQLLENS_TEST_INVOCATION\"\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)

    result = subprocess.run(
        ["/bin/sh", "apps/api/entrypoint.sh", command],
        cwd=Path(__file__).resolve().parents[2],
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "SQLLENS_TEST_INVOCATION": str(invocation),
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 64
    assert result.stderr == f"unsupported runtime command: {command}\n"
    assert not invocation.exists()


@pytest.mark.parametrize("arguments", [[], ["web-api"]])
def test_m0_entrypoint_allows_only_the_web_application(
    tmp_path: Path,
    arguments: list[str],
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    invocation = tmp_path / "python-invocation"
    fake_python = fake_bin / "python"
    fake_python.write_text(
        "#!/bin/sh\n"
        "printf '%s|%s|%s\\n' \"$*\" \"$SQLLENS_BIND_HOST\" \"$SQLLENS_PORT\" "
        "> \"$SQLLENS_TEST_INVOCATION\"\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)

    result = subprocess.run(
        ["/bin/sh", "apps/api/entrypoint.sh", *arguments],
        cwd=Path(__file__).resolve().parents[2],
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "SQLLENS_TEST_INVOCATION": str(invocation),
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert invocation.read_text(encoding="utf-8") == (
        "-m sqllens_api.main web-api|0.0.0.0|8080\n"
    )
