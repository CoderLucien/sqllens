from __future__ import annotations

import html
import re
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs/superpowers/specs/2026-09-02-sqllens-vnext-product-spec.md"
PROTOTYPE = ROOT / "docs/product/sqllens-vnext-customer-journey.html"
DOCKERFILE = ROOT / "apps/api/Dockerfile"


def _install_command_from_spec() -> list[str]:
    match = re.search(
        r"~~~bash\n(?P<command>docker run .*?)\n~~~",
        SPEC.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    )
    assert match is not None
    command = match.group("command").replace("\\\n", " ")
    return shlex.split(command)


def test_single_docker_command_freezes_local_persistence_and_sandbox_boundaries() -> None:
    command = _install_command_from_spec()

    assert command[:3] == ["docker", "run", "-d"]
    assert command.count("docker") == 1
    assert command[command.index("--name") + 1] == "sqllens"
    assert command[command.index("--restart") + 1] == "unless-stopped"
    assert "--read-only" in command
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("-p") + 1] == "127.0.0.1:18080:8080"
    assert command[command.index("--tmpfs") + 1] == "/tmp:rw,noexec,nosuid,nodev,size=64m"
    assert "sqllens-data:/data" in command
    assert "sqllens-secrets:/secrets" in command
    assert "--privileged" not in command
    assert "0.0.0.0:18080:8080" not in command


def test_review_prototype_keeps_the_image_reference_deliberately_unrunnable() -> None:
    prototype = html.unescape(PROTOTYPE.read_text(encoding="utf-8"))

    assert "registry.example.invalid/sqllens@sha256:<published-digest>" in prototype
    assert "评审稿不会提供可运行镜像" in prototype
    assert "只有版本、来源、SBOM、签名和 QA 证据全部冻结后" in prototype


def test_runtime_image_declares_the_fixed_non_root_identity() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert re.search(r"(?m)^USER 10001:10001$", dockerfile)
