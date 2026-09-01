from __future__ import annotations

import os
from pathlib import Path

import pytest
import sqllens_api.credentials as credentials_module
import sqllens_api.setup as setup_runtime
from sqllens_api.config import Settings
from sqllens_api.credentials import CredentialUnavailableError, CredentialVault
from sqllens_api.setup import SetupSessionSigner, SetupStore


def test_explicit_rotation_recovers_from_an_invalid_length_key(tmp_path: Path) -> None:
    key_path = tmp_path / "secrets" / "credential.key"
    vault = CredentialVault(key_path)
    previous = vault.encrypt("old-provider-secret")
    key_path.write_bytes(b"corrupt")
    key_path.chmod(0o600)

    rotated = vault.rotate("new-provider-secret", previous=previous)

    assert rotated.key_version.startswith("file-v1:")
    assert vault.decrypt(rotated) == "new-provider-secret"
    assert CredentialVault(key_path).decrypt(rotated) == "new-provider-secret"
    with pytest.raises(CredentialUnavailableError):
        vault.decrypt(previous)


def test_explicit_rotation_rejects_a_symlinked_previous_key(tmp_path: Path) -> None:
    key_path = tmp_path / "secrets" / "credential.key"
    vault = CredentialVault(key_path)
    previous = vault.encrypt("old-provider-secret")
    alternate = tmp_path / "alternate.key"
    alternate.write_bytes(b"x" * 32)
    alternate.chmod(0o600)
    key_path.unlink()
    key_path.symlink_to(alternate)

    with pytest.raises(CredentialUnavailableError):
        vault.rotate("new-provider-secret", previous=previous)

    assert list(key_path.parent.glob("credential.file-v1-*.key")) == []


def test_failed_key_permission_update_closes_the_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor: int | None = None

    def fail_fchmod(fd: int, _mode: int) -> None:
        nonlocal descriptor
        descriptor = fd
        raise OSError("forced fchmod failure")

    monkeypatch.setattr(credentials_module.os, "fchmod", fail_fchmod)

    with pytest.raises(CredentialUnavailableError):
        CredentialVault(tmp_path / "secrets" / "credential.key").encrypt("secret")

    assert descriptor is not None
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_credential_directory_and_key_symlinks_fail_closed(tmp_path: Path) -> None:
    unsafe_directory = tmp_path / "unsafe"
    unsafe_directory.mkdir(mode=0o755)
    with pytest.raises(CredentialUnavailableError):
        CredentialVault(unsafe_directory / "credential.key").encrypt("secret")

    safe_directory = tmp_path / "safe"
    safe_directory.mkdir(mode=0o700)
    target = tmp_path / "target.key"
    target.write_bytes(b"x" * 32)
    target.chmod(0o600)
    (safe_directory / "credential.key").symlink_to(target)
    with pytest.raises(CredentialUnavailableError):
        CredentialVault(safe_directory / "credential.key").encrypt("secret")


def test_failed_session_key_permission_update_closes_the_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    descriptor: int | None = None

    def fail_fchmod(fd: int, _mode: int) -> None:
        nonlocal descriptor
        descriptor = fd
        raise OSError("forced fchmod failure")

    monkeypatch.setattr(setup_runtime.os, "fchmod", fail_fchmod)

    with pytest.raises(RuntimeError):
        SetupSessionSigner(Settings(data_dir=data_dir))

    assert descriptor is not None
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_setup_store_rejects_a_symlinked_data_directory_without_chmodding_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    data_dir = tmp_path / "data"
    data_dir.symlink_to(target, target_is_directory=True)

    with pytest.raises(RuntimeError):
        SetupStore(Settings(data_dir=data_dir))

    assert target.stat().st_mode & 0o777 == 0o755
