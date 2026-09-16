from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
import sqllens_api.credentials as credentials_module
import sqllens_api.setup as setup_runtime
from sqllens_api.config import Settings
from sqllens_api.credentials import CredentialUnavailableError, CredentialVault
from sqllens_api.setup import SetupSessionSigner, SetupStore


def test_rotation_plan_is_ephemeral_until_materialized(tmp_path: Path) -> None:
    key_path = tmp_path / "secrets" / "credential.key"
    vault = CredentialVault(key_path)
    active = vault.encrypt("old-provider-secret")
    before = set(key_path.parent.iterdir())

    plan = vault.plan_rotation(active)

    assert plan.key_version not in repr(plan)
    assert plan.key.hex() not in repr(plan)
    assert set(key_path.parent.iterdir()) == before

    encrypted = vault.materialize_rotation("new-provider-secret", plan)

    assert encrypted.key_version == plan.key_version
    assert vault.decrypt(encrypted) == "new-provider-secret"


def test_materialized_rotation_fsyncs_file_then_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = tmp_path / "secrets" / "credential.key"
    vault = CredentialVault(key_path)
    active = vault.encrypt("old-provider-secret")
    plan = vault.plan_rotation(active)
    synced_types: list[str] = []
    original_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        mode = os.fstat(descriptor).st_mode
        synced_types.append("directory" if stat.S_ISDIR(mode) else "file")
        original_fsync(descriptor)

    monkeypatch.setattr(credentials_module.os, "fsync", record_fsync)

    vault.materialize_rotation("new-provider-secret", plan)

    assert synced_types == ["file", "directory"]


def test_staged_retirement_removes_safe_partial_file_without_digest_match(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "secrets" / "credential.key"
    vault = CredentialVault(key_path)
    active = vault.encrypt("old-provider-secret")
    plan = vault.plan_rotation(active)
    staged_path = key_path.with_name(
        f"{key_path.stem}.file-v1-{plan.identifier}{key_path.suffix}"
    )
    staged_path.write_bytes(b"partial")
    staged_path.chmod(0o600)

    vault.retire_staged_version(plan.key_version)

    assert not staged_path.exists()
    assert vault.decrypt(active) == "old-provider-secret"


@pytest.mark.parametrize("unsafe_kind", ["symlink", "fifo", "mode"])
def test_staged_retirement_does_not_touch_unsafe_exact_path(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    key_path = tmp_path / "secrets" / "credential.key"
    vault = CredentialVault(key_path)
    active = vault.encrypt("old-provider-secret")
    plan = vault.plan_rotation(active)
    staged_path = key_path.with_name(
        f"{key_path.stem}.file-v1-{plan.identifier}{key_path.suffix}"
    )
    target = tmp_path / "target.key"
    target.write_bytes(b"target")
    target.chmod(0o600)
    if unsafe_kind == "symlink":
        staged_path.symlink_to(target)
    elif unsafe_kind == "fifo":
        os.mkfifo(staged_path, mode=0o600)
    else:
        staged_path.write_bytes(b"partial")
        staged_path.chmod(0o644)

    with pytest.raises(CredentialUnavailableError):
        vault.retire_staged_version(plan.key_version)

    assert os.path.lexists(staged_path)
    assert target.read_bytes() == b"target"
    assert vault.decrypt(active) == "old-provider-secret"


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
