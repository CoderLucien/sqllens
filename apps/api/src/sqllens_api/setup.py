from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    case,
    create_engine,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine

from sqllens_api.config import Settings
from sqllens_api.credentials import EncryptedCredential
from sqllens_api.provider import ProviderProbeRequest, ProviderProbeResult

SETUP_COOKIE_NAME = "sqllens_setup_session"
OWNER_COOKIE_NAME = "sqllens_owner_session"
_STATE_ID = 1
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

metadata = MetaData()
setup_state = Table(
    "setup_state",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("stage", String(40), nullable=False),
    Column("bootstrap_hash", String(128)),
    Column("bootstrap_salt", String(64)),
    Column("bootstrap_expires_at", Float),
    Column("bootstrap_consumed_at", Float),
    Column("bootstrap_failed_attempts", Integer, nullable=False, default=0),
    Column("setup_epoch", Integer, nullable=False, default=1),
    Column("external_model_egress", Boolean),
    Column("allowed_provider_hosts", Text),
    Column("send_sql_text", Boolean, nullable=False, default=False),
    Column("policy_committed_at", Float),
    Column("provider_status", String(30)),
    Column("provider_base_url", Text),
    Column("provider_model", String(200)),
    Column("provider_verified_at", Float),
    Column("provider_credential_ciphertext", Text),
    Column("provider_credential_key_version", String(80)),
    Column("model_mode", String(30)),
    Column("owner_password_hash", String(128)),
    Column("owner_password_salt", String(64)),
    Column("owner_session_epoch", Integer, nullable=False, default=0),
    Column("owner_failed_attempts", Integer, nullable=False, default=0),
    Column("owner_locked_until", Float),
    Column("finalized_at", Float),
    Column("updated_at", Float, nullable=False),
)


def _timestamp(value: datetime) -> float:
    if value.tzinfo is None:
        raise ValueError("clock values must be timezone-aware")
    return value.astimezone(UTC).timestamp()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def normalize_bootstrap_code(value: str) -> str:
    return "".join(character for character in value.upper() if character in _CODE_ALPHABET)


def format_bootstrap_code(value: str) -> str:
    return "-".join(value[index : index + 4] for index in range(0, len(value), 4))


def _derive_code_hash(code: str, salt: bytes) -> str:
    derived = hashlib.scrypt(
        normalize_bootstrap_code(code).encode("ascii"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return _b64(derived)


def _derive_password_hash(password: str, salt: bytes) -> str:
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return _b64(derived)


@dataclass(frozen=True, slots=True)
class SetupSnapshot:
    stage: str
    initialized: bool
    external_model_egress: bool | None
    allowed_provider_hosts: tuple[str, ...]
    policy_committed_at: float | None
    provider_status: str | None
    provider_base_url: str | None
    provider_model: str | None
    provider_verified_at: float | None
    provider_credential: EncryptedCredential | None
    model_mode: str | None
    bootstrap_persisted: bool
    bootstrap_expires_at: float | None
    bootstrap_consumed_at: float | None
    bootstrap_failed_attempts: int
    setup_epoch: int
    owner_configured: bool
    owner_session_epoch: int
    owner_failed_attempts: int
    owner_locked_until: float | None


@dataclass(frozen=True, slots=True)
class OwnerAuthentication:
    status: Literal["authenticated", "invalid", "limited"]
    setup_epoch: int | None = None
    session_epoch: int | None = None


class SetupStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._prepare_data_dir()
        self.engine = create_engine(
            f"sqlite+pysqlite:///{settings.database_path}",
            connect_args={"check_same_thread": False, "timeout": 5.0},
        )
        self.migrate()

    def _prepare_data_dir(self) -> None:
        try:
            self.settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        except FileExistsError:
            pass
        except OSError as error:
            raise RuntimeError("data directory cannot be created safely") from error
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.settings.data_dir, flags)
        except OSError as error:
            raise RuntimeError("data directory cannot be opened safely") from error
        try:
            directory = os.fstat(descriptor)
            if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid():
                raise RuntimeError("data directory ownership is invalid")
            os.fchmod(descriptor, 0o700)
        except OSError as error:
            raise RuntimeError("data directory permissions cannot be set safely") from error
        finally:
            os.close(descriptor)

    def migrate(self) -> None:
        metadata.create_all(self.engine)
        now = datetime.now(UTC).timestamp()
        with self.engine.begin() as connection:
            existing_columns = {
                row[1] for row in connection.exec_driver_sql("PRAGMA table_info(setup_state)")
            }
            migrations = {
                "setup_epoch": "INTEGER NOT NULL DEFAULT 1",
                "provider_credential_ciphertext": "TEXT",
                "provider_credential_key_version": "VARCHAR(80)",
                "owner_password_hash": "VARCHAR(128)",
                "owner_password_salt": "VARCHAR(64)",
                "owner_session_epoch": "INTEGER NOT NULL DEFAULT 0",
                "owner_failed_attempts": "INTEGER NOT NULL DEFAULT 0",
                "owner_locked_until": "FLOAT",
            }
            for column, definition in migrations.items():
                if column not in existing_columns:
                    connection.exec_driver_sql(
                        f"ALTER TABLE setup_state ADD COLUMN {column} {definition}"
                    )
            exists = connection.execute(
                select(setup_state.c.id).where(setup_state.c.id == _STATE_ID)
            ).first()
            if exists is None:
                connection.execute(
                    insert(setup_state).values(
                        id=_STATE_ID,
                        stage="bootstrap_required",
                        bootstrap_failed_attempts=0,
                        setup_epoch=1,
                        owner_session_epoch=0,
                        owner_failed_attempts=0,
                        send_sql_text=False,
                        updated_at=now,
                    )
                )
        self.settings.database_path.chmod(0o600)

    def snapshot(self) -> SetupSnapshot:
        with self.engine.connect() as connection:
            row = (
                connection.execute(select(setup_state).where(setup_state.c.id == _STATE_ID))
                .mappings()
                .one()
            )
        hosts = tuple(json.loads(row["allowed_provider_hosts"] or "[]"))
        credential = None
        if row["provider_credential_ciphertext"] and row["provider_credential_key_version"]:
            credential = EncryptedCredential(
                ciphertext=row["provider_credential_ciphertext"],
                key_version=row["provider_credential_key_version"],
            )
        return SetupSnapshot(
            stage=row["stage"],
            initialized=row["finalized_at"] is not None,
            external_model_egress=row["external_model_egress"],
            allowed_provider_hosts=hosts,
            policy_committed_at=row["policy_committed_at"],
            provider_status=row["provider_status"],
            provider_base_url=row["provider_base_url"],
            provider_model=row["provider_model"],
            provider_verified_at=row["provider_verified_at"],
            provider_credential=credential,
            model_mode=row["model_mode"],
            bootstrap_persisted=row["bootstrap_hash"] is not None,
            bootstrap_expires_at=row["bootstrap_expires_at"],
            bootstrap_consumed_at=row["bootstrap_consumed_at"],
            bootstrap_failed_attempts=row["bootstrap_failed_attempts"],
            setup_epoch=row["setup_epoch"],
            owner_configured=row["owner_password_hash"] is not None,
            owner_session_epoch=row["owner_session_epoch"],
            owner_failed_attempts=row["owner_failed_attempts"],
            owner_locked_until=row["owner_locked_until"],
        )

    def is_ready(self) -> bool:
        return self.snapshot().initialized

    def issue_bootstrap_code(self, now: datetime, *, code: str | None = None) -> str:
        normalized = normalize_bootstrap_code(code or "")
        if code is None:
            normalized = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(16))
        if len(normalized) < 12:
            raise ValueError("bootstrap code must contain at least 12 valid characters")
        if not self.reissue_bootstrap_code(normalized, now):
            raise RuntimeError("setup is already finalized")
        return format_bootstrap_code(normalized)

    def ingest_bootstrap_code(self, code: str, now: datetime) -> bool:
        normalized = normalize_bootstrap_code(code)
        if len(normalized) < 12:
            raise ValueError("bootstrap code must contain at least 12 valid characters")
        salt = secrets.token_bytes(16)
        now_value = _timestamp(now)
        with self.engine.begin() as connection:
            result = connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.bootstrap_hash.is_(None),
                    setup_state.c.finalized_at.is_(None),
                )
                .values(
                    stage="bootstrap_required",
                    bootstrap_hash=_derive_code_hash(normalized, salt),
                    bootstrap_salt=_b64(salt),
                    bootstrap_expires_at=now_value + self.settings.bootstrap_ttl_seconds,
                    bootstrap_consumed_at=None,
                    bootstrap_failed_attempts=0,
                    updated_at=now_value,
                )
            )
        return result.rowcount == 1

    def reissue_bootstrap_code(self, code: str, now: datetime) -> bool:
        normalized = normalize_bootstrap_code(code)
        if len(normalized) < 12:
            raise ValueError("bootstrap code must contain at least 12 valid characters")
        salt = secrets.token_bytes(16)
        now_value = _timestamp(now)
        with self.engine.begin() as connection:
            result = connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.finalized_at.is_(None),
                )
                .values(
                    stage="bootstrap_required",
                    bootstrap_hash=_derive_code_hash(normalized, salt),
                    bootstrap_salt=_b64(salt),
                    bootstrap_expires_at=now_value + self.settings.bootstrap_ttl_seconds,
                    bootstrap_consumed_at=None,
                    bootstrap_failed_attempts=0,
                    setup_epoch=setup_state.c.setup_epoch + 1,
                    external_model_egress=None,
                    allowed_provider_hosts=None,
                    send_sql_text=False,
                    policy_committed_at=None,
                    provider_status=None,
                    provider_base_url=None,
                    provider_model=None,
                    provider_verified_at=None,
                    provider_credential_ciphertext=None,
                    provider_credential_key_version=None,
                    model_mode=None,
                    owner_password_hash=None,
                    owner_password_salt=None,
                    owner_session_epoch=setup_state.c.owner_session_epoch + 1,
                    owner_failed_attempts=0,
                    owner_locked_until=None,
                    updated_at=now_value,
                )
            )
        return result.rowcount == 1

    def consume_bootstrap_code(self, code: str, now: datetime) -> int | None:
        now_value = _timestamp(now)
        with self.engine.connect() as connection:
            row = (
                connection.execute(select(setup_state).where(setup_state.c.id == _STATE_ID))
                .mappings()
                .one()
            )
        salt_value = row["bootstrap_salt"]
        expected_hash = row["bootstrap_hash"]
        if salt_value is None or expected_hash is None:
            return None
        if (
            row["stage"] != "bootstrap_required"
            or row["bootstrap_consumed_at"] is not None
            or row["bootstrap_expires_at"] is None
            or row["bootstrap_expires_at"] < now_value
            or row["bootstrap_failed_attempts"] >= self.settings.bootstrap_max_attempts
        ):
            return None
        candidate_hash = _derive_code_hash(code, _decode_b64(salt_value))
        eligible = hmac.compare_digest(candidate_hash, expected_hash)
        if eligible:
            with self.engine.begin() as connection:
                result = connection.execute(
                    update(setup_state)
                    .where(
                        setup_state.c.id == _STATE_ID,
                        setup_state.c.stage == "bootstrap_required",
                        setup_state.c.bootstrap_hash == expected_hash,
                        setup_state.c.bootstrap_salt == salt_value,
                        setup_state.c.setup_epoch == row["setup_epoch"],
                        setup_state.c.bootstrap_consumed_at.is_(None),
                        setup_state.c.bootstrap_expires_at >= now_value,
                        setup_state.c.bootstrap_failed_attempts
                        < self.settings.bootstrap_max_attempts,
                    )
                    .values(
                        bootstrap_consumed_at=now_value,
                        stage="security_policy_required",
                        updated_at=now_value,
                    )
                )
            return row["setup_epoch"] if result.rowcount == 1 else None
        if row["bootstrap_consumed_at"] is None and row["bootstrap_expires_at"] >= now_value:
            with self.engine.begin() as connection:
                connection.execute(
                    update(setup_state)
                    .where(
                        setup_state.c.id == _STATE_ID,
                        setup_state.c.stage == "bootstrap_required",
                        setup_state.c.bootstrap_hash == expected_hash,
                        setup_state.c.bootstrap_salt == salt_value,
                        setup_state.c.setup_epoch == row["setup_epoch"],
                        setup_state.c.bootstrap_consumed_at.is_(None),
                        setup_state.c.bootstrap_failed_attempts
                        == row["bootstrap_failed_attempts"],
                    )
                    .values(
                        bootstrap_failed_attempts=setup_state.c.bootstrap_failed_attempts + 1,
                        updated_at=now_value,
                    )
                )
        return None

    def save_policy(
        self,
        *,
        external_model_egress: bool,
        allowed_provider_hosts: list[str],
        send_sql_text: bool,
        now: datetime,
    ) -> None:
        snapshot = self.snapshot()
        if snapshot.stage != "security_policy_required" or snapshot.initialized:
            raise RuntimeError("security policy is not valid in the current setup stage")
        now_value = _timestamp(now)
        with self.engine.begin() as connection:
            result = connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.stage == "security_policy_required",
                    setup_state.c.setup_epoch == snapshot.setup_epoch,
                    setup_state.c.finalized_at.is_(None),
                )
                .values(
                    stage="model_required",
                    external_model_egress=external_model_egress,
                    allowed_provider_hosts=json.dumps(sorted(set(allowed_provider_hosts))),
                    send_sql_text=send_sql_text,
                    policy_committed_at=now_value,
                    provider_status=None,
                    provider_base_url=None,
                    provider_model=None,
                    provider_verified_at=None,
                    updated_at=now_value,
                )
            )
        if result.rowcount != 1:
            raise RuntimeError("security policy state changed concurrently")

    def save_provider_probe(
        self,
        request: ProviderProbeRequest,
        result: ProviderProbeResult,
        credential: EncryptedCredential,
        now: datetime,
    ) -> None:
        if result.status != "verified":
            return
        snapshot = self.snapshot()
        if snapshot.stage != "model_required" or snapshot.initialized:
            raise RuntimeError("provider probe is not valid in the current setup stage")
        with self.engine.begin() as connection:
            write_result = connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.stage == "model_required",
                    setup_state.c.setup_epoch == snapshot.setup_epoch,
                    setup_state.c.finalized_at.is_(None),
                    setup_state.c.policy_committed_at == snapshot.policy_committed_at,
                )
                .values(
                    provider_status=result.status,
                    provider_base_url=request.base_url,
                    provider_model=request.model,
                    provider_verified_at=_timestamp(now),
                    provider_credential_ciphertext=credential.ciphertext,
                    provider_credential_key_version=credential.key_version,
                    updated_at=_timestamp(now),
                )
            )
        if write_result.rowcount != 1:
            raise RuntimeError("provider state changed concurrently")

    def finalize(
        self,
        mode: Literal["external", "rules"],
        owner_password: str,
        now: datetime,
    ) -> tuple[int, int]:
        snapshot = self.snapshot()
        if snapshot.stage != "model_required" or snapshot.initialized:
            raise RuntimeError("finalize is not valid in the current setup stage")
        if snapshot.policy_committed_at is None:
            raise RuntimeError("security policy is required")
        if mode == "external" and (
            snapshot.provider_status != "verified" or snapshot.provider_credential is None
        ):
            raise RuntimeError("a verified external provider is required")
        owner_salt = secrets.token_bytes(16)
        owner_hash = _derive_password_hash(owner_password, owner_salt)
        now_value = _timestamp(now)
        with self.engine.begin() as connection:
            result = connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.stage == "model_required",
                    setup_state.c.setup_epoch == snapshot.setup_epoch,
                    setup_state.c.finalized_at.is_(None),
                    setup_state.c.policy_committed_at == snapshot.policy_committed_at,
                    setup_state.c.provider_status == snapshot.provider_status,
                )
                .values(
                    stage="ready",
                    model_mode=mode,
                    provider_status=(snapshot.provider_status if mode == "external" else None),
                    provider_base_url=(
                        snapshot.provider_base_url if mode == "external" else None
                    ),
                    provider_model=(snapshot.provider_model if mode == "external" else None),
                    provider_verified_at=(
                        snapshot.provider_verified_at if mode == "external" else None
                    ),
                    provider_credential_ciphertext=(
                        snapshot.provider_credential.ciphertext
                        if mode == "external" and snapshot.provider_credential is not None
                        else None
                    ),
                    provider_credential_key_version=(
                        snapshot.provider_credential.key_version
                        if mode == "external" and snapshot.provider_credential is not None
                        else None
                    ),
                    owner_password_hash=owner_hash,
                    owner_password_salt=_b64(owner_salt),
                    owner_session_epoch=setup_state.c.owner_session_epoch + 1,
                    owner_failed_attempts=0,
                    owner_locked_until=None,
                    finalized_at=now_value,
                    updated_at=now_value,
                )
            )
        if result.rowcount != 1:
            raise RuntimeError("finalize state changed concurrently")
        finalized = self.snapshot()
        return finalized.setup_epoch, finalized.owner_session_epoch

    def authenticate_owner(self, password: str, now: datetime) -> OwnerAuthentication:
        now_value = _timestamp(now)
        with self.engine.connect() as connection:
            row = (
                connection.execute(select(setup_state).where(setup_state.c.id == _STATE_ID))
                .mappings()
                .one()
            )
        if row["finalized_at"] is None or not row["owner_password_hash"]:
            return OwnerAuthentication("invalid")
        if row["owner_locked_until"] is not None and row["owner_locked_until"] > now_value:
            return OwnerAuthentication("limited")
        candidate = _derive_password_hash(password, _decode_b64(row["owner_password_salt"]))
        if hmac.compare_digest(candidate, row["owner_password_hash"]):
            with self.engine.begin() as connection:
                result = connection.execute(
                    update(setup_state)
                    .where(
                        setup_state.c.id == _STATE_ID,
                        setup_state.c.setup_epoch == row["setup_epoch"],
                        setup_state.c.owner_session_epoch == row["owner_session_epoch"],
                        setup_state.c.owner_password_hash == row["owner_password_hash"],
                        setup_state.c.finalized_at.is_not(None),
                    )
                    .values(owner_failed_attempts=0, owner_locked_until=None, updated_at=now_value)
                )
            if result.rowcount == 1:
                return OwnerAuthentication(
                    "authenticated",
                    setup_epoch=row["setup_epoch"],
                    session_epoch=row["owner_session_epoch"],
                )
            return OwnerAuthentication("invalid")

        failed_attempts = case(
            (
                setup_state.c.owner_locked_until.is_not(None)
                & (setup_state.c.owner_locked_until <= now_value),
                1,
            ),
            else_=setup_state.c.owner_failed_attempts + 1,
        )
        locked_until = case(
            (
                failed_attempts >= self.settings.owner_login_max_attempts,
                now_value + self.settings.owner_login_lock_seconds,
            ),
            else_=None,
        )
        with self.engine.begin() as connection:
            connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.setup_epoch == row["setup_epoch"],
                    setup_state.c.owner_session_epoch == row["owner_session_epoch"],
                    setup_state.c.owner_password_hash == row["owner_password_hash"],
                    setup_state.c.finalized_at.is_not(None),
                )
                .values(
                    owner_failed_attempts=failed_attempts,
                    owner_locked_until=locked_until,
                    updated_at=now_value,
                )
            )
        return OwnerAuthentication("invalid")

    def revoke_owner_sessions(self, *, setup_epoch: int, session_epoch: int, now: datetime) -> bool:
        with self.engine.begin() as connection:
            result = connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.setup_epoch == setup_epoch,
                    setup_state.c.owner_session_epoch == session_epoch,
                    setup_state.c.finalized_at.is_not(None),
                )
                .values(
                    owner_session_epoch=setup_state.c.owner_session_epoch + 1,
                    updated_at=_timestamp(now),
                )
            )
        return result.rowcount == 1

    def replace_provider_credential(
        self,
        request: ProviderProbeRequest,
        result: ProviderProbeResult,
        credential: EncryptedCredential,
        *,
        expected_credential: EncryptedCredential | None,
        expected_setup_epoch: int,
        now: datetime,
    ) -> bool:
        with self.engine.begin() as connection:
            write_result = connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.setup_epoch == expected_setup_epoch,
                    setup_state.c.finalized_at.is_not(None),
                    setup_state.c.external_model_egress.is_(True),
                    (
                        setup_state.c.provider_credential_ciphertext.is_(None)
                        if expected_credential is None
                        else setup_state.c.provider_credential_ciphertext
                        == expected_credential.ciphertext
                    ),
                    (
                        setup_state.c.provider_credential_key_version.is_(None)
                        if expected_credential is None
                        else setup_state.c.provider_credential_key_version
                        == expected_credential.key_version
                    ),
                )
                .values(
                    provider_status=result.status,
                    provider_base_url=request.base_url,
                    provider_model=request.model,
                    provider_verified_at=_timestamp(now),
                    provider_credential_ciphertext=credential.ciphertext,
                    provider_credential_key_version=credential.key_version,
                    model_mode="external",
                    updated_at=_timestamp(now),
                )
            )
        return write_result.rowcount == 1

    def delete_provider_credential(
        self,
        *,
        expected_credential: EncryptedCredential | None,
        expected_setup_epoch: int,
        now: datetime,
    ) -> bool:
        with self.engine.begin() as connection:
            result = connection.execute(
                update(setup_state)
                .where(
                    setup_state.c.id == _STATE_ID,
                    setup_state.c.setup_epoch == expected_setup_epoch,
                    setup_state.c.finalized_at.is_not(None),
                    (
                        setup_state.c.provider_credential_ciphertext.is_(None)
                        if expected_credential is None
                        else setup_state.c.provider_credential_ciphertext
                        == expected_credential.ciphertext
                    ),
                    (
                        setup_state.c.provider_credential_key_version.is_(None)
                        if expected_credential is None
                        else setup_state.c.provider_credential_key_version
                        == expected_credential.key_version
                    ),
                )
                .values(
                    provider_status=None,
                    provider_base_url=None,
                    provider_model=None,
                    provider_verified_at=None,
                    provider_credential_ciphertext=None,
                    provider_credential_key_version=None,
                    model_mode="rules",
                    updated_at=_timestamp(now),
                )
            )
        return result.rowcount == 1


class SetupSessionSigner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.key = self._load_or_create_key(settings.session_key_path)

    @staticmethod
    def _load_or_create_key(path: Path) -> bytes:
        directory = path.parent.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise RuntimeError("setup session key directory permissions are invalid")
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            try:
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except OSError as error:
                raise RuntimeError("setup session key cannot be opened safely") from error
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise RuntimeError("setup session key permissions are invalid")
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    key = handle.read(33)
            finally:
                os.close(descriptor)
        else:
            key = secrets.token_bytes(32)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(key)
            except OSError as error:
                with suppress(OSError):
                    os.close(descriptor)
                with suppress(OSError):
                    path.unlink()
                raise RuntimeError("setup session key cannot be written safely") from error
        if len(key) != 32:
            raise RuntimeError("setup session key has an invalid length")
        return key

    def issue(self, now: datetime, *, epoch: int) -> tuple[str, str]:
        token = _b64(secrets.token_bytes(32))
        expires_at = int(_timestamp(now)) + self.settings.setup_session_ttl_seconds
        payload = f"{token}.{expires_at}.{epoch}"
        signature = _b64(hmac.digest(self.key, payload.encode("ascii"), "sha256"))
        cookie = f"{payload}.{signature}"
        return cookie, self.csrf_for(token)

    def verify(self, cookie: str, now: datetime, *, expected_epoch: int) -> str | None:
        try:
            token, expires_text, epoch_text, supplied_signature = cookie.split(".", maxsplit=3)
            expires_at = int(expires_text)
            epoch = int(epoch_text)
        except (TypeError, ValueError):
            return None
        payload = f"{token}.{expires_at}.{epoch}"
        expected = _b64(hmac.digest(self.key, payload.encode("ascii"), "sha256"))
        if (
            epoch != expected_epoch
            or expires_at < int(_timestamp(now))
            or not hmac.compare_digest(supplied_signature, expected)
        ):
            return None
        return token

    def csrf_for(self, token: str) -> str:
        return _b64(hmac.digest(self.key, f"csrf:{token}".encode("ascii"), "sha256"))

    def verify_csrf(self, token: str, supplied: str | None) -> bool:
        return supplied is not None and hmac.compare_digest(self.csrf_for(token), supplied)

    def issue_owner(
        self,
        now: datetime,
        *,
        setup_epoch: int,
        session_epoch: int,
    ) -> tuple[str, str]:
        token = _b64(secrets.token_bytes(32))
        expires_at = int(_timestamp(now)) + self.settings.owner_session_ttl_seconds
        payload = f"owner.{token}.{expires_at}.{setup_epoch}.{session_epoch}"
        signature = _b64(hmac.digest(self.key, payload.encode("ascii"), "sha256"))
        return f"{payload}.{signature}", self.csrf_for(token)

    def verify_owner(
        self,
        cookie: str,
        now: datetime,
        *,
        expected_setup_epoch: int,
        expected_session_epoch: int,
    ) -> str | None:
        try:
            purpose, token, expires_text, setup_text, session_text, supplied_signature = (
                cookie.split(".", maxsplit=5)
            )
            expires_at = int(expires_text)
            setup_epoch = int(setup_text)
            session_epoch = int(session_text)
        except (TypeError, ValueError):
            return None
        payload = f"{purpose}.{token}.{expires_at}.{setup_epoch}.{session_epoch}"
        expected = _b64(hmac.digest(self.key, payload.encode("ascii"), "sha256"))
        if (
            purpose != "owner"
            or setup_epoch != expected_setup_epoch
            or session_epoch != expected_session_epoch
            or expires_at < int(_timestamp(now))
            or not hmac.compare_digest(supplied_signature, expected)
        ):
            return None
        return token


def migrate(settings: Settings) -> Engine:
    return SetupStore(settings).engine
