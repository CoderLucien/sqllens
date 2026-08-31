from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
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
    create_engine,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine

from sqllens_api.config import Settings
from sqllens_api.provider import ProviderProbeRequest, ProviderProbeResult

SETUP_COOKIE_NAME = "sqllens_setup_session"
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
    Column("external_model_egress", Boolean),
    Column("allowed_provider_hosts", Text),
    Column("send_sql_text", Boolean, nullable=False, default=False),
    Column("policy_committed_at", Float),
    Column("provider_status", String(30)),
    Column("provider_base_url", Text),
    Column("provider_model", String(200)),
    Column("provider_verified_at", Float),
    Column("model_mode", String(30)),
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
    model_mode: str | None
    bootstrap_persisted: bool


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
        self.settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.settings.data_dir.chmod(0o700)

    def migrate(self) -> None:
        metadata.create_all(self.engine)
        now = datetime.now(UTC).timestamp()
        with self.engine.begin() as connection:
            exists = connection.execute(
                select(setup_state.c.id).where(setup_state.c.id == _STATE_ID)
            ).first()
            if exists is None:
                connection.execute(
                    insert(setup_state).values(
                        id=_STATE_ID,
                        stage="bootstrap_required",
                        bootstrap_failed_attempts=0,
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
            model_mode=row["model_mode"],
            bootstrap_persisted=row["bootstrap_hash"] is not None,
        )

    def is_ready(self) -> bool:
        return self.snapshot().initialized

    def issue_bootstrap_code(self, now: datetime, *, code: str | None = None) -> str:
        snapshot = self.snapshot()
        if snapshot.initialized:
            raise RuntimeError("setup is already finalized")
        normalized = normalize_bootstrap_code(code or "")
        if code is None:
            normalized = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(16))
        if len(normalized) < 12:
            raise ValueError("bootstrap code must contain at least 12 valid characters")
        salt = secrets.token_bytes(16)
        now_value = _timestamp(now)
        with self.engine.begin() as connection:
            connection.execute(
                update(setup_state)
                .where(setup_state.c.id == _STATE_ID)
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

    def consume_bootstrap_code(self, code: str, now: datetime) -> bool:
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
            return False
        candidate_hash = _derive_code_hash(code, _decode_b64(salt_value))
        eligible = (
            row["bootstrap_consumed_at"] is None
            and row["bootstrap_expires_at"] is not None
            and row["bootstrap_expires_at"] >= now_value
            and row["bootstrap_failed_attempts"] < self.settings.bootstrap_max_attempts
            and hmac.compare_digest(candidate_hash, expected_hash)
        )
        if eligible:
            with self.engine.begin() as connection:
                result = connection.execute(
                    update(setup_state)
                    .where(
                        setup_state.c.id == _STATE_ID,
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
            return result.rowcount == 1
        if row["bootstrap_consumed_at"] is None and row["bootstrap_expires_at"] >= now_value:
            with self.engine.begin() as connection:
                connection.execute(
                    update(setup_state)
                    .where(setup_state.c.id == _STATE_ID)
                    .values(
                        bootstrap_failed_attempts=setup_state.c.bootstrap_failed_attempts + 1,
                        updated_at=now_value,
                    )
                )
        return False

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
            connection.execute(
                update(setup_state)
                .where(setup_state.c.id == _STATE_ID)
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

    def save_provider_probe(
        self,
        request: ProviderProbeRequest,
        result: ProviderProbeResult,
        now: datetime,
    ) -> None:
        if result.status != "verified":
            return
        snapshot = self.snapshot()
        if snapshot.stage != "model_required" or snapshot.initialized:
            raise RuntimeError("provider probe is not valid in the current setup stage")
        with self.engine.begin() as connection:
            connection.execute(
                update(setup_state)
                .where(setup_state.c.id == _STATE_ID)
                .values(
                    provider_status=result.status,
                    provider_base_url=request.base_url,
                    provider_model=request.model,
                    provider_verified_at=_timestamp(now),
                    updated_at=_timestamp(now),
                )
            )

    def finalize(self, mode: Literal["external", "rules"], now: datetime) -> None:
        snapshot = self.snapshot()
        if snapshot.stage != "model_required" or snapshot.initialized:
            raise RuntimeError("finalize is not valid in the current setup stage")
        if snapshot.policy_committed_at is None:
            raise RuntimeError("security policy is required")
        if mode == "external" and snapshot.provider_status != "verified":
            raise RuntimeError("a verified external provider is required")
        now_value = _timestamp(now)
        with self.engine.begin() as connection:
            connection.execute(
                update(setup_state)
                .where(setup_state.c.id == _STATE_ID)
                .values(
                    stage="ready",
                    model_mode=mode,
                    finalized_at=now_value,
                    updated_at=now_value,
                )
            )


class SetupSessionSigner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.key = self._load_or_create_key(settings.session_key_path)

    @staticmethod
    def _load_or_create_key(path: Path) -> bytes:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key = path.read_bytes()
        else:
            key = secrets.token_bytes(32)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(key)
        path.chmod(0o600)
        if len(key) != 32:
            raise RuntimeError("setup session key has an invalid length")
        return key

    def issue(self, now: datetime) -> tuple[str, str]:
        token = _b64(secrets.token_bytes(32))
        expires_at = int(_timestamp(now)) + self.settings.setup_session_ttl_seconds
        payload = f"{token}.{expires_at}"
        signature = _b64(hmac.digest(self.key, payload.encode("ascii"), "sha256"))
        cookie = f"{payload}.{signature}"
        return cookie, self.csrf_for(token)

    def verify(self, cookie: str, now: datetime) -> str | None:
        try:
            token, expires_text, supplied_signature = cookie.split(".", maxsplit=2)
            expires_at = int(expires_text)
        except (TypeError, ValueError):
            return None
        payload = f"{token}.{expires_at}"
        expected = _b64(hmac.digest(self.key, payload.encode("ascii"), "sha256"))
        if expires_at < int(_timestamp(now)) or not hmac.compare_digest(
            supplied_signature, expected
        ):
            return None
        return token

    def csrf_for(self, token: str) -> str:
        return _b64(hmac.digest(self.key, f"csrf:{token}".encode("ascii"), "sha256"))

    def verify_csrf(self, token: str, supplied: str | None) -> bool:
        return supplied is not None and hmac.compare_digest(self.csrf_for(token), supplied)


def migrate(settings: Settings) -> Engine:
    return SetupStore(settings).engine
