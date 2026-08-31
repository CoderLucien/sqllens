from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ASSOCIATED_DATA = b"sqllens/provider-credential/v1"
_FORMAT_PREFIX = "aesgcm-v1:"
_VERSIONED_KEY_PATTERN = re.compile(
    r"^file-v1:(?P<identifier>[0-9a-f]{32}):(?P<digest>[0-9a-f]{32})$"
)


class CredentialUnavailableError(RuntimeError):
    pass


class _KeyAlreadyExistsError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EncryptedCredential:
    ciphertext: str
    key_version: str


class CredentialVault:
    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path

    def encrypt(self, plaintext: str) -> EncryptedCredential:
        key = self._load_base_key(create=True)
        return self._encrypt_with_key(plaintext, key, self._base_key_version(key))

    def rotate(
        self,
        plaintext: str,
        *,
        previous: EncryptedCredential | None,
    ) -> EncryptedCredential:
        """Create a new versioned key without invalidating the current DB reference."""
        self._ensure_directory(create=True)
        previous_path = (
            self._path_for_version(previous.key_version)[0]
            if previous is not None
            else self.key_path
        )
        self._validate_rotation_source(previous_path)

        for _attempt in range(4):
            identifier = secrets.token_hex(16)
            rotated_path = self._versioned_path(identifier)
            try:
                key = self._create_key_file(rotated_path)
            except _KeyAlreadyExistsError:
                continue
            version = self._versioned_key_version(identifier, key)
            try:
                return self._encrypt_with_key(plaintext, key, version)
            except Exception:
                self._discard_path(rotated_path)
                raise
        raise CredentialUnavailableError("credential key rotation could not be allocated safely")

    def discard_rotation(self, encrypted: EncryptedCredential) -> None:
        match = _VERSIONED_KEY_PATTERN.fullmatch(encrypted.key_version)
        if match is None:
            return
        self._discard_path(self._versioned_path(match.group("identifier")))

    def retire(self, encrypted: EncryptedCredential | None) -> None:
        if encrypted is None:
            return
        try:
            path, _version = self._path_for_version(encrypted.key_version)
        except CredentialUnavailableError:
            return
        self._discard_path(path)

    def decrypt(self, encrypted: EncryptedCredential) -> str:
        key_path, expected_version = self._path_for_version(encrypted.key_version)
        key = self._read_key(key_path)
        version_match = _VERSIONED_KEY_PATTERN.fullmatch(expected_version)
        actual_version = (
            self._base_key_version(key)
            if version_match is None
            else self._versioned_key_version(version_match.group("identifier"), key)
        )
        if expected_version != actual_version:
            raise CredentialUnavailableError("credential key version does not match")
        if not encrypted.ciphertext.startswith(_FORMAT_PREFIX):
            raise CredentialUnavailableError("credential ciphertext format is unsupported")
        try:
            payload = base64.urlsafe_b64decode(
                encrypted.ciphertext.removeprefix(_FORMAT_PREFIX).encode("ascii")
            )
        except (ValueError, UnicodeEncodeError) as error:
            raise CredentialUnavailableError("credential ciphertext is invalid") from error
        if len(payload) < 29:
            raise CredentialUnavailableError("credential ciphertext is invalid")
        try:
            plaintext = AESGCM(key).decrypt(payload[:12], payload[12:], _ASSOCIATED_DATA)
            return plaintext.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as error:
            raise CredentialUnavailableError("credential cannot be decrypted") from error

    @staticmethod
    def _encrypt_with_key(
        plaintext: str,
        key: bytes,
        key_version: str,
    ) -> EncryptedCredential:
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _ASSOCIATED_DATA)
        payload = base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")
        return EncryptedCredential(
            ciphertext=f"{_FORMAT_PREFIX}{payload}",
            key_version=key_version,
        )

    def _load_base_key(self, *, create: bool) -> bytes:
        self._ensure_directory(create=create)
        if create:
            try:
                return self._create_key_file(self.key_path)
            except _KeyAlreadyExistsError:
                pass
        return self._read_key(self.key_path)

    def _ensure_directory(self, *, create: bool) -> None:
        directory = self.key_path.parent
        if create:
            try:
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError as error:
                raise CredentialUnavailableError(
                    "credential directory cannot be created safely"
                ) from error
        self._validate_path(directory, expected_mode=0o700, directory=True)

    def _create_key_file(self, path: Path) -> bytes:
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError as error:
            raise _KeyAlreadyExistsError from error
        except OSError as error:
            raise CredentialUnavailableError(
                "credential key cannot be created safely"
            ) from error

        key = secrets.token_bytes(32)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            with suppress(OSError):
                os.close(descriptor)
            self._discard_path(path)
            raise CredentialUnavailableError(
                "credential key cannot be written safely"
            ) from error
        return key

    def _read_key(self, path: Path) -> bytes:
        self._ensure_directory(create=False)
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError as error:
            raise CredentialUnavailableError("credential key is unavailable") from error
        except OSError as error:
            raise CredentialUnavailableError("credential key cannot be opened safely") from error
        try:
            with os.fdopen(descriptor, "rb") as handle:
                metadata = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise CredentialUnavailableError("credential key permissions are invalid")
                key = handle.read(33)
        except CredentialUnavailableError:
            raise
        except OSError as error:
            raise CredentialUnavailableError("credential key cannot be read safely") from error
        if len(key) != 32:
            raise CredentialUnavailableError("credential key has an invalid length")
        return key

    def _path_for_version(self, version: str) -> tuple[Path, str]:
        if re.fullmatch(r"sha256:[0-9a-f]{32}", version):
            return self.key_path, version
        match = _VERSIONED_KEY_PATTERN.fullmatch(version)
        if match is None:
            raise CredentialUnavailableError("credential key version is unsupported")
        return self._versioned_path(match.group("identifier")), version

    def _versioned_path(self, identifier: str) -> Path:
        return self.key_path.with_name(
            f"{self.key_path.stem}.file-v1-{identifier}{self.key_path.suffix}"
        )

    @staticmethod
    def _validate_rotation_source(path: Path) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise CredentialUnavailableError(
                "previous credential key cannot be inspected safely"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise CredentialUnavailableError("previous credential key is unsafe")

    @staticmethod
    def _discard_path(path: Path) -> None:
        try:
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid():
                path.unlink()
        except FileNotFoundError:
            return
        except OSError:
            return

    @staticmethod
    def _validate_path(path: Path, *, expected_mode: int, directory: bool) -> None:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise CredentialUnavailableError("credential directory is unavailable") from error
        correct_type = (
            stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
        )
        if (
            not correct_type
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != expected_mode
        ):
            raise CredentialUnavailableError("credential path permissions are invalid")

    @staticmethod
    def _base_key_version(key: bytes) -> str:
        return f"sha256:{hashlib.sha256(key).hexdigest()[:32]}"

    @staticmethod
    def _versioned_key_version(identifier: str, key: bytes) -> str:
        digest = hashlib.sha256(key).hexdigest()[:32]
        return f"file-v1:{identifier}:{digest}"
