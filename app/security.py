"""Cryptographic primitives: argon2id hashing (passwords, API keys, verification codes), Fernet encryption of stored
workspace secrets, and random tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from .config import APP_SECRET_KEY

_hasher = PasswordHasher()  # argon2id with the library's recommended parameters
_DUMMY_HASH = _hasher.hash("timing-equaliser")
ENC_PREFIX = "enc:v1:"
API_KEY_PREFIX = "sntl"


# ---------------------------------------------------------------------- argon2
def hash_secret(value: str) -> str:
    return _hasher.hash(value)


def verify_secret(stored_hash: str | None, value: str) -> bool:
    """Constant-ish time: a missing hash still costs one argon2 verification."""
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, value) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# ---------------------------------------------------------------------- tokens
def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_digest(token: str) -> str:
    """Session tokens are high-entropy, so a fast digest is enough for lookup."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def new_api_key() -> tuple[str, str]:
    """Return (full key, lookup prefix). Format: ``sntl_<prefix>_<secret>``."""
    prefix = secrets.token_hex(6)
    return f"{API_KEY_PREFIX}_{prefix}_{secrets.token_urlsafe(32)}", prefix


def parse_api_key(key: str) -> str | None:
    """Lookup prefix of a well-formed key, else None."""
    parts = (key or "").split("_", 2)
    if len(parts) != 3 or parts[0] != API_KEY_PREFIX or len(parts[1]) != 12 or len(parts[2]) < 32:
        return None
    return parts[1]


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------- encryption at rest
def _fernet() -> Fernet:
    if not APP_SECRET_KEY:
        raise RuntimeError("APP_SECRET_KEY is not set - it is required to encrypt stored workspace secrets")
    key = base64.urlsafe_b64encode(hashlib.sha256(APP_SECRET_KEY.encode()).digest())
    return Fernet(key)


def encrypt(value: str) -> str:
    return ENC_PREFIX + _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    if not value or not value.startswith(ENC_PREFIX):
        return value or ""
    try:
        return _fernet().decrypt(value[len(ENC_PREFIX):].encode()).decode()
    except InvalidToken:
        return ""
