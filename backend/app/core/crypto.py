"""Symmetric encryption for secrets stored at rest (LDAP bind passwords,
OIDC client secrets, SAML private keys).

Uses Fernet (AES-128-CBC + HMAC-SHA256). The key is derived from
``settings.credential_encryption_key`` when provided, otherwise from
``settings.secret_key`` via SHA-256. Changing either without first
re-encrypting existing rows will render stored secrets unreadable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime
from functools import lru_cache

import structlog
from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

logger = structlog.get_logger(__name__)


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    raw = settings.credential_encryption_key.strip()
    if raw:
        try:
            return Fernet(raw.encode())
        except Exception as exc:  # noqa: BLE001 — Fernet raises bare ValueError/binascii
            # Explicit key is malformed. Falling through to the derived key
            # would encrypt with a DIFFERENT key than the operator intended,
            # silently orphaning every secret written with the (broken) key.
            # So it is a hard error (#1222), unless the operator opted into
            # ALLOW_INSECURE_SECRET_KEY for local development.
            msg = (
                "CREDENTIAL_ENCRYPTION_KEY is set but not a valid Fernet key "
                f"({exc!r}). Generate one with `Fernet.generate_key()`."
            )
            if not settings.allow_insecure_secret_key:
                raise ValueError(msg) from exc
            logger.error("credential_encryption_key_invalid", error=str(exc))
            print(f"WARNING: {msg} Falling back to a SECRET_KEY-derived key.", file=sys.stderr)
    else:
        # No explicit key — secrets are encrypted with a key DERIVED from
        # SECRET_KEY. That couples the two: rotating SECRET_KEY without
        # re-encrypting rows makes every stored LDAP/OIDC/SAML secret +
        # backup-target credential unreadable. Note it once at startup.
        if "pytest" not in sys.modules:
            logger.info("credential_encryption_key_derived_from_secret_key")
    digest = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_str(plaintext: str) -> bytes:
    return _fernet().encrypt(plaintext.encode())


def encrypted_at(token: bytes) -> datetime:
    """When ``token`` was encrypted. A Fernet token carries its own creation
    time (verified with the signature), so a caller can tell how old a value
    is without a column for it. ``ValueError`` if the token is not ours."""
    try:
        return datetime.fromtimestamp(_fernet().extract_timestamp(token), UTC)
    except InvalidToken as exc:
        raise ValueError("encrypted value could not be verified") from exc


def decrypt_str(token: bytes) -> str:
    try:
        return _fernet().decrypt(token).decode()
    except InvalidToken as exc:
        raise ValueError("encrypted value could not be decrypted") from exc


def encrypt_dict(data: dict) -> bytes:
    return encrypt_str(json.dumps(data, separators=(",", ":"), sort_keys=True))


def decrypt_dict(token: bytes) -> dict:
    return json.loads(decrypt_str(token))
