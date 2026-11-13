"""Symmetric encryption for secrets stored at rest (LDAP bind passwords,
OIDC client secrets, SAML private keys, integration tokens, ...).

Uses Fernet (AES-128-CBC + HMAC-SHA256). Two keys can be in play (#1358):

* the **dedicated** key, ``settings.credential_encryption_key`` — random,
  independent of ``SECRET_KEY``. When set it is the ONLY key new writes use.
* the **legacy** key, derived from ``settings.secret_key`` via SHA-256. It is
  what every install encrypted with before the dedicated key existed, so it
  stays a *read* fallback for as long as a dedicated key is configured: a
  value written before the upgrade keeps decrypting, and
  ``python -m app.core.rotate_credential_key`` moves them onto the dedicated
  key. With no dedicated key configured the derived key is used for both
  reading and writing, as before (and a warning is logged once).

While ``settings.credential_key_since`` equals the running version (the
rollout that added the key to a running install), the order is swapped: the
derived key writes and the dedicated one is only read, so a pod that does not
have the dedicated key yet can still read everything written meanwhile.

Replacing either key without first re-encrypting existing rows makes the
values written under it unreadable.
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

from app.config import credential_key_writes_deferred, settings

logger = structlog.get_logger(__name__)


def _derived_fernet() -> Fernet:
    digest = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


@lru_cache(maxsize=1)
def _fernet() -> tuple[Fernet, ...]:
    """The keys in trial order. Index 0 encrypts; every entry may decrypt."""
    raw = settings.credential_encryption_key.strip()
    if raw:
        try:
            dedicated = Fernet(raw.encode())
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
            return (_derived_fernet(),)
        if credential_key_writes_deferred(settings.credential_key_since, settings.version):
            # The rollout that introduced the key: some reader may not have
            # it yet, so keep WRITING under the derived key and only read the
            # dedicated one. Writes move across on the next release.
            logger.info("credential_encryption_key_writes_deferred")
            return (_derived_fernet(), dedicated)
        # Writes use the dedicated key; the SECRET_KEY-derived one stays a
        # read fallback so values written before it was configured still open.
        return (dedicated, _derived_fernet())
    # No dedicated key: secrets are encrypted with a key DERIVED from
    # SECRET_KEY, which couples the two (anyone who can recover SECRET_KEY —
    # e.g. from a session token — can decrypt every stored secret).
    logger.warning(
        "credential_encryption_key_not_set",
        detail=(
            "stored credentials are encrypted with a key derived from SECRET_KEY; "
            "set CREDENTIAL_ENCRYPTION_KEY and run "
            "`python -m app.core.rotate_credential_key` (#1358)"
        ),
    )
    return (_derived_fernet(),)


def encrypt_str(plaintext: str) -> bytes:
    return _fernet()[0].encrypt(plaintext.encode())


def _open(token: bytes) -> tuple[Fernet, bytes]:
    """The key that opened ``token`` and the plaintext. ``InvalidToken`` if none."""
    for f in _fernet():
        try:
            return f, f.decrypt(token)
        except InvalidToken:
            continue
    raise InvalidToken


def is_current_key(token: bytes) -> bool:
    """True when ``token`` is under the key new writes use (so a rotation
    has nothing to do for it). ``ValueError`` if no configured key opens it."""
    try:
        return _open(token)[0] is _fernet()[0]
    except InvalidToken as exc:
        raise ValueError("encrypted value could not be decrypted") from exc


def encrypted_at(token: bytes) -> datetime:
    """When ``token`` was encrypted. A Fernet token carries its own creation
    time (verified with the signature), so a caller can tell how old a value
    is without a column for it. ``ValueError`` if the token is not ours."""
    try:
        f, _ = _open(token)
        return datetime.fromtimestamp(f.extract_timestamp(token), UTC)
    except InvalidToken as exc:
        raise ValueError("encrypted value could not be verified") from exc


def decrypt_str(token: bytes) -> str:
    try:
        return _open(token)[1].decode()
    except InvalidToken as exc:
        raise ValueError("encrypted value could not be decrypted") from exc


def encrypt_dict(data: dict) -> bytes:
    return encrypt_str(json.dumps(data, separators=(",", ":"), sort_keys=True))


def decrypt_dict(token: bytes) -> dict:
    return json.loads(decrypt_str(token))
