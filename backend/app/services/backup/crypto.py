"""Passphrase-wrapped envelope for the ``secrets.enc`` payload of a
backup archive (issue #117 Phase 1a).

The shape we emit + accept is a single JSON document:

.. code-block:: json

    {
      "v": 1,
      "kdf": "pbkdf2-hmac-sha256",
      "iterations": 600000,
      "salt": "<32 hex chars>",
      "nonce": "<24 hex chars>",
      "ciphertext": "<hex>",
      "hint": "<operator-supplied label or empty>"
    }

* **PBKDF2-HMAC-SHA256** at 600 000 iterations (OWASP 2023 floor)
  derives a 32-byte AES-256 key from the operator's passphrase + a
  fresh per-backup 16-byte salt.
* **AES-256-GCM** encrypts the secret payload (a JSON dict carrying
  the source install's ``SECRET_KEY`` and any other operator-supplied
  metadata). The 12-byte nonce is random per backup; GCM's auth tag
  (16 bytes) is appended to the ciphertext by the cryptography
  library.
* The serialised envelope is human-inspectable — operators can
  ``unzip backup.zip secrets.enc | jq .`` to confirm they have the
  right archive without supplying the passphrase.

Restoring decrypts in the obvious order: derive the key from
passphrase + salt, run AES-GCM decrypt over the ciphertext+tag,
parse the resulting JSON. A wrong passphrase yields
``BackupCryptoError`` (raised from cryptography's
``InvalidTag``) rather than producing garbage plaintext.
"""

from __future__ import annotations

import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# OWASP 2023 floor for PBKDF2-HMAC-SHA256. 600 k iterations on a
# typical workstation costs ~0.3 s — annoying enough to bracket
# brute-force, fast enough that operators don't notice it on the
# legitimate path.
_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32  # AES-256
_ENVELOPE_VERSION = 1


class BackupCryptoError(Exception):
    """Raised when a backup envelope can't be decrypted or parsed.

    Distinct from ``BackupArchiveError`` so the API layer can tell
    "you typed the wrong passphrase" apart from "the zip is
    malformed" without staring at tracebacks.
    """


#: The 422 detail every write path returns for a hint that gives the
#: passphrase away. One string so the three endpoints cannot drift.
HINT_REVEALS_PASSPHRASE = (
    "passphrase_hint must not contain the passphrase — the hint is stored "
    "unencrypted in every archive (manifest.json and the secrets.enc header), "
    "in the API response and in the audit log"
)


def hint_reveals_passphrase(passphrase: str | None, hint: str | None) -> bool:
    """True when ``hint`` contains ``passphrase``.

    The hint is written in clear next to the ciphertext it unlocks —
    deliberately, so an operator can tell archives apart without the
    passphrase. That makes a hint which *is* the passphrase (the field
    sits directly under the passphrase input, and gets the paste meant
    for it) a silent total loss: ``secrets.enc`` then protects nothing.

    Case-insensitive substring match: a hint that only re-cases the
    passphrase, or wraps it in other text, gives it away just as well.
    The passphrase minimum of 8 characters keeps this from catching a
    hint that merely shares a short word with it.
    """
    if not passphrase or not hint:
        return False
    secret = passphrase.strip().casefold()
    return bool(secret) and secret in hint.casefold()


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_secrets(
    payload: dict[str, Any],
    *,
    passphrase: str,
    hint: str | None = None,
) -> bytes:
    """Encrypt ``payload`` with a fresh AES-GCM key derived from
    ``passphrase``. Returns the JSON envelope as UTF-8 bytes ready
    to write into ``secrets.enc``.
    """
    if not passphrase:
        raise BackupCryptoError("passphrase is required to encrypt secrets")
    if hint_reveals_passphrase(passphrase, hint):
        # The API refuses this combination; a row saved before that
        # check existed can still carry it. Dropping the hint keeps the
        # scheduled backup running while not writing the key beside the
        # lock. ``build_backup_archive`` logs it.
        hint = None
    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, associated_data=None)
    envelope = {
        "v": _ENVELOPE_VERSION,
        "kdf": "pbkdf2-hmac-sha256",
        "iterations": _PBKDF2_ITERATIONS,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "hint": (hint or "").strip()[:200],
    }
    return json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8")


def decrypt_secrets(envelope_bytes: bytes, *, passphrase: str) -> dict[str, Any]:
    """Decrypt a ``secrets.enc`` envelope. Raises
    :class:`BackupCryptoError` on any wrong-shape / wrong-passphrase
    failure.
    """
    if not passphrase:
        raise BackupCryptoError("passphrase is required to decrypt secrets")
    try:
        envelope = json.loads(envelope_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupCryptoError("secrets.enc is not a valid JSON envelope") from exc
    if not isinstance(envelope, dict):
        raise BackupCryptoError("secrets.enc envelope is not a JSON object")
    if envelope.get("v") != _ENVELOPE_VERSION:
        raise BackupCryptoError(
            f"unsupported secrets envelope version: {envelope.get('v')!r} "
            f"(this build expects {_ENVELOPE_VERSION})"
        )
    try:
        salt = bytes.fromhex(envelope["salt"])
        nonce = bytes.fromhex(envelope["nonce"])
        ciphertext = bytes.fromhex(envelope["ciphertext"])
        iterations = int(envelope.get("iterations", _PBKDF2_ITERATIONS))
    except (KeyError, ValueError, TypeError) as exc:
        raise BackupCryptoError("secrets envelope is missing required fields") from exc
    # We always derive at the envelope's declared iteration count —
    # locks the cost factor to whatever was used at backup time, so
    # an operator who tightens iterations in a future build can still
    # decrypt older archives.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    aes = AESGCM(key)
    try:
        plaintext = aes.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise BackupCryptoError(
            "decryption failed — passphrase mismatch or corrupted archive"
        ) from exc
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupCryptoError(
            "decrypted payload is not valid JSON — archive may be corrupted"
        ) from exc
