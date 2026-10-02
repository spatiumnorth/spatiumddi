"""MFA — TOTP enrolment + verification + recovery codes (issue #69).

Pure-functions module; the auth router orchestrates persistence.

* TOTP secrets are 32-byte (160-bit) base32 strings, the RFC 6238
  default. Stored on the user row as Fernet ciphertext via
  ``app.core.crypto`` so a leaked DB dump doesn't yield the
  symmetric secret.
* Recovery codes are 10 random 8-character chunks of an alphabet
  drawn from ``base32`` minus the visually-ambiguous ``0``, ``1``,
  ``8`` (which look like ``O``, ``I``, ``B`` in many fonts).
  Stored as a Fernet-encrypted JSON list of sha256 hashes — the
  raw codes are only ever visible to the operator at enrolment.
  Consumption deletes the matching hash from the list and
  re-encrypts.
* Verification uses pyotp's ``valid_window=1`` so a one-step skew
  in either direction passes; that's the standard TOTP guidance
  and matches what GitHub / Google use.

Failed verification attempts are NOT counted here — the existing
account-lockout machinery in the login router handles that
uniformly across password / MFA / recovery flows.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pyotp

from app.core.crypto import decrypt_dict, decrypt_str, encrypt_dict, encrypt_str, encrypted_at

# Number of recovery codes generated per enrolment. Mirror common
# practice (GitHub: 16, Google: 10, AWS: 10) — 10 is plenty without
# being unwieldy to print.
_RECOVERY_CODE_COUNT: Final[int] = 10

# Recovery-code alphabet — base32 minus the visually ambiguous
# characters (no I/O/0/1). 24 letters + 6 digits = 30 chars.
_RECOVERY_ALPHABET: Final[str] = "ABCDEFGHJKLMNPQRSTUVWXYZ234567"

# Code length per chunk + chunks per code. 4-4 split with a hyphen
# so the operator can read it off paper without losing place. Total
# entropy = 8 chars × log2(30) ≈ 39.3 bits per code; brute-forcing
# even one is impractical against the rate-limited verify endpoint.
_RECOVERY_CHUNK_LEN: Final[int] = 4
_RECOVERY_CHUNK_COUNT: Final[int] = 2


def generate_secret() -> str:
    """Fresh base32 TOTP secret, 32 bytes of entropy."""
    return pyotp.random_base32(length=32)


def otpauth_uri(secret: str, username: str, issuer: str = "SpatiumDDI") -> str:
    """Build the ``otpauth://`` URI consumed by authenticator apps.

    The label is ``{issuer}:{username}`` per the URI spec — the
    issuer prefix lets apps group entries by service when the user
    has accounts on multiple SpatiumDDI deployments.
    """
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """Validate a 6-digit code against the secret. ``valid_window=1``
    accepts ±1 step (30s) of clock drift in either direction —
    standard practice; GitHub / AWS use the same window."""
    if not code or not code.strip().isdigit():
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def generate_recovery_codes() -> list[str]:
    """Ten fresh recovery codes. Format ``ABCD-EF12`` — chunked for
    legibility when read off a printed sheet. Returned in the order
    they should be displayed to the operator; the encrypted-on-disk
    representation is order-independent (we store hashes only)."""
    codes: list[str] = []
    for _ in range(_RECOVERY_CODE_COUNT):
        chunks = [
            "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_CHUNK_LEN))
            for _ in range(_RECOVERY_CHUNK_COUNT)
        ]
        codes.append("-".join(chunks))
    return codes


def _hash_recovery_code(code: str) -> str:
    """Stable hash for storage. ``code`` is normalised — uppercase +
    hyphens stripped — so an operator typing ``abcd-ef12`` matches
    the stored ``ABCDEF12`` hash."""
    normalised = code.strip().upper().replace("-", "")
    return hashlib.sha256(normalised.encode()).hexdigest()


def encrypt_recovery_codes(codes: list[str]) -> bytes:
    """Take raw recovery codes and produce the Fernet ciphertext that
    persists. Storage shape is ``{"hashes": [...]}`` so the on-disk
    JSON has a stable top-level shape if we ever need to add metadata
    (consumption timestamps, etc.)."""
    return encrypt_dict({"hashes": [_hash_recovery_code(c) for c in codes]})


def consume_recovery_code(blob: bytes, candidate: str) -> tuple[bool, bytes | None]:
    """Validate ``candidate`` against the encrypted code list.

    Returns ``(matched, new_blob)``:
      * ``matched=True`` and ``new_blob`` is the freshly-encrypted
        list with the consumed hash removed — caller persists this.
      * ``matched=False`` and ``new_blob=None`` — caller leaves the
        stored blob alone.

    The caller is responsible for noticing when the returned list
    has emptied and force-regenerating on the next successful login.
    """
    try:
        data = decrypt_dict(blob)
    except ValueError:
        return False, None
    hashes = list(data.get("hashes") or [])
    target = _hash_recovery_code(candidate)
    if target not in hashes:
        return False, None
    hashes.remove(target)
    new_blob = encrypt_dict({"hashes": hashes})
    return True, new_blob


def remaining_recovery_codes(blob: bytes | None) -> int:
    """Count how many recovery codes are still live. Surfaced on the
    Settings panel so the operator knows when to regenerate."""
    if blob is None:
        return 0
    try:
        data = decrypt_dict(blob)
    except ValueError:
        return 0
    return len(data.get("hashes") or [])


#: How long a started enrolment can be completed (#1354). ``begin`` hands
#: out a secret and ``verify`` turns MFA on with it; an abandoned one used to
#: stay open indefinitely to 6-digit guesses from any of the user's sessions.
PENDING_ENROLMENT_TTL: Final[timedelta] = timedelta(minutes=15)


def enrolment_pending(user: Any, now: datetime | None = None) -> bool:
    """Whether ``user`` has a started, unexpired enrolment.

    The start time is the candidate secret's own Fernet timestamp: ``begin``
    encrypts a fresh secret each time it runs and nothing else writes one
    while MFA is off, so the token's age is the enrolment's age.
    """
    if user.totp_enabled or user.totp_secret_encrypted is None:
        return False
    try:
        started = encrypted_at(user.totp_secret_encrypted)
    except ValueError:
        return False
    return (now or datetime.now(UTC)) - started <= PENDING_ENROLMENT_TTL


def clear_pending_enrolment(user: Any) -> bool:
    """Drop a started-but-unfinished enrolment (its secret and recovery
    codes). Never touches an enabled one. Returns whether anything changed;
    the caller commits."""
    if user.totp_enabled or user.totp_secret_encrypted is None:
        return False
    user.totp_secret_encrypted = None
    user.recovery_codes_encrypted = None
    return True


def encrypt_secret(secret: str) -> bytes:
    return encrypt_str(secret)


def decrypt_secret(blob: bytes) -> str:
    return decrypt_str(blob)


__all__ = [
    "PENDING_ENROLMENT_TTL",
    "clear_pending_enrolment",
    "enrolment_pending",
    "generate_secret",
    "otpauth_uri",
    "verify_totp",
    "generate_recovery_codes",
    "encrypt_recovery_codes",
    "consume_recovery_code",
    "remaining_recovery_codes",
    "encrypt_secret",
    "decrypt_secret",
]
