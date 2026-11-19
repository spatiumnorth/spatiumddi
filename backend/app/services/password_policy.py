"""Password policy enforcement (issue #70).

Pure functions over a ``PasswordPolicy`` snapshot read from
``PlatformSettings``. The auth + users routers call ``validate`` before
hashing a new password and ``check_history`` / ``push_history`` to keep
``user.password_history_encrypted`` rotating.

Why a snapshot instead of taking the SQLAlchemy row: the routers already
do their own ``db.get(PlatformSettings, 1)`` and we want the validator
to be unit-testable without a DB round-trip. ``PasswordPolicy.from_row``
copies the seven knobs and nothing else, so callers can't accidentally
mutate the live row.

History blob shape: Fernet-encrypted JSON ``{"hashes": [...]}``. Bcrypt
hashes (60 chars each) — comparing a candidate against the list is N
bcrypt checks where N == ``password_history_count`` (default 5), which
is fine on the rare change-password path.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import bcrypt
import structlog

from app.core.crypto import decrypt_str, encrypt_str
from app.models.auth import User
from app.models.settings import PlatformSettings, platform_setting_default

logger = structlog.get_logger(__name__)


_SYMBOL_CHARS: frozenset[str] = frozenset(string.punctuation)


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_digit: bool
    require_symbol: bool
    history_count: int
    max_age_days: int

    @classmethod
    def from_row(cls, row: PlatformSettings | None) -> PasswordPolicy:
        if row is None:
            # The singleton row is created lazily, so on a fresh install the
            # first login runs before it exists. Fall back to the column
            # defaults (derived, not copied) so the shipped policy applies
            # to display and enforcement alike (#3203).
            d = platform_setting_default
            return cls(
                min_length=int(d("password_min_length")),
                require_uppercase=bool(d("password_require_uppercase")),
                require_lowercase=bool(d("password_require_lowercase")),
                require_digit=bool(d("password_require_digit")),
                require_symbol=bool(d("password_require_symbol")),
                history_count=int(d("password_history_count")),
                max_age_days=int(d("password_max_age_days")),
            )
        return cls(
            min_length=int(row.password_min_length),
            require_uppercase=bool(row.password_require_uppercase),
            require_lowercase=bool(row.password_require_lowercase),
            require_digit=bool(row.password_require_digit),
            require_symbol=bool(row.password_require_symbol),
            history_count=int(row.password_history_count),
            max_age_days=int(row.password_max_age_days),
        )


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: list[str]


# The hasher's hard ceiling — see app.core.security.BCRYPT_MAX_BYTES. Stated
# as a policy rule so the operator gets an actionable message instead of a
# 500 from inside the hash.
MAX_PASSWORD_BYTES = 72


def validate(password: str, policy: PasswordPolicy) -> ValidationResult:
    """Run every enabled rule. Returns one error per failed rule so the
    UI can render all violations at once instead of the operator
    bouncing through them serially."""
    errors: list[str] = []
    if len(password) < policy.min_length:
        errors.append(f"Password must be at least {policy.min_length} characters")
    # bcrypt hashes at most 72 BYTES and raises above it, so an unbounded
    # password reaches the hasher and 500s on the set path. Bytes, not
    # characters: a 40-character password of 2-byte characters is over the
    # line while a 71-character ASCII one is not, and only the byte count
    # matches what bcrypt actually measures.
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        errors.append(
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes "
            "(non-ASCII characters count as more than one)"
        )
    if policy.require_uppercase and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    if policy.require_lowercase and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    if policy.require_digit and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")
    if policy.require_symbol and not any(c in _SYMBOL_CHARS for c in password):
        errors.append("Password must contain at least one symbol (e.g. ! @ # $)")
    return ValidationResult(ok=not errors, errors=errors)


# ── History ─────────────────────────────────────────────────────────


def _decode_history(blob: bytes | None) -> list[str]:
    if blob is None:
        return []
    try:
        data = json.loads(decrypt_str(blob))
    except ValueError:
        # Bad ciphertext (key rotation? operator nuked the secret?) —
        # treat as empty history rather than locking out the change-
        # password path. Logged so it's visible.
        logger.warning("password_history_decrypt_failed")
        return []
    if not isinstance(data, dict):
        return []
    items = data.get("hashes", [])
    if not isinstance(items, list):
        return []
    return [h for h in items if isinstance(h, str)]


def _encode_history(hashes: list[str]) -> bytes:
    return encrypt_str(json.dumps({"hashes": hashes}, separators=(",", ":")))


def is_in_history(password: str, blob: bytes | None) -> bool:
    """True when ``password`` matches any bcrypt hash in the history
    blob. Cost is N bcrypt checks where N is the history depth."""
    for h in _decode_history(blob):
        try:
            if bcrypt.checkpw(password.encode(), h.encode()):
                return True
        except (ValueError, Exception):  # noqa: BLE001 — bcrypt can raise on bad hashes
            continue
    return False


def push_history(new_hash: str, blob: bytes | None, max_count: int) -> bytes | None:
    """Prepend ``new_hash`` to the history list and trim to ``max_count``.
    Returns the new blob, or None if history is disabled (``max_count <=
    0``) — caller should clear the column in that case so the row
    doesn't carry stale ciphertext."""
    if max_count <= 0:
        return None
    existing = _decode_history(blob)
    # Dedupe: if the same hash is already at the head (shouldn't happen
    # because bcrypt.gensalt() randomises every call, but defensive).
    if existing and existing[0] == new_hash:
        return blob
    updated = [new_hash, *existing][:max_count]
    return _encode_history(updated)


# ── Max-age ─────────────────────────────────────────────────────────


def is_expired(user: User, policy: PasswordPolicy) -> bool:
    """True when the operator has rotation enabled and the user's
    password is older than the configured threshold. External-auth
    users always return False — they don't carry a SpatiumDDI-side
    password."""
    if policy.max_age_days <= 0:
        return False
    if user.auth_source != "local":
        return False
    if user.password_changed_at is None:
        return False
    cutoff = datetime.now(UTC) - timedelta(days=policy.max_age_days)
    return user.password_changed_at < cutoff
