"""JWT token issuance/validation and password hashing."""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from jose import JWTError, jwt

from app.config import settings

ALGORITHM = "HS256"


# ── Passwords ──────────────────────────────────────────────────────────────────


# bcrypt reads at most 72 bytes of input and RAISES on anything longer, so
# both halves of the pair have to agree on the boundary or they disagree
# about what a password even is. `verify_password` truncates below; hashing
# must truncate identically, or a >72-byte password would hash fine and then
# never verify. The API layer rejects over-length input before it reaches
# here (password_policy.validate) — this is the defensive floor under it, so
# no caller can 500 on a password that is merely too long.
BCRYPT_MAX_BYTES = 72


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:BCRYPT_MAX_BYTES], bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    # Total by contract: a candidate password can only ever be WRONG, never an
    # exception. bcrypt.checkpw raises ValueError on >72-byte input and on NUL
    # bytes (and on a malformed stored hash) — request schemas allow up to 256
    # chars, so any caller that fed this a user-supplied string 500'd on those
    # inputs instead of answering 401/403 (live: DELETE
    # /appliance/appliances/{id} answered 500 on every conformance run).
    # bcrypt itself only reads the first 72 bytes of a valid input, so the
    # truncation cannot accept a password the untruncated compare would reject.
    try:
        return bcrypt.checkpw(plain.encode()[:BCRYPT_MAX_BYTES], hashed.encode())
    except ValueError:
        return False


# ── JWT ────────────────────────────────────────────────────────────────────────


# Every access token has carried a ``jti`` naming its ``UserSession`` since
# #72 (2026.05.07-1): both places that mint one pass it. So a token without
# one was not minted by this server. It can only be forged, and a forged
# token would also escape force-logout, which works by revoking the session
# the jti names. Such tokens are refused (#1222).
#
# The test suite sets this to True: its fixtures mint tokens with no session
# row, and making every one of them create a session proves nothing a
# dedicated test does not. It is a module attribute, not a setting, so no
# environment variable or config file can turn it on.
ACCEPT_ACCESS_TOKENS_WITHOUT_SESSION = False


def create_access_token(
    subject: str,
    extra: dict[str, Any] | None = None,
    *,
    jti: str | None = None,
) -> str:
    """Mint an access JWT. ``jti`` ties the token to a ``UserSession``
    row so a superadmin can force-logout an in-flight token by
    flipping ``UserSession.revoked`` (issue #72). Every real login passes
    one; a token minted without it is refused by
    :func:`decode_access_token` outside the test suite (#1222)."""
    expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    payload: dict[str, Any] = {"sub": subject, "exp": expire, "type": "access"}
    if jti is not None:
        payload["jti"] = jti
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def create_refresh_token(subject: str) -> tuple[str, str]:
    """Return (raw_token, hashed_token). Store only the hash."""
    raw = secrets.token_urlsafe(48)
    hashed = _hash_token(raw)
    return raw, hashed


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate an access JWT. Raises JWTError on failure."""
    payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    if payload.get("type") != "access":
        raise JWTError("Not an access token")
    if payload.get("jti") is None and not ACCEPT_ACCESS_TOKENS_WITHOUT_SESSION:
        raise JWTError("Access token names no session")
    return payload


async def live_access_session(db: Any, payload: dict[str, Any]) -> Any:
    """The live ``UserSession`` a decoded access token names, or raise.

    The one session gate for every path that accepts an access token (the
    auth dependency, the nmap stream, the maintenance-mode bypass), so they
    cannot disagree. Raises :class:`JWTError` when the session is missing,
    revoked or expired (force-logout, #72), or belongs to a different user
    than the token's ``sub``. That last check is what makes a jti worth
    requiring (#1222): without it, anyone able to sign a token could put
    their OWN live session's jti next to a superadmin's user id.

    Returns None only for a token with no ``jti``, which
    :func:`decode_access_token` has already refused outside the test suite.
    """
    from app.models.auth import UserSession  # noqa: PLC0415 — keep security import-light

    jti = payload.get("jti")
    if jti is None:
        return None
    session = await db.get(UserSession, jti)
    if session is None or session.revoked or session.expires_at <= datetime.now(UTC):
        raise JWTError("Session revoked or expired")
    if str(session.user_id) != str(payload.get("sub")):
        raise JWTError("Session belongs to another user")
    return session


# ── MFA challenge tokens (issue #69) ──────────────────────────────────────────
#
# Short-lived JWT minted by ``/auth/login`` when a user has TOTP enabled. Only
# valid as the ``mfa_token`` in ``/auth/login/mfa``. Carries ``type="mfa"`` so
# it can never be mistaken for an access token by the auth deps. 5 min TTL
# is enough for the user to fish their phone out and type the code without
# leaving a window large enough to phish-replay.

_MFA_TOKEN_TTL_MINUTES = 5


def create_mfa_challenge_token(user_id: str) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=_MFA_TOKEN_TTL_MINUTES)
    # ``jti`` lets the redeem path mark the challenge single-use in Redis
    # so a captured (challenge + TOTP) pair can't be replayed within the
    # TTL (#7).
    payload: dict[str, Any] = {
        "sub": user_id,
        "exp": expire,
        "type": "mfa",
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_mfa_challenge_token(token: str) -> dict[str, Any]:
    """Decode a challenge token. Raises JWTError on bad signature, expired,
    or wrong type — same error class the access path uses so the login router
    can collapse the failure modes."""
    payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    if payload.get("type") != "mfa":
        raise JWTError("Not an MFA challenge token")
    return payload


# ── API Tokens ─────────────────────────────────────────────────────────────────


def generate_api_token() -> tuple[str, str, str]:
    """
    Return (full_token, prefix, hash).
    full_token is shown to the user once and never stored.
    """
    prefix = "sddi_"
    raw = prefix + secrets.token_urlsafe(40)
    hashed = _hash_token(raw)
    return raw, prefix, hashed


def hash_api_token(raw: str) -> str:
    return _hash_token(raw)


def hash_refresh_token(raw: str) -> str:
    return _hash_token(raw)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
