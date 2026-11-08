"""JWT mint/verify/rotate for DNS agents.

Per docs/deployment/DNS_AGENT.md §6:
- HS256, signed with control-plane SECRET_KEY
- 24h lifetime, rotated silently via heartbeat if within rotation window
- Claims: sub=server_id, agent_id, fingerprint, exp
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import settings
from app.core import jwt_compat as jwt
from app.core.jwt_compat import JWTError

ALGORITHM = "HS256"
DEFAULT_TTL_HOURS = 24
ROTATION_WINDOW_HOURS = 12


def mint_agent_token(
    server_id: str,
    agent_id: str,
    fingerprint: str,
    ttl_hours: int = DEFAULT_TTL_HOURS,
) -> tuple[str, datetime]:
    """Mint a new agent JWT. Returns (token, expires_at)."""
    expire = datetime.now(UTC) + timedelta(hours=ttl_hours)
    payload: dict[str, Any] = {
        "sub": server_id,
        "agent_id": agent_id,
        "fingerprint": fingerprint,
        "typ": "dns_agent",
        "exp": expire,
        # A unique id per mint: exp is whole seconds, so two tokens minted for
        # one server in the same second would otherwise be byte-identical, and
        # the stored hash could not tell the displaced one from its replacement.
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
    return token, expire


def verify_agent_token(token: str) -> dict[str, Any]:
    """Decode and validate. Raises JWTError on failure."""
    payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    if payload.get("typ") != "dns_agent":
        raise JWTError("Not a DNS agent token")
    return payload


def needs_rotation(payload: dict[str, Any]) -> bool:
    """Return True if the token is within the rotation window."""
    exp = payload.get("exp")
    if not exp:
        return True
    expire = datetime.fromtimestamp(int(exp), UTC)
    return (expire - datetime.now(UTC)) < timedelta(hours=ROTATION_WINDOW_HOURS)


def hash_token(token: str) -> str:
    """Store a hash of the token on the server row (not the token itself)."""
    return hashlib.sha256(token.encode()).hexdigest()
