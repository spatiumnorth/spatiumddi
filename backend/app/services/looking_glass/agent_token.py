"""JWT mint/verify/rotate for BGP Looking Glass collectors.

Mirrors ``app.services.dhcp.agent_token`` — the collector is an
agent-managed resource, so it reuses the identical PSK→JWT bootstrap and
near-expiry rotation shape. The only difference is the token ``typ``
(``lg_agent``) so a DHCP / DNS token can't be replayed against the
Looking Glass agent endpoints.
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
    collector_id: str,
    agent_id: str,
    fingerprint: str,
    ttl_hours: int = DEFAULT_TTL_HOURS,
) -> tuple[str, datetime]:
    expire = datetime.now(UTC) + timedelta(hours=ttl_hours)
    payload: dict[str, Any] = {
        "sub": collector_id,
        "agent_id": agent_id,
        "fingerprint": fingerprint,
        "typ": "lg_agent",
        "exp": expire,
        # A unique id per mint: exp is whole seconds, so two tokens minted for
        # one server in the same second would otherwise be byte-identical, and
        # the stored hash could not tell the displaced one from its replacement.
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
    return token, expire


def verify_agent_token(token: str) -> dict[str, Any]:
    payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    if payload.get("typ") != "lg_agent":
        raise JWTError("Not a Looking Glass agent token")
    return payload


def needs_rotation(payload: dict[str, Any]) -> bool:
    exp = payload.get("exp")
    if not exp:
        return True
    expire = datetime.fromtimestamp(int(exp), UTC)
    return (expire - datetime.now(UTC)) < timedelta(hours=ROTATION_WINDOW_HOURS)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


__all__ = [
    "mint_agent_token",
    "verify_agent_token",
    "needs_rotation",
    "hash_token",
]
