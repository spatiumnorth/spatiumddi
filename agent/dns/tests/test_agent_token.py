"""Control-plane agent_token service tests (mint / verify / rotate)."""

from __future__ import annotations

import time

import pytest


def test_mint_and_verify() -> None:
    """Round-trip: mint a token, verify produces the same claims."""
    try:
        from app.services.dns.agent_token import mint_agent_token, verify_agent_token
    except ImportError:
        pytest.skip("control-plane package not importable from agent tests")
    token, exp = mint_agent_token("server-1", "agent-1", "fp-1")
    payload = verify_agent_token(token)
    assert payload["sub"] == "server-1"
    assert payload["agent_id"] == "agent-1"
    assert payload["fingerprint"] == "fp-1"
    assert payload["typ"] == "dns_agent"
    assert exp is not None


def test_needs_rotation_fresh_token_is_false() -> None:
    try:
        from app.services.dns.agent_token import (
            mint_agent_token,
            needs_rotation,
            verify_agent_token,
        )
    except ImportError:
        pytest.skip("control-plane package not importable")
    token, _ = mint_agent_token("server-1", "agent-1", "fp-1", ttl_hours=24)
    payload = verify_agent_token(token)
    assert needs_rotation(payload) is False


def test_rejects_non_agent_token() -> None:
    try:
        from app.core import jwt_compat as jwt

        from app.config import settings
        from app.services.dns.agent_token import verify_agent_token
    except ImportError:
        pytest.skip("control-plane package not importable")
    bad = jwt.encode({"sub": "x", "typ": "access", "exp": int(time.time()) + 3600},
                     settings.secret_key, algorithm="HS256")
    with pytest.raises(Exception):
        verify_agent_token(bad)
