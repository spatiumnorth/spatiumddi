"""Unit coverage for the security-hardening fixes from the Copilot review.

Pure / deterministic surfaces only — the Redis-backed throttles
(login_rate_limited, mfa_challenge_consume) fail open and are exercised
here only on their no-Redis / no-jti fallback paths.
"""

from __future__ import annotations

import pytest

from app.api.v1.users.router import CreateUserRequest
from app.config import Settings
from app.core.auth_throttle import mfa_challenge_consume
from app.core.request_meta import clean_user_agent


# ── #9 User-Agent sanitisation ──────────────────────────────────────────
def test_clean_user_agent_strips_control_chars() -> None:
    assert clean_user_agent("Mozilla/5.0\r\nInjected: evil") == "Mozilla/5.0Injected: evil"


def test_clean_user_agent_strips_c1_controls() -> None:
    # NEL (U+0085) and CSI (U+009B) are C1 controls: a line break to
    # Unicode-aware readers and a terminal control-sequence introducer.
    raw = "Mozilla/5.0 (X11\u0085Injected) \u009b31mAgent"
    out = clean_user_agent(raw)
    assert out == "Mozilla/5.0 (X11Injected) 31mAgent"
    assert not any(0x80 <= ord(c) <= 0x9F for c in out)
    # Every C1 code point is dropped; the first printable Latin-1 one is kept.
    assert clean_user_agent("".join(chr(c) for c in range(0x80, 0xA0))) is None
    assert clean_user_agent("caf\u00e9") == "caf\u00e9"


def test_clean_user_agent_truncates() -> None:
    out = clean_user_agent("A" * 900)
    assert out is not None and len(out) == 500


def test_clean_user_agent_empty_is_none() -> None:
    assert clean_user_agent(None) is None
    assert clean_user_agent("   ") is None
    assert clean_user_agent("\x00\x01") is None


# ── #1 CORS origins parsing ─────────────────────────────────────────────
def test_cors_origins_default_wildcard() -> None:
    assert Settings(cors_origins="*").cors_origins_list == ["*"]
    assert Settings(cors_origins="").cors_origins_list == ["*"]


def test_cors_origins_explicit_list() -> None:
    s = Settings(cors_origins="https://a.example.com, https://b.example.com ,")
    assert s.cors_origins_list == ["https://a.example.com", "https://b.example.com"]


# ── #14 email validation ────────────────────────────────────────────────
@pytest.mark.parametrize("good", ["a@b.co", "ops.team@ddi.example.com"])
def test_create_user_accepts_valid_email(good: str) -> None:
    req = CreateUserRequest(username="u", email=good, display_name="U", password="longenough")
    assert req.email == good


@pytest.mark.parametrize("bad", ["not-an-email", "a@b", "@b.co", "a b@c.co", "a@@b.co"])
def test_create_user_rejects_bad_email(bad: str) -> None:
    with pytest.raises(ValueError):
        CreateUserRequest(username="u", email=bad, display_name="U", password="longenough")


# ── #7 MFA replay guard fail-open ───────────────────────────────────────
@pytest.mark.asyncio
async def test_mfa_consume_missing_jti_allows() -> None:
    # A legacy challenge token without a jti can't be tracked — allow it
    # (preserves the prior stateless behaviour rather than locking out).
    assert await mfa_challenge_consume(None) is True
    assert await mfa_challenge_consume("") is True
