"""A placeholder SECRET_KEY no longer boots, and a forged token has nowhere to go (#1222).

SECRET_KEY signs every session token and, unless CREDENTIAL_ENCRYPTION_KEY is
set, derives the key every stored credential is encrypted with. Compose and
k8s/base shipped committed placeholders, and the boot check only warned. On
such an install any signed-in user could mint a superadmin token (user ids
are visible in the audit log), and a token with no ``jti`` escaped
force-logout on top. These pin:

* the refusal, for both placeholders the repo shipped and for weak keys;
* that a malformed CREDENTIAL_ENCRYPTION_KEY stops the boot instead of
  silently falling back to a different key;
* that a token naming no session is refused, while a REAL login's token
  (which always names one) still works;
* that force-logout reaches the nmap stream's own token check;
* the rotation command that moves an existing install onto a real key.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.core.security as security
from app.config import Settings, secret_key_problem, settings
from app.core import crypto, rotate_secret_key
from app.core.security import create_access_token, decode_access_token, hash_password
from app.models.ai import AIProvider
from app.models.auth import User, UserSession
from app.services.backup.rewrap import RewrapOutcome, _fernet_from_keys

_GOOD_KEY = "3f" * 32  # what `openssl rand -hex 32` produces: 64 hex chars
_PASSWORD = "Sup3r-secret!"


# ── the boot refusal ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "key",
    [
        "change-me-to-a-random-32-char-string",  # .env.example
        "CHANGEME-generate-with-openssl-rand-hex-32",  # k8s/base, which never warned
        "please-Change-this-before-going-to-production-ok",
        "ChangeMeChangeMeChangeMeChangeMe1",  # no separator, but still a placeholder
        "short-but-random-7f3a9c",
        "",
    ],
)
def test_weak_keys_refuse_to_boot(key: str) -> None:
    assert secret_key_problem(key) is not None
    with pytest.raises(ValidationError, match="SECRET_KEY is not safe"):
        Settings(secret_key=key, allow_insecure_secret_key=False)


def test_a_generated_key_boots() -> None:
    assert secret_key_problem(_GOOD_KEY) is None
    # Helm's randAlphaNum 64 can spell "change" by chance; no separator, no refusal.
    assert secret_key_problem("aB3" + "Change" + "x9Q" * 18) is None
    assert Settings(secret_key=_GOOD_KEY, allow_insecure_secret_key=False).secret_key == _GOOD_KEY


def test_dev_can_opt_in_explicitly() -> None:
    s = Settings(secret_key="change-me-to-a-random-32-char-string", allow_insecure_secret_key=True)
    assert s.allow_insecure_secret_key is True


def test_the_refusal_says_how_to_recover() -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(secret_key="change-me-to-a-random-32-char-string", allow_insecure_secret_key=False)
    message = str(exc.value)
    assert "openssl rand -hex 32" in message
    assert "app.core.rotate_secret_key" in message


def test_strict_secret_key_still_parses() -> None:
    """Deprecated, but an existing .env carrying it must not break the boot."""
    assert Settings(secret_key=_GOOD_KEY, strict_secret_key=True).secret_key == _GOOD_KEY


def test_a_malformed_credential_key_stops_the_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Falling back to the SECRET_KEY-derived key would encrypt with a
    different key than the operator configured, so it is an error now."""
    monkeypatch.setattr(settings, "credential_encryption_key", "not-a-fernet-key")
    monkeypatch.setattr(settings, "allow_insecure_secret_key", False)
    crypto._fernet.cache_clear()
    try:
        with pytest.raises(ValueError, match="CREDENTIAL_ENCRYPTION_KEY"):
            crypto._fernet()
    finally:
        crypto._fernet.cache_clear()


def test_a_malformed_credential_key_is_refused_at_boot() -> None:
    """``crypto._fernet`` is lazy, so the check has to live in Settings or a
    bad key boots and then fails every credential read at runtime."""
    with pytest.raises(ValidationError, match="CREDENTIAL_ENCRYPTION_KEY"):
        Settings(
            secret_key=_GOOD_KEY,
            credential_encryption_key="3f" * 32,  # hex, not a Fernet key
            allow_insecure_secret_key=False,
        )
    good = Fernet.generate_key().decode()
    assert (
        Settings(
            secret_key=_GOOD_KEY, credential_encryption_key=good, allow_insecure_secret_key=False
        ).credential_encryption_key
        == good
    )


# ── tokens that name no session ──────────────────────────────────────────────


@pytest.fixture()
def production_token_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo the test suite's opt-out, so tokens are judged as in production."""
    monkeypatch.setattr(security, "ACCEPT_ACCESS_TOKENS_WITHOUT_SESSION", False)


async def _local_user(db: AsyncSession) -> User:
    user = User(
        username=f"key-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="Key Tester",
        hashed_password=hash_password(_PASSWORD),
        auth_source="local",
        is_active=True,
        is_superadmin=False,
    )
    db.add(user)
    await db.commit()
    return user


def test_decode_refuses_a_token_without_a_session(production_token_rule: None) -> None:
    from jose import JWTError

    with pytest.raises(JWTError):
        decode_access_token(create_access_token(str(uuid.uuid4())))
    assert decode_access_token(create_access_token(str(uuid.uuid4()), jti="abc"))["jti"] == "abc"


async def test_a_sessionless_token_is_refused_by_the_api(
    production_token_rule: None, db_session: AsyncSession, client: AsyncClient
) -> None:
    """What a forged token looks like: correctly signed, naming no session."""
    user = await _local_user(db_session)
    token = create_access_token(str(user.id))
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


async def test_a_real_login_still_works(
    production_token_rule: None, db_session: AsyncSession, client: AsyncClient
) -> None:
    """The login path mints tokens with a jti, so the rule costs nothing."""
    user = await _local_user(db_session)
    login = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": _PASSWORD}
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text


async def test_force_logout_reaches_the_nmap_stream(db_session: AsyncSession) -> None:
    """The stream checks its own token and used to skip the session."""
    from starlette.requests import Request

    from app.api.v1.nmap.router import _resolve_user_from_query_token

    user = await _local_user(db_session)
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=uuid.uuid4().hex,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=1),
        revoked=True,
    )
    db_session.add(session)
    await db_session.commit()
    token = create_access_token(str(user.id), jti=str(session.id))
    request = Request({"type": "http", "headers": [], "path": "/api/v1/nmap/scans/x/stream"})
    with pytest.raises(HTTPException) as exc:
        await _resolve_user_from_query_token(db_session, token, request)
    assert exc.value.status_code == 401


async def test_a_session_of_another_user_is_refused(
    production_token_rule: None, db_session: AsyncSession, client: AsyncClient
) -> None:
    """A signer pairing their own live session with someone else's user id."""
    victim = await _local_user(db_session)
    attacker = await _local_user(db_session)
    session = UserSession(
        user_id=attacker.id,
        refresh_token_hash=uuid.uuid4().hex,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=1),
        revoked=False,
    )
    db_session.add(session)
    await db_session.commit()
    token = create_access_token(str(victim.id), jti=str(session.id))
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


# ── rotation ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def new_key(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(settings, "secret_key", _GOOD_KEY)
    monkeypatch.setattr(settings, "credential_encryption_key", "")
    return _GOOD_KEY


async def test_rotation_refuses_a_weak_new_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "secret_key", "change-me-to-a-random-32-char-string")
    assert await rotate_secret_key.rotate("anything", "") == 2


async def test_rotation_refuses_old_equal_to_new(new_key: str) -> None:
    assert await rotate_secret_key.rotate(new_key, "") == 2


async def test_a_pinned_credential_key_needs_no_rewrap(
    monkeypatch: pytest.MonkeyPatch, new_key: str
) -> None:
    pinned = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "credential_encryption_key", pinned)
    audited: list[RewrapOutcome] = []

    async def _record(outcome: RewrapOutcome) -> None:
        audited.append(outcome)

    monkeypatch.setattr(rotate_secret_key, "_audit", _record)
    assert await rotate_secret_key.rotate("change-me-to-a-random-32-char-string", pinned) == 0
    assert audited == []


async def test_rotation_reencrypts_stored_credentials(
    db_session: AsyncSession, new_key: str
) -> None:
    """End to end against the test database: a credential encrypted under
    the placeholder-derived key is readable under the new one afterwards,
    and the rotation is audited without its keys."""
    old = "change-me-to-a-random-32-char-string"
    provider = AIProvider(
        name=f"rot-{uuid.uuid4().hex[:6]}",
        kind="openai_compat",
        api_key_encrypted=_fernet_from_keys(old, "").encrypt(b"sk-live-secret"),
    )
    db_session.add(provider)
    await db_session.commit()

    assert await rotate_secret_key.rotate(old, "") == 0

    await db_session.refresh(provider)
    assert provider.api_key_encrypted is not None
    assert _fernet_from_keys(new_key, "").decrypt(provider.api_key_encrypted) == b"sk-live-secret"

    from app.models.audit import AuditLog

    row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "rotate_secret_key"))
    ).scalar_one()
    assert row.result == "success"
    assert row.new_value is not None and row.new_value["rewrapped_rows"] >= 1
    assert new_key not in str(row.new_value) and old not in str(row.new_value)

    # Idempotent: a second run moves nothing and still succeeds.
    assert await rotate_secret_key.rotate(old, "") == 0


async def test_adding_a_credential_key_while_rotating_moves_the_values(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, new_key: str
) -> None:
    """OLD_CREDENTIAL_ENCRYPTION_KEY left unset must mean "there was none",
    not "same as the new one", or this reports nothing to do and strands
    every credential."""
    old = "change-me-to-a-random-32-char-string"
    pinned = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "credential_encryption_key", pinned)
    monkeypatch.delenv("OLD_CREDENTIAL_ENCRYPTION_KEY", raising=False)
    provider = AIProvider(
        name=f"rot-{uuid.uuid4().hex[:6]}",
        kind="openai_compat",
        api_key_encrypted=_fernet_from_keys(old, "").encrypt(b"sk-live-secret"),
    )
    db_session.add(provider)
    await db_session.commit()

    old_credential = rotate_secret_key.old_credential_key_from_env()
    assert old_credential == ""
    assert await rotate_secret_key.rotate(old, old_credential) == 0

    await db_session.refresh(provider)
    assert provider.api_key_encrypted is not None
    assert (
        _fernet_from_keys(new_key, pinned).decrypt(provider.api_key_encrypted) == b"sk-live-secret"
    )
