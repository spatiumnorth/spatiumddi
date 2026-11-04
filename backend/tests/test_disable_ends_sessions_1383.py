"""Disabling a user ends its sessions (#1383).

``PUT /api/v1/users/{id}`` with ``is_active: false`` only set the flag. Every
request on the user's sessions was refused while the account stayed disabled
(403 "User account is disabled"), but the sessions stayed valid: re-enabling
the account brought every one of them back until it expired, including one an
attacker held, and each refresh extended it. A refused request also bumped the
session's ``last_seen_at``, so the Sessions view showed recent activity on an
account that could do nothing. Disabling is how an administrator contains an
account; a re-enabled account must start with no sessions.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.api_tokens.router import ApiTokenCreate, create_token
from app.core.security import generate_api_token
from app.models.audit import AuditLog
from app.models.auth import APIToken, User
from tests.conftest import _TestSessionLocal
from tests.test_fix_m3_m4_auth_session import _bearer, _ensure_settings, _session, _user


async def _set_active(client: AsyncClient, admin: User, target: User, active: bool) -> None:
    resp = await client.put(
        f"/api/v1/users/{target.id}", json={"is_active": active}, headers=_bearer(admin)
    )
    assert resp.status_code == 200, resp.text


async def _audits(db: AsyncSession, target: User) -> list[AuditLog]:
    return list(
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.resource_id == str(target.id), AuditLog.action == "update")
                .order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    )


async def test_disabling_ends_the_sessions_and_re_enabling_brings_none_back(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _ensure_settings(db_session)
    admin = await _user(db_session, is_superadmin=True)
    target = await _user(db_session)
    session = await _session(db_session, target)
    await db_session.commit()
    headers = _bearer(target, session)
    # Control: the session works before the disable.
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200

    await _set_active(client, admin, target, False)
    await db_session.refresh(session)
    assert session.revoked is True, "disabling the account left its session live"

    await _set_active(client, admin, target, True)
    again = await client.get("/api/v1/auth/me", headers=headers)
    assert again.status_code == 401, (
        "after a disable and a re-enable, the session from before the disable answered "
        f"{again.status_code}: a re-enabled account must start with no sessions. {again.text}"
    )

    disable, enable = await _audits(db_session, target)
    assert disable.new_value == {
        "is_active": False,
        "sessions_revoked": 1,
        "api_tokens_revoked": 0,
    }, disable.new_value
    assert enable.new_value == {
        "is_active": True,
        "sessions_revoked": 0,
        "api_tokens_revoked": 0,
    }, enable.new_value


async def test_an_account_disabled_before_brings_back_no_session_when_re_enabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An account disabled without its sessions ending (before this fix, or
    in the database) must not get them back when it is re-enabled."""
    await _ensure_settings(db_session)
    admin = await _user(db_session, is_superadmin=True)
    target = await _user(db_session)
    session = await _session(db_session, target)
    target.is_active = False
    await db_session.commit()

    await _set_active(client, admin, target, True)
    resp = await client.get("/api/v1/auth/me", headers=_bearer(target, session))
    assert (
        resp.status_code == 401
    ), f"re-enabling the account revived a session it held while disabled: {resp.status_code}"
    await db_session.refresh(session)
    assert session.revoked is True


async def test_a_disabled_accounts_refused_request_is_not_activity(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _ensure_settings(db_session)
    target = await _user(db_session)
    session = await _session(db_session, target)
    seen = datetime.now(UTC) - timedelta(minutes=10)
    session.last_seen_at = seen
    target.is_active = False
    await db_session.commit()

    resp = await client.get("/api/v1/auth/me", headers=_bearer(target, session))
    assert resp.status_code == 403, resp.text
    await db_session.refresh(session)
    assert session.last_seen_at == seen, (
        f"a request refused because the account is disabled moved the session's "
        f"last_seen_at from {seen} to {session.last_seen_at}"
    )


async def test_an_edit_that_keeps_the_account_active_ends_no_session(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Control: only a change of ``is_active`` ends sessions."""
    await _ensure_settings(db_session)
    admin = await _user(db_session, is_superadmin=True)
    target = await _user(db_session)
    session = await _session(db_session, target)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/users/{target.id}",
        json={"display_name": "Renamed", "is_active": True},
        headers=_bearer(admin),
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(session)
    assert session.revoked is False
    assert (
        await client.get("/api/v1/auth/me", headers=_bearer(target, session))
    ).status_code == 200


async def _token(db: AsyncSession, owner: User, *, active: bool = True) -> APIToken:
    raw, prefix, token_hash = generate_api_token()
    tok = APIToken(
        name=f"t-{uuid.uuid4().hex[:6]}",
        token_hash=token_hash,
        prefix=raw[:10],
        scope="user",
        scopes=[],
        user_id=owner.id,
        created_by_user_id=owner.id,
        is_active=active,
    )
    db.add(tok)
    await db.flush()
    tok._raw = raw  # type: ignore[attr-defined]
    return tok


async def test_disabling_revokes_api_tokens_and_re_enabling_does_not_restore_them(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3432 — a bearer token authenticates as its owner, so a disable must end it."""
    await _ensure_settings(db_session)
    admin = await _user(db_session, is_superadmin=True)
    target = await _user(db_session)
    other = await _user(db_session)
    tok = await _token(db_session, target)
    other_tok = await _token(db_session, other)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {tok._raw}"}  # type: ignore[attr-defined]
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200

    await _set_active(client, admin, target, False)
    await db_session.refresh(tok)
    await db_session.refresh(other_tok)
    assert tok.is_active is False, "disabling the account left its API token live"
    assert other_tok.is_active is True, "another user's token was revoked"

    await _set_active(client, admin, target, True)
    await db_session.refresh(tok)
    assert tok.is_active is False, "re-enabling the account brought the token back"
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401

    disable, enable = await _audits(db_session, target)
    assert disable.new_value["api_tokens_revoked"] == 1, disable.new_value
    assert enable.new_value["api_tokens_revoked"] == 0, enable.new_value


async def test_an_account_disabled_before_brings_back_no_token_when_re_enabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3432 — an account disabled with its tokens left live (before this fix,
    or in the database) must not get them back when it is re-enabled."""
    await _ensure_settings(db_session)
    admin = await _user(db_session, is_superadmin=True)
    target = await _user(db_session)
    tok = await _token(db_session, target)
    target.is_active = False
    await db_session.commit()
    headers = {"Authorization": f"Bearer {tok._raw}"}  # type: ignore[attr-defined]

    await _set_active(client, admin, target, True)
    resp = await client.get("/api/v1/auth/me", headers=headers)
    assert (
        resp.status_code == 401
    ), f"re-enabling the account revived a token it held while disabled: {resp.status_code}"
    await db_session.refresh(tok)
    assert tok.is_active is False
    (enable,) = await _audits(db_session, target)
    assert enable.new_value["api_tokens_revoked"] == 1, enable.new_value


async def test_each_revoked_token_gets_its_own_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3432 — the revoke shows in the token's own history, as a PATCH revoke does."""
    await _ensure_settings(db_session)
    admin = await _user(db_session, is_superadmin=True)
    target = await _user(db_session)
    tok = await _token(db_session, target)
    dead = await _token(db_session, target, active=False)
    await db_session.commit()

    await _set_active(client, admin, target, False)

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "api_token",
                    AuditLog.resource_id.in_([str(tok.id), str(dead.id)]),
                )
            )
        )
        .scalars()
        .all()
    )
    assert [(r.resource_id, r.action, r.user_id) for r in rows] == [
        (str(tok.id), "update", admin.id)
    ], rows
    assert rows[0].changed_fields == ["is_active"]
    assert rows[0].new_value == {"is_active": False, "reason": "owner_disabled"}


async def test_a_mint_racing_the_disable_is_refused(db_session: AsyncSession) -> None:
    """#3432 — a token minted by a caller authenticated just before the disable
    committed must not be inserted live after the disable read the tokens."""
    await _ensure_settings(db_session)
    target = await _user(db_session)
    target_id = target.id
    await db_session.commit()
    # ``target`` stays is_active=True in this session: the caller as auth saw it.

    async with _TestSessionLocal() as disabler:
        # The disable holds the account row, as PUT /users/{id} does.
        await disabler.execute(select(User.id).where(User.id == target_id).with_for_update())
        mint = asyncio.create_task(
            create_token(
                ApiTokenCreate(name="racer", stepup_password="OldPass123!"),
                db_session,
                target,
            )
        )
        await asyncio.sleep(0.5)
        await disabler.execute(update(User).where(User.id == target_id).values(is_active=False))
        await disabler.commit()

    with pytest.raises(HTTPException) as exc:
        await mint
    assert exc.value.status_code == 403, exc.value.detail
    await db_session.rollback()
    live = (
        (
            await db_session.execute(
                select(APIToken).where(APIToken.user_id == target_id, APIToken.is_active.is_(True))
            )
        )
        .scalars()
        .all()
    )
    assert live == [], "a token minted during the disable was left live"
