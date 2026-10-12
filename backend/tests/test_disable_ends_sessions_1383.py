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

from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import User
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
    assert disable.new_value == {"is_active": False, "sessions_revoked": 1}, disable.new_value
    assert enable.new_value == {"is_active": True, "sessions_revoked": 0}, enable.new_value


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
