"""A 403 decided inside a handler leaves a ``denied`` audit row (#3644)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User

pytestmark = pytest.mark.asyncio


async def _plain_user(db: AsyncSession) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Plain",
        hashed_password=hash_password("x"),
    )
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _denied(db: AsyncSession, user_id: uuid.UUID) -> list[AuditLog]:
    res = await db.execute(
        select(AuditLog).where(AuditLog.user_id == user_id, AuditLog.result == "denied")
    )
    return list(res.scalars().all())


async def test_handler_level_refusal_writes_one_denied_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _plain_user(db_session)
    user_id = user.id
    resp = await client.post("/api/v1/settings/oui/refresh", headers=headers)
    assert resp.status_code == 403, resp.text
    assert resp.status_code == 403 and "Permission denied" in resp.json()["detail"]
    rows = await _denied(db_session, user_id)
    assert len(rows) == 1, [r.resource_display for r in rows]
    assert rows[0].resource_display == "POST /api/v1/settings/oui/refresh"
    assert "Permission denied" in (rows[0].error_detail or "")


async def test_gate_refusal_is_not_double_written(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _plain_user(db_session)
    user_id = user.id
    resp = await client.post("/api/v1/webhooks", headers=headers, json={})
    assert resp.status_code == 403, resp.text
    assert len(await _denied(db_session, user_id)) == 1


async def test_unauthenticated_403_is_not_audited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    resp = await client.post("/api/v1/domains", json={"name": "example.org"})
    assert resp.status_code in (401, 403)
    res = await db_session.execute(select(AuditLog).where(AuditLog.result == "denied"))
    assert res.scalars().all() == []


async def test_non_403_http_errors_are_untouched_and_unaudited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _plain_user(db_session)
    user_id = user.id
    missing = await client.get("/api/v1/no-such-route-3644", headers=headers)
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Not Found"}
    anon = await client.get("/api/v1/users/me")
    assert anon.status_code in (401, 403)
    assert await _denied(db_session, user_id) == []


async def test_403_body_and_status_match_the_stock_response(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _plain_user(db_session)
    resp = await client.post("/api/v1/settings/oui/refresh", headers=headers)
    assert resp.status_code == 403
    assert list(resp.json()) == ["detail"]
    assert resp.headers["content-type"] == "application/json"


async def test_domain_create_with_read_only_grant_writes_one_denied_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # The router-level gate passes on ``read``; the refusal is the handler's own.
    user, headers = await _plain_user(db_session)
    user_id = user.id
    role = Role(
        name=f"r-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[{"action": "read", "resource_type": "manage_domains"}],
    )
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    await db_session.refresh(user, ["groups"])
    group.users = [user]
    db_session.add_all([role, group])
    await db_session.commit()
    resp = await client.post("/api/v1/domains", headers=headers, json={"name": "example.org"})
    assert resp.status_code == 403, resp.text
    assert resp.json() == {"detail": "Permission denied"}
    rows = await _denied(db_session, user_id)
    assert len(rows) == 1, [r.resource_display for r in rows]
    assert rows[0].resource_display == "POST /api/v1/domains"
