"""A refused SuperAdmin-only route leaves a ``denied`` audit row (#2304).

``require_permission`` has always recorded its refusals; the ``SuperAdmin``
dependency and the per-router ``_require_superadmin`` helpers raised 403 and
wrote nothing, so probing backup restore, webhooks or the diagnostics surface
with a low-privilege token was invisible to the security dashboard and to a
SIEM fed by audit forwarding.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User

pytestmark = pytest.mark.asyncio


async def _plain_user(db: AsyncSession, *, superadmin: bool = False) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Plain",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _denied(db: AsyncSession, user: User) -> list[AuditLog]:
    res = await db.execute(
        select(AuditLog).where(AuditLog.user_id == user.id, AuditLog.result == "denied")
    )
    return list(res.scalars().all())


# (method, path) — one SuperAdmin dependency route and one route per converted
# hand-rolled helper family.
ROUTES = [
    ("POST", "/api/v1/webhooks"),  # SuperAdmin dependency
    ("POST", "/api/v1/diagnostics/errors/{id}/acknowledge"),  # diagnostics helper
    ("GET", "/api/v1/backup/sections"),  # backup router inline check
    ("GET", "/api/v1/backup/targets"),  # backup targets helper
    ("POST", "/api/v1/alerts/evaluate"),  # alerts helper
    ("GET", "/api/v1/settings/audit-forward-targets"),  # settings inline check
    ("GET", "/api/v1/settings/influxdb-targets"),
]


@pytest.mark.parametrize("method,path", ROUTES)
async def test_refusal_is_one_denied_row_and_still_403(
    client: AsyncClient, db_session: AsyncSession, method: str, path: str
) -> None:
    user, headers = await _plain_user(db_session)
    path = path.replace("{id}", str(uuid.uuid4()))

    resp = await client.request(
        method, path, headers=headers, json={} if method == "POST" else None
    )
    assert resp.status_code == 403, resp.text

    rows = await _denied(db_session, user)
    assert len(rows) == 1, [r.resource_display for r in rows]
    # The refusal body names no resource and carries no audit detail.
    assert set(resp.json()) == {"detail"}


async def test_superadmin_is_not_audited_as_denied(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, auth_headers = await _plain_user(db_session, superadmin=True)
    resp = await client.get("/api/v1/settings/influxdb-targets", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    n = await db_session.scalar(
        select(func.count()).select_from(AuditLog).where(AuditLog.result == "denied")
    )
    assert n == 0
