"""A refused route's ``denied`` row carries the type its change rows use (#4718).

The permission gate used to write the permission's own type, so a refusal on a
DNS server group route listed under ``dns_group`` while the group's changes
were ``dns_server_group``; no Resource filter listed both. The permission's
name stays in ``error_detail``.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User

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


async def _denied(db: AsyncSession, user: User) -> AuditLog:
    res = await db.execute(
        select(AuditLog).where(AuditLog.user_id == user.id, AuditLog.result == "denied")
    )
    rows = list(res.scalars().all())
    assert len(rows) == 1, [r.resource_display for r in rows]
    return rows[0]


@pytest.mark.parametrize(
    "method,path,audited,permission",
    [
        ("POST", "/api/v1/dns/groups", "dns_server_group", "dns_group"),
        ("PUT", "/api/v1/dns/groups/{id}", "dns_server_group", "dns_group"),
        ("DELETE", "/api/v1/dns/groups/{id}", "dns_server_group", "dns_group"),
        # Not a server group: the group's servers are audited as dns_server.
        ("POST", "/api/v1/dns/groups/{id}/servers", "dns_group", "dns_group"),
        ("POST", "/api/v1/dhcp/server-groups", "dhcp_server_group", "dhcp_server"),
        ("PUT", "/api/v1/dhcp/server-groups/{id}", "dhcp_server_group", "dhcp_server"),
        # A DHCP server route still writes the permission's own type.
        ("POST", "/api/v1/dhcp/servers", "dhcp_server", "dhcp_server"),
    ],
)
async def test_denied_row_type(
    client: AsyncClient,
    db_session: AsyncSession,
    method: str,
    path: str,
    audited: str,
    permission: str,
) -> None:
    user, headers = await _plain_user(db_session)
    resp = await client.request(
        method, path.replace("{id}", str(uuid.uuid4())), headers=headers, json={}
    )
    assert resp.status_code == 403, resp.text

    row = await _denied(db_session, user)
    assert row.resource_type == audited
    assert f"on {permission})" in (row.error_detail or "")
