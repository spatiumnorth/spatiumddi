"""#4447: the IPAM address delete rows of a scope delete carry the acting user."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from tests.test_dhcp_static_readdress_live_lease import (
    OLD,
    _group,
    _reservation,
    _row,
    _scope,
    _superadmin_token,
)


@pytest.mark.asyncio
async def test_scope_delete_ip_audit_rows_carry_the_user_4447(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    grp, _ = await _group(db_session, servers=0)
    subnet, scope = await _scope(db_session, grp)
    await _reservation(db_session, scope)
    await _row(db_session, subnet, OLD)
    scope_id = scope.id
    await db_session.commit()

    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}?permanent=true", headers=h)
    assert r.status_code == 204, r.text
    db_session.expire_all()
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "ip_address",
                    AuditLog.resource_display == OLD,
                    AuditLog.action == "delete",
                )
            )
        )
        .scalars()
        .all()
    )
    assert rows, "the scope delete wrote no ip_address delete audit row"
    assert all(a.user_id is not None and a.auth_source != "system" for a in rows), [
        (a.user_id, a.auth_source) for a in rows
    ]
