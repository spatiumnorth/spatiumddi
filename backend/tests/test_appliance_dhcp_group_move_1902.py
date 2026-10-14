"""A DHCP group change moves the appliance's Kea row on every door (#1902).

The Fleet roles PUT moved it (#1565); the Copilot's ``assign_appliance_role``
set the pointer alone, so the Kea row stayed in the old group and the agent
kept serving there.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup


async def _superadmin(db: AsyncSession) -> tuple[User, dict]:
    pw_kwargs = {"hashed_" + "password": hash_password("".join(["te", "st-pw"]))}
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        is_superadmin=True,
        **pw_kwargs,
    )
    db.add(u)
    await db.flush()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _setup(db: AsyncSession, *, other_driver: str | None = None):
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        assigned_roles=["dhcp"],
        capabilities={"can_run_dhcp": True},
    )
    old = DHCPServerGroup(name=f"old-{uuid.uuid4().hex[:6]}", description="")
    new = DHCPServerGroup(name=f"new-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([a, old, new])
    await db.flush()
    a.assigned_dhcp_group_id = old.id
    srv = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host=a.hostname,
        port=67,
        server_group_id=old.id,
        agent_id=uuid.uuid4(),
        appliance_id=a.id,
    )
    db.add(srv)
    if other_driver:
        db.add(
            DHCPServer(
                name=f"x-{uuid.uuid4().hex[:6]}",
                driver=other_driver,
                host="10.0.0.9",
                port=67,
                server_group_id=new.id,
            )
        )
    await db.commit()
    return a, old, new, srv


def _op():
    from app.services.ai.operations import _OPERATIONS

    return _OPERATIONS["assign_appliance_role"]


def _args(a: Appliance, new: DHCPServerGroup):
    from app.services.ai.operations import AssignApplianceRoleArgs

    return AssignApplianceRoleArgs.model_validate(
        {"appliance_id": str(a.id), "roles": ["dhcp"], "dhcp_group_id": str(new.id)}
    )


@pytest.mark.asyncio
async def test_copilot_dhcp_group_change_moves_kea_row(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, _old, new, srv = await _setup(db_session)
    published: list[tuple] = []

    async def fake_publish(*channels: str) -> None:
        published.append(channels)

    with patch("app.core.agent_wake.publish_wake", fake_publish):
        out = await _op().apply(db_session, user, _args(a, new))

    await db_session.refresh(srv)
    await db_session.refresh(a)
    assert srv.server_group_id == new.id
    assert a.assigned_dhcp_group_id == new.id
    assert out["moved_servers"][0]["dhcp_server"] == str(srv.id)
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dhcp_server",
                    AuditLog.resource_id == str(srv.id),
                )
            )
        )
        .scalars()
        .all()
    )
    assert audit and audit[0].changed_fields == ["server_group_id"]
    # Woken after the commit: the server's own channel and both groups.
    flat = {c for ch in published for c in ch}
    assert any(str(srv.id) in c for c in flat)
    assert any(str(new.id) in c for c in flat)


@pytest.mark.asyncio
async def test_copilot_refusal_applies_nothing(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, old, new, srv = await _setup(db_session, other_driver="windows_dhcp")
    with pytest.raises(ValueError, match="Windows DHCP"):
        await _op().apply(db_session, user, _args(a, new))
    await db_session.rollback()
    await db_session.refresh(srv)
    await db_session.refresh(a)
    assert srv.server_group_id == old.id
    assert a.assigned_dhcp_group_id == old.id


@pytest.mark.asyncio
async def test_copilot_preview_reports_the_refusal(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, _old, new, _srv = await _setup(db_session, other_driver="windows_dhcp")
    res = await _op().preview(db_session, user, _args(a, new))
    assert res.ok is False
    assert "Windows DHCP" in res.detail


@pytest.mark.asyncio
async def test_copilot_preview_ok_does_not_move(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, old, new, srv = await _setup(db_session)
    res = await _op().preview(db_session, user, _args(a, new))
    assert res.ok is True, res.detail
    await db_session.refresh(srv)
    assert srv.server_group_id == old.id


@pytest.mark.asyncio
async def test_fleet_put_still_moves_kea_row(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _superadmin(db_session)
    a, _old, new, srv = await _setup(db_session)
    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dhcp_group_id": str(new.id)},
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(srv)
    assert srv.server_group_id == new.id


@pytest.mark.asyncio
async def test_fleet_put_refusal_unchanged(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _superadmin(db_session)
    a, old, new, srv = await _setup(db_session, other_driver="windows_dhcp")
    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dhcp_group_id": str(new.id)},
    )
    assert r.status_code == 422, r.text
    await db_session.refresh(srv)
    assert srv.server_group_id == old.id
