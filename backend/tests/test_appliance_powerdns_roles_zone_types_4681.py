"""An appliance engine change to PowerDNS keeps its DNS group, so the roles
save must refuse a group holding a forward or stub zone (#4681), with the
same wording as adding a PowerDNS server to that group (#4570)."""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone


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


async def _setup(db: AsyncSession, zone_type: str | None) -> tuple[Appliance, DNSServerGroup]:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    if zone_type:
        db.add(
            DNSZone(
                group_id=g.id,
                name="fwd.example.com.",
                zone_type=zone_type,
                kind="forward",
                primary_ns="ns1.example.",
                admin_email="a.example.",
            )
        )
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        capabilities={"can_run_dns_bind9": True, "can_run_dns_powerdns": True},
        assigned_roles=["dns-bind9"],
        assigned_dns_group_id=g.id,
    )
    db.add(a)
    await db.flush()
    await db.commit()
    return a, g


@pytest.mark.asyncio
@pytest.mark.parametrize("zone_type", ["forward", "stub"])
async def test_roles_save_to_powerdns_refused_for_group_zone(
    zone_type: str, client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, h = await _superadmin(db_session)
    a, g = await _setup(db_session, zone_type)
    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles", json={"roles": ["dns-powerdns"]}, headers=h
    )
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert g.name in detail and "fwd.example.com" in detail and zone_type in detail


@pytest.mark.asyncio
async def test_roles_save_to_powerdns_ok_without_such_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, h = await _superadmin(db_session)
    a, _g = await _setup(db_session, None)
    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles", json={"roles": ["dns-powerdns"]}, headers=h
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_bind9_to_bind9_unaffected(client: AsyncClient, db_session: AsyncSession) -> None:
    _u, h = await _superadmin(db_session)
    a, _g = await _setup(db_session, "forward")
    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dns-bind9"]},
        headers=h,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_copilot_assign_refuses_powerdns_for_group_zone(db_session: AsyncSession) -> None:
    from app.services.ai.operations import (
        AssignApplianceRoleArgs,
        _apply_assign_appliance_role,
        _preview_assign_appliance_role,
    )

    u, _h = await _superadmin(db_session)
    a, g = await _setup(db_session, "forward")
    args = AssignApplianceRoleArgs(appliance_id=str(a.id), roles=["dns-powerdns"])
    preview = await _preview_assign_appliance_role(db_session, u, args)
    assert not preview.ok
    assert g.name in (preview.detail or "") and "fwd.example.com" in (preview.detail or "")
    with pytest.raises(ValueError, match="fwd.example.com"):
        await _apply_assign_appliance_role(db_session, u, args)
    ok = await _preview_assign_appliance_role(
        db_session, u, AssignApplianceRoleArgs(appliance_id=str(a.id), roles=["dns-bind9"])
    )
    assert ok.ok, ok.detail
