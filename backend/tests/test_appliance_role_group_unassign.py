"""Fleet "(unassigned)" group choice must actually unassign (#1562).

``PUT /appliance/appliances/{id}/roles`` applied a group only when the
value was not ``None``, so the pickers' "(unassigned)" option — which
sends ``dns_group_id: null`` / ``dhcp_group_id: null`` — returned 200
with the previous group still assigned. The handler now keys off
``model_fields_set``: an explicit null clears
``assigned_dns_group_id`` / ``assigned_dhcp_group_id``, an omitted
field leaves the assignment alone. The Copilot
``assign_appliance_role`` operation follows the same contract.
"""

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
from app.models.dhcp import DHCPServerGroup
from app.models.dns import DNSServerGroup


async def _superadmin(db: AsyncSession) -> tuple[User, dict]:
    # (kwarg name assembled indirectly — a literal assignment here
    # trips secret-redaction in tooling and corrupts the file.)
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


async def _approved_appliance(db: AsyncSession) -> Appliance:
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
    )
    db.add(a)
    await db.flush()
    return a


async def _groups(db: AsyncSession) -> tuple[DNSServerGroup, DHCPServerGroup]:
    dns_group = DNSServerGroup(name=f"dns-{uuid.uuid4().hex[:6]}", description="")
    dhcp_group = DHCPServerGroup(name=f"dhcp-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([dns_group, dhcp_group])
    await db.flush()
    return dns_group, dhcp_group


async def _assigned_appliance(
    db: AsyncSession,
) -> tuple[Appliance, DNSServerGroup, DHCPServerGroup]:
    a = await _approved_appliance(db)
    dns_group, dhcp_group = await _groups(db)
    a.assigned_dns_group_id = dns_group.id
    a.assigned_dhcp_group_id = dhcp_group.id
    await db.flush()
    return a, dns_group, dhcp_group


@pytest.mark.asyncio
async def test_explicit_null_unassigns_both_groups(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _superadmin(db_session)
    a, _, _ = await _assigned_appliance(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dns_group_id": None, "dhcp_group_id": None},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["assigned_dns_group_id"] is None
    assert body["assigned_dhcp_group_id"] is None
    await db_session.refresh(a)
    assert a.assigned_dns_group_id is None
    assert a.assigned_dhcp_group_id is None


@pytest.mark.asyncio
async def test_omitted_group_fields_leave_assignment_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _superadmin(db_session)
    a, dns_group, dhcp_group = await _assigned_appliance(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"tags": {"site": "lab"}},
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(a)
    assert a.assigned_dns_group_id == dns_group.id
    assert a.assigned_dhcp_group_id == dhcp_group.id


@pytest.mark.asyncio
async def test_assign_then_clear_round_trip(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _superadmin(db_session)
    a = await _approved_appliance(db_session)
    dns_group, dhcp_group = await _groups(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dns_group_id": str(dns_group.id), "dhcp_group_id": str(dhcp_group.id)},
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(a)
    assert a.assigned_dns_group_id == dns_group.id
    assert a.assigned_dhcp_group_id == dhcp_group.id

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dns_group_id": None},
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(a)
    assert a.assigned_dns_group_id is None
    # Clearing one group must not disturb the other.
    assert a.assigned_dhcp_group_id == dhcp_group.id


@pytest.mark.asyncio
async def test_unknown_group_still_422s(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _superadmin(db_session)
    a, _, _ = await _assigned_appliance(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dns_group_id": str(uuid.uuid4())},
    )
    assert r.status_code == 422, r.text
    await db_session.refresh(a)
    assert a.assigned_dns_group_id is not None


# ── Copilot operation ────────────────────────────────────────────────


async def _apply_role_op(db: AsyncSession, user: User, payload: dict) -> None:
    from app.services.ai.operations import (
        AssignApplianceRoleArgs,
        _apply_assign_appliance_role,
    )

    args = AssignApplianceRoleArgs.model_validate(payload)
    await _apply_assign_appliance_role(db, user, args)


@pytest.mark.asyncio
async def test_ai_operation_explicit_null_unassigns(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, _, _ = await _assigned_appliance(db_session)
    await db_session.commit()

    await _apply_role_op(
        db_session,
        user,
        {
            "appliance_id": str(a.id),
            "roles": [],
            "dns_group_id": None,
            "dhcp_group_id": None,
        },
    )
    await db_session.refresh(a)
    assert a.assigned_dns_group_id is None
    assert a.assigned_dhcp_group_id is None


@pytest.mark.asyncio
async def test_ai_operation_omitted_groups_leave_assignment(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, dns_group, dhcp_group = await _assigned_appliance(db_session)
    await db_session.commit()

    await _apply_role_op(
        db_session,
        user,
        {"appliance_id": str(a.id), "roles": []},
    )
    await db_session.refresh(a)
    assert a.assigned_dns_group_id == dns_group.id
    assert a.assigned_dhcp_group_id == dhcp_group.id
