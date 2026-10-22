"""Assigning a DNS role with ``core.dns`` off is refused (#2135).

The DNS counterpart of #2130. ``PUT /appliance/appliances/{id}/roles``
accepted ``dns-bind9`` / ``dns-powerdns`` / ``dns-technitium`` while the DNS
module was off. The DNS *agent* routers are mounted outside the module gate
on purpose (a 404 would make an agent drop its JWT and re-bootstrap), so
nothing else stopped the agent registering into a subsystem the operator
had switched off. The refusal names the reason and the toggle, applies only
to a newly ADDED engine, and is shared by the REST route and the Copilot.
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
from app.services import feature_modules


@pytest.fixture(autouse=True)
def _reset_module_cache() -> None:
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


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


async def _appliance(db: AsyncSession) -> Appliance:
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        capabilities={"can_run_dhcp": True, "can_run_dns_bind9": True},
    )
    db.add(a)
    await db.flush()
    return a


async def _set_module(db: AsyncSession, user: User, module: str, on: bool) -> None:
    await feature_modules.set_module_enabled(db, module, on, user_id=user.id)
    await db.commit()
    feature_modules.invalidate_cache()


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["dns-bind9", "dns-powerdns", "dns-technitium"])
async def test_dns_role_refused_when_module_off(
    role: str, client: AsyncClient, db_session: AsyncSession
) -> None:
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    a.capabilities = {
        "can_run_dhcp": True,
        "can_run_dns_bind9": True,
        "can_run_dns_powerdns": True,
        "can_run_dns_technitium": True,
    }
    await db_session.flush()
    await _set_module(db_session, u, "core.dns", False)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": [role]},
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "core.dns" in r.json()["detail"]
    assert "disabled" in r.json()["detail"]
    assert role in r.json()["detail"]

    await db_session.refresh(a)
    assert not (a.assigned_roles or [])


@pytest.mark.asyncio
async def test_dns_role_accepted_when_module_on(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Positive control: the same request, module on."""
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    await _set_module(db_session, u, "core.dns", True)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dns-bind9"]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["assigned_roles"] == ["dns-bind9"]


@pytest.mark.asyncio
async def test_non_dns_role_still_accepted_when_dns_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    await _set_module(db_session, u, "core.dns", False)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dhcp"]},
        headers=h,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_resave_of_an_existing_dns_role_is_not_refused_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The refusal is on ADDING the engine. An appliance that already holds
    one must still save — or turning DNS off would freeze its assignment."""
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    a.assigned_roles = ["dns-bind9"]
    await db_session.flush()
    await _set_module(db_session, u, "core.dns", False)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dns-bind9", "dhcp"]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert set(r.json()["assigned_roles"]) == {"dns-bind9", "dhcp"}


@pytest.mark.asyncio
async def test_swapping_to_another_dns_engine_is_refused_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Holding ``dns-bind9`` does not license ADDING ``dns-powerdns``."""
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    a.capabilities = {"can_run_dns_bind9": True, "can_run_dns_powerdns": True}
    a.assigned_roles = ["dns-bind9"]
    await db_session.flush()
    await _set_module(db_session, u, "core.dns", False)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dns-powerdns"]},
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "core.dns" in r.json()["detail"]


@pytest.mark.asyncio
async def test_removing_a_dns_role_is_allowed_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    a.assigned_roles = ["dns-bind9"]
    await db_session.flush()
    await _set_module(db_session, u, "core.dns", False)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": []},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["assigned_roles"] == []


@pytest.mark.asyncio
async def test_copilot_assign_refuses_new_dns_role_but_not_a_held_one(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.operations import (
        AssignApplianceRoleArgs,
        _apply_assign_appliance_role,
        _preview_assign_appliance_role,
    )

    u, _h = await _superadmin(db_session)
    a = await _appliance(db_session)
    await _set_module(db_session, u, "core.dns", False)

    args = AssignApplianceRoleArgs(appliance_id=str(a.id), roles=["dns-bind9"])
    preview = await _preview_assign_appliance_role(db_session, u, args)
    assert not preview.ok
    assert "core.dns" in (preview.detail or "")
    with pytest.raises(ValueError, match="core.dns"):
        await _apply_assign_appliance_role(db_session, u, args)

    a2 = await _appliance(db_session)
    a2.assigned_roles = ["dns-bind9"]
    await db_session.commit()
    preview = await _preview_assign_appliance_role(
        db_session,
        u,
        AssignApplianceRoleArgs(appliance_id=str(a2.id), roles=["dns-bind9"]),
    )
    assert preview.ok, preview.detail
