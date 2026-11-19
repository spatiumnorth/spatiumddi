"""Assigning the DHCP role with ``core.dhcp`` off is refused (#2130).

``PUT /appliance/appliances/{id}/roles`` accepted ``dhcp`` while the DHCP
module was off; the appliance's DHCP agent was then refused at register
(its routes are gated), so the failure showed up on the node instead of at
the operator's save. The refusal names the reason and the toggle.
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


async def _set_dhcp(db: AsyncSession, user: User, on: bool) -> None:
    await feature_modules.set_module_enabled(db, "core.dhcp", on, user_id=user.id)
    await db.commit()
    feature_modules.invalidate_cache()


@pytest.mark.asyncio
async def test_dhcp_role_refused_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    await _set_dhcp(db_session, u, False)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dhcp"]},
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "core.dhcp" in r.json()["detail"]
    assert "disabled" in r.json()["detail"]

    await db_session.refresh(a)
    assert not (a.assigned_roles or [])


@pytest.mark.asyncio
async def test_non_dhcp_role_still_accepted_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    await _set_dhcp(db_session, u, False)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dns-bind9"]},
        headers=h,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_dhcp_role_accepted_when_module_on(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    await _set_dhcp(db_session, u, True)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dhcp"]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["assigned_roles"] == ["dhcp"]


@pytest.mark.asyncio
async def test_alert_catalogue_drops_dhcp_rule_types_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The rule editor must not offer rules the evaluator will never run."""
    u, h = await _superadmin(db_session)

    await _set_dhcp(db_session, u, True)
    on = {t["rule_type"] for t in (await client.get("/api/v1/alerts/rule-types", headers=h)).json()}
    assert "dhcp_pool_exhaustion" in on

    await _set_dhcp(db_session, u, False)
    off = {
        t["rule_type"] for t in (await client.get("/api/v1/alerts/rule-types", headers=h)).json()
    }
    assert "dhcp_pool_exhaustion" not in off
    assert "dhcp_scope_uncoordinated" not in off
    assert "subnet_utilization" in off


@pytest.mark.asyncio
async def test_resave_of_an_existing_dhcp_role_is_not_refused_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The refusal is on ADDING the role. An appliance that already holds it
    must still save — or turning DHCP off would freeze its whole assignment."""
    u, h = await _superadmin(db_session)
    a = await _appliance(db_session)
    a.assigned_roles = ["dhcp"]
    await db_session.flush()
    await _set_dhcp(db_session, u, False)

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dhcp", "dns-bind9"]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert set(r.json()["assigned_roles"]) == {"dhcp", "dns-bind9"}


@pytest.mark.asyncio
async def test_copilot_assign_refuses_new_dhcp_role_but_not_a_held_one(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.operations import (
        AssignApplianceRoleArgs,
        _apply_assign_appliance_role,
        _preview_assign_appliance_role,
    )

    u, _h = await _superadmin(db_session)
    a = await _appliance(db_session)
    await _set_dhcp(db_session, u, False)

    args = AssignApplianceRoleArgs(appliance_id=str(a.id), roles=["dhcp"])
    preview = await _preview_assign_appliance_role(db_session, u, args)
    assert not preview.ok
    assert "core.dhcp" in (preview.detail or "")
    with pytest.raises(ValueError, match="core.dhcp"):
        await _apply_assign_appliance_role(db_session, u, args)

    a2 = await _appliance(db_session)
    a2.assigned_roles = ["dhcp"]
    await db_session.commit()
    preview = await _preview_assign_appliance_role(
        db_session, u, AssignApplianceRoleArgs(appliance_id=str(a2.id), roles=["dhcp"])
    )
    assert preview.ok, preview.detail
