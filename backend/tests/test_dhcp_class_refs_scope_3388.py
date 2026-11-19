"""Generated PXE / phone classes stay defined for the pools that name them (#3388).

A PXE class is evaluated only in the scopes bound to its profile (#2731), so
which pool loses it depends on the pool's own scope, not on whether some other
scope still binds the profile. A phone class renders group-wide while its
profile is enabled and attached to an active scope, so disabling, deleting or
detaching the profile, or deleting / deactivating its last attached scope,
takes it from every pool that names it.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import (
    DHCPPhoneProfile,
    DHCPPhoneProfileScope,
    DHCPPool,
    DHCPScope,
)
from app.models.ipam import IPBlock, Subnet
from app.services.dhcp.config_bundle import build_config_bundle
from tests.test_dhcp_phone_profiles import _make_group_server_scope
from tests.test_dhcp_pxe_rule_ids_3374 import _m, _setup
from tests.test_dhcp_pxe_vendor_match_validation import _headers


async def _second_scope(db: AsyncSession, first: DHCPScope, octet: int = 21) -> DHCPScope:
    """Another active scope in ``first``'s group, on its own /24."""
    sub = await db.get(Subnet, first.subnet_id)
    assert sub is not None
    cidr = f"10.0.{octet}.0/24"
    block = IPBlock(name=f"blk{octet}", space_id=sub.space_id, network=cidr)
    db.add(block)
    await db.flush()
    subnet = Subnet(name=f"s{octet}", space_id=sub.space_id, block_id=block.id, network=cidr)
    db.add(subnet)
    await db.flush()
    sc = DHCPScope(
        name=f"scope-{octet}",
        group_id=first.group_id,
        subnet_id=subnet.id,
        is_active=True,
        lease_time=3600,
    )
    db.add(sc)
    await db.flush()
    return sc


async def _scope_bound_to(db: AsyncSession, profile_id: str) -> DHCPScope:
    sc = (
        await db.execute(select(DHCPScope).where(DHCPScope.pxe_profile_id == uuid.UUID(profile_id)))
    ).scalar_one()
    return sc


# ── PXE: the pool's own scope is the one that matters (#2731) ──────────────


async def test_unbinding_another_scope_is_allowed_but_the_pools_own_is_not(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, srv, prof, _rule, cls = await _setup(client, db_session)
    a = await _scope_bound_to(db_session, prof["id"])
    b = await _second_scope(db_session, a)
    b.pxe_profile_id = uuid.UUID(prof["id"])
    await db_session.commit()

    # B holds no pool naming the class: unbinding it takes nothing away.
    r = await client.put(f"/api/v1/dhcp/scopes/{b.id}", headers=h, json={"clear_pxe_profile": True})
    assert r.status_code == 200, r.text
    await db_session.refresh(b)
    assert b.pxe_profile_id is None

    # Re-bind B, then unbind A — the pool's own scope. B still binding the
    # profile does not help: Kea evaluates the class only where it is listed.
    b.pxe_profile_id = uuid.UUID(prof["id"])
    await db_session.commit()
    r = await client.put(f"/api/v1/dhcp/scopes/{a.id}", headers=h, json={"clear_pxe_profile": True})
    assert r.status_code == 409, r.text
    assert cls in r.json()["detail"]
    bundle = await build_config_bundle(db_session, srv)
    scope_a = next(s for s in bundle.scopes if s.subnet_cidr == "10.0.20.0/24")
    assert cls in scope_a.pxe_class_names


async def test_pool_in_a_scope_not_bound_to_the_profile_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, cls = await _setup(client, db_session)
    a = await _scope_bound_to(db_session, prof["id"])
    b = await _second_scope(db_session, a)
    await db_session.commit()
    body = {"start_ip": "10.0.21.10", "end_ip": "10.0.21.20", "pool_type": "dynamic"}
    r = await client.post(
        f"/api/v1/dhcp/scopes/{b.id}/pools", headers=h, json={**body, "class_restriction": cls}
    )
    assert r.status_code == 422, r.text
    assert "not one of them" in r.json()["detail"]


async def test_pool_naming_a_disabled_profiles_class_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, cls = await _setup(client, db_session)
    a = await _scope_bound_to(db_session, prof["id"])
    await db_session.execute(DHCPPool.__table__.update().values(class_restriction=None))
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json={"enabled": False}
    )
    assert r.status_code == 200, r.text
    body = {"start_ip": "10.0.20.100", "end_ip": "10.0.20.120", "pool_type": "dynamic"}
    r = await client.post(
        f"/api/v1/dhcp/scopes/{a.id}/pools", headers=h, json={**body, "class_restriction": cls}
    )
    assert r.status_code == 422, r.text
    assert "disabled" in r.json()["detail"]


async def test_rules_differing_only_in_kind_or_arch_order_are_duplicates(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, _cls = await _setup(client, db_session)
    url = f"/api/v1/dhcp/server-groups/{prof['group_id']}/pxe-profiles"
    chain = {**_m(20, 7, "b.efi"), "match_kind": "ipxe_chain"}
    r = await client.post(
        url,
        headers=h,
        json={"name": "d1", "next_server": "10.0.0.7", "matches": [_m(10, 7, "a.efi"), chain]},
    )
    assert r.status_code == 422, r.text
    two = {**_m(10, 7, "a.efi"), "arch_codes": [7, 9]}
    owt = {**_m(20, 7, "b.efi"), "arch_codes": [9, 7]}
    r = await client.post(
        url, headers=h, json={"name": "d2", "next_server": "10.0.0.7", "matches": [two, owt]}
    )
    assert r.status_code == 422, r.text
    # Different arch codes are different clients.
    r = await client.post(
        url,
        headers=h,
        json={"name": "d3", "next_server": "10.0.0.7", "matches": [_m(10, 7, "a"), _m(20, 9, "b")]},
    )
    assert r.status_code == 201, r.text


# ── Phone profiles ─────────────────────────────────────────────────────────


async def _phone_setup(client: AsyncClient, db: AsyncSession):
    """Profile attached to scope A only; a pool in scope B names its class."""
    h = await _headers(db)
    _grp, srv, a = await _make_group_server_scope(db)
    b = await _second_scope(db, a)
    prof = DHCPPhoneProfile(
        group_id=a.group_id,
        name="polycom",
        enabled=True,
        vendor_class_match="Polycom",
        option_set=[],
    )
    db.add(prof)
    await db.flush()
    db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=a.id))
    cls = f"voip-{str(prof.id)[:8]}"
    db.add(
        DHCPPool(
            scope_id=b.id,
            start_ip="10.0.21.10",
            end_ip="10.0.21.50",
            pool_type="dynamic",
            class_restriction=cls,
        )
    )
    await db.commit()
    return h, srv, prof, a, b, cls


async def _phone_class_rendered(db: AsyncSession, srv, cls: str) -> bool:
    bundle = await build_config_bundle(db, srv)
    return cls in {c.name for c in bundle.phone_classes}


async def test_phone_profile_disable_delete_detach_are_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, srv, prof, a, b, cls = await _phone_setup(client, db_session)
    url = f"/api/v1/dhcp/phone-profiles/{prof.id}"

    r = await client.put(url, headers=h, json={"enabled": False})
    assert r.status_code == 409, r.text
    assert cls in r.json()["detail"] and "10.0.21.10-10.0.21.50" in r.json()["detail"]

    r = await client.put(f"{url}/scopes", headers=h, json={"scope_ids": []})
    assert r.status_code == 409, r.text

    r = await client.delete(url, headers=h)
    assert r.status_code == 409, r.text
    assert await _phone_class_rendered(db_session, srv, cls)

    # Moving the attachment to the pool's own scope keeps the class rendered.
    r = await client.put(f"{url}/scopes", headers=h, json={"scope_ids": [str(b.id)]})
    assert r.status_code == 200, r.text
    assert await _phone_class_rendered(db_session, srv, cls)


async def test_deleting_or_deactivating_the_last_attached_scope_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, srv, _prof, a, _b, cls = await _phone_setup(client, db_session)

    r = await client.put(f"/api/v1/dhcp/scopes/{a.id}", headers=h, json={"enabled": False})
    assert r.status_code == 409, r.text
    assert cls in r.json()["detail"]

    r = await client.delete(f"/api/v1/dhcp/scopes/{a.id}", headers=h)
    assert r.status_code == 409, r.text
    assert await _phone_class_rendered(db_session, srv, cls)


async def test_deleting_an_attached_scope_is_allowed_while_another_stays(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, srv, prof, a, _b, cls = await _phone_setup(client, db_session)
    c = await _second_scope(db_session, a, octet=22)
    db_session.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=c.id))
    await db_session.commit()

    r = await client.delete(f"/api/v1/dhcp/scopes/{a.id}", headers=h)
    assert r.status_code == 204, r.text
    assert await _phone_class_rendered(db_session, srv, cls)


async def test_pool_naming_an_unrendered_phone_class_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _a, b, cls = await _phone_setup(client, db_session)
    url = f"/api/v1/dhcp/scopes/{b.id}/pools"
    body = {"start_ip": "10.0.21.100", "end_ip": "10.0.21.120", "pool_type": "dynamic"}
    r = await client.post(url, headers=h, json={**body, "class_restriction": cls})
    assert r.status_code == 201, r.text

    prof.enabled = False
    await db_session.commit()
    body = {"start_ip": "10.0.21.130", "end_ip": "10.0.21.140", "pool_type": "dynamic"}
    r = await client.post(url, headers=h, json={**body, "class_restriction": cls})
    assert r.status_code == 422, r.text
    assert "disabled" in r.json()["detail"]


async def test_copilot_delete_scope_preview_names_the_refusal(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.ai.operations_risky import DeleteScopeArgs, _preview_delete_scope

    _h, _srv, _prof, a, _b, cls = await _phone_setup(client, db_session)
    res = await _preview_delete_scope(db_session, None, DeleteScopeArgs(scope_id=a.id))  # type: ignore[arg-type]
    assert res.ok is False
    assert cls in res.detail


async def test_a_save_may_keep_a_stored_duplicate_but_not_add_one(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, _cls = await _setup(client, db_session)
    url = f"/api/v1/dhcp/pxe-profiles/{prof['id']}"
    rows = [
        {
            k: m[k]
            for k in ("priority", "match_kind", "vendor_class_match", "arch_codes", "boot_filename")
        }
        for m in prof["matches"]
    ]
    r = await client.put(url, headers=h, json={"matches": [*rows, {**rows[0], "priority": 99}]})
    assert r.status_code == 422, r.text
