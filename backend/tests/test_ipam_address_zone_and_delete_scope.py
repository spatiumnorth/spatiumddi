"""Address routes hold every caller without type-level subnet write to the zone
rule (#2438), and a delete needs a delete grant covering the address."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.address_set import AddressSet
from app.models.auth import Group, Role, User
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

SET_START, SET_END = "10.0.5.100", "10.0.5.150"


async def _user(
    db: AsyncSession, permissions: list[dict], *, superadmin: bool = False
) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="u",
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


class World:
    subnet: Subnet
    other: Subnet
    aset: AddressSet
    own: DNSZone
    foreign: DNSZone


async def _world(db: AsyncSession) -> World:
    w = World()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    w.subnet = Subnet(space_id=space.id, block_id=block.id, network="10.0.5.0/24", name="x")
    w.other = Subnet(space_id=space.id, block_id=block.id, network="10.0.6.0/24", name="y")
    db.add_all([w.subnet, w.other])
    await db.flush()
    tag = uuid.uuid4().hex[:6]
    g1 = DNSServerGroup(name=f"g1-{tag}", description="")
    g2 = DNSServerGroup(name=f"g2-{tag}", description="")
    db.add_all([g1, g2])
    await db.flush()
    w.own = DNSZone(group_id=g1.id, name=f"own-{tag}.test.", kind="forward")
    w.foreign = DNSZone(group_id=g2.id, name=f"foreign-{tag}.test.", kind="forward")
    db.add_all([w.own, w.foreign])
    await db.flush()
    w.subnet.dns_zone_id = str(w.own.id)
    w.subnet.dns_inherit_settings = False
    w.aset = AddressSet(
        name="slice",
        subnet_id=w.subnet.id,
        range_kind="contiguous",
        start_address=SET_START,
        end_address=SET_END,
    )
    db.add(w.aset)
    await db.flush()
    return w


def _set_writer(w: World) -> list[dict]:
    # Shaped like the built-in Address Set Editor: no subnet or DNS grant.
    return [{"action": "admin", "resource_type": "address_set"}]


def _subnet_scoped(w: World) -> list[dict]:
    sid = str(w.subnet.id)
    return [
        {"action": "read", "resource_type": "subnet", "resource_id": sid},
        {"action": "write", "resource_type": "subnet", "resource_id": sid},
    ]


_UNSCOPED = [
    {"action": "read", "resource_type": "subnet"},
    {"action": "write", "resource_type": "subnet"},
]


async def _roles(db: AsyncSession, w: World) -> dict[str, dict[str, str]]:
    return {
        "set": await _user(db, _set_writer(w)),
        "scoped": await _user(db, _subnet_scoped(w)),
        "unscoped": await _user(db, _UNSCOPED),
        "super": await _user(db, [], superadmin=True),
    }


# ── Zone check ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_address_zone_check_covers_every_non_unscoped_caller(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    w = await _world(db_session)
    roles = await _roles(db_session, w)
    await db_session.commit()
    url = f"/api/v1/ipam/subnets/{w.subnet.id}/addresses"

    def body(n: int, **kw: object) -> dict:
        # Inside the address set, so only the zone decides the answer.
        return {"address": f"10.0.5.{100 + n}", "hostname": f"h{n}", **kw}

    foreign = {"dns_zone_id": str(w.foreign.id)}
    r = await client.post(url, json=body(1, **foreign), headers=roles["set"])
    assert r.status_code == 403, r.text
    r = await client.post(
        url, json=body(2, extra_zone_ids=[str(w.foreign.id)]), headers=roles["set"]
    )
    assert r.status_code == 403, r.text
    r = await client.post(url, json=body(3, **foreign), headers=roles["scoped"])
    assert r.status_code == 403, r.text
    # The subnet's own zone is fine for the set holder.
    r = await client.post(url, json=body(4, dns_zone_id=str(w.own.id)), headers=roles["set"])
    assert r.status_code == 201, r.text
    # Holders of the type-level write and superadmins publish where they name.
    for n, who in ((5, "unscoped"), (6, "super")):
        r = await client.post(url, json=body(n, **foreign), headers=roles[who])
        assert r.status_code == 201, (who, r.text)


@pytest.mark.asyncio
async def test_next_ip_zone_check_covers_every_non_unscoped_caller(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    w = await _world(db_session)
    roles = await _roles(db_session, w)
    await db_session.commit()
    url = f"/api/v1/ipam/subnets/{w.subnet.id}/next"
    foreign = {"hostname": "n1", "dns_zone_id": str(w.foreign.id)}

    for who in ("set", "scoped"):
        r = await client.post(url, json=foreign, headers=roles[who])
        assert r.status_code == 403, (who, r.text)
    r = await client.post(
        url,
        json={"hostname": "n2", "extra_zone_ids": [str(w.foreign.id)]},
        headers=roles["set"],
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        url, json={"hostname": "n3", "dns_zone_id": str(w.own.id)}, headers=roles["set"]
    )
    assert r.status_code == 201, r.text
    assert SET_START <= r.json()["address"] <= SET_END
    for who in ("unscoped", "super"):
        r = await client.post(url, json={**foreign, "hostname": f"n-{who}"}, headers=roles[who])
        assert r.status_code == 201, (who, r.text)


@pytest.mark.asyncio
async def test_other_address_routes_hold_the_same_zone_rule(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    w = await _world(db_session)
    roles = await _roles(db_session, w)
    row = IPAddress(subnet_id=w.subnet.id, address="10.0.5.110", status="allocated")
    db_session.add(row)
    await db_session.commit()
    foreign = str(w.foreign.id)

    # Editing an address's zone.
    r = await client.put(
        f"/api/v1/ipam/addresses/{row.id}", json={"dns_zone_id": foreign}, headers=roles["set"]
    )
    assert r.status_code == 403, r.text
    # Bulk allocate, preview and commit.
    ba = {
        "range_start": "10.0.5.120",
        "range_end": "10.0.5.122",
        "hostname_template": "bulk-{n}",
        "dns_zone_id": foreign,
    }
    for path in ("bulk-allocate/preview", "bulk-allocate"):
        r = await client.post(
            f"/api/v1/ipam/subnets/{w.subnet.id}/{path}", json=ba, headers=roles["set"]
        )
        assert r.status_code == 403, (path, r.text)
    # Bulk edit skips the row rather than moving it into the foreign zone.
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        json={"ip_ids": [str(row.id)], "changes": {"dns_zone_id": foreign}},
        headers=roles["set"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["updated_count"] == 0
    # An unscoped writer may still name the zone on an edit.
    r = await client.put(
        f"/api/v1/ipam/addresses/{row.id}", json={"dns_zone_id": foreign}, headers=roles["unscoped"]
    )
    assert r.status_code == 200, r.text


# ── Delete ───────────────────────────────────────────────────────────────────


async def _addresses(db: AsyncSession, w: World) -> tuple[IPAddress, IPAddress, IPAddress]:
    inside = IPAddress(subnet_id=w.subnet.id, address="10.0.5.110", status="allocated")
    outside = IPAddress(subnet_id=w.subnet.id, address="10.0.5.20", status="allocated")
    elsewhere = IPAddress(subnet_id=w.other.id, address="10.0.6.20", status="allocated")
    db.add_all([inside, outside, elsewhere])
    await db.commit()
    return inside, outside, elsewhere


@pytest.mark.asyncio
async def test_delete_needs_a_delete_grant_covering_the_address(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    w = await _world(db_session)
    inside, outside, elsewhere = await _addresses(db_session, w)
    # write on every subnet, but delete only on one address set.
    mixed = await _user(
        db_session,
        [
            {"action": "read", "resource_type": "subnet"},
            {"action": "write", "resource_type": "subnet"},
            {"action": "delete", "resource_type": "address_set", "resource_id": str(w.aset.id)},
        ],
    )
    set_editor = await _user(db_session, _set_writer(w))
    deleter = await _user(
        db_session,
        _UNSCOPED + [{"action": "delete", "resource_type": "subnet"}],
    )
    await db_session.commit()

    for row in (outside, elsewhere):
        r = await client.delete(f"/api/v1/ipam/addresses/{row.id}?permanent=true", headers=mixed)
        assert r.status_code == 403, r.text
    # The set editor (admin on sets) reaches only its set.
    r = await client.delete(
        f"/api/v1/ipam/addresses/{outside.id}?permanent=true", headers=set_editor
    )
    assert r.status_code == 403, r.text
    r = await client.delete(f"/api/v1/ipam/addresses/{inside.id}?permanent=true", headers=mixed)
    assert r.status_code == 204, r.text
    # Delete on the subnet reaches every address in it.
    r = await client.delete(f"/api/v1/ipam/addresses/{outside.id}?permanent=true", headers=deleter)
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
async def test_bulk_delete_skips_rows_without_a_covering_delete_grant(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    w = await _world(db_session)
    inside, outside, elsewhere = await _addresses(db_session, w)
    mixed = await _user(
        db_session,
        [
            {"action": "read", "resource_type": "subnet"},
            {"action": "write", "resource_type": "subnet"},
            {"action": "delete", "resource_type": "address_set", "resource_id": str(w.aset.id)},
        ],
    )
    superadmin = await _user(db_session, [], superadmin=True)
    await db_session.commit()

    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        json={"ip_ids": [str(i.id) for i in (inside, outside, elsewhere)], "permanent": True},
        headers=mixed,
    )
    assert r.status_code == 200, r.text
    assert r.json()["deleted_count"] == 1
    assert sorted(r.json()["skipped"]) == sorted([str(outside.id), str(elsewhere.id)])
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        json={"ip_ids": [str(outside.id), str(elsewhere.id)], "permanent": True},
        headers=superadmin,
    )
    assert r.status_code == 200, r.text
    assert r.json()["deleted_count"] == 2
