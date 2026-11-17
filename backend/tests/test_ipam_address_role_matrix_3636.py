"""The everyday address paths stay open to the roles that had them (#3636).

#3636 puts every caller without type-level subnet write through the zone rule
on the address routes, and asks a delete grant covering the address before a
delete. These cases walk the built-in IPAM Editor and Address Set Editor roles,
subnet-scoped writers, holders of DNS grants and resource-bound API tokens
through create, Next available, Bulk allocate, an edit and a delete, so the
common path (an address in a subnet the caller may write, published into the
subnet's own zone) is not refused for anyone who could take it before.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.address_set import AddressSet
from app.models.auth import APIToken, Group, Role, User
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

IPAM_EDITOR = _BUILTIN_ROLES["IPAM Editor"][1]
ADDRESS_SET_EDITOR = _BUILTIN_ROLES["Address Set Editor"][1]


async def _owner(db: AsyncSession, permissions: list[dict]) -> User:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="u",
        hashed_password=hash_password("password123"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return user


async def _session(db: AsyncSession, permissions: list[dict]) -> dict[str, str]:
    user = await _owner(db, permissions)
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _token(db: AsyncSession, owner: User, grants: list[dict]) -> dict[str, str]:
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=grants,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.flush()
    return {"Authorization": f"Bearer {raw}"}


class World:
    subnet: Subnet
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
    db.add(w.subnet)
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
        start_address="10.0.5.100",
        end_address="10.0.5.199",
    )
    db.add(w.aset)
    await db.flush()
    return w


async def _walk_common_path(
    client: AsyncClient, db: AsyncSession, w: World, headers: dict[str, str], base: int
) -> None:
    """Create, Next available, Bulk allocate, an edit and a delete, all in the
    subnet's own zone and inside the address set."""
    sid = w.subnet.id
    own = str(w.own.id)
    # Create with no zone named: the subnet's own zone.
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        json={"address": f"10.0.5.{base}", "hostname": f"a{base}"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["forward_zone_id"] == own
    # Create naming the subnet's own zone.
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        json={"address": f"10.0.5.{base + 1}", "hostname": f"b{base}", "dns_zone_id": own},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    # Next available, with and without the zone.
    for i, extra in enumerate(({}, {"dns_zone_id": own})):
        r = await client.post(
            f"/api/v1/ipam/subnets/{sid}/next",
            json={"hostname": f"n{base}-{i}", **extra},
            headers=headers,
        )
        assert r.status_code == 201, r.text
    # Bulk allocate into the subnet's own zone, preview then commit.
    ba = {
        "range_start": f"10.0.5.{base + 5}",
        "range_end": f"10.0.5.{base + 6}",
        "hostname_template": f"bulk{base}-{{n}}",
        "dns_zone_id": own,
    }
    for path in ("bulk-allocate/preview", "bulk-allocate"):
        r = await client.post(f"/api/v1/ipam/subnets/{sid}/{path}", json=ba, headers=headers)
        assert r.status_code < 300, (path, r.text)
    # An edit re-saving the zone the row already has (the Edit dialog does).
    r = await client.put(
        f"/api/v1/ipam/addresses/{created['id']}",
        json={"description": "edited", "dns_zone_id": own},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    # And a delete.
    r = await client.delete(
        f"/api/v1/ipam/addresses/{created['id']}?permanent=true", headers=headers
    )
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "who",
    ["ipam_editor", "address_set_editor", "ipam_editor_subnet_token"],
)
async def test_common_path_stays_open(
    db_session: AsyncSession, client: AsyncClient, who: str
) -> None:
    w = await _world(db_session)
    if who == "ipam_editor":
        headers = await _session(db_session, IPAM_EDITOR)
    elif who == "address_set_editor":
        headers = await _session(db_session, ADDRESS_SET_EDITOR)
    else:
        # A token bound to the subnet. (One bound only to an address set is
        # refused the subnet routes by the token's own subnet scope.)
        owner = await _owner(db_session, IPAM_EDITOR)
        headers = await _token(
            db_session,
            owner,
            [{"action": "admin", "resource_type": "subnet", "resource_id": str(w.subnet.id)}],
        )
    await db_session.commit()
    await _walk_common_path(client, db_session, w, headers, 110)


@pytest.mark.asyncio
async def test_a_dns_grant_on_the_named_zone_still_admits_it(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The zone rule lets a caller name a zone it holds write on, beyond the
    subnet's own: a set holder or a subnet-scoped writer with a DNS grant."""
    w = await _world(db_session)
    zone_grant = {"action": "write", "resource_type": "dns_zone", "resource_id": str(w.foreign.id)}
    set_holder = await _session(db_session, ADDRESS_SET_EDITOR + [zone_grant])
    sid = str(w.subnet.id)
    scoped = await _session(
        db_session,
        [
            {"action": "read", "resource_type": "subnet", "resource_id": sid},
            {"action": "write", "resource_type": "subnet", "resource_id": sid},
            zone_grant,
        ],
    )
    await db_session.commit()
    foreign = str(w.foreign.id)
    for n, headers in ((120, set_holder), (121, scoped)):
        r = await client.post(
            f"/api/v1/ipam/subnets/{sid}/addresses",
            json={"address": f"10.0.5.{n}", "hostname": f"f{n}", "dns_zone_id": foreign},
            headers=headers,
        )
        assert r.status_code == 201, r.text
        assert r.json()["forward_zone_id"] == foreign
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        json={"hostname": "fnext", "dns_zone_id": foreign},
        headers=set_holder,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_alias_delete_needs_a_delete_grant_covering_the_address(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """DELETE /addresses/{id}/aliases/{record_id} rides the same gate as the
    address delete: a delete grant on one set must not reach every address."""
    w = await _world(db_session)
    inside = IPAddress(subnet_id=w.subnet.id, address="10.0.5.130", status="allocated")
    outside = IPAddress(subnet_id=w.subnet.id, address="10.0.5.20", status="allocated")
    db_session.add_all([inside, outside])
    mixed = await _session(
        db_session,
        [
            {"action": "read", "resource_type": "subnet"},
            {"action": "write", "resource_type": "subnet"},
            {"action": "delete", "resource_type": "address_set", "resource_id": str(w.aset.id)},
        ],
    )
    await db_session.commit()
    missing = uuid.uuid4()
    r = await client.delete(f"/api/v1/ipam/addresses/{outside.id}/aliases/{missing}", headers=mixed)
    assert r.status_code == 403, r.text
    # Inside the set the delete grant covers the address, so the handler goes
    # on to look the alias up.
    r = await client.delete(f"/api/v1/ipam/addresses/{inside.id}/aliases/{missing}", headers=mixed)
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_bulk_delete_says_why_a_row_was_skipped(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    w = await _world(db_session)
    outside = IPAddress(subnet_id=w.subnet.id, address="10.0.5.20", status="allocated")
    db_session.add(outside)
    mixed = await _session(
        db_session,
        [
            {"action": "read", "resource_type": "subnet"},
            {"action": "write", "resource_type": "subnet"},
            {"action": "delete", "resource_type": "address_set", "resource_id": str(w.aset.id)},
        ],
    )
    await db_session.commit()
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        json={"ip_ids": [str(outside.id)], "permanent": True},
        headers=mixed,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deleted_count"] == 0
    assert "No delete permission" in body["skipped_reasons"][str(outside.id)]


@pytest.mark.asyncio
async def test_a_delete_grant_scoped_to_one_subnet_is_refused_at_the_gate(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The console's per-row Delete takes the subnet half at the type level
    because the gate does: the delete routes are not on the subnet instance
    allow-list, so a grant naming the subnet does not reach them."""
    w = await _world(db_session)
    row = IPAddress(subnet_id=w.subnet.id, address="10.0.5.20", status="allocated")
    db_session.add(row)
    headers = await _session(
        db_session,
        [
            {"action": "read", "resource_type": "subnet"},
            {"action": "write", "resource_type": "subnet"},
            {"action": "delete", "resource_type": "subnet", "resource_id": str(w.subnet.id)},
        ],
    )
    await db_session.commit()
    r = await client.delete(f"/api/v1/ipam/addresses/{row.id}?permanent=true", headers=headers)
    assert r.status_code == 403, r.text
