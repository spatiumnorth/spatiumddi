"""#2438: a grant scoped to ONE subnet reaches that subnet and its children, nothing else."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, Group, Role, User
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.ownership import Customer


async def _user(db: AsyncSession, permissions: list[dict]) -> dict[str, str]:
    user = await _make_user(db, permissions)
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _make_user(db: AsyncSession, permissions: list[dict]) -> User:
    user = User(
        username=f"sc-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="scoped",
        hashed_password=hash_password("password123"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return user


async def _two_subnets(db: AsyncSession) -> tuple[Subnet, Subnet, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    other = IPBlock(space_id=space.id, network="10.9.0.0/16", name="b2")
    db.add_all([block, other])
    await db.flush()
    x = Subnet(space_id=space.id, block_id=block.id, network="10.0.5.0/24", name="x")
    y = Subnet(space_id=space.id, block_id=block.id, network="10.0.6.0/24", name="y")
    db.add_all([x, y])
    await db.commit()
    return x, y, other


def _rw(x: Subnet) -> list[dict]:
    return [
        {"action": "read", "resource_type": "subnet", "resource_id": str(x.id)},
        {"action": "write", "resource_type": "subnet", "resource_id": str(x.id)},
    ]


@pytest.mark.asyncio
async def test_scoped_holder_reads_and_edits_only_its_subnet(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, y, _o = await _two_subnets(db_session)
    h = await _user(db_session, _rw(x))
    await db_session.commit()

    assert (await client.get(f"/api/v1/ipam/subnets/{x.id}", headers=h)).status_code == 200
    r = await client.put(f"/api/v1/ipam/subnets/{x.id}", json={"description": "mine"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["description"] == "mine"
    assert (
        await client.get(f"/api/v1/ipam/subnets/{x.id}/addresses", headers=h)
    ).status_code == 200
    c = await client.post(
        f"/api/v1/ipam/subnets/{x.id}/addresses",
        json={"address": "10.0.5.20", "hostname": "h1"},
        headers=h,
    )
    assert c.status_code == 201, c.text
    lst = await client.get("/api/v1/ipam/subnets", headers=h)
    assert lst.status_code == 200
    assert [s["id"] for s in lst.json()] == [str(x.id)]


@pytest.mark.asyncio
async def test_scoped_grant_does_not_reach_other_subnets_or_aggregates(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, y, other = await _two_subnets(db_session)
    h = await _user(db_session, _rw(x))
    await db_session.commit()

    # The sibling subnet Y: every verb refused.
    assert (await client.get(f"/api/v1/ipam/subnets/{y.id}", headers=h)).status_code == 403
    resp = await client.put(f"/api/v1/ipam/subnets/{y.id}", json={"description": "no"}, headers=h)
    assert resp.status_code == 403
    assert (
        await client.get(f"/api/v1/ipam/subnets/{y.id}/addresses", headers=h)
    ).status_code == 403
    resp = await client.post(
        f"/api/v1/ipam/subnets/{y.id}/addresses",
        json={"address": "10.0.6.20", "hostname": "h1"},
        headers=h,
    )
    assert resp.status_code == 403
    # Aggregates and structure above the subnet stay closed.
    assert (await client.get("/api/v1/ipam/spaces", headers=h)).status_code == 403
    assert (await client.get("/api/v1/ipam/blocks", headers=h)).status_code == 403
    # Write routes that are not on the allow-list stay refused even for X.
    resp = await client.delete(f"/api/v1/ipam/subnets/{x.id}", headers=h)
    assert resp.status_code == 403
    resp = await client.post(
        f"/api/v1/ipam/subnets/{x.id}/resize", json={"new_network": "10.0.5.0/23"}, headers=h
    )
    assert resp.status_code in (403, 422)
    # Re-parenting X under another block touches a resource the grant does not name.
    mv = await client.put(
        f"/api/v1/ipam/subnets/{x.id}", json={"block_id": str(other.id)}, headers=h
    )
    assert mv.status_code == 403, mv.text


@pytest.mark.asyncio
async def test_scoped_read_only_cannot_write(db_session: AsyncSession, client: AsyncClient) -> None:
    x, _y, _o = await _two_subnets(db_session)
    h = await _user(
        db_session, [{"action": "read", "resource_type": "subnet", "resource_id": str(x.id)}]
    )
    await db_session.commit()
    assert (await client.get(f"/api/v1/ipam/subnets/{x.id}", headers=h)).status_code == 200
    resp = await client.put(f"/api/v1/ipam/subnets/{x.id}", json={"description": "n"}, headers=h)
    assert resp.status_code == 403
    resp = await client.post(
        f"/api/v1/ipam/subnets/{x.id}/addresses",
        json={"address": "10.0.5.21", "hostname": "h1"},
        headers=h,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_type_level_subnet_read_still_lists_everything(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, y, _o = await _two_subnets(db_session)
    h = await _user(db_session, [{"action": "read", "resource_type": "subnet"}])
    await db_session.commit()
    ids = {s["id"] for s in (await client.get("/api/v1/ipam/subnets", headers=h)).json()}
    assert {str(x.id), str(y.id)} <= ids


# ── Adversarial cases (#2438 validation) ─────────────────────────────────────


async def _zones(db: AsyncSession) -> tuple[DNSZone, DNSZone]:
    tag = uuid.uuid4().hex[:6]
    group = DNSServerGroup(name=f"g-{tag}", description="")
    db.add(group)
    await db.flush()
    own = DNSZone(group_id=group.id, name=f"own-{tag}.test.", kind="forward")
    foreign = DNSZone(group_id=group.id, name=f"foreign-{tag}.test.", kind="forward")
    db.add_all([own, foreign])
    await db.flush()
    return own, foreign


@pytest.mark.asyncio
async def test_scoped_holder_cannot_publish_into_a_zone_the_subnet_does_not_use(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Naming a DNS zone in the body would write records into a zone the grant
    never mentions: the subnet's own zones pass, any other is refused."""
    x, _y, _o = await _two_subnets(db_session)
    own, foreign = await _zones(db_session)
    x.dns_zone_id = str(own.id)
    x.dns_inherit_settings = False
    h = await _user(db_session, _rw(x))
    await db_session.commit()

    # Rebinding the subnet to a foreign zone.
    r = await client.put(
        f"/api/v1/ipam/subnets/{x.id}", json={"dns_zone_id": str(foreign.id)}, headers=h
    )
    assert r.status_code == 403, r.text
    r = await client.put(
        f"/api/v1/ipam/subnets/{x.id}",
        json={"dns_additional_zone_ids": [str(foreign.id)]},
        headers=h,
    )
    assert r.status_code == 403, r.text
    # Re-saving the zone it already has is not a rebinding.
    r = await client.put(
        f"/api/v1/ipam/subnets/{x.id}", json={"dns_zone_id": str(own.id)}, headers=h
    )
    assert r.status_code == 200, r.text

    # Naming a foreign zone on an address create.
    for body in (
        {"address": "10.0.5.30", "hostname": "h30", "dns_zone_id": str(foreign.id)},
        {"address": "10.0.5.31", "hostname": "h31", "extra_zone_ids": [str(foreign.id)]},
    ):
        r = await client.post(f"/api/v1/ipam/subnets/{x.id}/addresses", json=body, headers=h)
        assert r.status_code == 403, r.text
    # The subnet's own zone is fine.
    r = await client.post(
        f"/api/v1/ipam/subnets/{x.id}/addresses",
        json={"address": "10.0.5.32", "hostname": "h32", "dns_zone_id": str(own.id)},
        headers=h,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_scoped_holder_cannot_rebind_the_subnet_to_other_resources(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, _y, _o = await _two_subnets(db_session)
    cust = Customer(name=f"c-{uuid.uuid4().hex[:6]}")
    db_session.add(cust)
    h = await _user(db_session, _rw(x))
    await db_session.commit()

    for body in (
        {"customer_id": str(cust.id)},
        {"dhcp_server_group_id": str(uuid.uuid4())},
        {"dns_group_ids": [str(uuid.uuid4())]},
        {"ddns_domain_override": "victim.example.com"},
        {"site_id": str(uuid.uuid4())},
        {"vlan_ref_id": str(uuid.uuid4())},
    ):
        r = await client.put(f"/api/v1/ipam/subnets/{x.id}", json=body, headers=h)
        assert r.status_code == 403, (body, r.text)
    # Sending the values it already holds (a form re-save) is not a change.
    r = await client.put(
        f"/api/v1/ipam/subnets/{x.id}",
        json={"customer_id": None, "dhcp_server_group_id": None, "site_id": None, "name": "x2"},
        headers=h,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_type_level_subnet_writer_still_rebinds(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The rebinding refusals apply only to a holder admitted by a scoped
    grant; a type-level writer keeps today's behaviour."""
    x, _y, _o = await _two_subnets(db_session)
    _own, foreign = await _zones(db_session)
    cust = Customer(name=f"c-{uuid.uuid4().hex[:6]}")
    db_session.add(cust)
    h = await _user(
        db_session,
        [
            {"action": "read", "resource_type": "subnet"},
            {"action": "write", "resource_type": "subnet"},
        ],
    )
    await db_session.commit()
    r = await client.put(
        f"/api/v1/ipam/subnets/{x.id}",
        json={"dns_zone_id": str(foreign.id), "customer_id": str(cust.id)},
        headers=h,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_scoped_grant_reads_only_the_subnets_own_routes(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Reads are an allow-list of the subnet's own routes: a GET that carries
    ``subnet_id`` but reports another resource type (NAT mappings) or records
    outside the subnet (the DNS drift report) is not on it."""
    x, _y, _o = await _two_subnets(db_session)
    h = await _user(db_session, _rw(x))
    await db_session.commit()
    for path in (
        f"/api/v1/ipam/subnets/{x.id}/effective-fields",
        f"/api/v1/ipam/subnets/{x.id}/effective-dns",
        f"/api/v1/ipam/subnets/{x.id}/next-ip-preview",
        f"/api/v1/ipam/subnets/{x.id}/aliases",
        f"/api/v1/ipam/subnets/{x.id}/domains",
        f"/api/v1/ipam/subnets/{x.id}/utilization-history",
    ):
        assert (await client.get(path, headers=h)).status_code == 200, path
    for path in (
        f"/api/v1/ipam/nat-mappings/by-subnet/{x.id}",
        f"/api/v1/ipam/subnets/{x.id}/dns-sync/preview",
        f"/api/v1/ipam/subnets/{x.id}/dns-sync/summary",
    ):
        assert (await client.get(path, headers=h)).status_code in (403, 404), path


@pytest.mark.asyncio
async def test_scoped_grant_reaches_no_other_write_route_on_its_subnet(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, _y, _o = await _two_subnets(db_session)
    h = await _user(
        db_session,
        _rw(x) + [{"action": "admin", "resource_type": "subnet", "resource_id": str(x.id)}],
    )
    await db_session.commit()
    for method, path, body in (
        ("POST", f"/api/v1/ipam/subnets/{x.id}/next", {"hostname": "n"}),
        ("POST", f"/api/v1/ipam/subnets/{x.id}/bulk-allocate", {}),
        ("POST", f"/api/v1/ipam/subnets/{x.id}/split/commit", {}),
        ("POST", f"/api/v1/ipam/subnets/{x.id}/merge/commit", {}),
        ("POST", f"/api/v1/ipam/subnets/{x.id}/dns-sync/commit", {}),
        ("POST", f"/api/v1/ipam/subnets/{x.id}/discover", {}),
        ("POST", f"/api/v1/ipam/subnets/{x.id}/domains", {"dns_zone_id": str(uuid.uuid4())}),
        ("POST", f"/api/v1/ipam/subnets/{x.id}/orphans/purge", {}),
        ("POST", f"/api/v1/ipam/subnets/{x.id}/reverse-zones/backfill", {}),
        ("DELETE", f"/api/v1/ipam/subnets/{x.id}", None),
    ):
        r = await client.request(method, path, json=body, headers=h)
        assert r.status_code == 403, (method, path, r.status_code, r.text)


@pytest.mark.asyncio
async def test_address_outside_the_subnet_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, y, _o = await _two_subnets(db_session)
    h = await _user(db_session, _rw(x))
    await db_session.commit()
    # An address of the sibling subnet Y sent through X's route.
    r = await client.post(
        f"/api/v1/ipam/subnets/{x.id}/addresses",
        json={"address": "10.0.6.20", "hostname": "h"},
        headers=h,
    )
    assert r.status_code == 422, r.text
    # A body subnet_id is not a field, and cannot redirect the row.
    r = await client.post(
        f"/api/v1/ipam/subnets/{x.id}/addresses",
        json={"address": "10.0.5.40", "hostname": "h40", "subnet_id": str(y.id)},
        headers=h,
    )
    assert r.status_code == 201, r.text
    assert r.json()["subnet_id"] == str(x.id)


@pytest.mark.asyncio
async def test_collision_warning_does_not_reveal_other_subnets(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A MAC collision probe from a scoped holder still warns, but says
    nothing about the row in a subnet the holder cannot read."""
    x, y, _o = await _two_subnets(db_session)
    db_session.add(
        IPAddress(
            subnet_id=y.id,
            address="10.0.6.9",
            hostname="secret-host",
            mac_address="aa:bb:cc:00:11:22",
        )
    )
    h = await _user(db_session, _rw(x))
    await db_session.commit()
    r = await client.post(
        f"/api/v1/ipam/subnets/{x.id}/addresses",
        json={"address": "10.0.5.50", "hostname": "h50", "mac_address": "aa:bb:cc:00:11:22"},
        headers=h,
    )
    assert r.status_code == 409, r.text
    body = r.text
    assert "secret-host" not in body
    assert "10.0.6.9" not in body
    assert "10.0.6.0/24" not in body
    assert "mac_collision" in body


@pytest.mark.asyncio
async def test_scoped_write_without_read_cannot_read(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, _y, _o = await _two_subnets(db_session)
    h = await _user(
        db_session, [{"action": "write", "resource_type": "subnet", "resource_id": str(x.id)}]
    )
    await db_session.commit()
    assert (await client.get(f"/api/v1/ipam/subnets/{x.id}", headers=h)).status_code == 403
    assert (await client.get("/api/v1/ipam/subnets", headers=h)).status_code == 403
    r = await client.put(f"/api/v1/ipam/subnets/{x.id}", json={"description": "w"}, headers=h)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_soft_deleted_subnet_is_not_reachable(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, _y, _o = await _two_subnets(db_session)
    xid = x.id
    h = await _user(db_session, _rw(x))
    x.deleted_at = datetime.now(UTC)
    await db_session.commit()
    # The test client shares this session; drop the cached rows so the request
    # loads the subnet the way a fresh request session would.
    db_session.expunge_all()
    assert (await client.get(f"/api/v1/ipam/subnets/{xid}", headers=h)).status_code == 404
    resp = await client.put(f"/api/v1/ipam/subnets/{xid}", json={"description": "z"}, headers=h)
    assert resp.status_code == 404
    resp = await client.post(
        f"/api/v1/ipam/subnets/{xid}/addresses",
        json={"address": "10.0.5.60", "hostname": "h60"},
        headers=h,
    )
    assert resp.status_code == 404
    lst = await client.get("/api/v1/ipam/subnets", headers=h)
    assert lst.status_code == 200 and lst.json() == []


@pytest.mark.asyncio
async def test_token_narrowed_away_from_subnets_is_still_refused_the_list(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The list route's scoped admit honours a resource-scoped API token
    (#374): a token bound only to a DNS zone answers 403 on the subnet list,
    as it did before #2438, rather than an empty 200."""
    await _two_subnets(db_session)
    owner = await _make_user(db_session, [{"action": "read", "resource_type": "subnet"}])
    raw, _prefix, token_hash = generate_api_token()
    db_session.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=[
                {"action": "read", "resource_type": "dns_zone", "resource_id": str(uuid.uuid4())}
            ],
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db_session.commit()
    r = await client.get("/api/v1/ipam/subnets", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_null_and_empty_dns_group_ids_are_the_same_no_binding(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The Edit dialog sends null for a subnet storing the create default [] (#2438)."""
    x, y, _o = await _two_subnets(db_session)
    x.dns_group_ids = []
    y.dns_group_ids = None
    h = await _user(db_session, _rw(x) + _rw(y))
    await db_session.commit()

    r = await client.put(
        f"/api/v1/ipam/subnets/{x.id}", json={"dns_group_ids": None, "name": "x2"}, headers=h
    )
    assert r.status_code == 200, r.text
    r = await client.put(
        f"/api/v1/ipam/subnets/{y.id}", json={"dns_group_ids": [], "name": "y2"}, headers=h
    )
    assert r.status_code == 200, r.text
    # A real change is still refused.
    r = await client.put(
        f"/api/v1/ipam/subnets/{x.id}",
        json={"dns_group_ids": [str(uuid.uuid4())]},
        headers=h,
    )
    assert r.status_code == 403, r.text
