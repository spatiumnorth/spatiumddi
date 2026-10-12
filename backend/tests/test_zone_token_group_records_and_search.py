"""A dns_zone-scoped API token sees only its zones on every read surface
(GHSA-wr8j-6r46-pj7g).

The zone list and the per-zone routes already narrow to the token's bound
zones (#400). Two read surfaces did not: ``GET /dns/groups/{id}/records``
returned every record of every zone in the group, and global search
(``GET /search``, and the Copilot's ``global_search``, which runs the same
engine) returned zones and records outside the grant.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone


async def _owner(db: AsyncSession) -> User:
    user = User(
        username=f"tok-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Token User",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _token(db: AsyncSession, owner: User, grants: list[dict] | None) -> str:
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
    return raw


async def _group_with_two_zones(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone, DNSZone]:
    tag = uuid.uuid4().hex[:6]
    group = DNSServerGroup(name=f"g-{tag}", description="")
    db.add(group)
    await db.flush()
    zone_a = DNSZone(group_id=group.id, name=f"wr8ja-{tag}.test", kind="forward")
    zone_b = DNSZone(group_id=group.id, name=f"wr8jb-{tag}.test", kind="forward")
    db.add_all([zone_a, zone_b])
    await db.flush()
    for zone, host in ((zone_a, "hosta"), (zone_b, "hostb")):
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=f"{host}-{tag}",
                fqdn=f"{host}-{tag}.{zone.name}",
                record_type="A",
                value="10.0.0.9",
            )
        )
    await db.flush()
    return group, zone_a, zone_b


def _zone_grant(zone: DNSZone) -> list[dict]:
    return [
        {"action": "read", "resource_type": "dns_zone", "resource_id": str(zone.id)},
        {"action": "read", "resource_type": "dns_record", "resource_id": "*"},
    ]


@pytest.mark.asyncio
async def test_group_records_narrow_to_the_tokens_zones(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner = await _owner(db_session)
    group, zone_a, zone_b = await _group_with_two_zones(db_session)
    raw = await _token(db_session, owner, _zone_grant(zone_a))
    await db_session.commit()

    r = await client.get(
        f"/api/v1/dns/groups/{group.id}/records", headers={"Authorization": f"Bearer {raw}"}
    )
    assert r.status_code == 200, r.text
    zones = {item["zone_id"] for item in r.json()["items"]}
    assert zones == {str(zone_a.id)}, f"zone-scoped token saw {zones}"


@pytest.mark.asyncio
async def test_group_records_unchanged_for_a_session(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner = await _owner(db_session)
    group, zone_a, zone_b = await _group_with_two_zones(db_session)
    await db_session.commit()
    r = await client.get(
        f"/api/v1/dns/groups/{group.id}/records",
        headers={"Authorization": f"Bearer {create_access_token(str(owner.id))}"},
    )
    assert r.status_code == 200, r.text
    assert {item["zone_id"] for item in r.json()["items"]} == {str(zone_a.id), str(zone_b.id)}


@pytest.mark.asyncio
async def test_search_hides_zones_and_records_outside_the_grant(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner = await _owner(db_session)
    group, zone_a, zone_b = await _group_with_two_zones(db_session)
    raw = await _token(db_session, owner, _zone_grant(zone_a))
    await db_session.commit()

    r = await client.get(
        "/api/v1/search", params={"q": "wr8j"}, headers={"Authorization": f"Bearer {raw}"}
    )
    assert r.status_code == 200, r.text
    hits = r.json()["results"]
    zone_ids = {h.get("dns_zone_id") for h in hits if h["type"] in ("dns_zone", "dns_record")}
    assert str(zone_b.id) not in zone_ids, f"foreign zone leaked through search: {hits}"
    assert str(zone_a.id) in zone_ids, "the token's own zone should still be found"


@pytest.mark.asyncio
async def test_search_unchanged_for_a_session(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner = await _owner(db_session)
    group, zone_a, zone_b = await _group_with_two_zones(db_session)
    await db_session.commit()
    r = await client.get(
        "/api/v1/search",
        params={"q": "wr8j"},
        headers={"Authorization": f"Bearer {create_access_token(str(owner.id))}"},
    )
    assert r.status_code == 200, r.text
    zone_ids = {h.get("dns_zone_id") for h in r.json()["results"]}
    assert {str(zone_a.id), str(zone_b.id)} <= zone_ids


@pytest.mark.asyncio
async def test_search_narrows_addresses_to_a_subnet_scoped_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The same engine-level narrowing covers IPAM rows: a subnet-scoped token's
    search returns addresses only from its own subnet."""
    from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

    owner = await _owner(db_session)
    tag = uuid.uuid4().hex[:6]
    space = IPSpace(name=f"sp-{tag}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name=f"blk-{tag}")
    db_session.add(block)
    await db_session.flush()
    sub_a = Subnet(space_id=space.id, block_id=block.id, network="10.77.1.0/24", name="a")
    sub_b = Subnet(space_id=space.id, block_id=block.id, network="10.77.2.0/24", name="b")
    db_session.add_all([sub_a, sub_b])
    await db_session.flush()
    db_session.add_all(
        [
            IPAddress(subnet_id=sub_a.id, address="10.77.1.5", hostname=f"wr8jip-a-{tag}"),
            IPAddress(subnet_id=sub_b.id, address="10.77.2.5", hostname=f"wr8jip-b-{tag}"),
        ]
    )
    raw = await _token(
        db_session,
        owner,
        [
            {"action": "read", "resource_type": "subnet", "resource_id": str(sub_a.id)},
            {"action": "read", "resource_type": "ip_address", "resource_id": "*"},
        ],
    )
    await db_session.commit()

    r = await client.get(
        "/api/v1/search", params={"q": "wr8jip"}, headers={"Authorization": f"Bearer {raw}"}
    )
    assert r.status_code == 200, r.text
    subnets = {h.get("subnet_id") for h in r.json()["results"] if h["type"] == "ip_address"}
    assert subnets == {str(sub_a.id)}, f"subnet-scoped token saw addresses in {subnets}"
