"""Resize preview's reverse-zone lines agree with what the commit does (#4987).

The preview named the old and new CIDRs' zone names as "existing" / "create"
without reading a DNS group, so it promised zones a DNS-less or opted-out
subnet never gets and called zones existing that no group held. It now runs
the commit's own lookups (``plan_reverse_zones``).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone
from tests.test_subnet_gateway_ptr_1150 import (
    _admin_headers,
    _create_subnet,
    _dns,
    _space_block,
)

Z0 = "0.77.10.in-addr.arpa."
Z1 = "1.77.10.in-addr.arpa."


async def _group_zone_rows(db: AsyncSession, group_id: uuid.UUID) -> list[DNSZone]:
    db.expire_all()
    return list(
        (
            await db.execute(
                select(DNSZone).where(DNSZone.group_id == group_id, DNSZone.name.in_([Z0, Z1]))
            )
        )
        .scalars()
        .all()
    )


async def _preview(client: AsyncClient, h: dict[str, str], sid: str) -> dict:
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize/preview", headers=h, json={"new_cidr": "10.77.0.0/23"}
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _commit(client: AsyncClient, h: dict[str, str], sid: str) -> None:
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize", headers=h, json={"new_cidr": "10.77.0.0/23"}
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_no_dns_group_says_nothing_will_be_created(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin_headers(db_session)
    space, block = await _space_block(db_session, "10.77.0.0/16")
    await db_session.commit()
    sid = await _create_subnet(client, h, space, block, "10.77.0.0/24")
    p = await _preview(client, h, sid)
    assert p["reverse_zones_existing"] == []
    assert p["reverse_zones_will_be_created"] == []
    await _commit(client, h, sid)
    n = (await db_session.execute(select(DNSZone.id).where(DNSZone.name.in_([Z0, Z1])))).all()
    assert n == []


@pytest.mark.asyncio
async def test_opted_out_subnet_says_nothing_will_be_created(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin_headers(db_session)
    grp, _s, _z = await _dns(db_session)
    space, block = await _space_block(db_session, "10.77.0.0/16")
    await db_session.commit()
    gid = grp.id
    sid = await _create_subnet(
        client, h, space, block, "10.77.0.0/24", dns_group_id=str(gid), skip_reverse_zone=True
    )
    p = await _preview(client, h, sid)
    assert p["reverse_zones_existing"] == []
    assert p["reverse_zones_will_be_created"] == []
    await _commit(client, h, sid)
    assert await _group_zone_rows(db_session, gid) == []


@pytest.mark.asyncio
async def test_existing_zone_listed_existing_and_only_the_new_one_created(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin_headers(db_session)
    grp, _s, _z = await _dns(db_session)
    space, block = await _space_block(db_session, "10.77.0.0/16")
    await db_session.commit()
    gid = grp.id
    sid = await _create_subnet(client, h, space, block, "10.77.0.0/24", dns_group_id=str(gid))
    p = await _preview(client, h, sid)
    assert p["reverse_zones_existing"] == [Z0]
    assert p["reverse_zones_will_be_created"] == [Z1]
    await _commit(client, h, sid)
    assert sorted(z.name for z in await _group_zone_rows(db_session, gid)) == [Z0, Z1]


@pytest.mark.asyncio
async def test_missing_zone_is_created_not_called_existing(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin_headers(db_session)
    grp, _s, _z = await _dns(db_session)
    space, block = await _space_block(db_session, "10.77.0.0/16")
    await db_session.commit()
    gid = grp.id
    sid = await _create_subnet(client, h, space, block, "10.77.0.0/24", dns_group_id=str(gid))
    await db_session.execute(
        text("DELETE FROM dns_zone WHERE name = :n AND group_id = :g"), {"n": Z0, "g": gid}
    )
    await db_session.commit()
    p = await _preview(client, h, sid)
    assert p["reverse_zones_existing"] == []
    assert p["reverse_zones_will_be_created"] == [Z0, Z1]
    await _commit(client, h, sid)
    assert sorted(z.name for z in await _group_zone_rows(db_session, gid)) == [Z0, Z1]


@pytest.mark.asyncio
async def test_trashed_zone_is_not_existing_and_commit_makes_a_fresh_one(
    client: AsyncClient, db_session: AsyncSession
):
    """A trashed zone does not count as existing; the commit neither restores
    it nor trips on it: it creates a new live zone of the name."""
    h = await _admin_headers(db_session)
    grp, _s, _z = await _dns(db_session)
    space, block = await _space_block(db_session, "10.77.0.0/16")
    await db_session.commit()
    gid = grp.id
    sid = await _create_subnet(client, h, space, block, "10.77.0.0/24", dns_group_id=str(gid))
    await db_session.execute(
        text("UPDATE dns_zone SET deleted_at = now() WHERE name = :n AND group_id = :g"),
        {"n": Z0, "g": gid},
    )
    await db_session.commit()
    p = await _preview(client, h, sid)
    assert p["reverse_zones_existing"] == []
    assert p["reverse_zones_will_be_created"] == [Z0, Z1]
    await _commit(client, h, sid)
    live = await _group_zone_rows(db_session, gid)
    assert sorted(z.name for z in live) == [Z0, Z1]
    trashed = (
        await db_session.execute(
            text(
                "SELECT count(*) FROM dns_zone WHERE name = :n AND group_id = :g AND deleted_at IS NOT NULL"
            ),
            {"n": Z0, "g": gid},
        )
    ).scalar_one()
    assert trashed == 1  # still in Trash, not restored


@pytest.mark.asyncio
async def test_zone_in_another_group_is_not_existing(client: AsyncClient, db_session: AsyncSession):
    h = await _admin_headers(db_session)
    grp, _s, _z = await _dns(db_session)
    other = DNSServerGroup(name=f"other-{uuid.uuid4().hex[:6]}")
    db_session.add(other)
    await db_session.flush()
    db_session.add(DNSZone(group_id=other.id, name=Z0, zone_type="primary", kind="reverse"))
    space, block = await _space_block(db_session, "10.77.0.0/16")
    await db_session.commit()
    gid = grp.id
    sid = await _create_subnet(
        client, h, space, block, "10.77.0.0/24", dns_group_id=str(gid), skip_reverse_zone=True
    )
    await db_session.execute(
        text("UPDATE subnet SET skip_reverse_zone = false WHERE id = :i"), {"i": uuid.UUID(sid)}
    )
    await db_session.commit()
    p = await _preview(client, h, sid)
    assert p["reverse_zones_existing"] == []
    assert p["reverse_zones_will_be_created"] == [Z0, Z1]
    await _commit(client, h, sid)
    assert sorted(z.name for z in await _group_zone_rows(db_session, gid)) == [Z0, Z1]


@pytest.mark.asyncio
async def test_preview_route_contract(client: AsyncClient, db_session: AsyncSession):
    h = await _admin_headers(db_session)
    space, block = await _space_block(db_session, "10.77.0.0/16")
    await db_session.commit()
    sid = await _create_subnet(client, h, space, block, "10.77.0.0/24")
    url = f"/api/v1/ipam/subnets/{sid}/resize/preview"
    body = {"new_cidr": "10.77.0.0/23"}
    # unauthenticated
    assert (await client.post(url, json=body)).status_code in (401, 403)
    # unknown subnet -> 404
    r = await client.post(
        f"/api/v1/ipam/subnets/{uuid.uuid4()}/resize/preview", headers=h, json=body
    )
    assert r.status_code == 404
    # bad input -> 422
    assert (await client.post(url, headers=h, json={})).status_code == 422
    # no write permission -> 403, never 500
    u = User(
        username=f"viewer-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="v",
        hashed_password="x",
        is_superadmin=False,
    )
    db_session.add(u)
    await db_session.flush()
    from app.core.security import create_access_token

    vh = {"Authorization": f"Bearer {create_access_token(str(u.id))}"}
    assert (await client.post(url, headers=vh, json=body)).status_code == 403
    # response shape + no write: preview creates no audit row / zone
    p = await _preview(client, h, sid)
    assert isinstance(p["reverse_zones_existing"], list)
    assert isinstance(p["reverse_zones_will_be_created"], list)
    assert (
        await db_session.execute(select(DNSZone.id).where(DNSZone.name.in_([Z0, Z1])))
    ).all() == []
