"""spatiumddi#4941 — a subnet's reverse zone is looked for where its PTRs go
(its DNS group, the forward zone's view), not by name alone."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerGroup, DNSView, DNSZone
from app.models.ipam import IPBlock, IPSpace
from tests.test_subnet_delete_reverse_zone_1066 import _admin_headers

REV = "11.11.10.in-addr.arpa."


def _zone(gid: uuid.UUID, name: str, kind: str, view_id: uuid.UUID | None = None) -> DNSZone:
    return DNSZone(
        group_id=gid,
        view_id=view_id,
        name=name,
        zone_type="primary",
        kind=kind,
        primary_ns="ns1.x.",
        admin_email="a.x.",
    )


async def _space(db: AsyncSession) -> tuple[IPSpace, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.11.0.0/16", name="b")
    db.add(block)
    await db.flush()
    return space, block


@pytest.mark.asyncio
async def test_create_makes_reverse_zone_in_forward_zones_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    space, block = await _space(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    inside = DNSView(group_id=grp.id, name="inside")
    outside = DNSView(group_id=grp.id, name="outside")
    db_session.add_all([inside, outside])
    await db_session.flush()
    other = _zone(grp.id, REV, "reverse", outside.id)
    fwd = _zone(grp.id, "fa.test.", "forward", inside.id)
    db_session.add_all([other, fwd])
    await db_session.commit()

    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.11.11.0/24",
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(fwd.id),
        },
    )
    assert resp.status_code == 201, resp.text
    zones = (await db_session.execute(select(DNSZone).where(DNSZone.name == REV))).scalars().all()
    by_view = {z.view_id: z for z in zones}
    assert set(by_view) == {outside.id, inside.id}
    assert str(by_view[inside.id].linked_subnet_id) == resp.json()["id"]


@pytest.mark.asyncio
async def test_backfill_makes_zone_in_own_group_when_another_group_holds_the_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    space, block = await _space(db_session)
    own = DNSServerGroup(name=f"own-{uuid.uuid4().hex[:6]}")
    other = DNSServerGroup(name=f"oth-{uuid.uuid4().hex[:6]}")
    db_session.add_all([own, other])
    await db_session.flush()
    fwd = _zone(own.id, "fb.test.", "forward")
    db_session.add_all([_zone(other.id, "21.11.10.in-addr.arpa.", "reverse"), fwd])
    await db_session.commit()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.11.21.0/24",
            "dns_group_id": str(own.id),
            "dns_zone_id": str(fwd.id),
            "skip_reverse_zone": True,
        },
    )
    assert resp.status_code == 201, resp.text
    sid = resp.json()["id"]

    resp = await client.post(f"/api/v1/ipam/subnets/{sid}/reverse-zones/backfill", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["created"] == [{"subnet": "10.11.21.0/24", "zone": "21.11.10.in-addr.arpa."}]
    mine = (
        (
            await db_session.execute(
                select(DNSZone).where(
                    DNSZone.group_id == own.id, DNSZone.name == "21.11.10.in-addr.arpa."
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(mine) == 1 and str(mine[0].linked_subnet_id) == sid
