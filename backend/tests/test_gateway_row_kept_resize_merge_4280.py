"""#4280 - Resize (Move gateway) and Merge keep an annotated old Gateway row.

Edit Subnet retires the old Gateway row only while it is untouched
(``untouched_gateway_row``, #3042). Resize and Merge used an older four-field
test, so a row with tags, a MAC, an owner or custom fields was deleted. They
share the predicate now; a bare auto-created row is still replaced.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.subnet_merge import commit_subnet_merge, preview_subnet_merge
from tests.test_dhcp_static_readdress_live_lease import _superadmin_token


async def _gw_row(db: AsyncSession, sid: uuid.UUID, addr: str) -> IPAddress | None:
    return (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.subnet_id == sid, IPAddress.address == addr)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _resize_world(
    client: AsyncClient, db: AsyncSession, net_block: str, cidr: str
) -> tuple[dict[str, str], uuid.UUID]:
    h = {"Authorization": f"Bearer {await _superadmin_token(db)}"}
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=net_block, name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": cidr,
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    return h, uuid.UUID(r.json()["id"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("annotate", "kept"),
    [
        ({"tags": {"xp": "router"}}, True),
        ({"mac_address": "02:00:5e:c6:01:81"}, True),
        ({}, False),  # a bare row: the control, still replaced
    ],
)
async def test_resize_move_gateway_keeps_an_annotated_gateway_row(
    client: AsyncClient, db_session: AsyncSession, annotate: dict, kept: bool
) -> None:
    h, sid = await _resize_world(client, db_session, "10.198.0.0/16", "10.198.1.128/25")
    row = await _gw_row(db_session, sid, "10.198.1.129")
    assert row is not None
    if annotate:
        r = await client.put(
            f"/api/v1/ipam/addresses/{row.id}", headers=h, json={**annotate, "force": True}
        )
        assert r.status_code == 200, r.text
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize",
        headers=h,
        json={"new_cidr": "10.198.1.0/24", "move_gateway_to_first_usable": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["subnet"]["gateway"] == "10.198.1.1"
    old = await _gw_row(db_session, sid, "10.198.1.129")
    assert (old is not None) is kept
    if old is not None:
        assert old.id == row.id
    assert await _gw_row(db_session, sid, "10.198.1.1") is not None


async def _two_sources(db: AsyncSession) -> tuple[Subnet, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    a, b = (
        Subnet(space_id=space.id, block_id=block.id, network=c, name="s", total_ips=100, gateway=g)
        for c, g in (("10.0.0.0/25", "10.0.0.1"), ("10.0.0.128/25", "10.0.0.129"))
    )
    db.add_all([a, b])
    await db.flush()
    for s in (a, b):
        db.add(
            IPAddress(
                subnet_id=s.id,
                address=str(s.gateway),
                status="reserved",
                hostname="gateway",
                description="Gateway",
            )
        )
    await db.flush()
    return a, b


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "annotate",
    [{"tags": {"xp": "router"}}, {"mac_address": "02:00:5e:c6:02:81"}, {"custom_fields": {"a": 1}}],
)
async def test_merge_keeps_an_annotated_retired_gateway_row(
    db_session: AsyncSession, annotate: dict
) -> None:
    a, b = await _two_sources(db_session)
    row = await _gw_row(db_session, b.id, "10.0.0.129")
    assert row is not None
    for k, v in annotate.items():
        setattr(row, k, v)
    await db_session.flush()

    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert not any("10.0.0.129" in w and "retired" in w for w in preview.warnings), preview.warnings
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    kept = await _gw_row(db_session, res.merged_subnet.id, "10.0.0.129")
    assert kept is not None and kept.id == row.id


@pytest.mark.asyncio
async def test_merge_still_retires_a_bare_gateway_row(db_session: AsyncSession) -> None:
    a, b = await _two_sources(db_session)
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert any("10.0.0.129" in w and "retired" in w for w in preview.warnings), preview.warnings
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    assert await _gw_row(db_session, res.merged_subnet.id, "10.0.0.129") is None
