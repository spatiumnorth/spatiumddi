"""Resize with "Move gateway" reserves the new gateway (#2413).

The commit used to write only ``subnet.gateway``: no row was made at the new
address, so Next available offered the router's own address to a host.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _make(client: AsyncClient, db: AsyncSession):
    h = await _headers(db)
    space = IPSpace(name=f"sp2413-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.231.0.0/16", name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.231.5.0/24",
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    return h, str(r.json()["id"])


async def _addresses(client, h, sid) -> dict[str, dict]:
    r = await client.get(f"/api/v1/ipam/subnets/{sid}/addresses", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    rows = body["items"] if isinstance(body, dict) else body
    return {str(a["address"]): a for a in rows}


async def test_moved_gateway_is_reserved_and_not_offered(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session)
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize",
        headers=h,
        json={"new_cidr": "10.231.4.0/23", "move_gateway_to_first_usable": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["subnet"]["gateway"] == "10.231.4.1"

    rows = await _addresses(client, h, sid)
    assert rows["10.231.4.1"]["status"] == "reserved"
    assert rows["10.231.4.1"]["description"] == "Gateway"
    # The old default gateway row is retired, not left as a stale "Gateway".
    assert "10.231.5.1" not in rows

    nxt = await client.get(f"/api/v1/ipam/subnets/{sid}/next-ip-preview", headers=h)
    assert nxt.status_code == 200, nxt.text
    assert nxt.json()["address"] not in (None, "10.231.4.1")

    # Utilisation counters follow the rows. Network and broadcast placeholders
    # are not counted (#2411), so only the gateway is.
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    counted = [r for r in rows.values() if r["status"] not in ("network", "broadcast")]
    assert sub["allocated_ips"] == len(counted) == 1


async def test_without_move_gateway_row_is_untouched(client: AsyncClient, db_session: AsyncSession):
    h, sid = await _make(client, db_session)
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize", headers=h, json={"new_cidr": "10.231.4.0/23"}
    )
    assert r.status_code == 200, r.text
    rows = await _addresses(client, h, sid)
    assert rows["10.231.5.1"]["status"] == "reserved"
    assert "10.231.4.1" not in rows


async def test_move_gateway_refused_when_target_holds_a_host(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    space = IPSpace(name=f"sp2413b-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.232.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    await db_session.commit()
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.232.4.0/24",
            "gateway": "10.232.4.7",
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    sid = str(r.json()["id"])
    a = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": "10.232.4.1", "hostname": "host1"},
    )
    assert a.status_code == 201, a.text

    body = {"new_cidr": "10.232.4.0/23", "move_gateway_to_first_usable": True}
    pv = await client.post(f"/api/v1/ipam/subnets/{sid}/resize/preview", headers=h, json=body)
    assert pv.status_code == 200, pv.text
    assert "gateway_move_target_in_use" in [c["type"] for c in pv.json()["conflicts"]]
    cm = await client.post(f"/api/v1/ipam/subnets/{sid}/resize", headers=h, json=body)
    assert cm.status_code == 409, cm.text
    rows = await _addresses(client, h, sid)
    assert rows["10.232.4.1"]["hostname"] == "host1"
