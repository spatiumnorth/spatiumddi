"""The gateway tools follow the free-slot rule, and agree (#3709).

An ``available`` row is a free slot (#2980): Next available offers it and
Bulk allocate takes it over (#3319). Edit Subnet refused it as the gateway
all the same, and Resize's gateway move refused it, and a ``reserved`` row
Edit Subnet keeps as the gateway's own, as well. Both tools now accept no row,
an ``available`` row (taken over) and a ``reserved`` row (kept), and refuse a
host, a lease or a discovered row.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _make(client: AsyncClient, db: AsyncSession, network: str, **extra):
    h = await _headers(db)
    space = IPSpace(name=f"sp3709-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.109.0.0/16", name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": network,
            "skip_reverse_zone": True,
            **extra,
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


async def _row(client, h, sid, address, status, hostname):
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": address, "status": status, "hostname": hostname},
    )
    assert r.status_code == 201, r.text
    return r.json()


async def _make_available(db: AsyncSession, client, h, sid, address, hostname):
    """An ``available`` row with a hostname, as a swept reservation leaves one."""
    row = await _row(client, h, sid, address, "reserved", hostname)
    obj = await db.get(IPAddress, uuid.UUID(row["id"]))
    obj.status = "available"
    await db.commit()
    return row


async def test_edit_subnet_takes_an_available_row_as_the_gateway(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.109.10.0/29")
    for last in (2, 3, 4):
        await _row(client, h, sid, f"10.109.10.{last}", "allocated", f"h{last}")
    av = await _make_available(db_session, client, h, sid, "10.109.10.5", "xp-av5")
    nxt = await client.get(f"/api/v1/ipam/subnets/{sid}/next-ip-preview", headers=h)
    assert nxt.json()["address"] == "10.109.10.5"

    r = await client.put(f"/api/v1/ipam/subnets/{sid}", headers=h, json={"gateway": "10.109.10.5"})
    assert r.status_code == 200, r.text
    assert r.json()["gateway"] == "10.109.10.5"
    rows = await _addresses(client, h, sid)
    assert rows["10.109.10.5"]["id"] == av["id"]
    assert rows["10.109.10.5"]["status"] == "reserved"
    assert rows["10.109.10.5"]["hostname"] == "gateway"
    assert "10.109.10.1" not in rows
    nxt = await client.get(f"/api/v1/ipam/subnets/{sid}/next-ip-preview", headers=h)
    assert nxt.json()["address"] != "10.109.10.5"


async def test_edit_subnet_still_refuses_a_host(client: AsyncClient, db_session: AsyncSession):
    h, sid = await _make(client, db_session, "10.109.13.0/29")
    await _row(client, h, sid, "10.109.13.5", "allocated", "printer")
    r = await client.put(f"/api/v1/ipam/subnets/{sid}", headers=h, json={"gateway": "10.109.13.5"})
    assert r.status_code == 409, r.text


async def _resize(client, h, sid, new_cidr, preview):
    path = f"/api/v1/ipam/subnets/{sid}/resize" + ("/preview" if preview else "")
    return await client.post(
        path, headers=h, json={"new_cidr": new_cidr, "move_gateway_to_first_usable": True}
    )


async def test_resize_gateway_move_takes_an_available_row(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.109.11.0/29", gateway="10.109.11.6")
    av = await _make_available(db_session, client, h, sid, "10.109.11.1", "xp-av1")
    pv = await _resize(client, h, sid, "10.109.11.0/28", True)
    assert pv.status_code == 200, pv.text
    assert pv.json()["conflicts"] == []
    cm = await _resize(client, h, sid, "10.109.11.0/28", False)
    assert cm.status_code == 200, cm.text
    rows = await _addresses(client, h, sid)
    assert rows["10.109.11.1"]["id"] == av["id"]
    assert rows["10.109.11.1"]["status"] == "reserved"
    assert rows["10.109.11.1"]["hostname"] == "gateway"
    assert "10.109.11.6" not in rows


async def test_resize_gateway_move_keeps_a_reserved_row(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.109.12.0/29", gateway="10.109.12.6")
    rsv = await _row(client, h, sid, "10.109.12.1", "reserved", "core")
    pv = await _resize(client, h, sid, "10.109.12.0/28", True)
    assert pv.status_code == 200, pv.text
    assert pv.json()["conflicts"] == []
    cm = await _resize(client, h, sid, "10.109.12.0/28", False)
    assert cm.status_code == 200, cm.text
    rows = await _addresses(client, h, sid)
    assert rows["10.109.12.1"]["id"] == rsv["id"]
    assert rows["10.109.12.1"]["hostname"] == "core"
    assert cm.json()["subnet"]["gateway"] == "10.109.12.1"


async def test_resize_gateway_move_still_refuses_a_host(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.109.14.0/29", gateway="10.109.14.6")
    await _row(client, h, sid, "10.109.14.1", "allocated", "host1")
    pv = await _resize(client, h, sid, "10.109.14.0/28", True)
    assert "gateway_move_target_in_use" in [c["type"] for c in pv.json()["conflicts"]]
    cm = await _resize(client, h, sid, "10.109.14.0/28", False)
    assert cm.status_code == 409, cm.text
