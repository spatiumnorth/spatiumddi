"""Edit Subnet moves a gateway the way New Subnet makes one (#3317, #3318).

The edit used to write the gateway column and nothing else: no row was reserved
at the new address, so Next available offered the router's own address to a
host, and a gateway on the network / broadcast address, which New Subnet
refuses with a 422, was stored.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _make(client: AsyncClient, db: AsyncSession, network: str = "10.232.5.0/29", **extra):
    h = await _headers(db)
    space = IPSpace(name=f"sp3317-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.232.0.0/16", name="b")
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


async def _put(client, h, sid, **body):
    return await client.put(f"/api/v1/ipam/subnets/{sid}", headers=h, json=body)


async def test_moved_gateway_is_reserved_and_never_offered(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session)
    r = await _put(client, h, sid, gateway="10.232.5.6")
    assert r.status_code == 200, r.text
    assert r.json()["gateway"] == "10.232.5.6"

    rows = await _addresses(client, h, sid)
    assert rows["10.232.5.6"]["status"] == "reserved"
    assert rows["10.232.5.6"]["hostname"] == "gateway"
    # The old default gateway row is retired, not left as a stale "Gateway".
    assert "10.232.5.1" not in rows

    # The counters follow the rows: only the gateway is counted (#2411).
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    assert sub["allocated_ips"] == 1

    # Take every host below the new gateway: Next available must not fall
    # through to it.
    for last in (1, 2, 3, 4, 5):
        a = await client.post(
            f"/api/v1/ipam/subnets/{sid}/addresses",
            headers=h,
            json={"address": f"10.232.5.{last}", "status": "allocated", "hostname": f"h{last}"},
        )
        assert a.status_code == 201, a.text
    nxt = await client.get(f"/api/v1/ipam/subnets/{sid}/next-ip-preview", headers=h)
    assert nxt.status_code == 200, nxt.text
    assert nxt.json()["address"] != "10.232.5.6"


async def test_gateway_on_network_or_broadcast_is_refused_like_new_subnet(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.232.6.0/29")
    for bad, word in (("10.232.6.0", "network"), ("10.232.6.7", "broadcast")):
        r = await _put(client, h, sid, gateway=bad)
        assert r.status_code == 422, r.text
        assert bad in r.json()["detail"] and word in r.json()["detail"]
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    assert sub["gateway"] == "10.232.6.1"
    rows = await _addresses(client, h, sid)
    assert rows["10.232.6.1"]["status"] == "reserved"


async def test_resaving_the_stored_gateway_changes_nothing(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.232.7.0/29")
    before = await _addresses(client, h, sid)
    r = await _put(client, h, sid, gateway="10.232.7.1", name="renamed")
    assert r.status_code == 200, r.text
    after = await _addresses(client, h, sid)
    assert {a: v["id"] for a, v in before.items()} == {a: v["id"] for a, v in after.items()}


async def test_an_operators_gateway_row_is_kept_when_the_gateway_moves(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.232.8.0/29")
    rows = await _addresses(client, h, sid)
    r = await client.put(
        f"/api/v1/ipam/addresses/{rows['10.232.8.1']['id']}",
        headers=h,
        json={"hostname": "core-router"},
    )
    assert r.status_code == 200, r.text
    r = await _put(client, h, sid, gateway="10.232.8.2")
    assert r.status_code == 200, r.text
    rows = await _addresses(client, h, sid)
    assert rows["10.232.8.1"]["hostname"] == "core-router"
    assert rows["10.232.8.2"]["hostname"] == "gateway"


async def test_clearing_the_gateway_retires_its_default_row(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.232.9.0/29")
    r = await _put(client, h, sid, gateway=None)
    assert r.status_code == 200, r.text
    assert r.json()["gateway"] is None
    assert "10.232.9.1" not in await _addresses(client, h, sid)
