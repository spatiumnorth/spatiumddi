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


# ── The new address already holds a row ─────────────────────────────────────


async def _alloc(client, h, sid, address, status="allocated", hostname="h"):
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": address, "status": status, "hostname": hostname},
    )
    assert r.status_code == 201, r.text
    return r.json()


async def test_a_gateway_onto_a_host_is_refused_like_resize(
    client: AsyncClient, db_session: AsyncSession
):
    """The gateway would point at a host's address, and when the host went the
    address would be offered as free: refused, as Resize refuses it (#2413)."""
    h, sid = await _make(client, db_session, "10.232.10.0/29")
    await _alloc(client, h, sid, "10.232.10.5", hostname="printer")
    before = await _addresses(client, h, sid)
    r = await _put(client, h, sid, gateway="10.232.10.5")
    assert r.status_code == 409, r.text
    assert "10.232.10.5" in r.json()["detail"] and "printer" in r.json()["detail"]
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    assert sub["gateway"] == "10.232.10.1"
    after = await _addresses(client, h, sid)
    assert {a: v["id"] for a, v in before.items()} == {a: v["id"] for a, v in after.items()}


async def test_a_gateway_onto_a_discovered_row_is_refused(
    client: AsyncClient, db_session: AsyncSession
):
    from app.models.ipam import IPAddress

    h, sid = await _make(client, db_session, "10.232.11.0/29")
    db_session.add(IPAddress(subnet_id=uuid.UUID(sid), address="10.232.11.4", status="discovered"))
    await db_session.commit()
    r = await _put(client, h, sid, gateway="10.232.11.4")
    assert r.status_code == 409, r.text
    assert "10.232.11.4" in r.json()["detail"]


async def test_a_gateway_onto_a_reserved_row_keeps_that_row(
    client: AsyncClient, db_session: AsyncSession
):
    """The router already recorded as a reservation is the gateway: the row is
    the operator's and stays as it is; no second row is made."""
    h, sid = await _make(client, db_session, "10.232.12.0/29")
    router_row = await _alloc(client, h, sid, "10.232.12.6", status="reserved", hostname="core")
    r = await _put(client, h, sid, gateway="10.232.12.6")
    assert r.status_code == 200, r.text
    rows = await _addresses(client, h, sid)
    assert rows["10.232.12.6"]["id"] == router_row["id"]
    assert rows["10.232.12.6"]["hostname"] == "core"
    assert "10.232.12.1" not in rows
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    assert sub["allocated_ips"] == 1


async def test_a_subnet_made_without_placeholders_keeps_new_subnets_rules(
    client: AsyncClient, db_session: AsyncSession
):
    """New Subnet with skip_auto_addresses makes no rows and accepts a gateway
    on the network address; the edit agrees and makes no gateway row."""
    h, sid = await _make(client, db_session, "10.232.13.0/29", skip_auto_addresses=True)
    r = await _put(client, h, sid, gateway="10.232.13.0")
    assert r.status_code == 200, r.text
    assert r.json()["gateway"] == "10.232.13.0"
    assert await _addresses(client, h, sid) == {}


# ── DNS: the PTR follows the gateway row ────────────────────────────────────


async def test_the_gateway_ptr_moves_through_the_record_op_queue(
    client: AsyncClient, db_session: AsyncSession
):
    from sqlalchemy import select

    from app.models.dns import DNSRecordOp
    from tests.test_subnet_gateway_ptr_1150 import (
        _admin_headers,
        _create_subnet,
        _dns,
        _drift,
        _gateway_records,
        _space_block,
    )

    h = await _admin_headers(db_session)
    grp, server, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.88.0.0/16")
    await db_session.commit()
    sid = await _create_subnet(
        client,
        h,
        space,
        block,
        "10.88.23.0/24",
        dns_group_id=str(grp.id),
        dns_zone_id=str(zone.id),
    )
    r = await _put(client, h, sid, gateway="10.88.23.254")
    assert r.status_code == 200, r.text
    assert await _gateway_records(db_session, sid) == [
        ("23.88.10.in-addr.arpa.", "PTR", "254", f"gateway.{zone.name}")
    ]
    assert await _drift(client, h, sid) == {"missing": 0, "mismatched": 0, "stale": 0}
    ops = (
        await db_session.execute(
            select(DNSRecordOp.op, DNSRecordOp.record["name"].astext).where(
                DNSRecordOp.server_id == server.id,
                DNSRecordOp.zone_name == "23.88.10.in-addr.arpa.",
            )
        )
    ).all()
    assert sorted(tuple(o) for o in ops) == [("create", "1"), ("create", "254"), ("delete", "1")]


# ── The subnet import's overwrite moves a gateway the same way ──────────────


async def _import(client, h, space_id, csv: bytes, step="commit"):
    return await client.post(
        f"/api/v1/ipam/import/{step}",
        headers=h,
        files={"file": ("s.csv", csv, "text/csv")},
        data={"space_id": space_id, "strategy": "overwrite"},
    )


async def test_import_overwrite_moves_the_gateway_row(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.232.14.0/29")
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    r = await _import(client, h, sub["space_id"], b"network,gateway\n10.232.14.0/29,10.232.14.6\n")
    assert r.status_code == 200, r.text
    assert r.json()["updated_subnets"] == 1
    rows = await _addresses(client, h, sid)
    assert rows["10.232.14.6"]["hostname"] == "gateway"
    assert "10.232.14.1" not in rows
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    assert sub["gateway"] == "10.232.14.6" and sub["allocated_ips"] == 1


async def test_import_overwrite_onto_a_host_is_a_row_error_in_preview_and_commit(
    client: AsyncClient, db_session: AsyncSession
):
    h, sid = await _make(client, db_session, "10.232.15.0/29")
    await _alloc(client, h, sid, "10.232.15.5", hostname="printer")
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    csv = b"network,gateway\n10.232.15.0/29,10.232.15.5\n"
    p = await _import(client, h, sub["space_id"], csv, step="preview")
    assert p.status_code == 200, p.text
    assert [e["network"] for e in p.json()["errors"]] == ["10.232.15.0/29"]
    assert "printer" in p.json()["errors"][0]["reason"]
    c = await _import(client, h, sub["space_id"], csv)
    assert c.status_code == 200, c.text
    assert c.json()["updated_subnets"] == 0 and len(c.json()["errors"]) == 1
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    assert sub["gateway"] == "10.232.15.1"
