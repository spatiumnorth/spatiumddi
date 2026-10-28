"""Counters and Next available do not depend on the creating path (#2979, #2980, #2981)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers
from tests.test_ipam_block_rollup_tree_writes_2412 import _alloc, _space_block


async def _mk_subnet(client, h, space, block, cidr) -> str:
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={"space_id": space, "block_id": block, "network": cidr, "skip_reverse_zone": True},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _addrs(client, h, sid) -> dict[str, str]:
    r = await client.get(f"/api/v1/ipam/subnets/{sid}/addresses?limit=500", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    items = body["items"] if isinstance(body, dict) else body
    return {i["address"]: i["status"] for i in items}


# ── #2979 ────────────────────────────────────────────────────────────────


async def test_import_subnets_makes_the_create_rows(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space = IPSpace(name=f"sp2979-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.commit()
    csv = b"network,name,gateway\n10.233.67.0/24,imported,10.233.67.1\n10.233.68.0/24,nogw,\n"
    files = {"file": ("s.csv", csv, "text/csv")}
    r = await client.post(
        "/api/v1/ipam/import/commit",
        headers=h,
        files=files,
        data={"space_id": str(space.id), "strategy": "fail"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["created_subnets"] == 2
    subs = (await client.get(f"/api/v1/ipam/subnets?space_id={space.id}", headers=h)).json()
    subs = subs["items"] if isinstance(subs, dict) else subs
    by_net = {s["network"]: s for s in subs}
    s1 = by_net["10.233.67.0/24"]
    rows = await _addrs(client, h, s1["id"])
    assert rows == {
        "10.233.67.0": "network",
        "10.233.67.255": "broadcast",
        "10.233.67.1": "reserved",
    }
    assert s1["allocated_ips"] == 1
    nxt = await client.get(f"/api/v1/ipam/subnets/{s1['id']}/next-ip-preview", headers=h)
    assert nxt.json()["address"] == "10.233.67.2"
    # No gateway given: defaults to the first host, as New Subnet does.
    s2 = by_net["10.233.68.0/24"]
    assert (await _addrs(client, h, s2["id"]))["10.233.68.1"] == "reserved"
    # The auto parent block rolled the counts up.
    blocks = (await client.get(f"/api/v1/ipam/blocks?space_id={space.id}", headers=h)).json()
    blocks = blocks["items"] if isinstance(blocks, dict) else blocks
    assert {b["network"]: b["allocated_ips"] for b in blocks}["10.233.67.0/24"] == 1


async def test_import_subnet_gateway_on_network_address_is_a_row_error(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    space = IPSpace(name=f"sp2979b-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.commit()
    csv = b"network,name,gateway\n10.233.70.0/24,x,10.233.70.0\n"
    r = await client.post(
        "/api/v1/ipam/import/commit",
        headers=h,
        files={"file": ("s.csv", csv, "text/csv")},
        data={"space_id": str(space.id), "strategy": "fail"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["created_subnets"] == 0
    assert any("network or broadcast" in e for e in r.json()["errors"])


# ── #2981 ────────────────────────────────────────────────────────────────


async def test_import_addresses_recounts_subnet_and_blocks(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    space, root = await _space_block(db_session, "10.233.0.0/16")
    mid = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={"space_id": space, "parent_block_id": root, "network": "10.233.32.0/19", "name": "m"},
    )
    assert mid.status_code == 201, mid.text
    mid_id = mid.json()["id"]
    sid = await _mk_subnet(client, h, space, mid_id, "10.233.36.0/24")
    assert await _alloc(client, h, "subnets", sid) == 1
    csv = (
        b"address,hostname,status\n"
        b"10.233.36.10,,allocated\n10.233.36.11,,allocated\n10.233.36.12,,allocated\n"
        b"10.233.36.13,,allocated\n10.233.36.20,,available\n"
    )
    r = await client.post(
        "/api/v1/ipam/import/addresses/commit",
        headers=h,
        files={"file": ("a.csv", csv, "text/csv")},
        data={"subnet_id": sid, "strategy": "fail"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 5
    assert await _alloc(client, h, "subnets", sid) == 5  # available is free
    assert await _alloc(client, h, "blocks", mid_id) == 5
    assert await _alloc(client, h, "blocks", root) == 5


async def test_anchored_plan_without_new_block_rolls_up_anchor(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    space, root = await _space_block(db_session, "10.234.0.0/16")
    tree = {
        "id": "r",
        "network": "10.234.0.0/16",
        "name": "root",
        "kind": "block",
        "existing_block_id": root,
        "children": [
            {"id": "s1", "network": "10.234.162.0/24", "name": "s1", "kind": "subnet"},
            {"id": "s2", "network": "10.234.163.0/24", "name": "s2", "kind": "subnet"},
        ],
    }
    c = await client.post(
        "/api/v1/ipam/plans", headers=h, json={"name": "p", "space_id": space, "tree": tree}
    )
    assert c.status_code == 201, c.text
    ap = await client.post(f"/api/v1/ipam/plans/{c.json()['id']}/apply", headers=h)
    assert ap.status_code == 200, ap.text
    assert ap.json()["block_ids"] == []
    assert await _alloc(client, h, "blocks", root) == 2


# ── #2980 ────────────────────────────────────────────────────────────────


async def _avail_subnet(client, h, db_session) -> tuple[str, str]:
    space, root = await _space_block(db_session, "10.163.0.0/16")
    sid = await _mk_subnet(client, h, space, root, "10.163.4.0/29")
    for i in range(2, 6):
        r = await client.post(
            f"/api/v1/ipam/subnets/{sid}/addresses",
            headers=h,
            json={"address": f"10.163.4.{i}", "status": "allocated", "hostname": f"h{i}"},
        )
        assert r.status_code == 201, r.text
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": "10.163.4.6", "status": "available", "hostname": "free6"},
    )
    assert r.status_code == 201, r.text
    return sid, root


async def test_next_available_offers_an_available_row(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    sid, _ = await _avail_subnet(client, h, db_session)
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    assert (sub["allocated_ips"], sub["total_ips"]) == (5, 6)
    p = await client.get(f"/api/v1/ipam/subnets/{sid}/next-ip-preview", headers=h)
    assert p.json()["address"] == "10.163.4.6"
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=h,
        json={"status": "allocated", "hostname": "n"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["address"] == "10.163.4.6"
    assert r.json()["status"] == "allocated"
    sub = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()
    assert sub["allocated_ips"] == 6
    # Now truly full.
    p = await client.get(f"/api/v1/ipam/subnets/{sid}/next-ip-preview", headers=h)
    assert p.json()["address"] is None


async def test_specific_ip_reuses_an_available_row_but_refuses_a_held_one(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    sid, _ = await _avail_subnet(client, h, db_session)
    held = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": "10.163.4.5", "status": "allocated", "hostname": "x"},
    )
    assert held.status_code == 409
    assert "already allocated" in held.json()["detail"]
    ok = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": "10.163.4.6", "status": "allocated", "hostname": "y"},
    )
    assert ok.status_code == 201, ok.text
    rows = await _addrs(client, h, sid)
    assert rows["10.163.4.6"] == "allocated"
    assert (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).json()["allocated_ips"] == 6


# ── #2980: the take keeps the row and retracts what it published ─────────


async def test_specific_ip_takes_a_swept_reservation_in_place(
    client: AsyncClient, db_session: AsyncSession
):
    """The reservation sweep flips an expired ``reserved`` row to ``available``
    and keeps its name, its A / alias records and its MAC history. Taking the
    address must retract those records (not leave them served with no row,
    which a delete would: ``dns_record.ip_address_id`` is SET NULL), keep the
    row's identity (a delete would CASCADE away MAC history and the OT /
    BACnet / E911 registrations hanging off it) and audit the take."""
    from sqlalchemy import select

    from app.models.audit import AuditLog
    from app.models.ipam import IPAddress, IpMacHistory
    from tests.test_ipam_alias_cname_exclusive_2080 import _records, _setup

    h, sid, zone = await _setup(client, db_session, "10.97.0.0/16", "10.97.5.0/24")
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={
            "address": "10.97.5.50",
            "status": "reserved",
            "hostname": "old50",
            "mac_address": "aa:bb:cc:00:00:50",
            "description": "held",
            "aliases": [{"name": "www50", "record_type": "CNAME"}],
        },
    )
    assert r.status_code == 201, r.text
    old_id = r.json()["id"]
    assert ("old50", "A") in await _records(db_session, zone.id)
    assert ("www50", "CNAME") in await _records(db_session, zone.id)
    # What the sweep does (ipam_reservation_sweep._sweep).
    row = await db_session.get(IPAddress, uuid.UUID(old_id))
    assert row is not None
    row.status = "available"
    await db_session.commit()

    p = await client.get(f"/api/v1/ipam/subnets/{sid}/next-ip-preview", headers=h)
    assert p.status_code == 200
    ok = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": "10.97.5.50", "status": "allocated", "hostname": "new50"},
    )
    assert ok.status_code == 201, ok.text
    body = ok.json()
    assert body["id"] == old_id
    assert body["hostname"] == "new50"
    assert body["mac_address"] is None
    assert body["description"] == ""
    recs = await _records(db_session, zone.id)
    assert ("old50", "A") not in recs
    assert ("www50", "CNAME") not in recs
    assert ("new50", "A") in recs
    hist = (
        (
            await db_session.execute(
                select(IpMacHistory).where(IpMacHistory.ip_address_id == uuid.UUID(old_id))
            )
        )
        .scalars()
        .all()
    )
    assert len(hist) == 1
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "ip_address", AuditLog.resource_id == old_id
                )
            )
        )
        .scalars()
        .all()
    )
    took = [a for a in audits if (a.old_value or {}).get("reason") == "reclaimed_available_row"]
    assert len(took) == 1
    assert took[0].old_value["hostname"] == "old50"


async def test_an_available_row_still_linked_to_a_reservation_is_held(
    client: AsyncClient, db_session: AsyncSession
):
    from app.models.ipam import IPAddress

    h = await _headers(db_session)
    sid, _ = await _avail_subnet(client, h, db_session)
    from sqlalchemy import select

    row = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == uuid.UUID(sid), IPAddress.address == "10.163.4.6"
            )
        )
    ).scalar_one()
    row.static_assignment_id = str(uuid.uuid4())
    await db_session.commit()
    p = await client.get(f"/api/v1/ipam/subnets/{sid}/next-ip-preview", headers=h)
    assert p.json()["address"] is None
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": "10.163.4.6", "status": "allocated", "hostname": "y"},
    )
    assert r.status_code == 409, r.text


# ── #2979: the import follows New Subnet's rule, kind included ───────────


async def test_import_multicast_subnet_gets_no_placeholder_rows(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    space = IPSpace(name=f"sp2979m-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.commit()
    csv = b"network,name,gateway\n239.192.10.0/24,mc,\n10.233.90.0/31,p2p,\n"
    r = await client.post(
        "/api/v1/ipam/import/commit",
        headers=h,
        files={"file": ("s.csv", csv, "text/csv")},
        data={"space_id": str(space.id), "strategy": "fail"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["created_subnets"] == 2, r.text
    subs = (await client.get(f"/api/v1/ipam/subnets?space_id={space.id}", headers=h)).json()
    subs = subs["items"] if isinstance(subs, dict) else subs
    by_net = {s["network"]: s for s in subs}
    mc = by_net["239.192.10.0/24"]
    assert mc["kind"] == "multicast"
    assert await _addrs(client, h, mc["id"]) == {}
    assert await _addrs(client, h, by_net["10.233.90.0/31"]["id"]) == {}


async def test_import_many_subnets_rolls_up_a_shared_chain(
    client: AsyncClient, db_session: AsyncSession
):
    """Several imported subnets under one existing chain: every block on it
    equals the sum of its subnets (recounted once per block, batched)."""
    h = await _headers(db_session)
    space, root = await _space_block(db_session, "10.235.0.0/16")
    mid = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={"space_id": space, "parent_block_id": root, "network": "10.235.0.0/20", "name": "m"},
    )
    assert mid.status_code == 201, mid.text
    rows = "".join(f"10.235.{i}.0/24,s{i},\n" for i in range(1, 6)).encode()
    r = await client.post(
        "/api/v1/ipam/import/commit",
        headers=h,
        files={"file": ("s.csv", b"network,name,gateway\n" + rows, "text/csv")},
        data={"space_id": space, "strategy": "fail"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["created_subnets"] == 5
    assert await _alloc(client, h, "blocks", mid.json()["id"]) == 5
    assert await _alloc(client, h, "blocks", root) == 5
