"""Bulk edit's "clear DNS zone" removes the records (#2172).

``dns_zone_id: ""`` in Bulk edit IPs used to run ``_sync_dns_record`` with
``zone_id=None, action="update"`` — and ``None`` there means "resolve a zone",
so the records moved into the subnet's zone, or (with no subnet zone) were
re-published where they already were, and the request reported success.

A bulk clear now runs the clear single Edit runs for zone None: every
auto-generated record the address owns (forward A/AAAA, PTR, aliases, extra
zones) is deleted with a delete op queued, ``forward_zone_id`` goes null, and
the response names the addresses whose records were removed.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _setup(
    client: AsyncClient, db: AsyncSession, *, subnet_zone: bool
) -> tuple[dict[str, str], str, DNSZone, DNSZone]:
    """A subnet 10.97.5.0/24 with a reverse zone; returns (headers, subnet
    id, the subnet's zone or a zone not bound to it, a second forward zone)."""
    headers = await _headers(db)
    grp = DNSServerGroup(name=f"g2172-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zones = []
    for prefix in ("a", "b"):
        z = DNSZone(
            group_id=grp.id,
            name=f"{prefix}{uuid.uuid4().hex[:6]}.example.",
            zone_type="primary",
            kind="forward",
            primary_ns="ns1.example.",
            admin_email="admin.example.",
        )
        db.add(z)
        zones.append(z)
    db.add(
        DNSZone(
            group_id=grp.id,
            name="5.97.10.in-addr.arpa.",
            zone_type="primary",
            kind="reverse",
            primary_ns="ns1.example.",
            admin_email="admin.example.",
        )
    )
    space = IPSpace(name=f"sp2172-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.97.0.0/16", name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    body: dict[str, object] = {
        "space_id": str(space.id),
        "block_id": str(block.id),
        "network": "10.97.5.0/24",
        "skip_reverse_zone": True,
    }
    if subnet_zone:
        body["dns_group_id"] = str(grp.id)
        body["dns_zone_id"] = str(zones[0].id)
    resp = await client.post("/api/v1/ipam/subnets", headers=headers, json=body)
    assert resp.status_code == 201, resp.text
    return headers, str(resp.json()["id"]), zones[0], zones[1]


async def _alloc(
    client: AsyncClient, headers: dict[str, str], sid: str, addr: str, host: str, **extra: object
) -> str:
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": addr, "hostname": host, **extra},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _rows(db: AsyncSession, ip_id: str) -> list[tuple[str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type).where(
                DNSRecord.ip_address_id == uuid.UUID(ip_id)
            )
        )
    ).all()
    return sorted((str(n), str(t)) for n, t in rows)


async def _delete_ops(db: AsyncSession) -> list[tuple[str, str, str]]:
    ops = (
        (
            await db.execute(
                select(DNSRecordOp)
                .where(DNSRecordOp.op == "delete")
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    return sorted(
        (str(o.record.get("name")), str(o.record.get("type")), str(o.record.get("value")))
        for o in ops
    )


async def _forward_zone(db: AsyncSession, ip_id: str) -> uuid.UUID | None:
    ip = (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.id == uuid.UUID(ip_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return ip.forward_zone_id


async def _bulk_clear(client: AsyncClient, headers: dict[str, str], ids: list[str]) -> dict:
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=headers,
        json={"ip_ids": ids, "changes": {"dns_zone_id": ""}},
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
@pytest.mark.parametrize("subnet_zone", [True, False])
async def test_bulk_clear_removes_forward_and_ptr_records(
    client: AsyncClient, db_session: AsyncSession, subnet_zone: bool
) -> None:
    headers, sid, zone, other = await _setup(client, db_session, subnet_zone=subnet_zone)
    # Each address sits in the zone NOT bound to the subnet, so the old code's
    # fallback is observable either way: a move into the subnet's zone, or (with
    # no subnet zone) a re-publish in place.
    ids = [
        await _alloc(client, headers, sid, f"10.97.5.{n}", f"h{n}", dns_zone_id=str(other.id))
        for n in (10, 11, 12)
    ]
    # The reverse zone is found through the subnet's DNS group, so a subnet
    # with no DNS binding publishes no PTR.
    ptr = subnet_zone
    for n, ip_id in zip((10, 11, 12), ids, strict=True):
        expected = [(f"h{n}", "A")] + ([(str(n), "PTR")] if ptr else [])
        assert await _rows(db_session, ip_id) == sorted(expected)
        assert await _forward_zone(db_session, ip_id) == other.id

    res = await _bulk_clear(client, headers, ids)

    assert res["updated_count"] == 3
    for ip_id in ids:
        assert await _rows(db_session, ip_id) == []
        assert await _forward_zone(db_session, ip_id) is None
    # Nothing landed in the subnet's zone, or anywhere else.
    assert (
        await db_session.execute(
            select(DNSRecord).where(DNSRecord.zone_id.in_([zone.id, other.id]))
        )
    ).first() is None
    assert sorted((n, t) for n, t, _ in await _delete_ops(db_session)) == sorted(
        [(f"h{n}", "A") for n in (10, 11, 12)]
        + ([(str(n), "PTR") for n in (10, 11, 12)] if ptr else [])
    )
    assert sorted(res["dns_cleared"]) == sorted(ids)


@pytest.mark.asyncio
async def test_bulk_clear_in_the_subnet_zone_removes_rather_than_republishes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone, _other = await _setup(client, db_session, subnet_zone=True)
    ip_id = await _alloc(client, headers, sid, "10.97.5.20", "h20")
    assert await _forward_zone(db_session, ip_id) == zone.id

    res = await _bulk_clear(client, headers, [ip_id])

    assert await _rows(db_session, ip_id) == []
    assert await _forward_zone(db_session, ip_id) is None
    assert res["dns_cleared"] == [ip_id]


@pytest.mark.asyncio
async def test_bulk_clear_removes_aliases_and_extra_zone_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone, other = await _setup(client, db_session, subnet_zone=True)
    ip_id = await _alloc(
        client,
        headers,
        sid,
        "10.97.5.30",
        "h30",
        aliases=[{"name": "www", "record_type": "CNAME"}, {"name": "api", "record_type": "A"}],
    )
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"extra_zone_ids": [str(other.id)]},
    )
    assert put.status_code == 200, put.text
    before = await _rows(db_session, ip_id)
    assert ("www", "CNAME") in before and ("api", "A") in before
    assert before.count(("h30", "A")) == 2  # primary + extra zone

    res = await _bulk_clear(client, headers, [ip_id])

    assert await _rows(db_session, ip_id) == []
    assert await _forward_zone(db_session, ip_id) is None
    deleted = await _delete_ops(db_session)
    assert any(d[:2] == ("www", "CNAME") for d in deleted)
    assert ("api", "A", "10.97.5.30") in deleted
    assert [d for d in deleted if d[0] == "h30"] == [("h30", "A", "10.97.5.30")] * 2
    assert res["dns_cleared"] == [ip_id]


@pytest.mark.asyncio
async def test_bulk_clear_on_an_address_with_no_records_is_a_no_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone, _other = await _setup(client, db_session, subnet_zone=False)
    # No hostname and no zone: nothing was ever published.
    row = IPAddress(subnet_id=uuid.UUID(sid), address="10.97.5.40", status="allocated")
    db_session.add(row)
    await db_session.commit()
    bare = str(row.id)
    with_records = await _alloc(
        client, headers, sid, "10.97.5.41", "h41", dns_zone_id=str(_zone.id)
    )

    res = await _bulk_clear(client, headers, [bare, with_records])

    assert res["updated_count"] == 2
    assert res["skipped"] == []
    assert await _rows(db_session, bare) == []
    assert await _forward_zone(db_session, bare) is None
    assert await _rows(db_session, with_records) == []
    # Only the address that had records reports them removed.
    assert res["dns_cleared"] == [with_records]


@pytest.mark.asyncio
async def test_bulk_clear_matches_single_edit_clear(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone, other = await _setup(client, db_session, subnet_zone=True)
    single = await _alloc(
        client,
        headers,
        sid,
        "10.97.5.50",
        "h50",
        dns_zone_id=str(other.id),
        aliases=[{"name": "w50", "record_type": "CNAME"}],
    )
    bulk = await _alloc(
        client,
        headers,
        sid,
        "10.97.5.51",
        "h51",
        dns_zone_id=str(other.id),
        aliases=[{"name": "w51", "record_type": "CNAME"}],
    )

    put = await client.put(
        f"/api/v1/ipam/addresses/{single}", headers=headers, json={"dns_zone_id": None}
    )
    assert put.status_code == 200, put.text
    await _bulk_clear(client, headers, [bulk])

    for ip_id in (single, bulk):
        assert await _rows(db_session, ip_id) == []
        assert await _forward_zone(db_session, ip_id) is None
    deleted = await _delete_ops(db_session)
    # The same three deletes for each: the A, the PTR and the alias.
    for n in ("50", "51"):
        assert sorted(t for name, t, _ in deleted if name in {f"h{n}", n, f"w{n}"}) == [
            "A",
            "CNAME",
            "PTR",
        ]


async def _clear(client: AsyncClient, headers: dict[str, str], ip_id: str, how: str) -> None:
    if how == "bulk":
        await _bulk_clear(client, headers, [ip_id])
    else:
        put = await client.put(
            f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"dns_zone_id": None}
        )
        assert put.status_code == 200, put.text


async def _sync_dns(client: AsyncClient, headers: dict[str, str], sid: str) -> dict:
    """Preview the subnet's Sync DNS, then commit everything it offers, as the
    Sync DNS modal's "select all" and the scheduled auto-sync both do."""
    prev = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/preview", headers=headers)
    assert prev.status_code == 200, prev.text
    report = prev.json()
    commit = await client.post(
        f"/api/v1/ipam/subnets/{sid}/dns-sync/commit",
        headers=headers,
        json={
            "create_for_ip_ids": sorted({m["ip_id"] for m in report["missing"]}),
            "update_record_ids": [m["record_id"] for m in report["mismatched"]],
            "delete_stale_record_ids": [s["record_id"] for s in report["stale"]],
        },
    )
    assert commit.status_code == 200, commit.text
    return report


@pytest.mark.asyncio
@pytest.mark.parametrize("how", ["bulk", "single"])
async def test_a_cleared_address_is_not_republished_into_its_extra_zones(
    client: AsyncClient, db_session: AsyncSession, how: str
) -> None:
    """A clear empties ``extra_zone_ids`` with the records, or the next Sync
    DNS (or auto-sync, or any later edit) lists the extra-zone record missing
    and publishes it again, undoing the clear."""
    headers, sid, zone, other = await _setup(client, db_session, subnet_zone=False)
    ip_id = await _alloc(client, headers, sid, "10.97.5.60", "h60", dns_zone_id=str(other.id))
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"extra_zone_ids": [str(zone.id)]},
    )
    assert put.status_code == 200, put.text
    assert await _rows(db_session, ip_id) == [("h60", "A"), ("h60", "A")]

    await _clear(client, headers, ip_id, how)
    assert await _rows(db_session, ip_id) == []

    report = await _sync_dns(client, headers, sid)
    assert report["missing"] == []
    assert await _rows(db_session, ip_id) == []

    # A later unrelated edit does not bring them back either.
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "h60b"}
    )
    assert put.status_code == 200, put.text
    assert await _rows(db_session, ip_id) == []
    row = (
        await db_session.execute(
            select(IPAddress)
            .where(IPAddress.id == uuid.UUID(ip_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert row.extra_zone_ids == []
    assert row.forward_zone_id is None


@pytest.mark.asyncio
@pytest.mark.parametrize("how", ["bulk", "single"])
async def test_sync_dns_never_puts_a_cleared_address_back_in_its_old_zone(
    client: AsyncClient, db_session: AsyncSession, how: str
) -> None:
    """With ``forward_zone_id`` null the address has no zone of its own, so a
    Sync DNS that judges an address by its own zone (#2104) cannot return it
    to the one it was cleared from.

    A subnet with a forward zone still claims the host: the address follows
    it, and Sync DNS offers the record there. That is the subnet's binding, not
    the cleared zone coming back, and is stated rather than asserted here.
    """
    headers, sid, zone, other = await _setup(client, db_session, subnet_zone=True)
    ip_id = await _alloc(client, headers, sid, "10.97.5.70", "h70", dns_zone_id=str(other.id))
    await _clear(client, headers, ip_id, how)
    assert await _rows(db_session, ip_id) == []

    report = await _sync_dns(client, headers, sid)

    assert str(other.id) not in {m["zone_id"] for m in report["missing"]}
    assert (
        await db_session.execute(select(DNSRecord).where(DNSRecord.zone_id == other.id))
    ).first() is None
    assert await _forward_zone(db_session, ip_id) != other.id
