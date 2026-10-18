"""An address cannot be named after one of its own aliases (#2106).

Renaming an address onto its own A alias left two identical rows at the name;
deleting the alias then queued a delete for an RR the host record still
claimed, so the host vanished from the served zone. The sync now refuses
(409, the #2080 shape) on the request paths and skips-and-logs on the
background ones. A CNAME alias is the same clash with the CNAME rule behind it.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _alloc, _records, _setup
from tests.test_ipam_alias_marker_2084 import _extra_zone, _rows
from tests.test_ipam_dns_cname_1441 import _address_records, _ip, _reverse_zone
from tests.test_ipam_dns_cname_1441 import _setup as _cname_setup


async def _ops(db: AsyncSession, op: str | None = None) -> list[tuple[str, str, str, str]]:
    q = select(DNSRecordOp).execution_options(populate_existing=True)
    out = []
    for o in (await db.execute(q)).scalars().all():
        if op is None or o.op == op:
            r = o.record
            out.append((o.op, str(r.get("name")), str(r.get("type")), str(r.get("value"))))
    return sorted(out)


@pytest.mark.asyncio
async def test_rename_onto_own_a_alias_is_refused_and_the_host_survives_alias_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    r = await _alloc(
        client, headers, sid, "10.98.5.10", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    assert r.status_code == 201, r.text
    ip_id = r.json()["id"]
    ops_before = await _ops(db_session)

    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "www"}
    )
    assert put.status_code == 409, put.text
    assert "www" in put.text and "alias" in put.text

    # Nothing of the refused edit was written: one A per name, no new ops.
    assert await _records(db_session, zone.id) == [("h1", "A"), ("www", "A")]
    assert await _ops(db_session) == ops_before
    # (The test session is shared with the app, so the unrolled-back in-memory
    # hostname is not evidence either way; the rows and the ops are.)

    # The alias can still be deleted, and only the alias goes from the zone.
    rows = await _rows(db_session, ip_id)
    alias = next(x for x in rows if x.name == "www")
    d = await client.delete(f"/api/v1/ipam/addresses/{ip_id}/aliases/{alias.id}", headers=headers)
    assert d.status_code in (200, 204), d.text
    assert [o for o in await _ops(db_session, "delete")] == [("delete", "www", "A", "10.98.5.10")]
    assert await _records(db_session, zone.id) == [("h1", "A")]


@pytest.mark.asyncio
async def test_rename_onto_own_cname_alias_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    r = await _alloc(
        client, headers, sid, "10.98.5.11", "h1", aliases=[{"name": "www", "record_type": "CNAME"}]
    )
    ip_id = r.json()["id"]
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "WWW"}
    )
    assert put.status_code == 409, put.text
    assert "CNAME" in put.text and "RFC 2181" in put.text
    assert await _records(db_session, zone.id) == [("h1", "A"), ("www", "CNAME")]


@pytest.mark.asyncio
async def test_aaaa_alias_on_an_ipv6_address(client: AsyncClient, db_session: AsyncSession) -> None:
    headers, sid, zone = await _setup(client, db_session, "fd00:98::/48", "fd00:98:0:5::/64")
    r = await _alloc(
        client,
        headers,
        sid,
        "fd00:98:0:5::10",
        "h1",
        aliases=[{"name": "www", "record_type": "A"}],
    )
    assert r.status_code == 201, r.text
    assert await _records(db_session, zone.id) == [("h1", "AAAA"), ("www", "AAAA")]
    put = await client.put(
        f"/api/v1/ipam/addresses/{r.json()['id']}", headers=headers, json={"hostname": "www"}
    )
    assert put.status_code == 409, put.text
    assert "AAAA alias" in put.text


@pytest.mark.asyncio
async def test_alias_equal_to_the_hosts_own_name_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    bad = await _alloc(
        client, headers, sid, "10.98.5.12", "h1", aliases=[{"name": "H1", "record_type": "A"}]
    )
    assert bad.status_code == 409, bad.text
    ok = await _alloc(client, headers, sid, "10.98.5.13", "h2")
    add = await client.post(
        f"/api/v1/ipam/addresses/{ok.json()['id']}/aliases",
        headers=headers,
        json={"name": "h2", "record_type": "A"},
    )
    assert add.status_code == 409, add.text
    assert await _records(db_session, zone.id) == [("h2", "A")]


@pytest.mark.asyncio
async def test_zone_change_back_onto_an_alias_is_refused_single_and_bulk(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    other = await _extra_zone(db_session, zone)
    r = await _alloc(
        client, headers, sid, "10.98.5.14", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    ip_id = r.json()["id"]
    # Host moves to the other zone under the alias's name: no clash there.
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"dns_zone_id": str(other.id), "hostname": "www"},
    )
    assert put.status_code == 200, put.text
    # Moving it back puts the host on the alias, in the zone that holds it.
    back = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"dns_zone_id": str(zone.id)}
    )
    assert back.status_code == 409, back.text
    bulk = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=headers,
        json={"ip_ids": [ip_id], "changes": {"dns_zone_id": str(zone.id)}},
    )
    assert bulk.status_code == 409, bulk.text
    rows = await _rows(db_session, ip_id)
    assert sorted((x.name, str(x.zone_id)) for x in rows if x.record_type == "A") == sorted(
        [("www", str(zone.id)), ("www", str(other.id))]
    )


@pytest.mark.asyncio
async def test_extra_zone_edit_onto_an_alias_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    other = await _extra_zone(db_session, zone)
    r = await _alloc(
        client, headers, sid, "10.98.5.15", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    ip_id = r.json()["id"]
    # Host in extra zone under the alias's name while the alias stays in the primary:
    # renaming it puts the host in BOTH zones, and the primary one holds the alias.
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"extra_zone_ids": [str(other.id)], "hostname": "www"},
    )
    assert put.status_code == 409, put.text


@pytest.mark.asyncio
async def test_background_sync_skips_and_never_writes_a_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    r = await _alloc(
        client, headers, sid, "10.98.5.16", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    ip_id = uuid.UUID(r.json()["id"])
    ip = await db_session.get(IPAddress, ip_id, populate_existing=True)
    assert ip is not None
    subnet = await db_session.get(Subnet, ip.subnet_id)
    assert subnet is not None
    ip.hostname = "www"  # what a lease / integration rename does
    await _sync_dns_record(db_session, ip, subnet, action="update")  # not strict: no raise
    await db_session.commit()
    rows = list(
        (
            await db_session.execute(
                select(DNSRecord)
                .where(DNSRecord.ip_address_id == ip_id, DNSRecord.record_type == "A")
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert [(x.name, x.ip_alias) for x in rows] == [("www", True)]
    # nothing is created at www beyond the alias's own create from allocation
    creates = [o for o in await _ops(db_session, "create") if o[1] == "www"]
    assert len(creates) == 1  # the alias's own create, from allocation
    assert isinstance(zone, DNSZone)


# ── Validator: the background (non-strict) paths, decided cases ──────────────
#
# A lease, an integration or an importer renames an address onto one of its
# own aliases. These pin what DNS is left holding, on the sync directly.


async def _own_alias_setup(
    db: AsyncSession, alias_type: str
) -> tuple[Subnet, DNSZone, IPAddress, DNSRecord]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
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
    zone = DNSZone(
        group_id=grp.id,
        name="corp.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.corp.test.",
        admin_email="admin.corp.test.",
    )
    db.add(zone)
    await db.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.81.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.81.1.0/24",
        name="s",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    await _reverse_zone(db, subnet, zone)
    ip = IPAddress(subnet_id=subnet.id, address="10.81.1.30", status="allocated", hostname="h1")
    db.add(ip)
    await db.flush()
    await _sync_dns_record(db, ip, subnet)
    alias = DNSRecord(
        zone_id=zone.id,
        name="www",
        fqdn="www.corp.test",
        record_type=alias_type,
        value="h1.corp.test." if alias_type == "CNAME" else "10.81.1.30",
        auto_generated=True,
        ip_alias=True,
        ip_address_id=ip.id,
    )
    db.add(alias)
    await db.flush()
    return subnet, zone, ip, alias


async def _zone_rows(db: AsyncSession, ip: IPAddress) -> list[tuple[str, str, str, bool]]:
    rows = await db.execute(
        select(DNSRecord)
        .where(DNSRecord.ip_address_id == ip.id)
        .execution_options(populate_existing=True)
    )
    return sorted((r.name, r.record_type, r.value, r.ip_alias) for r in rows.scalars().all())


@pytest.mark.asyncio
async def test_background_rename_onto_own_a_alias_leaves_the_name_answering(
    db_session: AsyncSession,
) -> None:
    """The skip retracts the old name rather than keeping it (question 1).

    The alias already answers ``www -> address``, so after the retraction DNS
    holds exactly what a correct rename would: ``www`` resolves, the PTR names
    ``www``, and the stale ``h1`` (which another lease could take) is gone. The
    next sync after the alias is deleted writes the host record itself.
    """
    subnet, zone, ip, alias = await _own_alias_setup(db_session, "A")
    ip.hostname = "www"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    assert await _zone_rows(db_session, ip) == [
        ("30", "PTR", "www.corp.test.", False),
        ("www", "A", "10.81.1.30", True),
    ]

    await db_session.delete(alias)
    await db_session.flush()
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    assert await _zone_rows(db_session, ip) == [
        ("30", "PTR", "www.corp.test.", False),
        ("www", "A", "10.81.1.30", False),
    ]


@pytest.mark.asyncio
async def test_background_rename_onto_own_cname_alias_keeps_the_1493_ptr_rule(
    db_session: AsyncSession,
) -> None:
    """A CNAME alias on a background path is the #1441 skip, PTR rule included:
    no PTR may name a CNAME (RFC 1912 section 2.4, #1493), and the DDNS path
    must hear that nothing was published."""
    subnet, zone, ip, _alias = await _own_alias_setup(db_session, "CNAME")
    ip.hostname = "www"
    published = await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    assert await _zone_rows(db_session, ip) == [("www", "CNAME", "h1.corp.test.", True)]
    assert published is False
    assert getattr(ip, "_dns_skipped_cname", False) is True


@pytest.mark.asyncio
async def test_strict_sync_still_skips_an_operator_cname(db_session: AsyncSession) -> None:
    """#1441 for an operator's CNAME (not an alias) is unchanged on strict paths."""
    subnet, zone = await _cname_setup(db_session)
    ip = await _ip(db_session, subnet, "10.81.1.40", "www")
    await _sync_dns_record(db_session, ip, subnet, strict=True)
    await db_session.flush()
    assert await _address_records(db_session, zone, "www") == []


@pytest.mark.asyncio
async def test_a_duplicate_that_predates_the_fix_is_left_and_a_rename_away_moves_the_host(
    db_session: AsyncSession,
) -> None:
    """The "zone already carries the name" exemption: host and alias both at
    ``www`` (written before this fix). A re-sync touches nothing; a rename away
    moves the host row only, and its delete names the host's row, so the
    alias's identical RR stays on the wire (#1230)."""
    subnet, zone, ip, alias = await _own_alias_setup(db_session, "A")
    # Put the host on the alias's name the way a release before the fix did.
    host = (
        await db_session.execute(
            select(DNSRecord).where(
                DNSRecord.ip_address_id == ip.id,
                DNSRecord.record_type == "A",
                DNSRecord.ip_alias.is_(False),
            )
        )
    ).scalar_one()
    host.name, host.fqdn = "www", "www.corp.test"
    ip.hostname = "www"
    await db_session.flush()
    forward_before = [o for o in await _ops(db_session) if o[2] == "A"]

    # Not refused, and no forward op: the host already holds the name.
    await _sync_dns_record(db_session, ip, subnet, action="update", strict=True)
    await db_session.flush()
    assert [o for o in await _ops(db_session) if o[2] == "A"] == forward_before

    ip.hostname = "h3"
    await _sync_dns_record(db_session, ip, subnet, action="update", strict=True)
    await db_session.flush()
    rows = await _zone_rows(db_session, ip)
    assert ("h3", "A", "10.81.1.30", False) in rows
    assert ("www", "A", "10.81.1.30", True) in rows
    deletes = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.op == "delete")))
        .scalars()
        .all()
    )
    www_deletes = [o for o in deletes if o.record.get("name") == "www"]
    assert [o.record.get("record_id") for o in www_deletes] == [str(host.id)]
    assert alias.id != host.id
