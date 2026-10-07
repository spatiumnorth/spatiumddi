"""spatiumddi#1633 — IPAM writes forward records only into a zone it authors.

A subnet can be bound to any zone of its DNS group as its forward zone,
whatever the zone's type, and an address can list any zone in
``extra_zone_ids``. IPAM wrote every host's A/AAAA record (and every alias)
into such a zone and queued a create op for the group's primary, which
cannot take it: the BIND9 agent renders a forward zone as a forwarders block
with no zone file and no allow-update, and a secondary's or a stub's data
comes from its primary. The record was served by nobody, and the drift check
read the subnet in sync because it expected the record in the same zone.

This is the forward half of spatiumddi#1419, which states the same contract
for PTRs: IPAM writes a record only into a zone SpatiumDDI serves as primary.
A forwarder, a secondary or a stub bound to a subnet still names its hosts
(their FQDN, and the PTR IPAM writes for them in a reverse zone it does
author), but IPAM writes no A/AAAA or alias into it and queues no op, and the
drift check expects none.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

NOT_AUTHORED = ["forward", "secondary", "stub"]


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u1633-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _zone(grp: DNSServerGroup, label: str, zone_type: str) -> DNSZone:
    """A forward-lookup zone of ``zone_type``, stored ``kind: forward`` the way
    Add Zone and the importers store a zone with a name like this."""
    if zone_type == "primary":
        extra: dict[str, object] = {"primary_ns": "ns1.example.", "admin_email": "admin.example."}
    elif zone_type == "forward":
        extra = {"forwarders": ["192.0.2.53"], "primary_ns": "", "admin_email": ""}
    else:
        extra = {"masters": ["192.0.2.10"], "primary_ns": "", "admin_email": ""}
    return DNSZone(
        group_id=grp.id,
        name=f"{label}-{uuid.uuid4().hex[:6]}.example.",
        zone_type=zone_type,
        kind="forward",
        **extra,
    )


async def _setup(db: AsyncSession) -> tuple[DNSServerGroup, IPSpace, IPBlock]:
    """A group served by one BIND9 primary, and a space with the 10.97.0.0/16
    block the subnet is carved from."""
    grp = DNSServerGroup(name=f"g1633-{uuid.uuid4().hex[:6]}")
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
    space = IPSpace(name=f"sp1633-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.97.0.0/16", name="b")
    db.add(block)
    await db.flush()
    return grp, space, block


async def _subnet(
    client: AsyncClient,
    headers: dict[str, str],
    space: IPSpace,
    block: IPBlock,
    grp: DNSServerGroup,
    zone: DNSZone,
    *,
    skip_reverse_zone: bool = True,
) -> str:
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.97.5.0/24",
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(zone.id),
            "skip_reverse_zone": skip_reverse_zone,
        },
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _allocate(
    client: AsyncClient,
    headers: dict[str, str],
    sid: str,
    address: str,
    hostname: str,
    **extra: object,
) -> str:
    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": address, "hostname": hostname, **extra},
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _records(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type, DNSRecord.value)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted((str(n), str(t), str(v)) for n, t, v in rows)


async def _ops(db: AsyncSession, zone_name: str) -> list[tuple[str, str]]:
    rows = (
        await db.execute(
            select(DNSRecordOp.op, DNSRecordOp.record["name"].astext).where(
                DNSRecordOp.zone_name == zone_name
            )
        )
    ).all()
    return sorted((str(op), str(name)) for op, name in rows)


async def _ip(db: AsyncSession, ip_id: str | uuid.UUID) -> IPAddress:
    ip = (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.id == uuid.UUID(str(ip_id)))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return ip


async def _preview(client: AsyncClient, headers: dict[str, str], sid: str) -> dict:
    resp = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/preview", headers=headers)
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


# ── The issue's contract ──────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("zone_type", NOT_AUTHORED)
async def test_ipam_writes_no_forward_record_into_a_zone_it_does_not_author(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    """The issue's reproduction: a subnet bound to a ``zone_type`` zone as its
    forward zone, one allocated host. On the broken build the host's A record
    was written into the zone and a create op queued for it. The zone still
    names the host: the PTR in the subnet's own reverse zone points at
    ``host.<zone>``, as before."""
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    other = _zone(grp, "corp", zone_type)
    db_session.add(other)
    await db_session.commit()

    sid = await _subnet(client, headers, space, block, grp, other, skip_reverse_zone=False)
    host = await _allocate(client, headers, sid, "10.97.5.10", "host")

    records, ops = await _records(db_session, other.id), await _ops(db_session, other.name)
    assert (records, ops) == ([], []), (
        f"IPAM wrote into a {zone_type} zone it does not author: "
        f"records {records}, record ops queued {ops}"
    )
    ip = await _ip(db_session, host)
    assert (ip.dns_record_id, ip.forward_zone_id) == (None, other.id)
    assert ip.fqdn == f"host.{other.name.rstrip('.')}"

    rev = (
        await db_session.execute(
            select(DNSZone).where(
                DNSZone.group_id == grp.id, DNSZone.name == "5.97.10.in-addr.arpa."
            )
        )
    ).scalar_one()
    assert await _records(db_session, rev.id) == [
        ("1", "PTR", f"gateway.{other.name}"),
        ("10", "PTR", f"host.{other.name}"),
    ]
    # The drift check expects no forward record either, and reads in sync.
    report = await _preview(client, headers, sid)
    assert (report["missing"], report["mismatched"], report["stale"]) == ([], [], []), report


@pytest.mark.asyncio
async def test_extra_zones_take_the_record_only_where_ipam_authors_them(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``extra_zone_ids`` fans the record out (#25). A primary among them takes
    it; a forwarder, a secondary and a stub among them do not, and no op is
    queued for them. On the broken build every one of them took the record."""
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    primary = _zone(grp, "home", "primary")
    extra_primary = _zone(grp, "extra", "primary")
    others = [_zone(grp, f"x{zone_type}", zone_type) for zone_type in NOT_AUTHORED]
    db_session.add_all([primary, extra_primary, *others])
    await db_session.commit()

    sid = await _subnet(client, headers, space, block, grp, primary)
    await _allocate(
        client,
        headers,
        sid,
        "10.97.5.10",
        "host",
        extra_zone_ids=[str(extra_primary.id), *(str(z.id) for z in others)],
    )

    assert await _records(db_session, primary.id) == [("host", "A", "10.97.5.10")]
    assert await _records(db_session, extra_primary.id) == [("host", "A", "10.97.5.10")]
    assert await _ops(db_session, extra_primary.name) == [("create", "host")]
    written = {
        z.zone_type: (await _records(db_session, z.id), await _ops(db_session, z.name))
        for z in others
    }
    assert written == {zone_type: ([], []) for zone_type in NOT_AUTHORED}


@pytest.mark.asyncio
async def test_ipam_writes_no_alias_into_a_zone_it_does_not_author(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Aliases are records IPAM writes into the same zone. Allocating with an
    alias writes none into a forwarder, and asking for one says why instead
    of writing it. On the broken build both were written, with create ops."""
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    forwarder = _zone(grp, "corp", "forward")
    db_session.add(forwarder)
    await db_session.commit()
    sid = await _subnet(client, headers, space, block, grp, forwarder)

    host = await _allocate(
        client,
        headers,
        sid,
        "10.97.5.10",
        "host",
        aliases=[{"name": "www", "record_type": "CNAME"}],
    )
    resp = await client.post(
        f"/api/v1/ipam/addresses/{host}/aliases",
        headers=headers,
        json={"name": "ftp", "record_type": "CNAME"},
    )
    assert resp.status_code == 409, resp.text
    assert forwarder.name in resp.text and "primary" in resp.text, resp.text

    assert await _records(db_session, forwarder.id) == []
    assert await _ops(db_session, forwarder.name) == []


# ── A zone that stops being SpatiumDDI's, and rows an earlier release wrote ───


@pytest.mark.asyncio
async def test_a_forward_zone_made_secondary_takes_no_more_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An operator hands a subnet's forward zone to another server (Edit Zone:
    secondary, a master set). Its names now come from that server: IPAM writes
    no record for the next host, and the record it wrote before is dropped
    from the zone's rows the next time it syncs that address, with no op,
    since a secondary refuses updates. A 422 on the binding could not catch
    this: the zone changed type after it was bound."""
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    zone = _zone(grp, "corp", "primary")
    db_session.add(zone)
    await db_session.commit()

    sid = await _subnet(client, headers, space, block, grp, zone)
    first = await _allocate(client, headers, sid, "10.97.5.10", "host")
    assert await _records(db_session, zone.id) == [("host", "A", "10.97.5.10")]

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        headers=headers,
        json={"zone_type": "secondary", "masters": ["192.0.2.10"]},
    )
    assert resp.status_code == 200, resp.text
    ops_before = await _ops(db_session, zone.name)

    await _allocate(client, headers, sid, "10.97.5.11", "host2")
    resp = await client.put(
        f"/api/v1/ipam/addresses/{first}", headers=headers, json={"hostname": "host-renamed"}
    )
    assert resp.status_code == 200, resp.text

    assert [r for r in await _records(db_session, zone.id) if r[1] in ("A", "AAAA")] == []
    assert await _ops(db_session, zone.name) == ops_before


@pytest.mark.asyncio
async def test_records_an_earlier_release_wrote_into_a_forwarder_leave_without_an_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Upgraded from a release with the bug: a forwarder bound to a subnet
    holds IPAM's A records for three hosts. Renaming one drops its row,
    renaming another back to the gateway placeholder drops its row, and
    deleting the third drops its row; none queues an op against the
    forwarder, which never took the records. On the broken build the rename
    queued a delete and a create, and the gateway rename a delete."""
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    forwarder = _zone(grp, "corp", "forward")
    db_session.add(forwarder)
    await db_session.commit()
    sid = await _subnet(client, headers, space, block, grp, forwarder)
    subnet = await db_session.get(Subnet, uuid.UUID(sid))
    assert subnet is not None

    ips: dict[str, IPAddress] = {}
    for last, host in (("10", "alpha"), ("11", "beta"), ("12", "gamma")):
        ip = IPAddress(subnet_id=subnet.id, address=f"10.97.5.{last}", status="allocated")
        ip.hostname = host
        db_session.add(ip)
        await db_session.flush()
        rec = DNSRecord(
            zone_id=forwarder.id,
            name=host,
            fqdn=f"{host}.{forwarder.name.rstrip('.')}",
            record_type="A",
            value=f"10.97.5.{last}",
            auto_generated=True,
            ip_address_id=ip.id,
        )
        db_session.add(rec)
        await db_session.flush()
        ip.dns_record_id = rec.id
        ip.forward_zone_id = forwarder.id
        ip.fqdn = rec.fqdn
        ips[host] = ip
    await db_session.commit()
    ops_before = await _ops(db_session, forwarder.name)

    resp = await client.put(
        f"/api/v1/ipam/addresses/{ips['alpha'].id}",
        headers=headers,
        json={"hostname": "alpha-renamed"},
    )
    assert resp.status_code == 200, resp.text
    resp = await client.put(
        f"/api/v1/ipam/addresses/{ips['gamma'].id}", headers=headers, json={"hostname": "gateway"}
    )
    assert resp.status_code == 200, resp.text
    resp = await client.delete(f"/api/v1/ipam/addresses/{ips['beta'].id}", headers=headers)
    assert resp.status_code == 204, resp.text

    assert await _records(db_session, forwarder.id) == []
    assert await _ops(db_session, forwarder.name) == ops_before
    alpha = await _ip(db_session, ips["alpha"].id)
    assert (alpha.dns_record_id, alpha.forward_zone_id) == (None, forwarder.id)
    assert alpha.fqdn == f"alpha-renamed.{forwarder.name.rstrip('.')}"


@pytest.mark.asyncio
async def test_an_address_named_in_a_forwarder_keeps_it_across_a_rename(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An address whose own zone is a forwarder, in a subnet whose zone is a
    primary. IPAM writes its record into neither: not into the forwarder, and
    not into the subnet's zone on a later rename, since the address keeps the
    forwarder as its forward zone (#493: a hostname edit never re-homes the
    record out of the address's zone). On the broken build the forwarder took
    the record and the rename's ops."""
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    primary = _zone(grp, "home", "primary")
    forwarder = _zone(grp, "corp", "forward")
    db_session.add_all([primary, forwarder])
    await db_session.commit()
    sid = await _subnet(client, headers, space, block, grp, primary)

    host = await _allocate(
        client, headers, sid, "10.97.5.10", "host", dns_zone_id=str(forwarder.id)
    )
    resp = await client.put(
        f"/api/v1/ipam/addresses/{host}", headers=headers, json={"hostname": "host-renamed"}
    )
    assert resp.status_code == 200, resp.text

    written = {
        "forwarder": (
            await _records(db_session, forwarder.id),
            await _ops(db_session, forwarder.name),
        ),
        "subnet zone": (
            await _records(db_session, primary.id),
            await _ops(db_session, primary.name),
        ),
    }
    assert written == {"forwarder": ([], []), "subnet zone": ([], [])}
    ip = await _ip(db_session, host)
    assert (ip.forward_zone_id, ip.fqdn) == (
        forwarder.id,
        f"host-renamed.{forwarder.name.rstrip('.')}",
    )


# ── The drift check ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_drift_check_offers_no_delete_into_a_zone_it_does_not_author(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An A record an earlier release wrote into a forwarder for an address
    since deleted (its ``ip_address_id`` set null). The drift check listed it
    stale, so applying the sync queued a delete op the forwarder cannot take.
    The zone is not one IPAM writes into, so its rows are not IPAM's drift."""
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    forwarder = _zone(grp, "corp", "forward")
    db_session.add(forwarder)
    await db_session.commit()
    sid = await _subnet(client, headers, space, block, grp, forwarder)
    db_session.add(
        DNSRecord(
            zone_id=forwarder.id,
            name="gone",
            fqdn=f"gone.{forwarder.name.rstrip('.')}",
            record_type="A",
            value="10.97.5.20",
            auto_generated=True,
            ip_address_id=None,
        )
    )
    await db_session.commit()

    report = await _preview(client, headers, sid)
    assert [s for s in report["stale"] if s["zone_id"] == str(forwarder.id)] == [], report
    assert (report["missing"], report["mismatched"]) == ([], []), report
