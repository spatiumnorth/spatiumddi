"""spatiumddi#1419 — IPAM writes PTR records only into a zone it authors.

IPAM chose the zone for a PTR by kind and name suffix alone
(``_resolve_reverse_zone``), never by zone type. So a conditional forwarder, a
secondary or a stub stored ``kind: reverse`` — the importers classify a zone's
kind by its name whatever its type, and an operator who picks Reverse lookup
for a forwarder of a reverse name makes the truthful choice — took IPAM's PTR
rows for the gateway and every allocated host, and record ops were queued for
the group's primary, which refuses them: the BIND9 agent renders a forward zone
as a forwarders block with no zone file and no allow-update, and a secondary's
or a stub's data comes from its primary. The drift check found the zone the
same way (``_effective_reverse_zone``) and read the subnet in sync, and the
reverse-zone auto-create returned it by name as the subnet's reverse zone
(``ensure_reverse_zone_for_subnet``).

The zone that owns a reverse name is the most specific zone whose name is a
suffix of it, whatever its type, and IPAM writes there only when that zone is
a primary. When a forwarder, a secondary or a stub owns the names, IPAM writes
no PTR, queues no op, and the drift check expects none.
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

NOT_AUTHORED = [
    pytest.param("forward", {"forwarders": ["192.0.2.53"]}, id="forward"),
    pytest.param("secondary", {"masters": ["192.0.2.10"]}, id="secondary"),
    pytest.param("stub", {"masters": ["192.0.2.10"]}, id="stub"),
]


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u1419-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _setup(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone, IPSpace, IPBlock]:
    """A group served by one BIND9 primary, its primary forward zone, and a
    space with the 10.98.0.0/16 block the subnets are carved from."""
    grp = DNSServerGroup(name=f"g1419-{uuid.uuid4().hex[:6]}")
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
    fwd = DNSZone(
        group_id=grp.id,
        name=f"z1419-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    space = IPSpace(name=f"sp1419-{uuid.uuid4().hex[:8]}", description="")
    db.add_all([fwd, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.98.0.0/16", name="b")
    db.add(block)
    await db.flush()
    return grp, fwd, space, block


def _zone(grp: DNSServerGroup, name: str, zone_type: str, kind: str = "reverse") -> DNSZone:
    """A zone of ``zone_type`` stored with ``kind`` — ``reverse`` the way the
    importers store any zone named under in-addr.arpa."""
    if zone_type == "primary":
        extra: dict[str, object] = {"primary_ns": "ns1.example.", "admin_email": "admin.example."}
    elif zone_type == "forward":
        extra = {"forwarders": ["192.0.2.53"], "primary_ns": "", "admin_email": ""}
    else:
        extra = {"masters": ["192.0.2.10"], "primary_ns": "", "admin_email": ""}
    return DNSZone(group_id=grp.id, name=name, zone_type=zone_type, kind=kind, **extra)


async def _subnet(
    client: AsyncClient,
    headers: dict[str, str],
    space: IPSpace,
    block: IPBlock,
    grp: DNSServerGroup,
    fwd: DNSZone,
    network: str = "10.98.95.0/24",
) -> str:
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": network,
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(fwd.id),
        },
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _allocate(
    client: AsyncClient, headers: dict[str, str], sid: str, address: str, hostname: str
) -> str:
    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": address, "hostname": hostname},
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _ptrs(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str, str]]:
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


async def _zone_names(db: AsyncSession, grp: DNSServerGroup) -> list[str]:
    rows = (await db.execute(select(DNSZone.name).where(DNSZone.group_id == grp.id))).scalars()
    return sorted(str(n) for n in rows)


async def _preview(client: AsyncClient, headers: dict[str, str], sid: str) -> dict:
    resp = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/preview", headers=headers)
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


# ── The issue's contract ──────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(("zone_type", "extra"), NOT_AUTHORED)
async def test_ipam_writes_no_ptr_into_a_zone_it_does_not_author(
    client: AsyncClient, db_session: AsyncSession, zone_type: str, extra: dict
) -> None:
    """The issue's reproduction: a ``95.98.10.in-addr.arpa.`` of ``zone_type``
    stored ``kind: reverse``, a subnet bound to the group and its forward
    zone, one allocated host. On the broken build the gateway's and the host's
    PTRs were written into it and a create op queued for each."""
    headers = await _headers(db_session)
    grp, fwd, space, block = await _setup(db_session)
    other = DNSZone(
        group_id=grp.id,
        name="95.98.10.in-addr.arpa.",
        zone_type=zone_type,
        kind="reverse",
        primary_ns="",
        admin_email="",
        **extra,
    )
    db_session.add(other)
    await db_session.commit()

    sid = await _subnet(client, headers, space, block, grp, fwd)
    await _allocate(client, headers, sid, "10.98.95.10", "host")

    ptrs, ops = await _ptrs(db_session, other.id), await _ops(db_session, other.name)
    assert (ptrs, ops) == ([], []), (
        f"IPAM wrote into a {zone_type} zone it does not author: "
        f"PTR rows {ptrs}, record ops queued {ops}"
    )
    # Nothing was created beside it: (group, view, name) is unique, and
    # another server owns those names anyway.
    assert await _zone_names(db_session, grp) == sorted([fwd.name, other.name])
    # The drift check expects none either: no reverse zone, no missing PTR.
    report = await _preview(client, headers, sid)
    assert report["reverse_zone_id"] is None, report
    assert [m for m in report["missing"] if m["record_type"] == "PTR"] == [], report


# ── The most specific zone owns the names, whatever its type ──────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["reverse", "forward"])
async def test_a_forwarder_inside_a_primary_reverse_zone_owns_its_names(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    """A primary ``10.in-addr.arpa.`` with a conditional forwarder for
    ``95.98.10.in-addr.arpa.`` inside it. The hosts of 10.98.95.0/24 belong to
    the forwarder, so IPAM writes their PTRs into neither zone: not into the
    forwarder, which cannot take them, and not into the parent, whose names
    there the forwarder owns. ``kind`` is how the forwarder was stored:
    ``reverse`` by an importer, ``forward`` by Add Zone, which keeps the kind
    of a zone that is not primary (#1310). On the broken build the first took
    the PTRs, and with the second the parent did."""
    headers = await _headers(db_session)
    grp, fwd, space, block = await _setup(db_session)
    parent = _zone(grp, "10.in-addr.arpa.", "primary")
    forwarder = _zone(grp, "95.98.10.in-addr.arpa.", "forward", kind=kind)
    db_session.add_all([parent, forwarder])
    await db_session.commit()

    sid = await _subnet(client, headers, space, block, grp, fwd)
    await _allocate(client, headers, sid, "10.98.95.10", "host")

    written = {
        "parent PTRs": await _ptrs(db_session, parent.id),
        "parent ops": await _ops(db_session, parent.name),
        "forwarder PTRs": await _ptrs(db_session, forwarder.id),
        "forwarder ops": await _ops(db_session, forwarder.name),
    }
    assert written == {
        "parent PTRs": [],
        "parent ops": [],
        "forwarder PTRs": [],
        "forwarder ops": [],
    }
    assert (await _preview(client, headers, sid))["reverse_zone_id"] is None


@pytest.mark.asyncio
async def test_a_primary_reverse_zone_beneath_a_forwarder_still_takes_the_ptrs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The other way round: a forwarder for all of ``10.in-addr.arpa.``, and
    the subnet's own reverse zone, which IPAM auto-creates as a primary,
    beneath it. The primary is the most specific zone, so it owns the names
    and takes the gateway's and the host's PTRs, as before the fix."""
    headers = await _headers(db_session)
    grp, fwd, space, block = await _setup(db_session)
    forwarder = _zone(grp, "10.in-addr.arpa.", "forward")
    db_session.add(forwarder)
    await db_session.commit()

    sid = await _subnet(client, headers, space, block, grp, fwd)
    await _allocate(client, headers, sid, "10.98.95.10", "host")

    auto = (
        await db_session.execute(
            select(DNSZone).where(
                DNSZone.group_id == grp.id, DNSZone.name == "95.98.10.in-addr.arpa."
            )
        )
    ).scalar_one()
    assert (auto.zone_type, auto.kind) == ("primary", "reverse")
    assert await _ptrs(db_session, auto.id) == [
        ("1", "PTR", f"gateway.{fwd.name}"),
        ("10", "PTR", f"host.{fwd.name}"),
    ]
    assert await _ptrs(db_session, forwarder.id) == []
    assert await _ops(db_session, forwarder.name) == []
    report = await _preview(client, headers, sid)
    assert report["reverse_zone_id"] == str(auto.id)
    assert (report["missing"], report["mismatched"], report["stale"]) == ([], [], [])


# ── A zone that stops being SpatiumDDI's, and rows an earlier release wrote ───


@pytest.mark.asyncio
async def test_a_reverse_zone_made_secondary_takes_no_more_ptrs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An operator hands a subnet's reverse zone to another server (Edit Zone:
    secondary, a master set). Its names now come from that server: IPAM writes
    no PTR for the next host, and the PTR it wrote before is dropped from the
    zone's rows the next time it syncs that address, with no op, since a
    secondary refuses updates."""
    headers = await _headers(db_session)
    grp, fwd, space, block = await _setup(db_session)
    await db_session.commit()

    sid = await _subnet(client, headers, space, block, grp, fwd)
    first = await _allocate(client, headers, sid, "10.98.95.10", "host")
    rev = (
        await db_session.execute(
            select(DNSZone).where(
                DNSZone.group_id == grp.id, DNSZone.name == "95.98.10.in-addr.arpa."
            )
        )
    ).scalar_one()
    assert ("10", "PTR", f"host.{fwd.name}") in await _ptrs(db_session, rev.id)

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{rev.id}",
        headers=headers,
        json={"zone_type": "secondary", "masters": ["192.0.2.10"]},
    )
    assert resp.status_code == 200, resp.text
    ops_before = await _ops(db_session, rev.name)

    await _allocate(client, headers, sid, "10.98.95.11", "host2")
    resp = await client.put(
        f"/api/v1/ipam/addresses/{first}", headers=headers, json={"hostname": "host-renamed"}
    )
    assert resp.status_code == 200, resp.text

    ptr_names = [name for name, rtype, _ in await _ptrs(db_session, rev.id) if rtype == "PTR"]
    assert "11" not in ptr_names
    assert "10" not in ptr_names
    assert await _ops(db_session, rev.name) == ops_before


@pytest.mark.asyncio
async def test_ptrs_an_earlier_release_wrote_into_a_forwarder_leave_without_an_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Upgraded from a release with the bug: a forwarder holds IPAM's PTRs
    for two hosts. Renaming one drops its PTR row, and deleting the other
    drops its row; neither queues an op against the forwarder, which never
    took the records. On the broken build the rename queued an update and the
    delete a delete."""
    headers = await _headers(db_session)
    grp, fwd, space, block = await _setup(db_session)
    forwarder = _zone(grp, "95.98.10.in-addr.arpa.", "forward")
    db_session.add(forwarder)
    await db_session.commit()
    sid = await _subnet(client, headers, space, block, grp, fwd)
    subnet = await db_session.get(Subnet, uuid.UUID(sid))
    assert subnet is not None

    ips: dict[str, IPAddress] = {}
    for last, host in (("10", "alpha"), ("11", "beta")):
        ip = IPAddress(subnet_id=subnet.id, address=f"10.98.95.{last}", status="allocated")
        ip.hostname = host
        db_session.add(ip)
        await db_session.flush()
        db_session.add(
            DNSRecord(
                zone_id=forwarder.id,
                name=last,
                fqdn=f"{last}.95.98.10.in-addr.arpa.",
                record_type="PTR",
                value=f"{host}.{fwd.name}",
                auto_generated=True,
                ip_address_id=ip.id,
            )
        )
        ip.reverse_zone_id = forwarder.id
        ips[host] = ip
    await db_session.commit()
    ops_before = await _ops(db_session, forwarder.name)

    resp = await client.put(
        f"/api/v1/ipam/addresses/{ips['alpha'].id}",
        headers=headers,
        json={"hostname": "alpha-renamed"},
    )
    assert resp.status_code == 200, resp.text
    resp = await client.delete(f"/api/v1/ipam/addresses/{ips['beta'].id}", headers=headers)
    assert resp.status_code == 204, resp.text

    assert [r for r in await _ptrs(db_session, forwarder.id) if r[0] in ("10", "11")] == []
    assert await _ops(db_session, forwarder.name) == ops_before


# ── The reverse-zone auto-create ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_reverse_zone_auto_create_adopts_no_zone_it_does_not_author(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A forwarder of the subnet's reverse name, stored ``kind: forward`` the
    way Add Zone stores a zone that is not primary (#1310).
    ``ensure_reverse_zone_for_subnet`` found it by name and returned it as the
    subnet's reverse zone, so the backfill endpoint reported it created.
    Another server owns those names: there is no reverse zone to create or to
    adopt."""
    from app.services.dns.reverse_zone import ensure_reverse_zone_for_subnet

    headers = await _headers(db_session)
    grp, fwd, space, block = await _setup(db_session)
    forwarder = _zone(grp, "95.98.10.in-addr.arpa.", "forward", kind="forward")
    db_session.add(forwarder)
    await db_session.commit()
    sid = await _subnet(client, headers, space, block, grp, fwd)

    resp = await client.post(f"/api/v1/ipam/subnets/{sid}/reverse-zones/backfill", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["created"] == [], resp.text

    subnet = await db_session.get(Subnet, uuid.UUID(sid))
    assert subnet is not None
    assert await ensure_reverse_zone_for_subnet(db_session, subnet, None) is None
    assert await _zone_names(db_session, grp) == sorted([fwd.name, forwarder.name])
