"""A subnet wider than a /24 gets a reverse zone for EVERY /24 it spans (#1840).

The old single-name ``compute_reverse_zone_name`` rounded a /17–/23 DOWN to the /24 of its network
address, so a /23 got one zone and every address in its second /24 had no PTR.
A subnet now gets one zone per /24 (IPv6: per nibble piece) — never one
enclosing /16, which would make us authoritative for space outside the subnet.
The address → zone mapping is per ADDRESS, shared by the IPAM write path and
the drift check; the subnet's zones are a SET that retire / resize handle whole.
"""

from __future__ import annotations

import ipaddress
import json
import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns.reverse_zone import (
    compute_reverse_zone_names,
    ensure_reverse_zones_for_subnet,
    retire_auto_reverse_zones,
    reverse_zone_network,
)
from app.services.dns.sync_check import compute_subnet_dns_drift

FWD = "z1840.example."


@pytest.mark.parametrize(
    ("network", "count", "first", "last"),
    [
        ("10.55.2.0/24", 1, "2.55.10.in-addr.arpa.", "2.55.10.in-addr.arpa."),
        ("10.55.2.128/25", 1, "2.55.10.in-addr.arpa.", "2.55.10.in-addr.arpa."),
        ("10.55.2.0/23", 2, "2.55.10.in-addr.arpa.", "3.55.10.in-addr.arpa."),
        ("10.55.16.0/20", 16, "16.55.10.in-addr.arpa.", "31.55.10.in-addr.arpa."),
        ("10.55.128.0/17", 128, "128.55.10.in-addr.arpa.", "255.55.10.in-addr.arpa."),
        ("10.55.0.0/16", 1, "55.10.in-addr.arpa.", "55.10.in-addr.arpa."),
        ("10.48.0.0/12", 16, "48.10.in-addr.arpa.", "63.10.in-addr.arpa."),
        ("10.0.0.0/8", 1, "10.in-addr.arpa.", "10.in-addr.arpa."),
        ("2001:db8:1::/64", 1, "0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", None),
        ("2001:db8:1::/56", 1, "0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", None),
        ("2001:db8::/48", 1, "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", None),
        ("2001:db8::/44", 1, "0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", None),
        # One bit past a nibble: the widest IPv6 set, eight zones.
        (
            "2001:db8::/45",
            8,
            "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            "7.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ),
        ("10.128.0.0/9", 128, "128.10.in-addr.arpa.", "255.10.in-addr.arpa."),
        # Not nibble-aligned: its two /56 pieces, never a /52 that is not ours.
        (
            "2001:db8:0:200::/55",
            2,
            "2.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            "3.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ),
    ],
)
def test_one_zone_per_piece_and_every_address_is_covered(network, count, first, last):
    got = compute_reverse_zone_names(network)
    assert len(got) == count and got[0] == first
    if last:
        assert got[-1] == last
    net = ipaddress.ip_network(network)
    for addr in (net.network_address, net[net.num_addresses // 2], net[-1]):
        ptr = addr.reverse_pointer + "."
        assert any(ptr.endswith("." + z) for z in got), (addr, got)


@pytest.mark.parametrize("prefix", range(1, 33))
def test_no_ipv4_zone_claims_space_outside_a_subnet_of_a_24_or_wider(prefix):
    """Zac's rule: a zone of the set never covers an address outside the
    subnet — except the /24 a narrower subnet shares with its neighbours.
    Checked at a non-zero base for every prefix length, with the count
    bounded."""
    net = ipaddress.ip_network(f"172.16.0.0/{prefix}", strict=False)
    zones = [reverse_zone_network(n) for n in compute_reverse_zone_names(str(net))]
    assert 1 <= len(zones) <= 256
    assert sum(z.num_addresses for z in zones) >= net.num_addresses
    for z in zones:
        assert z is not None
        if prefix <= 24:
            assert z.subnet_of(net), (net, z)
        else:
            assert z.prefixlen == 24 and net.subnet_of(z), (net, z)


@pytest.mark.parametrize("prefix", range(1, 129))
def test_no_ipv6_zone_claims_space_outside_the_subnet(prefix):
    net = ipaddress.ip_network(f"2001:db8:abcd:1234::/{prefix}", strict=False)
    zones = [reverse_zone_network(n) for n in compute_reverse_zone_names(str(net))]
    assert 1 <= len(zones) <= 8
    assert sum(z.num_addresses for z in zones) == net.num_addresses
    assert all(z is not None and z.subnet_of(net) for z in zones), (net, zones)


async def _setup(db: AsyncSession, network: str):
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="technitium",
            host="10.0.0.1",
            name="ns1",
            is_primary=True,
            is_enabled=True,
            agent_id=uuid.uuid4(),
        )
    )
    fwd = DNSZone(
        group_id=grp.id,
        name=FWD,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(fwd)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=network,
        name="s",
        dns_zone_id=str(fwd.id),
        dns_group_ids=[str(grp.id)],
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    return grp, fwd, subnet


async def _allocate(db: AsyncSession, subnet: Subnet, address: str, host: str) -> IPAddress:
    from app.api.v1.ipam.router import _sync_dns_record

    ip = IPAddress(subnet_id=subnet.id, address=address, status="allocated", hostname=host)
    db.add(ip)
    await db.flush()
    await _sync_dns_record(db, ip, subnet, action="create")
    await db.flush()
    return ip


async def _ptr(db: AsyncSession, ip: IPAddress) -> tuple[str, str] | None:
    row = (
        await db.execute(
            select(DNSZone.name, DNSRecord.name)
            .join(DNSRecord, DNSRecord.zone_id == DNSZone.id)
            .where(DNSRecord.ip_address_id == ip.id, DNSRecord.record_type == "PTR")
        )
    ).first()
    return (row[0], row[1]) if row else None


@pytest.mark.parametrize(
    ("network", "addresses"),
    [
        ("10.55.2.0/23", ["10.55.2.5", "10.55.3.5", "10.55.3.250"]),
        ("10.56.16.0/20", ["10.56.16.9", "10.56.23.9", "10.56.31.254"]),
    ],
)
async def test_every_part_of_a_wide_subnet_gets_a_ptr(db_session, network, addresses):
    _grp, _fwd, subnet = await _setup(db_session, network)
    zones = await ensure_reverse_zones_for_subnet(db_session, subnet, None)
    assert [z.name for z in zones] == compute_reverse_zone_names(network)
    for i, addr in enumerate(addresses):
        ip = await _allocate(db_session, subnet, addr, f"h{i}")
        octets = addr.split(".")
        assert await _ptr(db_session, ip) == (
            f"{octets[2]}.{octets[1]}.10.in-addr.arpa.",
            octets[3],
        ), addr


async def test_a_slash_17_creates_all_128_zones(db_session):
    _grp, _fwd, subnet = await _setup(db_session, "10.60.128.0/17")
    zones = await ensure_reverse_zones_for_subnet(db_session, subnet, None)
    assert len(zones) == 128 and len({z.name for z in zones}) == 128
    ip = await _allocate(db_session, subnet, "10.60.255.7", "far")
    assert await _ptr(db_session, ip) == ("255.60.10.in-addr.arpa.", "7")
    # Idempotent: a second pass creates nothing.
    again = await ensure_reverse_zones_for_subnet(db_session, subnet, None)
    assert {z.id for z in again} == {z.id for z in zones}


async def test_existing_first_24_zone_keeps_working_and_the_rest_is_covered(db_session):
    """An install from before #1840: the /23's only zone is its first /24's.
    It keeps serving its addresses; the next allocation backfills the second
    /24's zone. The drift check agrees on both."""
    grp, _fwd, subnet = await _setup(db_session, "10.57.2.0/23")
    legacy = DNSZone(
        group_id=grp.id,
        name="2.57.10.in-addr.arpa.",
        zone_type="primary",
        kind="reverse",
        is_auto_generated=True,
        linked_subnet_id=subnet.id,
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(legacy)
    await db_session.flush()

    first = await _allocate(db_session, subnet, "10.57.2.7", "low")
    second = await _allocate(db_session, subnet, "10.57.3.7", "high")
    assert await _ptr(db_session, first) == ("2.57.10.in-addr.arpa.", "7")
    assert await _ptr(db_session, second) == ("3.57.10.in-addr.arpa.", "7")

    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert report.missing == [] and report.mismatched == [], (report.missing, report.mismatched)


async def test_growing_a_subnet_adds_the_zones_for_the_new_range(db_session):
    _grp, _fwd, subnet = await _setup(db_session, "10.58.2.0/24")
    assert [z.name for z in await ensure_reverse_zones_for_subnet(db_session, subnet, None)] == [
        "2.58.10.in-addr.arpa."
    ]
    subnet.network = "10.58.0.0/22"
    grown = await ensure_reverse_zones_for_subnet(db_session, subnet, None)
    assert [z.name for z in grown] == [f"{i}.58.10.in-addr.arpa." for i in range(4)]
    ip = await _allocate(db_session, subnet, "10.58.3.9", "grown")
    assert await _ptr(db_session, ip) == ("3.58.10.in-addr.arpa.", "9")


async def test_deleting_the_subnet_retires_every_zone_of_its_set(db_session):
    _grp, _fwd, subnet = await _setup(db_session, "10.59.16.0/20")
    zones = await ensure_reverse_zones_for_subnet(db_session, subnet, None)
    assert len(zones) == 16
    retired, relinked, _wake = await retire_auto_reverse_zones(db_session, subnet)
    assert len(retired) == 16 and relinked == []
    await db_session.flush()
    left = await db_session.scalar(
        select(func.count()).select_from(DNSZone).where(DNSZone.linked_subnet_id == subnet.id)
    )
    assert left == 0


async def test_a_25_pair_keeps_its_shared_zone_when_one_half_is_deleted(db_session):
    """Two /25s share their /24's zone. Retiring one re-links the zone to the
    other instead of taking the survivor's PTRs with it."""
    grp, _fwd, low = await _setup(db_session, "10.61.3.0/25")
    high = Subnet(
        space_id=low.space_id,
        block_id=low.block_id,
        network="10.61.3.128/25",
        name="n",
        dns_group_ids=[str(grp.id)],
        dns_inherit_settings=False,
    )
    db_session.add(high)
    await db_session.flush()
    (zone,) = await ensure_reverse_zones_for_subnet(db_session, low, None)
    assert [z.id for z in await ensure_reverse_zones_for_subnet(db_session, high, None)] == [
        zone.id
    ]
    retired, relinked, _ = await retire_auto_reverse_zones(db_session, low)
    assert retired == [] and [z.id for z in relinked] == [zone.id]
    assert zone.linked_subnet_id == high.id


async def test_drift_header_lists_every_zone_and_orphans_stay_with_their_subnet(db_session):
    """The drift report names every zone of a /23 (the first one alone was all
    the header showed), and an orphan PTR in a zone two /25s share is reported
    for the half it belongs to, not for every subnet of the group."""
    grp, _fwd, wide = await _setup(db_session, "10.62.2.0/23")
    await ensure_reverse_zones_for_subnet(db_session, wide, None)
    report = await compute_subnet_dns_drift(db_session, wide.id)
    assert report.reverse_zone_names == ["2.62.10.in-addr.arpa.", "3.62.10.in-addr.arpa."]
    assert report.reverse_zone_name == "2.62.10.in-addr.arpa."

    low = Subnet(
        space_id=wide.space_id,
        block_id=wide.block_id,
        network="10.62.8.0/25",
        name="low",
        dns_group_ids=[str(grp.id)],
        dns_inherit_settings=False,
    )
    high = Subnet(
        space_id=wide.space_id,
        block_id=wide.block_id,
        network="10.62.8.128/25",
        name="high",
        dns_group_ids=[str(grp.id)],
        dns_inherit_settings=False,
    )
    db_session.add_all([low, high])
    await db_session.flush()
    (shared,) = await ensure_reverse_zones_for_subnet(db_session, low, None)
    db_session.add(
        DNSRecord(
            zone_id=shared.id,
            name="200",
            record_type="PTR",
            value="gone.z1840.example.",
            auto_generated=True,
        )
    )
    await db_session.flush()
    low_stale = (await compute_subnet_dns_drift(db_session, low.id)).stale
    high_stale = (await compute_subnet_dns_drift(db_session, high.id)).stale
    wide_stale = (await compute_subnet_dns_drift(db_session, wide.id)).stale
    assert low_stale == [] and wide_stale == []
    assert [(s.name, s.reason) for s in high_stale] == [("200", "ip-deleted")]


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    from app.core.security import create_access_token, hash_password
    from app.models.auth import User

    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _api_fixture(db: AsyncSession) -> tuple[str, str, str, str]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([block, grp])
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="192.0.2.53",
            name="ns1",
            is_primary=True,
            is_enabled=True,
            agent_id=uuid.uuid4(),
        )
    )
    fwd = DNSZone(
        group_id=grp.id,
        name=FWD,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(fwd)
    await db.commit()
    return str(space.id), str(block.id), str(grp.id), str(fwd.id)


async def _create_subnet(client, headers, ids, network: str) -> str:
    space_id, block_id, gid, zid = ids
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": network,
            "dns_group_id": gid,
            "dns_zone_id": zid,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _zones_of(db: AsyncSession, gid: str, names: list[str]) -> list[DNSZone]:
    return list(
        (
            await db.execute(
                select(DNSZone)
                .where(DNSZone.group_id == uuid.UUID(gid), DNSZone.name.in_(names))
                .execution_options(include_deleted=True, populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


async def test_creating_a_17_through_the_api_makes_128_zones_and_wakes_once(
    client, db_session, monkeypatch
):
    import time

    from app.core import agent_wake
    from app.services.dns.agent_config import render_bundle_body

    published: list[tuple[str, ...]] = []

    async def _record(*channels: str) -> None:
        published.append(channels)

    monkeypatch.setattr(agent_wake, "publish_wake", _record)
    headers = await _admin_headers(db_session)
    ids = await _api_fixture(db_session)
    gid = ids[2]
    server = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == uuid.UUID(gid)))
    ).scalar_one()
    before = len(json.dumps((await render_bundle_body(db_session, server)).body, default=str))

    started = time.perf_counter()
    sid = await _create_subnet(client, headers, ids, "10.63.128.0/17")
    elapsed = time.perf_counter() - started

    names = compute_reverse_zone_names("10.63.128.0/17")
    zones = await _zones_of(db_session, gid, names)
    assert len(zones) == 128 and {str(z.linked_subnet_id) for z in zones} == {sid}
    # One wake for the group, not one per zone.
    group_channel = agent_wake.dns_group_channel(gid)
    assert sum(chs.count(group_channel) for chs in published) == 1, published
    # One audit row per zone created.
    audits = await db_session.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.resource_type == "dns_zone", AuditLog.action == "create")
        .where(AuditLog.resource_id.in_([str(z.id) for z in zones]))
    )
    assert audits == 128

    after = len(json.dumps((await render_bundle_body(db_session, server)).body, default=str))
    print(
        f"\n#1840 /17 create: {elapsed:.2f}s; bundle {before} -> {after} bytes "
        f"(+{(after - before) / 128:.0f} B/zone)"
    )
    assert elapsed < 30


async def test_deleting_a_20_trashes_all_16_zones_and_restore_brings_them_back(client, db_session):
    headers = await _admin_headers(db_session)
    ids = await _api_fixture(db_session)
    gid = ids[2]
    sid = await _create_subnet(client, headers, ids, "10.64.16.0/20")
    names = compute_reverse_zone_names("10.64.16.0/20")
    assert len(await _zones_of(db_session, gid, names)) == 16

    resp = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert resp.status_code == 204, resp.text
    subnet = (
        await db_session.execute(
            select(Subnet)
            .where(Subnet.id == uuid.UUID(sid))
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).scalar_one()
    zones = await _zones_of(db_session, gid, names)
    assert len(zones) == 16
    assert all(z.deleted_at is not None for z in zones)
    assert {z.deletion_batch_id for z in zones} == {subnet.deletion_batch_id}

    restored = await client.post(f"/api/v1/admin/trash/subnet/{sid}/restore", headers=headers)
    assert restored.status_code == 200, restored.text
    zones = await _zones_of(db_session, gid, names)
    assert len(zones) == 16
    assert all(z.deleted_at is None and str(z.linked_subnet_id) == sid for z in zones)


async def test_permanently_deleting_a_20_removes_all_16_zones(client, db_session):
    headers = await _admin_headers(db_session)
    ids = await _api_fixture(db_session)
    gid = ids[2]
    sid = await _create_subnet(client, headers, ids, "10.65.16.0/20")
    names = compute_reverse_zone_names("10.65.16.0/20")
    assert len(await _zones_of(db_session, gid, names)) == 16
    resp = await client.delete(
        f"/api/v1/ipam/subnets/{sid}?permanent=true&force=true", headers=headers
    )
    assert resp.status_code == 204, resp.text
    assert await _zones_of(db_session, gid, names) == []


async def test_the_cutover_check_counts_a_16_zone_as_covering_its_24s(db_session):
    """A /16 subnet's one /16 zone covers every /24 its A records imply; the
    check used to compare names and call each /24 missing."""
    from app.services.cutover.checklist import STATE_OK, _check_reverse_zones

    grp, fwd, _subnet = await _setup(db_session, "10.66.0.0/16")
    rev = DNSZone(
        group_id=grp.id,
        name="66.10.in-addr.arpa.",
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(rev)
    await db_session.flush()
    for i, addr in enumerate(("10.66.1.5", "10.66.200.9")):
        db_session.add(DNSRecord(zone_id=fwd.id, name=f"h{i}", record_type="A", value=addr))
    await db_session.flush()

    assert (await _check_reverse_zones(db_session, [fwd, rev]))["state"] == STATE_OK
    out = await _check_reverse_zones(db_session, [fwd])
    assert "66.10.in-addr.arpa." in out["detail"]
    assert "1.66.10.in-addr.arpa." not in out["detail"]
