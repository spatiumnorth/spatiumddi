"""IPAM never writes an A / AAAA beside a CNAME (#1441).

A name that holds a CNAME holds nothing else (RFC 1034 section 3.6.2). #1381
made the record API refuse such a pair, but IPAM's auto-generated forward
records (an address's hostname, and DHCP DDNS, which goes through the same
``_sync_dns_record``) did not ask. An address named like an operator's CNAME
wrote an A beside it; BIND then refuses the whole zone and the agent stops
applying every record change on that server (#1378).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _setup(db: AsyncSession) -> tuple[Subnet, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
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
    # The operator's CNAME at "www".
    db.add(
        DNSRecord(
            zone_id=zone.id,
            name="www",
            fqdn="www.corp.test",
            record_type="CNAME",
            value="web.corp.test.",
            auto_generated=False,
        )
    )
    await db.flush()
    return subnet, zone


async def _address_records(db: AsyncSession, zone: DNSZone, name: str) -> list[DNSRecord]:
    rows = await db.execute(
        select(DNSRecord).where(
            DNSRecord.zone_id == zone.id,
            DNSRecord.name == name,
            DNSRecord.record_type.in_(["A", "AAAA"]),
        )
    )
    return list(rows.scalars().all())


async def _ip(db: AsyncSession, subnet: Subnet, address: str, hostname: str) -> IPAddress:
    ip = IPAddress(subnet_id=subnet.id, address=address, status="allocated", hostname=hostname)
    db.add(ip)
    await db.flush()
    return ip


@pytest.mark.asyncio
async def test_an_address_named_like_a_cname_writes_no_a_record(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    ip = await _ip(db_session, subnet, "10.81.1.10", "www")

    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()

    assert await _address_records(db_session, zone, "www") == []
    assert ip.dns_record_id is None


@pytest.mark.asyncio
async def test_an_address_with_its_own_name_still_gets_its_a_record(
    db_session: AsyncSession,
) -> None:
    subnet, zone = await _setup(db_session)
    ip = await _ip(db_session, subnet, "10.81.1.11", "app")

    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()

    (rec,) = await _address_records(db_session, zone, "app")
    assert rec.value == "10.81.1.11"
    assert ip.dns_record_id == rec.id


@pytest.mark.asyncio
async def test_renaming_onto_a_cname_retracts_the_old_record_and_writes_none(
    db_session: AsyncSession,
) -> None:
    subnet, zone = await _setup(db_session)
    ip = await _ip(db_session, subnet, "10.81.1.12", "app")
    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()
    assert len(await _address_records(db_session, zone, "app")) == 1

    ip.hostname = "www"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()

    assert await _address_records(db_session, zone, "app") == []
    assert await _address_records(db_session, zone, "www") == []
    assert ip.dns_record_id is None


@pytest.mark.asyncio
async def test_a_family_swap_onto_a_cname_name_writes_none(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    ip = await _ip(db_session, subnet, "10.81.1.13", "app")
    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()
    (rec,) = await _address_records(db_session, zone, "app")

    # The A record is still named "app", but the hostname moved onto the
    # CNAME's name and the address family changed in one edit.
    rec.record_type = "AAAA"
    ip.hostname = "www"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()

    assert await _address_records(db_session, zone, "www") == []


# ── #1493: no PTR naming the alias, and the sync reports the skip ─────────────


async def _reverse_zone(db: AsyncSession, subnet: Subnet, zone: DNSZone) -> DNSZone:
    rev = DNSZone(
        group_id=zone.group_id,
        name="1.81.10.in-addr.arpa.",
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.corp.test.",
        admin_email="admin.corp.test.",
        linked_subnet_id=subnet.id,
    )
    db.add(rev)
    await db.flush()
    return rev


async def _ptrs(db: AsyncSession, ip: IPAddress) -> list[DNSRecord]:
    rows = await db.execute(
        select(DNSRecord).where(DNSRecord.ip_address_id == ip.id, DNSRecord.record_type == "PTR")
    )
    return list(rows.scalars().all())


@pytest.mark.asyncio
async def test_no_ptr_is_written_for_a_name_that_holds_a_cname(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    await _reverse_zone(db_session, subnet, zone)
    ip = await _ip(db_session, subnet, "10.81.1.20", "www")

    published = await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()

    assert await _ptrs(db_session, ip) == []
    # Nothing was published, so the DDNS path must not log ``ddns_applied``.
    assert published is False
    assert getattr(ip, "_dns_skipped_cname", False) is True


@pytest.mark.asyncio
async def test_renaming_onto_a_cname_retracts_the_ptr(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    await _reverse_zone(db_session, subnet, zone)
    ip = await _ip(db_session, subnet, "10.81.1.21", "app")
    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()
    assert len(await _ptrs(db_session, ip)) == 1

    ip.hostname = "www"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()

    assert await _ptrs(db_session, ip) == []
    assert ip.reverse_zone_id is None


@pytest.mark.asyncio
async def test_an_address_with_its_own_name_still_gets_its_ptr(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    await _reverse_zone(db_session, subnet, zone)
    ip = await _ip(db_session, subnet, "10.81.1.22", "host")

    assert await _sync_dns_record(db_session, ip, subnet) is True
    await db_session.flush()

    ptrs = await _ptrs(db_session, ip)
    assert [p.value for p in ptrs] == ["host.corp.test."]
