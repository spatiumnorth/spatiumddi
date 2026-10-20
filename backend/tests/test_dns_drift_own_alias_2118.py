"""Sync DNS drift treats a name the address's own alias serves as satisfied (#2118).

#2117 skips the host A when the address's own A alias already answers for the
name. Drift ignores alias rows, so it listed that host A as missing and the
apply reported #2117's 409 in ``errors`` — on every auto-sync interval.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import DnsSyncCommitRequest, _apply_dns_sync, _sync_dns_record
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns.sync_check import compute_subnet_dns_drift
from tests.test_ipam_own_alias_host_2106 import _own_alias_setup


def _fwd_missing(report) -> list[tuple[str, str]]:
    return sorted(
        (m.expected_name, m.record_type) for m in report.missing if m.record_type != "PTR"
    )


async def _ops(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count()).select_from(DNSRecordOp))).scalar_one())


async def _drop_host_rows(db: AsyncSession, ip: IPAddress) -> None:
    """Forget the host rows the setup's first sync wrote, so none stands in for a missing one."""
    await db.execute(
        DNSRecord.__table__.delete().where(
            DNSRecord.ip_address_id == ip.id, DNSRecord.ip_alias.is_(False)
        )
    )
    await db.flush()


async def _renamed_onto_alias(db: AsyncSession, alias_type: str = "A"):
    subnet, zone, ip, alias = await _own_alias_setup(db, alias_type)
    ip.hostname = "www"  # what a lease / integration rename does
    await _sync_dns_record(db, ip, subnet, action="update")
    await db.flush()
    return subnet, zone, ip, alias


@pytest.mark.asyncio
async def test_own_a_alias_at_the_name_is_not_missing_and_apply_is_clean(
    db_session: AsyncSession,
) -> None:
    subnet, _zone, _ip, _alias = await _renamed_onto_alias(db_session)
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert _fwd_missing(report) == []

    ops_before = await _ops(db_session)
    body = DnsSyncCommitRequest(
        create_for_ip_ids=[m.ip_id for m in report.missing],
        update_record_ids=[m.record_id for m in report.mismatched],
    )
    _c, _u, _d, errors = await _apply_dns_sync(db_session, body, restrict_subnet_id=subnet.id)
    assert errors == []
    assert await _ops(db_session) == ops_before  # the auto-sync body: nothing to write


@pytest.mark.asyncio
async def test_alias_match_is_case_insensitive(db_session: AsyncSession) -> None:
    subnet, _zone, ip, alias = await _renamed_onto_alias(db_session)
    alias.name = "WWW"
    await db_session.flush()
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert _fwd_missing(report) == []
    assert ip.hostname == "www"


@pytest.mark.asyncio
async def test_a_genuinely_missing_a_is_still_listed(db_session: AsyncSession) -> None:
    subnet, _zone, ip, _alias = await _own_alias_setup(db_session, "A")
    # Positive control: a host with no record and no alias at its name.
    ip.hostname = "fresh"
    await _drop_host_rows(db_session, ip)
    await db_session.flush()
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert _fwd_missing(report) == [("fresh", "A")]


@pytest.mark.asyncio
async def test_another_addresses_alias_does_not_satisfy_it(db_session: AsyncSession) -> None:
    subnet, _zone, _ip, _alias = await _own_alias_setup(db_session, "A")
    # ip1 owns the "www" alias; ip2 is named "www" with no record of its own.
    other = IPAddress(subnet_id=subnet.id, address="10.81.1.31", status="allocated", hostname="www")
    db_session.add(other)
    await db_session.flush()
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert [m for m in report.missing if m.ip_id == other.id and m.record_type == "A"]


@pytest.mark.asyncio
async def test_an_alias_of_another_type_does_not_satisfy_it(db_session: AsyncSession) -> None:
    subnet, _zone, ip, alias = await _own_alias_setup(db_session, "A")
    alias.record_type = "AAAA"
    alias.value = "2001:db8::1"
    ip.hostname = "www"
    await _drop_host_rows(db_session, ip)
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert ("www", "A") in _fwd_missing(report)


@pytest.mark.asyncio
async def test_the_ptr_is_still_expected(db_session: AsyncSession) -> None:
    subnet, _zone, ip, _alias = await _own_alias_setup(db_session, "A")
    ip.hostname = "www"
    # No sync after the rename: neither host A nor PTR was written for "www".
    await _drop_host_rows(db_session, ip)
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert _fwd_missing(report) == []
    assert [m for m in report.missing if m.record_type == "PTR" and m.ip_id == ip.id]


async def _ptr_rows(db: AsyncSession, ip: IPAddress) -> list[DNSRecord]:
    rows = await db.execute(
        select(DNSRecord).where(DNSRecord.ip_address_id == ip.id, DNSRecord.record_type == "PTR")
    )
    return list(rows.scalars().all())


async def _apply_report(db: AsyncSession, subnet, report) -> list[str]:
    body = DnsSyncCommitRequest(
        create_for_ip_ids=[m.ip_id for m in report.missing],
        update_record_ids=[m.record_id for m in report.mismatched],
    )
    _c, _u, _d, errors = await _apply_dns_sync(db, body, restrict_subnet_id=subnet.id)
    return errors


@pytest.mark.asyncio
async def test_apply_writes_the_missing_ptr_and_skips_the_alias_zone(
    db_session: AsyncSession,
) -> None:
    # The stated limit of the drift-only fix: with the PTR missing too, the
    # apply ran a strict sync for the address and hit #2117's 409, so the PTR
    # was never written and the error came back every interval.
    subnet, zone, ip, _alias = await _renamed_onto_alias(db_session)
    for r in await _ptr_rows(db_session, ip):
        await db_session.delete(r)
    await db_session.flush()

    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert _fwd_missing(report) == []
    assert [m for m in report.missing if m.record_type == "PTR" and m.ip_id == ip.id]

    assert await _apply_report(db_session, subnet, report) == []
    ptrs = await _ptr_rows(db_session, ip)
    assert [p.value for p in ptrs] == ["www.corp.test."]
    host = await db_session.execute(
        select(DNSRecord).where(
            DNSRecord.ip_address_id == ip.id,
            DNSRecord.ip_alias.is_(False),
            DNSRecord.zone_id == zone.id,
            DNSRecord.record_type == "A",
        )
    )
    assert host.scalars().all() == []  # the alias serves the name; no twin
    again = await compute_subnet_dns_drift(db_session, subnet.id)
    assert [m for m in again.missing if m.ip_id == ip.id] == []


@pytest.mark.asyncio
async def test_apply_still_refuses_a_cname_alias_at_the_name(db_session: AsyncSession) -> None:
    subnet, _zone, ip, _alias = await _own_alias_setup(db_session, "CNAME")
    ip.hostname = "www"
    await _drop_host_rows(db_session, ip)
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    errors = await _apply_report(db_session, subnet, report)
    assert len(errors) == 1 and "CNAME alias" in errors[0]


@pytest.mark.asyncio
async def test_own_alias_in_an_extra_zone_is_not_missing(db_session: AsyncSession) -> None:
    subnet, zone, ip, _alias = await _own_alias_setup(db_session, "A")
    extra = DNSZone(
        group_id=zone.group_id,
        name="extra.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.extra.test.",
        admin_email="admin.extra.test.",
    )
    db_session.add(extra)
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=extra.id,
            name="www",
            fqdn="www.extra.test",
            record_type="A",
            value="10.81.1.30",
            auto_generated=True,
            ip_alias=True,
            ip_address_id=ip.id,
        )
    )
    ip.extra_zone_ids = [str(extra.id)]
    ip.hostname = "www"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert [(m.zone_id, m.record_type) for m in report.missing if m.record_type != "PTR"] == []


@pytest.mark.asyncio
async def test_own_aaaa_alias_at_the_name_is_not_missing(db_session: AsyncSession) -> None:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    db_session.add(
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
        name="v6.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.v6.test.",
        admin_email="admin.v6.test.",
    )
    db_session.add(zone)
    await db_session.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="2001:db8:81::/48", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="2001:db8:81:1::/64",
        name="s6",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db_session.add(subnet)
    await db_session.flush()
    ip = IPAddress(
        subnet_id=subnet.id, address="2001:db8:81:1::30", status="allocated", hostname="h1"
    )
    db_session.add(ip)
    await db_session.flush()
    await _sync_dns_record(db_session, ip, subnet)
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="www",
            fqdn="www.v6.test",
            record_type="AAAA",
            value="2001:db8:81:1::30",
            auto_generated=True,
            ip_alias=True,
            ip_address_id=ip.id,
        )
    )
    await db_session.flush()
    ip.hostname = "www"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert _fwd_missing(report) == []
    assert await _apply_report(db_session, subnet, report) == []


@pytest.mark.asyncio
async def test_own_alias_in_the_addresses_own_zone_is_not_missing(
    db_session: AsyncSession,
) -> None:
    # #2104 + #2118 together: the address is published in its own zone T, not
    # the subnet's, and renamed onto its own A alias in T. Drift reads T (the
    # address's zone) and finds the name served there; the apply writes the
    # missing PTR with no 409 and leaves the host in T.
    subnet, zone, ip, alias = await _own_alias_setup(db_session, "A")
    # The setup's alias sits in the subnet's zone. Drop it, or a check against
    # the subnet's zone would pass by accident.
    await db_session.delete(alias)
    other = DNSZone(
        group_id=zone.group_id,
        name="other.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.other.test.",
        admin_email="admin.other.test.",
    )
    db_session.add(other)
    await db_session.flush()
    await _sync_dns_record(db_session, ip, subnet, zone_id=other.id, action="update")
    await db_session.flush()
    assert ip.forward_zone_id == other.id

    db_session.add(
        DNSRecord(
            zone_id=other.id,
            name="www",
            fqdn="www.other.test",
            record_type="A",
            value="10.81.1.30",
            auto_generated=True,
            ip_alias=True,
            ip_address_id=ip.id,
        )
    )
    ip.hostname = "www"
    await _sync_dns_record(db_session, ip, subnet, zone_id=other.id, action="update")
    for r in await _ptr_rows(db_session, ip):
        await db_session.delete(r)
    await db_session.flush()

    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert _fwd_missing(report) == []
    assert [m for m in report.mismatched if m.ip_id == ip.id] == []
    assert [s for s in report.stale if s.ip_id == ip.id] == []
    assert [m for m in report.missing if m.record_type == "PTR" and m.ip_id == ip.id]

    assert await _apply_report(db_session, subnet, report) == []
    assert ip.forward_zone_id == other.id
    assert [p.value for p in await _ptr_rows(db_session, ip)] == ["www.other.test."]
    hosts = await db_session.execute(
        select(DNSRecord.zone_id).where(
            DNSRecord.ip_address_id == ip.id,
            DNSRecord.ip_alias.is_(False),
            DNSRecord.record_type == "A",
        )
    )
    assert hosts.scalars().all() == []  # no twin in T, nothing moved to the subnet's zone
    again = await compute_subnet_dns_drift(db_session, subnet.id)
    assert [m for m in again.missing if m.ip_id == ip.id] == []
