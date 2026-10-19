"""Sync DNS drift treats a name the address's own alias serves as satisfied (#2118).

#2117 skips the host A when the address's own A alias already answers for the
name. Drift ignores alias rows, so it listed that host A as missing and the
apply reported #2117's 409 in ``errors`` — on every auto-sync interval.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import DnsSyncCommitRequest, _apply_dns_sync, _sync_dns_record
from app.models.dns import DNSRecord, DNSRecordOp
from app.models.ipam import IPAddress
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
