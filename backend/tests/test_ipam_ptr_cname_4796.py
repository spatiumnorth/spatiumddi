"""IPAM never writes a PTR beside a CNAME in the reverse zone (#4796).

RFC 2317's classless delegation puts a CNAME at an address's label in a /24's
reverse zone. The record API refuses a PTR there (409), but IPAM's
``_sync_dns_record`` did not ask, and BIND then refused the whole reverse zone
("CNAME and other data"). The PTR is now held to the same rule, through the
same helper, as the forward record (#1441).
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, Subnet
from tests.test_ipam_dns_cname_1441 import _ip, _ptrs, _reverse_zone, _setup


async def _cname_at_label(db: AsyncSession, rev: DNSZone, label: str) -> DNSRecord:
    rec = DNSRecord(
        zone_id=rev.id,
        name=label,
        fqdn=f"{label}.1.81.10.in-addr.arpa",
        record_type="CNAME",
        value=f"{label}.64-127.1.81.10.in-addr.arpa.",
        auto_generated=False,
    )
    db.add(rec)
    await db.flush()
    return rec


async def _rows_at(db: AsyncSession, rev: DNSZone, label: str) -> list[DNSRecord]:
    rows = await db.execute(
        select(DNSRecord).where(DNSRecord.zone_id == rev.id, DNSRecord.name == label)
    )
    return list(rows.scalars().all())


async def _fixture(db: AsyncSession) -> tuple[Subnet, DNSZone]:
    subnet, zone = await _setup(db)
    rev = await _reverse_zone(db, subnet, zone)
    return subnet, rev


@pytest.mark.asyncio
async def test_no_ptr_beside_an_rfc2317_cname_and_the_skip_is_said(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.v1.ipam import router

    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        router.logger, "warning", lambda ev, **kw: events.append((ev, kw)), raising=False
    )
    subnet, rev = await _fixture(db_session)
    await _cname_at_label(db_session, rev, "65")
    ip = await _ip(db_session, subnet, "10.81.1.65", "s65")

    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()

    assert await _ptrs(db_session, ip) == []
    assert [r.record_type for r in await _rows_at(db_session, rev, "65")] == ["CNAME"]
    assert ip.reverse_zone_id is None
    skips = [kw for ev, kw in events if ev == "ipam_dns_record_skipped_cname"]
    assert skips and "no PTR written" in skips[0]["detail"]


@pytest.mark.asyncio
async def test_ptr_is_written_without_the_cname(db_session: AsyncSession) -> None:
    subnet, rev = await _fixture(db_session)
    await _cname_at_label(db_session, rev, "65")
    ip = await _ip(db_session, subnet, "10.81.1.66", "s66")

    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()

    (ptr,) = await _ptrs(db_session, ip)
    assert ptr.name == "66" and ptr.zone_id == rev.id


@pytest.mark.asyncio
async def test_address_edit_onto_a_cname_label_retracts_the_ptr(
    db_session: AsyncSession,
) -> None:
    """The edit path moves the PTR to a new label: no PTR beside the CNAME."""
    subnet, rev = await _fixture(db_session)
    await _cname_at_label(db_session, rev, "65")
    ip = await _ip(db_session, subnet, "10.81.1.70", "s70")
    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()
    assert len(await _ptrs(db_session, ip)) == 1

    ip.address = "10.81.1.65"
    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()

    assert await _ptrs(db_session, ip) == []
    assert [r.record_type for r in await _rows_at(db_session, rev, "65")] == ["CNAME"]


@pytest.mark.asyncio
async def test_resync_retracts_a_ptr_an_earlier_release_wrote_beside_a_cname(
    db_session: AsyncSession,
) -> None:
    """Recovery: a PTR already beside a CNAME goes on the next sync."""
    subnet, rev = await _fixture(db_session)
    ip: IPAddress = await _ip(db_session, subnet, "10.81.1.80", "s80")
    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()
    (ptr,) = await _ptrs(db_session, ip)
    await _cname_at_label(db_session, rev, ptr.name)  # the CNAME lands after

    await _sync_dns_record(db_session, ip, subnet, action="update")
    await db_session.flush()

    assert await _ptrs(db_session, ip) == []
    assert [r.record_type for r in await _rows_at(db_session, rev, "80")] == ["CNAME"]


async def _drift(db: AsyncSession, subnet: Subnet):  # type: ignore[no-untyped-def]
    from app.services.dns.sync_check import compute_subnet_dns_drift

    return await compute_subnet_dns_drift(db, subnet.id)


@pytest.mark.asyncio
async def test_drift_lists_a_ptr_beside_a_cname_as_stale_and_commit_removes_it(
    db_session: AsyncSession,
) -> None:
    """A PTR an earlier release wrote beside a CNAME is offered for deletion,
    and committing that preview (as the console does) removes it."""
    from app.api.v1.ipam.router import DnsSyncCommitRequest, _apply_dns_sync

    subnet, rev = await _fixture(db_session)
    ip = await _ip(db_session, subnet, "10.81.1.90", "s90")
    await _sync_dns_record(db_session, ip, subnet)
    await db_session.flush()
    (ptr,) = await _ptrs(db_session, ip)
    await _cname_at_label(db_session, rev, ptr.name)

    report = await _drift(db_session, subnet)
    assert [(s.record_id, s.reason) for s in report.stale] == [(ptr.id, "cname-at-label")]
    assert report.missing == [] and report.mismatched == []

    _c, _u, deleted, errors = await _apply_dns_sync(
        db_session,
        DnsSyncCommitRequest(delete_stale_record_ids=[ptr.id]),
        allowed_stale_ids=[s.record_id for s in report.stale],
        restrict_subnet_id=subnet.id,
    )
    await db_session.flush()
    assert errors == [] and deleted == 1
    assert await _ptrs(db_session, ip) == []
    assert [r.record_type for r in await _rows_at(db_session, rev, "90")] == ["CNAME"]
    after = await _drift(db_session, subnet)
    assert after.stale == [] and not [m for m in after.missing if m.record_type == "PTR"]


@pytest.mark.asyncio
async def test_drift_does_not_expect_a_ptr_at_a_cname_label(db_session: AsyncSession) -> None:
    subnet, rev = await _fixture(db_session)
    await _cname_at_label(db_session, rev, "65")
    skipped = await _ip(db_session, subnet, "10.81.1.65", "s65")
    plain = await _ip(db_session, subnet, "10.81.1.66", "s66")

    report = await _drift(db_session, subnet)

    ptr_missing = {m.ip_id for m in report.missing if m.record_type == "PTR"}
    assert skipped.id not in ptr_missing
    assert plain.id in ptr_missing  # no regression: a normal missing PTR is listed
