"""A renewal with an unchanged name repairs what DDNS published (#3776).

DDNS treated a renewal whose name was already published as done, judging
only the forward record's name. A deleted PTR therefore stayed missing until
the client renamed or the lease ended, and a changed ``ddns_ttl`` never
reached the existing records (a rename kept the old TTL too, because the
record sync stamped the TTL only on records it created). Now the no-write
decision, shared by the DDNS step and the read-only check a lease-events
batch skips its zone locks on (#3773), also requires the PTR and the
effective TTL; and the DDNS path writes the TTL on an update of its own
records, never on an operator's.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import event, select
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp, DNSZone
from app.models.ipam import Subnet
from tests.test_lease_events_ha_renewal_3773 import _IPS, _ev, _pair, _post, _zone_locks
from tests.test_lease_events_trashed_scope_3733 import (
    concurrent_client,  # noqa: F401 — the fixture, shared
)


async def _records(db: AsyncSession, ip: str) -> dict[str, DNSRecord]:
    """The A and PTR records naming ``ip``'s lease, by type."""
    rows = (
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.record_type.in_(["A", "PTR"]))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    last = ip.rsplit(".", 1)[1]
    out: dict[str, DNSRecord] = {}
    for rec in rows:
        if rec.record_type == "A" and rec.value == ip:
            out["A"] = rec
        elif rec.record_type == "PTR" and rec.name == last:
            out["PTR"] = rec
    return out


async def _serial(db: AsyncSession, zone_id: Any) -> int | None:
    return (
        await db.execute(
            select(DNSZone.last_serial)
            .where(DNSZone.id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _set_ttl(db: AsyncSession, subnet: Subnet, ttl: int) -> None:
    row = await db.get(Subnet, subnet.id, populate_existing=True)
    assert row is not None
    row.ddns_ttl = ttl
    await db.commit()


@pytest.mark.asyncio
async def test_a_deleted_ptr_is_republished_at_the_next_renewal(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    _peer_a, peer_b, _subnet, _zone_id = await _pair(concurrent_client, db_session)
    ptr = (await _records(db_session, _IPS[0]))["PTR"]
    rev_zone_id = ptr.zone_id
    await db_session.delete(ptr)
    await db_session.commit()
    serial = await _serial(db_session, rev_zone_id)

    r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS])
    assert r.status_code == 200, r.text
    recs = await _records(db_session, _IPS[0])
    assert "PTR" in recs, recs
    assert recs["PTR"].value.startswith("renew-20."), recs["PTR"].value
    assert await _serial(db_session, rev_zone_id) != serial

    # Repaired, the next renewal writes nothing again and locks no zone.
    with _zone_locks() as seen:
        r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS])
        assert r.status_code == 200, r.text
    assert seen == [], seen


@pytest.mark.asyncio
async def test_a_changed_ttl_reaches_the_a_and_ptr_at_the_next_renewal(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    _peer_a, peer_b, subnet, zone_id = await _pair(concurrent_client, db_session)
    before = await _records(db_session, _IPS[0])
    assert before["A"].ttl is None and before["PTR"].ttl is None
    rev_zone_id = before["PTR"].zone_id
    fwd_serial = await _serial(db_session, zone_id)
    rev_serial = await _serial(db_session, rev_zone_id)
    await _set_ttl(db_session, subnet, 600)

    r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS])
    assert r.status_code == 200, r.text
    after = await _records(db_session, _IPS[0])
    assert after["A"].ttl == 600 and after["PTR"].ttl == 600, after
    assert after["A"].name == "renew-20"

    # The new TTL goes to the agents as an RFC 2136 update, and the zones'
    # serials move.
    ops = (
        (
            await db_session.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.op == "update", DNSRecordOp.zone_id.in_([zone_id, rev_zone_id])
                )
            )
        )
        .scalars()
        .all()
    )
    sent = {(op.record.get("type"), op.record.get("ttl")) for op in ops}
    assert ("A", 600) in sent and ("PTR", 600) in sent, sent
    assert await _serial(db_session, zone_id) != fwd_serial
    assert await _serial(db_session, rev_zone_id) != rev_serial

    # Applied, the next renewal writes nothing and locks no zone (#3773).
    with _zone_locks() as seen:
        r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS])
        assert r.status_code == 200, r.text
    assert seen == [], seen


@pytest.mark.asyncio
async def test_a_rename_publishes_with_the_current_ttl(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    _peer_a, peer_b, subnet, _zone_id = await _pair(concurrent_client, db_session)
    await _set_ttl(db_session, subnet, 900)

    r = await _post(
        concurrent_client, peer_b, [_ev(_IPS[0], "moved"), *(_ev(ip) for ip in _IPS[1:])]
    )
    assert r.status_code == 200, r.text
    recs = await _records(db_session, _IPS[0])
    assert recs["A"].name == "moved", recs
    assert recs["PTR"].value.startswith("moved."), recs["PTR"].value
    assert recs["A"].ttl == 900 and recs["PTR"].ttl == 900, recs


@pytest.mark.asyncio
async def test_an_operator_records_ttl_is_left_alone(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """An operator wrote the A the lease would publish: DDNS adopts it
    (#1867) and must not rewrite its TTL. The PTR DDNS generated beside it
    does follow the setting."""
    _peer_a, peer_b, subnet, zone_id = await _pair(concurrent_client, db_session)
    generated = (await _records(db_session, _IPS[0]))["A"]
    await db_session.delete(generated)
    zone = await db_session.get(DNSZone, zone_id)
    assert zone is not None
    operator = DNSRecord(
        zone_id=zone_id,
        name="renew-20",
        fqdn=f"renew-20.{zone.name.rstrip('.')}",
        record_type="A",
        value=_IPS[0],
        ttl=3600,
        auto_generated=False,
    )
    db_session.add(operator)
    await db_session.commit()
    operator_id = operator.id
    await _set_ttl(db_session, subnet, 600)

    r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS])
    assert r.status_code == 200, r.text
    recs = await _records(db_session, _IPS[0])
    assert recs["A"].id == operator_id, recs
    assert recs["A"].ttl == 3600 and not recs["A"].auto_generated
    assert recs["PTR"].ttl == 600

    with _zone_locks() as seen:
        r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS])
        assert r.status_code == 200, r.text
    assert seen == [], seen
    kept = await db_session.get(DNSRecord, operator_id, populate_existing=True)
    assert kept is not None and kept.ttl == 3600


@pytest.mark.asyncio
async def test_an_unchanged_renewal_with_a_ttl_set_locks_no_zone(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """With a ddns_ttl in force from the start, an unchanged renewal is still
    the quiet path: PTR present, TTL current, no zone lock (#3773)."""
    _peer_a, peer_b, subnet, _zone_id = await _pair(concurrent_client, db_session)
    await _set_ttl(db_session, subnet, 300)
    r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS])
    assert r.status_code == 200, r.text
    assert (await _records(db_session, _IPS[0]))["A"].ttl == 300

    with _zone_locks() as seen:
        for _ in range(2):
            r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS])
            assert r.status_code == 200, r.text
    assert seen == [], seen


@pytest.mark.asyncio
async def test_the_renewal_check_reads_per_batch_not_per_lease(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """The PTR and TTL reads the check gained are made once per batch (each
    address's generated records) or once per subnet (its reverse zones), so
    an unchanged renewal of three leases reads them as often as one does."""
    _peer_a, peer_b, _subnet, _zone_id = await _pair(concurrent_client, db_session)

    async def _reads(ips: list[str]) -> tuple[int, int]:
        seen: list[str] = []

        def _record(conn: Any, cursor: Any, statement: str, *a: Any) -> None:
            seen.append(statement)

        event.listen(Engine, "before_cursor_execute", _record)
        try:
            r = await _post(concurrent_client, peer_b, [_ev(ip) for ip in ips])
            assert r.status_code == 200, r.text
        finally:
            event.remove(Engine, "before_cursor_execute", _record)
        generated = sum(
            1 for s in seen if "FROM dns_record" in s and "dns_record.ip_alias IS false" in s
        )
        reverse = sum(1 for s in seen if "dns_zone.linked_subnet_id =" in s)
        return generated, reverse

    one = await _reads(_IPS[:1])
    three = await _reads(_IPS)
    assert one == three, (one, three)
    assert three[0] >= 1 and three[1] >= 1, three
