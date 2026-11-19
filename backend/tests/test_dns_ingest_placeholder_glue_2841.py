"""The control plane does not mirror the BIND9 placeholder glue (#2841)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.services.dns.ingest import (
    EXTERNAL_IMPORT_SOURCE,
    IncomingRecord,
    reconcile_external_records,
)

GLUE = IncomingRecord(name="ns1", record_type="A", value="127.0.0.1", ttl=600)


async def _zone(db: AsyncSession, primary_ns: str = "") -> DNSZone:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    zone = DNSZone(
        group_id=group.id,
        name="glue.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
        primary_ns=primary_ns,
    )
    db.add(zone)
    await db.flush()
    return zone


def _rec(zone: DNSZone, name: str, rtype: str, value: str, source: str | None) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=zone.name.rstrip(".") if name == "@" else f"{name}.{zone.name.rstrip('.')}",
        record_type=rtype,
        value=value,
        import_source=source,
    )


async def _external(db: AsyncSession, zone: DNSZone) -> list[tuple[str, str]]:
    rows = (
        (
            await db.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id == zone.id,
                    DNSRecord.import_source == EXTERNAL_IMPORT_SOURCE,
                    DNSRecord.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return sorted((r.name, r.value) for r in rows)


async def test_placeholder_glue_is_not_mirrored(db_session: AsyncSession) -> None:
    zone = await _zone(db_session)
    res = await reconcile_external_records(
        db_session, zone, [GLUE, IncomingRecord("ws1", "A", "192.0.2.5")]
    )
    assert res.added == 1
    assert await _external(db_session, zone) == [("ws1", "192.0.2.5")]


async def test_an_already_mirrored_placeholder_row_is_removed(
    db_session: AsyncSession,
) -> None:
    zone = await _zone(db_session, primary_ns="ns1.glue.example.com.")
    db_session.add(_rec(zone, "ns1", "A", "127.0.0.1", EXTERNAL_IMPORT_SOURCE))
    await db_session.flush()
    res = await reconcile_external_records(db_session, zone, [GLUE])
    assert res.removed == 1 and res.added == 0
    assert await _external(db_session, zone) == []


async def test_real_ns_naming_ns1_keeps_its_loopback_a(db_session: AsyncSession) -> None:
    zone = await _zone(db_session)
    db_session.add(_rec(zone, "@", "NS", "ns1.glue.example.com.", None))
    await db_session.flush()
    res = await reconcile_external_records(db_session, zone, [GLUE])
    assert res.added == 1
    assert await _external(db_session, zone) == [("ns1", "127.0.0.1")]


async def test_primary_ns_outside_the_zone_keeps_it(db_session: AsyncSession) -> None:
    zone = await _zone(db_session, primary_ns="ns.other.net.")
    res = await reconcile_external_records(db_session, zone, [GLUE])
    assert res.added == 1
