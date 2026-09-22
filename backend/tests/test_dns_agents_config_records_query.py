"""The agent bundle fetches every zone's records in ONE query, in a stable
order.

This was one ``select(DNSRecord)`` per zone inside the zone loop, each row a
tracked ORM instance. At the sizing campaign's 250k A+PTR records the build
held ~500k instances for the life of the request — most of the api's working
set on every agent long-poll (2026-09-02/03). The rows are now column tuples
from a single ``WHERE zone_id IN (...)`` in a stable order, so the payload —
and the ETag the agent compares — is the same from poll to poll.

#1111 — the order is the ``ix_dns_record_zone_name`` prefix ``(zone_id,
name)`` followed by every other shipped column, not ``(zone_id, id)``: ``id``
is a random UUID no index covers, so at 1.09 M rows the planner sorted the
whole table inside asyncpg's 30 s ``command_timeout`` and every agent poll
answered 503. A total order over the shipped columns keeps the payload stable
without it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.agent_config import build_config_bundle


async def _group_with_zones(db: AsyncSession, zones: int, per_zone: int) -> DNSServer:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    for zi in range(zones):
        zone = DNSZone(
            group_id=grp.id,
            name=f"z{zi}-{uuid.uuid4().hex[:4]}.example.",
            zone_type="primary",
            kind="forward",
            primary_ns="ns1.example.",
            admin_email="admin.example.",
        )
        db.add(zone)
        await db.flush()
        db.add_all(
            DNSRecord(
                zone_id=zone.id,
                name=f"h{i:03d}",
                fqdn=f"h{i:03d}.{zone.name}",
                record_type="A",
                value=f"10.{zi}.{i // 250}.{i % 250}",
            )
            for i in range(per_zone)
        )
        await db.flush()
    return server


class _RecordSelects:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def __call__(self, conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        s = " ".join(statement.split()).upper()
        if s.startswith("SELECT") and " FROM DNS_RECORD " in s + " " and "DNS_RECORD_OP" not in s:
            self.statements.append(statement)


@pytest.mark.asyncio
async def test_all_zones_records_come_from_one_query(db_session: AsyncSession) -> None:
    server = await _group_with_zones(db_session, zones=4, per_zone=30)
    await db_session.commit()

    counter = _RecordSelects()
    event.listen(Engine, "before_cursor_execute", counter)
    try:
        bundle = await build_config_bundle(db_session, server)
    finally:
        event.remove(Engine, "before_cursor_execute", counter)

    assert len(counter.statements) == 1, counter.statements
    # #1111 — the order the planner can serve from ``ix_dns_record_zone_name``
    # (zone_id, name) rather than a full sort of the table by a random UUID.
    ordered = " ".join(counter.statements[0].split())
    assert (
        "ORDER BY dns_record.zone_id, dns_record.name, dns_record.record_type" in ordered
    ), ordered
    assert "dns_record.id" not in ordered.split("ORDER BY", 1)[1], ordered
    assert sorted(len(z["records"]) for z in bundle["zones"]) == [30, 30, 30, 30]
    rec = bundle["zones"][0]["records"][0]
    assert set(rec) == {"name", "type", "ttl", "value", "priority", "weight", "port"}


@pytest.mark.asyncio
async def test_the_payload_and_etag_are_stable_across_polls(db_session: AsyncSession) -> None:
    server = await _group_with_zones(db_session, zones=2, per_zone=50)
    await db_session.commit()

    first = await build_config_bundle(db_session, server)
    second = await build_config_bundle(db_session, server)
    assert first["zones"] == second["zones"]
    assert first["etag"] == second["etag"]
    assert first["structural_etag"] == second["structural_etag"]
