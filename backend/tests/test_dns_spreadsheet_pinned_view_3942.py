"""#3942 — a spreadsheet import must not store a record scoped to a view a
pinned zone never serves (the record API's rule, #3839)."""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSView
from tests.test_dns_zone_spreadsheet_2139 import _commit, _csv, _headers, _preview, _zone


async def _pinned(db: AsyncSession) -> tuple[Any, Any, DNSView, DNSView]:
    grp, zone, _ = await _zone(db)
    a = DNSView(group_id=grp.id, name="internal")
    b = DNSView(group_id=grp.id, name="external")
    db.add_all([a, b])
    await db.flush()
    zone.view_id = a.id
    await db.commit()
    return grp, zone, a, b


async def test_row_in_another_view_is_an_error_and_blocks_the_commit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone, a, _b = await _pinned(db_session)
    data = _csv(
        [
            {"name": "ok", "type": "A", "value": "192.0.2.1", "view": "internal"},
            {"name": "shared", "type": "A", "value": "192.0.2.3"},
            {"name": "lost", "type": "A", "value": "192.0.2.2", "view": "external"},
        ]
    )
    p = await _preview(client, h, grp, zone, data)
    assert [e["row"] for e in p["errors"]] == [4]
    assert "pinned" in p["errors"][0]["reason"]
    assert sorted(c["name"] for c in p["to_create"]) == ["ok", "shared"]

    await _commit(client, h, grp, zone, data, expect=422)
    rows = (await db_session.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))).all()
    assert rows == []


async def test_id_row_moving_a_record_to_another_view_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone, _a, b = await _pinned(db_session)
    rec = DNSRecord(zone_id=zone.id, name="mail", record_type="A", value="192.0.2.83", fqdn="mail")
    db_session.add(rec)
    await db_session.commit()
    data = _csv(
        [
            {
                "id": str(rec.id),
                "name": "mail",
                "type": "A",
                "value": "192.0.2.83",
                "view": "external",
            }
        ]
    )
    p = await _preview(client, h, grp, zone, data)
    assert len(p["errors"]) == 1 and "pinned" in p["errors"][0]["reason"]
    assert p["to_update"] == []
    await _commit(client, h, grp, zone, data, expect=422)
    await db_session.refresh(rec)
    assert rec.view_id is None


async def test_id_row_keeping_a_legacy_view_is_not_rejudged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone, _a, b = await _pinned(db_session)
    rec = DNSRecord(
        zone_id=zone.id, name="old", record_type="A", value="192.0.2.9", fqdn="old", view_id=b.id
    )
    db_session.add(rec)
    await db_session.commit()
    data = _csv(
        [
            {
                "id": str(rec.id),
                "name": "old",
                "type": "A",
                "value": "192.0.2.9",
                "ttl": "600",
                "view": "external",
            }
        ]
    )
    p = await _preview(client, h, grp, zone, data)
    assert p["errors"] == []
    assert len(p["to_update"]) == 1
