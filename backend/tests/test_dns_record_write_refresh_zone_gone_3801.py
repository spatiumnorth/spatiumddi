"""#3801 — a record write whose zone is permanently deleted right after its
commit answers 404, never a 500 ``Could not refresh instance``.

The delete is simulated at the exact window: right after the write's commit
the zone (and with it the new record) is removed and committed, then the
handler's re-read runs.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from tests.test_dns_zone_move_same_provider_3805 import _group, _token


async def _zone_with_record(db: AsyncSession) -> tuple[DNSZone, DNSRecord]:
    g = await _group(db, "g3801")
    zone = DNSZone(group_id=g.id, name="race.example.", zone_type="primary")
    db.add(zone)
    await db.flush()
    rec = DNSRecord(
        zone_id=zone.id, name="www", fqdn="www.race.example.", record_type="A", value="192.0.2.1"
    )
    db.add(rec)
    await db.flush()
    await db.commit()
    return zone, rec


def _delete_zone_after_commit(monkeypatch: pytest.MonkeyPatch, zone_id: object) -> None:
    orig = AsyncSession.commit
    fired = {"done": False}

    async def commit(self: AsyncSession) -> None:
        await orig(self)
        if not fired["done"]:
            fired["done"] = True
            await self.execute(delete(DNSRecord).where(DNSRecord.zone_id == zone_id))
            await self.execute(delete(DNSZone).where(DNSZone.id == zone_id))
            await orig(self)

    monkeypatch.setattr(AsyncSession, "commit", commit)


@pytest.mark.asyncio
async def test_create_record_zone_deleted_after_commit_is_404(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await _token(db_session)
    zone, _ = await _zone_with_record(db_session)
    _delete_zone_after_commit(monkeypatch, zone.id)
    resp = await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records",
        json={"name": "new", "record_type": "A", "value": "192.0.2.9"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_update_record_zone_deleted_after_commit_is_404(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await _token(db_session)
    zone, rec = await _zone_with_record(db_session)
    _delete_zone_after_commit(monkeypatch, zone.id)
    resp = await client.put(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records/{rec.id}",
        json={"value": "192.0.2.50"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404, resp.text
