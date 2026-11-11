"""spatiumddi#3924 — a zone restored from the Trash answers what IPAM holds now.

The zone's records come back as the Trash held them; the addresses of its subnet
went on changing meanwhile (renamed, added, deleted for good). The restore's
follow-up task re-runs the IPAM-DNS sync over the zone's subnets.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord
from app.tasks import ipam_dns_sync
from tests.test_subnet_trash_retracts_dns_1906 import _address, _admin_headers, _setup
from tests.test_zone_restore_trashed_subnet_records_2732 import _forward_a


def _capture(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    queued: list[list[str]] = []

    class _Task:
        @staticmethod
        def delay(ids: list[str]) -> None:
            queued.append(list(ids))

    # raising=False: on unfixed code the task does not exist and nothing is queued.
    monkeypatch.setattr(ipam_dns_sync, "reconcile_restored_zone_records_task", _Task, raising=False)
    return queued


async def _trash_zone(client, headers, grp, zone):  # type: ignore[no-untyped-def]
    r = await client.delete(f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}", headers=headers)
    assert r.status_code == 204, r.text


async def _restore_and_reconcile(client, db, headers, zone, queued):  # type: ignore[no-untyped-def]
    r = await client.post(f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=headers)
    assert r.status_code == 200, r.text
    for ids in queued:
        await ipam_dns_sync.reconcile_restored_zone_records(db, [uuid.UUID(i) for i in ids])


@pytest.mark.asyncio
async def test_rename_and_add_while_trashed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    queued = _capture(monkeypatch)
    headers = await _admin_headers(db_session)
    grp, _s, zone, sid, _ = await _setup(
        client, db_session, headers, "10.146.1.0/24", None, "10.146.0.0/16"
    )
    renamed = await _address(client, headers, sid, "10.146.1.10", "r5a")
    await _address(client, headers, sid, "10.146.1.11", "r5b")
    await _trash_zone(client, headers, grp, zone)
    r = await client.put(
        f"/api/v1/ipam/addresses/{renamed}", headers=headers, json={"hostname": "r5z"}
    )
    assert r.status_code == 200, r.text
    await _address(client, headers, sid, "10.146.1.12", "r5c")
    await _restore_and_reconcile(client, db_session, headers, zone, queued)
    assert await _forward_a(db_session, zone.id) == [
        ("r5b", "10.146.1.11", True),
        ("r5c", "10.146.1.12", True),
        ("r5z", "10.146.1.10", True),
    ]


@pytest.mark.asyncio
async def test_deleted_for_good_stays_gone(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    queued = _capture(monkeypatch)
    headers = await _admin_headers(db_session)
    grp, _s, zone, sid, _ = await _setup(
        client, db_session, headers, "10.146.2.0/24", None, "10.146.0.0/16"
    )
    gone = await _address(client, headers, sid, "10.146.2.10", "h1")
    await _address(client, headers, sid, "10.146.2.11", "h2")
    await _trash_zone(client, headers, grp, zone)
    r = await client.delete(f"/api/v1/ipam/addresses/{gone}?permanent=true", headers=headers)
    assert r.status_code == 204, r.text
    zone_id = zone.id
    await _restore_and_reconcile(client, db_session, headers, zone, queued)
    assert await _forward_a(db_session, zone_id) == [("h2", "10.146.2.11", True)]


@pytest.mark.asyncio
async def test_manual_record_survives(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    queued = _capture(monkeypatch)
    headers = await _admin_headers(db_session)
    grp, _s, zone, sid, _ = await _setup(
        client, db_session, headers, "10.146.3.0/24", None, "10.146.0.0/16"
    )
    renamed = await _address(client, headers, sid, "10.146.3.10", "m1")
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="manual",
            fqdn=f"manual.{zone.name}",
            record_type="A",
            value="10.146.3.99",
            ttl=300,
        )
    )
    await db_session.commit()
    await _trash_zone(client, headers, grp, zone)
    r = await client.put(
        f"/api/v1/ipam/addresses/{renamed}", headers=headers, json={"hostname": "m2"}
    )
    assert r.status_code == 200, r.text
    await _restore_and_reconcile(client, db_session, headers, zone, queued)
    assert await _forward_a(db_session, zone.id) == [
        ("m2", "10.146.3.10", True),
        ("manual", "10.146.3.99", True),
    ]
