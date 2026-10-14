"""#1830 — every permanent removal of a trashed DNS zone drives the agentless
driver's zone delete before the row goes.

A zone is never torn down at soft-delete, so the permanent delete is its only
retraction point. The Trash page's per-row purge skipped the push, leaving the
zone served by Windows DNS / cloud / technitium_api with no DB trace.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.tasks.trash_purge import _purge_dns_zones


class _FakeAgentlessDriver:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail = fail

    async def apply_zone_change(self, _server: Any, zone: Any, op: str) -> bool:
        self.calls.append((zone.name, op))
        if self.fail:
            raise RuntimeError("provider unreachable")
        return True


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"t1830-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="t1830",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _trashed_zone(db: AsyncSession, age_days: int = 1) -> DNSZone:
    grp = DNSServerGroup(name=f"g1830-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="technitium_api",
            host="10.9.9.9",
            name=f"s-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
            credentials_encrypted=b"x",
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    db.add(
        DNSRecord(
            zone_id=zone.id,
            fqdn=f"w.{zone.name}",
            name="w",
            record_type="A",
            value="203.0.113.1",
            ttl=300,
        )
    )
    zone.deleted_at = datetime.now(UTC) - timedelta(days=age_days)
    zone.deletion_batch_id = uuid.uuid4()
    await db.commit()
    return zone


async def _row(db: AsyncSession, zone_id: uuid.UUID) -> DNSZone | None:
    db.expire_all()
    return (
        await db.execute(
            select(DNSZone).where(DNSZone.id == zone_id).execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_trash_permanent_delete_drives_agentless_driver(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _admin(db_session)
    zone = await _trashed_zone(db_session)
    drv = _FakeAgentlessDriver()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda _n: drv)

    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zone.id}", headers=headers)
    assert r.status_code == 204, r.text
    assert drv.calls == [(zone.name, "delete")]
    assert await _row(db_session, zone.id) is None


@pytest.mark.asyncio
async def test_trash_permanent_delete_keeps_row_when_provider_fails(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _admin(db_session)
    zone = await _trashed_zone(db_session)
    drv = _FakeAgentlessDriver(fail=True)
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda _n: drv)

    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zone.id}", headers=headers)
    assert r.status_code in (409, 502), r.text
    assert drv.calls == [(zone.name, "delete")]
    assert await _row(db_session, zone.id) is not None, "failed teardown must not orphan the zone"


@pytest.mark.asyncio
async def test_retention_sweep_drives_agentless_driver(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone = await _trashed_zone(db_session, age_days=40)
    drv = _FakeAgentlessDriver()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda _n: drv)

    purged, skipped = await _purge_dns_zones(db_session, datetime.now(UTC) - timedelta(days=30))
    assert (purged, skipped) == (1, 0)
    assert drv.calls == [(zone.name, "delete")]
    assert await _row(db_session, zone.id) is None


@pytest.mark.asyncio
async def test_permanent_query_flag_drives_agentless_driver(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _admin(db_session)
    zone = await _trashed_zone(db_session)
    zone.deleted_at = None
    zone.deletion_batch_id = None
    await db_session.commit()
    drv = _FakeAgentlessDriver()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda _n: drv)

    r = await client.delete(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}?permanent=true", headers=headers
    )
    assert r.status_code == 204, r.text
    assert drv.calls == [(zone.name, "delete")]
    assert await _row(db_session, zone.id) is None
