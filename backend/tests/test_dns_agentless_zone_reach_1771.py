"""#1771 — a zone SpatiumDDI holds must reach the agentless server.

The import commit wrote the zone row and then queued its record ops, which an
agentless server (technitium_api / Windows / cloud) refused with "No such zone"
or took into an enclosing zone. Sync with Servers listed adopted zones as
pushed, and tried to create every zone when the zone listing failed. (A second
``technitium_api`` server per group is refused since #1784.)
"""

from __future__ import annotations

import io
import tarfile
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone

from .test_dns_auto_zone_agentless_1932 import _FakeTechnitium, provider  # noqa: F401

ZONE = "imp1771.test."


def _archive() -> bytes:
    named = f'zone "{ZONE.rstrip(".")}" {{ type master; file "z.zone"; }};\n'
    zone = (
        "$TTL 3600\n"
        f"@ IN SOA ns1.{ZONE} hostmaster.example.com. ( 1 3600 1800 1209600 3600 )\n"
        f"  IN NS ns1.{ZONE}\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.2\n"
    )
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for path, content in (("etc/named.conf", named), ("var/named/z.zone", zone)):
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return bio.getvalue()


async def _group(db: AsyncSession, driver: str) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g1771-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver=driver,
            host="10.0.0.1",
            name="ns1",
            is_primary=True,
            is_enabled=True,
            credentials_encrypted=b"x" if driver == "technitium_api" else None,
            agent_id=None if driver == "technitium_api" else uuid.uuid4(),
        )
    )
    await db.flush()
    return grp


async def _import(db: AsyncSession, client: AsyncClient, grp: DNSServerGroup) -> None:
    user = User(
        username=f"imp1771-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="imp1771",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    pre = await client.post(
        "/api/v1/dns/import/bind9/preview",
        headers=h,
        files={"file": ("b.tar.gz", _archive(), "application/gzip")},
        data={"target_group_id": str(grp.id)},
    )
    assert pre.status_code == 200, pre.text
    res = await client.post(
        "/api/v1/dns/import/bind9/commit",
        headers=h,
        json={"target_group_id": str(grp.id), "plan": pre.json(), "conflict_actions": {}},
    )
    assert res.status_code == 200, res.text


@pytest.mark.asyncio
async def test_import_commit_creates_the_zone_at_an_agentless_server_before_its_records(
    db_session: AsyncSession,
    client: AsyncClient,
    provider: type[_FakeTechnitium],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _batch(self: Any, server: Any, changes: list[Any]) -> list[Any]:
        from app.drivers.dns.base import RecordChangeResult

        for c in changes:
            await self.apply_record_change(server, c)
        return [RecordChangeResult(change=c, ok=True) for c in changes]

    monkeypatch.setattr(_FakeTechnitium, "apply_record_changes", _batch, raising=False)
    grp = await _group(db_session, "technitium_api")
    provider.zones = set()
    await _import(db_session, client, grp)
    assert ZONE in provider.zones
    assert provider.log.count(("zone-create", ZONE)) == 1
    recs = [e for e in provider.log if e[0] == "record-create"]
    assert recs, provider.log
    assert provider.log.index(("zone-create", ZONE)) < provider.log.index(recs[0])


@pytest.mark.asyncio
async def test_import_into_an_agent_group_makes_no_provider_call(
    db_session: AsyncSession,
    client: AsyncClient,
    provider: type[_FakeTechnitium],  # noqa: F811
) -> None:
    grp = await _group(db_session, "technitium")
    await _import(db_session, client, grp)
    assert [e for e in provider.log if e[0].startswith("zone-")] == []
    zones = (await db_session.execute(select(DNSZone).where(DNSZone.group_id == grp.id))).all()
    assert len(zones) == 1


class _SyncDriver:
    def __init__(self, *, listing_fails: bool, existing: set[str]) -> None:
        self.listing_fails = listing_fails
        self.existing = existing
        self.created: list[str] = []
        self.pulled = False

    async def pull_zones_from_server(self, _server: Any) -> list[dict[str, Any]]:
        self.pulled = True
        if self.listing_fails:
            raise RuntimeError("zones/list: 503")
        return []

    async def apply_zone_change(self, _server: Any, zone: Any, op: str) -> bool:
        self.created.append(zone.name)
        return zone.name not in self.existing

    async def apply_record_change(self, *_a: Any, **_k: Any) -> None:
        return None

    async def pull_records_from_server(self, *_a: Any, **_k: Any) -> list[Any]:
        return []


async def _sync(
    db: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch, drv: _SyncDriver
) -> dict[str, Any]:
    grp = await _group(db, "technitium_api")
    srv = (await db.execute(select(DNSServer).where(DNSServer.group_id == grp.id))).scalar_one()
    db.add(DNSZone(group_id=grp.id, name="a.test.", zone_type="primary", kind="forward"))
    user = User(
        username=f"s1771-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="s",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    import app.drivers.dns as drivers

    monkeypatch.setattr(drivers, "get_driver", lambda _n: drv)
    res = await client.post(
        f"/api/v1/dns/groups/{grp.id}/servers/{srv.id}/sync-from-server",
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
        json={},
    )
    assert res.status_code == 200, res.text
    return res.json()


@pytest.mark.asyncio
async def test_sync_does_not_create_every_zone_when_the_zone_listing_failed(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = _SyncDriver(listing_fails=True, existing=set())
    body = await _sync(db_session, client, monkeypatch, drv)
    assert drv.pulled
    assert drv.created == []
    assert body["zones_pushed_to_server"] == []


@pytest.mark.asyncio
async def test_sync_does_not_report_an_adopted_zone_as_pushed(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = _SyncDriver(listing_fails=False, existing={"a.test."})
    body = await _sync(db_session, client, monkeypatch, drv)
    assert "a.test." in drv.created
    assert body["zones_pushed_to_server"] == []
