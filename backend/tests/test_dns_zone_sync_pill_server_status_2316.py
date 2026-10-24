"""The zone sync pill does not count a server that is not active as in sync (#2316).

``GET .../server-state`` compared each server's stored serial with the target
and ignored ``server.status``, so a server that went down after reporting a
matching serial still read "3/3 synced". A paused (maintenance) server is
left out of the count and reported separately. ``reported_at`` is not a
freshness bound: agents report only after an apply or at boot.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerZoneState, DNSZone

SERIAL = 2026100201


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u2316-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _setup(
    db: AsyncSession, servers: list[dict[str, Any]]
) -> tuple[DNSZone, list[DNSServer]]:
    grp = DNSServerGroup(name=f"g2316-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        last_serial=SERIAL,
    )
    db.add(zone)
    rows: list[DNSServer] = []
    for i, kw in enumerate(servers):
        srv = DNSServer(
            group_id=grp.id,
            name=f"ns{i}",
            driver="bind9",
            host=f"10.0.0.{i + 1}",
            port=53,
            **kw,
        )
        db.add(srv)
        rows.append(srv)
    await db.flush()
    for srv in rows:
        db.add(
            DNSServerZoneState(
                server_id=srv.id,
                zone_id=zone.id,
                current_serial=SERIAL,
                # Old on purpose: a quiet zone's report is old and still current.
                reported_at=datetime.now(UTC) - timedelta(days=3),
            )
        )
    await db.commit()
    return zone, rows


async def _state(client: AsyncClient, db: AsyncSession, zone: DNSZone) -> dict[str, Any]:
    r = await client.get(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/server-state",
        headers=await _headers(db),
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_all_active_servers_matching_serial_is_in_sync(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, _ = await _setup(db_session, [{"status": "active"}, {"status": "active"}])
    body = await _state(client, db_session, zone)
    assert body["in_sync"] is True
    assert [(s["freshness"], s["counted"]) for s in body["servers"]] == [("ok", True)] * 2


@pytest.mark.asyncio
async def test_unreachable_server_with_matching_serial_is_not_in_sync(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, _ = await _setup(
        db_session, [{"status": "active"}, {"status": "active"}, {"status": "unreachable"}]
    )
    body = await _state(client, db_session, zone)
    assert body["in_sync"] is False
    by_name = {s["server_name"]: s for s in body["servers"]}
    assert by_name["ns2"]["current_serial"] == SERIAL
    assert (by_name["ns2"]["freshness"], by_name["ns2"]["counted"]) == ("unreachable", False)
    assert by_name["ns0"]["counted"] is True


@pytest.mark.asyncio
async def test_paused_server_is_excluded_not_counted_as_drift(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, rows = await _setup(
        db_session,
        [{"status": "active"}, {"status": "unreachable", "maintenance_mode": True}],
    )
    body = await _state(client, db_session, zone)
    paused = next(s for s in body["servers"] if s["server_name"] == "ns1")
    assert (paused["freshness"], paused["counted"]) == ("paused", False)
    assert body["in_sync"] is True


@pytest.mark.asyncio
async def test_only_paused_servers_is_not_in_sync(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone, _ = await _setup(db_session, [{"status": "active", "maintenance_mode": True}])
    assert (await _state(client, db_session, zone))["in_sync"] is False
