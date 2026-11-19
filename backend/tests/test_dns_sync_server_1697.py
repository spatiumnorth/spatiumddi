"""Group-level Sync with Servers syncs each server's own copy (#1697).

The per-server loop used to call the per-zone sync with no server, which
resolved the zone's primary every time: an unreachable server was listed as
succeeded with the primary's counts.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import RecordChangeResult, RecordData
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.services.dns import pull_from_server as pfs
from app.services.dns.pull_from_server import sync_zone_with_server

_ZONE = "example.com."


class _PerServerDriver:
    """Serves each server its own zone copy; one server is down."""

    def __init__(self) -> None:
        self.pulled_from: list[str] = []
        self.pushed_to: list[str] = []

    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A"]}

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        self.pulled_from.append(server.name)
        if server.name == "down":
            raise RuntimeError("connection refused")
        return [RecordData(name="only-on-primary", record_type="A", value="192.0.2.1", ttl=300)]

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        self.pushed_to.append(server.name)
        return [RecordChangeResult(ok=True, change=c) for c in changes]


async def test_sync_zone_with_a_named_server_reads_that_server(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    primary = DNSServer(
        group_id=group.id,
        name="primary",
        driver="technitium_api",
        host="10.0.0.1",
        port=53,
        is_enabled=True,
        is_primary=True,
    )
    down = DNSServer(
        group_id=group.id,
        name="down",
        driver="technitium_api",
        host="10.0.0.2",
        port=53,
        is_enabled=True,
    )
    zone = DNSZone(group_id=group.id, name=_ZONE, zone_type="primary", kind="forward")
    db_session.add_all([primary, down, zone])
    await db_session.flush()

    fake = _PerServerDriver()
    monkeypatch.setattr(pfs, "get_driver", lambda name: fake)

    # Default: the zone's primary, as the per-zone endpoint does.
    await sync_zone_with_server(db_session, zone, apply=False)
    assert fake.pulled_from == ["primary"]

    # The walked server: its own copy is read, so a dead server fails.
    fake.pulled_from.clear()
    with pytest.raises(RuntimeError, match="connection refused"):
        await sync_zone_with_server(db_session, zone, apply=False, server=down)
    assert fake.pulled_from == ["down"]


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_group_sync_reports_each_servers_own_result(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issue's reproduction, through the endpoint: the server whose API
    is down is listed with the zone failed, not with the primary's counts."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    for name, primary in (("primary", True), ("down", False)):
        db_session.add(
            DNSServer(
                group_id=group.id,
                name=name,
                driver="technitium_api",
                host=f"{name}.example.net",
                port=53,
                is_enabled=True,
                is_primary=primary,
            )
        )
    db_session.add(DNSZone(group_id=group.id, name=_ZONE, zone_type="primary", kind="forward"))
    headers = await _admin_headers(db_session)
    await db_session.commit()

    fake = _PerServerDriver()
    monkeypatch.setattr(pfs, "get_driver", lambda name: fake)

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/sync-with-servers",
        params={"import_new_zones": "false"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    by_server = {i["server_name"]: i["result"] for i in resp.json()["items"]}
    assert sorted(fake.pulled_from) == ["down", "primary"]

    (down_zone,) = by_server["down"]["items"]
    assert "connection refused" in (down_zone["error"] or "")
    assert by_server["down"]["zones_succeeded"] == 0

    (primary_zone,) = by_server["primary"]["items"]
    assert primary_zone["error"] is None
    assert primary_zone["imported"] == 1
