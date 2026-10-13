"""Group-level Sync with Servers syncs each server's own copy (#1697).

The per-server loop used to call the per-zone sync with no server, which
resolved the zone's primary every time: an unreachable server was listed as
succeeded with the primary's counts.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordChangeResult, RecordData
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
