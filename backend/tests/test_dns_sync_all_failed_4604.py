"""Group Sync with Servers: a server whose every zone failed did not succeed (#4604 B6)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.services.dns import pull_from_server as pfs
from tests.test_dns_sync_server_1697 import _admin_headers


class _DeadDriver:
    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A"]}

    async def pull_zone_records(self, server: Any, zone_name: str, *, tsig: Any = None) -> Any:
        if server.name == "down":
            raise RuntimeError("unsupported")
        return []

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        return []


async def test_group_sync_does_not_count_an_all_failed_server(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    for name, primary in (("up", True), ("down", False)):
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
    db_session.add(
        DNSZone(group_id=group.id, name="example.com.", zone_type="primary", kind="forward")
    )
    headers = await _admin_headers(db_session)
    await db_session.commit()
    monkeypatch.setattr(pfs, "get_driver", lambda name: _DeadDriver())

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/sync-with-servers",
        params={"import_new_zones": "false"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["servers_attempted"] == 2
    assert body["servers_succeeded"] == 1
