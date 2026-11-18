"""#4140 — a blocklist change wakes the agents of every group it touches."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import agent_wake
from app.core.agent_wake import dns_group_channel
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[set[str]]:
    sent: list[set[str]] = []

    async def fake(*channels: str) -> None:
        sent.append(set(channels))

    monkeypatch.setattr(agent_wake, "publish_wake", fake)
    return sent


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username="bl4140",
        email="bl4140@example.com",
        display_name="bl4140",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _woke(published: list[set[str]], gid: Any) -> bool:
    return any(dns_group_channel(gid) in s for s in published)


@pytest.mark.asyncio
async def test_blocklist_mutations_wake_the_assigned_group(
    client: AsyncClient, db_session: AsyncSession, published: list[set[str]]
) -> None:
    h = await _admin(db_session)
    g = DNSServerGroup(name="g4140")
    db_session.add(g)
    await db_session.flush()
    r = await client.post("/api/v1/dns/blocklists", json={"name": "l4140"}, headers=h)
    lid = r.json()["id"]
    base = f"/api/v1/dns/blocklists/{lid}"

    async def step(label: str, method: str, url: str, body: dict[str, Any] | None = None) -> Any:
        published.clear()
        r = await client.request(method, url, json=body, headers=h)
        assert r.status_code < 300, f"{label}: {r.text}"
        assert _woke(published, g.id), f"{label}: no wake for the assigned group"
        return r

    # Detach wakes the group it LEAVES, too.
    published.clear()
    r = await client.put(f"{base}/assignments", json={"server_group_ids": [str(g.id)]}, headers=h)
    assert _woke(published, g.id), "attach: no wake"

    r = await step(
        "add entry", "POST", f"{base}/entries", {"domain": "a.example.com", "entry_type": "block"}
    )
    eid = r.json()["id"]
    await step(
        "bulk add", "POST", f"{base}/entries/bulk", {"domains": ["b.example.com", "c.example.com"]}
    )
    await step("update entry", "PUT", f"{base}/entries/{eid}", {"reason": "x"})
    await step("delete entry", "DELETE", f"{base}/entries/{eid}")
    r = await step("add exception", "POST", f"{base}/exceptions", {"domain": "ok.example.com"})
    xid = r.json()["id"]
    await step("update exception", "PUT", f"{base}/exceptions/{xid}", {"reason": "y"})
    await step("delete exception", "DELETE", f"{base}/exceptions/{xid}")
    await step("update list", "PUT", base, {"description": "changed"})
    await step("detach", "PUT", f"{base}/assignments", {"remove_server_group_ids": [str(g.id)]})
    # Re-attach, then delete the list: the delete wakes the group that held it.
    await client.put(f"{base}/assignments", json={"server_group_ids": [str(g.id)]}, headers=h)
    await step("delete list", "DELETE", base)
    assert uuid.UUID(lid)
