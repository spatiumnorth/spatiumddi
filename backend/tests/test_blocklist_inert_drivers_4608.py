"""#4608 — a blocklist assigned to a group with no blocklist-capable server
(PowerDNS, Windows DNS, cloud drivers) blocks nothing, so it is refused."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns import _DRIVERS, blocklist_capable
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSView

INERT = [d for d in _DRIVERS if d not in ("bind9", "technitium")]


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username="bl4608",
        email="bl4608@example.com",
        display_name="bl4608",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession, name: str, *drivers: str) -> DNSServerGroup:
    g = DNSServerGroup(name=name)
    db.add(g)
    await db.flush()
    for i, d in enumerate(drivers):
        db.add(DNSServer(group_id=g.id, name=f"{name}-{i}", driver=d, host=f"10.46.8.{i + 1}"))
    await db.flush()
    return g


async def _list(client: AsyncClient, h: dict[str, str]) -> str:
    r = await client.post("/api/v1/dns/blocklists", json={"name": "l4608"}, headers=h)
    return r.json()["id"]


def test_capability_source() -> None:
    assert blocklist_capable("bind9") and blocklist_capable("technitium")
    for d in INERT:
        assert not blocklist_capable(d), d
    assert {"windows_dns", "route53", "cloudflare", "powerdns"} <= set(INERT)


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["windows_dns", "route53", "azure_dns", "powerdns"])
async def test_new_assignment_refused(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    h = await _admin(db_session)
    g = await _group(db_session, f"g-{driver}", driver)
    view = DNSView(group_id=g.id, name="v4608")
    db_session.add(view)
    await db_session.flush()
    lid = await _list(client, h)
    url = f"/api/v1/dns/blocklists/{lid}/assignments"
    for body in (
        {"server_group_ids": [str(g.id)]},
        {"add_server_group_ids": [str(g.id)]},
        {"view_ids": [str(view.id)]},
        {"add_view_ids": [str(view.id)]},
    ):
        r = await client.put(url, json=body, headers=h)
        assert r.status_code == 422, (body, r.text)
    r = await client.get(f"/api/v1/dns/blocklists/{lid}", headers=h)
    assert r.json()["applied_group_ids"] == []


@pytest.mark.asyncio
async def test_capable_and_mixed_groups_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    bind = await _group(db_session, "bind4608", "bind9")
    tech = await _group(db_session, "tech4608", "technitium")
    mixed = await _group(db_session, "mixed4608", "windows_dns", "bind9")
    empty = await _group(db_session, "empty4608")
    lid = await _list(client, h)
    r = await client.put(
        f"/api/v1/dns/blocklists/{lid}/assignments",
        json={"server_group_ids": [str(x.id) for x in (bind, tech, mixed, empty)]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["unapplied_warning"] is None


@pytest.mark.asyncio
async def test_stored_assignment_warns_and_stays_removable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    g = await _group(db_session, "late4608")
    lid = await _list(client, h)
    url = f"/api/v1/dns/blocklists/{lid}/assignments"
    assert (
        await client.put(url, json={"server_group_ids": [str(g.id)]}, headers=h)
    ).status_code == 200
    db_session.add(DNSServer(group_id=g.id, name="late4608-0", driver="route53", host="10.46.8.9"))
    await db_session.flush()

    r = await client.get(f"/api/v1/dns/blocklists/{lid}", headers=h)
    assert "late4608" in r.json()["unapplied_warning"]
    r = await client.put(url, json={"server_group_ids": [str(g.id)]}, headers=h)
    assert r.status_code == 200, r.text
    r = await client.put(url, json={"remove_server_group_ids": [str(g.id)]}, headers=h)
    assert r.status_code == 200
    assert r.json()["unapplied_warning"] is None
