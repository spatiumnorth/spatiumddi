"""#4573 — a blocklist assigned to a PowerDNS-only group blocks nothing (no RPZ)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSView


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username="bl4573",
        email="bl4573@example.com",
        display_name="bl4573",
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
        db.add(DNSServer(group_id=g.id, name=f"{name}-{i}", driver=d, host=f"10.45.7.{i + 1}"))
    await db.flush()
    return g


async def _list(client: AsyncClient, h: dict[str, str]) -> str:
    r = await client.post("/api/v1/dns/blocklists", json={"name": "l4573"}, headers=h)
    return r.json()["id"]


@pytest.mark.asyncio
async def test_new_assignment_to_powerdns_group_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    pdns = await _group(db_session, "pdns4573", "powerdns")
    lid = await _list(client, h)
    url = f"/api/v1/dns/blocklists/{lid}/assignments"
    for body in (
        {"server_group_ids": [str(pdns.id)]},
        {"add_server_group_ids": [str(pdns.id)]},
    ):
        r = await client.put(url, json=body, headers=h)
        assert r.status_code == 422, r.text
        assert "RPZ" in r.json()["detail"]
    r = await client.get(f"/api/v1/dns/blocklists/{lid}", headers=h)
    assert r.json()["applied_group_ids"] == []


@pytest.mark.asyncio
async def test_view_of_powerdns_group_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    pdns = await _group(db_session, "pdnsv4573", "powerdns")
    view = DNSView(group_id=pdns.id, name="v4573")
    db_session.add(view)
    await db_session.flush()
    lid = await _list(client, h)
    r = await client.put(
        f"/api/v1/dns/blocklists/{lid}/assignments",
        json={"add_view_ids": [str(view.id)]},
        headers=h,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_bind9_and_mixed_groups_still_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    bind = await _group(db_session, "bind4573", "bind9")
    mixed = await _group(db_session, "mixed4573", "powerdns", "bind9")
    lid = await _list(client, h)
    r = await client.put(
        f"/api/v1/dns/blocklists/{lid}/assignments",
        json={"server_group_ids": [str(bind.id), str(mixed.id)]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["unapplied_warning"] is None


@pytest.mark.asyncio
async def test_existing_assignment_stays_removable_and_warns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    g = await _group(db_session, "late4573")
    lid = await _list(client, h)
    url = f"/api/v1/dns/blocklists/{lid}/assignments"
    r = await client.put(url, json={"server_group_ids": [str(g.id)]}, headers=h)
    assert r.status_code == 200
    # The group's server turned out to be PowerDNS after the assignment.
    db_session.add(DNSServer(group_id=g.id, name="late4573-0", driver="powerdns", host="10.45.7.9"))
    await db_session.flush()

    r = await client.get(f"/api/v1/dns/blocklists/{lid}", headers=h)
    assert "late4573" in r.json()["unapplied_warning"]
    # Re-saving the stored set is not a new assignment.
    r = await client.put(url, json={"server_group_ids": [str(g.id)]}, headers=h)
    assert r.status_code == 200, r.text
    r = await client.put(url, json={"remove_server_group_ids": [str(g.id)]}, headers=h)
    assert r.status_code == 200
    assert r.json()["applied_group_ids"] == []
    assert r.json()["unapplied_warning"] is None
