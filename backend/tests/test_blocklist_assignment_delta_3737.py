"""#3737 — assignment deltas change only the named group / view."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username="bl3737",
        email="bl3737@example.com",
        display_name="bl3737",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


@pytest.mark.asyncio
async def test_delta_leaves_other_groups_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    a, b, c = (DNSServerGroup(name=f"g3737{n}") for n in "abc")
    db_session.add_all([a, b, c])
    await db_session.flush()
    r = await client.post("/api/v1/dns/blocklists", json={"name": "l3737"}, headers=h)
    lid = r.json()["id"]
    url = f"/api/v1/dns/blocklists/{lid}/assignments"

    # Another client attached B after this tab loaded the list (A only).
    r = await client.put(url, json={"server_group_ids": [str(a.id), str(b.id)]}, headers=h)
    assert r.status_code == 200, r.text

    # The stale tab attaches C and detaches A, by delta.
    r = await client.put(
        url,
        json={
            "add_server_group_ids": [str(c.id)],
            "remove_server_group_ids": [str(a.id)],
        },
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert set(r.json()["applied_group_ids"]) == {str(b.id), str(c.id)}

    # Idempotent add, unknown id refused.
    r = await client.put(url, json={"add_server_group_ids": [str(c.id)]}, headers=h)
    assert set(r.json()["applied_group_ids"]) == {str(b.id), str(c.id)}
    r = await client.put(
        url,
        json={"add_server_group_ids": ["00000000-0000-0000-0000-000000000001"]},
        headers=h,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_full_set_still_replaces(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    a, b = DNSServerGroup(name="g3737x"), DNSServerGroup(name="g3737y")
    db_session.add_all([a, b])
    await db_session.flush()
    lid = (await client.post("/api/v1/dns/blocklists", json={"name": "l3737b"}, headers=h)).json()[
        "id"
    ]
    url = f"/api/v1/dns/blocklists/{lid}/assignments"
    await client.put(url, json={"server_group_ids": [str(a.id)]}, headers=h)
    r = await client.put(url, json={"server_group_ids": [str(b.id)]}, headers=h)
    assert r.json()["applied_group_ids"] == [str(b.id)]
