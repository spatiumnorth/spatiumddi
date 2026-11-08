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


async def _setup(client: AsyncClient, db: AsyncSession, tag: str):
    h = await _admin_named(db, tag)
    a, b = DNSServerGroup(name=f"g{tag}a"), DNSServerGroup(name=f"g{tag}b")
    db.add_all([a, b])
    await db.flush()
    lid = (await client.post("/api/v1/dns/blocklists", json={"name": f"l{tag}"}, headers=h)).json()[
        "id"
    ]
    return h, a, b, f"/api/v1/dns/blocklists/{lid}/assignments", lid


async def _admin_named(db: AsyncSession, tag: str) -> dict[str, str]:
    u = User(
        username=f"bl{tag}",
        email=f"bl{tag}@example.com",
        display_name=f"bl{tag}",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


@pytest.mark.asyncio
async def test_full_set_and_delta_for_one_dimension_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, a, b, url, _ = await _setup(client, db_session, "mix")
    await client.put(url, json={"server_group_ids": [str(a.id)]}, headers=h)
    r = await client.put(
        url,
        json={"server_group_ids": [str(b.id)], "remove_server_group_ids": [str(a.id)]},
        headers=h,
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        url,
        json={"add_server_group_ids": [str(b.id)], "remove_server_group_ids": [str(b.id)]},
        headers=h,
    )
    assert r.status_code == 422, r.text
    # Nothing changed by either refusal; a full set on one dimension with a
    # delta on the OTHER is fine.
    r = await client.put(
        url, json={"server_group_ids": [str(a.id)], "remove_view_ids": []}, headers=h
    )
    assert r.status_code == 200, r.text
    assert r.json()["applied_group_ids"] == [str(a.id)]


@pytest.mark.asyncio
async def test_empty_body_is_a_no_op(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.v1.dns import blocklist_router

    h, a, _b, url, lid = await _setup(client, db_session, "nop")
    await client.put(url, json={"server_group_ids": [str(a.id)]}, headers=h)
    woken: list[str] = []
    monkeypatch.setattr(blocklist_router, "collect_wake", woken.append)
    before = await _assignment_audits(db_session, lid)

    r = await client.put(url, json={}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["applied_group_ids"] == [str(a.id)]
    assert woken == []
    assert await _assignment_audits(db_session, lid) == before


@pytest.mark.asyncio
async def test_delta_remove_wakes_the_removed_group(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.v1.dns import blocklist_router
    from app.core.agent_wake import dns_group_channel

    h, a, b, url, _ = await _setup(client, db_session, "wak")
    await client.put(url, json={"server_group_ids": [str(a.id)]}, headers=h)
    woken: list[str] = []
    monkeypatch.setattr(blocklist_router, "collect_wake", woken.append)
    r = await client.put(
        url,
        json={"add_server_group_ids": [str(b.id)], "remove_server_group_ids": [str(a.id)]},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert set(woken) == {dns_group_channel(a.id), dns_group_channel(b.id)}


async def _assignment_audits(db: AsyncSession, lid: str) -> int:
    from sqlalchemy import func, select

    from app.models.audit import AuditLog

    return (
        await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.resource_type == "dns_blocklist_assignment",
                AuditLog.resource_id == lid,
            )
        )
    ).scalar_one()
