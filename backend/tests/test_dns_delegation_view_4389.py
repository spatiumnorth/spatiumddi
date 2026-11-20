"""Delegate finds the parent zone in the child's own view (#4389)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone


async def _setup(db: AsyncSession) -> tuple[DNSServerGroup, dict[str, str]]:
    user = User(
        username=f"dg-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    return grp, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _view(db: AsyncSession, grp: DNSServerGroup, name: str) -> DNSView:
    view = DNSView(group_id=grp.id, name=name)
    db.add(view)
    await db.flush()
    return view


async def _zone(
    db: AsyncSession, grp: DNSServerGroup, name: str, view: DNSView | None = None
) -> DNSZone:
    zone = DNSZone(
        group_id=grp.id,
        view_id=view.id if view else None,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        ttl=3600,
    )
    db.add(zone)
    await db.flush()
    return zone


async def _record(db: AsyncSession, zone: DNSZone, name: str, rtype: str, value: str) -> None:
    fqdn = zone.name if name == "@" else f"{name}.{zone.name}"
    db.add(
        DNSRecord(zone_id=zone.id, fqdn=fqdn, name=name, record_type=rtype, value=value, ttl=3600)
    )
    await db.flush()


def _url(zone: DNSZone, tail: str) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}{tail}"


async def _count(db: AsyncSession, zone: DNSZone) -> int:
    return (
        await db.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone.id)
        )
    ).scalar_one()


# ── #4389 ───────────────────────────────────────────────────────────────────


async def _two_views(db: AsyncSession, grp: DNSServerGroup, first: str) -> tuple[DNSView, DNSView]:
    # Both orders: the pre-fix lookup took whichever row the database returned.
    names = [first, "v-int" if first == "v-ext" else "v-ext"]
    views = {n: await _view(db, grp, n) for n in names}
    return views["v-int"], views["v-ext"]


async def test_delegate_writes_into_childs_own_view_parent_4389(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    for order, label in (("v-ext", "a"), ("v-int", "b")):
        grp2 = DNSServerGroup(name=f"g2-{label}-{uuid.uuid4().hex[:4]}")
        db_session.add(grp2)
        await db_session.flush()
        v_int, v_ext = await _two_views(db_session, grp2, order)
        zones = {}
        for v in (v_ext, v_int) if order == "v-ext" else (v_int, v_ext):
            zones[v.name] = await _zone(db_session, grp2, "p1.example.", v)
        child = await _zone(db_session, grp2, "sub.p1.example.", v_int)
        await _record(db_session, child, "@", "NS", "ns1.sub.p1.example.")
        await _record(db_session, child, "ns1", "A", "192.0.2.45")

        r = await client.get(_url(child, "/delegation-preview"), headers=h)
        assert r.json()["parent_zone_id"] == str(zones["v-int"].id)
        assert r.json()["parent_view_name"] == "v-int"
        r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
        assert r.status_code == 201, r.text
        assert {x["record_type"] for x in r.json()} == {"NS", "A"}
        assert await _count(db_session, zones["v-int"]) == 2
        assert await _count(db_session, zones["v-ext"]) == 0


async def test_parent_only_in_another_view_is_no_parent_4389(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    v_int = await _view(db_session, grp, "v-int")
    v_ext = await _view(db_session, grp, "v-ext")
    other = await _zone(db_session, grp, "p1.example.", v_ext)
    child = await _zone(db_session, grp, "sub.p1.example.", v_int)
    await _record(db_session, child, "@", "NS", "ns1.example.net.")
    r = await client.get(_url(child, "/delegation-preview"), headers=h)
    assert r.json()["has_parent"] is False
    r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
    assert r.status_code == 404, r.text
    assert await _count(db_session, other) == 0


async def test_unpinned_child_takes_only_unpinned_parent_4389(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    v_ext = await _view(db_session, grp, "v-ext")
    pinned = await _zone(db_session, grp, "p1.example.", v_ext)
    child = await _zone(db_session, grp, "sub.p1.example.")
    await _record(db_session, child, "@", "NS", "ns1.example.net.")
    r = await client.get(_url(child, "/delegation-preview"), headers=h)
    assert r.json()["has_parent"] is False
    unpinned = await _zone(db_session, grp, "p1.example.")
    r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
    assert r.status_code == 201, r.text
    assert await _count(db_session, unpinned) == 1
    assert await _count(db_session, pinned) == 0


async def test_pinned_child_falls_back_to_unpinned_parent_4389(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    v_int = await _view(db_session, grp, "v-int")
    unpinned = await _zone(db_session, grp, "p1.example.")
    child = await _zone(db_session, grp, "sub.p1.example.", v_int)
    await _record(db_session, child, "@", "NS", "ns1.example.net.")
    r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
    assert r.status_code == 201, r.text
    assert await _count(db_session, unpinned) == 1
