"""Delegate holds the record API's CNAME rule (#4388)."""

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


# ── #4388 ───────────────────────────────────────────────────────────────────


async def test_delegate_refused_beside_cname_at_child_label_4388(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    parent = await _zone(db_session, grp, "p1.example.")
    await _record(db_session, parent, "sub", "CNAME", "target.example.net.")
    child = await _zone(db_session, grp, "sub.p1.example.")
    await _record(db_session, child, "@", "NS", "ns1.example.net.")

    r = await client.get(_url(child, "/delegation-preview"), headers=h)
    body = r.json()
    assert body["has_parent"] is True
    assert body["ns_records_to_create"] == []
    assert len(body["cname_conflicts"]) == 1
    assert "sub.p1.example is a CNAME" in body["cname_conflicts"][0]
    assert "Delete or rename that CNAME" in body["cname_conflicts"][0]

    r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
    assert r.status_code == 409, r.text
    assert "CNAME" in r.json()["detail"]
    assert await _count(db_session, parent) == 1  # only the CNAME


async def test_delegate_refused_beside_cname_at_glue_name_4388(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    parent = await _zone(db_session, grp, "p2.example.")
    await _record(db_session, parent, "ns1.sub", "CNAME", "target.example.net.")
    child = await _zone(db_session, grp, "sub.p2.example.")
    await _record(db_session, child, "@", "NS", "ns1.sub.p2.example.")
    await _record(db_session, child, "ns1", "A", "192.0.2.44")

    r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
    assert r.status_code == 409, r.text
    assert "ns1.sub.p2.example is a CNAME" in r.json()["detail"]
    # The NS row was not written either: nothing lands beside the CNAME.
    assert await _count(db_session, parent) == 1


async def test_delegate_without_cname_still_works_4388(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, h = await _setup(db_session)
    parent = await _zone(db_session, grp, "p3.example.")
    await _record(db_session, parent, "other", "CNAME", "target.example.net.")
    child = await _zone(db_session, grp, "sub.p3.example.")
    await _record(db_session, child, "@", "NS", "ns1.example.net.")
    r = await client.post(_url(child, "/delegate-from-parent"), headers=h)
    assert r.status_code == 201, r.text
    assert await _count(db_session, parent) == 2
