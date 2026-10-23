"""Sites: sibling-code uniqueness must not block code-less siblings (#279 bug).

The unique index over ``(parent_site_id, code)`` uses ``NULLS NOT
DISTINCT`` so two top-level sites can't share a *code*. The bug: that
flag also made the optional ``code`` column's NULLs/empties compare
equal, so a second code-less top-level site 409'd with "a sibling site
with this code already exists" despite having no code. The fix makes the
index partial (``WHERE code IS NOT NULL``) and normalises ``""`` → NULL.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User


async def _admin(db: AsyncSession) -> dict[str, str]:
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


@pytest.mark.asyncio
async def test_two_codeless_top_level_sites_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reported bug: a second top-level site with no code must work."""
    h = await _admin(db_session)
    r1 = await client.post("/api/v1/sites", json={"name": "HQ"}, headers=h)
    assert r1.status_code == 201, r1.text
    r2 = await client.post("/api/v1/sites", json={"name": "Branch"}, headers=h)
    assert r2.status_code == 201, r2.text


@pytest.mark.asyncio
async def test_empty_string_code_normalised_to_null(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An empty/whitespace code is stored as NULL, and two such siblings
    don't collide."""
    h = await _admin(db_session)
    r1 = await client.post("/api/v1/sites", json={"name": "A", "code": "   "}, headers=h)
    assert r1.status_code == 201, r1.text
    assert r1.json()["code"] is None
    r2 = await client.post("/api/v1/sites", json={"name": "B", "code": ""}, headers=h)
    assert r2.status_code == 201, r2.text
    assert r2.json()["code"] is None


@pytest.mark.asyncio
async def test_duplicate_nonnull_top_level_code_still_blocked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Real codes stay unique among top-level sites — the intended rule."""
    h = await _admin(db_session)
    r1 = await client.post("/api/v1/sites", json={"name": "East", "code": "DC-1"}, headers=h)
    assert r1.status_code == 201, r1.text
    r2 = await client.post("/api/v1/sites", json={"name": "West", "code": "DC-1"}, headers=h)
    assert r2.status_code == 409, r2.text


@pytest.mark.asyncio
async def test_same_code_under_different_parents_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``F1`` under campus A and ``F1`` under campus B don't collide."""
    h = await _admin(db_session)
    a = await client.post("/api/v1/sites", json={"name": "Campus A"}, headers=h)
    b = await client.post("/api/v1/sites", json={"name": "Campus B"}, headers=h)
    a_id, b_id = a.json()["id"], b.json()["id"]
    fa = await client.post(
        "/api/v1/sites",
        json={"name": "Floor 1", "code": "F1", "parent_site_id": a_id},
        headers=h,
    )
    assert fa.status_code == 201, fa.text
    fb = await client.post(
        "/api/v1/sites",
        json={"name": "Floor 1", "code": "F1", "parent_site_id": b_id},
        headers=h,
    )
    assert fb.status_code == 201, fb.text


async def _site_with_default_binding(db: AsyncSession, name: str):
    from app.models.e911 import EmergencyResponseLocation, ERLBinding
    from app.models.ownership import Site

    site = Site(name=name, kind="datacenter")
    erl = EmergencyResponseLocation(name=f"erl-{name}", country="US", a1="NY", rd="Broadway")
    db.add_all([site, erl])
    await db.flush()
    db.add(ERLBinding(erl_id=erl.id, rule_kind="site_default", site_id=site.id))
    await db.flush()
    return site


@pytest.mark.asyncio
async def test_site_with_e911_default_binding_cannot_be_deleted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2298: the binding is ON DELETE CASCADE; the delete must be refused, not cascade."""
    from sqlalchemy import func, select

    from app.models.e911 import ERLBinding

    h = await _admin(db_session)
    site = await _site_with_default_binding(db_session, "HQ-e911")
    r = await client.delete(f"/api/v1/sites/{site.id}", headers=h)
    assert r.status_code == 409, r.text
    assert "HQ-e911" in r.json()["detail"] and "erl-HQ-e911" in r.json()["detail"]
    assert (await client.get(f"/api/v1/sites/{site.id}", headers=h)).status_code == 200
    n = (
        await db_session.execute(
            select(func.count()).select_from(ERLBinding).where(ERLBinding.site_id == site.id)
        )
    ).scalar_one()
    assert n == 1


@pytest.mark.asyncio
async def test_bulk_delete_refused_whole_when_any_site_is_e911_bound(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    bound = await _site_with_default_binding(db_session, "bound-site")
    plain = (await client.post("/api/v1/sites", json={"name": "plain-site"}, headers=h)).json()
    r = await client.post(
        "/api/v1/sites/bulk-delete", json={"ids": [str(bound.id), plain["id"]]}, headers=h
    )
    assert r.status_code == 409, r.text
    assert "bound-site" in r.json()["detail"]
    assert (await client.get(f"/api/v1/sites/{plain['id']}", headers=h)).status_code == 200


@pytest.mark.asyncio
async def test_site_deletes_after_binding_removed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from sqlalchemy import delete

    from app.models.e911 import ERLBinding

    h = await _admin(db_session)
    site = await _site_with_default_binding(db_session, "later")
    await db_session.execute(delete(ERLBinding).where(ERLBinding.site_id == site.id))
    await db_session.flush()
    r = await client.delete(f"/api/v1/sites/{site.id}", headers=h)
    assert r.status_code == 204, r.text
