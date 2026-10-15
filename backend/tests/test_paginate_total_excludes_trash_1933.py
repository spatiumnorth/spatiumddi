"""#1933 — a paginated list's ``total`` must not count rows in Trash.

``paginate`` counts through ``select(count()).select_from(base.subquery())``;
the soft-delete filter did not see the entities inside that subquery, so the
page query was filtered and the count was not.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.pagination import paginate
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone


async def _headers(db: AsyncSession) -> dict[str, str]:
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


async def _seed(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="trash.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.trash.example.",
        admin_email="admin.trash.example.",
    )
    db.add(zone)
    await db.flush()
    for i in range(10):
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=f"h{i}",
                fqdn=f"h{i}.trash.example.",
                record_type="A",
                value=f"10.0.0.{i + 1}",
                deleted_at=datetime.now(UTC) if i < 4 else None,
            )
        )
    await db.flush()
    return grp, zone


@pytest.mark.asyncio
async def test_zone_records_total_excludes_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone = await _seed(db_session)
    r = await client.get(f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 6
    assert body["total"] == 6


@pytest.mark.asyncio
async def test_group_records_total_excludes_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, _ = await _seed(db_session)
    r = await client.get(f"/api/v1/dns/groups/{grp.id}/records", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == len(body["items"]) == 6


@pytest.mark.asyncio
async def test_paginate_helper_total_excludes_trash(db_session: AsyncSession) -> None:
    _, zone = await _seed(db_session)
    rows, total = await paginate(
        db_session, select(DNSRecord).where(DNSRecord.zone_id == zone.id), page=1, page_size=3
    )
    assert len(rows) == 3
    assert total == 6


@pytest.mark.asyncio
async def test_nested_subquery_count_is_filtered_and_opt_out_still_sees_trash(
    db_session: AsyncSession,
) -> None:
    """The filter lands inside a subquery however deep it is nested, and a
    statement that opts out with ``include_deleted`` still counts the trashed
    rows: Trash, restore and purge depend on that."""
    _, zone = await _seed(db_session)
    inner = select(DNSRecord.id).where(DNSRecord.zone_id == zone.id).subquery()
    nested = select(func.count()).select_from(select(inner.c.id).subquery())
    assert (await db_session.execute(nested)).scalar_one() == 6
    opted_out = nested.execution_options(include_deleted=True)
    assert (await db_session.execute(opted_out)).scalar_one() == 10
