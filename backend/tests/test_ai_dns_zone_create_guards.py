"""Copilot ``create_dns_zone`` refuses what REST ``create_zone`` refuses (#2652).

``uq_dns_zone_group_view_name`` cannot catch a same-name twin when ``view_id``
is NULL (NULLs are distinct), so the existence check is the only guard — and
apply used to skip it, leaving two rows that make BIND refuse the group.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone
from app.services.ai.operations import CreateDNSZoneArgs, get_operation


async def _user(db: AsyncSession) -> User:
    suffix = uuid.uuid4().hex[:8]
    u = User(
        username=f"zg-{suffix}",
        email=f"zg-{suffix}@example.test",
        display_name="Zone Guards",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.commit()
    return u


async def _group(db: AsyncSession) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    return grp


@pytest.mark.asyncio
async def test_apply_refuses_existing_zone(db_session: AsyncSession) -> None:
    user = await _user(db_session)
    grp = await _group(db_session)
    name = f"z{uuid.uuid4().hex[:6]}.example.com"
    op = get_operation("create_dns_zone")
    assert op is not None
    args = CreateDNSZoneArgs(name=name, group_id=str(grp.id))

    await op.apply(db_session, user, args)
    # The twin the preview of the SECOND proposal never saw (proposed before the
    # first applied) — apply must refuse it.
    with pytest.raises(ValueError, match="already exists"):
        await op.apply(db_session, user, args)

    count = (
        await db_session.execute(
            select(func.count()).select_from(DNSZone).where(DNSZone.group_id == grp.id)
        )
    ).scalar_one()
    assert count == 1
    preview = await op.preview(db_session, user, args)
    assert not preview.ok and "already exists" in preview.detail


@pytest.mark.asyncio
async def test_admin_email_validated_at_preview_and_apply(db_session: AsyncSession) -> None:
    # primary_ns is already host-name-validated by the args model; admin_email
    # (interpolated raw into the SOA line) was not, and REST rejects it.
    field, value = "admin_email", "a b;c.example.com."
    user = await _user(db_session)
    grp = await _group(db_session)
    op = get_operation("create_dns_zone")
    assert op is not None
    args = CreateDNSZoneArgs(
        name=f"z{uuid.uuid4().hex[:6]}.example.com", group_id=str(grp.id), **{field: value}
    )
    preview = await op.preview(db_session, user, args)
    assert not preview.ok and field in preview.detail
    with pytest.raises(ValueError, match=field):
        await op.apply(db_session, user, args)
