"""Copilot ``create_dns_record`` honours the REST zone refusals (#2653).

REST ``create_record`` refuses a zone an integration reconciler owns (it would
overwrite the row on the next sync); the copilot path did not, and apply never
re-checked that the zone had not been trashed since the proposal.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPSpace
from app.models.netbird import NetbirdInstance
from app.services.ai.operations import CreateDNSRecordArgs, get_operation
from app.services.dns.zone_synthesis import synthesised_zone_error


async def _setup(db: AsyncSession) -> tuple[User, DNSZone]:
    u = User(
        username=f"ai-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="AI Writer",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="bind9.example.com",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.flush()
    return u, zone


def _args(zone: DNSZone) -> CreateDNSRecordArgs:
    return CreateDNSRecordArgs(
        zone_id=str(zone.id), name="www", record_type="A", value="192.0.2.10"
    )


@pytest.mark.asyncio
async def test_synthesised_zone_refused_at_preview_and_apply(db_session: AsyncSession) -> None:
    user, zone = await _setup(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    inst = NetbirdInstance(name=f"nb-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id)
    db_session.add(inst)
    await db_session.flush()
    zone.netbird_instance_id = inst.id
    await db_session.commit()

    op = get_operation("create_dns_record")
    assert op is not None
    preview = await op.preview(db_session, user, _args(zone))
    assert not preview.ok and "synthesised" in preview.detail
    with pytest.raises(ValueError, match="synthesised"):
        await op.apply(db_session, user, _args(zone))


@pytest.mark.asyncio
async def test_apply_refuses_zone_trashed_after_proposal(db_session: AsyncSession) -> None:
    user, zone = await _setup(db_session)
    await db_session.commit()
    op = get_operation("create_dns_record")
    assert op is not None
    assert (await op.preview(db_session, user, _args(zone))).ok
    zone.deleted_at = dt.datetime.now(dt.UTC)
    await db_session.commit()
    with pytest.raises(ValueError, match="not found|deleted"):
        await op.apply(db_session, user, _args(zone))


def test_helper_is_none_for_ordinary_zone() -> None:
    z = DNSZone(name="a.", tailscale_tenant_id=None, netbird_instance_id=None)
    assert synthesised_zone_error(z, "edit") is None
