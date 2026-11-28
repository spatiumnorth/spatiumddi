"""spatiumddi#5005: a permanent zone delete's preview counts the zone's records
that sit in the Trash.

The delete removes them through the foreign-key cascade, but the soft-delete
filter hid them from the preview's count, so the approver was told too few and
a trashed record added after the request could not make the approval refuse.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.change_request import ApprovalPolicy, ChangeRequest
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.services.ai.operations_risky import DeleteZoneArgs, _preview_delete_zone

ZONE = "t5005.example.test."


async def _superadmin(db: AsyncSession, name: str) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{name}-{uuid.uuid4().hex[:8]}@example.test",
        display_name=name,
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _record(zone: DNSZone, name: str, *, trashed: bool = False) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{ZONE}",
        record_type="A",
        value="192.0.2.1",
        deleted_at=datetime.now(UTC) if trashed else None,
        deletion_batch_id=uuid.uuid4() if trashed else None,
    )


async def _zone(db: AsyncSession) -> DNSZone:
    group = DNSServerGroup(name=f"g5005-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    zone = DNSZone(
        group_id=group.id,
        name=ZONE,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db.add(zone)
    await db.flush()
    db.add_all([_record(zone, f"live{i}") for i in range(3)])
    db.add_all([_record(zone, f"gone{i}", trashed=True) for i in range(2)])
    await db.flush()
    return zone


def _path(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}?permanent=true"


@pytest.mark.asyncio
async def test_permanent_delete_preview_counts_trashed_records(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session, "z5005")
    zone = await _zone(db_session)
    preview = await _preview_delete_zone(
        db_session, user, DeleteZoneArgs(group_id=zone.group_id, zone_id=zone.id, permanent=True)
    )
    assert preview.ok, preview.detail
    assert "cascades 5 DNS record(s) (2 of them in the Trash)" in preview.preview_text


@pytest.mark.asyncio
async def test_approval_preview_counts_trashed_and_catches_drift(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    zone = await _zone(db_session)
    db_session.add(
        ApprovalPolicy(
            name="delete:dns_zone",
            resource_type="dns_zone",
            action="delete",
            min_count=None,
            enabled=True,
            applies_to_superadmin=True,
            ttl_hours=168,
            is_builtin=False,
        )
    )
    _, requester = await _superadmin(db_session, "z5005-req")
    _, approver = await _superadmin(db_session, "z5005-app")
    await db_session.flush()
    resp = await client.delete(_path(zone), headers=requester)
    assert resp.status_code == 202, resp.text
    cr_id = resp.json()["change_request_id"]
    assert "cascades 5 DNS record(s) (2 of them in the Trash)" in resp.json()["preview_text"]

    # A third record lands in the Trash after the request.
    db_session.add(_record(zone, "gone-late", trashed=True))
    await db_session.commit()

    resp = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=approver, json={})
    assert resp.status_code == 409, resp.text
    assert "scope changed" in resp.json()["detail"].lower()
    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None and cr.state == "pending"
    total = (
        await db_session.execute(
            select(func.count(DNSRecord.id))
            .where(DNSRecord.zone_id == zone.id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert total == 6
