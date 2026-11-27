"""The Trash's "Delete permanently" goes through the approval gate.

``DELETE /admin/trash/{type}/{id}`` is a permanent delete, so an enabled
``delete`` policy on the row's type queues a change request (202) instead of
removing the row, and approving the request performs the hard delete.
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
from app.models.feature_module import FeatureModule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import feature_modules


async def _superadmin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"sa-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Superadmin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _module(db: AsyncSession, enabled: bool) -> None:
    db.add(FeatureModule(id="governance.approvals", enabled=enabled))
    await db.flush()
    feature_modules.invalidate_cache()


async def _policy(db: AsyncSession, resource_type: str, *, applies_to_superadmin: bool) -> None:
    db.add(
        ApprovalPolicy(
            name=f"delete:{resource_type}",
            resource_type=resource_type,
            action="delete",
            min_count=None,
            enabled=True,
            applies_to_superadmin=applies_to_superadmin,
            ttl_hours=168,
            is_builtin=True,
        )
    )
    await db.flush()


async def _trashed(db: AsyncSession, kind: str) -> tuple[type, uuid.UUID]:
    """A trashed row of ``kind``, stamped directly (the soft delete itself is
    not what is under test)."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.77.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    now = datetime.now(UTC)
    if kind == "subnet":
        subnet.deleted_at = now
        row: IPBlock | Subnet = subnet
    else:
        # A trashed block takes its trashed subnet with it.
        subnet.deleted_at = now
        block.deleted_at = now
        row = block
    await db.flush()
    return type(row), row.id


async def _exists(db: AsyncSession, model: type, row_id: uuid.UUID) -> bool:
    db.expire_all()
    stmt = (
        select(func.count())
        .select_from(model)
        .where(model.id == row_id)  # type: ignore[attr-defined]
        .execution_options(include_deleted=True)
    )
    return (await db.execute(stmt)).scalar_one() == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["subnet", "ip_block"])
async def test_trash_purge_queues_then_approval_deletes(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    await _module(db_session, True)
    await _policy(db_session, kind, applies_to_superadmin=True)
    model, row_id = await _trashed(db_session, kind)
    _, requester = await _superadmin(db_session)
    _, approver = await _superadmin(db_session)

    r = await client.delete(f"/api/v1/admin/trash/{kind}/{row_id}", headers=requester)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["state"] == "pending"
    assert "Permanently delete" in body["preview_text"]
    assert await _exists(db_session, model, row_id)
    cr = await db_session.get(ChangeRequest, uuid.UUID(body["change_request_id"]))
    assert cr is not None and cr.resource_id == str(row_id)

    r2 = await client.post(
        f"/api/v1/change-requests/{body['change_request_id']}/approve",
        headers=approver,
        json={},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["state"] == "executed"
    assert not await _exists(db_session, model, row_id)


@pytest.mark.asyncio
async def test_trash_purge_inline_when_policy_exempts_superadmin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _module(db_session, True)
    await _policy(db_session, "subnet", applies_to_superadmin=False)
    model, row_id = await _trashed(db_session, "subnet")
    _, h = await _superadmin(db_session)

    r = await client.delete(f"/api/v1/admin/trash/subnet/{row_id}", headers=h)
    assert r.status_code == 204, r.text
    assert not await _exists(db_session, model, row_id)


@pytest.mark.asyncio
async def test_trash_purge_inline_when_module_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _module(db_session, False)
    await _policy(db_session, "subnet", applies_to_superadmin=True)
    model, row_id = await _trashed(db_session, "subnet")
    _, h = await _superadmin(db_session)

    r = await client.delete(f"/api/v1/admin/trash/subnet/{row_id}", headers=h)
    assert r.status_code == 204, r.text
    assert not await _exists(db_session, model, row_id)
    n = (await db_session.execute(select(func.count(ChangeRequest.id)))).scalar_one()
    assert n == 0


@pytest.mark.asyncio
async def test_trash_purge_unknown_row_is_404_not_queued(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _module(db_session, True)
    await _policy(db_session, "subnet", applies_to_superadmin=True)
    _, h = await _superadmin(db_session)

    r = await client.delete(f"/api/v1/admin/trash/subnet/{uuid.uuid4()}", headers=h)
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_approval_after_restore_does_not_delete_live_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A request queued while the row was trashed must not hard-delete it once
    the row has been restored in the meantime."""
    await _module(db_session, True)
    await _policy(db_session, "subnet", applies_to_superadmin=True)
    model, row_id = await _trashed(db_session, "subnet")
    _, requester = await _superadmin(db_session)
    _, approver = await _superadmin(db_session)

    r = await client.delete(f"/api/v1/admin/trash/subnet/{row_id}", headers=requester)
    assert r.status_code == 202, r.text
    cr_id = r.json()["change_request_id"]

    row = await db_session.get(Subnet, row_id, execution_options={"include_deleted": True})
    assert row is not None
    row.deleted_at = None  # restored from the Trash
    await db_session.commit()

    r2 = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=approver, json={})
    assert r2.status_code != 200 or r2.json()["state"] != "executed", r2.text
    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id), populate_existing=True)
    assert cr is not None and cr.state == "failed"
    assert await _exists(db_session, model, row_id)
    live = await db_session.get(Subnet, row_id)
    assert live is not None and live.deleted_at is None
