"""Soft-delete + 30-day recovery tests for IPAM / DNS / DHCP rows.

Covers:
  * Cascade soft-delete (IPSpace → IPBlock → Subnet → DHCPScope)
  * The global query filter hides soft-deleted rows from default SELECTs
  * Restore by batch brings every cascaded row back atomically
  * Conflict on restore returns 409 with structured ``conflicts[]``
  * ``?permanent=true`` runs the legacy hard-delete path
  * Trash list endpoint surfaces soft-deleted rows
  * Purge sweep hard-deletes rows older than the retention window
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.settings import PlatformSettings


async def _make_admin(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"sd-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Soft-Delete Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


# ── IPAM cascade soft-delete ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_soft_delete_ip_space_cascades(client: AsyncClient, db_session: AsyncSession) -> None:
    """Deleting an IPSpace soft-deletes every block + subnet under it
    with the same deletion_batch_id."""
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    space = IPSpace(name=f"sd-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()

    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db_session.add(block)
    await db_session.flush()

    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.0.0.0/24",
        name="lan",
    )
    db_session.add(subnet)
    await db_session.flush()
    await db_session.commit()

    resp = await client.delete(f"/api/v1/ipam/spaces/{space.id}", headers=headers)
    assert resp.status_code == 204, resp.text

    # Default SELECTs hide them.
    list_res = await client.get("/api/v1/ipam/spaces", headers=headers)
    assert list_res.status_code == 200
    assert all(s["id"] != str(space.id) for s in list_res.json())

    # Direct DB checks (with include_deleted) — every row stamped with
    # the same batch UUID.
    space_row = (
        await db_session.execute(
            select(IPSpace).where(IPSpace.id == space.id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert space_row.deleted_at is not None
    assert space_row.deletion_batch_id is not None

    block_row = (
        await db_session.execute(
            select(IPBlock).where(IPBlock.id == block.id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert block_row.deleted_at is not None
    assert block_row.deletion_batch_id == space_row.deletion_batch_id

    subnet_row = (
        await db_session.execute(
            select(Subnet).where(Subnet.id == subnet.id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert subnet_row.deleted_at is not None
    assert subnet_row.deletion_batch_id == space_row.deletion_batch_id


@pytest.mark.asyncio
async def test_global_query_filter_hides_soft_deleted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A row with deleted_at IS NOT NULL is invisible to default queries."""
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    space = IPSpace(
        name=f"sd-{uuid.uuid4().hex[:6]}",
        description="",
        deleted_at=datetime.now(UTC),
        deletion_batch_id=uuid.uuid4(),
    )
    db_session.add(space)
    await db_session.flush()
    await db_session.commit()

    list_res = await client.get("/api/v1/ipam/spaces", headers=headers)
    assert list_res.status_code == 200
    assert all(s["id"] != str(space.id) for s in list_res.json())


@pytest.mark.asyncio
async def test_restore_batch_atomic(client: AsyncClient, db_session: AsyncSession) -> None:
    """Restore brings every batch sibling back in one transaction."""
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    space = IPSpace(name=f"sd-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="172.16.0.0/12", name="root")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="172.16.1.0/24", name="lan")
    db_session.add(subnet)
    await db_session.flush()
    await db_session.commit()

    # Cascade soft-delete via the API.
    del_res = await client.delete(f"/api/v1/ipam/spaces/{space.id}", headers=headers)
    assert del_res.status_code == 204

    # Restore the space — block + subnet should come along for the ride.
    restore_res = await client.post(
        f"/api/v1/admin/trash/ip_space/{space.id}/restore", headers=headers
    )
    assert restore_res.status_code == 200, restore_res.text
    body = restore_res.json()
    # 3 rows in the batch: space + block + subnet
    assert body["restored"] == 3

    # Confirm the rows are live again via the default API.
    list_res = await client.get("/api/v1/ipam/spaces", headers=headers)
    assert any(s["id"] == str(space.id) for s in list_res.json())


@pytest.mark.asyncio
async def test_restore_conflict_409(client: AsyncClient, db_session: AsyncSession) -> None:
    """Restoring a batch whose head row would clash returns 409.

    Tested via DNSZone: a live zone of the same name in the same group
    (the partial ``uq_dns_zone_group_view_name`` index covers live rows
    only, #3824) is what the restore conflict check flags.
    """
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    group1 = DNSServerGroup(name=f"sd-{uuid.uuid4().hex[:6]}")
    db_session.add(group1)
    await db_session.flush()

    zone = DNSZone(
        group_id=group1.id,
        name="conflict.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.conflict.test.",
        admin_email="admin.conflict.test.",
    )
    db_session.add(zone)
    await db_session.flush()
    await db_session.commit()

    # Soft-delete via API.
    resp = await client.delete(f"/api/v1/dns/groups/{group1.id}/zones/{zone.id}", headers=headers)
    assert resp.status_code == 204

    # Create an active zone with the same name in the SAME group — the
    # constraint allows this because the soft-deleted zone is still in
    # the row but the unique partial-index path (which we'd want long
    # term) isn't yet there. Instead we simulate a conflict by editing
    # the zone's record_signature manually: just create a live zone in
    # the same group with the same name but the soft-deleted row is
    # still occupying the slot from the constraint's perspective —
    # that's the real product issue and we don't fix it here, so this
    # test demonstrates the conflict_check path explicitly using a
    # live row already present.
    live = DNSZone(
        group_id=group1.id,
        name="other.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.other.test.",
        admin_email="admin.other.test.",
    )
    db_session.add(live)
    await db_session.flush()

    # Manually rewrite the soft-deleted row to clash with `live`.
    sd_row = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == zone.id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    sd_row.name = "other.test."
    await db_session.flush()
    await db_session.commit()

    # Restore should now flag the conflict.
    restore_res = await client.post(
        f"/api/v1/admin/trash/dns_zone/{sd_row.id}/restore", headers=headers
    )
    assert restore_res.status_code == 409, restore_res.text
    detail = restore_res.json()["detail"]
    assert "conflicts" in detail
    assert any(c["type"] == "dns_zone" for c in detail["conflicts"])


# ── Permanent delete bypass ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_permanent_delete_hard_removes_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``?permanent=true`` runs the legacy hard-delete code path."""
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    space = IPSpace(name=f"sd-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    await db_session.commit()

    resp = await client.delete(f"/api/v1/ipam/spaces/{space.id}?permanent=true", headers=headers)
    assert resp.status_code == 204, resp.text

    # Even include_deleted shouldn't find the row.
    res = await db_session.execute(
        select(IPSpace).where(IPSpace.id == space.id).execution_options(include_deleted=True)
    )
    assert res.scalar_one_or_none() is None


# ── Trash list ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trash_list_surface(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    space = IPSpace(name=f"sd-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    await db_session.commit()

    del_res = await client.delete(f"/api/v1/ipam/spaces/{space.id}", headers=headers)
    assert del_res.status_code == 204

    list_res = await client.get("/api/v1/admin/trash", headers=headers)
    assert list_res.status_code == 200, list_res.text
    body = list_res.json()
    assert body["total"] >= 1
    matched = [item for item in body["items"] if item["id"] == str(space.id)]
    assert matched
    entry = matched[0]
    assert entry["type"] == "ip_space"
    assert entry["batch_size"] == 1


@pytest.mark.asyncio
async def test_trash_list_filter_by_type(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    space = IPSpace(name=f"sd-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    await db_session.commit()

    await client.delete(f"/api/v1/ipam/spaces/{space.id}", headers=headers)

    res = await client.get("/api/v1/admin/trash?type=dns_zone", headers=headers)
    assert res.status_code == 200
    assert all(item["type"] == "dns_zone" for item in res.json()["items"])
    assert all(item["id"] != str(space.id) for item in res.json()["items"])


# ── DNS zone soft-delete ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dns_zone_soft_delete_cascades_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    group = DNSServerGroup(name=f"sd-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()

    zone = DNSZone(
        group_id=group.id,
        name="example.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db_session.add(zone)
    await db_session.flush()

    record = DNSRecord(
        zone_id=zone.id,
        name="www",
        fqdn="www.example.test.",
        record_type="A",
        value="192.0.2.1",
    )
    db_session.add(record)
    await db_session.flush()
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dns/groups/{group.id}/zones/{zone.id}", headers=headers)
    assert resp.status_code == 204, resp.text

    # Default SELECT hides them.
    list_res = await client.get(f"/api/v1/dns/groups/{group.id}/zones", headers=headers)
    assert list_res.status_code == 200
    assert all(z["id"] != str(zone.id) for z in list_res.json())

    # Both rows share the same deletion_batch_id.
    zone_row = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == zone.id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    rec_row = (
        await db_session.execute(
            select(DNSRecord)
            .where(DNSRecord.id == record.id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert zone_row.deleted_at is not None
    assert rec_row.deleted_at is not None
    assert zone_row.deletion_batch_id == rec_row.deletion_batch_id


# ── Purge sweep ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_sweep_removes_aged_rows(db_session: AsyncSession) -> None:
    """Soft-deleted rows older than the retention window are hard-deleted."""

    # Default purge_days = 30. Stamp a row's deleted_at as 31 days ago.
    space = IPSpace(
        name=f"sd-{uuid.uuid4().hex[:6]}",
        description="",
        deleted_at=datetime.now(UTC) - timedelta(days=31),
        deletion_batch_id=uuid.uuid4(),
    )
    db_session.add(space)
    await db_session.flush()
    await db_session.commit()

    # Run the sweep directly (the celery task wraps asyncio.run; call the
    # async helper instead to avoid spinning up a second loop).
    from app.tasks.trash_purge import _sweep

    result = await _sweep()

    # Use include_deleted to confirm hard-delete actually happened.
    res = await db_session.execute(
        select(IPSpace).where(IPSpace.id == space.id).execution_options(include_deleted=True)
    )
    assert res.scalar_one_or_none() is None
    assert result["removed"] >= 1
    assert result["per_type"]["ip_space"] >= 1


@pytest.mark.asyncio
async def test_purge_sweep_disabled_when_zero(db_session: AsyncSession) -> None:
    """purge_days=0 disables the sweep entirely."""

    ps = (await db_session.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.soft_delete_purge_days = 0
    await db_session.flush()
    await db_session.commit()

    space = IPSpace(
        name=f"sd-{uuid.uuid4().hex[:6]}",
        description="",
        deleted_at=datetime.now(UTC) - timedelta(days=365),
        deletion_batch_id=uuid.uuid4(),
    )
    db_session.add(space)
    await db_session.flush()
    await db_session.commit()

    from app.tasks.trash_purge import _sweep

    result = await _sweep()
    assert result["skipped"] is True
    assert result["removed"] == 0

    # Row still exists.
    res = await db_session.execute(
        select(IPSpace).where(IPSpace.id == space.id).execution_options(include_deleted=True)
    )
    assert res.scalar_one_or_none() is not None


# ── DHCP scope soft-delete ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dhcp_scope_soft_delete(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_admin(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    space = IPSpace(name=f"sd-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.0.5.0/24", name="lan")
    db_session.add(subnet)
    await db_session.flush()

    group = DHCPServerGroup(name=f"sd-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()

    server = DHCPServer(
        name=f"sd-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        server_group_id=group.id,
    )
    db_session.add(server)
    await db_session.flush()

    scope = DHCPScope(
        group_id=group.id,
        subnet_id=subnet.id,
        name="test-scope",
        address_family="ipv4",
    )
    db_session.add(scope)
    await db_session.flush()
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=headers)
    assert resp.status_code == 204, resp.text

    # ``DHCPScope`` has joined-eager-load relationships (pools / statics) so
    # the result needs ``.unique()`` before scalar_one().
    result = await db_session.execute(
        select(DHCPScope).where(DHCPScope.id == scope.id).execution_options(include_deleted=True)
    )
    scope_row = result.unique().scalar_one()
    assert scope_row.deleted_at is not None
    assert scope_row.deletion_batch_id is not None
