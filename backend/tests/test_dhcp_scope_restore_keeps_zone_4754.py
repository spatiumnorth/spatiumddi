"""#4754: a DHCP scope restored from the Trash puts each reservation back in the DNS zones
its address was published into, not in the subnet's zone."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress
from tests.test_dhcp_static_readdress_live_lease import (
    OLD,
    _group,
    _reservation,
    _row,
    _scope,
    _superadmin_token,
)


async def _zone(db: AsyncSession, grp: DNSServerGroup, tag: str) -> DNSZone:
    z = DNSZone(
        group_id=grp.id,
        name=f"{tag}-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(z)
    await db.flush()
    return z


async def _setup(db: AsyncSession, *, extra: bool = False):
    dgrp = DNSServerGroup(name=f"dg-{uuid.uuid4().hex[:6]}")
    db.add(dgrp)
    await db.flush()
    db.add(DNSServer(group_id=dgrp.id, driver="bind9", host="10.9.9.9", name="ns1"))
    za = await _zone(db, dgrp, "za")
    zb = await _zone(db, dgrp, "zb")
    zc = await _zone(db, dgrp, "zc")
    grp, _ = await _group(db, servers=0)
    subnet, scope = await _scope(db, grp)
    subnet.dns_inherit_settings = False
    subnet.dns_group_ids = [str(dgrp.id)]
    subnet.dns_zone_id = str(za.id)
    await _reservation(db, scope)
    row = await _row(db, subnet, OLD)
    assert row is not None
    row.forward_zone_id = zb.id
    row.extra_zone_ids = [str(zc.id)] if extra else []
    await db.flush()
    # What the zone select of Edit does: re-home the host out of the subnet's zone.
    await _sync_dns_record(db, row, subnet, zone_id=zb.id, action="update")
    await db.commit()
    return subnet, scope, zb, zc


async def _zones_of(db: AsyncSession, row_id) -> set[uuid.UUID]:
    res = await db.execute(
        select(DNSRecord.zone_id)
        .where(DNSRecord.ip_address_id == row_id, DNSRecord.record_type == "A")
        .execution_options(populate_existing=True)
    )
    return set(res.scalars().all())


@pytest.mark.asyncio
async def test_restore_puts_the_reservation_back_in_its_own_and_extra_zones(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    subnet, scope, zb, zc = await _setup(db_session, extra=True)
    scope_id, subnet_id, zb_id, zc_id = scope.id, subnet.id, zb.id, zc.id

    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)
    assert r.status_code == 204, r.text
    await db_session.commit()  # the restore is its own transaction
    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope_id}/restore", headers=h)
    assert r.status_code == 200, r.text
    warnings = r.json().get("warnings")

    db_session.expire_all()
    row = (
        await db_session.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet_id, IPAddress.address == OLD)
        )
    ).scalar_one()
    assert row.forward_zone_id == zb_id
    assert row.extra_zone_ids == [str(zc_id)]
    assert await _zones_of(db_session, row.id) == {zb_id, zc_id}
    assert warnings == []


@pytest.mark.asyncio
async def test_restore_falls_back_with_a_warning_when_the_zone_is_gone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    subnet, scope, zb, _zc = await _setup(db_session)
    scope_id, subnet_id, zb_id = scope.id, subnet.id, zb.id

    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)
    assert r.status_code == 204, r.text
    await db_session.commit()  # the restore is its own transaction
    zone = await db_session.get(DNSZone, zb.id)
    assert zone is not None
    zone.deleted_at = datetime.now(UTC)
    await db_session.commit()

    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope_id}/restore", headers=h)
    assert r.status_code == 200, r.text
    assert len(r.json()["warnings"]) == 1
    assert OLD in r.json()["warnings"][0]

    db_session.expire_all()
    row = (
        await db_session.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet_id, IPAddress.address == OLD)
        )
    ).scalar_one()
    assert row.forward_zone_id != zb_id


@pytest.mark.asyncio
async def test_restore_of_a_snapshot_from_an_older_build_and_a_duplicate_extra_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.dhcp import DHCPStaticAssignment

    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    subnet, scope, zb, _zc = await _setup(db_session)
    scope_id, subnet_id, zb_id = scope.id, subnet.id, zb.id

    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)
    assert r.status_code == 204, r.text
    await db_session.commit()
    st = (
        await db_session.execute(
            select(DHCPStaticAssignment)
            .where(DHCPStaticAssignment.scope_id == scope_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    snap = dict(st.ipam_metadata_snapshot or {})
    assert snap.get("forward_zone_id") == str(zb_id)
    # A snapshot a 1.0.1 build wrote has neither zone key.
    st.ipam_metadata_snapshot = {
        k: v for k, v in snap.items() if k not in ("forward_zone_id", "extra_zone_ids")
    } or None
    await db_session.commit()

    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope_id}/restore", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["warnings"] == []
    db_session.expire_all()
    row = (
        await db_session.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet_id, IPAddress.address == OLD)
        )
    ).scalar_one()
    assert row.forward_zone_id != zb_id  # the subnet's zone, as before this fix
    assert row.extra_zone_ids == []

    # An extra zone equal to the primary zone is not kept twice.
    from app.services.dhcp.static_ipam import _restore_zone_binding

    row.forward_zone_id = None
    await _restore_zone_binding(
        db_session,
        row,
        await db_session.get(type(subnet), subnet_id),
        {"forward_zone_id": str(zb_id), "extra_zone_ids": [str(zb_id)]},
        [],
    )
    assert row.forward_zone_id == zb_id
    assert row.extra_zone_ids == []
