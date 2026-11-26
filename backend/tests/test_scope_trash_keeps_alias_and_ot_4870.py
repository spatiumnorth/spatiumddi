"""#4870: a scope sent to the Trash keeps a reservation's address row when a DNS alias or
an OT descriptor hangs off it, so the restore finds both where they were."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ot import OTDevice
from tests.test_dhcp_static_readdress_live_lease import (
    OLD,
    _group,
    _reservation,
    _row,
    _scope,
    _superadmin_token,
)


async def _setup(db: AsyncSession, *, alias: bool, ot: bool):
    grp, _ = await _group(db, servers=0)
    subnet, scope = await _scope(db, grp)
    await _reservation(db, scope)
    row = await _row(db, subnet, OLD)
    assert row is not None
    row_id = row.id
    if alias:
        dgrp = DNSServerGroup(name=f"dg-{uuid.uuid4().hex[:6]}")
        db.add(dgrp)
        await db.flush()
        z = DNSZone(
            group_id=dgrp.id,
            name="za.example.",
            zone_type="primary",
            kind="forward",
            primary_ns="ns1.example.",
            admin_email="admin.example.",
        )
        db.add(z)
        await db.flush()
        db.add(
            DNSRecord(
                zone_id=z.id,
                name="al1",
                fqdn="al1.za.example.",
                record_type="CNAME",
                value="h1.za.example.",
                auto_generated=True,
                ip_alias=True,
                ip_address_id=row_id,
            )
        )
    if ot:
        db.add(OTDevice(ip_address_id=row_id, ot_protocol="profinet"))
    ids = (subnet, scope.id, row_id)
    await db.commit()
    return ids


@pytest.mark.asyncio
@pytest.mark.parametrize("alias,ot", [(True, False), (False, True)])
async def test_scope_delete_and_restore_keep_alias_and_ot(
    client: AsyncClient, db_session: AsyncSession, alias: bool, ot: bool
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    subnet, scope_id, row_id = await _setup(db_session, alias=alias, ot=ot)
    subnet_id = subnet.id

    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)).status_code == 204
    db_session.expire_all()
    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope_id}/restore", headers=h)
    assert r.status_code == 200, r.text

    db_session.expire_all()
    row = await _row(db_session, await db_session.get(type(subnet), subnet_id), OLD)
    assert row is not None and row.id == row_id and row.static_assignment_id is not None
    if alias:
        recs = (
            (await db_session.execute(select(DNSRecord).where(DNSRecord.ip_alias.is_(True))))
            .scalars()
            .all()
        )
        assert [x.name for x in recs] == ["al1"]
    if ot:
        n = await db_session.execute(select(OTDevice).where(OTDevice.ip_address_id == row_id))
        assert n.scalar_one_or_none() is not None
