"""Adding / removing a DNSSEC trust anchor writes an audit row (#2299)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from tests.test_dns_trust_anchors_2266 import _anchor, _group, _superadmin


async def _rows(db: AsyncSession, action: str) -> list[AuditLog]:
    db.expire_all()
    res = await db.execute(
        select(AuditLog).where(
            AuditLog.resource_type == "dns_trust_anchor", AuditLog.action == action
        )
    )
    return list(res.scalars())


@pytest.mark.asyncio
async def test_add_and_delete_each_write_one_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    group_id = str(group.id)
    url = f"/api/v1/dns/groups/{group_id}/options/trust-anchors"

    r = await client.post(url, json=_anchor(), headers=headers)
    assert r.status_code == 201, r.text
    anchor_id = r.json()["id"]

    created = await _rows(db_session, "create")
    assert len(created) == 1
    row = created[0]
    assert row.resource_id == anchor_id
    assert row.result == "success"
    assert row.new_value["zone_name"] == "."
    assert row.new_value["key_tag"] == 20326
    assert row.new_value["algorithm"] == 8
    assert row.new_value["group_id"] == group_id

    r = await client.delete(f"{url}/{anchor_id}", headers=headers)
    assert r.status_code == 204, r.text
    deleted = await _rows(db_session, "delete")
    assert len(deleted) == 1
    assert deleted[0].resource_id == anchor_id
    assert deleted[0].old_value["key_tag"] == 20326


@pytest.mark.asyncio
async def test_refused_delete_writes_no_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options/trust-anchors/{group.id}"
    r = await client.delete(url, headers=headers)
    assert r.status_code == 404
    assert await _rows(db_session, "delete") == []
