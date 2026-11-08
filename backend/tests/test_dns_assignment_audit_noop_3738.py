"""#3738 - saving an unchanged blocklist scope / zone ACL audits nothing."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import DNSBlockList, DNSServerGroup
from tests.test_dns_dynamic_update_acl import _bind9_group_zone_key, _superadmin

pytestmark = pytest.mark.asyncio


async def _rows(db: AsyncSession, rtype: str) -> list[AuditLog]:
    db.expire_all()
    return list(
        (await db.execute(select(AuditLog).where(AuditLog.resource_type == rtype))).scalars().all()
    )


async def test_blocklist_scope_audits_only_changes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _superadmin(db_session)
    g1 = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    g2 = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    bl = DNSBlockList(name=f"bl-{uuid.uuid4().hex[:6]}", category="custom", source_type="manual")
    db_session.add_all([g1, g2, bl])
    await db_session.commit()
    url = f"/api/v1/dns/blocklists/{bl.id}/assignments"
    id1, id2 = str(g1.id), str(g2.id)

    r = await client.put(url, headers=headers, json={"server_group_ids": [id1]})
    assert r.status_code == 200, r.text
    rows = await _rows(db_session, "dns_blocklist_assignment")
    assert [x.changed_fields for x in rows] == [["server_group_ids"]]

    # Same set, resent with view_ids empty: nothing changed.
    r = await client.put(url, headers=headers, json={"server_group_ids": [id1], "view_ids": []})
    assert r.status_code == 200, r.text
    assert len(await _rows(db_session, "dns_blocklist_assignment")) == 1

    r = await client.put(
        url, headers=headers, json={"server_group_ids": [id1, id2], "view_ids": []}
    )
    assert r.status_code == 200
    rows = await _rows(db_session, "dns_blocklist_assignment")
    assert len(rows) == 2
    assert sorted(x.changed_fields for x in rows)[1] == ["server_group_ids"]


async def test_zone_acl_audits_only_changed_field(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _superadmin(db_session)
    group, zone, key = await _bind9_group_zone_key(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl"
    entry = {"match_kind": "tsig_key", "action": "grant", "tsig_key_id": str(key.id)}

    r = await client.put(
        url, headers=headers, json={"dynamic_update_enabled": True, "entries": [entry]}
    )
    assert r.status_code == 200, r.text
    rows = await _rows(db_session, "dns_zone")
    assert sorted(rows[-1].changed_fields) == ["dynamic_update_enabled", "update_acl"]
    n = len(rows)

    # Identical save: no audit row, still 200 with the current object.
    r = await client.put(
        url, headers=headers, json={"dynamic_update_enabled": True, "entries": [entry]}
    )
    assert r.status_code == 200 and r.json()["dynamic_update_enabled"] is True
    assert len(r.json()["entries"]) == 1
    assert len(await _rows(db_session, "dns_zone")) == n

    # Only the flag flips.
    r = await client.put(
        url, headers=headers, json={"dynamic_update_enabled": False, "entries": [entry]}
    )
    assert r.status_code == 200
    rows = await _rows(db_session, "dns_zone")
    assert len(rows) == n + 1
    assert rows[-1].changed_fields == ["dynamic_update_enabled"]
