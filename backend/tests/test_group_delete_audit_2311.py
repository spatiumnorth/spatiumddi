"""Deleting a server group writes one audit row per trashed zone / scope it purges (#2311).

The zones and scopes in Trash go with the group by FK cascade, which runs no
Python, so before this the only record was the group's own row. #1957's
convention for a Trash purge is one row per cascaded item.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup, DNSView
from tests.test_server_group_delete_1399 import _admin, _dhcp_group_with_scope


async def _rows(db: AsyncSession, resource_type: str, resource_id: str) -> list[AuditLog]:
    db.expire_all()
    rows = list(
        (
            await db.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == resource_type, AuditLog.resource_id == resource_id
                )
            )
        )
        .scalars()
        .all()
    )
    if resource_type == "dns_server_group" or resource_type == "dhcp_server_group":
        return rows
    # The zone / scope also carries its own create / trash rows; the purge row
    # is the one stamped as taken with the group.
    return [r for r in rows if (r.old_value or {}).get("purged_with")]


async def test_dns_group_delete_audits_each_trashed_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    group = DNSServerGroup(name=f"ga-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    view = DNSView(group_id=group.id, name="internal")
    db_session.add(view)
    await db_session.flush()
    group_id, view_id = group.id, view.id
    await db_session.commit()

    ids = {}
    for name, vid in (("a2311.test", None), ("b2311.test", str(view_id))):
        body = {"name": name}
        if vid:
            body["view_id"] = vid
        made = await client.post(f"/api/v1/dns/groups/{group_id}/zones", headers=headers, json=body)
        assert made.status_code == 201, made.text
        zid = made.json()["id"]
        ids[name] = zid
        rec = await client.post(
            f"/api/v1/dns/groups/{group_id}/zones/{zid}/records",
            headers=headers,
            json={"name": "www", "record_type": "A", "value": "192.0.2.10"},
        )
        assert rec.status_code == 201, rec.text
        gone = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zid}", headers=headers)
        assert gone.status_code in (200, 204), gone.text

    resp = await client.delete(f"/api/v1/dns/groups/{group_id}", headers=headers)
    assert resp.status_code == 204, resp.text

    for name, zid in ids.items():
        rows = await _rows(db_session, "dns_zone", zid)
        assert len(rows) == 1, f"{name}: expected one per-zone audit row, got {len(rows)}"
        old = rows[0].old_value
        assert rows[0].action == "delete"
        assert old["name"].rstrip(".") == name
        assert old["view"] == ("internal" if name.startswith("b") else None)
        assert old["record_count"] >= 1
    grp = await _rows(db_session, "dns_server_group", str(group_id))
    assert len(grp) == 1 and grp[0].old_value["trashed_zones_deleted"] == 2


async def test_dhcp_group_delete_audits_each_trashed_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    group_id, scope_id = await _dhcp_group_with_scope(client, db_session, headers)
    gone = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=headers)
    assert gone.status_code in (200, 204), gone.text

    resp = await client.delete(f"/api/v1/dhcp/server-groups/{group_id}", headers=headers)
    assert resp.status_code == 204, resp.text

    rows = await _rows(db_session, "dhcp_scope", str(scope_id))
    assert len(rows) == 1, f"expected one per-scope audit row, got {len(rows)}"
    assert rows[0].action == "delete"
    assert rows[0].old_value["name"] == "gd-scope"
    assert rows[0].old_value["purged_with"] == "dhcp_server_group"
    grp = await _rows(db_session, "dhcp_server_group", str(group_id))
    assert len(grp) == 1 and grp[0].old_value["trashed_scopes_deleted"] == 1
