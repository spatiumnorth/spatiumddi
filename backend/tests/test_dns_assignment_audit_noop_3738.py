"""#3738 - saving an unchanged blocklist scope / zone ACL audits nothing."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import DNSBlockList, DNSServerGroup, DNSView
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


async def test_blocklist_noop_does_not_wake_and_view_change_does(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.v1.dns.blocklist_router as br

    _, headers = await _superadmin(db_session)
    g1 = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(g1)
    await db_session.flush()
    view = DNSView(group_id=g1.id, name="internal")
    bl = DNSBlockList(name=f"bl-{uuid.uuid4().hex[:6]}", category="custom", source_type="manual")
    db_session.add_all([view, bl])
    await db_session.commit()
    url = f"/api/v1/dns/blocklists/{bl.id}/assignments"
    gid, vid = str(g1.id), str(view.id)
    body = {"server_group_ids": [gid], "view_ids": []}
    assert (await client.put(url, headers=headers, json=body)).status_code == 200

    woken: list[str] = []
    monkeypatch.setattr(br, "collect_wake", lambda *ch: woken.extend(ch))
    n = len(await _rows(db_session, "dns_blocklist_assignment"))

    assert (await client.put(url, headers=headers, json=body)).status_code == 200
    assert woken == []
    assert len(await _rows(db_session, "dns_blocklist_assignment")) == n

    # A view-only change audits view_ids alone and wakes the group.
    body["view_ids"] = [vid]
    r = await client.put(url, headers=headers, json=body)
    assert r.status_code == 200, r.text
    rows = await _rows(db_session, "dns_blocklist_assignment")
    assert len(rows) == n + 1
    assert rows[-1].changed_fields == ["view_ids"]
    assert woken


async def test_blocklist_noop_still_404s_unknown_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _superadmin(db_session)
    bl = DNSBlockList(name=f"bl-{uuid.uuid4().hex[:6]}", category="custom", source_type="manual")
    db_session.add(bl)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/blocklists/{bl.id}/assignments",
        headers=headers,
        json={"server_group_ids": [str(uuid.uuid4())]},
    )
    assert r.status_code == 404


async def test_zone_acl_changes_audit_wake_and_push(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.v1.dns.router as dr

    _, headers = await _superadmin(db_session)
    group, zone, key = await _bind9_group_zone_key(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl"
    tsig = {"match_kind": "tsig_key", "action": "grant", "tsig_key_id": str(key.id)}
    ip = {"match_kind": "ip", "action": "grant", "ip_cidr": "10.0.0.0/24", "name_scope": None}
    assert (
        await client.put(
            url, headers=headers, json={"dynamic_update_enabled": True, "entries": [tsig, ip]}
        )
    ).status_code == 200

    woken: list[str] = []
    pushed: list[object] = []

    async def _fake_push(*a: object, **k: object) -> list[str]:
        pushed.append(a)
        return []

    monkeypatch.setattr(dr, "collect_wake", lambda *ch: woken.extend(ch))
    monkeypatch.setattr(dr, "_push_windows_dynamic_update", _fake_push)
    n = len(await _rows(db_session, "dns_zone"))

    # Identical resend: no audit, wake, or push.
    r = await client.put(
        url, headers=headers, json={"dynamic_update_enabled": True, "entries": [tsig, ip]}
    )
    assert r.status_code == 200
    assert (woken, pushed) == ([], [])
    assert len(await _rows(db_session, "dns_zone")) == n

    # Same entries, different order: first-match order is meaningful -> a change.
    r = await client.put(
        url, headers=headers, json={"dynamic_update_enabled": True, "entries": [ip, tsig]}
    )
    assert r.status_code == 200
    rows = await _rows(db_session, "dns_zone")
    assert len(rows) == n + 1 and rows[-1].changed_fields == ["update_acl"]
    assert woken and len(pushed) == 1

    # Edited entry (flag unchanged) audits update_acl only.
    ip2 = {**ip, "ip_cidr": "10.0.1.0/24"}
    r = await client.put(url, headers=headers, json={"entries": [ip, ip2]})
    assert r.status_code == 200
    rows = await _rows(db_session, "dns_zone")
    assert len(rows) == n + 2 and rows[-1].changed_fields == ["update_acl"]
    assert len(pushed) == 2


async def test_zone_acl_noop_still_validated(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.drivers.dns.bind9 import BIND9Driver

    _, headers = await _superadmin(db_session)
    group, zone, key = await _bind9_group_zone_key(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl"
    body = {
        "dynamic_update_enabled": True,
        "entries": [{"match_kind": "tsig_key", "action": "grant", "tsig_key_id": str(key.id)}],
    }
    assert (await client.put(url, headers=headers, json=body)).status_code == 200

    def _refuse(self: object, zone_name: str, entries: object) -> list[str]:
        raise ValueError("unsupported now")

    monkeypatch.setattr(BIND9Driver, "validate_update_acl", _refuse)
    r = await client.put(url, headers=headers, json=body)
    assert r.status_code == 422
