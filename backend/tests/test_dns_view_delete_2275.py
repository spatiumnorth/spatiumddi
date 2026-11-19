"""Deleting a DNS view, and two zones of one name in one view (#2275).

``view_id`` on zones and records is ``ON DELETE SET NULL``, and NULL means
*shared*: rendered into every view. So deleting a view used to serve its zones
and records in every other view, and a zone with a same-name twin in another
view was then declared twice there, which makes BIND refuse the whole group.

These tests assert on what is stored and on what the agent bundle would
render, never on the guard itself.
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import (
    DNSBlockList,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSView,
    DNSZone,
)
from app.services.dns.agent_config import build_config_bundle


async def _admin(db: AsyncSession) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"a-{tag}",
        email=f"{tag}@example.com",
        display_name="A",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    db.add(DNSServer(group_id=group.id, name="ns1", driver="bind9", host="127.0.0.1", port=53))
    await db.flush()
    return group


async def _view(client: AsyncClient, hdr: dict, group_id: Any, name: str, cidr: str) -> str:
    r = await client.post(
        f"/api/v1/dns/groups/{group_id}/views",
        headers=hdr,
        json={"name": name, "match_clients": [cidr]},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _zone(
    client: AsyncClient, hdr: dict, group_id: Any, name: str, view_id: str | None
) -> Any:
    body: dict[str, Any] = {"name": name}
    if view_id is not None:
        body["view_id"] = view_id
    return await client.post(f"/api/v1/dns/groups/{group_id}/zones", headers=hdr, json=body)


async def _record(
    client: AsyncClient, hdr: dict, group_id: Any, zone_id: str, view_id: str | None
) -> Any:
    body: dict[str, Any] = {"name": "www", "record_type": "A", "value": "10.0.0.5"}
    if view_id is not None:
        body["view_id"] = view_id
    return await client.post(
        f"/api/v1/dns/groups/{group_id}/zones/{zone_id}/records", headers=hdr, json=body
    )


async def _rendered(db: AsyncSession, group_id: Any) -> list[tuple[str | None, str]]:
    """(view, zone name) for every zone stanza the group's agent would render."""
    server = (
        await db.execute(select(DNSServer).where(DNSServer.group_id == group_id))
    ).scalar_one()
    bundle = await build_config_bundle(db, server)
    return [(z["view_name"], z["name"].rstrip(".").lower()) for z in bundle["zones"]]


def _dupes(rendered: list[tuple[str | None, str]]) -> list[tuple[str | None, str]]:
    return [k for k, n in Counter(rendered).items() if n > 1]


# ── view delete ─────────────────────────────────────────────────────────────


async def test_deleting_a_view_that_owns_a_zone_is_refused(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    await _view(client, hdr, group.id, "external", "any")
    r = await _zone(client, hdr, group.id, "secret.example.", internal)
    assert r.status_code == 201, r.text

    r = await client.delete(f"/api/v1/dns/groups/{group.id}/views/{internal}", headers=hdr)
    assert r.status_code == 409, r.text
    assert "secret.example" in r.json()["detail"]

    # Nothing moved: the view is still there, the zone still pinned to it, and
    # the zone is served on internal only, not on external.
    assert await db_session.get(DNSView, uuid.UUID(internal)) is not None
    zone = (
        await db_session.execute(select(DNSZone).where(DNSZone.name == "secret.example."))
    ).scalar_one()
    assert str(zone.view_id) == internal
    assert await _rendered(db_session, group.id) == [("internal", "secret.example")]


async def test_deleting_a_view_that_scopes_a_record_is_refused(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    await _view(client, hdr, group.id, "external", "any")
    z = await _zone(client, hdr, group.id, "corp.example.", None)
    zone_id = z.json()["id"]
    assert (await _record(client, hdr, group.id, zone_id, internal)).status_code == 201

    r = await client.delete(f"/api/v1/dns/groups/{group.id}/views/{internal}", headers=hdr)
    assert r.status_code == 409, r.text
    assert "1 record(s)" in r.json()["detail"]
    rec = (
        await db_session.execute(select(DNSRecord).where(DNSRecord.zone_id == uuid.UUID(zone_id)))
    ).scalar_one()
    assert str(rec.view_id) == internal


async def test_deleting_a_view_whose_zone_is_in_the_trash_is_refused(
    client: AsyncClient, db_session
):
    """A trashed zone keeps its view_id; SET NULL would bring it back shared."""
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    z = await _zone(client, hdr, group.id, "secret.example.", internal)
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/zones/{z.json()['id']}", headers=hdr)
    assert r.status_code == 204, r.text

    r = await client.delete(f"/api/v1/dns/groups/{group.id}/views/{internal}", headers=hdr)
    assert r.status_code == 409, r.text
    assert "in Trash" in r.json()["detail"]
    trashed = (
        await db_session.execute(
            select(DNSZone)
            .where(DNSZone.id == uuid.UUID(z.json()["id"]))
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert str(trashed.view_id) == internal


async def test_twin_zone_view_delete_is_refused_and_never_renders_twice(
    client: AsyncClient, db_session
):
    """The issue's second consequence: corp.example in internal AND external."""
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    external = await _view(client, hdr, group.id, "external", "any")
    assert (await _zone(client, hdr, group.id, "corp.example.", internal)).status_code == 201
    assert (await _zone(client, hdr, group.id, "corp.example.", external)).status_code == 201
    assert sorted(await _rendered(db_session, group.id)) == [
        ("external", "corp.example"),
        ("internal", "corp.example"),
    ]

    r = await client.delete(f"/api/v1/dns/groups/{group.id}/views/{internal}", headers=hdr)
    assert r.status_code == 409, r.text

    rendered = await _rendered(db_session, group.id)
    assert _dupes(rendered) == []
    assert sorted(rendered) == [("external", "corp.example"), ("internal", "corp.example")]


async def test_an_empty_view_deletes(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    lab = await _view(client, hdr, group.id, "lab", "192.0.2.0/24")
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/views/{lab}", headers=hdr)
    assert r.status_code == 204, r.text
    assert await db_session.get(DNSView, uuid.UUID(lab)) is None


async def test_view_scoped_blocklists_need_an_acknowledgement(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    kids = await _view(client, hdr, group.id, "kids", "192.168.50.0/24")
    view = await db_session.get(DNSView, uuid.UUID(kids))
    bl = DNSBlockList(name=f"family-{uuid.uuid4().hex[:6]}")
    bl.views = [view]
    db_session.add(bl)
    await db_session.flush()

    r = await client.delete(f"/api/v1/dns/groups/{group.id}/views/{kids}", headers=hdr)
    assert r.status_code == 409, r.text
    assert bl.name in r.json()["detail"]
    assert "stop filtering anywhere" in r.json()["detail"]
    assert await db_session.get(DNSView, uuid.UUID(kids)) is not None

    r = await client.delete(
        f"/api/v1/dns/groups/{group.id}/views/{kids}",
        headers=hdr,
        params={"acknowledge_blocklist_detach": "true"},
    )
    assert r.status_code == 204, r.text
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dns_view",
                AuditLog.resource_id == kids,
                AuditLog.action == "delete",
            )
        )
    ).scalar_one()
    assert audit.old_value == {
        "blocklists_detached": [bl.name],
        "blocklists_left_unscoped": [bl.name],
    }


# ── a duplicate zone stanza in one view, reached without a delete ───────────


async def test_a_shared_zone_cannot_land_beside_a_pinned_twin(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    await _view(client, hdr, group.id, "external", "any")
    assert (await _zone(client, hdr, group.id, "corp.example.", internal)).status_code == 201

    r = await _zone(client, hdr, group.id, "corp.example.", None)
    assert r.status_code == 409, r.text
    assert "internal" in r.json()["detail"]
    assert _dupes(await _rendered(db_session, group.id)) == []


async def test_a_pinned_zone_cannot_land_beside_a_shared_twin(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    assert (await _zone(client, hdr, group.id, "corp.example.", None)).status_code == 201

    r = await _zone(client, hdr, group.id, "corp.example.", internal)
    assert r.status_code == 409, r.text
    assert _dupes(await _rendered(db_session, group.id)) == []


async def test_two_shared_twins_are_refused_in_a_flat_group(client: AsyncClient, db_session):
    """No views: every zone renders once, flat, so NULL-twins collide there."""
    hdr = await _admin(db_session)
    group = await _group(db_session)
    assert (await _zone(client, hdr, group.id, "corp.example.", None)).status_code == 201
    r = await _zone(client, hdr, group.id, "corp.example.", None)
    assert r.status_code == 409, r.text
    assert _dupes(await _rendered(db_session, group.id)) == []


async def test_clearing_a_zones_view_beside_a_twin_is_refused(client: AsyncClient, db_session):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    external = await _view(client, hdr, group.id, "external", "any")
    assert (await _zone(client, hdr, group.id, "corp.example.", internal)).status_code == 201
    z = await _zone(client, hdr, group.id, "corp.example.", external)

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{z.json()['id']}",
        headers=hdr,
        json={"view_id": None},
    )
    assert r.status_code == 409, r.text
    zone = await db_session.get(DNSZone, uuid.UUID(z.json()["id"]))
    await db_session.refresh(zone)
    assert str(zone.view_id) == external
    assert _dupes(await _rendered(db_session, group.id)) == []


async def test_record_view_changes_cannot_widen_a_shared_zone_onto_a_twin(
    client: AsyncClient, db_session
):
    """A shared zone with a record scoped to internal renders only there.

    Deleting that record makes it shared again (every view), and scoping a
    record to external places it in external too: both land beside the pinned
    external twin.
    """
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    external = await _view(client, hdr, group.id, "external", "any")
    shared = await _zone(client, hdr, group.id, "corp.example.", None)
    shared_id = shared.json()["id"]
    rec = await _record(client, hdr, group.id, shared_id, internal)
    assert rec.status_code == 201, rec.text
    assert (await _zone(client, hdr, group.id, "corp.example.", external)).status_code == 201
    assert _dupes(await _rendered(db_session, group.id)) == []

    r = await _record(client, hdr, group.id, shared_id, external)
    assert r.status_code == 409, r.text

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{shared_id}/records/{rec.json()['id']}",
        headers=hdr,
        json={"view_id": external},
    )
    assert r.status_code == 409, r.text

    r = await client.delete(
        f"/api/v1/dns/groups/{group.id}/zones/{shared_id}/records/{rec.json()['id']}",
        headers=hdr,
    )
    assert r.status_code == 409, r.text
    assert _dupes(await _rendered(db_session, group.id)) == []


async def test_restoring_a_shared_zone_beside_a_pinned_twin_is_refused(
    client: AsyncClient, db_session
):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    shared = await _zone(client, hdr, group.id, "corp.example.", None)
    shared_id = shared.json()["id"]
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/zones/{shared_id}", headers=hdr)
    assert r.status_code == 204, r.text
    assert (await _zone(client, hdr, group.id, "corp.example.", internal)).status_code == 201

    r = await client.post(f"/api/v1/admin/trash/dns_zone/{shared_id}/restore", headers=hdr)
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["conflicts"]
    trashed = (
        await db_session.execute(
            select(DNSZone)
            .where(DNSZone.id == uuid.UUID(shared_id))
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).scalar_one()
    assert trashed.deleted_at is not None
    assert _dupes(await _rendered(db_session, group.id)) == []


async def test_zone_move_preview_reports_a_twin_in_the_targets_views(
    client: AsyncClient, db_session
):
    hdr = await _admin(db_session)
    source = await _group(db_session)
    target = await _group(db_session)
    t_internal = await _view(client, hdr, target.id, "internal", "10.0.0.0/8")
    assert (await _zone(client, hdr, target.id, "corp.example.", t_internal)).status_code == 201
    z = await _zone(client, hdr, source.id, "corp.example.", None)

    r = await client.post(
        f"/api/v1/dns/groups/{source.id}/zones/{z.json()['id']}/move/preview",
        headers=hdr,
        json={"target_group_id": str(target.id)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["name_collision"] is True


# ── the guard's own contract ────────────────────────────────────────────────


async def test_an_existing_collision_blocks_neither_unrelated_edits_nor_its_fix(
    client: AsyncClient, db_session
):
    """Only collisions a change introduces are refused (the baseline rule)."""
    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    # Written straight to the table, as a pre-#2275 install could hold it.
    pinned = DNSZone(group_id=group.id, name="corp.example.", view_id=uuid.UUID(internal))
    shared = DNSZone(group_id=group.id, name="corp.example.")
    db_session.add_all([pinned, shared])
    await db_session.flush()
    assert _dupes(await _rendered(db_session, group.id)) == [("internal", "corp.example")]

    # Unrelated: a view-scoped record in the pinned twin changes nothing new.
    r = await _record(client, hdr, group.id, str(pinned.id), internal)
    assert r.status_code == 201, r.text

    # The fix: renaming the shared twin away resolves the collision.
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{shared.id}",
        headers=hdr,
        json={"name": "other.example."},
    )
    assert r.status_code == 200, r.text
    assert _dupes(await _rendered(db_session, group.id)) == []


async def test_the_dns_importer_fails_a_shared_zone_beside_a_pinned_twin(
    client: AsyncClient, db_session
):
    from tests.test_dns_import import _BASIC_NAMED, _BASIC_ZONE, _build_tar

    hdr = await _admin(db_session)
    group = await _group(db_session)
    internal = await _view(client, hdr, group.id, "internal", "10.0.0.0/8")
    assert (await _zone(client, hdr, group.id, "example.com.", internal)).status_code == 201
    gid = str(group.id)
    await db_session.commit()

    archive = _build_tar(
        [("etc/named.conf", _BASIC_NAMED), ("var/named/example.com.zone", _BASIC_ZONE)]
    )
    preview = await client.post(
        "/api/v1/dns/import/bind9/preview",
        headers=hdr,
        files={"file": ("bind.tar.gz", archive, "application/gzip")},
        data={"target_group_id": gid},
    )
    assert preview.status_code == 200, preview.text
    r = await client.post(
        "/api/v1/dns/import/bind9/commit",
        headers=hdr,
        json={"target_group_id": gid, "plan": preview.json(), "conflict_actions": {}},
    )
    assert r.status_code == 200, r.text
    (zone_result,) = r.json()["zones"]
    assert zone_result["action_taken"] == "failed"
    assert "twice in one view" in zone_result["error"]
    assert _dupes(await _rendered(db_session, uuid.UUID(gid))) == []


async def test_the_guard_and_the_bundle_agree_on_every_placement(client: AsyncClient, db_session):
    """Built behind the guard's back: what it reports is what the bundle renders."""
    from app.services.dns.view_collisions import zone_render_collisions

    hdr = await _admin(db_session)
    group = await _group(db_session)
    a = uuid.UUID(await _view(client, hdr, group.id, "a", "10.0.0.0/8"))
    b = uuid.UUID(await _view(client, hdr, group.id, "b", "172.16.0.0/12"))
    await _view(client, hdr, group.id, "c", "any")

    def zone(name: str, view: uuid.UUID | None) -> DNSZone:
        z = DNSZone(group_id=group.id, name=name, view_id=view)
        db_session.add(z)
        return z

    # one.: shared (a, b, c) + pinned a          → a
    # two.: shared scoped to b by a record + pinned b → b
    # three.: shared scoped to a + pinned b       → none
    # four.: pinned a + pinned b                 → none
    # five.: alone, shared                        → none (and no record scan)
    zones = [
        zone("one.", None),
        zone("one.", a),
        zone("two.", None),
        zone("two.", b),
        zone("three.", None),
        zone("three.", b),
        zone("four.", a),
        zone("four.", b),
        zone("five.", None),
    ]
    await db_session.flush()
    by_name: dict[str, list[DNSZone]] = {}
    for z in zones:
        by_name.setdefault(z.name, []).append(z)
    for zname, view in (("two.", b), ("three.", a)):
        shared = next(z for z in by_name[zname] if z.view_id is None)
        db_session.add(
            DNSRecord(
                zone_id=shared.id,
                name="h",
                fqdn=f"h.{zname}",
                record_type="A",
                value="192.0.2.1",
                view_id=view,
            )
        )
    await db_session.flush()

    expected = sorted(_dupes(await _rendered(db_session, group.id)))
    assert expected == [("a", "one"), ("b", "two")]
    got = sorted((c.view, c.zone_name) for c in await zone_render_collisions(db_session, group.id))
    assert got == expected
    for zname in ("one.", "two.", "three.", "four.", "five."):
        scoped = await zone_render_collisions(db_session, group.id, names=[zname])
        assert sorted((c.view, c.zone_name) for c in scoped) == [
            k for k in expected if k[1] == zname.rstrip(".")
        ]
