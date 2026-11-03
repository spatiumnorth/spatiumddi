"""A purged DNS zone is not left named in IPAM (#3443).

Spaces, blocks, subnets, templates, addresses and plans store zone ids as text /
JSONB with no foreign key. Every path that deletes a zone row prunes the id
(Trash rows included), a migration clears ids already stranded, and the IPAM
writes refuse an id that names no zone.
"""

from __future__ import annotations

import importlib.util
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPAMTemplate, IPBlock, IPSpace, Subnet, SubnetPlan
from app.tasks.trash_purge import _purge_dns_zones
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _zones(db: AsyncSession, n: int, *, trashed: bool = False) -> list[DNSZone]:
    group = DNSServerGroup(name=f"g3443-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    zones = [
        DNSZone(
            group_id=group.id,
            name=f"z{i}-{uuid.uuid4().hex[:6]}.test.",
            kind="forward",
            deleted_at=datetime.now(UTC) - timedelta(days=40) if trashed else None,
        )
        for i in range(n)
    ]
    db.add_all(zones)
    await db.flush()
    return zones


async def _ipam(db: AsyncSession, dead: str, keep: str, other: str) -> dict[str, uuid.UUID]:
    """One row of every kind that names ``dead`` (and ``keep`` / ``other``)."""
    space = IPSpace(
        name=f"s3443-{uuid.uuid4().hex[:6]}",
        description="",
        dns_zone_id=dead,
        dns_additional_zone_ids=[other, dead.upper(), keep],
    )
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.83.0.0/16", name="b", dns_zone_id=keep)
    block.dns_additional_zone_ids = [dead]
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.83.1.0/24",
        name="n",
        dns_zone_id=dead,
        dns_additional_zone_ids=[keep, dead],
    )
    trashed = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.83.2.0/24",
        name="t",
        dns_zone_id=dead,
        dns_additional_zone_ids=[dead, other],
        deleted_at=datetime.now(UTC),
    )
    db.add_all([subnet, trashed])
    await db.flush()
    addr = IPAddress(
        subnet_id=subnet.id, address="10.83.1.5", status="allocated", extra_zone_ids=[dead, keep]
    )
    tpl = IPAMTemplate(
        name=f"t3443-{uuid.uuid4().hex[:6]}",
        applies_to="subnet",
        dns_zone_id=dead,
        dns_additional_zone_ids=[dead, keep],
    )
    plan = SubnetPlan(
        name=f"p3443-{uuid.uuid4().hex[:6]}",
        space_id=space.id,
        tree={
            "id": "r",
            "network": "10.84.0.0/16",
            "dns_zone_id": dead,
            "children": [
                {"id": "a", "network": "10.84.1.0/24", "dns_zone_id": keep},
                {"id": "b", "network": "10.84.2.0/24", "dns_zone_id": dead.upper()},
            ],
        },
    )
    db.add_all([addr, tpl, plan])
    await db.flush()
    await db.commit()
    return {
        "space": space.id,
        "block": block.id,
        "subnet": subnet.id,
        "trashed": trashed.id,
        "addr": addr.id,
        "tpl": tpl.id,
        "plan": plan.id,
    }


async def _col(db: AsyncSession, sql: str, i: uuid.UUID):
    db.expire_all()
    return (await db.execute(text(sql), {"i": i})).scalar_one()


async def _assert_pruned(db: AsyncSession, r: dict[str, uuid.UUID], keep: str, other: str) -> None:
    assert await _col(db, "SELECT dns_zone_id FROM ip_space WHERE id=:i", r["space"]) is None
    # Order of what is kept is preserved.
    assert await _col(
        db, "SELECT dns_additional_zone_ids FROM ip_space WHERE id=:i", r["space"]
    ) == [other, keep]
    assert await _col(db, "SELECT dns_zone_id FROM ip_block WHERE id=:i", r["block"]) == keep
    assert (
        await _col(db, "SELECT dns_additional_zone_ids FROM ip_block WHERE id=:i", r["block"]) == []
    )
    assert await _col(db, "SELECT dns_zone_id FROM subnet WHERE id=:i", r["subnet"]) is None
    assert await _col(
        db, "SELECT dns_additional_zone_ids FROM subnet WHERE id=:i", r["subnet"]
    ) == [keep]
    # A Trash row loses it too.
    assert await _col(db, "SELECT dns_zone_id FROM subnet WHERE id=:i", r["trashed"]) is None
    assert await _col(
        db, "SELECT dns_additional_zone_ids FROM subnet WHERE id=:i", r["trashed"]
    ) == [other]
    assert await _col(db, "SELECT extra_zone_ids FROM ip_address WHERE id=:i", r["addr"]) == [keep]
    assert await _col(db, "SELECT dns_zone_id FROM ipam_template WHERE id=:i", r["tpl"]) is None
    assert await _col(
        db, "SELECT dns_additional_zone_ids FROM ipam_template WHERE id=:i", r["tpl"]
    ) == [keep]
    tree = await _col(db, "SELECT tree FROM subnet_plan WHERE id=:i", r["plan"])
    assert tree["dns_zone_id"] is None
    assert [c["dns_zone_id"] for c in tree["children"]] == [keep, None]


async def test_trash_permanent_delete_prunes(client: AsyncClient, db_session: AsyncSession) -> None:
    db = db_session
    h = await _headers(db)
    dead, keep, other = await _zones(db, 3, trashed=True)
    r = await _ipam(db, str(dead.id), str(keep.id), str(other.id))
    resp = await client.delete(f"/api/v1/admin/trash/dns_zone/{dead.id}", headers=h)
    assert resp.status_code == 204, resp.text
    await _assert_pruned(db, r, str(keep.id), str(other.id))


async def test_scheduled_purge_prunes(db_session: AsyncSession) -> None:
    db = db_session
    dead, keep, other = await _zones(db, 3)
    dead.deleted_at = datetime.now(UTC) - timedelta(days=40)
    r = await _ipam(db, str(dead.id), str(keep.id), str(other.id))
    purged, skipped = await _purge_dns_zones(db, datetime.now(UTC) - timedelta(days=30))
    assert (purged, skipped) == (1, 0)
    await db.commit()
    await _assert_pruned(db, r, str(keep.id), str(other.id))


async def test_permanent_zone_delete_prunes(client: AsyncClient, db_session: AsyncSession) -> None:
    db = db_session
    h = await _headers(db)
    dead, keep, other = await _zones(db, 3)
    r = await _ipam(db, str(dead.id), str(keep.id), str(other.id))
    resp = await client.delete(
        f"/api/v1/dns/groups/{dead.group_id}/zones/{dead.id}?permanent=true", headers=h
    )
    assert resp.status_code == 204, resp.text
    await _assert_pruned(db, r, str(keep.id), str(other.id))


async def test_group_delete_prunes_trashed_zone_ids(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    h = await _headers(db)
    (dead,) = await _zones(db, 1, trashed=True)
    keep, other = await _zones(db, 2)
    r = await _ipam(db, str(dead.id), str(keep.id), str(other.id))
    resp = await client.delete(f"/api/v1/dns/groups/{dead.group_id}", headers=h)
    assert resp.status_code == 204, resp.text
    await _assert_pruned(db, r, str(keep.id), str(other.id))


async def test_a_trashed_zone_is_not_pruned_until_purged(db_session: AsyncSession) -> None:
    """Soft-delete keeps the ids: a restore must find its bindings."""
    from app.services.ipam.zone_binding import prune_zone_ids

    db = db_session
    dead, keep, other = await _zones(db, 3)
    dead_id, keep_id, other_id = dead.id, str(keep.id), str(other.id)
    r = await _ipam(db, str(dead_id), keep_id, other_id)
    await db.execute(text("UPDATE dns_zone SET deleted_at = now() WHERE id = :i"), {"i": dead_id})
    await db.commit()
    assert await _col(db, "SELECT dns_zone_id FROM ip_space WHERE id=:i", r["space"]) == str(
        dead_id
    )
    await prune_zone_ids(db, [dead_id])
    await db.commit()
    await _assert_pruned(db, r, keep_id, other_id)


async def test_migration_clears_stranded_ids(db_session: AsyncSession) -> None:
    db = db_session
    (live,) = await _zones(db, 1)
    (trashed,) = await _zones(db, 1, trashed=True)
    gone = str(uuid.uuid4())
    r = await _ipam(db, gone, str(live.id), str(trashed.id))
    path = (
        Path(__file__).resolve().parent.parent
        / "alembic/versions/c4e8a2d6b917_prune_purged_dns_zone_ids.py"
    )
    spec = importlib.util.spec_from_file_location("mig3443", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def _run(sync_conn) -> None:
        with Operations.context(MigrationContext.configure(sync_conn)):
            mod.upgrade()

    conn = await db.connection()
    await conn.run_sync(_run)
    await db.commit()
    # ``live`` stays, a Trash zone's id stays (restorable), ``gone`` goes.
    await _assert_pruned(db, r, str(live.id), str(trashed.id))


async def test_ipam_writes_refuse_unknown_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    h = await _headers(db)
    (live,) = await _zones(db, 1)
    await db.commit()
    dead = str(uuid.uuid4())
    live_id = str(live.id)

    r = await client.post(
        "/api/v1/ipam/spaces",
        headers=h,
        json={"name": f"x3443-{uuid.uuid4().hex[:6]}", "dns_additional_zone_ids": [live_id, dead]},
    )
    assert r.status_code == 422, r.text
    assert dead in r.text
    r = await client.post(
        "/api/v1/ipam/spaces",
        headers=h,
        json={"name": f"y3443-{uuid.uuid4().hex[:6]}", "dns_zone_id": live_id},
    )
    assert r.status_code == 201, r.text
    space_id = r.json()["id"]
    r = await client.put(f"/api/v1/ipam/spaces/{space_id}", headers=h, json={"dns_zone_id": dead})
    assert r.status_code == 422, r.text

    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={"space_id": space_id, "network": "10.85.0.0/16", "dns_zone_id": dead},
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/ipam/blocks", headers=h, json={"space_id": space_id, "network": "10.85.0.0/16"}
    )
    assert r.status_code == 201, r.text
    block_id = r.json()["id"]
    r = await client.put(
        f"/api/v1/ipam/blocks/{block_id}", headers=h, json={"dns_additional_zone_ids": [dead]}
    )
    assert r.status_code == 422, r.text

    body = {"space_id": space_id, "block_id": block_id, "network": "10.85.1.0/24"}
    r = await client.post("/api/v1/ipam/subnets", headers=h, json={**body, "dns_zone_id": dead})
    assert r.status_code == 422, r.text
    r = await client.post("/api/v1/ipam/subnets", headers=h, json=body)
    assert r.status_code == 201, r.text
    subnet_id = r.json()["id"]
    r = await client.put(
        f"/api/v1/ipam/subnets/{subnet_id}", headers=h, json={"dns_additional_zone_ids": [dead]}
    )
    assert r.status_code == 422, r.text

    # Addresses: ``extra_zone_ids`` is JSONB with no foreign key.
    addr = {"address": "10.85.1.7", "hostname": "h", "extra_zone_ids": [dead]}
    r = await client.post(f"/api/v1/ipam/subnets/{subnet_id}/addresses", headers=h, json=addr)
    assert r.status_code == 422, r.text

    # Templates.
    tpl = {"name": f"t3443-{uuid.uuid4().hex[:6]}", "applies_to": "subnet"}
    r = await client.post("/api/v1/ipam/templates", headers=h, json={**tpl, "dns_zone_id": dead})
    assert r.status_code == 422, r.text
    r = await client.post("/api/v1/ipam/templates", headers=h, json={**tpl, "dns_zone_id": live_id})
    assert r.status_code == 201, r.text
    r = await client.put(
        f"/api/v1/ipam/templates/{r.json()['id']}",
        headers=h,
        json={"dns_additional_zone_ids": [dead]},
    )
    assert r.status_code == 422, r.text

    assert await _col(db, "SELECT dns_zone_id FROM ip_space WHERE id=:i", uuid.UUID(space_id)) == (
        live_id
    )
    assert await _col(db, "SELECT dns_zone_id FROM subnet WHERE id=:i", uuid.UUID(subnet_id)) in (
        None,
        "",
    )


async def test_plan_naming_a_purged_zone_is_a_conflict(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    h = await _headers(db)
    (live,) = await _zones(db, 1)
    space = IPSpace(name=f"p3443-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    await db.commit()
    dead = str(uuid.uuid4())
    tree = {
        "id": "r",
        "network": "10.86.0.0/16",
        "name": "root",
        "dns_zone_id": str(live.id),
        "children": [
            {"id": "a", "network": "10.86.1.0/24", "name": "a"},
            {"id": "b", "network": "10.86.2.0/24", "name": "b", "dns_zone_id": dead},
        ],
    }
    r = await client.post(
        "/api/v1/ipam/plans/validate-tree",
        headers=h,
        json={"name": "v", "space_id": str(space.id), "tree": tree},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert [(c["node_id"], c["kind"]) for c in body["conflicts"]] == [("b", "invalid_binding")]
    assert dead in body["conflicts"][0]["message"]


# ── Validation follow-ups ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "factory,fk,url",
    [
        ("tailscale", "tailscale_tenant_id", "/api/v1/tailscale/tenants"),
        ("netbird", "netbird_instance_id", "/api/v1/netbird/instances"),
    ],
    ids=["tailscale", "netbird"],
)
async def test_integration_delete_prunes_its_cascaded_zones(
    client: AsyncClient, db_session: AsyncSession, factory: str, fk: str, url: str
) -> None:
    """The tenant / instance delete removes its zones by FK CASCADE (Trash rows
    too), where no zone-delete path sees them."""
    from app.models.netbird import NetbirdInstance
    from app.models.tailscale import TailscaleTenant

    db = db_session
    h = await _headers(db)
    keep, other = await _zones(db, 2)
    space = IPSpace(name=f"i3443-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    if factory == "tailscale":
        target: object = TailscaleTenant(name=f"t-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id)
    else:
        target = NetbirdInstance(
            name=f"n-{uuid.uuid4().hex[:6]}", api_key_encrypted=b"x", ipam_space_id=space.id
        )
    db.add(target)
    await db.flush()
    owned = DNSZone(
        group_id=keep.group_id,
        name=f"m-{uuid.uuid4().hex[:6]}.mesh.",
        kind="forward",
        deleted_at=datetime.now(UTC),
        **{fk: target.id},  # type: ignore[attr-defined]
    )
    db.add(owned)
    await db.flush()
    target_id = target.id  # type: ignore[attr-defined]
    r = await _ipam(db, str(owned.id), str(keep.id), str(other.id))
    resp = await client.delete(f"{url}/{target_id}", headers=h)
    assert resp.status_code == 204, resp.text
    await _assert_pruned(db, r, str(keep.id), str(other.id))


async def test_dns_factory_reset_prunes_every_zone_id(db_session: AsyncSession) -> None:
    """A DNS-only factory reset keeps IPAM and empties dns_zone."""
    from tests.test_factory_reset_fk_cascade import _wipe

    db = db_session
    dead, keep, other = await _zones(db, 3)
    r = await _ipam(db, str(dead.id), str(keep.id), str(other.id))
    await _wipe("dns")
    db.expire_all()
    assert await _col(db, "SELECT dns_zone_id FROM ip_space WHERE id=:i", r["space"]) is None
    assert await _col(db, "SELECT dns_zone_id FROM ip_block WHERE id=:i", r["block"]) is None
    for table, col, key in (
        ("ip_space", "dns_additional_zone_ids", "space"),
        ("subnet", "dns_additional_zone_ids", "trashed"),
        ("ip_address", "extra_zone_ids", "addr"),
        ("ipam_template", "dns_additional_zone_ids", "tpl"),
    ):
        assert await _col(db, f"SELECT {col} FROM {table} WHERE id=:i", r[key]) == []
    tree = await _col(db, "SELECT tree FROM subnet_plan WHERE id=:i", r["plan"])
    assert [tree["dns_zone_id"], *(c["dns_zone_id"] for c in tree["children"])] == [None] * 3


def _spellings(z: uuid.UUID) -> tuple[str, str, str]:
    return (z.hex, "{" + str(z).upper() + "}", f"urn:uuid:{z}")


async def test_migration_keeps_a_live_id_in_another_spelling(db_session: AsyncSession) -> None:
    """Before #2923 an id was stored as given; ``stored_zone_uuid`` still
    resolves an unhyphenated or braced one, so the migration must not clear it."""
    db = db_session
    (live,) = await _zones(db, 1)
    hexed, braced, urn = _spellings(live.id)
    gone = str(uuid.uuid4())
    space = IPSpace(
        name=f"m3443-{uuid.uuid4().hex[:6]}",
        description="",
        dns_zone_id=hexed,
        dns_additional_zone_ids=[braced, gone, urn],
    )
    db.add(space)
    await db.flush()
    space_id = space.id
    await db.commit()
    path = (
        Path(__file__).resolve().parent.parent
        / "alembic/versions/c4e8a2d6b917_prune_purged_dns_zone_ids.py"
    )
    spec = importlib.util.spec_from_file_location("mig3443b", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def _run(sync_conn) -> None:
        with Operations.context(MigrationContext.configure(sync_conn)):
            mod.upgrade()

    conn = await db.connection()
    await conn.run_sync(_run)
    await db.commit()
    assert await _col(db, "SELECT dns_zone_id FROM ip_space WHERE id=:i", space_id) == hexed
    assert await _col(db, "SELECT dns_additional_zone_ids FROM ip_space WHERE id=:i", space_id) == [
        braced,
        urn,
    ]


async def test_prune_matches_an_id_in_another_spelling(db_session: AsyncSession) -> None:
    from app.services.ipam.zone_binding import prune_zone_ids

    db = db_session
    dead, keep = await _zones(db, 2)
    dead_id, keep_id = dead.id, str(keep.id)
    hexed, braced, _ = _spellings(dead_id)
    space = IPSpace(
        name=f"q3443-{uuid.uuid4().hex[:6]}",
        description="",
        dns_zone_id=braced,
        dns_additional_zone_ids=[hexed, keep_id],
    )
    db.add(space)
    await db.flush()
    space_id = space.id
    await db.commit()
    await prune_zone_ids(db, [dead_id])
    await db.commit()
    assert await _col(db, "SELECT dns_zone_id FROM ip_space WHERE id=:i", space_id) is None
    assert await _col(db, "SELECT dns_additional_zone_ids FROM ip_space WHERE id=:i", space_id) == [
        keep_id
    ]


async def test_a_row_already_naming_a_dead_zone_still_takes_an_edit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The edit dialogs send the stored zone on every Save. A row that already
    names a dead zone (a selective IPAM restore whose zones are gone) must
    still save an unrelated change; only a NEW dead id is refused."""
    db = db_session
    h = await _headers(db)
    (keep,) = await _zones(db, 1)
    gone = str(uuid.uuid4())
    r = await _ipam(db, gone, str(keep.id), str(keep.id))
    space = (await client.get(f"/api/v1/ipam/spaces/{r['space']}", headers=h)).json()
    resp = await client.put(
        f"/api/v1/ipam/spaces/{r['space']}",
        headers=h,
        json={
            "description": "renamed",
            "dns_zone_id": space["dns_zone_id"],
            "dns_additional_zone_ids": space["dns_additional_zone_ids"],
        },
    )
    assert resp.status_code == 200, resp.text
    resp = await client.put(
        f"/api/v1/ipam/subnets/{r['subnet']}",
        headers=h,
        json={"description": "x", "dns_zone_id": gone, "dns_additional_zone_ids": [gone]},
    )
    assert resp.status_code == 200, resp.text
    resp = await client.put(
        f"/api/v1/ipam/templates/{r['tpl']}",
        headers=h,
        json={"description": "x", "dns_zone_id": gone},
    )
    assert resp.status_code == 200, resp.text
    # A different dead id is still refused on the same row.
    resp = await client.put(
        f"/api/v1/ipam/subnets/{r['subnet']}",
        headers=h,
        json={"dns_zone_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 422, resp.text
