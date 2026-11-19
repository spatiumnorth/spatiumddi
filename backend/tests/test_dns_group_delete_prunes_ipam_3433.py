"""A deleted DNS server group is not left named in IPAM (#3433).

``dns_group_ids`` on spaces, blocks and subnets is a JSONB id list with no
foreign key. Deleting a group now prunes its id (Trash rows included), and the
IPAM writes refuse an id that names no group, so a stale id cannot come back
in through a create, an update or a saved plan.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _groups(db: AsyncSession, *names: str) -> list[DNSServerGroup]:
    groups = [DNSServerGroup(name=f"{n}-{uuid.uuid4().hex[:6]}") for n in names]
    db.add_all(groups)
    await db.flush()
    return groups


async def _ids(db: AsyncSession, table: str, row_id: uuid.UUID) -> list[str]:
    return (
        await db.execute(text(f"SELECT dns_group_ids FROM {table} WHERE id = :i"), {"i": row_id})
    ).scalar_one()


async def test_group_delete_prunes_ipam_refs(client: AsyncClient, db_session: AsyncSession) -> None:
    db = db_session
    h = await _headers(db)
    gone, keep, other = await _groups(db, "gone", "keep", "other")
    g, k, o = str(gone.id), str(keep.id), str(other.id)
    # Order is kept: the first entry picks the reverse-zone group.
    space = IPSpace(name=f"s3433-{uuid.uuid4().hex[:6]}", description="", dns_group_ids=[o, g, k])
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.93.0.0/16", name="b", dns_group_ids=[g])
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.93.1.0/24", name="n", dns_group_ids=[g]
    )
    trashed = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.93.2.0/24",
        name="t",
        dns_group_ids=[g, k],
        deleted_at=datetime.now(UTC),
    )
    db.add_all([subnet, trashed])
    await db.flush()
    await db.commit()

    r = await client.delete(f"/api/v1/dns/groups/{gone.id}", headers=h)
    assert r.status_code == 204, r.text

    assert await _ids(db, "ip_space", space.id) == [o, k]
    assert await _ids(db, "ip_block", block.id) == []
    assert await _ids(db, "subnet", subnet.id) == []
    # A Trash row loses it too, so a restore brings back no dead reference.
    assert await _ids(db, "subnet", trashed.id) == [k]

    subnet_id = subnet.id
    db.expire_all()  # the test shares the app's session; drop the rows it holds
    r = await client.get(f"/api/v1/ipam/subnets/{subnet_id}/effective-dns", headers=h)
    assert r.status_code == 200, r.text
    assert g not in r.json()["dns_group_ids"]


async def test_ipam_writes_refuse_unknown_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    h = await _headers(db)
    (live,) = await _groups(db, "live")
    await db.commit()
    dead = str(uuid.uuid4())

    r = await client.post(
        "/api/v1/ipam/spaces",
        headers=h,
        json={"name": f"x3433-{uuid.uuid4().hex[:6]}", "dns_group_ids": [str(live.id), dead]},
    )
    assert r.status_code == 422, r.text
    assert dead in r.text

    r = await client.post(
        "/api/v1/ipam/spaces",
        headers=h,
        json={"name": f"y3433-{uuid.uuid4().hex[:6]}", "dns_group_ids": [str(live.id)]},
    )
    assert r.status_code == 201, r.text
    space_id = r.json()["id"]

    r = await client.put(
        f"/api/v1/ipam/spaces/{space_id}", headers=h, json={"dns_group_ids": [dead]}
    )
    assert r.status_code == 422, r.text

    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={"space_id": space_id, "network": "10.94.0.0/16", "dns_group_ids": [dead]},
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/ipam/blocks", headers=h, json={"space_id": space_id, "network": "10.94.0.0/16"}
    )
    assert r.status_code == 201, r.text
    block_id = r.json()["id"]
    r = await client.put(
        f"/api/v1/ipam/blocks/{block_id}", headers=h, json={"dns_group_ids": [dead]}
    )
    assert r.status_code == 422, r.text

    # The legacy singular ``dns_group_id`` seeds the list, so it is checked too.
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": "10.94.1.0/24",
            "dns_group_id": dead,
        },
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={"space_id": space_id, "block_id": block_id, "network": "10.94.1.0/24"},
    )
    assert r.status_code == 201, r.text
    subnet_id = r.json()["id"]
    r = await client.put(
        f"/api/v1/ipam/subnets/{subnet_id}", headers=h, json={"dns_group_ids": [dead]}
    )
    assert r.status_code == 422, r.text

    assert await _ids(db, "ip_space", uuid.UUID(space_id)) == [str(live.id)]
    assert await _ids(db, "ip_block", uuid.UUID(block_id)) == []
    assert await _ids(db, "subnet", uuid.UUID(subnet_id)) == []


async def test_plan_naming_a_deleted_group_is_a_conflict(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    h = await _headers(db)
    (live,) = await _groups(db, "plan")
    space = IPSpace(name=f"p3433-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    await db.commit()
    dead = str(uuid.uuid4())
    tree = {
        "id": "r",
        "network": "10.95.0.0/16",
        "name": "root",
        "kind": "block",
        "dns_group_id": str(live.id),
        "children": [
            {"id": "a", "network": "10.95.1.0/24", "name": "a", "kind": "subnet"},
            {
                "id": "b",
                "network": "10.95.2.0/24",
                "name": "b",
                "kind": "subnet",
                "dns_group_id": dead,
            },
        ],
    }
    r = await client.post(
        "/api/v1/ipam/plans/validate-tree",
        headers=h,
        json={"name": "v", "space_id": str(space.id), "tree": tree},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is False
    assert [(c["node_id"], c["kind"]) for c in body["conflicts"]] == [("b", "invalid_binding")]
    assert dead in body["conflicts"][0]["message"]


def _spellings(u: uuid.UUID) -> list[str]:
    """Spellings an older build stored as given and the readers resolve."""
    return ["{" + str(u).upper() + "}", u.hex, f"urn:uuid:{u}", str(u).upper()]


async def test_group_delete_prunes_every_spelling(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Before #2923 an id was stored as given; ``uuid.UUID`` resolves all of
    these, so the delete must remove them all and keep the live group's."""
    db = db_session
    h = await _headers(db)
    gone, keep = await _groups(db, "gone", "keep")
    kept = ["{" + str(keep.id) + "}", keep.id.hex]
    space = IPSpace(
        name=f"sp3433-{uuid.uuid4().hex[:6]}",
        description="",
        dns_group_ids=[kept[0], *_spellings(gone.id), kept[1]],
    )
    db.add(space)
    await db.flush()
    await db.commit()

    r = await client.delete(f"/api/v1/dns/groups/{gone.id}", headers=h)
    assert r.status_code == 204, r.text
    assert await _ids(db, "ip_space", space.id) == kept


async def test_update_keeps_a_dead_group_the_row_already_has(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A row carrying a dead id (a selective IPAM restore) still takes an
    unrelated edit from a dialog that re-sends its groups; a NEW dead id is
    still refused."""
    db = db_session
    h = await _headers(db)
    dead, new_dead = str(uuid.uuid4()), str(uuid.uuid4())
    space = IPSpace(name=f"r3433-{uuid.uuid4().hex[:6]}", description="", dns_group_ids=[dead])
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.96.0.0/16", name="b", dns_group_ids=[dead])
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.96.1.0/24",
        name="n",
        dns_group_ids=[dead],
    )
    db.add(subnet)
    await db.flush()
    await db.commit()
    paths = {
        "spaces": space.id,
        "blocks": block.id,
        "subnets": subnet.id,
    }
    db.expire_all()
    for kind, row_id in paths.items():
        r = await client.put(
            f"/api/v1/ipam/{kind}/{row_id}",
            headers=h,
            json={"description": "edited", "dns_group_ids": [dead]},
        )
        assert r.status_code == 200, (kind, r.text)
        r = await client.put(
            f"/api/v1/ipam/{kind}/{row_id}",
            headers=h,
            json={"dns_group_ids": [dead, new_dead]},
        )
        assert r.status_code == 422, (kind, r.text)
        assert new_dead in r.text and dead not in r.text


async def test_dns_factory_reset_clears_group_ids(db_session: AsyncSession) -> None:
    """A DNS-only factory reset wipes every group and keeps IPAM, so every
    ``dns_group_ids`` entry would name nothing."""
    from tests.test_factory_reset_fk_cascade import _wipe  # noqa: PLC0415

    db = db_session
    (grp,) = await _groups(db, "reset")
    space = IPSpace(
        name=f"f3433-{uuid.uuid4().hex[:6]}",
        description="",
        dns_group_ids=[str(grp.id), "{" + str(grp.id).upper() + "}"],
    )
    db.add(space)
    await db.flush()
    trashed = IPSpace(
        name=f"ft3433-{uuid.uuid4().hex[:6]}",
        description="",
        dns_group_ids=[str(grp.id)],
        deleted_at=datetime.now(UTC),
    )
    db.add(trashed)
    await db.flush()
    await db.commit()
    space_id, trashed_id = space.id, trashed.id

    await _wipe("dns")
    db.expire_all()
    assert await _ids(db, "ip_space", space_id) == []
    assert await _ids(db, "ip_space", trashed_id) == []


async def test_migration_keeps_live_ids_in_any_spelling(db_session: AsyncSession) -> None:
    """``b3d7e19a5c40`` drops dead ids and keeps a live one however it was
    spelled; comparing lower-cased text would clear the braced, unhyphenated
    and ``urn:uuid:`` spellings of a LIVE group."""
    import importlib.util  # noqa: PLC0415
    import pathlib  # noqa: PLC0415

    from alembic.migration import MigrationContext  # noqa: PLC0415
    from alembic.operations import Operations  # noqa: PLC0415

    path = next(
        (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions").glob(
            "b3d7e19a5c40_*.py"
        )
    )
    spec = importlib.util.spec_from_file_location("b3d7e19a5c40", path)
    assert spec is not None and spec.loader is not None
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)

    db = db_session
    (live,) = await _groups(db, "live")
    dead = uuid.uuid4()
    live_spellings = [str(live.id), *_spellings(live.id)]
    space = IPSpace(
        name=f"m3433-{uuid.uuid4().hex[:6]}",
        description="",
        dns_group_ids=[*_spellings(dead), live_spellings[1], str(dead), *live_spellings[2:]],
    )
    db.add(space)
    await db.flush()
    untouched = IPSpace(
        name=f"mu3433-{uuid.uuid4().hex[:6]}", description="", dns_group_ids=live_spellings
    )
    trashed = IPSpace(
        name=f"mt3433-{uuid.uuid4().hex[:6]}",
        description="",
        dns_group_ids=[str(dead), str(live.id)],
        deleted_at=datetime.now(UTC),
    )
    db.add_all([untouched, trashed])
    await db.flush()
    await db.commit()

    def _up(sync_conn: object) -> None:
        with Operations.context(MigrationContext.configure(connection=sync_conn)):
            mig.upgrade()

    conn = await db.connection()
    await conn.run_sync(_up)
    await db.commit()

    assert await _ids(db, "ip_space", space.id) == [live_spellings[1], *live_spellings[2:]]
    assert await _ids(db, "ip_space", untouched.id) == live_spellings
    assert await _ids(db, "ip_space", trashed.id) == [str(live.id)]
