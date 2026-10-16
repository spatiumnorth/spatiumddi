"""The Trash respects the IPAM / DNS / DHCP hierarchy (#1957, #1958, #1959, #1960).

Every case drives the real delete / restore / purge endpoints, because the
defects were all in the state those sequences leave behind: a child deleted
first sits in a batch of its own, and the parent's later delete stamps only what
was still live.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import (
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"th-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Trash Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _tree(db: AsyncSession) -> SimpleNamespace:
    """space > outer /16 > inner /20 > subnet /24."""
    space = IPSpace(name=f"th-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    outer = IPBlock(space_id=space.id, network="10.61.0.0/16", name="outer")
    db.add(outer)
    await db.flush()
    inner = IPBlock(space_id=space.id, parent_block_id=outer.id, network="10.61.0.0/20", name="in")
    db.add(inner)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=inner.id, network="10.61.1.0/24", name="lan")
    db.add(subnet)
    await db.flush()
    return SimpleNamespace(space=space.id, outer=outer.id, inner=inner.id, subnet=subnet.id)


async def _get(db: AsyncSession, model: type, row_id: uuid.UUID) -> Any:
    db.expire_all()
    stmt: Any = (
        select(model)
        .where(model.id == row_id)  # type: ignore[attr-defined]
        .execution_options(include_deleted=True, populate_existing=True)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def _del(client: AsyncClient, h: dict[str, str], path: str) -> None:
    resp = await client.delete(path, headers=h)
    assert resp.status_code == 204, resp.text


def _restore(client: AsyncClient, h: dict[str, str], typ: str, rid: uuid.UUID, **params: Any):
    return client.post(f"/api/v1/admin/trash/{typ}/{rid}/restore", headers=h, params=params)


def _purge(client: AsyncClient, h: dict[str, str], typ: str, rid: uuid.UUID):
    return client.delete(f"/api/v1/admin/trash/{typ}/{rid}", headers=h)


# ── #1957 ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_restoring_a_subnet_under_a_trashed_block_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    iid, sid = t.inner, t.subnet
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{sid}")
    await _del(client, h, f"/api/v1/ipam/blocks/{iid}")

    resp = await _restore(client, h, "subnet", sid)
    assert resp.status_code == 409, resp.text
    reason = resp.json()["detail"]["conflicts"][0]["reason"]
    assert "10.61.0.0/20" in reason and "Trash" in reason
    assert (await _get(db_session, Subnet, sid)).deleted_at is not None

    # Restoring the parent first, then the child, works.
    assert (await _restore(client, h, "ip_block", iid)).status_code == 200
    assert (await _restore(client, h, "subnet", sid)).status_code == 200
    assert (await _get(db_session, Subnet, sid)).deleted_at is None


@pytest.mark.asyncio
async def test_restoring_a_record_under_a_trashed_zone_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    group = DNSServerGroup(name=f"th-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    zone = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db_session.add(zone)
    await db_session.flush()
    rec = DNSRecord(
        zone_id=zone.id, name="xa", fqdn=f"xa.{zone.name}", record_type="A", value="192.0.2.9"
    )
    other = DNSRecord(
        zone_id=zone.id, name="xb", fqdn=f"xb.{zone.name}", record_type="A", value="192.0.2.10"
    )
    db_session.add_all([rec, other])
    await db_session.flush()
    gid, zid, zname, rid, oid = group.id, zone.id, zone.name, rec.id, other.id
    await db_session.commit()

    r = await client.delete(f"/api/v1/dns/groups/{gid}/zones/{zid}/records/{rid}", headers=h)
    assert r.status_code == 204, r.text
    await _del(client, h, f"/api/v1/dns/groups/{gid}/zones/{zid}")

    resp = await _restore(client, h, "dns_record", rid)
    assert resp.status_code == 409, resp.text
    assert zname in resp.json()["detail"]["conflicts"][0]["reason"]
    assert (await _get(db_session, DNSRecord, rid)).deleted_at is not None

    # A zone that is trashed cannot be purged out from under a LIVE record either.
    live = await _get(db_session, DNSRecord, oid)
    assert live.deleted_at is not None  # rode the zone's batch
    live.deleted_at = None
    live.deletion_batch_id = None
    await db_session.commit()
    purge = await _purge(client, h, "dns_zone", zid)
    assert purge.status_code == 409, purge.text
    assert "xb" in purge.json()["detail"]
    assert (await _get(db_session, DNSRecord, oid)).deleted_at is None


@pytest.mark.asyncio
async def test_restoring_a_scope_under_a_trashed_subnet_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    group = DHCPServerGroup(name=f"th-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    db_session.add(
        DHCPServer(
            name=f"th-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=group.id,
        )
    )
    scope = DHCPScope(group_id=group.id, subnet_id=t.subnet, name="sc", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()
    scid = scope.id
    await db_session.commit()

    await _del(client, h, f"/api/v1/dhcp/scopes/{scid}")
    await _del(client, h, f"/api/v1/ipam/subnets/{t.subnet}")
    resp = await _restore(client, h, "dhcp_scope", scid)
    assert resp.status_code == 409, resp.text
    assert "10.61.1.0/24" in resp.json()["detail"]["conflicts"][0]["reason"]
    assert (await _get(db_session, DHCPScope, scid)).deleted_at is not None


@pytest.mark.asyncio
async def test_a_purge_never_takes_a_live_subnet_with_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The legacy state: a live subnet under a trashed block."""
    h = await _admin(db_session)
    t = await _tree(db_session)
    iid, sid = t.inner, t.subnet
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/blocks/{iid}")
    sub = await _get(db_session, Subnet, sid)
    sub.deleted_at = None
    sub.deletion_batch_id = None
    await db_session.commit()

    resp = await _purge(client, h, "ip_block", t.inner)
    assert resp.status_code == 409, resp.text
    assert "10.61.1.0/24" in resp.json()["detail"]
    assert (await _get(db_session, Subnet, t.subnet)) is not None
    assert (await _get(db_session, IPBlock, t.inner)) is not None


@pytest.mark.asyncio
async def test_the_sweep_skips_a_block_with_a_live_subnet_instead_of_failing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    iid, sid = t.inner, t.subnet
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/blocks/{iid}")
    sub = await _get(db_session, Subnet, sid)
    sub.deleted_at = None
    sub.deletion_batch_id = None
    await db_session.execute(
        text("UPDATE ip_block SET deleted_at = now() - interval '60 days' WHERE id = :i"),
        {"i": t.inner},
    )
    await db_session.commit()

    from app.tasks.trash_purge import _delete_expired  # noqa: PLC0415

    removed, refused = await _delete_expired(
        db_session, IPBlock, datetime.now(UTC) - timedelta(days=30)
    )
    assert (removed, refused) == (0, 0)
    assert (await _get(db_session, Subnet, t.subnet)).deleted_at is None
    assert (await _get(db_session, IPBlock, t.inner)) is not None


# ── #1958 ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purging_a_trashed_block_deletes_the_subnets_and_blocks_in_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/blocks/{t.outer}")

    resp = await _purge(client, h, "ip_block", t.outer)  # subnet sits under a CHILD block
    assert resp.status_code == 204, resp.text
    for model, rid in ((Subnet, t.subnet), (IPBlock, t.inner), (IPBlock, t.outer)):
        assert await _get(db_session, model, rid) is None
    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "permanent_delete")))
        .scalars()
        .all()
    )
    assert {a.resource_type for a in audits} == {"ip_block", "subnet"}
    assert len(audits) == 3


@pytest.mark.asyncio
async def test_purging_a_trashed_space_deletes_what_it_holds(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/spaces/{t.space}")

    resp = await _purge(client, h, "ip_space", t.space)
    assert resp.status_code == 204, resp.text
    assert await _get(db_session, Subnet, t.subnet) is None
    assert await _get(db_session, IPBlock, t.outer) is None
    assert await _get(db_session, IPSpace, t.space) is None


@pytest.mark.asyncio
async def test_purging_a_block_takes_a_subnet_trashed_in_another_batch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{t.subnet}")
    await _del(client, h, f"/api/v1/ipam/blocks/{t.inner}")

    resp = await _purge(client, h, "ip_block", t.inner)
    assert resp.status_code == 204, resp.text
    assert await _get(db_session, Subnet, t.subnet) is None


# ── #1959 ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_restoring_a_subnet_that_overlaps_a_live_one_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{t.subnet}")
    db_session.add(Subnet(space_id=t.space, block_id=t.inner, network="10.61.1.0/25", name="s"))
    await db_session.commit()

    resp = await _restore(client, h, "subnet", t.subnet)
    assert resp.status_code == 409, resp.text
    assert "overlaps" in resp.json()["detail"]["conflicts"][0]["reason"]
    assert "10.61.1.0/25" in resp.json()["detail"]["conflicts"][0]["reason"]
    assert (await _get(db_session, Subnet, t.subnet)).deleted_at is not None


@pytest.mark.asyncio
async def test_restoring_a_block_that_overlaps_a_live_sibling_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    space = IPSpace(name=f"th-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    sp = space.id
    big = IPBlock(space_id=sp, network="10.96.0.0/16", name="big")
    db_session.add(big)
    await db_session.flush()
    bid = big.id
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/blocks/{bid}")
    db_session.add(IPBlock(space_id=sp, network="10.96.0.0/17", name="small"))
    await db_session.commit()

    resp = await _restore(client, h, "ip_block", bid)
    assert resp.status_code == 409, resp.text
    assert "10.96.0.0/17" in resp.json()["detail"]["conflicts"][0]["reason"]
    assert (await _get(db_session, IPBlock, bid)).deleted_at is not None


@pytest.mark.asyncio
async def test_a_non_overlapping_restore_still_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{t.subnet}")
    db_session.add(Subnet(space_id=t.space, block_id=t.inner, network="10.61.2.0/24", name="s"))
    await db_session.commit()
    assert (await _restore(client, h, "subnet", t.subnet)).status_code == 200


# ── #1960 ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_409_says_whether_restore_the_others_is_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    group = DNSServerGroup(name=f"th-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    zone = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db_session.add(zone)
    await db_session.flush()
    for n in ("ya", "yb"):
        db_session.add(
            DNSRecord(
                zone_id=zone.id,
                name=n,
                fqdn=f"{n}.{zone.name}",
                record_type="A",
                value="192.0.2.1" if n == "ya" else "192.0.2.2",
            )
        )
    await db_session.commit()
    zname = zone.name
    await _del(client, h, f"/api/v1/dns/groups/{group.id}/zones/{zone.id}")
    # A zone with the same name now exists: the zone restore clashes.
    db_session.add(
        DNSZone(
            group_id=group.id,
            name=zname,
            zone_type="primary",
            kind="forward",
            primary_ns="ns1.example.test.",
            admin_email="admin.example.test.",
        )
    )
    await db_session.commit()
    rec = (
        (
            await db_session.execute(
                select(DNSRecord)
                .where(DNSRecord.zone_id == zone.id)
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .first()
    )
    assert rec is not None

    resp = await _restore(client, h, "dns_record", rec.id)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["skip_conflicts_allowed"] is False
    # ...and the server agrees with what it said.
    assert (await _restore(client, h, "dns_record", rec.id, skip_conflicts=True)).status_code == 422


# ── #1961 / #1957 audit ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_listing_pages_and_can_start_from_the_oldest(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    space = IPSpace(name=f"th-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    ids = []
    for i in range(3):
        blk = IPBlock(space_id=space.id, network=f"10.{70 + i}.0.0/16", name=f"pg{i}")
        db_session.add(blk)
        await db_session.flush()
        ids.append(blk.id)
    sp = space.id
    await db_session.commit()
    for i in ids:
        await _del(client, h, f"/api/v1/ipam/blocks/{i}")

    newest = await client.get(
        "/api/v1/admin/trash", headers=h, params={"type": "ip_block", "limit": 1}
    )
    oldest = await client.get(
        "/api/v1/admin/trash",
        headers=h,
        params={"type": "ip_block", "limit": 1, "sort": "oldest"},
    )
    assert newest.json()["total"] == 3 and newest.json()["limit"] == 1
    assert newest.json()["items"][0]["id"] == str(ids[-1])
    assert oldest.json()["items"][0]["id"] == str(ids[0])
    page2 = await client.get(
        "/api/v1/admin/trash",
        headers=h,
        params={"type": "ip_block", "limit": 1, "offset": 2, "sort": "oldest"},
    )
    assert page2.json()["offset"] == 2
    assert page2.json()["items"][0]["id"] == str(ids[-1])
    assert sp is not None


@pytest.mark.asyncio
async def test_purging_a_subnet_audits_the_trashed_scope_it_takes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    group = DHCPServerGroup(name=f"th-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    db_session.add(
        DHCPServer(
            name=f"th-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=group.id,
        )
    )
    scope = DHCPScope(group_id=group.id, subnet_id=t.subnet, name="sc", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()
    scid = scope.id
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{t.subnet}")  # takes the scope with it

    assert (await _purge(client, h, "subnet", t.subnet)).status_code == 204
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "permanent_delete", AuditLog.resource_type == "dhcp_scope"
                )
            )
        )
        .scalars()
        .all()
    )
    assert [a.resource_id for a in audits] == [str(scid)]


# ── validation: data safety of the purge paths ────────────────────────────


async def _scope_on(db: AsyncSession, subnet_id: uuid.UUID) -> uuid.UUID:
    group = DHCPServerGroup(name=f"th-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(
        DHCPServer(
            name=f"th-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=group.id,
        )
    )
    scope = DHCPScope(group_id=group.id, subnet_id=subnet_id, name="sc", address_family="ipv4")
    db.add(scope)
    await db.flush()
    return scope.id


@pytest.mark.asyncio
async def test_the_sweep_never_cascades_through_a_trashed_child_to_a_live_grandchild(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ip_block.parent_block_id is CASCADE: a one-level "no live child" test lets
    the expired outer block take a live block two levels down with it."""
    h = await _admin(db_session)
    space = IPSpace(name=f"th-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    outer = IPBlock(space_id=space.id, network="10.62.0.0/16", name="outer")
    db_session.add(outer)
    await db_session.flush()
    mid = IPBlock(space_id=space.id, parent_block_id=outer.id, network="10.62.0.0/20", name="m")
    db_session.add(mid)
    await db_session.flush()
    leaf = IPBlock(space_id=space.id, parent_block_id=mid.id, network="10.62.0.0/22", name="l")
    db_session.add(leaf)
    await db_session.flush()
    oid, lid = outer.id, leaf.id
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/blocks/{oid}")
    # The legacy state: the grandchild came back live, its parents did not.
    await db_session.execute(
        text("UPDATE ip_block SET deleted_at = NULL, deletion_batch_id = NULL WHERE id = :l;"),
        {"l": lid},
    )
    await db_session.execute(
        text(
            "UPDATE ip_block SET deleted_at = now() - interval '60 days' WHERE deleted_at IS NOT NULL"
        )
    )
    await db_session.commit()

    from app.tasks.trash_purge import _delete_expired  # noqa: PLC0415

    await _delete_expired(db_session, IPBlock, datetime.now(UTC) - timedelta(days=30))
    await db_session.commit()
    leaf_row = await _get(db_session, IPBlock, lid)
    assert leaf_row is not None and leaf_row.deleted_at is None
    assert await _get(db_session, IPBlock, oid) is not None


@pytest.mark.asyncio
async def test_the_whole_sweep_purges_the_rest_and_reports_what_it_held_back(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.settings import PlatformSettings  # noqa: PLC0415
    from app.tasks.trash_purge import _sweep  # noqa: PLC0415

    h = await _admin(db_session)
    t = await _tree(db_session)
    other = IPBlock(space_id=t.space, network="10.99.0.0/16", name="other")
    db_session.add(other)
    await db_session.flush()
    other_id = other.id
    if (await db_session.execute(select(PlatformSettings).limit(1))).scalar_one_or_none() is None:
        db_session.add(PlatformSettings())
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/blocks/{t.inner}")
    await _del(client, h, f"/api/v1/ipam/blocks/{other_id}")
    sub = await _get(db_session, Subnet, t.subnet)
    sub.deleted_at = None
    sub.deletion_batch_id = None
    await db_session.execute(
        text(
            "UPDATE ip_block SET deleted_at = now() - interval '60 days' WHERE deleted_at IS NOT NULL"
        )
    )
    await db_session.commit()

    result = await _sweep()
    assert result["per_type"]["ip_block"] == 1, result
    assert result["held_back_live_children"] == {"ip_block": 1}, result
    assert await _get(db_session, IPBlock, other_id) is None
    assert await _get(db_session, IPBlock, t.inner) is not None
    assert (await _get(db_session, Subnet, t.subnet)).deleted_at is None
    # Idempotent: a second night changes nothing and does not fail.
    again = await _sweep()
    assert again["per_type"]["ip_block"] == 0
    assert (await _get(db_session, Subnet, t.subnet)).deleted_at is None


@pytest.mark.asyncio
async def test_a_purge_never_takes_a_live_reservation_under_a_trashed_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    scid = await _scope_on(db_session, t.subnet)
    st = DHCPStaticAssignment(
        scope_id=scid, ip_address="10.61.1.50", mac_address="aa:bb:cc:00:00:01"
    )
    db_session.add(st)
    await db_session.flush()
    stid = st.id
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{t.subnet}")
    row = await _get(db_session, DHCPStaticAssignment, stid)
    assert row.deleted_at is not None
    row.deleted_at = None  # the legacy state: restored alone onto a trashed scope
    row.deletion_batch_id = None
    await db_session.commit()

    for typ, rid in (("dhcp_scope", scid), ("subnet", t.subnet), ("ip_block", t.outer)):
        if typ == "ip_block":
            await _del(client, h, f"/api/v1/ipam/blocks/{t.outer}")
        resp = await _purge(client, h, typ, rid)
        assert resp.status_code == 409, (typ, resp.text)
        assert "reservation" in resp.json()["detail"], resp.text
    assert (await _get(db_session, DHCPStaticAssignment, stid)).deleted_at is None


@pytest.mark.asyncio
async def test_a_purge_never_takes_a_live_pool_under_a_trashed_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    scid = await _scope_on(db_session, t.subnet)
    pool = DHCPPool(scope_id=scid, start_ip="10.61.1.100", end_ip="10.61.1.150")
    db_session.add(pool)
    await db_session.flush()
    pid = pool.id
    await db_session.commit()
    await _del(client, h, f"/api/v1/dhcp/scopes/{scid}")
    row = await _get(db_session, DHCPPool, pid)
    row.deleted_at = None
    row.deletion_batch_id = None
    await db_session.commit()

    resp = await _purge(client, h, "dhcp_scope", scid)
    assert resp.status_code == 409, resp.text
    assert await _get(db_session, DHCPPool, pid) is not None


@pytest.mark.asyncio
async def test_a_trashed_subnet_under_a_live_block_under_a_trashed_space(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{t.subnet}")
    await _del(client, h, f"/api/v1/ipam/spaces/{t.space}")
    # The legacy state: the blocks came back, the space did not.
    await db_session.execute(
        text(
            "UPDATE ip_block SET deleted_at = NULL, deletion_batch_id = NULL " "WHERE space_id = :s"
        ),
        {"s": t.space},
    )
    await db_session.commit()

    resp = await _restore(client, h, "subnet", t.subnet)
    assert resp.status_code == 409, resp.text
    c = resp.json()["detail"]["conflicts"][0]
    assert c["parent_type"] == "ip_space" and c["parent_id"] == str(t.space)

    purge = await _purge(client, h, "ip_space", t.space)
    assert purge.status_code == 409, purge.text
    assert await _get(db_session, IPBlock, t.outer) is not None
    assert await _get(db_session, Subnet, t.subnet) is not None


@pytest.mark.asyncio
async def test_a_refused_restore_names_the_parent_row_to_restore(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    t = await _tree(db_session)
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{t.subnet}")
    await _del(client, h, f"/api/v1/ipam/blocks/{t.inner}")
    resp = await _restore(client, h, "subnet", t.subnet)
    c = resp.json()["detail"]["conflicts"][0]
    assert (c["parent_type"], c["parent_id"]) == ("ip_block", str(t.inner))
    assert c["parent_display"].startswith("10.61.0.0/20")


@pytest.mark.asyncio
async def test_restoring_a_block_over_a_live_sibling_does_not_reparent_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The create path accepts a strict supernet and re-parents what it covers;
    a restore must refuse instead of doing that silently."""
    h = await _admin(db_session)
    space = IPSpace(name=f"th-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    sp = space.id
    small = IPBlock(space_id=sp, network="10.97.0.0/17", name="small")
    db_session.add(small)
    await db_session.flush()
    smid = small.id
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/blocks/{smid}")
    big = IPBlock(space_id=sp, network="10.97.0.0/16", name="big")
    db_session.add(big)
    await db_session.commit()
    bid = big.id
    await _del(client, h, f"/api/v1/ipam/blocks/{bid}")
    db_session.add(IPBlock(space_id=sp, network="10.97.0.0/18", name="new"))
    await db_session.commit()

    resp = await _restore(client, h, "ip_block", bid)
    assert resp.status_code == 409, resp.text
    assert "10.97.0.0/18" in resp.json()["detail"]["conflicts"][0]["reason"]
    new = (
        await db_session.execute(select(IPBlock).where(IPBlock.network == "10.97.0.0/18"))
    ).scalar_one()
    assert new.parent_block_id is None


@pytest.mark.asyncio
async def test_restoring_an_ipv6_subnet_that_overlaps_a_live_one_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    space = IPSpace(name=f"th-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    blk = IPBlock(space_id=space.id, network="2001:db8::/48", name="v6")
    db_session.add(blk)
    await db_session.flush()
    sub = Subnet(space_id=space.id, block_id=blk.id, network="2001:db8:0:1::/64", name="v6")
    db_session.add(sub)
    await db_session.flush()
    sp, bid, sid = space.id, blk.id, sub.id
    await db_session.commit()
    await _del(client, h, f"/api/v1/ipam/subnets/{sid}")
    db_session.add(Subnet(space_id=sp, block_id=bid, network="2001:db8:0:1::/80", name="n"))
    await db_session.commit()

    resp = await _restore(client, h, "subnet", sid)
    assert resp.status_code == 409, resp.text
    assert "2001:db8:0:1::/80" in resp.json()["detail"]["conflicts"][0]["reason"]
