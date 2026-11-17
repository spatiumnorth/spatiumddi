"""spatiumddi#3491: one space delete puts each object of its tree into the batch once.

For an ``IPSpace`` root the walk selects every block of the space, nested
ones included, and walks each one's subtree; the walk into a block walks its
child blocks again. A block two levels down, and everything under it, was
collected three times: as a block of the space, under its parent and under
its grandparent. The batch is stamped, audited and counted per row, so one
delete wrote two or three ``soft_delete`` audit rows for a nested block, its
subnets, their scopes and reservations, and the reverse zone a nested subnet
auto-created; the space delete's approval preview counted them as often.

The tree, under one space:

    L1 10.91.0.0/16
      L2 10.91.0.0/18
        L3 10.91.0.0/20
          s1 10.91.1.0/24  scope (a pool, two reservations), auto reverse zone
          s2 10.91.2.0/24  scope (two reservations)
          s3 10.91.3.0/24
        s4 10.91.32.0/24   scope (two reservations)
      E  10.91.192.0/18    (empty)
      s5 10.91.128.0/24    scope (two reservations)
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.ai.operations_risky import DeleteSpaceArgs, _preview_delete_space
from app.services.soft_delete import add_to_batch, collect_soft_delete_batch

Key = tuple[str, uuid.UUID]


async def _make_admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"sd-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Soft-Delete Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _nested_space(db: AsyncSession) -> dict[str, Any]:
    """Build the module docstring's tree and return its rows by name."""
    space = IPSpace(name=f"sd3491-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    l1 = IPBlock(space_id=space.id, network="10.91.0.0/16", name="L1")
    db.add(l1)
    await db.flush()
    l2 = IPBlock(space_id=space.id, parent_block_id=l1.id, network="10.91.0.0/18", name="L2")
    db.add(l2)
    await db.flush()
    l3 = IPBlock(space_id=space.id, parent_block_id=l2.id, network="10.91.0.0/20", name="L3")
    empty = IPBlock(space_id=space.id, parent_block_id=l1.id, network="10.91.192.0/18", name="E")
    db.add_all([l3, empty])
    await db.flush()
    subnets = {
        "s1": Subnet(space_id=space.id, block_id=l3.id, network="10.91.1.0/24", name="s1"),
        "s2": Subnet(space_id=space.id, block_id=l3.id, network="10.91.2.0/24", name="s2"),
        "s3": Subnet(space_id=space.id, block_id=l3.id, network="10.91.3.0/24", name="s3"),
        "s4": Subnet(space_id=space.id, block_id=l2.id, network="10.91.32.0/24", name="s4"),
        "s5": Subnet(space_id=space.id, block_id=l1.id, network="10.91.128.0/24", name="s5"),
    }
    db.add_all(subnets.values())
    dhcp_group = DHCPServerGroup(name=f"sd3491-{uuid.uuid4().hex[:6]}")
    db.add(dhcp_group)
    await db.flush()

    scopes: dict[str, DHCPScope] = {}
    statics: list[DHCPStaticAssignment] = []
    for n, key in enumerate(("s1", "s2", "s4", "s5"), start=1):
        sub = subnets[key]
        scope = DHCPScope(
            group_id=dhcp_group.id, subnet_id=sub.id, name=f"scope-{key}", address_family="ipv4"
        )
        db.add(scope)
        await db.flush()
        scopes[key] = scope
        prefix = str(sub.network).rsplit(".", 1)[0]
        for host in (10, 11):
            static = DHCPStaticAssignment(
                scope_id=scope.id,
                ip_address=f"{prefix}.{host}",
                mac_address=f"02:91:00:00:{n:02x}:{host:02x}",
            )
            statics.append(static)
            db.add(static)
    pool = DHCPPool(scope_id=scopes["s1"].id, start_ip="10.91.1.100", end_ip="10.91.1.199")
    db.add(pool)

    # The reverse zone s1 auto-created: a space delete retires it into the
    # same batch, once per s1 row it finds there (#2734).
    dns_group = DNSServerGroup(name=f"sd3491-{uuid.uuid4().hex[:6]}")
    db.add(dns_group)
    await db.flush()
    reverse = DNSZone(
        group_id=dns_group.id,
        name="1.91.10.in-addr.arpa.",
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
        is_auto_generated=True,
        linked_subnet_id=subnets["s1"].id,
    )
    db.add(reverse)
    await db.flush()
    db.add(
        DNSRecord(
            zone_id=reverse.id,
            name="10",
            fqdn="10.1.91.10.in-addr.arpa.",
            record_type="PTR",
            value="host.example.test.",
        )
    )
    await db.commit()
    return {
        "space": space,
        "blocks": {"L1": l1, "L2": l2, "L3": l3, "E": empty},
        "subnets": subnets,
        "scopes": scopes,
        "statics": statics,
        "pool": pool,
        "reverse": reverse,
    }


def _tree_keys(tree: dict[str, Any]) -> set[Key]:
    """Every object the space delete must trash: the space and all below it."""
    keys: set[Key] = {("ip_space", tree["space"].id)}
    keys |= {("ip_block", b.id) for b in tree["blocks"].values()}
    keys |= {("subnet", s.id) for s in tree["subnets"].values()}
    keys |= {("dhcp_scope", s.id) for s in tree["scopes"].values()}
    keys |= {("dhcp_static_assignment", s.id) for s in tree["statics"]}
    keys.add(("dhcp_pool", tree["pool"].id))
    return keys


def _parent_key(obj: Any) -> Key | None:
    if isinstance(obj, IPBlock):
        if obj.parent_block_id is not None:
            return ("ip_block", obj.parent_block_id)
        return ("ip_space", obj.space_id)
    if isinstance(obj, Subnet):
        return ("ip_block", obj.block_id)
    if isinstance(obj, DHCPScope):
        return ("subnet", obj.subnet_id)
    if isinstance(obj, (DHCPPool, DHCPStaticAssignment)):
        return ("dhcp_scope", obj.scope_id)
    return None


@pytest.mark.asyncio
async def test_space_batch_holds_each_object_of_a_nested_tree_once(
    db_session: AsyncSession,
) -> None:
    tree = await _nested_space(db_session)
    space = tree["space"]

    batch = await collect_soft_delete_batch(db_session, space)
    keys = [(row.resource_type, row.obj.id) for row in batch.rows]
    times = Counter(keys)
    dupes = sorted(
        {
            f"{k[0]} {row.display} x{times[k]}"
            for row, k in zip(batch.rows, keys, strict=True)
            if times[k] > 1
        }
    )
    assert not dupes, f"objects collected more than once: {dupes}"
    assert set(keys) == _tree_keys(tree)
    assert batch.counts() == {
        "ip_space": 1,
        "ip_block": 4,
        "subnet": 5,
        "dhcp_scope": 4,
        "dhcp_pool": 1,
        "dhcp_static_assignment": 8,
    }

    # The walk's order holds: every row after the rows below it, the root last.
    position = {key: i for i, key in enumerate(keys)}
    assert keys[-1] == ("ip_space", space.id)
    for row in batch.rows:
        parent = _parent_key(row.obj)
        if parent is not None:
            assert position[parent] > position[(row.resource_type, row.obj.id)], row.display

    # Control: a block delete reaches each child once, through its own parent.
    l1_batch = await collect_soft_delete_batch(db_session, tree["blocks"]["L1"])
    l1_keys = [(row.resource_type, row.obj.id) for row in l1_batch.rows]
    assert len(l1_keys) == len(set(l1_keys))
    assert set(l1_keys) == _tree_keys(tree) - {("ip_space", space.id)}


@pytest.mark.asyncio
async def test_add_to_batch_skips_rows_the_batch_already_holds(
    db_session: AsyncSession,
) -> None:
    """A root added to a batch twice, or reached again through another root,
    joins it once, and a zone's records are registered once (#1066, #1231)."""
    tree = await _nested_space(db_session)
    s1, reverse = tree["subnets"]["s1"], tree["reverse"]

    batch = await collect_soft_delete_batch(db_session, s1)
    before = [(row.resource_type, row.obj.id) for row in batch.rows]
    assert len(before) == 5  # s1, its scope, the pool, two reservations
    await add_to_batch(db_session, batch, s1)
    assert [(row.resource_type, row.obj.id) for row in batch.rows] == before

    await add_to_batch(db_session, batch, reverse)
    await add_to_batch(db_session, batch, reverse)
    zone_rows = [row for row in batch.rows if row.resource_type == "dns_zone"]
    assert len(zone_rows) == 1
    assert len(batch.bulk) == 1
    assert batch.counts()["dns_record"] == 1


@pytest.mark.asyncio
async def test_space_delete_writes_one_soft_delete_audit_row_per_object(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _make_admin(db_session)
    tree = await _nested_space(db_session)
    space = tree["space"]

    resp = await client.delete(f"/api/v1/ipam/spaces/{space.id}", headers=headers)
    assert resp.status_code == 204, resp.text

    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "soft_delete")))
        .scalars()
        .all()
    )
    per_object: dict[tuple[str, str], int] = {}
    for a in audits:
        key = (a.resource_type, a.resource_id)
        per_object[key] = per_object.get(key, 0) + 1
    repeated = {f"{rt} {rid}": n for (rt, rid), n in per_object.items() if n > 1}
    assert not repeated, f"one delete audited these objects more than once: {repeated}"

    expected = {(rt, str(i)) for rt, i in _tree_keys(tree)} | {
        ("dns_zone", str(tree["reverse"].id))
    }
    assert set(per_object) == expected

    batch_ids = {a.old_value["deletion_batch_id"] for a in audits}
    assert len(batch_ids) == 1
    zone_audit = next(a for a in audits if a.resource_type == "dns_zone")
    assert zone_audit.old_value.get("cascaded") == {"dns_record": 1}

    # Every row of the tree is in the Trash under that one batch.
    stamped = (
        (
            await db_session.execute(
                select(IPBlock)
                .where(IPBlock.space_id == space.id)
                .execution_options(include_deleted=True, populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert {str(b.deletion_batch_id) for b in stamped} == batch_ids


@pytest.mark.asyncio
async def test_space_delete_preview_counts_each_object_once(
    db_session: AsyncSession,
) -> None:
    """The two-person approval preview renders the batch's counts: they are
    the tree's, not the tree's times its nesting. (Only the counts this issue
    is about: what the preview says after them is not pinned here.)"""
    user, _ = await _make_admin(db_session)
    tree = await _nested_space(db_session)

    preview = await _preview_delete_space(
        db_session, user, DeleteSpaceArgs(space_id=tree["space"].id)
    )
    assert preview.ok, preview.detail
    assert (
        "cascades 4 child blocks, 5 subnets, 4 DHCP scopes, 1 DHCP pool, 8 DHCP reservations"
        in preview.preview_text
    ), preview.preview_text
