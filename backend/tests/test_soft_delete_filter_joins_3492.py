"""#3492 — the soft-delete filter reaches models behind a JOIN or a subquery.

The global ``do_orm_execute`` hook used to look only at the outer entity, the
selected columns and FROM-subqueries (#1933). A soft-deletable model reached
only through a ``JOIN``, an ``EXISTS``, an ``IN (subquery)``, a CTE or a scalar
subquery got no ``deleted_at IS NULL``, so a trashed subnet's / zone's rows
came back through the join.

The compile tests pin every shape from the issue; the DB tests show the rows
actually stop coming back, and that ``include_deleted`` still opts out.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import exists, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

import app.models  # noqa: F401 — register every mapper
from app.db import _apply_soft_delete_filter
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.vlans import VLAN


def _sql(stmt: object) -> str:
    compiled = _apply_soft_delete_filter(stmt).compile(dialect=postgresql.dialect())
    return " ".join(str(compiled).split())


def _cte_shape() -> object:
    cte = select(Subnet.id).cte("live_subnets")
    return select(IPAddress.id).where(IPAddress.subnet_id.in_(select(cte.c.id)))


# (label, statement factory, table whose filter must appear)
_SHAPES = [
    (
        "join",
        lambda: select(IPAddress.id).join(Subnet, Subnet.id == IPAddress.subnet_id),
        "subnet",
    ),
    (
        "join_entity",
        lambda: select(IPAddress).join(Subnet, Subnet.id == IPAddress.subnet_id),
        "subnet",
    ),
    (
        "select_from_join",
        lambda: select(func.count())
        .select_from(IPAddress)
        .join(Subnet, Subnet.id == IPAddress.subnet_id),
        "subnet",
    ),
    (
        "aliased_join",
        lambda: (lambda s: select(IPAddress.id).join(s, s.id == IPAddress.subnet_id))(
            aliased(Subnet)
        ),
        "subnet_1",
    ),
    (
        "exists",
        lambda: select(IPAddress.id).where(exists().where(Subnet.id == IPAddress.subnet_id)),
        "subnet",
    ),
    (
        "select_exists",
        lambda: select(IPAddress.id).where(
            select(Subnet.id).where(Subnet.id == IPAddress.subnet_id).exists()
        ),
        "subnet",
    ),
    (
        "in_select",
        lambda: select(IPAddress.id).where(IPAddress.subnet_id.in_(select(Subnet.id))),
        "subnet",
    ),
    (
        "in_subquery",
        lambda: (lambda sq: select(IPAddress.id).where(IPAddress.subnet_id.in_(select(sq.c.id))))(
            select(Subnet.id).subquery()
        ),
        "subnet",
    ),
    ("in_cte", _cte_shape, "subnet"),
    (
        "scalar_subquery_column",
        lambda: select(
            VLAN.id,
            select(func.count())
            .where(Subnet.vlan_ref_id == VLAN.id)
            .scalar_subquery()
            .label("subnets"),
        ),
        "subnet",
    ),
    (
        "scalar_subquery_order_by",
        lambda: select(IPAddress.id).order_by(
            select(Subnet.name).where(Subnet.id == IPAddress.subnet_id).scalar_subquery()
        ),
        "subnet",
    ),
    (
        "where_only_core_count",
        lambda: select(func.count()).where(Subnet.block_id == IPBlock.id),
        "subnet",
    ),
    (
        "nested",
        lambda: select(IPAddress.id).where(
            IPAddress.subnet_id.in_(
                select(Subnet.id).where(
                    Subnet.block_id.in_(select(IPBlock.id).where(IPBlock.name == "x"))
                )
            )
        ),
        "ip_block",
    ),
]


@pytest.mark.parametrize(("label", "factory", "table"), _SHAPES, ids=[s[0] for s in _SHAPES])
def test_every_shape_gets_the_filter(label: str, factory: object, table: str) -> None:
    sql = _sql(factory())  # type: ignore[operator]
    assert f"{table}.deleted_at IS NULL" in sql, sql


def test_nested_filters_every_level() -> None:
    sql = _sql(_SHAPES[-1][1]())  # type: ignore[operator]
    assert "subnet.deleted_at IS NULL" in sql
    assert "ip_block.deleted_at IS NULL" in sql


def test_outer_join_keeps_its_meaning() -> None:
    """The predicate goes in the ON clause, never the WHERE, so an outer
    join still returns the rows that have no (live) match."""
    sql = _sql(select(IPAddress.id).outerjoin(Subnet, Subnet.id == IPAddress.subnet_id))
    on_clause, _, where = sql.partition(" WHERE ")
    assert "LEFT OUTER JOIN subnet ON" in on_clause
    assert "subnet.deleted_at IS NULL" in on_clause
    assert "deleted_at" not in where


def test_statement_with_no_soft_model_is_untouched() -> None:
    stmt = select(VLAN.id)
    assert _apply_soft_delete_filter(stmt) is stmt


def test_one_filter_per_occurrence_in_the_common_shapes() -> None:
    """The WHERE-only pass must not duplicate what the loader criteria
    already add, or every ordinary query grows a redundant predicate."""
    for stmt in (
        select(Subnet.id),
        select(Subnet).where(Subnet.name == "x"),
        select(func.count(Subnet.id)),
        select(func.count()).select_from(Subnet).where(Subnet.name == "x"),
        select(IPAddress.id).where(IPAddress.subnet_id.in_(select(Subnet.id))),
    ):
        assert _sql(stmt).count("deleted_at IS NULL") == 1, _sql(stmt)


# ── Behaviour against a real database ────────────────────────────────────────


async def _seed(db: AsyncSession) -> tuple[Subnet, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.92.0.0/16", name="b")
    db.add(block)
    await db.flush()
    live = Subnet(space_id=space.id, block_id=block.id, network="10.92.1.0/24", name="live")
    gone = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.92.2.0/24",
        name="gone",
        deleted_at=datetime.now(UTC),
    )
    db.add_all([live, gone])
    await db.flush()
    db.add_all(
        [
            IPAddress(subnet_id=live.id, address="10.92.1.10", status="allocated"),
            IPAddress(subnet_id=gone.id, address="10.92.2.10", status="allocated"),
        ]
    )
    await db.flush()
    return live, gone


@pytest.mark.asyncio
async def test_join_drops_rows_under_a_trashed_subnet(db_session: AsyncSession) -> None:
    await _seed(db_session)
    stmt = select(IPAddress.address).join(Subnet, Subnet.id == IPAddress.subnet_id)
    rows = [str(a) for a in (await db_session.execute(stmt)).scalars()]
    assert rows == ["10.92.1.10"]
    opted_out = stmt.execution_options(include_deleted=True)
    assert len((await db_session.execute(opted_out)).all()) == 2


@pytest.mark.asyncio
async def test_exists_and_in_subquery_drop_a_trashed_subnet(db_session: AsyncSession) -> None:
    await _seed(db_session)
    via_exists = select(IPAddress.address).where(
        exists().where(Subnet.id == IPAddress.subnet_id, Subnet.name.in_(["live", "gone"]))
    )
    via_in = select(IPAddress.address).where(
        IPAddress.subnet_id.in_(select(Subnet.id).where(Subnet.name.in_(["live", "gone"])))
    )
    for stmt in (via_exists, via_in):
        assert [str(a) for a in (await db_session.execute(stmt)).scalars()] == ["10.92.1.10"]


@pytest.mark.asyncio
async def test_scalar_subquery_count_skips_a_trashed_subnet(db_session: AsyncSession) -> None:
    live, _gone = await _seed(db_session)
    count = (
        select(func.count())
        .where(Subnet.block_id == IPBlock.id, Subnet.name.in_(["live", "gone"]))
        .scalar_subquery()
    )
    stmt = select(IPBlock.id, count).where(IPBlock.id == live.block_id)
    _, n = (await db_session.execute(stmt)).one()
    assert n == 1


@pytest.mark.asyncio
async def test_record_join_skips_a_trashed_zone(db_session: AsyncSession) -> None:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zones = []
    for name, deleted in (("live.example.", None), ("gone.example.", datetime.now(UTC))):
        z = DNSZone(
            group_id=grp.id,
            name=name,
            zone_type="primary",
            kind="forward",
            primary_ns=f"ns1.{name}",
            admin_email=f"admin.{name}",
            deleted_at=deleted,
        )
        db_session.add(z)
        zones.append(z)
    await db_session.flush()
    # A live record left under a trashed zone: the zone's own delete would
    # stamp it, so this is the leak the join used to expose.
    for z in zones:
        db_session.add(
            DNSRecord(
                zone_id=z.id,
                name="www",
                fqdn=f"www.{z.name}",
                record_type="A",
                value="192.0.2.1",
            )
        )
    await db_session.flush()
    stmt = (
        select(DNSRecord.fqdn)
        .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
        .where(DNSZone.group_id == grp.id)
    )
    assert list((await db_session.execute(stmt)).scalars()) == ["www.live.example."]


# ── Reference checks that must still see the Trash ──────────────────────────


@pytest.mark.asyncio
async def test_release_keeps_a_block_or_subnet_a_trashed_child_hangs_off(
    db_session: AsyncSession,
) -> None:
    """``release_outside_space`` deletes an integration's pure-mirror subnet or
    block, but only when nothing hangs off it. A child in the Trash still
    does: a trashed subnet's ``RESTRICT`` FK would fail the block's delete,
    and a trashed scope would cascade away with its subnet. Once the filter
    reached those ``EXISTS`` checks, both looked empty; they now count
    trashed rows explicitly."""
    from app.models.dhcp import DHCPScope, DHCPServerGroup
    from app.models.docker import DockerHost
    from app.services.integration_ownership import release_outside_space

    old = IPSpace(name=f"old-{uuid.uuid4().hex[:6]}")
    new = IPSpace(name=f"new-{uuid.uuid4().hex[:6]}")
    db_session.add_all([old, new])
    await db_session.flush()
    host = DockerHost(
        name=f"d-{uuid.uuid4().hex[:6]}",
        connection_type="tcp",
        endpoint=f"{uuid.uuid4().hex[:6]}.example.test:2376",
        ipam_space_id=old.id,
        client_key_encrypted=b"",
    )
    db_session.add(host)
    await db_session.flush()
    # ``block`` holds only a trashed subnet; ``other`` holds the owned subnet.
    block = IPBlock(
        space_id=old.id, network="10.93.0.0/16", name="mirror-b", docker_host_id=host.id
    )
    other = IPBlock(
        space_id=old.id, network="10.94.0.0/16", name="mirror-o", docker_host_id=host.id
    )
    db_session.add_all([block, other])
    await db_session.flush()
    trashed = Subnet(
        space_id=old.id,
        block_id=block.id,
        network="10.93.1.0/24",
        name="trashed",
        deleted_at=datetime.now(UTC),
    )
    owned = Subnet(
        space_id=old.id,
        block_id=other.id,
        network="10.94.2.0/24",
        name="mirror-s",
        docker_host_id=host.id,
    )
    db_session.add_all([trashed, owned])
    await db_session.flush()
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    scope = DHCPScope(
        group_id=group.id,
        subnet_id=owned.id,
        name="trashed-scope",
        address_family="ipv4",
        deleted_at=datetime.now(UTC),
    )
    db_session.add(scope)
    await db_session.commit()
    block_id, owned_id, scope_id = block.id, owned.id, scope.id

    out = await release_outside_space(db_session, "docker_host_id", host.id, [new.id])
    await db_session.commit()

    assert out.subnets_deleted == 0 and out.subnets_unclaimed == 1
    assert out.blocks_deleted == 0 and out.blocks_unclaimed == 2
    db_session.expire_all()
    assert await db_session.get(IPBlock, block_id) is not None
    assert await db_session.get(Subnet, owned_id) is not None
    kept = (
        await db_session.execute(
            select(DHCPScope.id)
            .where(DHCPScope.id == scope_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    assert kept == scope_id
