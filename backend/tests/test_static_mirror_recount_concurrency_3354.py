"""#3354 — freeing static_dhcp mirrors recounts without deadlocking writers.

The reservation-mirror paths recount the subnets they freed and their block
chains (#3354), with the lock order #3345 fixed for every recount: the
audit-chain lock, then subnets by id, then blocks by id. These tests run a
DHCP import Overwrite and the orphan-mirror sweep for real, each on its own
connection, at the same moment as subnet creates and address allocations
under the same block (the ``concurrent_client`` approach of
``test_recount_concurrency_3345``), and then check every cached figure
against the rows.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import upsert_ipam_for_static
from app.services.ipam.utilization import counts_toward_utilization
from tests import test_recount_concurrency_3345 as _c3345
from tests.test_recount_concurrency_3345 import _admin_headers, _fresh

# The same fixture: every request on its own session + connection.
concurrent_client = _c3345.concurrent_client

_ROUNDS = 3
_SUBNETS = 3  # scopes overwritten / swept per round


async def _tree(db: AsyncSession, second_octet: int) -> tuple[IPSpace, IPBlock, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    root = IPBlock(space_id=space.id, network=f"10.{second_octet}.0.0/16", name="root")
    db.add(root)
    await db.flush()
    block = IPBlock(
        space_id=space.id,
        parent_block_id=root.id,
        network=f"10.{second_octet}.0.0/17",
        name="b",
    )
    db.add(block)
    await db.flush()
    return space, root, block


async def _mirrored(db: AsyncSession, scope: DHCPScope, subnet: Subnet, tag: str) -> None:
    """Two reservations on ``scope``, each with its static_dhcp IPAM mirror."""
    net = str(subnet.network).rsplit(".", 1)[0]
    for n in (10, 11):
        st = DHCPStaticAssignment(
            scope_id=scope.id,
            ip_address=f"{net}.{n}",
            mac_address=f"aa:bb:{tag}:{n:02x}:00:01",
            hostname=f"r{n}",
            description="",
        )
        db.add(st)
        await db.flush()
        await upsert_ipam_for_static(db, scope, st)


async def _assert_counts(db: AsyncSession, root: IPBlock, block: IPBlock) -> None:
    """Every subnet's cached count matches its rows; both blocks sum them."""
    subnets = (await db.execute(select(Subnet).where(Subnet.block_id == block.id))).scalars().all()
    expected = 0
    for s in subnets:
        s = await _fresh(db, Subnet, s.id)
        rows = (
            await db.execute(
                select(func.count())
                .select_from(IPAddress)
                .where(IPAddress.subnet_id == s.id)
                .where(counts_toward_utilization())
            )
        ).scalar_one()
        assert s.allocated_ips == rows, (str(s.network), s.allocated_ips, rows)
        expected += rows + 2  # a subnet's network + broadcast count in its block
    assert (await _fresh(db, IPBlock, block.id)).allocated_ips == expected
    assert (await _fresh(db, IPBlock, root.id)).allocated_ips == expected


def _writers(
    client: AsyncClient,
    headers: dict[str, str],
    space: IPSpace,
    block: IPBlock,
    subnets: list[Subnet],
    second_octet: int,
    rnd: int,
) -> list[Any]:
    """Subnet creates under ``block`` and address allocations into the very
    subnets whose mirrors the other side is freeing."""
    creates = [
        client.post(
            "/api/v1/ipam/subnets",
            headers=headers,
            json={
                "space_id": str(space.id),
                "block_id": str(block.id),
                "network": f"10.{second_octet}.{rnd * 10 + i}.0/24",
                "name": f"c{rnd}-{i}",
                "skip_reverse_zone": True,
            },
        )
        for i in range(4)
    ]
    allocs = [
        client.post(
            f"/api/v1/ipam/subnets/{sn.id}/addresses",
            headers=headers,
            json={
                "address": f"{str(sn.network).rsplit('.', 1)[0]}.{100 + rnd * 2 + k}",
                "hostname": f"h{rnd}-{k}",
                "dns_zone_id": "",
            },
        )
        for sn in subnets
        for k in range(2)
    ]
    return creates + allocs


@pytest.mark.asyncio
async def test_import_overwrite_races_creates_and_allocations(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    """A Kea import Overwriting three mirrored scopes runs at the same moment
    as four subnet creates and six address allocations under the same block."""
    from app.services.dhcp_import import commit_import, parse_kea_config

    headers = await _admin_headers(db_session)
    importer = User(
        username=f"imp-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="imp",
        hashed_password="x",
        is_superadmin=True,
    )
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add_all([importer, grp])
    space, root, block = await _tree(db_session, 41)
    subnets = []
    for i in range(_SUBNETS):
        sn = Subnet(
            space_id=space.id,
            block_id=block.id,
            network=f"10.41.{100 + i}.0/24",
            name=f"m{i}",
            total_ips=254,
        )
        db_session.add(sn)
        subnets.append(sn)
    await db_session.commit()

    cidrs = [str(sn.network) for sn in subnets]
    conf = (
        '{"Dhcp4": {"subnet4": ['
        + ", ".join(
            f'{{"subnet": "{c}", "reservations": [{{"hw-address": '
            f'"aa:bb:cc:09:{i:02x}:01", "ip-address": "{c.rsplit(".", 1)[0]}.50"}}]}}'
            for i, c in enumerate(cidrs)
        )
        + "]}}"
    ).encode()

    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        for rnd in range(_ROUNDS):
            # Each round overwrites scopes that hold freshly mirrored
            # reservations, so there is always something for it to free.
            for i, sn in enumerate(subnets):
                scope = (
                    await db_session.execute(
                        select(DHCPScope).where(
                            DHCPScope.subnet_id == sn.id, DHCPScope.group_id == grp.id
                        )
                    )
                ).scalar_one_or_none()
                if scope is None:
                    scope = DHCPScope(group_id=grp.id, subnet_id=sn.id, is_active=True)
                    db_session.add(scope)
                    await db_session.flush()
                await _mirrored(db_session, scope, sn, f"{rnd:x}{i:x}")
            await db_session.commit()

            async def _import() -> Any:
                async with factory() as db:
                    user = await db.get(User, importer.id)
                    return await commit_import(
                        db,
                        preview=parse_kea_config(conf),
                        target_group_id=grp.id,
                        ipam_space_id=None,
                        ipam_block_id=None,
                        conflict_actions={c: "overwrite" for c in cidrs},
                        current_user=user,
                    )

            results = await asyncio.wait_for(
                asyncio.gather(
                    _import(),
                    *_writers(concurrent_client, headers, space, block, subnets, 41, rnd),
                ),
                timeout=120,
            )
            imported, responses = results[0], results[1:]
            assert [s.action_taken for s in imported.scopes] == ["overwrote"] * _SUBNETS, [
                (s.action_taken, s.error) for s in imported.scopes
            ]
            assert [r.status_code for r in responses] == [201] * len(responses), [
                (r.status_code, r.text[:300]) for r in responses if r.status_code != 201
            ]
    finally:
        await engine.dispose()

    # The overwrite freed every mirror it found; only the allocations remain.
    for sn in subnets:
        mirrors = (
            await db_session.execute(
                select(func.count())
                .select_from(IPAddress)
                .where(IPAddress.subnet_id == sn.id, IPAddress.status == "static_dhcp")
            )
        ).scalar_one()
        assert mirrors == 0
    await _assert_counts(db_session, root, block)


@pytest.mark.asyncio
async def test_orphan_mirror_sweep_races_creates_and_allocations(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    """The hourly orphan sweep frees stranded reservation mirrors in three
    subnets while subnet creates and allocations land under the same block."""
    from app.tasks.dhcp_mirror_sweep import _sweep

    headers = await _admin_headers(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(grp)
    space, root, block = await _tree(db_session, 42)
    subnets = []
    scopes = []
    for i in range(_SUBNETS):
        sn = Subnet(
            space_id=space.id,
            block_id=block.id,
            network=f"10.42.{100 + i}.0/24",
            name=f"o{i}",
            total_ips=254,
        )
        db_session.add(sn)
        await db_session.flush()
        scope = DHCPScope(group_id=grp.id, subnet_id=sn.id, is_active=True)
        db_session.add(scope)
        await db_session.flush()
        subnets.append(sn)
        scopes.append(scope)
    await db_session.commit()

    for rnd in range(_ROUNDS):
        # Strand fresh mirrors: the reservations go by Core DELETE, which
        # runs no Python, exactly the leftover the sweep exists for.
        for i, (sn, scope) in enumerate(zip(subnets, scopes)):
            await _mirrored(db_session, scope, sn, f"{rnd:x}{i:x}")
        await db_session.execute(
            DHCPStaticAssignment.__table__.delete().where(
                DHCPStaticAssignment.scope_id.in_([s.id for s in scopes])
            )
        )
        await db_session.commit()

        results = await asyncio.wait_for(
            asyncio.gather(
                _sweep(),
                *_writers(concurrent_client, headers, space, block, subnets, 42, rnd),
            ),
            timeout=120,
        )
        freed, responses = results[0], results[1:]
        assert freed == 2 * _SUBNETS
        assert [r.status_code for r in responses] == [201] * len(responses), [
            (r.status_code, r.text[:300]) for r in responses if r.status_code != 201
        ]

    await _assert_counts(db_session, root, block)
