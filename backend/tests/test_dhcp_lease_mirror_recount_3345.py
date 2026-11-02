"""#3345 — the DHCP lease-mirror pipeline recounts utilization.

Every path that creates or deletes an ``auto_from_lease`` IPAM row now
recounts the touched subnets and their block chain in the same transaction,
once per batch rather than once per lease.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import event, select
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _auth_agent
from app.main import app
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _seed(db: AsyncSession, *, driver: str = "kea") -> tuple[DHCPServer, Subnet, IPBlock]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.90.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.90.1.0/24", name="s")
    db.add(subnet)
    server = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add(server)
    await db.flush()
    db.add(DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True))
    await db.flush()
    return server, subnet, block


def _ev(i: int, state: str = "active") -> dict[str, Any]:
    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return {
        "ip_address": f"10.90.1.{i}",
        "mac_address": f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}",
        "hostname": f"h{i}",
        "state": state,
        "starts_at": datetime.now(UTC).isoformat(),
        "ends_at": end,
        "expires_at": end,
    }


async def _post(client: AsyncClient, server: DHCPServer, events: list[dict[str, Any]]) -> Any:
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        return await client.post("/api/v1/dhcp/agents/lease-events", json={"leases": events})
    finally:
        app.dependency_overrides.pop(_auth_agent, None)


async def _counts(db: AsyncSession, subnet: Subnet, block: IPBlock) -> tuple[int, int]:
    s = (
        await db.execute(
            select(Subnet.allocated_ips)
            .where(Subnet.id == subnet.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    b = (
        await db.execute(
            select(IPBlock.allocated_ips)
            .where(IPBlock.id == block.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return s, b


async def _mirror(db: AsyncSession, subnet: Subnet, ip: str, *, mac: str) -> IPAddress:
    row = IPAddress(
        subnet_id=subnet.id, address=ip, status="dhcp", mac_address=mac, auto_from_lease=True
    )
    db.add(row)
    await db.flush()
    return row


@pytest.mark.asyncio
async def test_lease_events_create_and_release_recount(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, block = await _seed(db_session)
    await db_session.commit()

    assert (await _post(client, server, [_ev(10), _ev(11), _ev(12)])).status_code == 200
    s, b = await _counts(db_session, subnet, block)
    assert s == 3
    assert b == 3 + 2  # the subnet's network + broadcast count in its block

    assert (await _post(client, server, [_ev(11, "released")])).status_code == 200
    s, b = await _counts(db_session, subnet, block)
    assert (s, b) == (2, 4)


@pytest.mark.asyncio
async def test_pull_leases_create_and_absence_delete_recount(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.dhcp import pull_leases as pl

    server, subnet, block = await _seed(db_session, driver="windows_dhcp")
    await db_session.commit()

    class _Driver:
        def __init__(self, leases: list[dict[str, Any]]) -> None:
            self.leases = leases

        async def get_leases(self, _s: DHCPServer) -> list[dict[str, Any]]:
            return self.leases

    wire = [
        {"ip_address": "10.90.1.20", "mac_address": "aa:bb:cc:00:00:20"},
        {"ip_address": "10.90.1.21", "mac_address": "aa:bb:cc:00:00:21"},
    ]
    drv = _Driver(wire)
    monkeypatch.setattr(pl, "get_driver", lambda _d: drv)
    monkeypatch.setattr(pl, "is_agentless", lambda _d: True)
    import app.services.dns.ddns as ddns

    async def _noop(*a: Any, **k: Any) -> None:
        return None

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", _noop)
    monkeypatch.setattr(ddns, "revoke_ddns_for_lease", _noop)

    await pl.pull_leases_from_server(db_session, server, apply=True)
    await db_session.commit()
    assert await _counts(db_session, subnet, block) == (2, 4)

    # .21 disappears from the wire (non-empty so the #482 floor guard passes).
    drv.leases = [wire[0]]
    await pl.pull_leases_from_server(db_session, server, apply=True)
    await db_session.commit()
    assert await _counts(db_session, subnet, block) == (1, 3)


@pytest.mark.asyncio
async def test_expiry_sweep_recounts(db_session: AsyncSession) -> None:
    import app.tasks.dhcp_lease_cleanup as cleanup

    server, subnet, block = await _seed(db_session)
    await _mirror(db_session, subnet, "10.90.1.30", mac="aa:bb:cc:00:00:30")
    db_session.add(
        DHCPLease(
            server_id=server.id,
            ip_address="10.90.1.30",
            mac_address="aa:bb:cc:00:00:30",
            state="active",
            expires_at=datetime.now(UTC) - timedelta(hours=2),
        )
    )
    await db_session.commit()
    # Stale cached figures, as the pipeline used to leave them.
    from app.services.ipam.utilization import recount_subnets_and_blocks

    await recount_subnets_and_blocks(db_session, [subnet.id])
    await db_session.commit()
    assert await _counts(db_session, subnet, block) == (1, 3)

    cleaned, _ = await cleanup._sweep()
    assert cleaned == 1
    assert await _counts(db_session, subnet, block) == (0, 2)


@pytest.mark.asyncio
async def test_orphan_mirror_sweep_recounts(db_session: AsyncSession) -> None:
    from app.services.dhcp.lease_cleanup import sweep_orphaned_lease_mirrors
    from app.services.ipam.utilization import recount_subnets_and_blocks

    _server, subnet, block = await _seed(db_session)
    row = await _mirror(db_session, subnet, "10.90.1.40", mac="aa:bb:cc:00:00:40")
    row.last_seen_at = datetime.now(UTC) - timedelta(hours=3)
    await recount_subnets_and_blocks(db_session, [subnet.id])
    await db_session.commit()
    assert await _counts(db_session, subnet, block) == (1, 3)

    assert await sweep_orphaned_lease_mirrors(db_session) == 1
    await db_session.commit()
    assert await _counts(db_session, subnet, block) == (0, 2)


@pytest.mark.asyncio
async def test_purge_lease_recounts(db_session: AsyncSession) -> None:
    from app.services.dhcp.lease_cleanup import purge_lease
    from app.services.ipam.utilization import recount_subnets_and_blocks

    server, subnet, block = await _seed(db_session)
    await _mirror(db_session, subnet, "10.90.1.50", mac="aa:bb:cc:00:00:50")
    lease = DHCPLease(
        server_id=server.id,
        ip_address="10.90.1.50",
        mac_address="aa:bb:cc:00:00:50",
        state="expired",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    db_session.add(lease)
    await recount_subnets_and_blocks(db_session, [subnet.id])
    await db_session.commit()
    assert await _counts(db_session, subnet, block) == (1, 3)

    assert await purge_lease(db_session, lease, subnet_id=subnet.id) is True
    await db_session.commit()
    assert await _counts(db_session, subnet, block) == (0, 2)


@pytest.mark.asyncio
async def test_recount_is_one_batch_for_a_100_lease_post(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One recount call per batch, and its SQL does not scale with leases."""
    import app.api.v1.dhcp.agents as agents

    server, subnet, block = await _seed(db_session)
    await db_session.commit()

    real = agents.recount_subnets_and_blocks
    calls: list[int] = []
    stmts: list[str] = []

    def _count(conn: Any, cur: Any, statement: str, *a: Any) -> None:
        stmts.append(statement)

    async def _wrapped(db: AsyncSession, ids: Any) -> None:
        ids = list(ids)
        calls.append(len(ids))
        stmts.clear()
        event.listen(Engine, "before_cursor_execute", _count)
        try:
            await real(db, ids)
        finally:
            event.remove(Engine, "before_cursor_execute", _count)

    monkeypatch.setattr(agents, "recount_subnets_and_blocks", _wrapped)

    r = await _post(client, server, [_ev(i) for i in range(10, 110)])
    assert r.status_code == 200, r.text
    assert calls == [1], "one recount for the whole batch, over one subnet"
    assert len(stmts) <= 8, f"recount statements must not scale with leases: {len(stmts)}"
    assert (await _counts(db_session, subnet, block))[0] == 100
