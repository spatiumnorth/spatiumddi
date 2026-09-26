"""The ACME apply wait scales with the group's render time (#1184).

Since #1122 an agent receives a DNS change with the first render of its
bundle that starts after the change committed, and renders go through one
fleet-wide slot. QA measured one render of a 1.09M-record group at about
30 s, so the fixed 30 s wait for an ACME TXT record failed intermittently.
``apply_timeout_for`` sizes the wait from the stored ``render_ms`` of the
servers the ops target.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSAgentBundle, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services import acme as acme_svc
from app.services.acme import (
    APPLY_TIMEOUT_MARGIN_SECONDS,
    DEFAULT_APPLY_TIMEOUT_SECONDS,
    MAX_APPLY_TIMEOUT_SECONDS,
    PROVIDER_MAX_APPLY_TIMEOUT_SECONDS,
    apply_timeout_for,
)


async def _group(db: AsyncSession, servers: int) -> tuple[DNSServerGroup, list[DNSServer]]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(group)
    await db.flush()
    rows = []
    for i in range(servers):
        server = DNSServer(
            name=f"ns{i}-{uuid.uuid4().hex[:6]}",
            host=f"192.0.2.{i + 1}",
            port=53,
            driver="bind9",
            group_id=group.id,
            is_primary=i == 0,
            is_enabled=True,
        )
        db.add(server)
        rows.append(server)
    await db.flush()
    return group, rows


def _bundle(server: DNSServer, render_ms: int, watermark: int) -> DNSAgentBundle:
    return DNSAgentBundle(
        server_id=server.id,
        dirty_watermark=watermark,
        snapshot_at=datetime.now(UTC),
        etag=uuid.uuid4().hex,
        structural_etag=uuid.uuid4().hex,
        ships_ops=True,
        body=b"",
        body_bytes=0,
        body_gzip_bytes=0,
        records=0,
        render_ms=render_ms,
        rendered_by="worker",
    )


def _op(server: DNSServer) -> DNSRecordOp:
    return DNSRecordOp(
        server_id=server.id,
        zone_name="example.test.",
        op="create",
        record={"name": "_acme-challenge", "type": "TXT", "value": "x", "ttl": 60},
    )


async def _ops(db: AsyncSession, servers: list[DNSServer]) -> list[uuid.UUID]:
    ops = [_op(s) for s in servers]
    db.add_all(ops)
    await db.flush()
    return [o.id for o in ops]


async def test_no_stored_render_keeps_the_fixed_wait(db_session: AsyncSession) -> None:
    """An agentless driver, or a server not rendered yet: nothing to scale by."""
    _, servers = await _group(db_session, 1)
    op_ids = await _ops(db_session, servers)
    assert await apply_timeout_for(db_session, op_ids) == DEFAULT_APPLY_TIMEOUT_SECONDS
    assert await apply_timeout_for(db_session, []) == DEFAULT_APPLY_TIMEOUT_SECONDS


async def test_fast_renders_keep_the_floor(db_session: AsyncSession) -> None:
    _, servers = await _group(db_session, 1)
    db_session.add(_bundle(servers[0], 2_000, 1))
    op_ids = await _ops(db_session, servers)
    assert await apply_timeout_for(db_session, op_ids) == DEFAULT_APPLY_TIMEOUT_SECONDS


async def test_one_server_waits_two_renders(db_session: AsyncSession) -> None:
    """The render already in the slot, then the one that covers the op. The
    issue's 1.09M-record group: ~30 s a render, so 70 s, where 30 s failed."""
    _, servers = await _group(db_session, 1)
    db_session.add(_bundle(servers[0], 30_000, 1))
    op_ids = await _ops(db_session, servers)
    assert await apply_timeout_for(db_session, op_ids) == 2 * 30 + APPLY_TIMEOUT_MARGIN_SECONDS


async def test_every_target_server_renders_in_turn(db_session: AsyncSession) -> None:
    """Renders share one fleet-wide slot, so a three-server group waits for
    the render in the slot plus all three of its own, at the slowest."""
    _, servers = await _group(db_session, 3)
    for server, ms in zip(servers, (20_000, 30_000, 25_000), strict=True):
        db_session.add(_bundle(server, ms, 1))
    op_ids = await _ops(db_session, servers)
    assert await apply_timeout_for(db_session, op_ids) == 4 * 30 + APPLY_TIMEOUT_MARGIN_SECONDS


async def test_the_slowest_stored_render_counts(db_session: AsyncSession) -> None:
    """The store keeps the last few renders per server; a slow one among
    them is what the next render may take again."""
    _, servers = await _group(db_session, 1)
    db_session.add_all([_bundle(servers[0], 40_000, 1), _bundle(servers[0], 10_000, 2)])
    op_ids = await _ops(db_session, servers)
    assert await apply_timeout_for(db_session, op_ids) == 2 * 40 + APPLY_TIMEOUT_MARGIN_SECONDS


async def test_only_the_target_servers_count(db_session: AsyncSession) -> None:
    _, servers = await _group(db_session, 2)
    db_session.add_all([_bundle(servers[0], 20_000, 1), _bundle(servers[1], 90_000, 1)])
    op_ids = await _ops(db_session, servers[:1])
    assert await apply_timeout_for(db_session, op_ids) == 2 * 20 + APPLY_TIMEOUT_MARGIN_SECONDS


async def test_the_wait_is_capped(db_session: AsyncSession) -> None:
    _, servers = await _group(db_session, 3)
    for server in servers:
        db_session.add(_bundle(server, 120_000, 1))
    op_ids = await _ops(db_session, servers)
    assert await apply_timeout_for(db_session, op_ids) == MAX_APPLY_TIMEOUT_SECONDS
    assert (
        await apply_timeout_for(db_session, op_ids, cap=PROVIDER_MAX_APPLY_TIMEOUT_SECONDS)
        == PROVIDER_MAX_APPLY_TIMEOUT_SECONDS
    )


async def test_solve_waits_for_the_scaled_timeout(db_session: AsyncSession) -> None:
    """The embedded client's ``dns01.solve`` passes the scaled wait on."""
    from app.services.acme_client import dns01  # noqa: PLC0415

    group, servers = await _group(db_session, 2)
    zone = DNSZone(
        name="example.test.",
        zone_type="primary",
        kind="forward",
        group_id=group.id,
        primary_ns="ns1.example.test.",
        admin_email="hostmaster.example.test.",
    )
    db_session.add(zone)
    db_session.add_all([_bundle(servers[0], 30_000, 1), _bundle(servers[1], 25_000, 1)])
    await db_session.commit()

    async def _applied(op_ids: list[uuid.UUID], *, timeout: float) -> dict[uuid.UUID, str]:
        seen["timeout"] = timeout
        return {op_id: "applied" for op_id in op_ids}

    seen: dict[str, float] = {}
    with (
        patch.object(acme_svc, "wait_for_ops_applied", new=_applied),
        patch.object(dns01, "publish_wake", new=AsyncMock()),
    ):
        await dns01.solve(db_session, "host.example.test", "token-1184")
    # One op per server, so three renders: the one in the slot and both
    # servers' own.
    assert seen["timeout"] == 3 * 30 + APPLY_TIMEOUT_MARGIN_SECONDS
