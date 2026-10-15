"""A server move and the worker's bundle render must not deadlock (#1703).

The worker's render holds ``FOR KEY SHARE`` on the ``dns_server`` row (the
bundle insert's foreign key) and then needs ``FOR NO KEY UPDATE`` for its
mirror UPDATE. The move used to demote the primary first (``FOR NO KEY
UPDATE``) and only then change ``group_id`` — a unique-index column, hence
``FOR UPDATE`` — which waits for the render, while the render waits for the
demotion: 40P01, the move rolled back whole, a bare 500.

Two real sessions, interleaved deterministically: the render's lock is taken
first, the move starts and blocks, then the render does its UPDATE.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select, text

from app.models.dns import DNSServer
from app.services.dns.server_move import move_server_to_group
from tests.conftest import _TestSessionLocal
from tests.test_dns_server_group_move import _group, _server


@pytest.mark.asyncio
async def test_move_and_render_serialise_instead_of_deadlocking(db_session) -> None:  # noqa: ANN001
    src = await _group(db_session, "src1703")
    dst = await _group(db_session, "dst1703")
    srv = await _server(db_session, src, "ns1", is_primary=True)
    await db_session.commit()
    server_id, dst_id = srv.id, dst.id

    task: asyncio.Task[None] | None = None
    render = _TestSessionLocal()
    mover = _TestSessionLocal()
    try:
        # Render side: the FK of the bundle insert's KEY SHARE on the row.
        await render.execute(
            select(DNSServer.id)
            .where(DNSServer.id == server_id)
            .with_for_update(read=True, key_share=True)
        )

        async def do_move() -> None:
            server = await mover.get(DNSServer, server_id)
            target = await mover.get(type(dst), dst_id)
            result = await move_server_to_group(mover, server, target)
            assert result is not None
            await mover.commit()

        task = asyncio.create_task(do_move())
        await asyncio.sleep(1.5)  # long enough for the move to reach its writes

        # Render side, second statement: its mirror UPDATE.
        await render.execute(
            text(
                "UPDATE dns_server SET bundle_render_count = bundle_render_count + 1 WHERE id = :i"
            ),
            {"i": server_id},
        )
        await render.commit()

        await asyncio.wait_for(task, timeout=15)  # DeadlockDetectedError on main
    finally:
        if task is not None and not task.done():
            task.cancel()
        await render.close()
        await mover.close()

    async with _TestSessionLocal() as check:
        row = (await check.execute(select(DNSServer).where(DNSServer.id == server_id))).scalar_one()
        assert row.group_id == dst_id
        assert row.bundle_render_count == 1
