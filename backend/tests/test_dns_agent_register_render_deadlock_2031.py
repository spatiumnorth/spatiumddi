"""An agent registration's SOA-timer switch and the worker's bundle render
must not deadlock (#2031).

The reported cycle, as Postgres recorded it on a QA walk:

* the render had written the server row once (``bundle_render_count``) and
  was issuing its second write (the ``bundle_watermark`` mirror);
* the registration's ``_switch_soa_timers`` held the group row ``FOR UPDATE``
  (``reconcile_soa_timers``) and, marking the group's bundles at commit, was
  queued for the server row behind the render's first write.

A second UPDATE of a row the transaction already updated re-runs its foreign-
key checks whether or not a key changed — Postgres fires them whenever the old
version is the transaction's own — so the render's second write wanted
``FOR KEY SHARE`` on the group row the switch held ``FOR UPDATE``: 40P01. The
switch lost, logged ``dns_group_soa_timers_failed``, and only ran again at the
agent's first heartbeat.

Two real sessions on two connections, interleaved deterministically on
``pg_stat_activity`` (the #1703 harness). The render side holds the server row
when the marker queues for it — on main that was the window between the
render's two writes — and then runs the real ``agent_bundle_store.store``.
Every await is bounded and both backends run with a ``lock_timeout``.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import _switch_soa_timers
from app.models.dns import DNSAgentBundle, DNSServer, DNSServerGroup
from app.services.dns import agent_bundle_store as bundle_store
from app.services.dns.bundle_dirty import mark_bundles_dirty
from tests.conftest import _TestSessionLocal
from tests.test_dns_server_group_move import _group, _server
from tests.test_dns_server_move_render_deadlock_1703 import (
    _STEP,
    _cleanup,
    _prepare,
    _wait_blocked,
)


async def _agent_server(db: AsyncSession, name: str) -> tuple[uuid.UUID, uuid.UUID]:
    """A group serving the zones' own timers, with one BIND9 agent of an older
    release in it: the next switch turns the group's timers off and marks the
    agent's bundle."""
    group = await _group(db, name)
    server = await _server(
        db,
        group,
        "ns1",
        is_primary=True,
        agent_id=uuid.uuid4(),
        agent_renders_soa_timers=False,
    )
    await db.commit()
    assert group.serves_soa_timers is True
    return group.id, server.id


async def _store(render: AsyncSession, server_id: uuid.UUID) -> None:
    """The render's real store: the bundle INSERT (FK ``FOR KEY SHARE`` on the
    server) and its writes to the server row."""
    server = await asyncio.wait_for(render.get(DNSServer, server_id), _STEP)
    assert server is not None
    row = await asyncio.wait_for(
        bundle_store.store(
            render,
            server,
            dirty_watermark=int(server.bundle_dirty_seq),
            snapshot_at=datetime.now(UTC),
            etag="sha256:e2031",
            structural_etag="sha256:s2031",
            ships_ops=True,
            body_gz=bundle_store.compress_body(b"{}"),
            body_bytes=2,
            records=0,
            render_ms=1,
            rendered_by=bundle_store.RENDERED_BY_WORKER,
        ),
        _STEP,
    )
    assert row is not None
    await asyncio.wait_for(render.commit(), _STEP)


async def _render_holds_the_row_when_the_mark_queues(
    server_id: uuid.UUID, mark: Callable[[AsyncSession], Awaitable[None]]
) -> str:
    """Returns the statement the marker blocked in."""
    render = _TestSessionLocal()
    marker = _TestSessionLocal()
    pids: list[int] = []
    task: asyncio.Task[Any] | None = None
    try:
        pids.append(await _prepare(render))
        marker_pid = await _prepare(marker)
        pids.append(marker_pid)
        # The render is mid-write on the server row.
        await asyncio.wait_for(
            render.execute(
                select(DNSServer.id)
                .where(DNSServer.id == server_id)
                .with_for_update(key_share=True)
            ),
            _STEP,
        )

        task = asyncio.create_task(mark(marker))
        blocked_in = await _wait_blocked(marker_pid, task)

        # The marker is queued for the server row. The render's writes must
        # still go through, then the marker's commit.
        await _store(render, server_id)  # DeadlockDetectedError on main, or:
        await asyncio.wait_for(task, _STEP)  # ... the marker lost it instead
        return blocked_in
    finally:
        await _cleanup(task, [render, marker], pids)


async def _assert_rendered_and_marked(server_id: uuid.UUID) -> DNSServer:
    async with _TestSessionLocal() as check:
        row = (
            await asyncio.wait_for(
                check.execute(select(DNSServer).where(DNSServer.id == server_id)), _STEP
            )
        ).scalar_one()
        # The render's store landed whole...
        assert row.bundle_render_count == 1
        assert row.bundle_etag == "sha256:e2031"
        bundles = (
            await check.execute(
                select(func.count())
                .select_from(DNSAgentBundle)
                .where(DNSAgentBundle.server_id == server_id)
            )
        ).scalar_one()
        assert bundles == 1
        # ... and so did the mark behind it, so the stored bundle is stale by
        # its own accounting and is rendered again.
        assert row.bundle_dirty_seq > row.bundle_watermark
        assert row.bundle_dirty_at is not None
        return row


@pytest.mark.asyncio
async def test_the_registration_switch_waits_for_an_in_flight_render(
    db_session: AsyncSession,
) -> None:
    """The reported request: registration's ``_switch_soa_timers`` turns the
    group's timers off while the render of the agent's bundle is storing."""
    group_id, server_id = await _agent_server(db_session, "g2031")

    async def switch(marker: AsyncSession) -> None:
        # It never raises: it logs ``dns_group_soa_timers_failed`` and rolls
        # back, which is what the walk saw. The group row below is the proof.
        await _switch_soa_timers(marker, group_id)

    blocked_in = await _render_holds_the_row_when_the_mark_queues(server_id, switch)
    # It queued in the commit-time bundle mark, as reported.
    assert "FOR NO KEY UPDATE" in blocked_in, blocked_in
    await _assert_rendered_and_marked(server_id)
    async with _TestSessionLocal() as check:
        group = await check.get(DNSServerGroup, group_id)
        assert group is not None
        assert group.serves_soa_timers is False  # the switch committed


@pytest.mark.asyncio
async def test_a_key_write_to_the_group_waits_for_an_in_flight_render(
    db_session: AsyncSession,
) -> None:
    """The same cycle through a lock no lock-strength change can soften: a
    group rename writes ``name``, a column of a unique index, so its UPDATE
    takes the row ``FOR UPDATE``. The render must not need the group at all."""
    group_id, server_id = await _agent_server(db_session, "g2031k")

    async def rename(marker: AsyncSession) -> None:
        group = await asyncio.wait_for(marker.get(DNSServerGroup, group_id), _STEP)
        assert group is not None
        group.name = "g2031k-renamed"
        await asyncio.wait_for(marker.flush(), _STEP)
        await mark_bundles_dirty(marker, group_ids=[group_id])
        await asyncio.wait_for(marker.commit(), _STEP)

    await _render_holds_the_row_when_the_mark_queues(server_id, rename)
    await _assert_rendered_and_marked(server_id)
    async with _TestSessionLocal() as check:
        name = await check.scalar(select(DNSServerGroup.name).where(DNSServerGroup.id == group_id))
        assert name == "g2031k-renamed"


@pytest.mark.asyncio
async def test_a_slow_render_still_never_rolls_the_mirror_back(
    db_session: AsyncSession,
) -> None:
    """The store's writes to the server row are one statement now; the mirror
    columns must still only move forward while the render counters always do."""
    _, server_id = await _agent_server(db_session, "g2031m")
    # The newer render's mirror, with the store's 'behind' clock running (a
    # mark landed after it): none of it may move for the older render.
    await db_session.execute(
        text(
            "UPDATE dns_server SET bundle_watermark = 5, bundle_etag = 'sha256:newer', "
            "bundle_built_at = '2026-01-01T00:00:00Z', bundle_rendered_by = 'api', "
            "bundle_app_version = 'newer', bundle_renderer_revision = 999, "
            "bundle_dirty_at = '2026-01-02T00:00:00Z', bundle_dirty_seq = 6 WHERE id = :i"
        ),
        {"i": server_id},
    )
    await db_session.commit()
    server = await db_session.get(DNSServer, server_id, populate_existing=True)
    assert server is not None
    mirror_before = (
        server.bundle_built_at,
        server.bundle_rendered_by,
        server.bundle_app_version,
        server.bundle_renderer_revision,
        server.bundle_dirty_at,
    )
    row = await bundle_store.store(
        db_session,
        server,
        dirty_watermark=3,
        snapshot_at=datetime.now(UTC),
        etag="sha256:older",
        structural_etag="sha256:s",
        ships_ops=True,
        body_gz=bundle_store.compress_body(b"{}"),
        body_bytes=2,
        records=0,
        render_ms=1,
        rendered_by=bundle_store.RENDERED_BY_WORKER,
    )
    await db_session.commit()
    assert row is not None
    assert server.bundle_watermark == 5
    assert server.bundle_etag == "sha256:newer"
    assert (
        server.bundle_built_at,
        server.bundle_rendered_by,
        server.bundle_app_version,
        server.bundle_renderer_revision,
        server.bundle_dirty_at,
    ) == mirror_before
    assert server.bundle_dirty_seq == 6
    assert server.bundle_render_count == 1
    assert server.bundle_render_status == bundle_store.RENDER_STATUS_OK
