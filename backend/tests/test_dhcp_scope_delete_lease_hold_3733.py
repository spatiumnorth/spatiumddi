"""#3733: a scope delete keeps its leases' lease-events batches answered.

The soft-delete tore the scope's leases down inside its own transaction, and
that teardown locks every lease row of the scope first (#3617), then purges
them one by one, revoking each mirror's DDNS: about 100 ms a lease. Every
lease-events batch renewing one of those leases waited for the delete's commit
in its first lock, so with about 1,000 leases the API cut those batches at its
30 s statement timeout (503), and the delete itself ran past the proxy's 60 s
read timeout (504) while it carried on to commit. The maintainer's case:
"A scope delete on a DDNS subnet with about 1,000 active leases while lease
events are flowing: the lease batches still answer 200 within a few seconds,
no deadlock."

The delete now puts the scope in the Trash and commits first, then tears the
leases down in committed batches, inline up to a deadline (the server delete's
bound, #2290) and in a background task after it. The lease sweep finishes any
scope in the Trash a lost enqueue left with leases.

The batch size and the deadline are set small here so a dozen leases show the
shape; the tests force the interleave with a hold rather than hope for it.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPScope
from app.services.dhcp import lease_cleanup
from app.tasks import dhcp_lease_cleanup as lease_tasks
from tests.test_lease_events_trashed_scope_3733 import (
    _NOTHING,
    _counts,
    _estate,
    _post,
    concurrent_client,  # noqa: F401 — the fixture, shared
)

# How long the held teardown waits for the batch. Far longer than the batch
# needs when nothing blocks it.
_HOLD_S = 3.0
_ESTATE = [f"10.31.1.{host}" for host in range(10, 22)]


async def _seeded(client: AsyncClient, db: AsyncSession) -> tuple[Any, ...]:
    server, scope_id, subnet, admin = await _estate(db)
    assert (await _post(client, server, _ESTATE)).status_code == 200
    seeded = await _counts(db, server, subnet)
    assert seeded["leases"] == seeded["mirrors"] == len(_ESTATE), seeded
    return server, scope_id, subnet, admin


@pytest.mark.asyncio
async def test_lease_batches_answer_while_the_scope_delete_tears_its_leases_down(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The delete is held at its first lease's teardown until a renewal of the
    scope's last lease (by id) has answered. That renewal must answer while the
    delete is held, and write nothing; on the unfixed code it waits on the
    lease row until the hold gives up, then inserts the lease again."""
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_BATCH", 5, raising=False)
    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    last = (
        await db_session.execute(
            select(DHCPLease.ip_address)
            .where(DHCPLease.scope_id == scope_id)
            .order_by(DHCPLease.id.desc())
            .limit(1)
        )
    ).scalar_one()
    real = lease_cleanup.purge_lease
    started, answered = asyncio.Event(), asyncio.Event()
    log: list[str] = []

    async def _held(db: AsyncSession, lease: Any, **kwargs: Any) -> bool:
        if not started.is_set():
            started.set()
            try:
                await asyncio.wait_for(answered.wait(), timeout=_HOLD_S)
                log.append("met")
            except TimeoutError:
                log.append("went on alone")
        return await real(db, lease, **kwargs)

    monkeypatch.setattr(lease_cleanup, "purge_lease", _held)
    delete = asyncio.create_task(
        concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    )
    await asyncio.wait_for(started.wait(), timeout=30)
    renewal = await _post(concurrent_client, server, [str(last)])
    answered.set()
    gone = await asyncio.wait_for(delete, timeout=60)

    assert gone.status_code == 204, gone.text
    assert renewal.status_code == 200, renewal.text
    assert log == ["met"], "the renewal waited for the scope delete's teardown"
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
async def test_a_scope_delete_past_its_deadline_answers_and_its_task_tears_down_the_rest(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no time left for the inline teardown the delete still answers 204
    with the scope in the Trash, and hands its leases to the background task,
    which tears every one of them down."""
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_BATCH", 5, raising=False)
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_INLINE_DEADLINE_S", 0.0, raising=False)
    handed: list[str] = []

    class _Task:
        @staticmethod
        def delay(scope_id: str) -> None:
            handed.append(scope_id)

    monkeypatch.setattr(lease_tasks, "tear_down_trashed_scope_leases", _Task, raising=False)
    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)

    gone = await concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    assert gone.status_code == 204, gone.text
    assert handed == [str(scope_id)]
    trashed = (
        await db_session.execute(
            select(DHCPScope.deleted_at)
            .where(DHCPScope.id == scope_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert trashed is not None

    removed, _mirrors, done = await lease_tasks._tear_down_trashed_scopes(handed[0])
    assert (removed, done) == (len(_ESTATE), True)
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
async def test_the_lease_sweep_tears_down_leases_a_trashed_scope_still_holds(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """What a lost enqueue leaves: a scope in the Trash, past the sweep's
    grace, that still has leases, mirrors and DDNS records. The lease sweep's
    next run tears them down."""
    server, scope_id, subnet, _admin = await _seeded(concurrent_client, db_session)
    scope = await db_session.get(DHCPScope, scope_id)
    assert scope is not None
    scope.deleted_at = (
        datetime.now(UTC) - lease_tasks.SWEEP_TRASHED_SCOPE_GRACE - timedelta(minutes=1)
    )
    await db_session.commit()

    await lease_tasks._run_both()
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
async def test_the_lease_sweep_leaves_a_scope_trashed_within_its_grace_to_the_delete(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """A scope trashed a moment ago still has its delete's own teardown
    running, inline or in its task. The sweep must not take the same scope's
    leases batch for batch beside it: it leaves the scope alone until its
    grace has passed."""
    server, scope_id, subnet, _admin = await _seeded(concurrent_client, db_session)
    seeded = await _counts(db_session, server, subnet)
    scope = await db_session.get(DHCPScope, scope_id)
    assert scope is not None
    scope.deleted_at = datetime.now(UTC)
    await db_session.commit()

    await lease_tasks._run_both()
    assert await _counts(db_session, server, subnet) == seeded


@pytest.mark.asyncio
async def test_the_wake_is_published_before_the_inline_teardown_runs(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#3748: Kea must stop serving the trashed scope when the stamp commits,
    not after the inline teardown (up to 20 s) has run."""
    from app.core import agent_wake

    server, scope_id, _subnet, admin = await _seeded(concurrent_client, db_session)
    log: list[str] = []
    real_publish = agent_wake.publish_wake

    async def _publish(*channels: str) -> None:
        log.append("wake")
        await real_publish(*channels)

    real_teardown = lease_cleanup.tear_down_scope_leases

    async def _teardown(*args: Any, **kwargs: Any) -> Any:
        log.append("teardown")
        return await real_teardown(*args, **kwargs)

    monkeypatch.setattr(agent_wake, "publish_wake", _publish)
    monkeypatch.setattr(lease_cleanup, "tear_down_scope_leases", _teardown)

    gone = await concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    assert gone.status_code == 204, gone.text
    assert "teardown" in log and "wake" in log, log
    assert log.index("wake") < log.index("teardown"), log


@pytest.mark.asyncio
async def test_a_failing_teardown_batch_still_answers_the_committed_delete(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#3748: a batch that raises after the stamp committed must not answer 500
    for a delete that happened: 204, the scope in the Trash, the task enqueued,
    and the delete's audit row there."""
    from app.models.audit import AuditLog

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("canceling statement due to statement timeout")

    monkeypatch.setattr(lease_cleanup, "tear_down_scope_leases", _boom)
    handed: list[str] = []

    class _Task:
        @staticmethod
        def delay(scope_id: str) -> None:
            handed.append(scope_id)

    monkeypatch.setattr(lease_tasks, "tear_down_trashed_scope_leases", _Task, raising=False)
    _server, scope_id, _subnet, admin = await _seeded(concurrent_client, db_session)

    gone = await concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    assert gone.status_code == 204, gone.text
    assert handed == [str(scope_id)]
    trashed = (
        await db_session.execute(
            select(DHCPScope.deleted_at)
            .where(DHCPScope.id == scope_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert trashed is not None
    audit = (
        await db_session.execute(
            select(AuditLog.result).where(
                AuditLog.resource_type == "dhcp_scope",
                AuditLog.resource_id == str(scope_id),
                AuditLog.action == "soft_delete",
            )
        )
    ).scalar_one()
    assert audit == "success"
