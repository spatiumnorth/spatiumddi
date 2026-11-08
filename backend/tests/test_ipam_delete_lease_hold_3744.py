"""#3744: a subnet, block, space or DHCP server group delete keeps its leases'
lease-events batches answered.

#3733 fixed the scope delete only: the stamp commits, then the scope's leases
go in committed batches. The other four deletes still tore the leases of their
scopes down inside their own transaction, holding every lease row to the
commit (about 100 ms a lease with DDNS on): lease batches renewing them waited
for their first lock and answered 503 at 30 s, and the DELETE answered 504 at
60 s, with nothing written back. They now route through the same helper.

As in the #3733 tests, the delete is held at its first lease purge until a
renewal of the scope's last lease (by id) has answered; the batch size is small
so that lease is in no earlier batch's lock.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _auth_agent
from app.main import app
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import Subnet
from app.services.dhcp import lease_cleanup
from app.tasks import dhcp_lease_cleanup as lease_tasks
from tests.test_dhcp_scope_delete_lease_hold_3733 import (
    _ESTATE,
    _HOLD_S,
    _seeded,
)
from tests.test_lease_events_trashed_scope_3733 import (
    _NOTHING,
    _counts,
    _post,
    concurrent_client,  # noqa: F401 — the fixture, shared
)

_KINDS = ["subnet", "block", "space"]


async def _delete_url(db: AsyncSession, kind: str, subnet: Subnet) -> str:
    if kind == "subnet":
        return f"/api/v1/ipam/subnets/{subnet.id}"
    if kind == "block":
        return f"/api/v1/ipam/blocks/{subnet.block_id}"
    return f"/api/v1/ipam/spaces/{subnet.space_id}"


async def _last_lease_ip(db: AsyncSession, scope_id: uuid.UUID) -> Any:
    return (
        await db.execute(
            select(DHCPLease.ip_address)
            .where(DHCPLease.scope_id == scope_id)
            .order_by(DHCPLease.id.desc())
            .limit(1)
        )
    ).scalar_one()


def _hold_first_purge(monkeypatch: pytest.MonkeyPatch, answered: asyncio.Event) -> tuple[Any, Any]:
    real = lease_cleanup.purge_lease
    started: asyncio.Event = asyncio.Event()
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
    return started, log


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", _KINDS)
async def test_lease_batches_answer_while_the_delete_tears_its_leases_down(
    kind: str,
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A renewal of the scope's last lease answers while the delete is held at
    its first lease, and writes nothing. On the unfixed code the delete holds
    every lease row to its commit, so the renewal waits for the hold to give up."""
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_BATCH", 5, raising=False)
    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    last = await _last_lease_ip(db_session, scope_id)
    url = await _delete_url(db_session, kind, subnet)
    answered = asyncio.Event()
    started, log = _hold_first_purge(monkeypatch, answered)

    delete = asyncio.create_task(concurrent_client.delete(url, headers=admin))
    await asyncio.wait_for(started.wait(), timeout=30)
    renewal = await _post(concurrent_client, server, [str(last)])
    answered.set()
    gone = await asyncio.wait_for(delete, timeout=60)

    assert gone.status_code == 204, gone.text
    assert renewal.status_code == 200, renewal.text
    assert log == ["met"], "the renewal waited for the delete's teardown"
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", _KINDS)
async def test_the_audit_row_carries_the_lease_counts_and_the_wake_comes_first(
    kind: str,
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#3748 carried over: Kea stops serving the trashed scope when the stamp
    commits, not after the teardown; and the scope's audit row, written before
    the response, counts the leases the teardown then removes."""
    from app.core import agent_wake
    from app.models.audit import AuditLog

    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    url = await _delete_url(db_session, kind, subnet)
    log: list[str] = []
    real_publish = agent_wake.publish_wake
    real_teardown = lease_cleanup.tear_down_scope_leases

    async def _publish(*channels: str) -> None:
        log.append("wake")
        await real_publish(*channels)

    async def _teardown(*args: Any, **kwargs: Any) -> Any:
        log.append("teardown")
        return await real_teardown(*args, **kwargs)

    monkeypatch.setattr(agent_wake, "publish_wake", _publish)
    monkeypatch.setattr(lease_cleanup, "tear_down_scope_leases", _teardown)

    gone = await concurrent_client.delete(url, headers=admin)
    assert gone.status_code == 204, gone.text
    assert "teardown" in log and "wake" in log, log
    assert log.index("wake") < log.index("teardown"), log
    audit = (
        await db_session.execute(
            select(AuditLog.old_value).where(
                AuditLog.resource_type == "dhcp_scope",
                AuditLog.resource_id == str(scope_id),
                AuditLog.action == "soft_delete",
            )
        )
    ).scalar_one()
    assert audit["leases_removed"] == len(_ESTATE), audit
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", _KINDS)
async def test_a_failing_batch_or_a_spent_deadline_still_answers_and_hands_on(
    kind: str,
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A batch that raises, or no time left, after the stamp committed: 204,
    the scope in the Trash, its task enqueued, which then tears everything down."""

    async def _boom(db: AsyncSession, *_a: Any, **_k: Any) -> Any:
        await db.execute(select(1))
        raise RuntimeError("canceling statement due to statement timeout")

    monkeypatch.setattr(lease_cleanup, "tear_down_scope_leases", _boom)
    handed: list[str] = []

    class _Task:
        @staticmethod
        def delay(scope_id: str) -> None:
            handed.append(scope_id)

    monkeypatch.setattr(lease_tasks, "tear_down_trashed_scope_leases", _Task, raising=False)
    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    url = await _delete_url(db_session, kind, subnet)

    gone = await concurrent_client.delete(url, headers=admin)
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

    monkeypatch.undo()
    removed, _mirrors, done = await lease_tasks._tear_down_trashed_scopes(handed[0])
    assert (removed, done) == (len(_ESTATE), True)
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
async def test_the_subnet_delete_does_not_trash_the_lease_mirrors_records_for_a_restore(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """The lease mirrors' DNS records are revoked by the teardown, never
    stamped into the delete's batch, which a restore would bring back."""
    from app.models.dns import DNSRecord

    server, _scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    gone = await concurrent_client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=admin)
    assert gone.status_code == 204, gone.text
    trashed_records = (
        (
            await db_session.execute(
                select(DNSRecord.id)
                .where(DNSRecord.auto_generated.is_(True), DNSRecord.deleted_at.is_not(None))
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    assert trashed_records == []
    assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
async def test_a_server_group_delete_tears_the_trashed_scopes_leases_down_in_batches(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The group's scopes in the Trash still hold leases (a lost enqueue). The
    group delete tears them down before its own transaction, so a renewal of the
    last lease answers while the delete is held at its first lease."""
    from datetime import UTC, datetime

    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_BATCH", 5, raising=False)
    server, scope_id, subnet, admin = await _seeded(concurrent_client, db_session)
    last = await _last_lease_ip(db_session, scope_id)
    scope = await db_session.get(DHCPScope, scope_id)
    assert scope is not None
    group_id = scope.group_id
    # The group must hold no server to be deleted: the leases' server moves out.
    other = DHCPServerGroup(name=f"other-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(other)
    await db_session.flush()
    srv = await db_session.get(DHCPServer, server.id)
    assert srv is not None
    srv.server_group_id = other.id
    scope.deleted_at = datetime.now(UTC)
    await db_session.commit()
    # The agent still believes it serves the old group, as it does until its
    # next config poll: its renewals resolve to the trashed scope.
    believed = DHCPServer(
        id=server.id,
        name=srv.name,
        driver="kea",
        host="127.0.0.1",
        port=67,
        server_group_id=group_id,
    )
    app.dependency_overrides[_auth_agent] = lambda: (believed, {})

    answered = asyncio.Event()
    started, log = _hold_first_purge(monkeypatch, answered)
    delete = asyncio.create_task(
        concurrent_client.delete(f"/api/v1/dhcp/server-groups/{group_id}", headers=admin)
    )
    await asyncio.wait_for(started.wait(), timeout=30)
    renewal = await _post(concurrent_client, server, [str(last)])
    answered.set()
    gone = await asyncio.wait_for(delete, timeout=60)

    assert gone.status_code == 204, gone.text
    assert renewal.status_code == 200, renewal.text
    assert log == ["met"], "the renewal waited for the group delete's teardown"
    left = (
        await db_session.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.server_id == server.id)
        )
    ).scalar_one()
    assert left == 0
