"""The ACME client never uses the shared engine inside its Celery task (#1687, #1726).

``run_acme_order`` runs ``run_order`` under ``asyncio.run()``, so every
attempt has its own event loop. The shared ``AsyncSessionLocal`` keeps
pooled asyncpg connections bound to whichever loop checked them out, and
in a worker that has run a task before, the next checkout meets a
connection whose loop is closed: "Event loop is closed". Two places in
the ACME path did that:

* ``run_order``'s ``finally`` teardown (the DNS-01 TXT records and the
  http-01 tokens) — the failure was logged as a warning and the cleanup
  skipped;
* ``dns01.solve``'s wait for the agents to apply the challenge TXT
  (``wait_for_ops_applied``) — the solve failed and the order ended
  ``invalid`` with ``unexpected: Event loop is closed``.

These tests reproduce the worker's state for real instead of mocking the
session factory: a connection is checked into the shared pool from an
event loop that is then closed, exactly as an earlier task leaves it.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.db import AsyncSessionLocal, engine, task_session
from app.models.acme_client import (
    ACME_ORDER_INVALID,
    ACME_ORDER_PENDING,
    ACMEClientAccount,
    ACMEHTTPChallenge,
    ACMEOrder,
)
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.acme_client import dns01, orchestrator
from app.services.acme_client.engine import ACMEProtocolError
from app.tasks import acme as acme_tasks


def _check_in_from_a_dead_loop() -> None:
    """Leave one shared-pool connection bound to a loop that is now closed —
    what any earlier task that touched ``AsyncSessionLocal`` leaves behind."""

    async def _use() -> None:
        async with AsyncSessionLocal() as s:
            await s.execute(text("select 1"))

    asyncio.run(_use())


@pytest.fixture
async def stranded_shared_pool() -> AsyncIterator[None]:
    # Start from an empty pool so the stranded connection is the one the
    # next checkout gets; drop it afterwards without touching its dead loop.
    await engine.dispose(close=False)
    await asyncio.to_thread(_check_in_from_a_dead_loop)
    yield
    await engine.dispose(close=False)


async def test_the_harness_really_strands_the_shared_pool(stranded_shared_pool: None) -> None:
    """Negative control: in a new loop the shared factory does fail, so the
    tests below pass only because the code under test avoids it."""

    async def _shared() -> None:
        async with AsyncSessionLocal() as s:
            await s.execute(text("select 1"))

    with pytest.raises(Exception, match="loop"):
        await asyncio.to_thread(asyncio.run, _shared())


class _RejectingCA:
    """A CA that answers with a protocol error, so the order ends in one
    attempt (no Celery retry, and no fresh connection to hide the bug)."""

    def __init__(self, *a: object, **kw: object) -> None:
        pass

    async def __aenter__(self) -> _RejectingCA:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def ensure_account(self, *, email: object = None) -> str:
        raise ACMEProtocolError("newAccount rejected", problem={"type": "unauthorized"})


async def test_the_order_teardown_sweeps_http01_tokens_in_a_used_worker(
    db_session: AsyncSession, stranded_shared_pool: None
) -> None:
    account = ACMEClientAccount(
        directory_url="https://ca.example.test/directory",
        email="ops@example.com",
        account_key_encrypted=encrypt_str("-stub-account-key-"),
    )
    db_session.add(account)
    await db_session.flush()
    order = ACMEOrder(
        account_id=account.id,
        domains=["www.example.com"],
        challenge_type="http-01",
        status=ACME_ORDER_PENDING,
    )
    db_session.add(order)
    await db_session.flush()
    oid = order.id
    db_session.add(ACMEHTTPChallenge(token="tok-1687", key_authorization="k", order_id=oid))
    await db_session.commit()

    with patch.object(orchestrator, "ACMEClient", _RejectingCA):
        result = await asyncio.to_thread(acme_tasks.run_acme_order.apply, args=[str(oid)])
    assert result.get() == ACME_ORDER_INVALID

    db_session.expire_all()
    left = (
        (
            await db_session.execute(
                select(ACMEHTTPChallenge).where(ACMEHTTPChallenge.order_id == oid)
            )
        )
        .scalars()
        .all()
    )
    assert left == [], "the http-01 token survived the order's teardown"


async def test_dns01_solve_waits_for_the_agents_in_a_used_worker(
    db_session: AsyncSession, stranded_shared_pool: None
) -> None:
    """The solve polls the op rows until the agents ACK them. In the worker
    those polls must not come from the shared engine, or the first one
    raises and the order ends ``invalid``."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(group)
    await db_session.flush()
    db_session.add(
        DNSServer(
            name="ns1",
            host="192.0.2.1",
            port=53,
            driver="bind9",
            group_id=group.id,
            is_primary=True,
            is_enabled=True,
        )
    )
    db_session.add(
        DNSZone(
            name="example.test.",
            zone_type="primary",
            kind="forward",
            group_id=group.id,
            primary_ns="ns1.example.test.",
            admin_email="hostmaster.example.test.",
        )
    )
    await db_session.commit()

    async def _agent_acks() -> None:
        # Stand in for the agent: ACK the challenge op once it is queued.
        for _ in range(100):
            async with task_session() as s:
                res = await s.execute(
                    update(DNSRecordOp)
                    .where(
                        DNSRecordOp.zone_name == "example.test.",
                        DNSRecordOp.op == "create",
                        DNSRecordOp.state == "pending",
                    )
                    .values(state="applied")
                )
                await s.commit()
                if res.rowcount:  # type: ignore[attr-defined]
                    return
            await asyncio.sleep(0.1)

    async def _solve_as_the_worker_does() -> None:
        async with task_session() as db:
            acks = asyncio.create_task(_agent_acks())
            handle = await dns01.solve(db, "host.example.test", "token-1687")
            await acks
            await dns01.cleanup(db, handle)

    with patch.object(dns01, "publish_wake", new=AsyncMock()):
        await asyncio.to_thread(asyncio.run, _solve_as_the_worker_does())

    db_session.expire_all()
    left = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.value == "token-1687")))
        .scalars()
        .all()
    )
    assert left == []
