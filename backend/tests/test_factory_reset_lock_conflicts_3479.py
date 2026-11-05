"""A factory reset that meets another session's locks answers 200 or 409, never 500 (#3479).

The wipe runs in one transaction and takes ACCESS EXCLUSIVE locks (its
``TRUNCATE``) on tables the agents' polls, the worker and the beat read all
the time. Seen live on a single-node appliance: a DNS-only reset's
``TRUNCATE`` waited behind the DNS agent's config long-poll, which held
``dns_record_op`` while it waited; the minute's alert evaluation read
``dns_blocklist`` and then queued on ``dns_record_op`` behind the
``TRUNCATE``; when the poll answered, the ``TRUNCATE`` took ``dns_record_op``,
reached ``dns_blocklist`` and Postgres ended it as the deadlock victim. The
endpoint answered a bare 500 and nothing was wiped.

These tests force that interleave with three sessions on a real Postgres:
``holder`` stands in for the long-poll, ``reader`` for the alert evaluation.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import asyncpg
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone
from app.services.factory_reset import runner
from app.services.factory_reset.sections import FACTORY_SECTIONS_BY_KEY

EXECUTE_URL = "/api/v1/system/factory-reset/execute"
PASSWORD = "reset-3479"

# A waiting lock on a named table, by mode, for one backend or any.
_WAITING = """
SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
WHERE NOT l.granted AND c.relname = $1 AND l.mode = $2 AND ($3::int IS NULL OR l.pid = $3)
"""


def _dsn() -> str:
    from tests.conftest import _TEST_DATABASE_URL  # noqa: PLC0415

    return str(_TEST_DATABASE_URL).replace("postgresql+asyncpg://", "postgresql://", 1)


async def _until(check: Callable[[], Awaitable[bool]], what: str, timeout: float = 10.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not await check():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.05)


async def _waiting(monitor: asyncpg.Connection, table: str, mode: str, pid: int | None) -> bool:
    return bool(await monitor.fetchval(_WAITING, table, mode, pid))


async def _estate(db: AsyncSession) -> dict[str, str]:
    """A superadmin with a known password, and one DNS group with a zone for
    the reset to wipe. Committed: the wipe runs on its own connection."""
    user = User(
        username=f"fr-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Factory Reset Admin",
        hashed_password=hash_password(PASSWORD),
        is_superadmin=True,
    )
    db.add(user)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(
        DNSZone(
            group_id=group.id,
            name=f"z{uuid.uuid4().hex[:6]}.example.",
            zone_type="primary",
            kind="forward",
            primary_ns="ns1.example.",
            admin_email="admin.example.",
        )
    )
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _dns_groups(db: AsyncSession) -> int:
    db.expire_all()
    return int((await db.execute(select(func.count()).select_from(DNSServerGroup))).scalar_one())


def _body() -> dict[str, Any]:
    return {
        "section_keys": ["dns"],
        "password": PASSWORD,
        "confirm_phrases": {"dns": FACTORY_SECTIONS_BY_KEY["dns"].phrase},
        "acknowledge_no_backup": True,
    }


@pytest.fixture
def no_redis_mutex(monkeypatch: pytest.MonkeyPatch) -> None:
    """The reset's cross-request mutex lives in Redis; these tests are about
    the database's locks, so it always grants."""

    async def _acquire() -> object:
        return object()

    async def _release(_client: object) -> None:
        return None

    monkeypatch.setattr(runner, "_acquire_lock_or_raise", _acquire)
    monkeypatch.setattr(runner, "_release_lock", _release)


@pytest.mark.asyncio
async def test_a_dns_reset_caught_in_a_deadlock_still_wipes(
    client: AsyncClient, db_session: AsyncSession, no_redis_mutex: None
) -> None:
    headers = await _estate(db_session)
    dsn = _dsn()
    holder = await asyncpg.connect(dsn)
    reader = await asyncpg.connect(dsn)
    monitor = await asyncpg.connect(dsn)
    reset: asyncio.Task[Any] | None = None
    try:
        # The agent's long-poll: a read of the op queue, then a wait with the
        # transaction still open.
        held = holder.transaction()
        await held.start()
        await holder.execute("SELECT 1 FROM dns_record_op LIMIT 1")

        reset = asyncio.create_task(client.post(EXECUTE_URL, json=_body(), headers=headers))
        await _until(
            lambda: _waiting(monitor, "dns_record_op", "AccessExclusiveLock", None),
            "the reset's TRUNCATE to queue behind the poll",
        )

        # The alert evaluation: dns_blocklist first, then dns_record_op, which
        # queues behind the TRUNCATE.
        reading = reader.transaction()
        await reading.start()
        await reader.execute("SELECT 1 FROM dns_blocklist LIMIT 1")
        second_read = asyncio.create_task(reader.execute("SELECT 1 FROM dns_record_op LIMIT 1"))
        reader_pid = reader.get_server_pid()
        await _until(
            lambda: _waiting(monitor, "dns_record_op", "AccessShareLock", reader_pid),
            "the reader to queue behind the TRUNCATE",
        )
        # As live, the reader has waited past deadlock_timeout before the poll
        # answers: its one deadlock check found no cycle, so the check that
        # finds it is the TRUNCATE's, and the TRUNCATE is the victim.
        timeout_ms = int(
            await monitor.fetchval(
                "SELECT setting::int FROM pg_settings WHERE name = 'deadlock_timeout'"
            )
        )
        await asyncio.sleep(timeout_ms / 1000 + 0.5)

        # The poll answers: the TRUNCATE takes dns_record_op, reaches
        # dns_blocklist and closes the cycle. Postgres ends the TRUNCATE.
        await held.rollback()
        await asyncio.wait_for(second_read, timeout=15)
        await reading.commit()

        resp = await asyncio.wait_for(reset, timeout=60)
    finally:
        if reset is not None and not reset.done():
            reset.cancel()
        for conn in (holder, reader, monitor):
            await conn.close()

    assert resp.status_code == 200, (resp.status_code, resp.text)
    assert resp.json()["success"] is True
    assert await _dns_groups(db_session) == 0


@pytest.mark.asyncio
async def test_a_dns_reset_that_cannot_get_its_locks_is_refused_with_409(
    client: AsyncClient,
    db_session: AsyncSession,
    no_redis_mutex: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Short bounds so the test is quick (raising=False: before #3479 the
    # runner had no bounds and waited forever).
    monkeypatch.setattr(runner, "WIPE_LOCK_TIMEOUT_MS", 300, raising=False)
    monkeypatch.setattr(runner, "WIPE_ATTEMPTS", 2, raising=False)
    monkeypatch.setattr(runner, "WIPE_RETRY_DELAY_S", 0.1, raising=False)
    headers = await _estate(db_session)
    holder = await asyncpg.connect(_dsn())
    reset: asyncio.Task[Any] | None = None
    try:
        held = holder.transaction()
        await held.start()
        await holder.execute("SELECT 1 FROM dns_record_op LIMIT 1")

        reset = asyncio.create_task(client.post(EXECUTE_URL, json=_body(), headers=headers))
        resp = await asyncio.wait_for(asyncio.shield(reset), timeout=20)
        await held.rollback()
    finally:
        if reset is not None and not reset.done():
            reset.cancel()
        await holder.close()

    assert resp.status_code == 409, (resp.status_code, resp.text)
    detail = resp.json()["detail"].lower()
    assert "nothing was deleted" in detail and "try again" in detail, detail
    assert await _dns_groups(db_session) == 1


@pytest.mark.asyncio
async def test_a_reset_that_meets_no_one_runs_once(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bounded retry changes nothing for a reset that meets no lock: one
    attempt, one transaction, the section wiped."""
    await _estate(db_session)
    attempts: list[int] = []
    real = runner._execute_sections

    async def _counted(*args: Any, **kwargs: Any) -> int:
        attempts.append(1)
        return await real(*args, **kwargs)

    monkeypatch.setattr(runner, "_execute_sections", _counted)
    await runner._wipe(_dsn(), runner._resolve_targets(["dns"]), calling_user_id=uuid.uuid4())
    assert attempts == [1]
    assert await _dns_groups(db_session) == 0
