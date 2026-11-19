"""#1539 — an agentless record op must reach the provider only AFTER the
database transaction that owns it commits.

Before the fix ``enqueue_record_op`` called the driver in the middle of the
request: a commit that then failed rolled back the DNSRecord change and its
op row while the provider kept the write — a change nothing recorded. The op
row is now the outbox: written ``pending`` in the transaction, dispatched by
an after-commit hook, outcome recorded on the row.

The fake driver is registered through the real driver registry
(``register_driver``), so the production ``get_driver`` path is exercised.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns import _DRIVERS, register_driver
from app.drivers.dns.base import RecordChangeResult
from app.models.auth import User
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.record_ops import (
    apply_pending_agentless_ops,
    enqueue_record_op,
    enqueue_record_ops_batch,
)


class _FakeProvider:
    """Class-level call log so every ``get_driver()`` instance shares it."""

    calls: list[tuple[str, str, str]] = []
    batches: list[int] = []
    fail = False
    # Awaited once, during the first provider call: lets a test act while a
    # dispatch is in progress.
    hook: Any = None

    async def apply_record_change(self, _server: Any, change: Any) -> None:
        type(self).calls.append((change.op, change.record.name, change.record.value))
        hook, type(self).hook = type(self).hook, None
        if hook is not None:
            await hook()
        if type(self).fail:
            raise RuntimeError("503 provider unavailable")

    async def apply_record_changes(self, _server: Any, changes: list[Any]) -> list[Any]:
        type(self).batches.append(len(changes))
        if type(self).fail:
            raise RuntimeError("503 provider unavailable")
        for c in changes:
            type(self).calls.append((c.op, c.record.name, c.record.value))
        return [RecordChangeResult(ok=True, change=c) for c in changes]


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> type[_FakeProvider]:
    _FakeProvider.calls = []
    _FakeProvider.batches = []
    _FakeProvider.fail = False
    _FakeProvider.hook = None
    monkeypatch.setitem(_DRIVERS, "windows_dns", _DRIVERS["windows_dns"])  # restore on exit
    register_driver("windows_dns", _FakeProvider)  # type: ignore[arg-type]
    return _FakeProvider


async def _zone(db: AsyncSession) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="windows_dns",
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    return zone


async def _ops_in_fresh_session(db: AsyncSession, zone_name: str) -> list[DNSRecordOp]:
    async with AsyncSession(db.bind, expire_on_commit=False) as other:
        return list(
            (await other.execute(select(DNSRecordOp).where(DNSRecordOp.zone_name == zone_name)))
            .scalars()
            .all()
        )


def _a(name: str = "www", value: str = "10.0.0.2") -> dict[str, Any]:
    return {"name": name, "type": "A", "value": value}


async def test_provider_untouched_until_commit(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    zone = await _zone(db_session)
    await db_session.commit()

    op = await enqueue_record_op(db_session, zone, "create", _a())
    await db_session.flush()

    assert provider.calls == [], "the provider was written before the DB committed"
    assert op is not None and op.state == "pending"

    await db_session.commit()
    assert provider.calls == [("create", "www", "10.0.0.2")]
    assert op.state == "applied" and op.attempts == 1


async def test_failed_commit_leaves_provider_untouched(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    zone = await _zone(db_session)
    await db_session.commit()
    zone_name = zone.name

    await enqueue_record_op(db_session, zone, "create", _a())
    # A later statement in the same transaction violates a constraint (NOT
    # NULL), exactly like an audit insert failing before commit.
    db_session.add(DNSServerGroup(name=None))  # type: ignore[arg-type]
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    assert provider.calls == [], "provider received a write whose transaction rolled back"
    assert await _ops_in_fresh_session(db_session, zone_name) == []


async def test_rollback_leaves_provider_untouched_and_next_commit_clean(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    zone = await _zone(db_session)
    await db_session.commit()

    await enqueue_record_op(db_session, zone, "create", _a("gone"))
    await db_session.rollback()
    await db_session.refresh(zone)  # a rollback expires every loaded row
    await enqueue_record_op(db_session, zone, "create", _a("kept"))
    await db_session.commit()

    assert provider.calls == [("create", "kept", "10.0.0.2")]


async def test_batch_is_one_driver_call_after_commit(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    zone = await _zone(db_session)
    await db_session.commit()

    rows = await enqueue_record_ops_batch(
        db_session,
        zone,
        [{"op": "create", "record": _a(f"h{i}", f"10.0.0.{i + 2}")} for i in range(3)],
    )
    await db_session.flush()
    assert provider.batches == [] and provider.calls == []

    await db_session.commit()
    assert provider.batches == [3], "batching must survive the deferral"
    assert [r.state for r in rows if r is not None] == ["applied"] * 3


async def test_provider_failure_after_commit_is_recorded_and_replayed(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    zone = await _zone(db_session)
    await db_session.commit()
    zone_name = zone.name
    provider.fail = True

    op = await enqueue_record_op(db_session, zone, "create", _a())
    await db_session.commit()  # the DB change commits even though the provider refused

    assert op is not None and op.state == "pending" and "503" in (op.last_error or "")
    (stored,) = await _ops_in_fresh_session(db_session, zone_name)
    assert stored.state == "pending" and stored.attempts == 1 and stored.next_attempt_at

    provider.fail = False
    stored_id = stored.id
    async with AsyncSession(db_session.bind, expire_on_commit=False) as other:
        row = await other.get(DNSRecordOp, stored_id)
        assert row is not None
        row.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        await other.commit()
        counts = await apply_pending_agentless_ops(other)
        await other.commit()
    assert counts["applied"] == 1
    assert provider.calls[-1] == ("create", "www", "10.0.0.2")


async def test_api_create_record_dispatches_once_after_commit(
    client: AsyncClient, db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    user = User(
        username=f"u1539-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    zone = await _zone(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    resp = await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records",
        json={"name": "api", "record_type": "A", "value": "10.1.1.1"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    assert provider.calls == [("create", "api", "10.1.1.1")]
    assert resp.json().get("provider_warning") is None


# ── Validation pass: savepoints, worker sessions, claims ─────────────────────


async def test_savepoint_release_does_not_dispatch_before_the_outer_commit(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    """``after_commit`` fires when a SAVEPOINT is released too (the DHCP
    lease path opens one per MAC observation). Dispatching there sent
    nothing — the rows were not yet visible to the dispatch session — and
    consumed the registration, so the real commit sent nothing either."""
    zone = await _zone(db_session)
    await db_session.commit()

    op = await enqueue_record_op(db_session, zone, "create", _a())
    async with db_session.begin_nested():
        db_session.add(DNSServerGroup(name=f"sp-{uuid.uuid4().hex[:6]}"))
    assert provider.calls == [], "a savepoint release is not the commit"

    await db_session.commit()
    assert provider.calls == [("create", "www", "10.0.0.2")]
    assert op is not None and op.state == "applied"


async def test_worker_task_session_dispatches_on_commit(provider: type[_FakeProvider]) -> None:
    """``task_session`` is ``pool_size=1, max_overflow=0``. The dispatch must
    not need a second connection while the committing one is still held, or
    every Celery-side commit (IPAM auto-sync, DDNS, trash purge) waits out
    the pool timeout and leaves the op to the sweep."""
    from app.db import task_session  # noqa: PLC0415

    async with task_session() as db:
        zone = await _zone(db)
        await db.commit()
        op = await enqueue_record_op(db, zone, "create", _a("worker"))
        await db.commit()
        assert provider.calls == [("create", "worker", "10.0.0.2")]
        assert op is not None and op.state == "applied"
        # Clean up: this session is not the per-test one the fixture truncates
        # around, but the truncate runs on every mapped table regardless.


async def test_no_connection_is_held_across_the_provider_call(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    """On a one-connection pool, a query issued while the provider call is in
    progress gets the connection — i.e. the dispatch holds none."""
    from sqlalchemy import text  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415

    url = db_session.bind.url.render_as_string(hide_password=False)
    engine = create_async_engine(url, pool_size=1, max_overflow=0, pool_timeout=3)
    seen: list[int] = []

    async def probe() -> None:
        async with AsyncSession(engine) as other:
            seen.append((await other.execute(text("SELECT 1"))).scalar_one())

    provider.hook = probe
    try:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            zone = await _zone(db)
            await db.commit()
            op = await enqueue_record_op(db, zone, "create", _a("held"))
            await db.commit()
        assert seen == [1], "the probe could not get the pool's only connection"
        assert op is not None and op.state == "applied"
    finally:
        await engine.dispose()


async def test_sweep_cannot_resend_an_op_whose_dispatch_is_still_running(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    """A Windows batch or a slow cloud API can outlast the 120 s grace. The
    row is claimed ``in_flight`` before the provider is called, so a sweep
    running past the grace finds nothing to send — no concurrent duplicate."""
    zone = await _zone(db_session)
    await db_session.commit()
    swept: list[dict[str, int]] = []

    async def sweep_meanwhile() -> None:
        async with AsyncSession(db_session.bind, expire_on_commit=False) as other:
            swept.append(
                await apply_pending_agentless_ops(
                    other, now=datetime.now(UTC) + timedelta(minutes=5)
                )
            )

    provider.hook = sweep_meanwhile
    op = await enqueue_record_op(db_session, zone, "create", _a("slow"))
    await db_session.commit()

    assert swept and swept[0]["applied"] == 0 and swept[0]["rescheduled"] == 0
    assert provider.calls == [("create", "slow", "10.0.0.2")], "sent twice"
    assert op is not None and op.state == "applied"


async def test_expired_lease_is_recovered_and_a_late_outcome_is_dropped(
    db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    """A dispatcher that dies (or hangs past its lease) leaves the row
    ``in_flight``; the sweep counts it as a failed attempt and puts it back
    on the retry path. If the original dispatch then finishes, its outcome
    must not overwrite the row the sweep now owns."""
    zone = await _zone(db_session)
    await db_session.commit()
    zone_name = zone.name
    late: list[dict[str, int]] = []

    async def lease_expires_meanwhile() -> None:
        async with AsyncSession(db_session.bind, expire_on_commit=False) as other:
            late.append(
                await apply_pending_agentless_ops(other, now=datetime.now(UTC) + timedelta(hours=2))
            )

    provider.hook = lease_expires_meanwhile
    await enqueue_record_op(db_session, zone, "create", _a("hung"))
    await db_session.commit()

    assert late and late[0]["recovered"] == 1
    (stored,) = await _ops_in_fresh_session(db_session, zone_name)
    assert stored.state == "pending", "the late success overwrote the recovered row"
    assert stored.attempts == 1 and "lease" in (stored.last_error or "")


async def test_bulk_delete_reports_a_refused_provider_delete(
    client: AsyncClient, db_session: AsyncSession, provider: type[_FakeProvider]
) -> None:
    """The DB delete commits before the provider is called, so a refusal can
    no longer keep the row — the response must say the provider still has
    the records instead of reading as a clean delete."""
    user = User(
        username=f"u1539b-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    zone = await _zone(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    base = f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"

    ids = []
    for i in range(2):
        resp = await client.post(
            base,
            json={"name": f"b{i}", "record_type": "A", "value": f"10.2.0.{i + 1}"},
            headers=headers,
        )
        assert resp.status_code == 201, resp.text
        ids.append(resp.json()["id"])

    provider.fail = True
    resp = await client.post(f"{base}/bulk-delete", json={"record_ids": ids}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] == 2
    assert body["provider_warning"] and "2 of 2" in body["provider_warning"]
    assert provider.batches[-1] == 2, "the delete is still one batch"
