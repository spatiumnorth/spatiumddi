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

    async def apply_record_change(self, _server: Any, change: Any) -> None:
        type(self).calls.append((change.op, change.record.name, change.record.value))
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
