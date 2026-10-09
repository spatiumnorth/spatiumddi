"""#1538 — agentless record ops must not be one-attempt-and-gone.

A transient provider error (429, 5xx, WinRM timeout) used to mark the op
``failed`` at ``attempts=1`` with no ``next_attempt_at``, while the API
reported success — the record stayed wrong on the server until a manual
zone sync. Now agentless failures go through the same ``fail_attempts``
retry accounting as agent ops (#1232), a beat sweep replays due ops, and
the DNS record CRUD surfaces a failed first attempt instead of auditing
it as a clean success.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import _agentless_op_warning
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.services.dns.record_ops import (
    MAX_OP_ATTEMPTS,
    apply_pending_agentless_ops,
    enqueue_record_op,
    enqueue_record_ops_batch,
)


async def _group_and_zone(
    db: AsyncSession, *, driver: str = "windows_dns"
) -> tuple[DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver=driver,
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
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
    return server, zone


class _FlakyDriver:
    """Agentless driver stand-in: raises while ``fail`` is set."""

    def __init__(self) -> None:
        self.fail = True
        self.calls = 0

    async def apply_record_change(self, _server: Any, _change: Any) -> None:
        self.calls += 1
        if self.fail:
            raise RuntimeError("429 rate limited")

    async def apply_record_changes(self, _server: Any, changes: Any) -> list[Any]:
        from app.drivers.dns.base import RecordChangeResult  # noqa: PLC0415

        self.calls += 1
        if self.fail:
            raise RuntimeError("503 provider unavailable")
        return [RecordChangeResult(ok=True, change=c) for c in changes]


def _patch_driver(monkeypatch: pytest.MonkeyPatch, driver: _FlakyDriver) -> None:
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: driver)


async def test_agentless_transient_failure_reschedules_instead_of_failing(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _server, zone = await _group_and_zone(db_session)
    driver = _FlakyDriver()
    _patch_driver(monkeypatch, driver)

    op = await enqueue_record_op(
        db_session, zone, "create", {"name": "www", "type": "A", "value": "10.0.0.2"}
    )

    assert op is not None
    assert op.state == "pending", "a first transient failure must schedule a retry"
    assert op.attempts == 1
    assert op.next_attempt_at is not None
    assert op.last_error is not None and "429" in op.last_error


async def test_retry_sweep_replays_due_op_and_marks_it_applied(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _server, zone = await _group_and_zone(db_session)
    driver = _FlakyDriver()
    _patch_driver(monkeypatch, driver)

    op = await enqueue_record_op(
        db_session, zone, "create", {"name": "www", "type": "A", "value": "10.0.0.2"}
    )
    assert op is not None and op.state == "pending"
    # Not due yet — the sweep must leave it alone.
    counts = await apply_pending_agentless_ops(db_session)
    assert counts["applied"] == 0

    op.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.flush()
    driver.fail = False
    counts = await apply_pending_agentless_ops(db_session)

    assert counts["applied"] == 1
    assert op.state == "applied"
    assert op.last_error is None
    assert op.next_attempt_at is None


async def test_retry_sweep_spends_the_budget_then_fails_terminally(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _server, zone = await _group_and_zone(db_session)
    driver = _FlakyDriver()
    _patch_driver(monkeypatch, driver)

    op = await enqueue_record_op(
        db_session, zone, "create", {"name": "www", "type": "A", "value": "10.0.0.2"}
    )
    assert op is not None
    op.attempts = MAX_OP_ATTEMPTS - 1
    op.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.flush()

    counts = await apply_pending_agentless_ops(db_session)

    assert counts["rescheduled"] == 1
    assert op.state == "failed", "the last budgeted attempt gives up terminally"
    assert op.next_attempt_at is None


async def test_batch_whole_failure_reschedules_every_row(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _server, zone = await _group_and_zone(db_session)
    driver = _FlakyDriver()
    _patch_driver(monkeypatch, driver)

    rows = await enqueue_record_ops_batch(
        db_session,
        zone,
        [
            {"op": "create", "record": {"name": "a", "type": "A", "value": "10.0.0.1"}},
            {"op": "create", "record": {"name": "b", "type": "A", "value": "10.0.0.2"}},
        ],
    )

    assert all(r is not None and r.state == "pending" for r in rows)
    assert all(r is not None and r.next_attempt_at is not None for r in rows)


def test_agentless_op_warning_only_for_unlanded_ops() -> None:
    assert _agentless_op_warning(None) is None
    assert _agentless_op_warning(SimpleNamespace(state="applied", last_error=None)) is None
    # Agent ops sit ``pending`` with no error — nothing to warn about.
    assert _agentless_op_warning(SimpleNamespace(state="pending", last_error=None)) is None
    warning = _agentless_op_warning(SimpleNamespace(state="pending", last_error="429"))
    assert warning is not None and "retry" in warning
    warning = _agentless_op_warning(SimpleNamespace(state="failed", last_error="boom"))
    assert warning is not None and "exhausted" in warning
