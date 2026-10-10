"""The rolling upgrade reboots each node into the slot it staged (#1445).

Found by ddi-pg walking #1449: the host runner writes the inactive slot,
arms the next boot and stops ("upgrade staged — reboot to boot the new
slot"), and nothing in the per-node chain asked for that reboot, so the
health gate could only time out. And the run's database session, which the
chain holds across the CNPG switchover it waits for, failed its next query
with "connection is closed".
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.audit import AuditLog
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import alerts, per_node

TARGET = "2026.10.03-1"
OLD = "2026.10.02-1"


class _Node:
    """The appliance columns the reboot step reads and writes."""

    def __init__(self, **kw: Any) -> None:
        self.id = uuid.uuid4()
        self.hostname = "node-1"
        self.installed_appliance_version: str | None = OLD
        self.last_upgrade_state: str | None = "done"
        self.last_upgrade_state_at: datetime | None = None
        self.last_upgrade_progress: dict[str, Any] | None = {"step": "reboot-pending"}
        self.slot_a_version: str | None = OLD
        self.slot_b_version: str | None = TARGET
        self.reboot_requested = False
        self.reboot_requested_at: datetime | None = None
        for k, v in kw.items():
            setattr(self, k, v)


def _db() -> Any:
    db = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


# ── What counts as staged ─────────────────────────────────────────────────────


def test_a_done_written_after_the_stamp_is_staged() -> None:
    stamped = datetime.now(UTC)
    node = _Node(last_upgrade_state_at=stamped + timedelta(minutes=4))
    assert per_node._slot_staged(node, TARGET, stamped) is True


def test_a_done_left_by_an_earlier_upgrade_is_not_staged() -> None:
    """Rebooting on it would restart the node in the middle of the apply
    this run just asked for."""
    stamped = datetime.now(UTC)
    node = _Node(last_upgrade_state_at=stamped - timedelta(hours=2))
    assert per_node._slot_staged(node, TARGET, stamped) is False


def test_a_naive_done_timestamp_is_read_as_utc() -> None:
    stamped = datetime.now(UTC)
    naive = (stamped + timedelta(minutes=4)).replace(tzinfo=None)
    assert per_node._slot_staged(_Node(last_upgrade_state_at=naive), TARGET, stamped) is True


def test_a_slot_not_carrying_the_target_is_not_staged() -> None:
    node = _Node(slot_b_version="2026.09.04-1")
    assert per_node._slot_staged(node, TARGET, None) is False


def test_an_apply_still_running_is_not_staged() -> None:
    node = _Node(last_upgrade_state="in-flight", last_upgrade_progress={"step": "writing"})
    assert per_node._slot_staged(node, TARGET, None) is False


def test_without_slot_versions_the_state_alone_decides() -> None:
    """A supervisor that reports no slot versions cannot veto."""
    node = _Node(slot_a_version=None, slot_b_version=None)
    assert per_node._slot_staged(node, TARGET, None) is True


# ── The step ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_step_waits_for_the_apply_then_requests_the_reboot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stamped = datetime.now(UTC)
    # Stale ``done`` from an earlier upgrade, then this run's apply, then staged.
    states = [
        ("done", stamped - timedelta(hours=1), {"step": "reboot-pending"}),
        ("in-flight", stamped, {"step": "writing"}),
        ("done", stamped + timedelta(minutes=5), {"step": "reboot-pending"}),
    ]
    node = _Node()

    async def _refresh(row: Any) -> None:
        state, at, progress = states.pop(0) if states else (None, None, None)
        if state is not None:
            row.last_upgrade_state = state
            row.last_upgrade_state_at = at
            row.last_upgrade_progress = progress

    db = _db()
    db.refresh = AsyncMock(side_effect=_refresh)
    wake = AsyncMock()
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node, "publish_wake", wake)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(db, "node-1", TARGET, stamped_at=stamped, timeout_s=5.0)

    assert step.ok is True, step.error
    assert node.reboot_requested is True
    assert node.reboot_requested_at is not None
    audit = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], AuditLog)]
    assert len(audit) == 1
    assert audit[0].action == "appliance.reboot_scheduled"
    assert audit[0].user_display_name == per_node.SYSTEM_ACTOR
    assert audit[0].auth_source == "system"
    wake.assert_awaited_once_with(per_node.appliance_channel(node.id))


@pytest.mark.asyncio
async def test_a_node_already_on_the_target_is_not_rebooted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = _Node(installed_appliance_version=TARGET)
    wake = AsyncMock()
    monkeypatch.setattr(per_node, "publish_wake", wake)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(_db(), "node-1", TARGET, stamped_at=None)
    assert step.ok is True
    assert node.reboot_requested is False
    wake.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_outstanding_request_is_not_stamped_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second stamp could reboot the node twice."""
    asked_at = datetime.now(UTC) - timedelta(seconds=20)
    node = _Node(reboot_requested=True, reboot_requested_at=asked_at)
    wake = AsyncMock()
    monkeypatch.setattr(per_node, "publish_wake", wake)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(_db(), "node-1", TARGET, stamped_at=None)
    assert step.ok is True
    assert node.reboot_requested_at == asked_at
    wake.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failed_apply_fails_the_step(monkeypatch: pytest.MonkeyPatch) -> None:
    node = _Node(last_upgrade_state="failed")
    monkeypatch.setattr(per_node, "publish_wake", AsyncMock())
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(_db(), "node-1", TARGET, stamped_at=None)
    assert step.ok is False
    assert node.reboot_requested is False
    assert (
        alerts.classify_per_node_failure(failed_at="reboot", error=step.error)
        == alerts.CATEGORY_SUPERVISOR_FAILED
    )


@pytest.mark.asyncio
async def test_a_slot_never_staged_times_out_without_rebooting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = _Node(last_upgrade_state="in-flight", last_upgrade_progress={"step": "writing"})
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node, "publish_wake", AsyncMock())
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(_db(), "node-1", TARGET, stamped_at=None, timeout_s=0.05)
    assert step.ok is False
    assert "not staged" in step.error
    assert node.reboot_requested is False


@pytest.mark.asyncio
async def test_each_poll_is_its_own_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh checkout per poll is what lets ``pool_pre_ping`` replace a
    connection lost to the switchover."""
    node = _Node(last_upgrade_state="in-flight", last_upgrade_progress={"step": "writing"})
    db = _db()
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        await per_node._step_reboot(db, "node-1", TARGET, stamped_at=None, timeout_s=0.05)
    assert db.commit.await_count == db.refresh.await_count >= 2


# ── Fresh vs repeated stamps ──────────────────────────────────────────────────


class _Row:
    def __init__(self) -> None:
        self.id = uuid.uuid4()
        self.hostname = "node-1"
        self.architecture: str | None = None
        self.supervisor_version: str | None = None
        self.installed_appliance_version: str | None = OLD
        self.desired_appliance_version: str | None = None
        self.desired_slot_image_url: str | None = None
        self.desired_slot_image_sha256: str | None = None
        self.desired_slot_image_tls_insecure = False


@pytest.mark.asyncio
async def test_a_repeated_stamp_is_not_fresh() -> None:
    """A re-driven node gets the same URL, which the supervisor's fire-once
    marker will not apply again; waiting for a new ``done`` would time out."""
    row = _Row()
    db = MagicMock(flush=AsyncMock())
    target = SlotImageTarget(url="https://mirror/slot.raw.xz")
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=row)):
        first = await per_node._step_trigger_slot_apply(db, "node-1", TARGET, target)
        again = await per_node._step_trigger_slot_apply(db, "node-1", TARGET, target)
    assert first.detail["fresh_stamp"] is True
    assert again.detail["fresh_stamp"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh", [True, False])
async def test_the_chain_passes_the_stamp_time_only_for_a_fresh_stamp(
    monkeypatch: pytest.MonkeyPatch, fresh: bool
) -> None:
    seen: dict[str, Any] = {}

    async def _ok(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="x", started_at="t").finish(True)

    async def _trigger(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="trigger_slot_apply", started_at="t").finish(
            True, fresh_stamp=fresh
        )

    async def _reboot(*_a: Any, stamped_at: datetime | None, **_k: Any) -> per_node.StepResult:
        seen["stamped_at"] = stamped_at
        return per_node.StepResult(name="reboot", started_at="t").finish(True)

    for name in (
        "preflight",
        "etcd_snapshot",
        "cordon",
        "drain",
        "health_gate",
        "convergence",
        "uncordon",
        "cluster_verify",
    ):
        monkeypatch.setattr(per_node, f"_step_{name}", _ok)
    monkeypatch.setattr(per_node, "_step_trigger_slot_apply", _trigger)
    monkeypatch.setattr(per_node, "_step_reboot", _reboot)

    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version=TARGET,
        slot_image=SlotImageTarget(url="https://mirror/slot.raw.xz"),
    )
    assert result.ok is True
    assert (seen["stamped_at"] is not None) is fresh


# ── The task session survives a dropped connection ───────────────────────────


@pytest.mark.asyncio
async def test_task_sessions_ping_their_connection_on_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import db as db_module

    seen: dict[str, Any] = {}
    real = db_module.create_async_engine

    def _spy(*a: Any, **kw: Any) -> Any:
        seen.update(kw)
        return real(*a, **kw)

    monkeypatch.setattr(db_module, "create_async_engine", _spy)
    async with db_module.task_session():
        pass
    assert seen.get("pool_pre_ping") is True
