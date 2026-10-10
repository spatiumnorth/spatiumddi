"""A previous attempt's ``failed`` does not fail this run's fresh stamp (#1449).

Found by ddi-pg walking #1660: after a node's apply failed once, the next
rolling run stamped a new image URL and failed the node's reboot step in the
same second, because ``last_upgrade_state`` still read the old ``failed``.
The supervisor then ran the new apply anyway, with no drive watching. The
health gate carried the same unguarded test, reachable through the reboot
step's early exits.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import per_node

TARGET = "2026.10.03-1"
OLD = "2026.10.02-1"


class _Node:
    """The appliance columns the trigger, reboot and health-gate steps touch."""

    def __init__(self, **kw: Any) -> None:
        self.id = uuid.uuid4()
        self.hostname = "node-1"
        self.architecture: str | None = None
        self.supervisor_version: str | None = None
        self.installed_appliance_version: str | None = OLD
        self.desired_appliance_version: str | None = None
        self.desired_slot_image_url: str | None = "https://mirror/old.raw.xz"
        self.desired_slot_image_sha256: str | None = None
        self.desired_slot_image_tls_insecure = False
        self.last_upgrade_state: str | None = "failed"
        self.last_upgrade_state_at: datetime | None = datetime.now(UTC) - timedelta(hours=1)
        self.last_upgrade_progress: dict[str, Any] | None = {"step": "download"}
        self.last_upgrade_log_tail: str | None = "curl: (60) certificate refused"
        self.slot_a_version: str | None = OLD
        self.slot_b_version: str | None = OLD
        self.reboot_requested = False
        self.reboot_requested_at: datetime | None = None
        for k, v in kw.items():
            setattr(self, k, v)


def _db(refresh: Any = None) -> Any:
    db = MagicMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    db.refresh = AsyncMock(side_effect=refresh) if refresh else AsyncMock()
    return db


# ── The stamp forgets the previous attempt ────────────────────────────────────


@pytest.mark.asyncio
async def test_a_fresh_stamp_resets_the_previous_outcome() -> None:
    node = _Node()
    target = SlotImageTarget(url="https://mirror/new.raw.xz")
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_trigger_slot_apply(_db(), "node-1", TARGET, target)
    assert step.detail["fresh_stamp"] is True
    assert node.last_upgrade_state is None
    assert node.last_upgrade_state_at is None
    assert node.last_upgrade_progress is None
    assert node.last_upgrade_log_tail is None


@pytest.mark.asyncio
async def test_a_repeated_stamp_keeps_the_outcome() -> None:
    """A re-driven node's apply is not repeated, so its state is the answer."""
    node = _Node(desired_slot_image_url="https://mirror/new.raw.xz")
    target = SlotImageTarget(url="https://mirror/new.raw.xz")
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_trigger_slot_apply(_db(), "node-1", TARGET, target)
    assert step.detail["fresh_stamp"] is False
    assert node.last_upgrade_state == "failed"


# ── The reboot step ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_qa_repro_stamp_then_reboot_waits_for_a_fresh_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """QA's unit repro: a fresh stamp over an old ``failed``, then the reboot
    step. Before the fix it failed on its first poll."""
    node = _Node()
    target = SlotImageTarget(url="https://mirror/new.raw.xz")
    stamped = datetime.now(UTC)
    old_failure = (node.last_upgrade_state, node.last_upgrade_state_at)
    # The next heartbeat re-publishes the host's old failure, then this
    # attempt runs and stages.
    states = [
        old_failure,
        ("in-flight", stamped + timedelta(seconds=30), {"step": "writing"}),
        ("done", stamped + timedelta(minutes=4), {"step": "reboot-pending"}),
    ]

    async def _refresh(row: Any) -> None:
        if not states:
            return
        st = states.pop(0)
        row.last_upgrade_state, row.last_upgrade_state_at = st[0], st[1]
        if len(st) > 2:
            row.last_upgrade_progress = st[2]
            row.slot_b_version = TARGET

    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node, "publish_wake", AsyncMock())
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        trig = await per_node._step_trigger_slot_apply(_db(), "node-1", TARGET, target)
        assert trig.detail["fresh_stamp"] is True
        step = await per_node._step_reboot(
            _db(_refresh), "node-1", TARGET, stamped_at=stamped, timeout_s=5.0
        )
    assert step.ok is True, step.error
    assert node.reboot_requested is True


@pytest.mark.asyncio
async def test_a_stale_failure_alone_is_waited_past_not_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stamped = datetime.now(UTC)
    node = _Node(last_upgrade_state_at=stamped - timedelta(minutes=10))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(
            _db(), "node-1", TARGET, stamped_at=stamped, timeout_s=0.05
        )
    assert step.ok is False
    assert "not staged" in (step.error or "")


@pytest.mark.asyncio
async def test_a_failure_written_after_the_stamp_fails_promptly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stamped = datetime.now(UTC)
    node = _Node(last_upgrade_state_at=stamped + timedelta(seconds=40))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(
            _db(), "node-1", TARGET, stamped_at=stamped, timeout_s=5.0
        )
    assert step.ok is False
    assert "upgrade failed" in (step.error or "")


@pytest.mark.asyncio
async def test_a_naive_failure_timestamp_is_read_as_utc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stamped = datetime.now(UTC)
    naive_after = (stamped + timedelta(seconds=40)).replace(tzinfo=None)
    node = _Node(last_upgrade_state_at=naive_after)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(
            _db(), "node-1", TARGET, stamped_at=stamped, timeout_s=5.0
        )
    assert step.ok is False
    assert "upgrade failed" in (step.error or "")


@pytest.mark.asyncio
async def test_without_a_stamp_any_failure_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = _Node()
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_reboot(_db(), "node-1", TARGET, stamped_at=None)
    assert step.ok is False


# ── The health gate ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_health_gate_waits_past_a_stale_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reached through the reboot step's ``reboot_already_requested`` exit,
    which never saw a fresh state."""
    stamped = datetime.now(UTC)
    node = _Node(reboot_requested=True)
    states = [
        ("failed", stamped - timedelta(hours=1), OLD),
        ("done", stamped + timedelta(minutes=6), TARGET),
    ]

    async def _refresh(row: Any) -> None:
        if states:
            st, at, installed = states.pop(0)
            row.last_upgrade_state, row.last_upgrade_state_at = st, at
            row.installed_appliance_version = installed

    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_health_gate(
            _db(_refresh), "node-1", TARGET, stamped_at=stamped, timeout_s=5.0
        )
    assert step.ok is True, step.error


@pytest.mark.asyncio
async def test_the_health_gate_fails_on_a_fresh_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stamped = datetime.now(UTC)
    node = _Node(last_upgrade_state_at=stamped + timedelta(minutes=2))
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_health_gate(
            _db(), "node-1", TARGET, stamped_at=stamped, timeout_s=5.0
        )
    assert step.ok is False
    assert "upgrade failed" in (step.error or "")


@pytest.mark.asyncio
async def test_the_chain_passes_the_stamp_time_to_the_health_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    async def _ok(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="preflight", started_at="t").finish(True)

    async def _trigger(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="trigger_slot_apply", started_at="t").finish(
            True, fresh_stamp=True
        )

    async def _gate(*_a: Any, stamped_at: datetime | None = None, **_k: Any) -> Any:
        seen["stamped_at"] = stamped_at
        return per_node.StepResult(name="health_gate", started_at="t").finish(True)

    for name in (
        "preflight",
        "etcd_snapshot",
        "cordon",
        "drain",
        "reboot",
        "convergence",
        "uncordon",
        "cluster_verify",
    ):
        monkeypatch.setattr(per_node, f"_step_{name}", _ok)
    monkeypatch.setattr(per_node, "_step_trigger_slot_apply", _trigger)
    monkeypatch.setattr(per_node, "_step_health_gate", _gate)

    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version=TARGET,
        slot_image=SlotImageTarget(url="https://mirror/slot.raw.xz"),
    )
    assert result.ok is True
    assert seen["stamped_at"] is not None
