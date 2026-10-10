"""A node stages its slot before it is cordoned and drained (#1463).

Found by ddi-pg's three-node walk of #1449: on a rolling upgrade from an
uploaded image, every node fetches its image through the slot-image mirror,
a single pod whose local volume pins it to one node. The chain drained each
node before telling it to fetch, so the mirror's own node evicted its image
source first: the replacement stayed Pending on the cordoned node, every
download answered 502, and the run failed there with the node left cordoned.
The node whose address the Plan was sent to failed the same way, refused,
once its drain had evicted the frontend behind that address (#1708).

Staging (download and write the inactive slot) and the reboot have been
separate steps since #1449, so the chain now stages first, while the node and
whatever runs on it still serve, and drains only before the reboot.
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

TARGET = "2026.10.09-900"
OLD = "2026.10.09-1"


class _Node:
    """The appliance columns the stage step reads."""

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


def _db(refresh: Any = None) -> Any:
    db = MagicMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    db.refresh = AsyncMock(side_effect=refresh) if refresh else AsyncMock()
    return db


def _recording_chain(monkeypatch: pytest.MonkeyPatch, events: list[str], fail: str = "") -> None:
    """Stub every step of the chain to record its name; ``fail`` fails one."""

    def _step(name: str) -> Any:
        async def _run(*_a: Any, **_k: Any) -> per_node.StepResult:
            events.append(name)
            ok = name != fail
            return per_node.StepResult(name=name, started_at="t").finish(  # type: ignore[arg-type]
                ok, **({} if ok else {"error": "supervisor reported upgrade failed"})
            )

        return _run

    for name in per_node.CHAIN:
        monkeypatch.setattr(per_node, f"_step_{name}", _step(name))


async def _chain(db: Any = None) -> per_node.SingleNodeResult:
    return await per_node.single_node_upgrade(
        db or MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version=TARGET,
        slot_image=SlotImageTarget(url="https://node/slot.raw.xz", sha256="ab" * 32),
        cnpg_cluster_name="pg-cluster",
    )


# ── The order ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_node_stages_before_it_is_cordoned_and_drained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _recording_chain(monkeypatch, events)

    result = await _chain()

    assert result.ok is True, result.error
    staged = events.index("stage")
    assert events.index("trigger_slot_apply") < staged
    for later in ("cnpg_maintenance_on", "cordon", "verify_primary_moved", "drain"):
        assert staged < events.index(later), events


@pytest.mark.asyncio
async def test_the_drain_comes_straight_before_the_reboot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _recording_chain(monkeypatch, events)

    await _chain()

    assert events.index("drain") + 1 == events.index("reboot"), events
    assert events.index("reboot") + 1 == events.index("health_gate"), events


@pytest.mark.asyncio
async def test_a_failed_fetch_leaves_the_node_in_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mirror's node (or the Plan's node) failing its fetch must fail the
    run with the node still schedulable and serving: nothing cordoned, no
    CNPG maintenance window opened, nothing evicted."""
    events: list[str] = []
    _recording_chain(monkeypatch, events, fail="stage")

    result = await _chain()

    assert result.ok is False
    assert result.failed_at == "stage"
    assert "upgrade failed" in (result.error or "")
    for never in ("cnpg_maintenance_on", "cordon", "verify_primary_moved", "drain", "reboot"):
        assert never not in events, events


@pytest.mark.asyncio
async def test_the_stamp_is_committed_before_the_node_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _recording_chain(monkeypatch, events)
    db = MagicMock()
    db.commit = AsyncMock(side_effect=lambda: events.append("commit"))

    await _chain(db)

    i = events.index("trigger_slot_apply")
    assert events[i + 1] == "commit"
    assert events[i + 2] == "stage"


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh", [True, False])
async def test_the_stamp_time_reaches_the_stage_the_reboot_and_the_gate(
    monkeypatch: pytest.MonkeyPatch, fresh: bool
) -> None:
    seen: dict[str, Any] = {}

    async def _ok(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="preflight", started_at="t").finish(True)

    async def _trigger(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="trigger_slot_apply", started_at="t").finish(
            True, fresh_stamp=fresh
        )

    def _seeing(name: str) -> Any:
        async def _step(*_a: Any, stamped_at: datetime | None = None, **_k: Any) -> Any:
            seen[name] = stamped_at
            return per_node.StepResult(name=name, started_at="t").finish(True)  # type: ignore[arg-type]

        return _step

    for name in per_node.CHAIN:
        monkeypatch.setattr(per_node, f"_step_{name}", _ok)
    monkeypatch.setattr(per_node, "_step_trigger_slot_apply", _trigger)
    for name in ("stage", "reboot", "health_gate"):
        monkeypatch.setattr(per_node, f"_step_{name}", _seeing(name))

    result = await _chain()

    assert result.ok is True
    for name in ("stage", "reboot", "health_gate"):
        assert (seen[name] is not None) is fresh, name
    assert seen["stage"] == seen["reboot"] == seen["health_gate"]


@pytest.mark.asyncio
async def test_a_resume_past_the_stage_skips_the_fetch_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _recording_chain(monkeypatch, events)

    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version=TARGET,
        slot_image=SlotImageTarget(url="https://node/slot.raw.xz"),
        cnpg_cluster_name="pg-cluster",
        start_step="cordon",
    )

    assert result.ok is True
    assert events[0] == "cordon"
    assert "trigger_slot_apply" not in events and "stage" not in events


# ── The stage step ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_stage_step_waits_for_the_host_and_never_reboots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stamped = datetime.now(UTC)
    # A stale ``done`` from an earlier upgrade, then this run's apply, then staged.
    states = [
        ("done", stamped - timedelta(hours=1), {"step": "reboot-pending"}),
        ("in-flight", stamped, {"step": "download"}),
        ("done", stamped + timedelta(minutes=5), {"step": "reboot-pending"}),
    ]
    node = _Node()

    async def _refresh(row: Any) -> None:
        state, at, progress = states.pop(0) if states else (None, None, None)
        if state is not None:
            row.last_upgrade_state = state
            row.last_upgrade_state_at = at
            row.last_upgrade_progress = progress

    db = _db(_refresh)
    wake = AsyncMock()
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node, "publish_wake", wake)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_stage(db, "node-1", TARGET, stamped_at=stamped, timeout_s=5.0)

    assert step.name == "stage"
    assert step.ok is True, step.error
    assert not states, "it returned before the host reported this run's apply staged"
    assert node.reboot_requested is False
    wake.assert_not_awaited()
    assert not [c for c in db.add.call_args_list if isinstance(c.args[0], AuditLog)]


@pytest.mark.asyncio
async def test_the_stage_step_takes_a_node_already_on_the_target() -> None:
    node = _Node(installed_appliance_version=TARGET)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_stage(_db(), "node-1", TARGET, stamped_at=None)
    assert step.ok is True
    assert step.detail.get("already_running_target") is True


@pytest.mark.asyncio
async def test_the_stage_step_takes_an_outstanding_reboot_request() -> None:
    """A resumed run whose node was already asked to reboot: staged long ago."""
    node = _Node(reboot_requested=True, last_upgrade_state=None, last_upgrade_progress=None)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_stage(_db(), "node-1", TARGET, stamped_at=None)
    assert step.ok is True
    assert step.detail.get("reboot_already_requested") is True


@pytest.mark.asyncio
async def test_a_fetch_that_fails_fails_the_stage_step(monkeypatch: pytest.MonkeyPatch) -> None:
    stamped = datetime.now(UTC)
    node = _Node(
        last_upgrade_state="failed",
        last_upgrade_state_at=stamped + timedelta(minutes=2),
        last_upgrade_progress={"step": "download"},
    )
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_stage(_db(), "node-1", TARGET, stamped_at=stamped)
    assert step.ok is False
    assert step.error == "supervisor reported upgrade failed"
    assert (
        alerts.classify_per_node_failure(failed_at="stage", error=step.error)
        == alerts.CATEGORY_SUPERVISOR_FAILED
    )


@pytest.mark.asyncio
async def test_a_previous_attempts_failure_is_waited_past(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stamped = datetime.now(UTC)
    node = _Node(
        last_upgrade_state="failed",
        last_upgrade_state_at=stamped - timedelta(hours=1),
        last_upgrade_progress={"step": "download"},
    )
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_stage(
            _db(), "node-1", TARGET, stamped_at=stamped, timeout_s=0.05
        )
    assert step.ok is False
    assert "not staged within" in (step.error or "")


@pytest.mark.asyncio
async def test_a_slot_never_staged_times_out_without_rebooting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = _Node(last_upgrade_state="in-flight", last_upgrade_progress={"step": "download"})
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_stage(_db(), "node-1", TARGET, stamped_at=None, timeout_s=0.05)
    assert step.ok is False
    assert "not staged within" in (step.error or "")
    assert node.reboot_requested is False


@pytest.mark.asyncio
async def test_the_reboot_after_the_drain_finds_the_slot_staged_and_requests_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reboot step keeps its own staged check (a resumed run can start
    there), and after a stage that passed it requests the reboot at once."""
    stamped = datetime.now(UTC)
    node = _Node(last_upgrade_state_at=stamped + timedelta(minutes=5))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node, "publish_wake", AsyncMock())
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        stage = await per_node._step_stage(_db(), "node-1", TARGET, stamped_at=stamped)
        assert node.reboot_requested is False
        reboot = await per_node._step_reboot(
            _db(), "node-1", TARGET, stamped_at=stamped, timeout_s=0.05
        )
    assert stage.ok is True and reboot.ok is True
    assert node.reboot_requested is True


def test_the_chain_lists_every_step_once_in_its_order() -> None:
    assert len(set(per_node.CHAIN)) == len(per_node.CHAIN)
    assert per_node.CHAIN.index("stage") < per_node.CHAIN.index("cordon")
    assert per_node.CHAIN.index("drain") + 1 == per_node.CHAIN.index("reboot")
