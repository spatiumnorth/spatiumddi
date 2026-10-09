"""Cluster rolling-upgrade orchestrator tests (#296 Phase D).

Covers:

* Node ordering: alphabetical sort + skip-completed.
* ``plan_upgrade``: preflight gate, dup-run refusal, node enumeration,
  source-versions capture.
* State transitions: planned → running, running → succeeded, running
  → failed (halt-on-failure), running → halted → running (resume),
  any-non-terminal → aborted.
* ``drive_upgrade``: happy-path 2-node walk, halt-on-failure on first
  bad node, resume from progress skips completed nodes.
* Lease renewal loop: renew failure flips the stop_event.

End-to-end against a live kubeapi + celery worker is exercised by the
Phase G UI integration tests (when they land); this file is pure-
Python with mocked k8s + per_node helpers.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import node_order, orchestrator, per_node

# ── Node ordering ─────────────────────────────────────────────────────


def test_pick_node_order_alphabetical_case_insensitive() -> None:
    """Lex-case-insensitive sort matches kubectl get nodes output."""
    nodes = [
        {"metadata": {"name": "node-c"}},
        {"metadata": {"name": "Node-A"}},
        {"metadata": {"name": "node-b"}},
    ]
    assert node_order.pick_node_order(nodes) == ["Node-A", "node-b", "node-c"]


def test_pick_node_order_skips_exclude() -> None:
    """Excluded names drop out of the result."""
    nodes = [{"metadata": {"name": n}} for n in ("a", "b", "c")]
    assert node_order.pick_node_order(nodes, exclude=["b"]) == ["a", "c"]


def test_pick_node_order_handles_missing_metadata() -> None:
    """Defensive: a node with no metadata shouldn't crash the planner."""
    nodes: list[dict[str, Any]] = [{"metadata": {}}, {"metadata": {"name": "x"}}]
    assert node_order.pick_node_order(nodes) == ["x"]


def test_next_node_to_upgrade_picks_first_uncompleted() -> None:
    assert node_order.next_node_to_upgrade(["a", "b", "c"], ["a"]) == "b"
    assert node_order.next_node_to_upgrade(["a", "b", "c"], ["a", "b"]) == "c"


def test_next_node_to_upgrade_none_when_done() -> None:
    assert node_order.next_node_to_upgrade(["a", "b"], ["a", "b"]) is None


def test_next_node_to_upgrade_empty_plan() -> None:
    assert node_order.next_node_to_upgrade([], []) is None


# ── plan_upgrade ─────────────────────────────────────────────────────


def _ok_preflight() -> orchestrator.preflight.PreflightReport:
    ok = orchestrator.preflight.PreflightResult("x", "ok", "fine", {})
    return orchestrator.preflight.PreflightReport(
        target_version="2026.06.01-1",
        current_version="2026.05.22-2",
        overall="ok",
        can_start=True,
        results=[ok],
    )


def _fail_preflight() -> orchestrator.preflight.PreflightReport:
    bad = orchestrator.preflight.PreflightResult("quorum", "fail", "no", {})
    return orchestrator.preflight.PreflightReport(
        target_version="2026.06.01-1",
        current_version="2026.05.22-2",
        overall="fail",
        can_start=False,
        results=[bad],
    )


def _build_mock_db_for_plan(
    *,
    existing_run: Any = None,
    appliance_rows: list[tuple[str, str | None]] | None = None,
) -> MagicMock:
    """Build an AsyncSession mock that:
    * Returns ``existing_run`` for the dup-run query (None = no dup).
    * Returns ``appliance_rows`` for the source-versions capture.
    * Records add() calls so the test can inspect them.
    """
    db = MagicMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.flush = AsyncMock()

    # Two calls: the dup-check + the source-versions select.
    dup_result = MagicMock()
    dup_result.scalar_one_or_none.return_value = existing_run

    source_result = MagicMock()
    source_result.all.return_value = appliance_rows or []

    # ``execute`` is called in this order: existing-run check, then
    # source-versions select. AsyncMock side_effect cycles through.
    db.execute = AsyncMock(side_effect=[dup_result, source_result])
    return db


@pytest.mark.asyncio
async def test_plan_upgrade_refuses_on_preflight_fail() -> None:
    db = MagicMock()
    with patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=_fail_preflight())):
        with pytest.raises(orchestrator.OrchestratorError, match="preflight failed"):
            await orchestrator.plan_upgrade(
                db,
                target_version="2026.06.01-1",
                slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            )


@pytest.mark.asyncio
async def test_plan_upgrade_refuses_on_existing_run() -> None:
    existing = MagicMock(id=uuid.uuid4(), state="running")
    db = _build_mock_db_for_plan(existing_run=existing)
    with patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=_ok_preflight())):
        with pytest.raises(orchestrator.OrchestratorError, match="in flight"):
            await orchestrator.plan_upgrade(
                db,
                target_version="2026.06.01-1",
                slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            )


@pytest.mark.asyncio
async def test_plan_upgrade_refuses_on_zero_nodes() -> None:
    db = _build_mock_db_for_plan(appliance_rows=[])
    with (
        patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=_ok_preflight())),
        patch.object(orchestrator.k8s, "list_nodes", return_value=(200, [])),
    ):
        with pytest.raises(orchestrator.OrchestratorError, match="no appliance nodes"):
            await orchestrator.plan_upgrade(
                db,
                target_version="2026.06.01-1",
                slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            )


@pytest.mark.asyncio
async def test_plan_upgrade_persists_node_order_and_sources() -> None:
    """Happy path — preflight ok, no existing run, 2 nodes → planned
    row persisted with the right shape."""
    nodes = [
        {"metadata": {"name": "node-b"}},
        {"metadata": {"name": "node-a"}},  # out of order on purpose
    ]
    db = _build_mock_db_for_plan(appliance_rows=[("node-a", "2026.05.22-2"), ("node-b", None)])
    with (
        patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=_ok_preflight())),
        patch.object(orchestrator.k8s, "list_nodes", return_value=(200, nodes)),
    ):
        plan = await orchestrator.plan_upgrade(
            db,
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        )
    # Alphabetical.
    assert plan.node_order == ["node-a", "node-b"]
    assert plan.target_version == "2026.06.01-1"
    assert plan.preflight_overall == "ok"
    # Run row + audit log both added.
    assert db.add.called
    db.commit.assert_awaited()


# ── State transitions ────────────────────────────────────────────────


class _FakeRun:
    """Stand-in for a SystemUpgradeRun row in transition tests.

    Carries just the fields ``_transition`` + ``_record_event`` touch
    so we can drive the state machine without spinning up the ORM.
    """

    def __init__(self, state: str = "planned", target: str = "2026.06.01-1") -> None:
        self.id = uuid.uuid4()
        self.state = state
        self.target_version = target
        self.progress: dict[str, Any] = {"events": [], "per_node": {}}
        self.plan: dict[str, Any] = {}
        self.last_error: str | None = None
        self.lease_holder: str | None = None
        self.lease_acquired_at: datetime | None = None
        self.started_at: datetime | None = datetime.now(UTC)
        self.finished_at: datetime | None = None


def _db_for_state_test(run: _FakeRun) -> MagicMock:
    db = MagicMock()
    db.get = AsyncMock(return_value=run)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.flush = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_halt_upgrade_running_to_halted() -> None:
    run = _FakeRun(state="running")
    db = _db_for_state_test(run)
    out = await orchestrator.halt_upgrade(db, run.id, actor_display="admin")
    assert out.state == "halted"
    # Event recorded.
    assert any(e["event"] == "halted" for e in out.progress["events"])


@pytest.mark.asyncio
async def test_halt_upgrade_refuses_from_planned() -> None:
    run = _FakeRun(state="planned")
    db = _db_for_state_test(run)
    with pytest.raises(orchestrator.OrchestratorError, match="can't transition"):
        await orchestrator.halt_upgrade(db, run.id)


@pytest.mark.asyncio
async def test_resume_upgrade_halted_to_running() -> None:
    run = _FakeRun(state="halted")
    db = _db_for_state_test(run)
    out = await orchestrator.resume_upgrade(db, run.id, actor_display="admin")
    assert out.state == "running"


@pytest.mark.asyncio
async def test_abort_upgrade_from_planned() -> None:
    run = _FakeRun(state="planned")
    db = _db_for_state_test(run)
    with patch.object(orchestrator.mutex, "release", return_value=(True, None)):
        out = await orchestrator.abort_upgrade(db, run.id, actor_display="admin")
    assert out.state == "aborted"
    assert out.finished_at is not None


@pytest.mark.asyncio
async def test_abort_upgrade_from_running_releases_lease() -> None:
    run = _FakeRun(state="running")
    db = _db_for_state_test(run)
    with patch.object(orchestrator.mutex, "release", return_value=(True, None)) as rel:
        out = await orchestrator.abort_upgrade(db, run.id)
    assert out.state == "aborted"
    rel.assert_called_once()


@pytest.mark.asyncio
async def test_abort_upgrade_refuses_from_terminal() -> None:
    run = _FakeRun(state="succeeded")
    db = _db_for_state_test(run)
    with pytest.raises(orchestrator.OrchestratorError, match="can't transition"):
        await orchestrator.abort_upgrade(db, run.id)


# ── _drive_loop ──────────────────────────────────────────────────────


def _good_step(name: per_node.StepName) -> per_node.StepResult:
    return per_node.StepResult(name=name, started_at="t", finished_at="t").finish(True)


def _good_result(node: str) -> per_node.SingleNodeResult:
    return per_node.SingleNodeResult(
        node_name=node,
        target_version="2026.06.01-1",
        ok=True,
        failed_at=None,
        steps=[_good_step("preflight"), _good_step("cordon")],
    )


def _bad_result(node: str, *, failed_at: per_node.StepName = "drain") -> per_node.SingleNodeResult:
    return per_node.SingleNodeResult(
        node_name=node,
        target_version="2026.06.01-1",
        ok=False,
        failed_at=failed_at,
        steps=[_good_step("preflight"), _good_step("cordon")],
        error=f"{failed_at} failed",
    )


@pytest.mark.asyncio
async def test_drive_loop_happy_path_two_nodes(monkeypatch: pytest.MonkeyPatch) -> None:
    """All nodes succeed → state transitions to succeeded + lease
    released."""
    run = _FakeRun(state="running")
    run.plan = {
        "node_order": ["node-a", "node-b"],
        "slot_image_url": "http://mirror/x",
        "cnpg_cluster_name": "pg",
    }
    db = _db_for_state_test(run)
    stop = asyncio.Event()

    calls: list[str] = []

    async def _fake_per_node(*args: Any, **kwargs: Any) -> per_node.SingleNodeResult:
        calls.append(kwargs["node_name"])
        return _good_result(kwargs["node_name"])

    # The run releases only its own lease, retrying an unanswered API (#1449).
    release_mock = MagicMock(return_value=True)
    monkeypatch.setattr(per_node, "single_node_upgrade", _fake_per_node)
    monkeypatch.setattr(orchestrator.mutex, "release_if_held", release_mock)
    monkeypatch.setattr(orchestrator, "_BETWEEN_NODES_PAUSE_S", 0.01)

    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]
    assert calls == ["node-a", "node-b"]
    assert run.state == "succeeded"
    assert run.finished_at is not None
    release_mock.assert_called_once_with(attempts=orchestrator._LEASE_RELEASE_ATTEMPTS)


@pytest.mark.asyncio
async def test_drive_loop_passes_its_lease_holder_to_each_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The node chain's preflight must know the lease is this run's (#1445)."""
    run = _FakeRun(state="running")
    run.lease_holder = "worker-0"
    run.plan = {"node_order": ["node-a"], "slot_image_url": "http://mirror/x"}
    db = _db_for_state_test(run)
    holders: list[Any] = []

    async def _fake_per_node(*args: Any, **kwargs: Any) -> per_node.SingleNodeResult:
        holders.append(kwargs.get("lease_holder"))
        return _good_result(kwargs["node_name"])

    monkeypatch.setattr(per_node, "single_node_upgrade", _fake_per_node)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))
    monkeypatch.setattr(orchestrator, "_BETWEEN_NODES_PAUSE_S", 0.01)

    await orchestrator._drive_loop(db, run, asyncio.Event())  # type: ignore[arg-type]
    assert holders == ["worker-0"]


@pytest.mark.asyncio
async def test_drive_loop_halts_on_first_node_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """node-a fails → state=failed, node-b never driven."""
    run = _FakeRun(state="running")
    run.plan = {"node_order": ["node-a", "node-b"], "slot_image_url": "http://x"}
    db = _db_for_state_test(run)
    stop = asyncio.Event()

    calls: list[str] = []

    async def _fake_per_node(*args: Any, **kwargs: Any) -> per_node.SingleNodeResult:
        calls.append(kwargs["node_name"])
        return _bad_result(kwargs["node_name"], failed_at="drain")

    monkeypatch.setattr(per_node, "single_node_upgrade", _fake_per_node)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))
    # Phase F — short-circuit the alert emit path (its async db.scalar
    # call doesn't have an AsyncMock fake here; the alert wiring has
    # its own dedicated tests).
    monkeypatch.setattr(
        orchestrator.upgrade_alerts,
        "emit_upgrade_failed_alert",
        AsyncMock(return_value=None),
    )

    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]
    assert calls == ["node-a"]
    assert run.state == "failed"
    assert "drain" in (run.last_error or "")
    # Per-node progress captured the failure detail.
    assert run.progress["per_node"]["node-a"]["ok"] is False
    assert run.progress["per_node"]["node-a"]["failed_at"] == "drain"


@pytest.mark.asyncio
async def test_drive_loop_resume_skips_completed_nodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """node-a already succeeded in a prior partial run → only node-b
    gets driven on this pass."""
    run = _FakeRun(state="running")
    run.plan = {"node_order": ["node-a", "node-b"], "slot_image_url": "http://x"}
    run.progress = {
        "events": [],
        "per_node": {"node-a": {"ok": True, "failed_at": None, "steps": []}},
    }
    db = _db_for_state_test(run)
    stop = asyncio.Event()

    calls: list[str] = []

    async def _fake_per_node(*args: Any, **kwargs: Any) -> per_node.SingleNodeResult:
        calls.append(kwargs["node_name"])
        return _good_result(kwargs["node_name"])

    monkeypatch.setattr(per_node, "single_node_upgrade", _fake_per_node)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))
    monkeypatch.setattr(orchestrator, "_BETWEEN_NODES_PAUSE_S", 0.01)

    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]
    assert calls == ["node-b"]
    assert run.state == "succeeded"


@pytest.mark.asyncio
async def test_drive_loop_exits_on_halt_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operator halts the row mid-loop → loop sees state=halted at the
    top of the next iteration + exits without driving the next node."""
    run = _FakeRun(state="running")
    run.plan = {"node_order": ["node-a", "node-b"], "slot_image_url": "http://x"}

    # Track that refresh() sees state flip to halted after node-a.
    refresh_count = 0

    async def _refresh(_obj: Any) -> None:
        nonlocal refresh_count
        refresh_count += 1
        if refresh_count == 2:
            run.state = "halted"

    db = _db_for_state_test(run)
    db.refresh = _refresh
    stop = asyncio.Event()
    calls: list[str] = []

    async def _fake_per_node(*args: Any, **kwargs: Any) -> per_node.SingleNodeResult:
        calls.append(kwargs["node_name"])
        return _good_result(kwargs["node_name"])

    monkeypatch.setattr(per_node, "single_node_upgrade", _fake_per_node)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))
    monkeypatch.setattr(orchestrator, "_BETWEEN_NODES_PAUSE_S", 0.01)

    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]
    # First iteration drove node-a; second iteration saw halted + exited.
    assert calls == ["node-a"]
    assert run.state == "halted"


@pytest.mark.asyncio
async def test_drive_loop_lease_lost_leaves_running_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stop_event set before the loop runs → exits cleanly without
    flipping state. Next take-over picks up from progress.
    """
    run = _FakeRun(state="running")
    run.plan = {"node_order": ["node-a"], "slot_image_url": "http://x"}
    db = _db_for_state_test(run)
    stop = asyncio.Event()
    stop.set()

    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]
    # Did NOT transition to failed/succeeded.
    assert run.state == "running"


# ── Lease renewal loop ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lease_renewal_loop_stops_on_renew_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Renew returns ok=False → renewal loop sets stop_event + exits."""
    stop = asyncio.Event()
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_INTERVAL_S", 0.01)
    monkeypatch.setattr(orchestrator.mutex, "renew", lambda **_kw: (False, "lease taken over"))

    await orchestrator._lease_renewal_loop(stop)
    assert stop.is_set()


@pytest.mark.asyncio
async def test_lease_renewal_loop_renews_until_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Renew returns ok=True every cycle → loop runs until stop_event
    is externally set."""
    stop = asyncio.Event()
    renew_count = 0

    def _renew(**_kw: Any) -> tuple[bool, str | None]:
        nonlocal renew_count
        renew_count += 1
        return True, None

    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_INTERVAL_S", 0.01)
    monkeypatch.setattr(orchestrator.mutex, "renew", _renew)

    async def _stop_after_a_few_renews() -> None:
        await asyncio.sleep(0.05)
        stop.set()

    await asyncio.gather(
        orchestrator._lease_renewal_loop(stop),
        _stop_after_a_few_renews(),
    )
    assert renew_count >= 2


# ── drive_upgrade entry point ────────────────────────────────────────


@pytest.mark.asyncio
async def test_drive_upgrade_planned_acquires_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``planned`` run flips to ``running`` + acquires the lease."""
    run = _FakeRun(state="planned")
    run.plan = {"node_order": [], "slot_image_url": ""}
    db = _db_for_state_test(run)

    acquire = MagicMock(return_value=(True, None))
    release = MagicMock(return_value=(True, None))
    monkeypatch.setattr(orchestrator.mutex, "acquire", acquire)
    monkeypatch.setattr(orchestrator.mutex, "release", release)
    monkeypatch.setattr(orchestrator.mutex, "renew", lambda **_kw: (True, None))
    monkeypatch.setattr(orchestrator.mutex, "_identity", lambda: "api-test")

    await orchestrator.drive_upgrade(db, run.id)
    acquire.assert_called_once()
    assert run.lease_holder == "api-test"
    # Empty node_order → loop transitions immediately to succeeded.
    assert run.state == "succeeded"


@pytest.mark.asyncio
async def test_drive_upgrade_refuses_when_lease_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _FakeRun(state="planned")
    db = _db_for_state_test(run)
    monkeypatch.setattr(orchestrator.mutex, "acquire", lambda **_kw: (False, "held by api-other"))
    with pytest.raises(orchestrator.OrchestratorError, match="acquire"):
        await orchestrator.drive_upgrade(db, run.id)


@pytest.mark.asyncio
async def test_drive_upgrade_terminal_state_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """A run already in a terminal state shouldn't acquire the lease
    or try to drive anything."""
    run = _FakeRun(state="succeeded")
    db = _db_for_state_test(run)

    acquire = MagicMock()
    monkeypatch.setattr(orchestrator.mutex, "acquire", acquire)

    out = await orchestrator.drive_upgrade(db, run.id)
    assert out.state == "succeeded"
    acquire.assert_not_called()
