"""A drive that takes a run over mid-node resumes the node where it was (#2809).

A Rolling Upgrade whose drive died after a node's drain used to restart that
node at ``preflight``. Its CNPG wait (#1544) counts the node's own Postgres
instance, which the dead drive's drain had evicted and the cordon keeps
Pending, so it timed out and failed the node, releasing nothing: the node
stayed cordoned and the CNPG maintenance window stayed open.

The chain now reports a checkpoint before each step, the orchestrator keeps it
as ``progress.in_flight``, and the drive that takes over resumes from it. The
end-to-end tests here run two real drive loops against a real run row, with
the real chain driving a fake cluster whose CNPG instance is pinned to the
cordoned node.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.system_upgrade import SystemUpgradeRun
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import orchestrator, per_node, preflight

FIRST = "worker-1_aaaa"
SECOND = "worker-0_bbbb"
NODE = "member-1"
TARGET = "2026.10.25-900"


class _DriveDied(BaseException):
    """The worker running the drive was killed (#2809: its liveness probe
    failed while Redis had no master). A BaseException, so neither the
    step wrapper nor the drive loop catches it, as with a SIGKILL."""


class _Cluster:
    """A CNPG cluster with one instance on each of three nodes (local-path
    volumes): a node's instance is evicted by its drain and comes back only
    once the node is uncordoned. ``cordoned`` / ``drained`` are the node
    names, so ``assert cluster.cordoned`` asks whether any node is."""

    def __init__(self) -> None:
        self.cordoned: set[str] = set()
        self.drained: set[str] = set()
        self.window = False
        self.calls: list[str] = []
        # (call, node) for the calls that name a node.
        self.node_calls: list[tuple[str, str]] = []

    def cnpg(self, *_a: Any, **_k: Any) -> tuple[int, dict[str, Any]]:
        ready = 3 - len(self.cordoned & self.drained)
        return 200, {"spec": {"instances": 3}, "status": {"readyInstances": ready}}

    def get_node(self, name: str) -> tuple[int, dict[str, Any]]:
        return 200, {"metadata": {"name": name}, "spec": {"unschedulable": name in self.cordoned}}

    def cordon(self, name: str) -> tuple[bool, None]:
        self.cordoned.add(name)
        self.calls.append("cordon")
        self.node_calls.append(("cordon", name))
        return True, None

    def uncordon(self, name: str) -> tuple[bool, None]:
        self.cordoned.discard(name)
        self.drained.discard(name)
        self.calls.append("uncordon")
        self.node_calls.append(("uncordon", name))
        return True, None

    def patch_window(self, _name: str, *, in_progress: bool, **_k: Any) -> tuple[bool, None]:
        self.window = in_progress
        self.calls.append(f"window={in_progress}")
        return True, None


def _ok(name: per_node.StepName) -> Any:
    async def _step(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name=name, started_at="t").finish(True)

    return _step


def _ok_check(name: str) -> preflight.PreflightResult:
    return preflight.PreflightResult(name=name, level="ok", message="ok", detail={})


@pytest.fixture
def cluster(monkeypatch: pytest.MonkeyPatch) -> _Cluster:
    """The real preflight (with its CNPG wait), cordon, uncordon and
    cluster-verify steps against ``_Cluster``; the host-side steps stubbed."""
    c = _Cluster()
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node, "DEFAULT_CNPG_READY_TIMEOUT_S", 0.2)
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", c.cnpg)
    monkeypatch.setattr(per_node.k8s, "get_node", c.get_node)
    monkeypatch.setattr(per_node.k8s, "cordon_node", c.cordon)
    monkeypatch.setattr(per_node.k8s, "uncordon_node", c.uncordon)
    monkeypatch.setattr(per_node.k8s, "patch_cnpg_maintenance_window", c.patch_window)
    monkeypatch.setattr(per_node.k8s, "get_config", lambda: None)

    real_preflight = per_node._step_preflight

    async def _preflight(*a: Any, **kw: Any) -> per_node.StepResult:
        c.calls.append("preflight")
        return await real_preflight(*a, **{**kw, "cnpg_timeout_s": 0.2})

    real_verify = per_node._step_cluster_verify

    async def _verify(target: str, **kw: Any) -> per_node.StepResult:
        return await real_verify(target, **{**kw, "cnpg_timeout_s": 0.2})

    async def _drain(node_name: str, *_a: Any, **_k: Any) -> per_node.StepResult:
        c.drained.add(node_name)
        c.calls.append("drain")
        c.node_calls.append(("drain", node_name))
        return per_node.StepResult(name="drain", started_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_preflight", _preflight)
    monkeypatch.setattr(per_node, "_step_cluster_verify", _verify)
    monkeypatch.setattr(per_node, "_step_drain", _drain)
    for name in (
        "mirror_ready",
        "trigger_slot_apply",
        "stage",
        "verify_primary_moved",
        "reboot",
        "health_gate",
        "convergence",
    ):
        monkeypatch.setattr(per_node, f"_step_{name}", _ok(name))
    report = preflight.PreflightReport(
        target_version=TARGET,
        current_version="2026.10.24-1",
        overall="ok",
        can_start=True,
        results=[_ok_check("x")],
    )
    monkeypatch.setattr(preflight, "run_all", AsyncMock(return_value=report))
    monkeypatch.setattr(
        preflight, "check_replication_lag", AsyncMock(return_value=_ok_check("repl"))
    )
    monkeypatch.setattr(preflight, "check_quorum", lambda: _ok_check("quorum"))
    return c


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    s = SimpleNamespace(
        release_if_held=MagicMock(return_value=True),
        alert=AsyncMock(return_value=None),
        enqueued=[],
    )
    monkeypatch.delenv("NODE_NAME", raising=False)
    monkeypatch.setattr(orchestrator.mutex, "acquire", lambda **_kw: (True, None))
    monkeypatch.setattr(orchestrator.mutex, "renew", lambda **_kw: (True, None))
    monkeypatch.setattr(
        orchestrator, "_enqueue_drive", lambda rid, *, avoid_node: s.enqueued.append(avoid_node)
    )
    monkeypatch.setattr(orchestrator.mutex, "release_if_held", s.release_if_held)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))
    monkeypatch.setattr(orchestrator.upgrade_alerts, "emit_upgrade_failed_alert", s.alert)
    monkeypatch.setattr(orchestrator, "_BETWEEN_NODES_PAUSE_S", 0.01)
    monkeypatch.setattr(
        orchestrator.chart_bump,
        "bump_chart_image_tag",
        AsyncMock(
            return_value=SimpleNamespace(
                ok=True, rolled_deployments=[], migrate_job_state=None, skipped=True, error=None
            )
        ),
    )
    monkeypatch.setattr(orchestrator.chart_bump, "result_to_dict", lambda _b: {})
    monkeypatch.setattr(orchestrator.safety, "verify_post_upgrade", AsyncMock(return_value=[]))
    monkeypatch.setattr(orchestrator.safety, "verification_overall", lambda _r: "ok")
    return s


@pytest_asyncio.fixture
async def other(db_session: AsyncSession) -> Any:
    """A second session: the drive that takes the run over."""
    async with AsyncSession(bind=db_session.bind, expire_on_commit=False) as s:
        yield s


async def _make_run(db: AsyncSession, nodes: list[str] | None = None) -> SystemUpgradeRun:
    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version=TARGET,
        source_versions={},
        plan={
            "node_order": nodes or [NODE],
            "slot_image_url": "http://x",
            "cnpg_cluster_name": "pg",
            "cnpg_namespace": "spatium",
        },
        progress={"per_node": {}, "events": [{"event": "started"}]},
        lease_holder=FIRST,
        started_at=datetime.now(UTC),
    )
    db.add(run)
    await db.commit()
    return run


async def _first_drive_dies_at(
    db: AsyncSession, run: SystemUpgradeRun, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """Drive the run until ``step`` starts, then kill the drive."""

    async def _die(*_a: Any, **_k: Any) -> per_node.StepResult:
        raise _DriveDied

    with monkeypatch.context() as m:
        m.setattr(per_node, f"_step_{step}", _die)
        with pytest.raises(_DriveDied):
            await orchestrator._drive_loop(db, run, asyncio.Event(), FIRST)


async def _take_over(db: AsyncSession, run_id: uuid.UUID) -> SystemUpgradeRun:
    """The second drive's view of the run once it holds the Lease."""
    row = await db.get(SystemUpgradeRun, run_id, populate_existing=True)
    assert row is not None
    row.lease_holder = SECOND
    await db.commit()
    return row


@pytest.mark.asyncio
async def test_a_takeover_after_the_drain_resumes_the_node_and_completes_it(
    db_session: AsyncSession,
    other: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
) -> None:
    """The walk's shape: the drive dies after the drain, before the reboot.
    The node is cordoned and its instance Pending (CNPG 2/3). The second
    drive must not wait for that instance at preflight: it resumes at the
    reboot and the node completes, uncordoned and with the window cleared.

    Negative control: on unpatched code the second drive starts the node at
    ``preflight``, the CNPG wait times out on the evicted instance, the run
    fails ``preflight_fail``, and the node is left cordoned with the window
    on."""
    run = await _make_run(db_session)
    await _first_drive_dies_at(db_session, run, monkeypatch, "reboot")
    assert cluster.cordoned and cluster.drained and cluster.window
    assert cluster.cnpg()[1]["status"]["readyInstances"] == 2

    row = await _take_over(other, run.id)
    assert row.progress["in_flight"]["node"] == NODE
    assert row.progress["in_flight"]["step"] == "reboot"
    # The cordon step's own read, from before this run's cordon.
    assert row.progress["in_flight"]["was_unschedulable"] is False

    cluster.calls.clear()
    await orchestrator._drive_loop(other, row, asyncio.Event(), SECOND)

    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.state == "succeeded", (row.last_error, row.progress["per_node"])
    entry = row.progress["per_node"][NODE]
    assert entry["ok"] is True
    assert entry["resumed_at"] == "reboot"
    assert [s["name"] for s in entry["steps"]] == [
        "reboot",
        "health_gate",
        "convergence",
        "uncordon",
        "cluster_verify",
    ]
    assert "preflight" not in cluster.calls
    assert not cluster.cordoned and not cluster.window
    # The node ended, so nothing is left for a later drive to resume.
    assert "in_flight" not in row.progress
    started = [e for e in row.progress["events"] if e["event"] == "node_started"]
    assert started[-1].get("resumed_at") == "reboot"
    stubs.alert.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failure_after_a_takeover_releases_the_node(
    db_session: AsyncSession,
    other: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
) -> None:
    """The resumed node fails (the host never comes back on the target):
    the second drive releases what the FIRST drive took — the cordon and the
    window — and the run fails at the step that failed, not at preflight.

    Negative control: on unpatched code the node fails at ``preflight`` and
    neither the cordon nor the window is released."""
    run = await _make_run(db_session)
    await _first_drive_dies_at(db_session, run, monkeypatch, "reboot")
    row = await _take_over(other, run.id)

    async def _gate(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="health_gate", started_at="t").finish(
            False, error="health gate timed out after 1800s"
        )

    monkeypatch.setattr(per_node, "_step_health_gate", _gate)
    await orchestrator._drive_loop(other, row, asyncio.Event(), SECOND)

    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.state == "failed"
    entry = row.progress["per_node"][NODE]
    assert entry["failed_at"] == "health_gate"
    assert entry["failure_category"] == "node_unreachable_after_apply"
    assert entry["steps"][-1]["name"] == "release_node"
    assert entry["steps"][-1]["ok"] is True
    assert not cluster.cordoned and not cluster.window
    assert "in_flight" not in row.progress
    stubs.alert.assert_awaited_once()
    assert stubs.alert.await_args.kwargs["failed_at_step"] == "health_gate"


@pytest.mark.asyncio
async def test_a_takeover_before_anything_is_held_starts_at_preflight(
    db_session: AsyncSession,
    other: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
) -> None:
    """A drive that died at the node's preflight held nothing: the next one
    starts the node over at preflight, as before."""
    run = await _make_run(db_session)
    await _first_drive_dies_at(db_session, run, monkeypatch, "preflight")
    row = await _take_over(other, run.id)
    assert row.progress["in_flight"]["step"] == "preflight"

    cluster.calls.clear()
    await orchestrator._drive_loop(other, row, asyncio.Event(), SECOND)
    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.state == "succeeded", row.last_error
    assert "resumed_at" not in row.progress["per_node"][NODE]
    assert cluster.calls[0] == "preflight"


@pytest.mark.asyncio
async def test_a_clean_run_leaves_no_checkpoint_behind(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
) -> None:
    """The normal path: one drive, the node completes from preflight, and
    its checkpoint is gone once the node is recorded."""
    run = await _make_run(db_session)
    run_id = run.id
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), FIRST)
    db_session.expire_all()
    row = await db_session.get(SystemUpgradeRun, run_id, populate_existing=True)
    assert row is not None
    assert row.state == "succeeded", row.last_error
    assert cluster.calls == [
        "preflight",
        "window=True",
        "cordon",
        "drain",
        "uncordon",
        "window=False",
    ]
    assert "in_flight" not in row.progress


@pytest.mark.asyncio
async def test_a_checkpoint_after_a_takeover_is_not_written_by_the_old_drive(
    db_session: AsyncSession, other: AsyncSession
) -> None:
    """Only the Lease holder's checkpoint lands (#1704's rule)."""
    run = await _make_run(db_session)
    await _take_over(other, run.id)
    write = orchestrator._checkpoint_writer(db_session, run.id, FIRST)
    await write({"node": NODE, "step": "drain"})
    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert "in_flight" not in row.progress

    write = orchestrator._checkpoint_writer(other, run.id, SECOND)
    await write({"node": NODE, "step": "drain"})
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.progress["in_flight"] == {"node": NODE, "step": "drain"}
    # Merged in: the rest of ``progress`` is untouched.
    assert row.progress["events"] == [{"event": "started"}]


# ── The chain's own resume semantics ─────────────────────────────────────────


def _run_chain(**kw: Any) -> Any:
    return per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock(), rollback=AsyncMock()),
        node_name=NODE,
        target_version=TARGET,
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        cnpg_cluster_name="pg",
        cnpg_namespace="spatium",
        **kw,
    )


def _stub_all(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
    for name in per_node.CHAIN:
        monkeypatch.setattr(per_node, f"_step_{name}", overrides.get(name) or _ok(name))


def _failing(name: per_node.StepName) -> Any:
    async def _step(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name=name, started_at="t").finish(False, error=f"{name} broke")

    return _step


@pytest.mark.asyncio
async def test_a_resumed_cordon_counts_as_held_and_keeps_the_earlier_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resumed IN the cordon step: the earlier drive's cordon may have
    landed. The re-run cordon must take the earlier read of the node (not
    schedulable-before = False), not re-read the node, which this run's own
    cordon makes unschedulable; and a failure then uncordons."""
    _stub_all(
        monkeypatch,
        preflight=_failing("preflight"),
        cordon=per_node._step_cordon,
        drain=_failing("drain"),
    )
    with (
        patch.object(
            per_node.k8s, "get_node", return_value=(200, {"spec": {"unschedulable": True}})
        ),
        patch.object(per_node.k8s, "cordon_node", return_value=(True, None)),
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(
            per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)
        ) as mw,
    ):
        result = await _run_chain(
            resume=per_node.NodeResume(
                step="cordon", was_unschedulable=False, pre_cordon_known=True
            )
        )
    assert result.failed_at == "drain"
    assert [s.name for s in result.steps] == [
        "cordon",
        "verify_primary_moved",
        "drain",
        "release_node",
    ]
    assert result.steps[0].detail["was_unschedulable"] is False
    un.assert_called_once_with(NODE)
    mw.assert_called_once_with("pg", in_progress=False, reuse_pvc=True, namespace="spatium")


@pytest.mark.asyncio
async def test_a_resume_keeps_an_operators_cordon(monkeypatch: pytest.MonkeyPatch) -> None:
    """The earlier drive read the node as already cordoned by an operator:
    the resumed chain's release must not uncordon it."""
    _stub_all(monkeypatch, health_gate=_failing("health_gate"))
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)),
    ):
        result = await _run_chain(
            resume=per_node.NodeResume(step="reboot", was_unschedulable=True, pre_cordon_known=True)
        )
    assert result.failed_at == "health_gate"
    assert result.steps[-1].detail["uncordon_skipped"]
    un.assert_not_called()


@pytest.mark.asyncio
async def test_a_failure_in_a_resumed_window_step_clears_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resumed IN ``cnpg_maintenance_on``: the earlier drive's patch may have
    landed, so a failure clears the window. The node was never cordoned by
    this run, so it is not uncordoned."""
    _stub_all(monkeypatch, cnpg_maintenance_on=_failing("cnpg_maintenance_on"))
    with (
        patch.object(per_node.k8s, "uncordon_node") as un,
        patch.object(
            per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)
        ) as mw,
    ):
        result = await _run_chain(resume=per_node.NodeResume(step="cnpg_maintenance_on"))
    assert result.failed_at == "cnpg_maintenance_on"
    assert result.steps[-1].name == "release_node"
    un.assert_not_called()
    mw.assert_called_once_with("pg", in_progress=False, reuse_pvc=True, namespace="spatium")


@pytest.mark.asyncio
async def test_a_resume_carries_the_runs_stamp_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stage / reboot / health-gate reads judge a ``done`` or ``failed``
    against THIS run's stamp; a resume past the stamp must keep its time."""
    seen: dict[str, Any] = {}

    def _record(name: per_node.StepName) -> Any:
        async def _step(*_a: Any, **kw: Any) -> per_node.StepResult:
            seen[name] = kw.get("stamped_at")
            return per_node.StepResult(name=name, started_at="t").finish(True)

        return _step

    _stub_all(monkeypatch, reboot=_record("reboot"), health_gate=_record("health_gate"))
    stamped = datetime(2026, 10, 25, 23, 55, tzinfo=UTC)
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)),
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)),
    ):
        result = await _run_chain(resume=per_node.NodeResume(step="drain", stamped_at=stamped))
    assert result.ok is True
    assert seen == {"reboot": stamped, "health_gate": stamped}


@pytest.mark.asyncio
async def test_the_chain_checkpoints_before_each_step(monkeypatch: pytest.MonkeyPatch) -> None:
    """One checkpoint per step run, naming the step about to run; the
    cordon's pre-read rides every checkpoint after it."""
    _stub_all(monkeypatch, cordon=per_node._step_cordon)
    entries: list[dict[str, Any]] = []

    async def _checkpoint(entry: dict[str, Any]) -> None:
        entries.append(entry)

    with (
        patch.object(per_node.k8s, "get_node", return_value=(200, {"spec": {}})),
        patch.object(per_node.k8s, "cordon_node", return_value=(True, None)),
    ):
        result = await _run_chain(checkpoint=_checkpoint)
    assert result.ok is True
    assert [e["step"] for e in entries] == list(per_node.CHAIN)
    assert all(e["node"] == NODE for e in entries)
    by_step = {e["step"]: e for e in entries}
    assert "was_unschedulable" not in by_step["cordon"]
    assert by_step["drain"]["was_unschedulable"] is False
    # Round-trips into a resume point.
    resume = per_node.resume_from_checkpoint(by_step["drain"], NODE)
    assert resume is not None
    assert resume.step == "drain"
    assert resume.pre_cordon_known and resume.was_unschedulable is False


@pytest.mark.asyncio
async def test_a_failing_checkpoint_does_not_fail_the_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The checkpoint is bookkeeping: a database error storing it is logged
    and the node goes on."""
    _stub_all(monkeypatch)

    async def _checkpoint(_entry: dict[str, Any]) -> None:
        raise ConnectionError("connection refused")

    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)),
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)),
    ):
        result = await _run_chain(checkpoint=_checkpoint)
    assert result.ok is True


def test_resume_point_from_checkpoint() -> None:
    assert per_node.resume_from_checkpoint(None, NODE) is None
    assert per_node.resume_from_checkpoint({"node": "other", "step": "drain"}, NODE) is None
    assert per_node.resume_from_checkpoint({"node": NODE, "step": "bogus"}, NODE) is None
    # Nothing is held at preflight: a fresh start, not a resume.
    assert per_node.resume_from_checkpoint({"node": NODE, "step": "preflight"}, NODE) is None
    r = per_node.resume_from_checkpoint(
        {"node": NODE, "step": "reboot", "stamped_at": "2026-10-25T23:55:00+00:00"}, NODE
    )
    assert r is not None
    assert r.step == "reboot"
    assert r.stamped_at == datetime(2026, 10, 25, 23, 55, tzinfo=UTC)
    assert r.pre_cordon_known is False and r.was_unschedulable is None


# ── The walk's crash: a checkpoint met the CNPG switchover ───────────────────


class _Orig(Exception):
    def __init__(self, msg: str, sqlstate: str | None = None) -> None:
        super().__init__(msg)
        self.sqlstate = sqlstate


def _connect_failed() -> DBAPIError:
    """A connection error, as the switchover's refused connect is classified
    (``is_transient_db_error``)."""
    return DBAPIError("UPDATE system_upgrade_run", {}, _Orig("Connect call failed", "08006"))


@pytest.fixture
def no_db_backoff(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []

    async def _sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(per_node, "_db_retry_sleep", _sleep)
    return slept


@pytest.mark.asyncio
async def test_a_checkpoint_that_meets_the_switchover_is_retried_and_the_node_completes(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
    no_db_backoff: list[float],
) -> None:
    """The gate walk's case 1 (#2809): on a clean roll, the checkpoint before
    ``drain`` landed 2-3 s into the CNPG switchover the cordon of the
    primary's node started, and its connect was refused. The failure rolled
    the drive's session back, which expires the run row, and the node-end
    fence's read of ``run.id`` then raised ``MissingGreenlet``: the drive
    crashed at the end of a node that had upgraded, ``in_flight`` left on it.

    The checkpoint is now retried on a fresh connection and the fence never
    loads an expired attribute, so the node and the run complete.

    Negative control: on ``04addc2`` the drive raises MissingGreenlet out of
    ``_drive_loop``."""
    run = await _make_run(db_session)
    run_id = run.id
    real_writer = orchestrator._checkpoint_writer
    attempts: list[str] = []

    def _writer(db: AsyncSession, rid: uuid.UUID, holder: str | None) -> Any:
        write = real_writer(db, rid, holder)

        async def _write(entry: dict[str, Any]) -> None:
            attempts.append(entry["step"])
            if entry["step"] == "drain" and attempts.count("drain") == 1:
                # The UPDATE began a transaction on the drive's session, and
                # the connection under it was closed by the switchover.
                await db.execute(select(1))
                raise _connect_failed()
            await write(entry)

        return _write

    monkeypatch.setattr(orchestrator, "_checkpoint_writer", _writer)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), FIRST)

    db_session.expire_all()
    row = await db_session.get(SystemUpgradeRun, run_id, populate_existing=True)
    assert row is not None
    assert row.state == "succeeded", row.last_error
    assert attempts.count("drain") == 2
    assert no_db_backoff == [per_node._DB_RETRY_BACKOFF_S[0]]
    assert "in_flight" not in row.progress
    assert "resumed_at" not in row.progress["per_node"][NODE]


@pytest.mark.asyncio
async def test_a_step_that_rides_a_failover_does_not_crash_the_node_end(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
    no_db_backoff: list[float],
) -> None:
    """The same expiry from main's own path (#2177): a step whose read met a
    failover is retried after a rollback of the drive's session. The node-end
    fence must not load the expired run row.

    Negative control: on ``04addc2`` (and main) MissingGreenlet."""
    run = await _make_run(db_session)
    run_id = run.id
    calls = {"n": 0}

    async def _reboot(db: AsyncSession, *_a: Any, **_k: Any) -> per_node.StepResult:
        calls["n"] += 1
        # The reboot step reads the appliance row; the first read's
        # connection is closed under it by the failover.
        await db.execute(select(1))
        if calls["n"] == 1:
            raise _connect_failed()
        return per_node.StepResult(name="reboot", started_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_reboot", _reboot)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), FIRST)

    db_session.expire_all()
    row = await db_session.get(SystemUpgradeRun, run_id, populate_existing=True)
    assert row is not None
    assert row.state == "succeeded", row.last_error
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_a_checkpoint_gives_up_after_the_budget_and_the_node_goes_on(
    no_db_backoff: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A database still unreachable once the step budget is spent: the
    checkpoint is dropped (logged), never the node."""
    clock = {"t": 0.0}

    async def _sleep(delay: float) -> None:
        clock["t"] += delay

    monkeypatch.setattr(per_node, "_db_retry_sleep", _sleep)
    monkeypatch.setattr(per_node, "_db_retry_clock", lambda: clock["t"])
    db = MagicMock(rollback=AsyncMock())
    tries = {"n": 0}

    async def _checkpoint(_entry: dict[str, Any]) -> None:
        tries["n"] += 1
        raise _connect_failed()

    await per_node._store_checkpoint(
        db, _checkpoint, {"node": NODE, "step": "drain"}, node_name=NODE, step="drain"
    )
    assert tries["n"] > 1
    assert clock["t"] <= per_node.DB_FAILOVER_BUDGET_S
    assert db.rollback.await_count == tries["n"]


# ── Takeovers on a multi-node plan (the gate walk's read of the code) ────────

M1, M2, SEED = "member-1", "member-2", "seed"
PLAN = [M1, M2, SEED]


async def _drive_as(
    db: AsyncSession, run_id: uuid.UUID, holder: str, own_node: str | None, mp: Any
) -> SystemUpgradeRun:
    """A whole drive (``drive_upgrade``: Lease takeover, then the loop) by a
    worker on ``own_node``."""
    if own_node is None:
        mp.delenv("NODE_NAME", raising=False)
    else:
        mp.setenv("NODE_NAME", own_node)
    return await orchestrator.drive_upgrade(db, run_id, holder=holder)


async def _first_drive_dies_in(
    db: AsyncSession, run: SystemUpgradeRun, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """The first drive, on ``M1``'s worker, defers ``M1`` and drives ``M2``
    until ``step`` starts, then its worker is killed."""
    monkeypatch.setenv("NODE_NAME", M1)
    await _first_drive_dies_at(db, run, monkeypatch, step)


def _started_since_takeover(row: SystemUpgradeRun) -> list[dict[str, Any]]:
    events = row.progress["events"]
    last = max(i for i, e in enumerate(events) if e["event"] == "lease_takeover")
    return [e for e in events[last:] if e["event"] == "node_started"]


@pytest.mark.asyncio
async def test_a_takeover_on_a_third_worker_resumes_the_node_in_flight_first(
    db_session: AsyncSession,
    other: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
) -> None:
    """Gate walk case 2, and the concern read from the code: the first drive
    (on M1's worker) dies after M2's drain. The takeover runs on the seed's
    worker, so plan order with its own node deferred names M1. It must resume
    M2 first, at the step it was in, with no CNPG wait for M2's evicted
    instance; then M1, then the seed via a hand-off, and the run succeeds.

    Negative control: on ``04addc2`` the takeover starts M1 at preflight,
    whose CNPG wait counts M2's evicted instance (2/3) and times out; the run
    fails ``preflight_fail`` with M2 still cordoned."""
    run = await _make_run(db_session, PLAN)
    await _first_drive_dies_in(db_session, run, monkeypatch, "reboot")
    assert cluster.cordoned == {M2} and cluster.drained == {M2} and cluster.window

    cluster.calls.clear()
    cluster.node_calls.clear()
    await _drive_as(other, run.id, SECOND, SEED, monkeypatch)

    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.state == "running", (row.last_error, row.progress["per_node"])
    started = _started_since_takeover(row)
    assert started[0] == {**started[0], "node": M2, "resumed_at": "reboot"}
    assert [e["node"] for e in started] == [M2, M1]
    # M2's chain went on from the reboot: its uncordon came first, before
    # any preflight (whose CNPG wait would have timed out on 2/3).
    assert cluster.node_calls[0] == ("uncordon", M2)
    assert cluster.calls.index("uncordon") < cluster.calls.index("preflight")
    # The seed is this worker's own node: handed to a worker elsewhere.
    assert stubs.enqueued == [SEED]

    third = "worker-2_cccc"
    await _drive_as(other, run.id, third, M1, monkeypatch)
    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.state == "succeeded", (row.last_error, row.progress["per_node"])
    per = row.progress["per_node"]
    assert all(per[n]["ok"] is True for n in PLAN)
    assert per[M2]["resumed_at"] == "reboot"
    assert "resumed_at" not in per[M1] and "resumed_at" not in per[SEED]
    assert "in_flight" not in row.progress
    assert not cluster.cordoned and not cluster.window
    stubs.alert.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_resumed_node_that_fails_on_a_third_worker_is_released(
    db_session: AsyncSession,
    other: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
) -> None:
    """Gate walk case 3: as above, but M2 never comes back healthy after the
    takeover. M2 is uncordoned, the window is off, the run fails at the step
    that failed (not ``preflight_fail``), the failed-run alert is raised, and
    M1 is never started.

    Negative control: on ``04addc2`` the takeover fails M1 at preflight,
    ``preflight_fail``, M2 left cordoned and the window on."""
    run = await _make_run(db_session, PLAN)
    await _first_drive_dies_in(db_session, run, monkeypatch, "reboot")

    async def _gate(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="health_gate", started_at="t").finish(
            False, error="health gate timed out after 1800s"
        )

    monkeypatch.setattr(per_node, "_step_health_gate", _gate)
    await _drive_as(other, run.id, SECOND, SEED, monkeypatch)

    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.state == "failed"
    assert [e["node"] for e in _started_since_takeover(row)] == [M2]
    entry = row.progress["per_node"][M2]
    assert entry["resumed_at"] == "reboot"
    assert entry["failed_at"] == "health_gate"
    assert entry["failure_category"] != "preflight_fail"
    assert entry["steps"][-1]["name"] == "release_node" and entry["steps"][-1]["ok"]
    assert M1 not in row.progress["per_node"]
    assert not cluster.cordoned and not cluster.window
    assert "in_flight" not in row.progress
    stubs.alert.assert_awaited_once()
    assert stubs.alert.await_args.kwargs["failed_node"] == M2
    assert stubs.alert.await_args.kwargs["failed_at_step"] == "health_gate"


@pytest.mark.asyncio
async def test_a_takeover_during_stage_resumes_that_node_at_stage(
    db_session: AsyncSession,
    other: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
) -> None:
    """Gate walk case 4, ``stage``: the first drive dies while M2 stages.
    M2 is already stamped (``trigger_slot_apply`` ran), so it is resumed AT
    stage, before any other node starts, and the run succeeds.

    Negative control: on ``04addc2`` the takeover starts M1 instead, and M2
    is later restarted at preflight with no ``resumed_at``."""
    run = await _make_run(db_session, PLAN)
    await _first_drive_dies_in(db_session, run, monkeypatch, "stage")
    assert not cluster.cordoned

    await _drive_as(other, run.id, SECOND, SEED, monkeypatch)
    await _drive_as(other, run.id, "worker-2_cccc", M1, monkeypatch)

    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.state == "succeeded", (row.last_error, row.progress["per_node"])
    per = row.progress["per_node"]
    assert per[M2]["resumed_at"] == "stage"
    assert per[M2]["steps"][0]["name"] == "stage"
    first_takeover = next(
        i for i, e in enumerate(row.progress["events"]) if e["event"] == "lease_takeover"
    )
    started = [e for e in row.progress["events"][first_takeover:] if e["event"] == "node_started"]
    assert started[0]["node"] == M2
    assert "in_flight" not in row.progress
    assert not cluster.cordoned and not cluster.window


@pytest.mark.asyncio
async def test_a_takeover_during_preflight_restarts_that_node_from_preflight(
    db_session: AsyncSession,
    other: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    cluster: _Cluster,
    stubs: SimpleNamespace,
) -> None:
    """Gate walk case 4, ``preflight``: the first drive dies in M2's
    preflight, which holds nothing. The takeover drives the plan in order
    (M1 first), M2 later starts over at preflight with no ``resumed_at``,
    and the run succeeds. (Behaves the same on ``04addc2``.)"""
    run = await _make_run(db_session, PLAN)
    await _first_drive_dies_in(db_session, run, monkeypatch, "preflight")

    await _drive_as(other, run.id, SECOND, SEED, monkeypatch)
    await _drive_as(other, run.id, "worker-2_cccc", M1, monkeypatch)

    other.expire_all()
    row = await other.get(SystemUpgradeRun, run.id, populate_existing=True)
    assert row is not None
    assert row.state == "succeeded", (row.last_error, row.progress["per_node"])
    per = row.progress["per_node"]
    assert all("resumed_at" not in per[n] for n in PLAN)
    assert per[M2]["steps"][0]["name"] == "preflight"
    assert "in_flight" not in row.progress


# ── A crashed drive raises the failed-run alert ──────────────────────────────


@pytest.mark.asyncio
async def test_a_crashed_drive_raises_the_failed_run_alert_naming_the_node_in_flight(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk's two crashed runs ended ``failed`` with the
    cluster-upgrade-failed rule on and raised nothing: only the drive's own
    failure paths called the alert. The crash handler now raises it, naming
    the node in flight, and says what that node may still hold.

    Negative control: on ``04addc2`` the alert is never emitted."""
    from contextlib import asynccontextmanager

    from app.services.upgrades import alerts as upgrade_alerts
    from app.services.upgrades import mutex
    from app.tasks import upgrade_orchestrator as task

    run = await _make_run(db_session, PLAN)
    run.lease_holder = None
    run.progress = {
        **run.progress,
        "in_flight": {"node": M2, "step": "drain", "stamped_at": None, "at": "t"},
    }
    await db_session.commit()
    run_id = run.id
    monkeypatch.setattr(mutex, "release_if_held", lambda **_k: True)
    alert = AsyncMock(return_value=None)
    monkeypatch.setattr(upgrade_alerts, "emit_upgrade_failed_alert", alert)

    @asynccontextmanager
    async def _session() -> Any:
        yield db_session

    async def _drive(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("greenlet_spawn has not been called")

    monkeypatch.setattr(task, "task_session", _session)
    monkeypatch.setattr(task, "drive_upgrade", _drive)

    out = await task._async_drive(str(run_id))
    assert out["state"] == "failed"
    db_session.expire_all()
    row = await db_session.get(SystemUpgradeRun, run_id)
    assert row is not None and row.state == "failed"
    assert row.last_error is not None
    assert "orchestrator crashed" in row.last_error
    assert "cordon" in row.last_error and "maintenance_window" in row.last_error
    alert.assert_awaited_once()
    kw = alert.await_args.kwargs
    assert kw["failed_node"] == M2
    assert kw["failed_at_step"] == "drain"
    assert kw["category"] == upgrade_alerts.CATEGORY_OTHER


def test_in_flight_hold_names_only_what_the_step_may_hold() -> None:
    from app.tasks.upgrade_orchestrator import _in_flight_hold

    assert _in_flight_hold(None) == (None, None, [])
    assert _in_flight_hold({"in_flight": {"node": M2, "step": "stage"}}) == (M2, "stage", [])
    assert _in_flight_hold({"in_flight": {"node": M2, "step": "cnpg_maintenance_on"}})[2] == [
        "maintenance_window"
    ]
    assert _in_flight_hold({"in_flight": {"node": M2, "step": "uncordon"}})[2] == [
        "cordon",
        "maintenance_window",
    ]
    assert _in_flight_hold({"in_flight": {"node": M2, "step": "cluster_verify"}})[2] == []
