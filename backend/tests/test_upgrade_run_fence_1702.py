"""Only the Lease holder writes a run's terminal state (#1702, #1704, #1707).

A drive keeps its own copy of the run row for the whole of a node. Written
back when the node ends, that copy overwrote an operator's Halt or Abort
(#1702), a second drive's takeover (#1704), and an Abort freed the Lease while
the aborted drive was still changing the cluster (#1707). These run a real
drive loop against a real row, with a second session standing in for the API.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.system_upgrade import SystemUpgradeRun
from app.services.upgrades import orchestrator, per_node

ME = "worker-0_aaaa"


@pytest_asyncio.fixture
async def api(db_session: AsyncSession) -> Any:
    """A second session: the API's, separate from the drive's."""
    async with AsyncSession(bind=db_session.bind, expire_on_commit=False) as s:
        yield s


async def _make_run(db: AsyncSession, state: str = "running") -> SystemUpgradeRun:
    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state=state,
        target_version="2026.10.20-1",
        source_versions={},
        plan={"node_order": ["node-a"], "slot_image_url": "http://x"},
        progress={"per_node": {}, "events": [{"event": "started"}]},
        lease_holder=ME,
        started_at=datetime.now(UTC),
    )
    db.add(run)
    await db.commit()
    return run


def _result(ok: bool) -> per_node.SingleNodeResult:
    step = per_node.StepResult(name="drain", started_at="t", finished_at="t").finish(True)
    return per_node.SingleNodeResult(
        node_name="node-a",
        target_version="2026.10.20-1",
        ok=ok,
        failed_at=None if ok else "reboot",
        steps=[step],
        error=None if ok else "supervisor reported upgrade failed",
    )


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    s = SimpleNamespace(
        release_if_held=MagicMock(return_value=True),
        alert=AsyncMock(return_value=None),
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


def _node_stub(monkeypatch: pytest.MonkeyPatch, *, ok: bool, during: Any) -> None:
    async def _fake(*_a: Any, **_kw: Any) -> per_node.SingleNodeResult:
        await during()  # what the operator does while the node is being driven
        return _result(ok)

    monkeypatch.setattr(per_node, "single_node_upgrade", _fake)


async def _fresh(db: AsyncSession, run_id: uuid.UUID) -> SystemUpgradeRun:
    db.expire_all()
    row = await db.get(SystemUpgradeRun, run_id, populate_existing=True)
    assert row is not None
    return row


def _events(row: SystemUpgradeRun) -> list[str]:
    return [e["event"] for e in row.progress["events"]]


# ── #1702: a Halt or Abort mid-node survives the node ending ──────────────────


@pytest.mark.asyncio
async def test_halt_mid_node_survives_the_node_failing(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    run = await _make_run(db_session)
    _node_stub(monkeypatch, ok=False, during=lambda: orchestrator.halt_upgrade(api, run.id))
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await _fresh(api, run.id)
    assert row.state == "halted"
    assert row.finished_at is None
    assert "halted" in _events(row)
    assert "node_failed" not in _events(row)
    assert row.progress["per_node"]["node-a"]["ok"] is False
    stubs.alert.assert_not_awaited()
    # The drive gives its own Lease up, so Resume's drive can take it.
    stubs.release_if_held.assert_called_with(
        holder=ME, attempts=orchestrator._LEASE_RELEASE_ATTEMPTS
    )


@pytest.mark.asyncio
async def test_abort_mid_node_survives_the_node_failing(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    run = await _make_run(db_session)
    aborted_at: list[datetime | None] = []

    async def _abort() -> None:
        out = await orchestrator.abort_upgrade(api, run.id)
        aborted_at.append(out.finished_at)

    _node_stub(monkeypatch, ok=False, during=_abort)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await _fresh(api, run.id)
    assert row.state == "aborted"
    assert row.finished_at == aborted_at[0]
    assert "aborted" in _events(row)
    assert "node_failed" not in _events(row)
    stubs.alert.assert_not_awaited()


@pytest.mark.asyncio
async def test_abort_mid_node_survives_the_node_succeeding(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    run = await _make_run(db_session)
    _node_stub(monkeypatch, ok=True, during=lambda: orchestrator.abort_upgrade(api, run.id))
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await _fresh(api, run.id)
    assert row.state == "aborted"
    assert "aborted" in _events(row)
    assert row.progress["per_node"]["node-a"]["ok"] is True


@pytest.mark.asyncio
async def test_a_halt_and_resume_mid_node_keep_their_events(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    """The node ends well and the run finishes, with the halt and the resume
    still in its history."""
    run = await _make_run(db_session)

    async def _halt_then_resume() -> None:
        await orchestrator.halt_upgrade(api, run.id)
        await orchestrator.resume_upgrade(api, run.id)

    _node_stub(monkeypatch, ok=True, during=_halt_then_resume)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await _fresh(api, run.id)
    assert row.state == "succeeded"
    events = _events(row)
    for expected in ("halted", "resumed", "node_succeeded"):
        assert expected in events, events


# ── #1704: a drive that lost the Lease writes nothing ─────────────────────────


@pytest.mark.asyncio
async def test_a_drive_that_lost_the_lease_does_not_fail_the_run(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    run = await _make_run(db_session)

    async def _takeover() -> None:
        row = await api.get(SystemUpgradeRun, run.id)
        assert row is not None
        row.lease_holder = "worker-1_bbbb"
        await api.commit()

    _node_stub(monkeypatch, ok=False, during=_takeover)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await _fresh(api, run.id)
    assert row.state == "running"
    assert row.lease_holder == "worker-1_bbbb"
    assert row.finished_at is None
    assert "node_failed" not in _events(row)
    stubs.alert.assert_not_awaited()
    # Not the other drive's Lease to give up.
    stubs.release_if_held.assert_not_called()


@pytest.mark.asyncio
async def test_the_crash_handler_leaves_a_run_another_drive_holds(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks import upgrade_orchestrator as task

    run = await _make_run(db_session)
    release = MagicMock(return_value=True)
    monkeypatch.setattr(orchestrator.mutex, "release_if_held", release)

    async def _crash(
        db: AsyncSession, rid: uuid.UUID, *, holder: str, avoid_version: str | None = None
    ) -> None:
        # Another drive has taken the run over by the time this one crashes.
        other = await db.get(SystemUpgradeRun, rid)
        assert other is not None
        other.lease_holder = "worker-1_bbbb"
        await db.commit()
        raise RuntimeError("database went away")

    monkeypatch.setattr(task, "drive_upgrade", _crash)
    out = await task._async_drive(str(run.id))
    assert out["state"] == "failed"  # this task's own result

    row = await _fresh(db_session, run.id)
    assert row.state == "running"
    assert row.last_error is None


@pytest.mark.asyncio
async def test_the_crash_handler_still_fails_its_own_run(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks import upgrade_orchestrator as task

    run = await _make_run(db_session)
    monkeypatch.setattr(orchestrator.mutex, "release_if_held", MagicMock(return_value=True))
    monkeypatch.setattr(orchestrator.mutex, "drive_identity", lambda: ME)

    async def _crash(
        db: AsyncSession, rid: uuid.UUID, *, holder: str, avoid_version: str | None = None
    ) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(task, "drive_upgrade", _crash)
    await task._async_drive(str(run.id))
    row = await _fresh(db_session, run.id)
    assert row.state == "failed"
    assert "boom" in (row.last_error or "")


@pytest.mark.asyncio
async def test_a_renewal_that_raises_stops_the_drive(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = asyncio.Event()
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_INTERVAL_S", 0.01)

    def _boom(**_kw: Any) -> Any:
        raise RuntimeError("http.client blew up")

    monkeypatch.setattr(orchestrator.mutex, "renew", _boom)
    await asyncio.wait_for(orchestrator._lease_renewal_loop(stop, ME), 2)
    assert stop.is_set()


# ── #1707: Abort leaves the Lease to the drive ────────────────────────────────


@pytest.mark.asyncio
async def test_abort_of_a_running_run_keeps_the_lease_until_the_drive_exits(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    released = MagicMock(return_value=(True, None))
    monkeypatch.setattr(orchestrator.mutex, "release", released)
    run = await _make_run(db_session)
    seen_during_node: list[int] = []

    async def _abort() -> None:
        await orchestrator.abort_upgrade(api, run.id)
        # The drive is still on its node: the Lease must still be held.
        seen_during_node.append(released.call_count)
        seen_during_node.append(stubs.release_if_held.call_count)

    _node_stub(monkeypatch, ok=True, during=_abort)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    assert seen_during_node == [0, 0]
    released.assert_not_called()
    # The drive released its own, once it had stopped.
    stubs.release_if_held.assert_called_once_with(
        holder=ME, attempts=orchestrator._LEASE_RELEASE_ATTEMPTS
    )


@pytest.mark.asyncio
async def test_abort_of_a_planned_run_frees_the_lease(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    released = MagicMock(return_value=(True, None))
    monkeypatch.setattr(orchestrator.mutex, "release", released)
    run = await _make_run(db_session, state="planned")
    out = await orchestrator.abort_upgrade(db_session, run.id)
    assert out.state == "aborted"
    released.assert_called_once()


# ── Validation pass: the fence's gaps ─────────────────────────────────────────


def _locked_elsewhere_probe(api: AsyncSession, run_id: uuid.UUID, seen: list[bool]) -> Any:
    """A probe the drive calls mid-step: can another session lock the run row
    right now? A row lock held across a slow call (alert delivery, the
    post-upgrade verify) makes Halt and Abort wait on it."""
    from sqlalchemy import select
    from sqlalchemy.exc import DBAPIError

    async def _probe() -> None:
        try:
            await api.execute(
                select(SystemUpgradeRun)
                .where(SystemUpgradeRun.id == run_id)
                .with_for_update(nowait=True)
            )
            seen.append(False)
        except DBAPIError:
            seen.append(True)
        await api.rollback()

    return _probe


@pytest.mark.asyncio
async def test_a_halt_while_the_hold_is_placed_stops_the_node_and_keeps_its_event(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    """ensure_hold talks to the kubeapi. A Halt landing then was overwritten
    by the commit that followed, and the node it was meant to stop ran."""
    from app.services.upgrades import shared_tags

    run = await _make_run(db_session)

    async def _hold(_db: AsyncSession, r: SystemUpgradeRun) -> Any:
        shared_tags._store(r, {"mode": "hold", "from_tag": "a", "released_at": None})
        await orchestrator.halt_upgrade(api, run.id)
        return shared_tags.StepOutcome(ok=True, mode="hold")

    monkeypatch.setattr(orchestrator.shared_tags, "ensure_hold", _hold)

    async def _must_not_run(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("a halted run must not start a node")

    monkeypatch.setattr(per_node, "single_node_upgrade", _must_not_run)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await _fresh(api, run.id)
    assert row.state == "halted"
    assert "halted" in _events(row)
    assert "node_started" not in _events(row)
    # The pins went on: the record of them is kept for whoever ends the hold.
    assert row.progress["shared_tags"]["mode"] == "hold"


@pytest.mark.asyncio
async def test_a_halt_during_the_settle_wait_keeps_its_event_and_the_flip_record(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    """settle() changes the drive's copy in memory; the fence's own re-read
    autoflushed that stale copy over the Halt before it could see it."""
    from app.config import settings
    from app.services.upgrades import shared_tags

    run = await _make_run(db_session)
    run.progress = {
        "per_node": {"node-a": {"ok": True}},
        "events": [{"event": "started"}],
        "shared_tags": {
            "mode": "hold",
            "from_tag": "2026.10.13-1",
            "released_at": "t",
            "flip": {"state": "flipped", "workloads": [], "handed_off_at": "t"},
        },
    }
    await db_session.commit()
    monkeypatch.setattr(settings, "version", "2026.10.20-1")

    async def _settle(_db: AsyncSession, r: SystemUpgradeRun, **_kw: Any) -> Any:
        record = shared_tags.record_of(r)
        record["flip"] = {**record["flip"], "state": "settled"}
        shared_tags._store(r, record)
        await orchestrator.halt_upgrade(api, run.id)
        return shared_tags.StepOutcome(ok=True, mode="hold")

    monkeypatch.setattr(orchestrator.shared_tags, "settle", _settle)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await _fresh(api, run.id)
    assert row.state == "halted"
    assert "halted" in _events(row)
    assert row.progress["shared_tags"]["flip"]["state"] == "settled"


@pytest.mark.asyncio
async def test_a_drive_that_lost_the_lease_records_nothing_even_after_a_halt(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    """After a takeover the row is the other drive's, whatever its state."""
    run = await _make_run(db_session)

    async def _takeover_then_halt() -> None:
        row = await api.get(SystemUpgradeRun, run.id)
        assert row is not None
        row.lease_holder = "worker-1_bbbb"
        await api.commit()
        await orchestrator.halt_upgrade(api, run.id)

    _node_stub(monkeypatch, ok=False, during=_takeover_then_halt)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await _fresh(api, run.id)
    assert row.state == "halted"
    assert "node_ended_after_stop" not in _events(row)
    assert row.progress["per_node"] == {}
    stubs.release_if_held.assert_not_called()


@pytest.mark.asyncio
async def test_a_failed_nodes_alert_is_delivered_without_the_row_lock(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    run = await _make_run(db_session)
    locked: list[bool] = []
    probe = _locked_elsewhere_probe(api, run.id, locked)

    async def _alert(*_a: Any, **_kw: Any) -> None:
        await probe()

    monkeypatch.setattr(orchestrator.upgrade_alerts, "emit_upgrade_failed_alert", _alert)
    _node_stub(monkeypatch, ok=False, during=AsyncMock())
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    assert locked == [False]
    row = await _fresh(api, run.id)
    assert row.state == "failed"


@pytest.mark.asyncio
async def test_the_post_upgrade_verify_runs_without_the_row_lock(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch, stubs: Any
) -> None:
    run = await _make_run(db_session)
    run.progress = {"per_node": {"node-a": {"ok": True}}, "events": []}
    await db_session.commit()
    locked: list[bool] = []
    probe = _locked_elsewhere_probe(api, run.id, locked)

    async def _verify(**_kw: Any) -> list[Any]:
        await probe()
        return []

    monkeypatch.setattr(orchestrator.safety, "verify_post_upgrade", _verify)
    await orchestrator._drive_loop(db_session, run, asyncio.Event(), ME)

    assert locked == [False]
    row = await _fresh(api, run.id)
    assert row.state == "succeeded"
    assert "chart_bump" in row.progress


@pytest.mark.asyncio
async def test_the_flips_record_write_keeps_a_halt_that_landed_during_it(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flip writes its record after kubeapi calls; written whole from the
    drive's copy, it dropped a Halt committed meanwhile."""
    from app.services.upgrades import shared_tags

    run = await _make_run(db_session)
    run.progress = {
        **run.progress,
        "shared_tags": {"mode": "hold", "from_tag": "2026.10.13-1", "released_at": None},
    }
    await db_session.commit()
    # The drive's copy is now as it was before the operator's Halt.
    await orchestrator.halt_upgrade(api, run.id)

    async def _no_wake() -> None:
        return None

    monkeypatch.setattr(shared_tags, "_list_workloads", lambda _ns: {})
    monkeypatch.setattr(shared_tags, "_apply_pins", lambda _tag: (True, None))
    monkeypatch.setattr(shared_tags, "_wake_supervisors", _no_wake)
    out = await shared_tags.flip(db_session, run)
    assert out.ok

    row = await _fresh(api, run.id)
    assert row.state == "halted"
    assert "halted" in _events(row)
    assert row.progress["shared_tags"]["flip"]["state"] == "flipped"
    assert row.progress["shared_tags"]["released_at"]


@pytest.mark.asyncio
async def test_the_beat_leaves_an_aborted_runs_hold_while_its_drive_holds_the_lease(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Abort leaves the drive finishing its node, which may yet boot the new
    slot: the members agreeing on one version now says nothing yet."""
    import hashlib
    import os

    from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
    from app.services.appliance import k8s
    from app.services.upgrades import mutex, shared_tags

    run = await _make_run(db_session, state="aborted")
    run.progress = {
        **run.progress,
        "shared_tags": {"mode": "hold", "from_tag": "a", "nodes": ["node-a"], "released_at": None},
    }
    for name, role in (("node-a", "primary"), ("node-b", "member")):
        der = os.urandom(32)
        db_session.add(
            Appliance(
                id=uuid.uuid4(),
                hostname=name,
                public_key_der=der,
                public_key_fingerprint=hashlib.sha256(der).hexdigest(),
                state=APPLIANCE_STATE_APPROVED,
                deployment_kind="appliance",
                cluster_role=role,
                installed_appliance_version="2026.10.13-1",
            )
        )
    await db_session.commit()
    pins: list[Any] = []

    async def _no_wake() -> None:
        return None

    monkeypatch.setattr(k8s, "get_config", object)
    monkeypatch.setattr(shared_tags, "_apply_pins", lambda tag: (pins.append(tag), (True, None))[1])
    monkeypatch.setattr(shared_tags, "_wake_supervisors", _no_wake)
    lease = mutex.LeaseState(held=True, holder=ME, renew_time=None, transitions=1, expired=False)
    monkeypatch.setattr(mutex, "get_state", lambda **_kw: lease)

    assert await shared_tags.release_lingering_hold(db_session) is None
    assert pins == []

    # The drive let go: the hold ends.
    monkeypatch.setattr(
        mutex,
        "get_state",
        lambda **_kw: mutex.LeaseState(
            held=False, holder=None, renew_time=None, transitions=1, expired=False
        ),
    )
    out = await shared_tags.release_lingering_hold(db_session)
    assert out is not None and out["run_id"] == str(run.id)
    assert pins == [None]


# ── The way out when the aborted drive died: force-release ────────────────────


def _lease_body(holder: str, idle_s: float) -> dict[str, Any]:
    from datetime import timedelta

    renewed = datetime.now(UTC) - timedelta(seconds=idle_s)
    return {
        "metadata": {"resourceVersion": "42"},
        "spec": {
            "holderIdentity": holder,
            "renewTime": renewed.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "leaseDurationSeconds": orchestrator.LEASE_DURATION_S,
            "leaseTransitions": 1,
        },
    }


@pytest.fixture
def kube_lease(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """The kubeapi's side of the Lease: what it returns, and what was cleared."""
    from app.services.appliance import k8s

    s = SimpleNamespace(body=None, cleared=[])

    def _get(_name: str, **_kw: Any) -> Any:
        return (200, s.body) if s.body is not None else (404, None)

    def _clear(_name: str, **kw: Any) -> tuple[bool, None]:
        s.cleared.append(kw.get("resource_version"))
        s.body = None
        return True, None

    monkeypatch.setattr(k8s, "get_config", object)
    monkeypatch.setattr(k8s, "get_lease", _get)
    monkeypatch.setattr(k8s, "clear_lease_holder", _clear)
    return s


async def _superadmin_headers(db: AsyncSession, *, superadmin: bool = True) -> dict[str, str]:
    from app.core.security import create_access_token, hash_password
    from app.models.auth import User

    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Operator",
        hashed_password=hash_password("pw-1707-test"),
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


_FORCE = "/api/v1/upgrades/lease/force-release"


@pytest.mark.asyncio
async def test_force_release_is_refused_while_the_holder_still_renews(
    db_session: AsyncSession, client: Any, kube_lease: SimpleNamespace
) -> None:
    kube_lease.body = _lease_body(ME, idle_s=60)
    resp = await client.post(_FORCE, headers=await _superadmin_headers(db_session))
    assert resp.status_code == 409, resp.text
    assert "alive" in resp.json()["detail"]
    assert kube_lease.cleared == []


@pytest.mark.asyncio
async def test_force_release_frees_a_dead_drives_lease_and_audits_it(
    db_session: AsyncSession, client: Any, kube_lease: SimpleNamespace
) -> None:
    from sqlalchemy import select

    from app.models.audit import AuditLog

    run = await _make_run(db_session, state="aborted")
    kube_lease.body = _lease_body(ME, idle_s=orchestrator.FORCE_RELEASE_MIN_IDLE_S + 30)
    resp = await client.post(_FORCE, headers=await _superadmin_headers(db_session))
    assert resp.status_code == 200, resp.text
    assert resp.json()["held"] is False
    # A compare-and-swap on the version read: a renewal in between loses.
    assert kube_lease.cleared == ["42"]

    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "upgrade.lease_force_released")
        )
    ).scalar_one()
    assert audit.resource_id == str(run.id)
    assert audit.user_display_name == "Test Operator"
    assert audit.new_value["holder"] == ME
    row = await _fresh(db_session, run.id)
    assert "lease_force_released" in _events(row)


@pytest.mark.asyncio
async def test_force_release_needs_a_superadmin_and_a_held_lease(
    db_session: AsyncSession, client: Any, kube_lease: SimpleNamespace
) -> None:
    kube_lease.body = _lease_body(ME, idle_s=3600)
    resp = await client.post(
        _FORCE, headers=await _superadmin_headers(db_session, superadmin=False)
    )
    assert resp.status_code == 403
    assert kube_lease.cleared == []

    kube_lease.body = None
    resp = await client.post(_FORCE, headers=await _superadmin_headers(db_session))
    assert resp.status_code == 409
    assert "not held" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_force_release_refuses_when_the_lease_cannot_be_read(
    db_session: AsyncSession,
    client: Any,
    kube_lease: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1713: an unanswered read is not "not held"."""
    from app.services.appliance import k8s

    def _down(*_a: Any, **_kw: Any) -> Any:
        raise k8s.KubeapiUnavailableError("timed out")

    monkeypatch.setattr(k8s, "get_lease", _down)
    resp = await client.post(_FORCE, headers=await _superadmin_headers(db_session))
    assert resp.status_code == 503
    assert kube_lease.cleared == []
