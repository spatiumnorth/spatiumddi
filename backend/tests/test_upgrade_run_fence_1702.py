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
