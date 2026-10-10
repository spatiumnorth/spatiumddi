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

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select, text

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
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


# ── The mirror wait (#1463) ───────────────────────────────────────────────────
#
# The mirror's node comes back from its reboot with the mirror still Pending:
# its replacement can only be scheduled on that node once it is uncordoned. The
# next node's stamp would land in that gap and its fetch would answer 502, so a
# node is told to fetch only once the mirror reports a Ready replica.

MIRROR = "spatium-control-spatiumddi-slot-image-mirror"
UPLOADED = SlotImageTarget(
    url="https://10.0.0.1/api/v1/appliance/upgrade-images/abc/raw.xz?t=tok",
    sha256="ab" * 32,
    tls_insecure=True,
)


class _Row:
    """The appliance columns the mirror wait reads."""

    def __init__(self, **kw: Any) -> None:
        self.id = uuid.uuid4()
        self.hostname = "node-1"
        self.installed_appliance_version: str | None = OLD
        self.supervisor_version: str | None = None
        self.desired_slot_image_url: str | None = "https://10.0.0.1/old.raw.xz?t=old"
        for k, v in kw.items():
            setattr(self, k, v)


def _deployments(*answers: Any) -> Any:
    """``k8s.get_deployment`` answering in turn: an int is readyReplicas, a
    status code alone is (code, None), an exception is raised."""
    calls: list[str] = []
    seq = list(answers)

    def _get(name: str, namespace: str | None = None) -> Any:
        calls.append(name)
        answer = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, tuple):
            return answer
        return 200, {"status": {"readyReplicas": answer} if answer else {}}

    _get.calls = calls  # type: ignore[attr-defined]
    return _get


async def _mirror_step(
    monkeypatch: pytest.MonkeyPatch,
    get: Any,
    *,
    row: Any = None,
    target: SlotImageTarget = UPLOADED,
    timeout_s: float = 5.0,
) -> per_node.StepResult:
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node.k8s, "get_deployment", get)
    with patch.object(
        per_node, "_resolve_appliance", AsyncMock(return_value=row if row else _Row())
    ):
        return await per_node._step_mirror_ready(
            _db(), "node-1", TARGET, target, deployment=MIRROR, timeout_s=timeout_s
        )


@pytest.mark.asyncio
async def test_a_node_waits_for_the_mirror_before_it_is_told_to_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _recording_chain(monkeypatch, events)

    await _chain()

    assert events.index("mirror_ready") + 1 == events.index("trigger_slot_apply"), events
    assert events.index("etcd_snapshot") < events.index("mirror_ready")


@pytest.mark.asyncio
async def test_the_mirror_wait_holds_until_a_replica_is_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    get = _deployments(0, 0, 1)

    step = await _mirror_step(monkeypatch, get)

    assert step.name == "mirror_ready"
    assert step.ok is True, step.error
    assert get.calls == [MIRROR, MIRROR, MIRROR]
    assert step.detail["ready_replicas"] == 1


@pytest.mark.asyncio
async def test_a_mirror_that_never_comes_back_fails_the_node_before_its_stamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    step = await _mirror_step(monkeypatch, _deployments(0), timeout_s=0.05)

    assert step.ok is False
    assert MIRROR in (step.error or "")
    assert "readyReplicas=0" in (step.error or "")
    category = alerts.classify_per_node_failure(failed_at="mirror_ready", error=step.error)
    assert category == alerts.CATEGORY_MIRROR_NOT_READY
    assert "mirror" in alerts.operator_hint(category)


@pytest.mark.asyncio
async def test_a_failed_mirror_wait_leaves_the_node_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _recording_chain(monkeypatch, events, fail="mirror_ready")

    result = await _chain()

    assert result.failed_at == "mirror_ready"
    for never in ("trigger_slot_apply", "stage", "cordon", "drain", "reboot"):
        assert never not in events, events


@pytest.mark.asyncio
async def test_a_cluster_without_a_mirror_does_not_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    step = await _mirror_step(monkeypatch, _deployments((404, None)))

    assert step.ok is True
    assert step.detail.get("skipped") is True


@pytest.mark.asyncio
async def test_an_operator_url_never_asks_for_the_mirror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    get = _deployments(RuntimeError("must not be asked"))

    step = await _mirror_step(
        monkeypatch, get, target=SlotImageTarget(url="https://releases.example/x.raw.xz")
    )

    assert step.ok is True
    assert step.detail.get("skipped") is True
    assert get.calls == []


@pytest.mark.asyncio
async def test_a_node_already_on_the_target_does_not_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    get = _deployments(0)

    step = await _mirror_step(monkeypatch, get, row=_Row(installed_appliance_version=TARGET))

    assert step.ok is True
    assert step.detail.get("skipped") is True
    assert get.calls == []


@pytest.mark.asyncio
async def test_a_node_already_holding_this_stamp_does_not_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A re-driven node: its stamp repeats the URL it already holds, so the
    supervisor's fire-once marker fetches nothing. That is the mirror's own
    node too, resumed after its drain with the mirror Pending on it; waiting
    there would wait for itself."""
    get = _deployments(0)

    step = await _mirror_step(monkeypatch, get, row=_Row(desired_slot_image_url=UPLOADED.url))

    assert step.ok is True
    assert step.detail.get("skipped") is True
    assert get.calls == []


@pytest.mark.asyncio
async def test_a_node_whose_runner_takes_the_nonce_waits_for_a_new_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stamp it compares is the one ``stamp_desired_slot_image`` would
    write: with a re-fire nonce, the same image is a new fetch."""
    target = SlotImageTarget(url=UPLOADED.url, sha256=UPLOADED.sha256, nonce="n1")
    row = _Row(desired_slot_image_url=UPLOADED.url, installed_appliance_version="2026.10.02-1")
    get = _deployments(1)

    step = await _mirror_step(monkeypatch, get, row=row, target=target)

    assert step.ok is True
    assert step.detail.get("skipped") is not True
    assert get.calls == [MIRROR]


@pytest.mark.asyncio
async def test_the_mirror_wait_polls_through_a_kubeapi_blip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.appliance import k8s

    get = _deployments(k8s.KubeapiUnavailableError("timed out"), (503, None), 1)

    step = await _mirror_step(monkeypatch, get)

    assert step.ok is True, step.error
    assert len(get.calls) == 3


def test_the_mirror_deployment_follows_the_chart_name() -> None:
    assert per_node.slot_image_mirror_deployment("spatium-control") == MIRROR
    assert per_node.slot_image_mirror_deployment("acme") == "acme-spatiumddi-slot-image-mirror"


@pytest.mark.asyncio
async def test_the_chain_asks_for_the_mirror_it_was_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []
    _recording_chain(monkeypatch, [])

    async def _mirror(*_a: Any, deployment: str, **_k: Any) -> per_node.StepResult:
        seen.append(deployment)
        return per_node.StepResult(name="mirror_ready", started_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_mirror_ready", _mirror)
    await _chain()
    await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version=TARGET,
        slot_image=UPLOADED,
        mirror_deployment="acme-spatiumddi-slot-image-mirror",
    )

    assert seen == [MIRROR, "acme-spatiumddi-slot-image-mirror"]


# ── No connection held while the node leaves service (#1463) ──────────────────
#
# Found by ddi-pg's three-node walk of this change. Cordoning the node that ran
# the CNPG primary switched the primary over, and the old primary's demotion
# closed every connection it held. The chain had carried the stage step's last
# read across the cordon on one of them, so the reboot after the drain
# committed on a closed connection and crashed: "cannot call
# Transaction.commit(): the underlying connection is closed".


async def _switchover(db: Any) -> None:
    """Close every other connection to the test database, as a CNPG primary's
    demotion closes every connection it held."""
    async with db.bind.connect() as conn:
        await conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                " WHERE datname = current_database() AND pid <> pg_backend_pid()"
            )
        )
    # Let asyncpg read the closed connections' end before the next step.
    await asyncio.sleep(0.2)


@pytest.mark.asyncio
async def test_a_switchover_at_the_cordon_does_not_crash_the_reboot(
    db_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_session.add(
        Appliance(
            id=uuid.uuid4(),
            hostname="node-1",
            public_key_der=b"fake-key",
            public_key_fingerprint="ab" * 32,
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            installed_appliance_version=OLD,
            last_upgrade_state="done",
            last_upgrade_state_at=datetime.now(UTC),
            last_upgrade_progress={"step": "reboot-pending"},
            slot_a_version=OLD,
            slot_b_version=TARGET,
        )
    )
    await db_session.commit()
    stage, reboot = per_node._step_stage, per_node._step_reboot
    _recording_chain(monkeypatch, [])
    monkeypatch.setattr(per_node, "_step_stage", stage)
    monkeypatch.setattr(per_node, "_step_reboot", reboot)

    async def _cordon(*_a: Any, **_k: Any) -> per_node.StepResult:
        await _switchover(db_session)
        return per_node.StepResult(name="cordon", started_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_cordon", _cordon)
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node, "publish_wake", AsyncMock())

    result = await _chain(db_session)

    assert result.ok is True, result.error
    requested = await db_session.scalar(
        select(Appliance.reboot_requested).where(Appliance.hostname == "node-1")
    )
    assert requested is True


@pytest.mark.asyncio
async def test_the_stage_read_ends_before_the_node_leaves_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _recording_chain(monkeypatch, events)
    db = MagicMock()
    db.commit = AsyncMock(side_effect=lambda: events.append("commit"))

    await _chain(db)

    i = events.index("stage")
    assert events[i + 1 : i + 3] == ["commit", "cnpg_maintenance_on"], events


@pytest.mark.asyncio
async def test_the_mirror_wait_holds_no_transaction_while_it_waits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wait can last minutes; a connection held idle across it is one the
    database can close under the stamp that follows."""
    events: list[str] = []
    db = _db(lambda _row: events.append("read"))
    db.commit = AsyncMock(side_effect=lambda: events.append("commit"))

    def _get(name: str, namespace: str | None = None) -> Any:
        events.append("poll")
        return 200, {"status": {"readyReplicas": 1}}

    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node.k8s, "get_deployment", _get)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=_Row())):
        step = await per_node._step_mirror_ready(db, "node-1", TARGET, UPLOADED, deployment=MIRROR)

    assert step.ok is True, step.error
    assert events == ["commit", "read", "commit", "poll"]


@pytest.mark.parametrize("failed_at", ["cordon", "verify_primary_moved", "drain"])
def test_a_failure_after_the_stage_tells_the_operator_the_slot_is_armed(failed_at: str) -> None:
    """Those steps now run after the host staged the slot and armed it for
    the next boot, so the node is left serving the old slot with the new one
    armed: an unplanned reboot boots it outside the run. The hint says so."""
    category = alerts.classify_per_node_failure(failed_at=failed_at, error="x")
    assert "armed" in alerts.operator_hint(category)


@pytest.mark.parametrize("failed_at", ["mirror_ready", "stage"])
def test_a_failure_before_the_stage_does_not_claim_an_armed_slot(failed_at: str) -> None:
    category = alerts.classify_per_node_failure(
        failed_at=failed_at, error="supervisor reported upgrade failed"
    )
    assert "armed" not in alerts.operator_hint(category)
