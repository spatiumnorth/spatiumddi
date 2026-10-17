"""A shared-tag step the kubeapi did not take is tried again, not the run's end (#2028).

A rolling run pins the shared charts' image tag before its first node,
re-asserts the pins before every later node, and removes them at the end
(#1710). Each of those steps is a handful of kubeapi requests, each on a new
connection through the ``kubernetes`` Service, and the run failed on the first
one that did not land. A k3s server answers 503 ``apiserver not ready`` while
its apiserver is not up, as after a restart, and the Service keeps routing to
it until its endpoint lapses: ddi-pg's three-node walk of nightly-2026.10.16
saw a run fail 10 s after Start, before any node, when the hold's create of
the bootstrap chart's HelmChartConfig met member-1's k3s restarting. Every
re-assert and the flip follow a node's reboot.

The contract: a shared-tag step whose request went unanswered or was refused
pauses the drive and is tried again (every step is idempotent), with Halt,
Abort and the Lease checked between tries as at every loop top (#1713); no
node starts and no flip happens until the step lands. Only a step that keeps
failing for ``_SHARED_TAG_RETRY_FOR_S`` fails the run, with the error it
failed with, as before.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import pytest_asyncio
import yaml
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.system_upgrade import SystemUpgradeRun
from app.services.appliance import k8s
from app.services.upgrades import per_node, shared_tags

FROM = "2026.10.13-1"
TO = "2026.10.14-1"
NODES = ["node-a", "node-b", "node-c"]
CONTROL_OVERRIDES = "api:\n  replicas: 3\nworker:\n  replicas: 3\n"
ME = "worker-a"

# What ``k8s.upsert_helmchartconfig`` returned on the walk, built the same way
# (``f"POST status {st}: {rb[:200]!r}"``) from the body k3s sends while its
# apiserver is not up.
NOT_READY = (
    b'{"kind":"Status","metadata":{},"status":"Failure","message":"apiserver not ready",'
    b'"reason":"ServiceUnavailable","code":503}\n'
)
POST_503 = f"POST status 503: {NOT_READY[:200]!r}"


class FlakyCluster:
    """kube-system's HelmChartConfigs (name -> valuesContent) and the release
    namespace's workloads, with answers the kubeapi does not give: each
    ``fail_writes`` entry refuses one write with that error, each
    ``fail_reads`` entry is raised by one read."""

    def __init__(self, hccs: dict[str, str] | None = None) -> None:
        self.hccs: dict[str, str] = dict(hccs or {})
        self.writes: list[str] = []
        self.refused: list[str] = []
        self.fail_writes: list[str] = []
        self.fail_reads: list[Exception] = []
        self.fail_lists: list[int] = []
        self.deployments: list[dict[str, Any]] = []
        self.daemonsets: list[dict[str, Any]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(k8s, "get_config", lambda: k8s._Config("h", 443, "t", "/ca", "spatium"))
        monkeypatch.setattr(k8s, "get_helmchartconfig", self.get_helmchartconfig)
        monkeypatch.setattr(k8s, "upsert_helmchartconfig", self.upsert_helmchartconfig)
        monkeypatch.setattr(k8s, "list_deployments", self.list_deployments)
        monkeypatch.setattr(k8s, "list_daemonsets", self.list_daemonsets, raising=False)

    def get_helmchartconfig(self, name: str, namespace: str = "kube-system") -> Any:
        assert namespace == "kube-system"
        if self.fail_reads:
            raise self.fail_reads.pop(0)
        if name not in self.hccs:
            return 404, None
        return 200, {"spec": {"valuesContent": self.hccs[name]}}

    def upsert_helmchartconfig(
        self, name: str, values_yaml: str, *, namespace: str = "kube-system"
    ) -> tuple[bool, str | None]:
        assert namespace == "kube-system"
        if self.fail_writes:
            self.refused.append(name)
            return False, self.fail_writes.pop(0)
        self.hccs[name] = values_yaml
        self.writes.append(name)
        return True, None

    def list_deployments(self, _selector: str, namespace: str | None = None) -> Any:
        assert namespace == "spatium"
        if self.fail_lists:
            return self.fail_lists.pop(0), []
        return 200, list(self.deployments)

    def list_daemonsets(self, _selector: str = "", namespace: str | None = None) -> Any:
        assert namespace == "spatium"
        return 200, list(self.daemonsets)

    def values(self, name: str) -> Any:
        return yaml.safe_load(self.hccs.get(name) or "") or {}


def _held() -> FlakyCluster:
    """The cluster in the middle of a held roll: both pins in place."""
    return FlakyCluster(
        {
            "spatium-bootstrap": f"global:\n  imageTag: {FROM}\n",
            "spatium-control": CONTROL_OVERRIDES + f"image:\n  tag: {FROM}\n",
        }
    )


def _hold_record() -> dict[str, Any]:
    return {
        "mode": "hold",
        "from_tag": FROM,
        "to_tag": TO,
        "nodes": list(NODES),
        "placed_at": "2026-10-13T18:00:00Z",
        "released_at": None,
        "release_reason": None,
    }


@pytest_asyncio.fixture
async def api(db_session: AsyncSession) -> Any:
    """A second session: the API's, separate from the drive's."""
    async with AsyncSession(bind=db_session.bind, expire_on_commit=False) as s:
        yield s


async def _run(
    db: AsyncSession, *, done: list[str], shared: dict[str, Any] | None = None
) -> SystemUpgradeRun:
    progress: dict[str, Any] = {"per_node": {n: {"ok": True} for n in done}, "events": []}
    if shared is not None:
        progress["shared_tags"] = shared
    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version=TO,
        source_versions={},
        plan={"node_order": list(NODES), "slot_image_url": "https://example.test/x.raw.xz"},
        progress=progress,
        lease_holder=ME,
    )
    db.add(run)
    await db.commit()
    return run


def _quiet(monkeypatch: pytest.MonkeyPatch, orch: Any) -> None:
    """No alerts, no lease, no pauses."""

    async def _no_alert(*_a: Any, **_k: Any) -> None:
        return None

    async def _no_wake(*_channels: str) -> None:
        return None

    monkeypatch.setattr(orch.upgrade_alerts, "emit_upgrade_failed_alert", _no_alert)
    monkeypatch.setattr(orch.mutex, "release_if_held", lambda **_k: True)
    monkeypatch.setattr(orch, "_BETWEEN_NODES_PAUSE_S", 0.0)
    monkeypatch.setattr(orch, "_SHARED_TAG_RETRY_S", 0.0)
    monkeypatch.setattr("app.core.agent_wake.publish_wake", _no_wake)
    monkeypatch.delenv("NODE_NAME", raising=False)
    monkeypatch.setattr(settings, "version", FROM)


def _node_result(node_name: str, ok: bool) -> per_node.SingleNodeResult:
    return per_node.SingleNodeResult(
        node_name=node_name,
        target_version=TO,
        ok=ok,
        failed_at=None if ok else "drain",
        steps=[],
    )


def _events(run: SystemUpgradeRun, name: str) -> list[dict[str, Any]]:
    return [e for e in run.progress.get("events") or [] if e.get("event") == name]


# ── The hold before the first node ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_hold_write_answered_apiserver_not_ready_is_tried_again(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk's failure: the bootstrap pin's create answered 503 once."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    cluster = FlakyCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.fail_writes = [POST_503]
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    seen: dict[str, dict[str, Any]] = {}

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        seen[node_name] = {n: cluster.values(n) for n in ("spatium-bootstrap", "spatium-control")}
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    # The first node started, and only once both pins were on.
    assert seen["node-a"]["spatium-bootstrap"] == {"global": {"imageTag": FROM}}
    assert seen["node-a"]["spatium-control"]["image"] == {"tag": FROM}
    assert cluster.refused == ["spatium-bootstrap"]
    assert cluster.writes == ["spatium-bootstrap", "spatium-control"]
    await db_session.refresh(run)
    # The run ends on the node (the test's), not on the hold.
    assert run.state == "failed"
    assert _events(run, "shared_tag_hold_failed") == []
    assert len(_events(run, "node_failed")) == 1
    (retrying,) = _events(run, "shared_tag_step_retrying")
    assert retrying["step"] == "shared_tag_hold"
    assert "apiserver not ready" in retrying["error"]


@pytest.mark.asyncio
async def test_an_unanswered_read_at_the_hold_is_tried_again(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    cluster = FlakyCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.fail_reads = [k8s.KubeapiUnavailableError("kubeapi GET /apis/...: timed out")]
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    started: list[str] = []

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        started.append(node_name)
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    assert started == ["node-a"]
    assert cluster.values("spatium-bootstrap") == {"global": {"imageTag": FROM}}
    await db_session.refresh(run)
    assert _events(run, "shared_tag_hold_failed") == []
    assert len(_events(run, "shared_tag_step_retrying")) == 1


@pytest.mark.asyncio
async def test_a_hold_that_keeps_failing_fails_the_run_once_its_time_is_spent(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retrying is bounded: the run still fails, with the hold's own error,
    and no node starts with the shared tags free to move."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    cluster = FlakyCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.fail_writes = [POST_503] * 50
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    clock = {"t": 0.0}

    def _tick() -> float:
        clock["t"] += 100.0
        return clock["t"]

    monkeypatch.setattr(orch, "_monotonic", _tick)
    monkeypatch.setattr(orch, "_SHARED_TAG_RETRY_FOR_S", 300.0)

    async def _must_not_run(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("no node may start without the hold")

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _must_not_run)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    await db_session.refresh(run)
    assert run.state == "failed"
    assert len(_events(run, "shared_tag_hold_failed")) == 1
    assert run.last_error.startswith(
        "could not hold the shared charts' image tag: spatium-bootstrap: POST status 503"
    )
    assert "still failing after 300 s" in run.last_error
    # Tried at 100, 200, 300 and 400 s; given up on the fourth.
    assert cluster.refused == ["spatium-bootstrap"] * 4
    assert len(_events(run, "shared_tag_step_retrying")) == 1
    # The record stays for whoever ends the hold (the beat, or the next run).
    record = run.progress["shared_tags"]
    assert record["mode"] == "hold" and record["released_at"] is None


@pytest.mark.asyncio
async def test_a_halt_while_the_hold_waits_to_retry_ends_the_drive_not_the_run(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    _quiet(monkeypatch, orch)
    calls: list[int] = []

    async def _hold(_db: AsyncSession, r: SystemUpgradeRun) -> Any:
        calls.append(1)
        shared_tags._store(r, _hold_record())
        await orch.halt_upgrade(api, run.id)
        return shared_tags.StepOutcome(
            ok=False, mode="hold", error=f"spatium-bootstrap: {POST_503}", retryable=True
        )

    monkeypatch.setattr(orch.shared_tags, "ensure_hold", _hold)

    async def _must_not_run(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("a halted run must not start a node")

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _must_not_run)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    row = await api.get(SystemUpgradeRun, run.id)
    assert row is not None
    await api.refresh(row)
    assert row.state == "halted"
    assert calls == [1]
    names = [e.get("event") for e in row.progress.get("events") or []]
    assert "halted" in names and "shared_tag_hold_failed" not in names
    # The pins may be half on: the record of them is kept.
    assert row.progress["shared_tags"]["mode"] == "hold"


# ── The re-assert before a later node ──────────────────────────────────────


@pytest.mark.asyncio
async def test_the_re_assert_after_a_node_is_tried_again(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The node just rebooted; the re-assert's write meets its k3s starting."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    cluster = FlakyCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    seen: dict[str, Any] = {}

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        seen[node_name] = cluster.values("spatium-control")
        if node_name == "node-a":
            # The seed supervisor's read-then-PATCH dropped the pin, and the
            # re-assert's write is refused once.
            cluster.hccs["spatium-control"] = CONTROL_OVERRIDES
            cluster.fail_writes = [POST_503.replace("POST", "PATCH")]
            return _node_result(node_name, ok=True)
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    assert seen["node-b"]["image"] == {"tag": FROM}
    await db_session.refresh(run)
    assert _events(run, "shared_tag_hold_failed") == []
    assert [e["node"] for e in _events(run, "node_started")] == ["node-a", "node-b"]
    assert len(_events(run, "shared_tag_step_retrying")) == 1


# ── The flip ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_flip_the_kubeapi_did_not_answer_is_tried_again(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flip comes right after the seed's own reboot."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=NODES, shared=_hold_record())
    cluster = _held()
    cluster.fail_writes = [POST_503.replace("POST", "PATCH")]
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    enqueued: list[tuple[Any, str]] = []
    monkeypatch.setattr(
        orch,
        "_enqueue_continuation",
        lambda rid, *, avoid_version: enqueued.append((rid, avoid_version)),
    )

    stop = asyncio.Event()
    await orch._drive_loop(db_session, run, stop, ME)

    assert cluster.values("spatium-bootstrap") == {}
    assert cluster.values("spatium-control") == {"api": {"replicas": 3}, "worker": {"replicas": 3}}
    await db_session.refresh(run)
    assert run.state == "running"
    assert run.progress["shared_tags"]["flip"]["state"] == "flipped"
    assert enqueued == [(run.id, FROM)]
    assert _events(run, "chart_bump_failed") == []
    (retrying,) = _events(run, "shared_tag_step_retrying")
    assert retrying["step"] == "shared_tag_flip"
    # The end of the roll is announced once, however many tries the flip took.
    assert len(_events(run, "all_nodes_complete")) == 1


@pytest.mark.asyncio
async def test_a_flip_that_keeps_failing_fails_the_run_as_before(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=NODES, shared=_hold_record())
    cluster = _held()
    cluster.fail_writes = [POST_503.replace("POST", "PATCH")] * 50
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    clock = {"t": 0.0}

    def _tick() -> float:
        clock["t"] += 200.0
        return clock["t"]

    monkeypatch.setattr(orch, "_monotonic", _tick)
    monkeypatch.setattr(orch, "_SHARED_TAG_RETRY_FOR_S", 300.0)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    await db_session.refresh(run)
    assert run.state == "failed"
    assert len(_events(run, "chart_bump_failed")) == 1
    assert run.last_error.startswith(f"shared tag flip to {TO} failed: could not remove a tag pin")
    assert "still failing after 400 s" in run.last_error


# ── What is not retried (validation of the QA fix) ─────────────────────────


@pytest.mark.parametrize(
    ("error", "transient"),
    [
        (POST_503, True),
        ("PATCH status 500: b'...'", True),
        ("PATCH status 409: b'conflict'", True),
        ("POST status 429: b'throttled'", True),
        ("kubeapi GET status 504", True),
        ("spatium-bootstrap: kubeapi unreachable: kubeapi GET /apis/x: timed out", True),
        ("Deployment list status 503", True),
        ("PATCH status 403: b'forbidden'", False),
        ("spatium-control: HelmChartConfig GET status 401", False),
        ("POST status 422: b'{\"code\":422}'", False),
        ("PATCH status 400: b'bad request'", False),
        ("ServiceAccount not mounted", False),
        ("ServiceAccount not mounted; kubeapi unreachable", False),
        ("Deployment list status 403", False),
        (None, False),
        ("", False),
    ],
)
def test_only_a_failure_a_later_try_can_get_past_is_transient(
    error: str | None, transient: bool
) -> None:
    assert shared_tags._transient(error) is transient


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "refusal",
    ["POST status 403: b'forbidden'", "POST status 422: b'{\"code\":422}'"],
)
async def test_a_hold_refused_for_good_fails_the_run_at_once(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    """RBAC or an invalid object is not the apiserver restarting: no later try
    changes the answer, so it is not hidden behind five minutes of retries."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    cluster = FlakyCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.fail_writes = [refusal] * 5
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)

    async def _must_not_run(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("no node may start without the hold")

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _must_not_run)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    await db_session.refresh(run)
    assert run.state == "failed"
    assert cluster.refused == ["spatium-bootstrap"]
    assert _events(run, "shared_tag_step_retrying") == []
    assert len(_events(run, "shared_tag_hold_failed")) == 1
    assert "still failing" not in (run.last_error or "")


@pytest.mark.asyncio
async def test_a_flip_whose_workload_list_is_refused_for_good_fails_at_once(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=NODES, shared=_hold_record())
    cluster = _held()
    cluster.fail_lists = [403] * 5
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    await db_session.refresh(run)
    assert run.state == "failed"
    assert _events(run, "shared_tag_step_retrying") == []
    assert len(_events(run, "chart_bump_failed")) == 1
    # Nothing moved: both pins are still on.
    assert cluster.values("spatium-bootstrap") == {"global": {"imageTag": FROM}}


@pytest.mark.asyncio
async def test_a_flip_whose_workload_list_went_unanswered_announces_the_end_once(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flip's first read fails before it records its snapshot: the retry
    still announces the end of the roll once, not once per try."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=NODES, shared=_hold_record())
    cluster = _held()
    cluster.fail_lists = [503, 503]
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(orch, "_enqueue_continuation", lambda rid, *, avoid_version: None)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)

    await db_session.refresh(run)
    assert run.state == "running"
    assert run.progress["shared_tags"]["flip"]["state"] == "flipped"
    assert cluster.values("spatium-bootstrap") == {}
    assert len(_events(run, "all_nodes_complete")) == 1
    assert len(_events(run, "shared_tag_step_retrying")) == 1


@pytest.mark.asyncio
async def test_an_abort_while_the_drive_waits_to_retry_ends_it_before_another_try(
    db_session: AsyncSession, api: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator aborts a run stuck retrying: the drive sees it at its
    loop top after the wait, tries nothing more and starts no node."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(orch, "_SHARED_TAG_RETRY_S", 0.5)
    calls: list[int] = []
    aborts: list[asyncio.Task[Any]] = []

    record_event = orch._record_event

    async def _record(db: AsyncSession, r: SystemUpgradeRun, event: str, **detail: Any) -> None:
        await record_event(db, r, event, **detail)
        if event == "shared_tag_step_retrying":
            # The operator's Abort, from the API's own session. It waits on
            # the row lock the drive holds until it commits, then lands
            # while the drive waits to try again.
            aborts.append(asyncio.create_task(orch.abort_upgrade(api, run.id)))

    monkeypatch.setattr(orch, "_record_event", _record)

    async def _hold(_db: AsyncSession, r: SystemUpgradeRun) -> Any:
        calls.append(1)
        shared_tags._store(r, _hold_record())
        return shared_tags.StepOutcome(
            ok=False, mode="hold", error=f"spatium-bootstrap: {POST_503}", retryable=True
        )

    monkeypatch.setattr(orch.shared_tags, "ensure_hold", _hold)

    async def _must_not_run(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("an aborted run must not start a node")

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _must_not_run)

    await orch._drive_loop(db_session, run, asyncio.Event(), ME)
    await aborts[0]

    row = await api.get(SystemUpgradeRun, run.id)
    assert row is not None
    await api.refresh(row)
    assert row.state == "aborted"
    assert calls == [1]
    names = [e.get("event") for e in row.progress.get("events") or []]
    assert "shared_tag_step_retrying" in names
    assert "shared_tag_hold_failed" not in names
    # The pins may be half on: the record of them is kept for the beat.
    assert row.progress["shared_tags"]["mode"] == "hold"
