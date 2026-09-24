"""The durable push spool (#1077) and the DNS streams wired through it.

The acceptance test the issue asks for is "stop the control plane, start it,
every row from the window appears once with its original timestamp". The
shipper tests below are that, in miniature: a fake POST that fails N times
and then accepts, and assertions on EXACTLY what it received. Each has a
negative control with ``AGENT_SPOOL_ENABLED=false``, so the same harness is
shown to be able to see a loss — a delivered-count assertion that could not
fail would prove nothing.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self

import httpx
import pytest

from spatium_dns_agent import spool as spool_mod
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.heartbeat import HeartbeatClient
from spatium_dns_agent.metrics import MetricsPoller
from spatium_dns_agent.query_log_shipper import MAX_BATCH, QueryLogShipper
from spatium_dns_agent.spool import (
    REJECTED,
    RETRY,
    SENT,
    Shipper,
    Spool,
    SpoolManager,
    classify_status,
)
from spatium_dns_agent.supervisor import build_spool_manager


def _drain_all(sp: Spool) -> list[dict[str, Any]]:
    got: list[dict[str, Any]] = []

    def send(p: dict[str, Any]) -> str:
        got.append(p)
        return SENT

    assert sp.drain(send, max_batches=10_000)
    return got


# ── Spool ────────────────────────────────────────────────────────────────


def test_append_then_drain_preserves_order(tmp_path: Path) -> None:
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    for i in range(20):
        kept = sp.append({"i": i})
        assert kept
    assert len(sp) == 20
    assert [p["i"] for p in _drain_all(sp)] == list(range(20))
    assert len(sp) == 0
    assert not [p for p in sp.dir.iterdir() if p.name != "_state.json"]


def test_spool_survives_restart(tmp_path: Path) -> None:
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    for i in range(5):
        sp.append({"i": i})
    del sp
    reopened = Spool(tmp_path, "s", 10_000_000, enabled=True)
    assert len(reopened) == 5
    # New appends after the restart still sort after the old backlog.
    reopened.append({"i": 5})
    assert [p["i"] for p in _drain_all(reopened)] == list(range(6))


def test_cap_trims_oldest_and_counts_persistently(tmp_path: Path) -> None:
    one = len(json.dumps({"v": 1, "spooled_at": time.time(), "payload": {"i": 0}}))
    sp = Spool(tmp_path, "s", one * 3 + 5, enabled=True)
    for i in range(10):
        sp.append({"i": i})
    st = sp.status()
    assert st["entries"] == 3
    assert st["bytes"] <= sp.cap_bytes
    assert st["trimmed_entries_total"] == 7
    assert st["trimmed_bytes_total"] > 0
    assert st["last_trim_at"] is not None
    # The newest survive, in order.
    reopened = Spool(tmp_path, "s", sp.cap_bytes, enabled=True)
    assert reopened.status()["trimmed_entries_total"] == 7
    assert [p["i"] for p in _drain_all(reopened)] == [7, 8, 9]


def test_oversize_entry_is_refused_and_counted(tmp_path: Path) -> None:
    sp = Spool(tmp_path, "s", 50, enabled=True)
    kept = sp.append({"blob": "x" * 500})
    assert not kept
    assert len(sp) == 0
    assert sp.status()["trimmed_entries_total"] == 1


def test_max_age_expires_at_drain_and_is_not_a_trim(tmp_path: Path, monkeypatch) -> None:
    sp = Spool(tmp_path, "s", 10_000_000, max_age_seconds=3600, enabled=True)
    sp.append({"i": "old"})
    real = time.time
    monkeypatch.setattr(spool_mod.time, "time", lambda: real() + 7200)
    sp.append({"i": "fresh"})
    assert [p["i"] for p in _drain_all(sp)] == ["fresh"]
    st = sp.status()
    assert st["expired_entries_total"] == 1
    assert st["trimmed_entries_total"] == 0


def test_rejected_is_dropped_and_counted(tmp_path: Path) -> None:
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    sp.append({"i": "poison"})
    sp.append({"i": "good"})
    seen: list[Any] = []

    def send(p: dict[str, Any]) -> str:
        seen.append(p["i"])
        return REJECTED if p["i"] == "poison" else SENT

    assert sp.drain(send)
    assert seen == ["poison", "good"]
    assert sp.status()["rejected_entries_total"] == 1


def test_retry_stops_the_drain_without_losing_anything(tmp_path: Path) -> None:
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    for i in range(3):
        sp.append({"i": i})
    calls: list[int] = []

    def send(p: dict[str, Any]) -> str:
        calls.append(p["i"])
        return RETRY

    assert not sp.drain(send)
    assert calls == [0]
    assert len(sp) == 3


def test_tmp_files_from_a_crash_are_discarded(tmp_path: Path) -> None:
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    sp.append({"i": 0})
    (sp.dir / "00000000000000000001.tmp").write_text("{half")
    reopened = Spool(tmp_path, "s", 10_000_000, enabled=True)
    assert not list(reopened.dir.glob("*.tmp"))
    assert len(reopened) == 1


def test_disabled_spool_keeps_nothing(tmp_path: Path) -> None:
    sp = Spool(tmp_path, "s", 10_000_000, enabled=False)
    kept = sp.append({"i": 0})
    assert not kept
    assert len(sp) == 0
    assert not (tmp_path / "spool").exists()


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        (200, SENT),
        (204, SENT),
        (401, RETRY),
        (404, RETRY),
        (429, RETRY),
        (503, RETRY),
        (400, REJECTED),
        (422, REJECTED),
    ],
)
def test_classify_status(status: int, outcome: str) -> None:
    assert classify_status(status) == outcome


def test_manager_splits_budget_and_aggregates_status(tmp_path: Path) -> None:
    m = SpoolManager(tmp_path, total_bytes=1000)
    m.declare("a", 3)
    m.declare("b", 1)
    assert m.get("a").cap_bytes == 750
    assert m.get("b").cap_bytes == 250
    m.get("a").append({"x": 1})
    st = m.status()
    assert st["entries"] == 1
    assert set(st["streams"]) == {"a", "b"}
    with pytest.raises(KeyError):
        m.get("nope")


def test_dns_and_dhcp_copies_are_byte_identical() -> None:
    here = Path(__file__).resolve()
    dns_copy = here.parents[1] / "spatium_dns_agent" / "spool.py"
    dhcp_copy = here.parents[2] / "dhcp" / "spatium_dhcp_agent" / "spool.py"
    if not dhcp_copy.exists():
        pytest.skip("DHCP agent source not present (e.g. inside an image)")
    assert (
        dns_copy.read_bytes() == dhcp_copy.read_bytes()
    ), "agent/dns and agent/dhcp spool.py have diverged — keep them identical"


# ── Shipper ──────────────────────────────────────────────────────────────


class _FlakyPost:
    """Fails the first ``fail`` calls (unreachable), then accepts."""

    def __init__(self, fail: int) -> None:
        self.fail = fail
        self.calls = 0
        self.received: list[dict[str, Any]] = []

    def __call__(self, payload: dict[str, Any]) -> int:
        self.calls += 1
        if self.calls <= self.fail:
            raise httpx.ConnectError("control plane down")
        # Deep copy through JSON, as the wire would.
        self.received.append(json.loads(json.dumps(payload)))
        return 200


def test_shipper_backoff_skips_posts_but_keeps_batches(tmp_path: Path, monkeypatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(spool_mod.time, "monotonic", lambda: now[0])
    post = _FlakyPost(fail=1)
    sh = Shipper(
        Spool(tmp_path, "s", 10_000_000, enabled=True),
        post,
        event_prefix="t",
        retry_backoff_seconds=5,
    )
    assert sh.ship({"i": 0}) == RETRY
    assert sh.ship({"i": 1}) == RETRY  # inside the backoff: no POST attempted
    assert not sh.drain()
    assert post.calls == 1
    now[0] += 6
    assert sh.ship({"i": 2}) == SENT
    assert [p["i"] for p in post.received] == [0, 1, 2]


class _StatusPost:
    """Answers each payload by a per-``i`` status; records what was accepted."""

    def __init__(self, statuses: dict[int, int]) -> None:
        self.statuses = statuses
        self.received: list[int] = []

    def __call__(self, payload: dict[str, Any]) -> int:
        status = self.statuses.get(payload["i"], 200)
        if status == 200:
            self.received.append(payload["i"])
        return status


def _clock(monkeypatch) -> list[float]:
    # Both clocks: the poison window is monotonic (an NTP step must not
    # satisfy it), the log stamp and max-age are wall-clock.
    now = [1_000_000.0]
    monkeypatch.setattr(spool_mod.time, "time", lambda: now[0])
    monkeypatch.setattr(spool_mod.time, "monotonic", lambda: now[0])
    return now


def test_a_batch_that_always_500s_is_poisoned_and_unblocks_the_stream(
    tmp_path: Path, monkeypatch
) -> None:
    now = _clock(monkeypatch)
    post = _StatusPost({0: 500})
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    sh = Shipper(sp, post, event_prefix="t")
    for i in range(3):
        sp.append({"i": i})
    # Enough attempts in quick succession is NOT enough: a burst of 500s
    # during a control-plane restart must not cost a batch.
    for _ in range(spool_mod.POISON_ATTEMPTS * 2):
        assert not sh.drain()
    assert post.received == []
    now[0] += spool_mod.POISON_MIN_SECONDS
    assert sh.drain()
    assert post.received == [1, 2]
    assert sp.status()["rejected_entries_total"] == 1
    assert len(list((sp.dir / "poison").glob("*.json"))) == 1


def test_a_500_that_clears_does_not_poison(tmp_path: Path, monkeypatch) -> None:
    now = _clock(monkeypatch)
    post = _StatusPost({0: 500})
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    sh = Shipper(sp, post, event_prefix="t")
    sp.append({"i": 0})
    for _ in range(spool_mod.POISON_ATTEMPTS - 1):
        assert not sh.drain()
        now[0] += spool_mod.POISON_MIN_SECONDS
    post.statuses[0] = 200
    assert sh.drain()
    assert post.received == [0]
    assert sp.status()["rejected_entries_total"] == 0


def test_a_500_for_every_body_never_poisons(tmp_path: Path, monkeypatch) -> None:
    """Schema skew mid-upgrade answers 500 to EVERY batch. That is an outage in
    all but status code: the probe behind the head fails too, so nothing goes."""
    now = _clock(monkeypatch)
    post = _StatusPost({0: 500, 1: 500, 2: 500})
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    sh = Shipper(sp, post, event_prefix="t")
    for i in range(3):
        sp.append({"i": i})
    for _ in range(spool_mod.POISON_ATTEMPTS * 10):
        assert not sh.drain()
        now[0] += spool_mod.POISON_MIN_SECONDS
    assert len(sp) == 3
    assert sp.status()["rejected_entries_total"] == 0


def test_a_lone_500ing_batch_waits_for_something_to_probe_with(
    tmp_path: Path, monkeypatch
) -> None:
    now = _clock(monkeypatch)
    post = _StatusPost({0: 500})
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    sh = Shipper(sp, post, event_prefix="t")
    sp.append({"i": 0})
    for _ in range(spool_mod.POISON_ATTEMPTS * 2):
        assert not sh.drain()
        now[0] += spool_mod.POISON_MIN_SECONDS
    assert len(sp) == 1
    # The next live batch queues behind it and becomes the probe on the next
    # drain: taken, so the head was the problem.
    assert sh.ship({"i": 1}) == RETRY
    assert sh.drain()
    assert post.received == [1]
    assert sp.status()["rejected_entries_total"] == 1


def test_an_outage_between_500s_restarts_the_count(tmp_path: Path, monkeypatch) -> None:
    """One 500, a long 503 window, then a few 500s while the control plane
    comes back up: the window and the count must not span the outage."""
    now = _clock(monkeypatch)
    post = _StatusPost({0: 500})
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    sh = Shipper(sp, post, event_prefix="t")
    sp.append({"i": 0})
    sp.append({"i": 1})
    assert not sh.drain()
    post.statuses = {0: 503, 1: 503}
    for _ in range(10):
        now[0] += spool_mod.POISON_MIN_SECONDS
        assert not sh.drain()
    post.statuses = {0: 500}
    for _ in range(spool_mod.POISON_ATTEMPTS):
        assert not sh.drain()
        now[0] += 1
    assert len(sp) == 2
    assert sp.status()["rejected_entries_total"] == 0


@pytest.mark.parametrize("status", [502, 503, 504])
def test_an_unavailable_control_plane_never_poisons(
    tmp_path: Path, monkeypatch, status: int
) -> None:
    """The outage the spool exists for: however long, nothing is discarded."""
    now = _clock(monkeypatch)
    post = _StatusPost({0: status, 1: status})
    sp = Spool(tmp_path, "s", 10_000_000, enabled=True)
    sh = Shipper(sp, post, event_prefix="t")
    sp.append({"i": 0})
    sp.append({"i": 1})
    for _ in range(spool_mod.POISON_ATTEMPTS * 10):
        assert not sh.drain()
        now[0] += spool_mod.POISON_MIN_SECONDS
    assert len(sp) == 2
    assert sp.status()["rejected_entries_total"] == 0


def test_a_rejected_batch_moves_the_alert_clock(tmp_path: Path) -> None:
    """A refused batch is lost like a trimmed one; the alert must see it."""
    sp = Spool(tmp_path, "lease_events", 10_000_000, enabled=True)
    sh = Shipper(sp, _StatusPost({0: 422}), event_prefix="t")
    sp.append({"i": 0})
    assert sp.status()["last_trim_at"] is None
    assert sh.drain()
    st = sp.status()
    assert st["rejected_entries_total"] == 1
    assert st["last_trim_at"] is not None
    # Persisted: a restart must not hide it.
    assert Spool(tmp_path, "lease_events", 10_000_000, enabled=True).status()["last_trim_at"]


# ── QueryLogShipper ──────────────────────────────────────────────────────


def _query_shipper(cfg: AgentConfig, sp: Spool, post: _FlakyPost) -> QueryLogShipper:
    qs = QueryLogShipper(cfg, ["tok"], path=str(cfg.state_dir / "q.log"), spool=sp)
    qs.shipper._post = post  # the network edge only
    qs.shipper._backoff = 0  # retry every flush; the backoff has its own test
    return qs


def _feed(qs: QueryLogShipper, lines: list[str]) -> None:
    qs._buffer.extend(lines)
    while qs._buffer:
        qs._flush()


@pytest.mark.parametrize("enabled", [True, False])
def test_query_log_outage_then_recovery(agent_cfg: AgentConfig, monkeypatch, enabled: bool) -> None:
    monkeypatch.setenv("AGENT_SPOOL_ENABLED", "true" if enabled else "false")
    sp = Spool(agent_cfg.state_dir, "query_log", 10_000_000)
    assert sp.enabled is enabled
    lines = [f"line {i}" for i in range(MAX_BATCH * 4 + 17)]  # 5 batches
    post = _FlakyPost(fail=3)
    qs = _query_shipper(agent_cfg, sp, post)
    _feed(qs, lines)
    # One more (idle-tick) drain once the control plane is back.
    qs.shipper.drain()

    delivered = [ln for body in post.received for ln in body["lines"]]
    if enabled:
        assert len(delivered) == len(lines)
        assert delivered == lines  # exactly once, original order
        assert len(sp) == 0
        ids = [b["batch_id"] for b in post.received]
        assert len(set(ids)) == len(ids) == 5
        assert all(len(i) == 32 for i in ids)
    else:
        # Negative control: the same harness sees the loss. Three failed
        # POSTs = three dropped batches.
        assert len(delivered) == len(lines) - 3 * MAX_BATCH
        assert delivered != lines


def test_query_log_batch_id_is_stable_across_retries(agent_cfg: AgentConfig) -> None:
    sp = Spool(agent_cfg.state_dir, "query_log", 10_000_000, enabled=True)
    attempts: list[str] = []

    def post(payload: dict[str, Any]) -> int:
        attempts.append(payload["batch_id"])
        return 503 if len(attempts) < 3 else 200

    qs = QueryLogShipper(agent_cfg, ["tok"], path=str(agent_cfg.state_dir / "q.log"), spool=sp)
    qs.shipper._post = post
    qs.shipper._backoff = 0
    _feed(qs, ["a", "b"])
    qs.shipper.drain()
    qs.shipper.drain()
    assert len(attempts) == 3
    assert len(set(attempts)) == 1


def test_query_log_spool_survives_agent_restart(agent_cfg: AgentConfig) -> None:
    lines = [f"l{i}" for i in range(MAX_BATCH * 2)]
    down = _FlakyPost(fail=10**9)
    _feed(
        _query_shipper(
            agent_cfg, Spool(agent_cfg.state_dir, "query_log", 10_000_000, enabled=True), down
        ),
        lines,
    )
    assert down.received == []
    # "Restart": a brand-new shipper over the same state dir.
    up = _FlakyPost(fail=0)
    qs = _query_shipper(
        agent_cfg, Spool(agent_cfg.state_dir, "query_log", 10_000_000, enabled=True), up
    )
    qs.shipper.drain()
    assert [ln for b in up.received for ln in b["lines"]] == lines


def test_query_log_idle_tick_drains_backlog(agent_cfg: AgentConfig, monkeypatch) -> None:
    """run() drains a backlog on a tick with nothing new to flush."""
    sp = Spool(agent_cfg.state_dir, "query_log", 10_000_000, enabled=True)
    sp.append({"lines": ["queued"], "batch_id": "b" * 32})
    log_file = agent_cfg.state_dir / "q.log"
    log_file.write_text("")
    post = _FlakyPost(fail=0)
    qs = _query_shipper(agent_cfg, sp, post)

    ticks = [0]

    def fake_wait(timeout: float | None = None) -> bool:
        ticks[0] += 1
        if ticks[0] >= 2:
            qs._stop.set()
        return qs._stop.is_set()

    monkeypatch.setattr(qs._stop, "wait", fake_wait)
    qs.run()
    assert post.received == [{"lines": ["queued"], "batch_id": "b" * 32}]


# ── MetricsPoller ────────────────────────────────────────────────────────


def test_metrics_outage_delivers_every_bucket_with_original_time(
    agent_cfg: AgentConfig,
) -> None:
    sp = Spool(agent_cfg.state_dir, "metrics", 10_000_000, enabled=True)
    mp = MetricsPoller(agent_cfg, ["tok"], spool=sp)
    post = _FlakyPost(fail=4)
    mp.shipper._post = post
    t0 = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    buckets = [t0 + timedelta(minutes=i) for i in range(6)]
    for i, b in enumerate(buckets):
        mp._report(b, {"queries_total": i})
    assert [r["bucket_at"] for r in post.received] == [b.isoformat() for b in buckets]
    assert [r["queries_total"] for r in post.received] == list(range(6))
    assert len(sp) == 0


def test_metrics_failed_report_still_advances_baseline(agent_cfg: AgentConfig) -> None:
    """The delta is spooled, not lost — re-baselining would double-count it."""
    mp = MetricsPoller(
        agent_cfg,
        ["tok"],
        spool=Spool(agent_cfg.state_dir, "metrics", 10_000_000, enabled=True),
    )
    post = _FlakyPost(fail=1)
    mp.shipper._post = post
    snaps = iter([{"queries_total": 10}, {"queries_total": 15}, {"queries_total": 22}])
    mp._poll_named = lambda: next(snaps)  # type: ignore[method-assign]
    mp.tick()  # baseline
    mp.tick()  # delta 5 — POST fails, spooled
    mp.tick()  # delta 7 — drains 5, then sends 7
    assert [r["queries_total"] for r in post.received] == [5, 7]


def test_metrics_idle_tick_drains(agent_cfg: AgentConfig) -> None:
    sp = Spool(agent_cfg.state_dir, "metrics", 10_000_000, enabled=True)
    sp.append({"bucket_at": "2026-09-22T12:00:00+00:00", "queries_total": 1, "batch_id": "c" * 32})
    mp = MetricsPoller(agent_cfg, ["tok"], spool=sp)
    post = _FlakyPost(fail=0)
    mp.shipper._post = post
    mp._poll_named = lambda: None  # type: ignore[method-assign]
    mp.tick()
    assert len(post.received) == 1


def test_metrics_without_spool_behaves_like_before(agent_cfg: AgentConfig) -> None:
    mp = MetricsPoller(agent_cfg, ["tok"])
    post = _FlakyPost(fail=1)
    mp.shipper._post = post
    t0 = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    mp._report(t0, {"queries_total": 1})
    mp._report(t0 + timedelta(minutes=1), {"queries_total": 2})
    assert [r["queries_total"] for r in post.received] == [2]
    assert not (agent_cfg.state_dir / "spool").exists()


# ── heartbeat + supervisor wiring ────────────────────────────────────────


class _CapturingClient:
    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self.sink = sink

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        self.sink.append(json)
        return httpx.Response(200, json={}, request=httpx.Request("POST", url))


def test_heartbeat_carries_spool_status(agent_cfg: AgentConfig, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_SPOOL_ENABLED", "true")
    manager = build_spool_manager(agent_cfg)
    manager.get("query_log").append({"lines": ["x"]})
    hb = HeartbeatClient(agent_cfg, ["tok"], spool_manager=manager)
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _CapturingClient(sent))
    hb.send_once()
    spool = sent[0]["spool"]
    assert spool["enabled"] is True
    assert spool["entries"] == 1
    assert set(spool["streams"]) == {"query_log", "metrics"}
    assert spool["streams"]["query_log"]["entries"] == 1
    assert spool["cap_bytes"] == manager.total_bytes


def test_heartbeat_survives_a_failing_spool_status(agent_cfg: AgentConfig, monkeypatch) -> None:
    class _Broken:
        def status(self) -> dict[str, Any]:
            raise OSError("disk gone")

    hb = HeartbeatClient(agent_cfg, ["tok"], spool_manager=_Broken())  # type: ignore[arg-type]
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _CapturingClient(sent))
    hb.send_once()
    assert len(sent) == 1
    assert "spool" not in sent[0]


def test_heartbeat_without_manager_omits_spool(agent_cfg: AgentConfig, monkeypatch) -> None:
    hb = HeartbeatClient(agent_cfg, ["tok"])
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _CapturingClient(sent))
    hb.send_once()
    assert "spool" not in sent[0]


def test_heartbeat_drops_spool_field_when_an_old_control_plane_422s_it(
    agent_cfg: AgentConfig, monkeypatch
) -> None:
    """A pre-#1077 control plane's heartbeat model is extra="forbid"; without the
    fallback every heartbeat 422s and a new agent reads as a dead server."""
    monkeypatch.setenv("AGENT_SPOOL_ENABLED", "true")
    sent: list[dict[str, Any]] = []

    class _OldCP(_CapturingClient):
        def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
            self.sink.append(dict(json))
            req = httpx.Request("POST", url)
            if "spool" in json:
                return httpx.Response(
                    422, json={"detail": [{"loc": ["body", "spool"]}]}, request=req
                )
            return httpx.Response(200, json={}, request=req)

    hb = HeartbeatClient(agent_cfg, ["tok"], spool_manager=build_spool_manager(agent_cfg))
    monkeypatch.setattr(hb, "_client", lambda: _OldCP(sent))
    hb.send_once()
    assert ["spool" in b for b in sent] == [True, False]
    hb.send_once()
    # Remembered: no second rejected attempt on later heartbeats.
    assert ["spool" in b for b in sent] == [True, False, False]


def test_supervisor_spool_shares_and_log_max_age(agent_cfg: AgentConfig, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_SPOOL_MAX_BYTES", "1000")
    monkeypatch.setenv("AGENT_SPOOL_LOG_MAX_AGE_HOURS", "2")
    m = build_spool_manager(agent_cfg)
    assert m.get("query_log").cap_bytes == 850
    assert m.get("query_log").max_age_seconds == 7200
    assert m.get("metrics").cap_bytes == 150
    assert m.get("metrics").max_age_seconds is None


def test_supervisor_log_max_age_defaults_to_retention(agent_cfg: AgentConfig, monkeypatch) -> None:
    monkeypatch.delenv("AGENT_SPOOL_LOG_MAX_AGE_HOURS", raising=False)
    assert build_spool_manager(agent_cfg).get("query_log").max_age_seconds == 24 * 3600
    monkeypatch.setenv("AGENT_SPOOL_LOG_MAX_AGE_HOURS", "0")
    assert build_spool_manager(agent_cfg).get("query_log").max_age_seconds is None
