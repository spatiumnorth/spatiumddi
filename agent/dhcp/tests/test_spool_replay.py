"""#1077 — outage-then-recovery for every spooled DHCP-agent stream.

Each test drives the REAL shipper code against a fake control plane that can
be taken down, brought back, and made to lose a response after accepting a
batch (the in-flight case). The fake ingests each ``batch_id`` once and
answers a replay with ``{"duplicate": true}``, exactly as the backend does.

Every positive test asserts an explicit delivered count, and the negative
controls re-run the same scenario with ``AGENT_SPOOL_ENABLED=false`` and
assert the loss — so "nothing was lost" cannot pass by checking nothing.
"""

from __future__ import annotations

import csv
import io
import time
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dhcp_agent.heartbeat import HeartbeatClient
from spatium_dhcp_agent.lease_snapshot import LeaseSnapshot
from spatium_dhcp_agent.leases import LeaseWatcher
from spatium_dhcp_agent.log_shipper import LogShipper
from spatium_dhcp_agent.metrics import MetricsPoller
from spatium_dhcp_agent.push import drain_for
from spatium_dhcp_agent.spool import Spool, SpoolManager

# ── fakes ────────────────────────────────────────────────────────────


class _Resp:
    def __init__(self, status: int, body: Any = None, text: str = "") -> None:
        self.status_code = status
        self._body = body
        self.text = text

    def json(self) -> Any:
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeCP:
    """A control plane that can be down, and that dedupes on batch_id."""

    def __init__(self) -> None:
        self.up = True
        self.lose_next_response = False
        self.attempts: list[tuple[str, dict]] = []
        self.ingested: dict[str, list[dict]] = {}
        self._seen: set[str] = set()

    def client(self) -> FakeCP:
        return self

    def __enter__(self) -> FakeCP:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def post(self, path: str, json: dict, headers: dict | None = None) -> _Resp:
        import copy

        body = copy.deepcopy(json)
        self.attempts.append((path, body))
        if not self.up:
            raise httpx.ConnectError("control plane down")
        bid = body.get("batch_id")
        if bid is not None and bid in self._seen:
            return _Resp(200, {"duplicate": True})
        if bid is not None:
            self._seen.add(bid)
        self.ingested.setdefault(path, []).append(body)
        if self.lose_next_response:
            # Accepted and committed server-side; the response never arrives.
            self.lose_next_response = False
            raise httpx.ReadTimeout("response lost")
        return _Resp(200, {"ok": True})

    def bodies(self, suffix: str) -> list[dict]:
        return [body for p, lst in self.ingested.items() if p.endswith(suffix) for body in lst]


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Drive every ``time.monotonic`` caller (shipper backoff, flush timers)."""
    c = Clock()
    monkeypatch.setattr(time, "monotonic", c)
    return c


@pytest.fixture
def cp() -> FakeCP:
    return FakeCP()


def _spool(state: Path, stream: str, cap: int = 64 * 1024 * 1024, **kw: Any) -> Spool:
    return Spool(state, stream, cap, **kw)


# ── DHCP activity log ────────────────────────────────────────────────


def _log_shipper(agent_cfg, cp: FakeCP, log_path: Path, spool: Spool) -> LogShipper:
    s = LogShipper(agent_cfg, ["tok"], path=str(log_path), spool=spool)
    s._cp_client = cp.client  # type: ignore[method-assign]
    return s


def _run_log_outage(agent_cfg, cp: FakeCP, clock: Clock, tmp_path: Path) -> list[str]:
    """Write 450 lines during an outage, restart the agent mid-outage,
    recover. Returns the lines the control plane ingested, in order."""
    log_path = tmp_path / "kea-dhcp4.log"
    log_path.write_text("")
    shipper = _log_shipper(agent_cfg, cp, log_path, _spool(tmp_path, "dhcp_log"))
    shipper.tick()  # attach at EOF

    cp.up = False
    with log_path.open("a") as fh:
        for i in range(450):
            fh.write(f"line-{i:04d}\n")
    shipper.tick()  # two full batches
    clock.advance(6)
    shipper.tick()  # the 50-line remainder, on the batch interval

    # Agent restart mid-outage: a new process, a new Spool on the same dir.
    shipper = _log_shipper(agent_cfg, cp, log_path, _spool(tmp_path, "dhcp_log"))
    cp.up = True
    clock.advance(60)
    shipper._maybe_drain()
    return [line for b in cp.bodies("/log-entries") for line in b["lines"]]


def test_log_outage_replays_every_line_in_order(agent_cfg, cp, clock, tmp_path):
    delivered = _run_log_outage(agent_cfg, cp, clock, tmp_path)
    assert len(delivered) == 450
    assert delivered == [f"line-{i:04d}" for i in range(450)]


def test_log_negative_control_spool_disabled_loses_the_window(
    agent_cfg, cp, clock, tmp_path, monkeypatch
):
    monkeypatch.setenv("AGENT_SPOOL_ENABLED", "false")
    delivered = _run_log_outage(agent_cfg, cp, clock, tmp_path)
    # The pre-#1077 behaviour: every batch posted during the outage dropped.
    assert len(delivered) == 0


def test_log_backoff_spools_without_a_post_per_batch(agent_cfg, cp, clock, tmp_path):
    """A black-holed control plane costs one POST per backoff window, not one
    per batch — every later batch goes straight to disk."""
    log_path = tmp_path / "kea-dhcp4.log"
    log_path.write_text("")
    spool = _spool(tmp_path, "dhcp_log")
    shipper = _log_shipper(agent_cfg, cp, log_path, spool)
    shipper.tick()
    cp.up = False
    with log_path.open("a") as fh:
        fh.writelines(f"l{i}\n" for i in range(1000))
    shipper.tick()
    assert len(cp.attempts) == 1
    assert len(spool) == 5


def test_log_in_flight_batch_is_replayed_once(agent_cfg, cp, clock, tmp_path):
    """The batch whose response was lost is re-sent with the SAME batch_id,
    and the control plane ingests it exactly once."""
    log_path = tmp_path / "kea-dhcp4.log"
    log_path.write_text("")
    shipper = _log_shipper(agent_cfg, cp, log_path, _spool(tmp_path, "dhcp_log"))
    shipper.tick()
    cp.lose_next_response = True
    with log_path.open("a") as fh:
        fh.writelines(f"l{i}\n" for i in range(200))
    shipper.tick()
    assert len(shipper._shipper.spool) == 1  # outcome unknown → kept
    clock.advance(60)
    shipper._maybe_drain()
    ids = [b["batch_id"] for _, b in cp.attempts]
    assert len(ids) == 2 and ids[0] == ids[1]
    assert len(cp.bodies("/log-entries")) == 1
    assert len(shipper._shipper.spool) == 0


# ── metrics ──────────────────────────────────────────────────────────


def _metrics(agent_cfg, cp: FakeCP, spool: Spool) -> MetricsPoller:
    p = MetricsPoller(agent_cfg, ["tok"], spool=spool)
    p._client = cp.client  # type: ignore[method-assign]
    return p


def _run_metrics_outage(agent_cfg, cp: FakeCP, tmp_path: Path) -> list[dict]:
    base = datetime(2026, 9, 12, 10, 0, tzinfo=UTC)
    p = _metrics(agent_cfg, cp, _spool(tmp_path, "metrics"))
    p._report(base, {"discover": 1}, 0)  # live
    cp.up = False
    for i in range(1, 6):
        p._report(base + timedelta(minutes=i), {"discover": i + 1}, 0)
    # Restart mid-outage.
    p = _metrics(agent_cfg, cp, _spool(tmp_path, "metrics"))
    cp.up = True
    p._report(base + timedelta(minutes=6), {"discover": 7}, 0)
    return cp.bodies("/metrics")


def test_metrics_every_bucket_delivered_once_with_original_bucket_at(agent_cfg, cp, tmp_path):
    delivered = _run_metrics_outage(agent_cfg, cp, tmp_path)
    base = datetime(2026, 9, 12, 10, 0, tzinfo=UTC)
    assert len(delivered) == 7
    assert [b["bucket_at"] for b in delivered] == [
        (base + timedelta(minutes=i)).isoformat() for i in range(7)
    ]
    assert [b["discover"] for b in delivered] == list(range(1, 8))
    # batch_id stable across retries: every attempt for a bucket, failed or
    # not, carried the one id the control plane finally ingested for it.
    ids: dict[str, set[str]] = {}
    for _, b in cp.attempts:
        ids.setdefault(b["bucket_at"], set()).add(b["batch_id"])
    retried = [
        b
        for b in delivered
        if len([a for _, a in cp.attempts if a["bucket_at"] == b["bucket_at"]]) > 1
    ]
    assert retried, "no bucket was retried — the outage never happened"
    for b in delivered:
        assert ids[b["bucket_at"]] == {b["batch_id"]}
    assert len({b["batch_id"] for b in delivered}) == 7


def test_metrics_negative_control_spool_disabled_loses_buckets(
    agent_cfg, cp, tmp_path, monkeypatch
):
    monkeypatch.setenv("AGENT_SPOOL_ENABLED", "false")
    delivered = _run_metrics_outage(agent_cfg, cp, tmp_path)
    assert len(delivered) == 2  # the live bucket before and after; five lost
    assert [b["discover"] for b in delivered] == [1, 7]


def test_metrics_baseline_advances_through_a_failed_report(agent_cfg, cp, tmp_path, monkeypatch):
    """Drive the real run() loop: Kea counters 0 → 5 → 12 with the control
    plane down on the second tick. Both deltas arrive (5 then 7) — the
    failed one is spooled, not re-folded into the next bucket."""
    p = _metrics(agent_cfg, cp, _spool(tmp_path, "metrics"))
    kea = iter([{"discover": 0}, {"discover": 5}, {"discover": 12}])
    monkeypatch.setattr(p, "_poll_kea", lambda: next(kea, None))
    monkeypatch.setattr(p._socket, "sample", lambda: 0)
    ticks = {"n": 0}

    def _wait(timeout=None):
        ticks["n"] += 1
        cp.up = ticks["n"] != 1  # down during tick 2's report
        if ticks["n"] >= 3:
            p._stop.set()
        return True

    monkeypatch.setattr(p._stop, "wait", _wait)
    p.run()
    assert [b["discover"] for b in cp.bodies("/metrics")] == [5, 7]


# ── lease events ─────────────────────────────────────────────────────


def _csv_rows(ips: list[str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    for n, ip in enumerate(ips):
        w.writerow(
            [
                ip,
                f"aa:bb:cc:00:{n // 256:02x}:{n % 256:02x}",
                "",
                "3600",
                "2000000000",
                "1",
                "0",
                "0",
                f"h{n}",
                "0",
                "",
                "1",
                "0",
                "0",
            ]
        )
    return buf.getvalue()


class FakeKea:
    """Serves ``lease4-get-page`` over an in-memory lease table."""

    def __init__(self, leases: list[dict] | None = None) -> None:
        self.leases = leases or []
        self.calls: list[dict] = []
        self.fail = False

    def __call__(self, arguments: dict) -> dict:
        self.calls.append(dict(arguments))
        if self.fail:
            raise OSError("no such socket")
        frm, limit = arguments["from"], arguments["limit"]
        start = 0
        if frm != "start":
            start = next(i for i, le in enumerate(self.leases) if le["ip-address"] == frm) + 1
        page = self.leases[start : start + limit]
        if not page:
            return {
                "result": 3,
                "text": "0 IPv4 lease(s) found.",
                "arguments": {"leases": [], "count": 0},
            }
        return {
            "result": 0,
            "text": f"{len(page)} IPv4 lease(s) found.",
            "arguments": {"leases": page, "count": len(page)},
        }


def _kea_lease(ip: str, mac: str = "aa:bb:cc:dd:ee:01", state: int = 0) -> dict:
    return {
        "ip-address": ip,
        "hw-address": mac,
        "client-id": "01:aa",
        "valid-lft": 3600,
        "cltt": 1_900_000_000,
        "subnet-id": 1,
        "fqdn-fwd": False,
        "fqdn-rev": False,
        "hostname": "host.example.",
        "state": state,
        "pool-id": 0,
    }


def _watcher(agent_cfg, cp: FakeCP, spool: Spool, kea: FakeKea, clock: Clock, hb=None):
    hb = hb or types.SimpleNamespace(lease_count_since_start=0)
    w = LeaseWatcher(
        agent_cfg,
        ["tok"],
        hb,
        spool=spool,
        snapshot=LeaseSnapshot(Path("/nonexistent"), lambda p: 0, clock=clock),
    )
    w._client = cp.client  # type: ignore[method-assign]
    # Rebind the snapshot to the watcher's real poster + the fake Kea.
    w.snapshot = LeaseSnapshot(Path("/nonexistent"), w._post_snapshot, clock=clock, fetch=kea)
    w.snapshot.request("agent_start")
    return w, hb


def _run_lease_outage(agent_cfg, cp, clock, tmp_path):
    ips = [f"10.1.{i // 200}.{i % 200 + 1}" for i in range(250)]
    kea = FakeKea()
    w, _ = _watcher(agent_cfg, cp, _spool(tmp_path, "lease_events"), kea, clock)
    cp.up = False
    agent_cfg.kea_lease_file.write_text(_csv_rows(ips))
    w.tick()
    clock.advance(6)
    w.tick()
    # Restart mid-outage. Kea's LFC has rotated the CSV in the meantime, so
    # the re-read at offset 0 cannot be what delivers these events.
    agent_cfg.kea_lease_file.write_text("")
    w, hb = _watcher(agent_cfg, cp, _spool(tmp_path, "lease_events"), kea, clock)
    cp.up = True
    clock.advance(60)
    w.tick()
    events = [e for b in cp.bodies("/lease-events") for e in b["leases"]]
    return ips, events, hb


def test_lease_events_survive_restart_and_replay_in_order(agent_cfg, cp, clock, tmp_path):
    ips, events, hb = _run_lease_outage(agent_cfg, cp, clock, tmp_path)
    assert len(events) == 250
    assert [e["ip_address"] for e in events] == ips
    # Drained events count as delivered on the heartbeat.
    assert hb.lease_count_since_start == 250


def test_lease_events_negative_control_spool_disabled(agent_cfg, cp, clock, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SPOOL_ENABLED", "false")
    _, events, hb = _run_lease_outage(agent_cfg, cp, clock, tmp_path)
    # The in-memory retry buffer died with the process.
    assert len(events) == 0
    assert hb.lease_count_since_start == 0


def test_lease_duplicate_replay_is_not_counted_twice(agent_cfg, cp, clock, tmp_path):
    w, hb = _watcher(agent_cfg, cp, _spool(tmp_path, "lease_events"), FakeKea(), clock)
    cp.lose_next_response = True
    agent_cfg.kea_lease_file.write_text(_csv_rows([f"10.2.0.{i}" for i in range(1, 101)]))
    w.tick()
    assert hb.lease_count_since_start == 0  # outcome unknown
    clock.advance(60)
    w.tick()
    assert len(cp.bodies("/lease-events")) == 1
    # The replay was answered {"duplicate": true}; the first POST landed but
    # its response was lost, so neither incremented the counter. Under-count
    # by one batch rather than double-count.
    assert hb.lease_count_since_start == 0


def test_snapshot_runs_on_start_then_on_recovery_throttled(agent_cfg, cp, clock, tmp_path):
    kea = FakeKea([_kea_lease("10.3.0.1")])
    w, _ = _watcher(agent_cfg, cp, _spool(tmp_path, "lease_events"), kea, clock)
    w.tick()

    def starts() -> int:
        return sum(1 for c in kea.calls if c["from"] == "start")

    assert starts() == 1  # the start snapshot
    assert w.snapshot.runs_completed == 1

    # Outage with lease traffic, recovery 60 s later.
    cp.up = False
    agent_cfg.kea_lease_file.write_text(_csv_rows(["10.3.0.2"]))
    clock.advance(6)
    w.tick()
    assert len(w._shipper.spool) == 1
    cp.up = True
    clock.advance(60)
    w.tick()
    assert len(w._shipper.spool) == 0
    # Recovery requested a snapshot, but one ran < 5 min ago.
    assert w.snapshot.due and starts() == 1
    clock.advance(300)
    w.tick()
    assert starts() == 2
    assert w.snapshot.runs_completed == 2
    snap_posts = [
        b
        for b in cp.bodies("/lease-events")
        if [e["ip_address"] for e in b["leases"]] == ["10.3.0.1"]
    ]
    assert len(snap_posts) == 2


def test_snapshot_waits_for_the_backlog(agent_cfg, cp, clock, tmp_path):
    """A snapshot never overtakes spooled events — replaying those after it
    would roll leases back to an older state."""
    kea = FakeKea([_kea_lease("10.4.0.1")])
    spool = _spool(tmp_path, "lease_events")
    spool.append(
        {
            "leases": [{"ip_address": "10.4.0.9", "mac_address": "aa:aa:aa:aa:aa:aa"}],
            "batch_id": "b" * 32,
        }
    )
    cp.up = False
    w, _ = _watcher(agent_cfg, cp, spool, kea, clock)
    w.tick()
    assert kea.calls == []
    cp.up = True
    clock.advance(60)
    w.tick()
    posted = [e["ip_address"] for b in cp.bodies("/lease-events") for e in b["leases"]]
    assert posted == ["10.4.0.9", "10.4.0.1"]


# ── lease snapshot unit ──────────────────────────────────────────────


def test_snapshot_pages_converts_and_skips_macless(clock):
    leases = [_kea_lease(f"10.5.{i // 250}.{i % 250 + 1}", state=i % 4) for i in range(250)]
    leases[7]["hw-address"] = ""  # MAC-less: cannot be mirrored (#428)
    kea = FakeKea(leases)
    posted: list[dict] = []
    snap = LeaseSnapshot(Path("/x"), lambda p: posted.append(p) or 200, clock=clock, fetch=kea)
    snap.request("test")
    while snap.step(budget_seconds=10):
        pass
    assert [c["from"] for c in kea.calls] == [
        "start",
        leases[99]["ip-address"],
        leases[199]["ip-address"],
    ]
    assert all(c["limit"] == 100 for c in kea.calls)
    events = [e for p in posted for e in p["leases"]]
    assert len(events) == 249
    assert all(len(p["batch_id"]) == 32 for p in posted)
    assert "10.5.0.8" not in {e["ip_address"] for e in events}
    e0 = events[0]
    assert e0 == {
        "ip_address": "10.5.0.1",
        "mac_address": "aa:bb:cc:dd:ee:01",
        "hostname": "host.example.",
        "state": "active",
        "starts_at": datetime.fromtimestamp(1_900_000_000, tz=UTC).isoformat(),
        "ends_at": datetime.fromtimestamp(1_900_003_600, tz=UTC).isoformat(),
        "expires_at": datetime.fromtimestamp(1_900_003_600, tz=UTC).isoformat(),
    }
    states = {e["ip_address"]: e["state"] for e in events}
    assert states["10.5.0.2"] == "declined"
    assert states["10.5.0.3"] == "expired"
    assert states["10.5.0.4"] == "released"
    assert snap.runs_completed == 1


def test_snapshot_exact_page_boundary_ends_on_result_3(clock):
    kea = FakeKea([_kea_lease(f"10.6.0.{i}") for i in range(1, 201)])
    posted: list[dict] = []
    snap = LeaseSnapshot(Path("/x"), lambda p: posted.append(p) or 200, clock=clock, fetch=kea)
    snap.request("test")
    while snap.step(budget_seconds=10):
        pass
    assert len(kea.calls) == 3  # the third page is the empty result-3 answer
    assert sum(len(p["leases"]) for p in posted) == 200
    assert snap.runs_completed == 1 and not snap.due


def test_snapshot_empty_table(clock):
    kea = FakeKea([])
    posted: list[dict] = []
    snap = LeaseSnapshot(Path("/x"), lambda p: posted.append(p) or 200, clock=clock, fetch=kea)
    snap.request("test")
    snap.step()
    assert posted == [] and snap.runs_completed == 1


def test_snapshot_backs_off_until_kea_answers(clock):
    kea = FakeKea([_kea_lease("10.7.0.1")])
    kea.fail = True
    posted: list[dict] = []
    snap = LeaseSnapshot(Path("/x"), lambda p: posted.append(p) or 200, clock=clock, fetch=kea)
    snap.request("agent_start")
    snap.step()
    snap.step()  # inside the backoff: no second attempt
    assert len(kea.calls) == 1 and snap.due
    kea.fail = False
    clock.advance(6)
    snap.step()
    assert len(posted) == 1 and snap.runs_completed == 1


def test_snapshot_abandoned_on_cp_outage_and_throttled(clock):
    kea = FakeKea([_kea_lease(f"10.8.0.{i}") for i in range(1, 151)])
    state = {"up": False}

    def post(p):
        if not state["up"]:
            raise httpx.ConnectError("down")
        return 200

    snap = LeaseSnapshot(Path("/x"), post, clock=clock, fetch=kea)
    snap.request("agent_start")
    snap.step()
    assert not snap.running and snap.due and snap.runs_completed == 0
    state["up"] = True
    clock.advance(60)
    snap.step()
    assert len(kea.calls) == 1  # throttled: at most one walk per 5 min
    clock.advance(241)
    while snap.step(budget_seconds=10):
        pass
    assert snap.runs_completed == 1


def test_kea_ctrl_accepts_result_3_when_asked(tmp_path):
    """The real control-socket client: result 3 raises by default and is
    returned when the caller lists it (what the snapshot does)."""
    import json
    import socket
    import threading

    from spatium_dhcp_agent.kea_ctrl import KeaCtrlError, send_command

    path = tmp_path / "s"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(2)

    def serve():
        for _ in range(2):
            conn, _a = srv.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(
                    json.dumps(
                        {
                            "result": 3,
                            "text": "0 IPv4 lease(s) found.",
                            "arguments": {"leases": [], "count": 0},
                        }
                    ).encode()
                )

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    with pytest.raises(KeaCtrlError):
        send_command(path, "lease4-get-page", {"from": "start", "limit": 100})
    resp = send_command(
        path, "lease4-get-page", {"from": "start", "limit": 100}, accept_results=(0, 3)
    )
    assert resp["result"] == 3
    t.join(timeout=5)
    srv.close()


# ── heartbeat + manager ──────────────────────────────────────────────


def test_heartbeat_carries_spool_status_and_survives_old_cp(agent_cfg, tmp_path, monkeypatch):
    mgr = SpoolManager(tmp_path, total_bytes=1000)
    mgr.declare("lease_events", 1.0)
    mgr.get("lease_events").append({"leases": [], "batch_id": "c" * 32})
    hb = HeartbeatClient(agent_cfg, ["tok"], spool_manager=mgr)
    monkeypatch.setattr(hb, "_kea_version", lambda: None)
    sent: list[dict] = []

    class _C:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, path, json, headers):
            sent.append(dict(json))
            if "spool" in json:
                return _Resp(422, text='{"detail":[{"loc":["body","spool"]}]}')
            return _Resp(200, {})

    monkeypatch.setattr(hb, "_client", lambda: _C())
    hb.send_once()
    assert sent[0]["spool"]["entries"] == 1
    assert sent[0]["spool"]["streams"]["lease_events"]["entries"] == 1
    assert "spool" not in sent[1]
    hb.send_once()
    assert "spool" not in sent[2]  # remembered: one POST per beat, not two


def test_drain_for_stops_when_the_control_plane_still_refuses(tmp_path, cp):
    from spatium_dhcp_agent.push import CPPoster
    from spatium_dhcp_agent.spool import Shipper

    sp = _spool(tmp_path, "metrics")
    for i in range(3):
        sp.append({"n": i, "batch_id": f"{i:032d}"})
    cfg = types.SimpleNamespace(control_plane_url="http://cp", httpx_verify=lambda: True)
    sh = Shipper(
        sp, CPPoster(cfg, ["t"], "/api/v1/dhcp/agents/metrics", cp.client), event_prefix="t"
    )
    cp.up = False
    assert drain_for(sh, 30) is False
    assert len(cp.attempts) == 1  # one refused attempt, not a busy loop
    cp.up = True
    assert drain_for(sh, 30) is True
    assert [b["n"] for b in cp.bodies("/metrics")] == [0, 1, 2]


def test_poster_retries_without_batch_id_against_a_pre_1077_cp(tmp_path):
    from spatium_dhcp_agent.push import CPPoster

    seen: list[dict] = []

    class _C:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, path, json, headers):
            seen.append(dict(json))
            if "batch_id" in json:
                return _Resp(
                    422, text='{"detail":[{"loc":["body","batch_id"],' '"type":"extra_forbidden"}]}'
                )
            return _Resp(200, {"upserted": 1})

    cfg = types.SimpleNamespace(control_plane_url="http://cp", httpx_verify=lambda: True)
    poster = CPPoster(cfg, ["t"], "/api/v1/dhcp/agents/lease-events", lambda: _C())
    assert poster({"leases": [], "batch_id": "d" * 32}) == 200
    assert poster({"leases": [], "batch_id": "e" * 32}) == 200
    assert [("batch_id" in b) for b in seen] == [True, False, False]


def test_spool_module_byte_identical_to_dns_agent():
    here = Path(__file__).resolve().parents[1] / "spatium_dhcp_agent" / "spool.py"
    dns = Path(__file__).resolve().parents[2] / "dns" / "spatium_dns_agent" / "spool.py"
    if not dns.exists():
        pytest.skip("DNS agent not present in this checkout")
    assert here.read_bytes() == dns.read_bytes()
