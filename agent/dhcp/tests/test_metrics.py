"""Tests for the Kea metrics poller.

Covers the interesting behaviors:
  • first tick after startup establishes a baseline, doesn't report;
  • second tick with a positive delta gets reported upstream;
  • counter-reset (Kea restart) is detected and the bucket is dropped;
  • the #980 loss counters ride the same delta, and ``socket_drop`` — which
    comes from procfs rather than from Kea — stays in lockstep with them.

We test ``_parse_snapshot`` + ``_compute_delta`` directly so the HTTP
client stays out of the test path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import spatium_dhcp_agent.metrics as m
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.metrics import MetricsPoller, _parse_snapshot


def _snapshot(values: dict[str, int]) -> dict:
    """Build a fake ``statistic-get-all`` response."""
    args: dict = {}
    for stat, v in values.items():
        args[stat] = [[v, "2026-04-22 09:00:00.000"]]
    return {"arguments": args}


def test_parse_snapshot_picks_expected_columns():
    resp = _snapshot(
        {
            "pkt4-discover-received": 10,
            "pkt4-offer-sent": 9,
            "pkt4-request-received": 9,
            "pkt4-ack-sent": 8,
            "pkt4-nak-sent": 1,
            "pkt4-decline-received": 0,
            "pkt4-release-received": 2,
            "pkt4-inform-received": 0,
        }
    )
    assert _parse_snapshot(resp) == {
        "discover": 10,
        "offer": 9,
        "request": 9,
        "ack": 8,
        "nak": 1,
        "decline": 0,
        "release": 2,
        "inform": 0,
        # #980 — absent from this response, so 0. The column exists either
        # way; a Kea too old to publish it is not a Kea that dropped nothing.
        "receive_drop": 0,
    }


def test_parse_snapshot_missing_counter_defaults_zero():
    # Fresh Kea that hasn't seen traffic yet won't have every counter
    # in its response. We must still produce a full row.
    resp = _snapshot({"pkt4-ack-sent": 5})
    out = _parse_snapshot(resp)
    assert out["ack"] == 5
    assert out["discover"] == 0
    assert out["request"] == 0


def _poller(tmp_path) -> MetricsPoller:
    cfg = AgentConfig(
        control_plane_url="http://api.invalid",
        agent_key="unused",
        server_name="dhcp-test",
        state_dir=tmp_path,
        kea_config_path=tmp_path / "kea.conf",
        kea_control_socket=tmp_path / "sock",
        kea_lease_file=tmp_path / "leases.csv",
        kea_config_path_v6=tmp_path / "kea6.conf",
        kea_control_socket_v6=tmp_path / "sock6",
        group_name=None,
        roles=["primary"],
        tls_ca_path=None,
        insecure_skip_tls_verify=True,
    )
    return MetricsPoller(cfg, token_ref=["unused"])


def test_first_tick_establishes_baseline(tmp_path):
    p = _poller(tmp_path)
    # First snapshot — no previous baseline, poller should not emit.
    delta = p._compute_delta(
        {
            "discover": 5,
            "offer": 5,
            "request": 5,
            "ack": 5,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    assert delta is None


def test_second_tick_emits_delta(tmp_path):
    p = _poller(tmp_path)
    p._compute_delta(
        {
            "discover": 5,
            "offer": 5,
            "request": 5,
            "ack": 5,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    delta = p._compute_delta(
        {
            "discover": 8,
            "offer": 8,
            "request": 8,
            "ack": 8,
            "nak": 1,
            "decline": 0,
            "release": 1,
            "inform": 0,
        }
    )
    assert delta == {
        "discover": 3,
        "offer": 3,
        "request": 3,
        "ack": 3,
        "nak": 1,
        "decline": 0,
        "release": 1,
        "inform": 0,
        "receive_drop": 0,
    }


def test_counter_reset_drops_bucket(tmp_path):
    p = _poller(tmp_path)
    p._compute_delta(
        {
            "discover": 100,
            "offer": 100,
            "request": 100,
            "ack": 100,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    # Kea restart: counters back to zero.
    delta = p._compute_delta(
        {
            "discover": 0,
            "offer": 0,
            "request": 0,
            "ack": 0,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    assert delta is None
    # Next normal tick produces a delta against the restart baseline.
    delta2 = p._compute_delta(
        {
            "discover": 2,
            "offer": 2,
            "request": 2,
            "ack": 2,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    assert delta2 == {
        "discover": 2,
        "offer": 2,
        "request": 2,
        "ack": 2,
        "nak": 0,
        "decline": 0,
        "release": 0,
        "inform": 0,
        "receive_drop": 0,
    }


# ── #980: the loss counters ─────────────────────────────────────────────────


def test_receive_drop_folds_both_address_families():
    """v4 and v6 are separate daemons sharing one row, like every other
    column here — so their drop counters sum rather than one overwriting
    the other."""
    resp = _snapshot({"pkt4-receive-drop": 4, "pkt6-receive-drop": 3})
    assert _parse_snapshot(resp)["receive_drop"] == 7


class _FakeResponse:
    status_code = 200


class _FakeClient:
    """Stands in for httpx.Client and records the JSON body actually posted."""

    def __init__(self, sink: list):
        self._sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, json=None, headers=None):
        self._sink.append(json)
        return _FakeResponse()


def _posted_body(tmp_path, monkeypatch, socket_drop):
    """Run the REAL ``_report`` and return the body it put on the wire."""
    p = _poller(tmp_path)
    sink: list = []
    monkeypatch.setattr(p, "_client", lambda: _FakeClient(sink))
    p._report(datetime(2026, 9, 6, 12, 0, tzinfo=UTC), {"discover": 3}, socket_drop)
    assert len(sink) == 1
    return sink[0]


def test_wire_body_carries_socket_drop_zero_as_a_value(tmp_path, monkeypatch):
    """Zero is a measurement and has to appear in the payload as 0.

    The server stores an omitted field as NULL, and NULL means "nobody
    looked" — so a working agent that measured no loss must not be filed
    under the same label as an agent that cannot measure at all. Asserts on
    the posted body rather than on a stubbed ``_report``, or the test would
    pass for a ``_report`` that silently dropped the field.
    """
    body = _posted_body(tmp_path, monkeypatch, 0)
    assert "socket_drop" in body
    assert body["socket_drop"] == 0
    assert body["discover"] == 3


def test_wire_body_carries_none_when_unmeasurable(tmp_path, monkeypatch):
    """The other half: unknown travels as an explicit null, not as 0 and not
    by omission (omission would be indistinguishable, but being explicit is
    what makes an older control plane's 422 loud rather than silent)."""
    body = _posted_body(tmp_path, monkeypatch, None)
    assert "socket_drop" in body
    assert body["socket_drop"] is None


def test_one_run_iteration_samples_both_counters_together(tmp_path, monkeypatch):
    """Drive the REAL ``run()`` loop for two ticks.

    Both baselines must advance on the same ticks: a bucket that is thrown
    away (agent start, Kea restart) throws away both deltas, and a bucket
    that is reported carries two numbers covering the same interval. If only
    one advanced, "drops against DISCOVERs" — the first comparison anyone
    makes — would span different windows.
    """
    p = _poller(tmp_path)
    sink: list = []
    monkeypatch.setattr(p, "_client", lambda: _FakeClient(sink))

    kea = iter([{"discover": 0}, {"discover": 7}])
    monkeypatch.setattr(p, "_poll_kea", lambda: next(kea, None))

    samples = iter([11, 22])
    sock_calls: list = []

    def _sample():
        v = next(samples, None)
        sock_calls.append(v)
        return v

    monkeypatch.setattr(p._socket, "sample", _sample)
    # Stop after the second tick rather than sleeping 60 s.
    real_wait = p._stop.wait
    ticks = {"n": 0}

    def _wait(timeout=None):
        ticks["n"] += 1
        if ticks["n"] >= 2:
            p._stop.set()
        return real_wait(0)

    monkeypatch.setattr(p._stop, "wait", _wait)

    p.run()

    # Two ticks -> two socket samples; only the second tick had a Kea
    # baseline, so exactly one bucket was posted, carrying that tick's
    # socket sample and not the first one.
    assert sock_calls == [11, 22]
    assert len(sink) == 1
    assert sink[0]["discover"] == 7
    assert sink[0]["socket_drop"] == 22


def test_the_drop_counter_follows_the_rendered_socket_mode(tmp_path):
    """#1283: the poller tells the drop counter kea-dhcp4's socket mode from
    the config file this agent writes for kea (``kea_config_path``)."""
    p = _poller(tmp_path)
    assert p._socket._socket_type() is None  # nothing rendered yet: unknown
    doc = {"Dhcp4": {"interfaces-config": {"dhcp-socket-type": "udp"}}}
    (tmp_path / "kea.conf").write_text(json.dumps(doc))
    assert p._socket._socket_type() == "udp"
    doc["Dhcp4"]["interfaces-config"]["dhcp-socket-type"] = "raw"
    (tmp_path / "kea.conf").write_text(json.dumps(doc))
    assert p._socket._socket_type() == "raw"


# ── #2889: requests evicted from Kea's packet queue ─────────────────────────


def test_parse_snapshot_keeps_pkt4_received_out_of_the_shipped_columns():
    """``pkt4-received`` is a term of ``queue_evicted``, not a column: it is
    parsed, and ``_compute_delta`` must not put it on the wire."""
    p = _parse_snapshot(_snapshot({"pkt4-received": 40, "pkt4-discover-received": 10}))
    assert p["_received4"] == 40
    assert "_received4" not in _parse_snapshot(_snapshot({"pkt6-solicit-received": 3}))


def _drive(tmp_path, monkeypatch, kea, socket_drops, v4_drops, arrivals):
    """Run the REAL ``run()`` for ``len(kea)`` ticks with scripted inputs and
    return every body posted."""
    p = _poller(tmp_path)
    sink: list = []
    monkeypatch.setattr(p, "_client", lambda: _FakeClient(sink))
    kea_it = iter(kea)
    monkeypatch.setattr(p, "_poll_kea", lambda: next(kea_it, None))
    sd_it = iter(zip(socket_drops, v4_drops))

    def _sample():
        total, v4 = next(sd_it)
        p._socket.last_v4 = v4
        return total

    monkeypatch.setattr(p._socket, "sample", _sample)
    # One (before, after) pair per tick: arrivals are read on both sides of
    # Kea's snapshot. A tick whose Kea poll fails takes only the first.
    arr_it = iter([v for pair in arrivals for v in pair])
    monkeypatch.setattr(p._arrivals, "sample", lambda: next(arr_it))
    real_wait = p._stop.wait
    ticks = {"n": 0}

    def _wait(timeout=None):
        if timeout is not None and timeout < 30:
            return False  # the #2889 aging wait inside a tick, not a tick
        ticks["n"] += 1
        if ticks["n"] >= len(kea):
            p._stop.set()
        return real_wait(0)

    monkeypatch.setattr(p._stop, "wait", _wait)
    p.run()
    return sink


def test_run_reports_queue_evicted_from_the_three_terms(tmp_path, monkeypatch):
    """1,000 arrive in one minute, the kernel drops 30 (all DHCPv4), the
    worker takes 870: 100 were evicted. Reported by the sample after, and
    the port-547 share of ``socket_drop`` is not subtracted from v4 arrivals."""
    kea = [
        {"discover": 0, "_received4": 0},
        {"discover": 500, "_received4": 500},
        {"discover": 1300, "_received4": 1370},
        {"discover": 1400, "_received4": 1470},
    ]
    sink = _drive(
        tmp_path,
        monkeypatch,
        kea,
        socket_drops=[None, 0, 35, 0],  # 5 of the 35 are DHCPv6
        v4_drops=[None, 0, 30, 0],
        arrivals=[(None, 0), (500, 0), (1000, 0), (100, 0)],
    )
    assert [b["queue_evicted"] for b in sink] == [0, 0, 100]
    assert [b["socket_drop"] for b in sink] == [0, 35, 0]


def test_run_reports_queue_evicted_none_when_arrivals_unmeasured(tmp_path, monkeypatch):
    """No CAP_NET_RAW, a v6-only server: unmeasured, explicit null, never 0."""
    kea = [{"discover": 0, "_received4": 0}, {"discover": 5, "_received4": 5}]
    sink = _drive(
        tmp_path,
        monkeypatch,
        kea,
        socket_drops=[None, 0],
        v4_drops=[None, 0],
        arrivals=[(None, None), (None, None)],
    )
    assert len(sink) == 1
    assert "queue_evicted" in sink[0]
    assert sink[0]["queue_evicted"] is None


def test_kea_restart_makes_the_bucket_after_it_unmeasured(tmp_path, monkeypatch):
    """``pkt4-received`` going backwards is a Kea restart: its delta, and so
    the eviction over that interval, is unknown — not a negative number and
    not a fabricated eviction of everything that arrived."""
    kea = [
        {"discover": 0, "_received4": 900},
        {"discover": 100, "_received4": 1000},
        {"discover": 0, "_received4": 3},  # restarted
        {"discover": 50, "_received4": 53},
        {"discover": 100, "_received4": 103},
    ]
    sink = _drive(
        tmp_path,
        monkeypatch,
        kea,
        socket_drops=[None, 0, 0, 0, 0],
        v4_drops=[None, 0, 0, 0, 0],
        arrivals=[(None, 0), (100, 0), (1000, 0), (50, 0), (50, 0)],
    )
    # The restart bucket itself is not posted (``_compute_delta`` drops it).
    assert [b["queue_evicted"] for b in sink] == [0, 0, 0]


def test_arrivals_are_carried_across_a_failed_kea_poll(tmp_path, monkeypatch):
    """Kea's control socket did not answer for a tick: the next good tick
    diffs Kea's counters across both minutes, so the arrivals read before
    the failed poll must be counted in it too — or the gap reads as Kea
    receiving more than arrived, and a real eviction after it is hidden."""
    kea = [
        {"discover": 0, "_received4": 0},
        {"discover": 100, "_received4": 100},
        None,  # control socket timed out
        {"discover": 300, "_received4": 300},
        {"discover": 400, "_received4": 340},  # 60 evicted
        {"discover": 500, "_received4": 440},
    ]
    sink = _drive(
        tmp_path,
        monkeypatch,
        kea,
        socket_drops=[None, 0, 0, 0, 0],
        v4_drops=[None, 0, 0, 0, 0],
        arrivals=[(None, 0), (100, 0), (100,), (100, 0), (100, 0), (100, 0)],
    )
    assert [b["queue_evicted"] for b in sink] == [0, 0, 0, 60]


# ── #2889: the QA walk's case 3, against a simulated Kea ───────────────────


class _SimKea:
    """A kea-dhcp4 in miniature, stepped 1 ms at a time: packets arrive at
    ``rate``/s, wait in a queue of at most ``depth`` (a full queue evicts its
    OLDEST packet, as Kea's ``pushBack`` does), and one worker takes them at
    ``service``/s except during ``stalls`` (``(start, end)`` seconds). Kea's
    ``pkt4-received`` counts a packet when the worker takes it."""

    def __init__(self, rate, service, depth=1024, stalls=(), bursts=(), queued=0):
        self.t = 0.0
        self.rate = rate
        self.service = service
        self.depth = depth
        self.stalls = stalls
        self.bursts = dict(bursts)  # second -> extra packets arriving then
        self.queue = queued
        self.arrived = queued  # cumulative, as the counting socket sees them
        self.received = 0
        self.evicted = 0
        self._arr_frac = 0.0
        self._srv_frac = 0.0
        self._read = 0

    def _push(self, n):
        self.arrived += n
        self.queue += n
        if self.queue > self.depth:
            self.evicted += self.queue - self.depth
            self.queue = self.depth

    def advance(self, seconds):
        steps = round(seconds * 1000)
        for _ in range(steps):
            self.t += 0.001
            sec = int(self.t)
            if sec in self.bursts and abs(self.t - sec - 0.0005) < 0.0006:
                self._push(self.bursts.pop(sec))
            self._arr_frac += self.rate / 1000
            n = int(self._arr_frac)
            self._arr_frac -= n
            if n:
                self._push(n)
            if any(a <= self.t < b for a, b in self.stalls):
                continue
            self._srv_frac += self.service / 1000
            k = min(int(self._srv_frac), self.queue)
            self._srv_frac -= int(self._srv_frac)
            self.queue -= k
            self.received += k

    def take_arrivals(self):
        n = self.arrived - self._read
        self._read = self.arrived
        return n


def _simulate(tmp_path, monkeypatch, sim, minutes, age=None):
    """The REAL ``run()`` against ``sim``: every wait advances its clock."""
    p = _poller(tmp_path)
    sink: list = []
    monkeypatch.setattr(p, "_client", lambda: _FakeClient(sink))
    monkeypatch.setattr(m.random, "uniform", lambda a, b: 0.0)
    if age is not None:
        monkeypatch.setattr(p, "_arrival_age", lambda: age)
    opened = {"done": False}

    def _arrivals():
        if not opened["done"]:  # the opening read: a window begun part-way
            opened["done"] = True
            sim.take_arrivals()
            return None
        return sim.take_arrivals()

    monkeypatch.setattr(p._arrivals, "sample", _arrivals)
    monkeypatch.setattr(
        p, "_poll_kea", lambda: {"discover": sim.received, "_received4": sim.received}
    )

    def _socket():
        p._socket.last_v4 = 0
        return 0

    monkeypatch.setattr(p._socket, "sample", _socket)
    ticks = {"n": 0}

    def _wait(timeout=None):
        sim.advance(timeout or 0)
        if timeout is not None and timeout >= 30:
            ticks["n"] += 1
            if ticks["n"] >= minutes:
                p._stop.set()
                return True
        return False

    monkeypatch.setattr(p._stop, "wait", _wait)
    p.run()
    return [b["queue_evicted"] for b in sink]


def _stalls_before_reads(age, period=60.0, first=60.0, n=10, length=0.253):
    """A Kea stall ending just before each Kea snapshot of the run."""
    out = []
    t = first
    for _ in range(n):
        snap = t + age
        out.append((snap - length, snap))
        t = snap + period
    return out


def test_case3_packets_in_flight_at_two_reads_are_not_evictions(tmp_path, monkeypatch):
    """The walk's case 3: a serving node at ~100 requests/s, Kea stalls
    253 ms just before consecutive snapshots, so ~25 packets are still
    waiting each time. Nothing is evicted; the bucket must read 0."""
    age = m.arrival_age_seconds(1024)
    sim = _SimKea(rate=100, service=700, stalls=_stalls_before_reads(age, n=8))
    out = _simulate(tmp_path, monkeypatch, sim, minutes=8)
    assert sim.evicted == 0
    assert out and all(v == 0 for v in out), out


def test_case3_reproduces_without_the_aging_wait(tmp_path, monkeypatch):
    """Negative control: the same run with the snapshot taken straight after
    the arrivals read (the estimator as walked at 256e823) reports the
    in-flight packets as evicted."""
    sim = _SimKea(rate=100, service=700, stalls=_stalls_before_reads(0.0, n=8))
    out = _simulate(tmp_path, monkeypatch, sim, minutes=8, age=0.0)
    assert sim.evicted == 0
    assert sum(v or 0 for v in out) > 0


def test_a_sustained_backlog_below_the_queue_depth_is_never_loss(tmp_path, monkeypatch):
    """Kea runs at exactly its capacity, and a burst at 90 s leaves ~900
    queued at every read from then on (below the 1,024 depth): nothing is
    evicted, nothing is reported. Without the aging wait this read as ~900
    evicted."""
    sim = _SimKea(rate=700, service=700, bursts={90: 900})
    out = _simulate(tmp_path, monkeypatch, sim, minutes=10)
    assert sim.evicted == 0
    assert 800 <= sim.queue <= 1024
    assert all(v == 0 for v in out), out
    sim = _SimKea(rate=700, service=700, bursts={90: 900})
    out = _simulate(tmp_path, monkeypatch, sim, minutes=10, age=0.0)
    assert sum(v or 0 for v in out) > 0  # negative control


def test_a_burst_deeper_than_the_queue_is_counted_exactly(tmp_path, monkeypatch):
    """The walk's case 1 shape: a burst evicts; the count matches what the
    queue actually evicted, one bucket after the burst, once."""
    sim = _SimKea(rate=0, service=700, bursts={150: 1043})
    out = _simulate(tmp_path, monkeypatch, sim, minutes=6)
    assert sim.evicted == 19
    assert sum(out) == 19
    assert max(out) == 19  # all in one bucket
    # Several bursts, quiet between them (the gate load's shape): each
    # counted exactly, once.
    sim = _SimKea(rate=0, service=700, bursts={150: 1043, 400: 1500, 520: 1100})
    out = _simulate(tmp_path, monkeypatch, sim, minutes=13)
    assert sim.evicted == 19 + 476 + 76
    assert sum(out) == sim.evicted


def test_steady_background_traffic_can_only_lower_the_count(tmp_path, monkeypatch):
    """The price of the aging wait: requests the worker serves during it
    were not yet counted as arrived, so under continuous background traffic
    the count is LOW by up to that traffic until a quieter read. It is
    never high."""
    sim = _SimKea(rate=50, service=700, bursts={150: 1043, 400: 1500})
    out = _simulate(tmp_path, monkeypatch, sim, minutes=10)
    assert sim.evicted > 0
    assert 0 <= sum(out) <= sim.evicted
