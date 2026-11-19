"""DORA retransmits back off like an RFC 2131 client (§4.1).

The wait after send n of a round (n = 0 for the first) is min(4 * 2**n, 64) s,
moved by a uniform draw in [-1, +1] s from the shard's seeded RNG. A device
sends 4 times (≈0, 4, 12, 28 s) and gives up ≈60 s into the round. Before,
every unanswered DISCOVER or SELECTING REQUEST was resent after a fixed 4.0 s
and a device gave up at 16 s, so devices that lost a packet together resent
together, and a lease that took longer than 16 s read as a timeout.

Driven like test_device_fleet_accounting.py: no socket, replies injected as
parsed dicts, timers fired by hand at the time the orchestrator scheduled
them. Needs PyYAML (the manifest), installed by the perf CI job; in a bare
environment the file import-skips.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import sys
from collections import Counter
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))  # generators/orchestrator
sys.path.insert(0, str(HERE.parents[3] / "harness"))  # spddi_perf

import device_fleet as df  # noqa: E402
from accounting import KIND_DISCOVER, KIND_SELECT  # noqa: E402
from spddi_perf.runpaths import RunPaths  # noqa: E402

SMOKE = HERE.parents[3] / "manifests" / "smoke.yaml"
STEPS = [4.0, 8.0, 16.0, 32.0]  # the nominal wait after each of a round's 4 sends
JITTER = 1.0


@pytest.fixture
def orch(tmp_path, monkeypatch):
    """A relay-topology orchestrator over 8 devices / 2 subnets, no socket."""
    monkeypatch.delenv("SPDDI_PERF_NODE_IP", raising=False)
    monkeypatch.delenv("SPDDI_PERF_API_BASE", raising=False)
    monkeypatch.delenv("SPDDI_PERF_DHCP_IFACE", raising=False)
    m = yaml.safe_load(SMOKE.read_text())
    m["target"]["node_ip"] = "192.0.2.10"
    m["target"]["api_base"] = "https://192.0.2.10/api"
    m["target"]["dhcp"] = {
        "port": 67,
        "topology": "relay",
        "giaddr": ["10.9.0.1", "10.9.1.1"],
        "iface": "",
    }
    m["scale"]["unique_devices"] = 8
    m["scale"]["peak_active_devices"] = 8
    m["scale"]["students"] = 8
    m["seed"]["ip_block"] = "10.8.0.0/16"
    m["seed"]["subnets"] = {"count": 2, "prefix": 24, "pool_fraction": 0.9}
    m["seed"]["relay_addresses_per_scope"] = True
    mpath = tmp_path / "m.yaml"
    mpath.write_text(yaml.safe_dump(m))
    run_root = tmp_path / "run"
    RunPaths.for_run("t-run", run_root).ensure_dirs()
    o = df.Orchestrator(
        argparse.Namespace(
            run_id="t-run", run_root=str(run_root), manifest=str(mpath), shard=0, shards=1
        )
    )
    o.sent = []
    o._send = lambda pkt, dev: o.sent.append((dev.index, bytes(pkt)))  # type: ignore[method-assign]
    # The send paths stamp tx_at and schedule timers with time.monotonic(); the
    # tests hand every handler an explicit `now` on the same clock.
    o.clock = {"t": 0.0}
    monkeypatch.setattr(df.time, "monotonic", lambda: o.clock["t"])
    return o


def at(o, t: float) -> float:
    """Advance the orchestrator's clock to t and return it (for a handler's `now`)."""
    o.clock["t"] = t
    return t


def due(o, idx: int, xid: int) -> float:
    """When the timer the orchestrator scheduled for exchange ``xid`` fires."""
    [when] = [w for w, i, a in o._timers if i == idx and a == f"dora_timeout:{xid}"]
    return when


def offer(ip: str, xid: int) -> dict:
    return {"xid": xid, "yiaddr": ip, "server_id": "192.0.2.10", "msg_type": df.dp.DHCPOFFER}


def ack(ip: str, xid: int) -> dict:
    return {
        "xid": xid,
        "yiaddr": ip,
        "server_id": "192.0.2.10",
        "lease_time": 1800,
        "msg_type": df.dp.DHCPACK,
    }


def within(value: float, nominal: float, slack: float) -> bool:
    return nominal - slack <= value <= nominal + slack


def lose_every_discover(o, idx: int, t0: float) -> list[float]:
    """Arrive at t0 and let every DISCOVER of the round go unanswered, firing
    each timer when it is due. Returns the waits the device chose."""
    dev = o.devices[idx]
    o._handle_timer(idx, "arrival", at(o, t0))
    t, waits = t0, []
    for _ in range(df.MAX_DORA_RETRIES + 1):
        fire = due(o, idx, dev.xid)
        waits.append(fire - t)
        o._handle_timer(idx, f"dora_timeout:{dev.xid}", at(o, fire))
        t = fire
    return waits


# ---- the schedule itself ---------------------------------------------------


def test_waits_double_from_4_s_to_the_64_s_cap_within_1_s_of_jitter() -> None:
    rng = random.Random(1)
    for n, nominal in enumerate([4.0, 8.0, 16.0, 32.0, 64.0, 64.0, 64.0]):
        for _ in range(500):
            assert within(df.dora_retransmit_wait(n, rng), nominal, JITTER)

    class Edge:
        """An RNG that always draws one end of the jitter range."""

        def __init__(self, end: int) -> None:
            self.end = end

        def uniform(self, a: float, b: float) -> float:
            return a if self.end < 0 else b

    assert [df.dora_retransmit_wait(n, Edge(-1)) for n in range(6)] == [3, 7, 15, 31, 63, 63]
    assert [df.dora_retransmit_wait(n, Edge(+1)) for n in range(6)] == [5, 9, 17, 33, 65, 65]


def test_a_round_sends_4_times_and_gives_up_about_60_s_in() -> None:
    nominal = [
        min(df.DORA_BACKOFF_BASE_S * 2**n, df.DORA_BACKOFF_CAP_S)
        for n in range(df.MAX_DORA_RETRIES + 1)
    ]
    assert nominal == STEPS
    # sends at 0, 4, 12, 28 s; the 4th send's wait runs out at 60 s
    assert list(itertools.accumulate([0.0, *nominal])) == [0.0, 4.0, 12.0, 28.0, 60.0]


def test_same_seed_same_schedule() -> None:
    def schedule(seed: int) -> list[float]:
        rng = random.Random(seed)
        return [df.dora_retransmit_wait(n, rng) for n in range(df.MAX_DORA_RETRIES + 1)]

    assert schedule(0xC0FFEE) == schedule(0xC0FFEE)
    assert schedule(0xC0FFEE) != schedule(0xC0FFEE ^ 1)


def test_a_cohort_that_timed_out_in_one_tick_resends_across_many() -> None:
    """1,000 devices whose first wait ran out in the same scheduler tick: at a
    fixed wait every one of them resent in one tick again; jittered, they
    spread over the ±1 s window and no tick holds more than a few percent."""
    rng = random.Random(0xC0FFEE)
    waits = [df.dora_retransmit_wait(1, rng) for _ in range(1000)]
    per_tick = Counter(int(w / df.SCHED_TICK_S) for w in waits)
    assert len(per_tick) >= 30  # the 2 s window is 40 ticks of 50 ms
    assert max(per_tick.values()) <= 60


# ---- the FSM: DISCOVER leg ---------------------------------------------------


def test_unanswered_discovers_back_off_and_give_up_after_the_fourth_wait(orch) -> None:
    o = orch
    dev = o.devices[0]
    o._handle_timer(0, "arrival", at(o, 0.0))
    sends, waits, t = [], [], 0.0
    for n in range(df.MAX_DORA_RETRIES + 1):
        assert dev.state is df.DState.DISCOVERING and dev.dora_retries == n
        assert o.ledger.get(dev.xid).kind == KIND_DISCOVER
        assert o.counters.timeout == 0  # no verdict before the 4th wait runs out
        sends.append(t)
        fire = due(o, 0, dev.xid)
        waits.append(fire - t)
        o._handle_timer(0, f"dora_timeout:{dev.xid}", at(o, fire))
        t = fire
    for w, step in zip(waits, STEPS, strict=True):
        assert within(w, step, JITTER)
    # sends ≈0, 4, 12, 28 s and the give-up ≈60 s, each within the jitter so far
    for k, nominal in enumerate([0.0, 4.0, 12.0, 28.0]):
        assert within(sends[k], nominal, k * JITTER)
    assert within(t, 60.0, 4 * JITTER)
    assert o.counters.dora_sent == 4 and o.counters.timeout == 1
    assert dev.state is df.DState.OFFLINE and dev.dora_retries == 0


def test_the_jitter_comes_from_the_shards_seeded_rng(orch) -> None:
    o = orch
    o.rng.seed(99)
    a = lose_every_discover(o, 2, 0.0)
    o.rng.seed(99)
    b = lose_every_discover(o, 3, 0.0)
    o.rng.seed(100)
    c = lose_every_discover(o, 4, 0.0)
    assert a == b  # same seed, same schedule: a run is reproducible
    assert a != c  # and the draw is the shard RNG's, not a fresh one's


def test_devices_that_time_out_together_no_longer_resend_together(orch) -> None:
    """The whole shard arrives in one tick and every first DISCOVER is lost
    (one queue overflow). The resends and the deadlines after them are spread
    by the jitter, where a fixed 4 s put all eight on the same instants."""
    o = orch
    idxs = sorted(o.devices)
    for i in idxs:
        o._handle_timer(i, "arrival", at(o, 0.0))
    first = [due(o, i, o.devices[i].xid) for i in idxs]
    assert all(within(w, 4.0, JITTER) for w in first)
    assert len(set(first)) == len(idxs)
    # one scheduler tick handles every expired deadline at once
    for i in idxs:
        o._handle_timer(i, f"dora_timeout:{o.devices[i].xid}", at(o, 5.0))
    second = [due(o, i, o.devices[i].xid) for i in idxs]
    assert all(within(w, 5.0 + 8.0, JITTER) for w in second)
    assert len(set(second)) == len(idxs)
    assert max(second) - min(second) >= 0.5  # 0 at a fixed wait


# ---- the FSM: SELECTING REQUEST leg ------------------------------------------


def test_unanswered_requests_back_off_on_the_same_schedule_and_give_up_the_same_way(orch) -> None:
    """Kea OFFERs every DISCOVER promptly but no ACK ever comes back: each
    REQUEST's wait takes the round's step, its timeout falls back to a DISCOVER
    one step on, and the device gives up after the 4th REQUEST's wait."""
    o = orch
    dev = o.devices[1]
    o._handle_timer(1, "arrival", at(o, 0.0))
    t, waits = 0.0, []
    for n in range(df.MAX_DORA_RETRIES + 1):
        assert dev.state is df.DState.DISCOVERING and dev.dora_retries == n
        xd = dev.xid
        o._on_offer(dev, offer("10.8.1.5", xd), o.ledger.get(xd), at(o, t + 0.02))
        xs = dev.xid
        assert o.ledger.get(xs).kind == KIND_SELECT
        assert o.counters.timeout == 0
        fire = due(o, 1, xs)
        waits.append(fire - (t + 0.02))
        o._handle_timer(1, f"dora_timeout:{xs}", at(o, fire))
        t = fire
    for w, step in zip(waits, STEPS, strict=True):
        assert within(w, step, JITTER)
    assert within(t, 60.0 + 4 * 0.02, 4 * JITTER)
    assert o.counters.timeout == 1 and dev.state is df.DState.OFFLINE
    assert o.counters.dora_sent == 4 and o.counters.request_sent == 4
    # every REQUEST of the round was marked, so a straggling ACK reads as late
    left_open = o.ledger.open_for(1)
    assert len(left_open) == 4 and all(e.kind == KIND_SELECT for e in left_open)
    assert all(e.gave_up_at is not None for e in left_open)


def test_a_nak_restarts_the_backoff_from_the_first_step(orch) -> None:
    """A NAK sends the client back to INIT: its next DISCOVER waits ≈4 s again,
    not the step the NAKed round had reached."""
    o = orch
    dev = o.devices[4]
    o._handle_timer(4, "arrival", at(o, 0.0))
    for _ in range(2):  # two DISCOVERs lost: the round is on its 3rd send
        o._handle_timer(4, f"dora_timeout:{dev.xid}", at(o, due(o, 4, dev.xid)))
    assert dev.dora_retries == 2
    t = o.clock["t"]
    o._on_offer(dev, offer("10.8.0.9", dev.xid), o.ledger.get(dev.xid), at(o, t + 0.02))
    assert within(due(o, 4, dev.xid) - (t + 0.02), 16.0, JITTER)
    o._on_nak(dev, o.ledger.get(dev.xid), at(o, t + 0.05))
    assert dev.dora_retries == 0 and dev.state is df.DState.DISCOVERING
    assert within(due(o, 4, dev.xid) - (t + 0.05), 4.0, JITTER)


# ---- the evidence: a slow success is still visible --------------------------


def test_a_lease_that_needed_a_resend_is_counted_as_one(orch) -> None:
    o = orch
    # device 5: its first DISCOVER is lost, the resend is answered at once
    d5 = o.devices[5]
    o._handle_timer(5, "arrival", at(o, 0.0))
    o._handle_timer(5, f"dora_timeout:{d5.xid}", at(o, due(o, 5, d5.xid)))
    t = o.clock["t"]
    o._on_offer(d5, offer("10.8.1.6", d5.xid), o.ledger.get(d5.xid), at(o, t + 0.02))
    xs = d5.xid
    o._on_ack(d5, ack("10.8.1.6", xs), at(o, t + 0.04), o.ledger.get(xs))
    # device 6: answered inside its first wait
    d6 = o.devices[6]
    o._handle_timer(6, "arrival", at(o, 10.0))
    o._on_offer(d6, offer("10.8.0.6", d6.xid), o.ledger.get(d6.xid), at(o, 10.02))
    o._on_ack(d6, ack("10.8.0.6", d6.xid), at(o, 10.04), o.ledger.get(d6.xid))

    c = o.counters
    assert c.dora_ack == 2 and c.dora_ack_resent == 1
    assert c.dora_ack_over_budget == 0  # the ACK's own exchange was prompt
    assert d5.state is df.DState.ONLINE and d5.dora_retries == 0
    events = [json.loads(x) for x in o.rp.lifecycle.read_text().splitlines()]
    resends = {e["index"]: e["resends"] for e in events if e["event"] == "dora_ack"}
    assert resends == {5: 1, 6: 0}

    h = df.handshake_summary(o._counter_snapshot())
    assert h["acked"] == 2 and h["acked_after_resend"] == 1
    assert h["acked_without_resend"] == 1 and h["without_resend_pct"] == 50.0
    assert h["acked_within_budget"] == 2  # why "within budget" alone hides it


def test_an_ack_overtaken_by_its_own_timer_counts_as_resent(orch) -> None:
    o = orch
    dev = o.devices[7]
    o._handle_timer(7, "arrival", at(o, 0.0))
    o._on_offer(dev, offer("10.8.1.7", dev.xid), o.ledger.get(dev.xid), at(o, 0.02))
    xs = dev.xid
    o._handle_timer(7, f"dora_timeout:{xs}", at(o, due(o, 7, xs)))  # REQUEST unanswered
    o._on_ack(dev, ack("10.8.1.7", xs), at(o, o.clock["t"] + 0.5), o.ledger.get(xs))
    assert o.counters.dora_ack == 1 and o.counters.dora_ack_over_budget == 1
    assert o.counters.dora_ack_resent == 1 and o.counters.timeout == 0


def test_the_shard_summary_counts_rounds_still_open_at_stop(orch) -> None:
    o = orch
    o._handle_timer(0, "arrival", at(o, 0.0))  # still waiting when the shard stops
    d1 = o.devices[1]
    o._handle_timer(1, "arrival", at(o, 0.0))
    o._on_offer(d1, offer("10.8.1.5", d1.xid), o.ledger.get(d1.xid), at(o, 0.02))
    o._on_ack(d1, ack("10.8.1.5", d1.xid), at(o, 0.04), o.ledger.get(d1.xid))
    o._finalize()
    path = o.rp.generator("orchestrator.shard0.summary.ndjson")
    summary = json.loads(path.read_text().splitlines()[-1])
    assert summary["counters"]["dora_in_flight"] == 1
    assert summary["counters"]["dora_ack_resent"] == 0
    assert summary["handshake"]["in_flight"] == 1
    assert summary["handshake"]["acked_after_resend"] == 0
    assert summary["handshake"]["attempts"] == 1  # the open round has no verdict yet
