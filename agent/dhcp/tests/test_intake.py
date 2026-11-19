"""DHCPv4 intake arrivals + the queue-eviction estimate (#2889).

Three layers, tested separately because each fails differently:

* the BPF program — run here through a small classic-BPF interpreter over
  hand-built IPv4 headers, so CI (unprivileged, no ``CAP_NET_RAW``) checks
  what the filter ACCEPTS, not just that it was emitted. A real-kernel test
  on loopback runs where a raw socket can be opened and skips elsewhere;
* :class:`ArrivalCounter` — open/reopen/unavailable, over a scripted socket;
* :class:`QueueEvictionEstimator` — the arithmetic, which is where a wrong
  answer would page someone.
"""

from __future__ import annotations

import json
import socket
import struct
import time

import pytest

from spatium_dhcp_agent.intake import (
    ArrivalCounter,
    Insn,
    IntakeConfig,
    QueueEvictionEstimator,
    Resolved,
    _PacketCountingSocket,
    _resolve_intake,
    build_filter,
    kea_intake_config,
)

HOST, BROADCAST, MULTICAST, OTHERHOST = 0, 1, 2, 3


# ── a classic-BPF interpreter, for the opcodes build_filter emits ──────────


def _run_bpf(prog: list[Insn], pkt: bytes, pkttype: int, ifindex: int) -> int:
    a = x = 0
    pc = 0
    while True:
        i = prog[pc]
        pc += 1
        if i.code == 0x30:  # ld b [k]
            a = pkt[i.k]
        elif i.code == 0x28:  # ld h [k]
            a = struct.unpack_from("!H", pkt, i.k)[0]
        elif i.code == 0x20:  # ld w [k] — ancillary, or a packet word
            if i.k >= 0x80000000:
                a = {0xFFFFF004: pkttype, 0xFFFFF008: ifindex}[i.k]
            else:
                a = struct.unpack_from("!I", pkt, i.k)[0]
        elif i.code == 0xB1:  # ldx 4*([k]&0xf)
            x = 4 * (pkt[i.k] & 0xF)
        elif i.code == 0x48:  # ld h [x+k]
            a = struct.unpack_from("!H", pkt, x + i.k)[0]
        elif i.code == 0x15:  # jeq #k
            pc += i.jt if a == i.k else i.jf
        elif i.code == 0x45:  # jset #k
            pc += i.jt if a & i.k else i.jf
        elif i.code == 0x06:  # ret #k
            return i.k
        else:  # pragma: no cover
            raise AssertionError(f"unexpected opcode {i.code:#x}")


# The address kea serves from in these tests, and its integer form.
KEA_ADDR = "10.0.0.2"
KEA = (0x0A000002,)


def _ipv4(
    proto: int = 17, dport: int = 67, frag: int = 0, ihl: int = 5, dst: str = KEA_ADDR
) -> bytes:
    opts = b"\0" * (4 * (ihl - 5))
    head = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl,
        0,
        0,
        1,
        frag,
        64,
        proto,
        0,
        b"\x0a\0\0\x01",
        socket.inet_aton(dst),
    )
    return head + opts + struct.pack("!HHHH", 68, dport, 8, 0)


def _accepts(prog, pkt=None, pkttype=HOST, ifindex=2) -> bool:
    return _run_bpf(prog, _ipv4() if pkt is None else pkt, pkttype, ifindex) != 0


def test_raw_mode_counts_unicast_and_broadcast_dhcp4():
    prog = build_filter("raw", (2,), None, KEA)
    assert _accepts(prog, pkttype=HOST)
    assert _accepts(prog, pkttype=BROADCAST)
    assert not _accepts(prog, pkttype=MULTICAST)
    assert not _accepts(prog, pkttype=OTHERHOST)  # promiscuous: not for us


def test_udp_mode_does_not_count_broadcasts():
    """Kea's UDP sockets are bound to interface addresses and never see a
    broadcast. Counting them would report every directly-attached client's
    DISCOVER as an eviction on a relay-mode server."""
    prog = build_filter("udp", (2,), None, KEA)
    assert _accepts(prog, pkttype=HOST)
    assert not _accepts(prog, pkttype=BROADCAST)


def test_only_dhcp4_server_port_first_fragment_udp():
    prog = build_filter("raw", (2,), None, KEA)
    assert not _accepts(prog, _ipv4(dport=68))  # client port
    assert not _accepts(prog, _ipv4(dport=547))  # DHCPv6
    assert not _accepts(prog, _ipv4(proto=6))  # TCP/67
    assert not _accepts(prog, _ipv4(frag=0x0005))  # later fragment
    assert _accepts(prog, _ipv4(frag=0x4000))  # DF set, first fragment
    assert _accepts(prog, _ipv4(ihl=6))  # IP options: the port is found past them


def test_only_kea_interfaces():
    prog = build_filter("raw", (2, 5), None, KEA)
    assert _accepts(prog, ifindex=2)
    assert _accepts(prog, ifindex=5)
    assert not _accepts(prog, ifindex=3)


def test_star_is_every_interface_but_loopback():
    prog = build_filter("raw", None, 1, KEA)
    assert _accepts(prog, ifindex=2)
    assert _accepts(prog, ifindex=77)
    assert not _accepts(prog, ifindex=1)


def test_no_existing_interface_counts_nothing():
    """Kea told to listen on interfaces that do not exist receives nothing,
    so nothing must be counted as having arrived for it."""
    prog = build_filter("raw", (), None, KEA)
    assert not _accepts(prog, ifindex=2)


def test_only_the_addresses_kea_serves_from():
    """Kea's own LPF filter admits 255.255.255.255 and the interface's address
    and nothing else. A packet for another address — a MetalLB relay VIP this
    node announces and forwards to another node's Kea, or traffic routed
    through the host — would otherwise count as an eviction on every bucket."""
    raw = build_filter("raw", (2,), None, KEA)
    assert _accepts(raw, _ipv4(dst=KEA_ADDR))
    assert _accepts(raw, _ipv4(dst="255.255.255.255"), pkttype=BROADCAST)
    assert not _accepts(raw, _ipv4(dst="192.0.2.50"))  # the VIP, or forwarded
    assert not _accepts(raw, _ipv4(dst="10.0.0.255"), pkttype=BROADCAST)  # directed
    udp = build_filter("udp", (2,), None, KEA)
    assert _accepts(udp, _ipv4(dst=KEA_ADDR))
    assert not _accepts(udp, _ipv4(dst="192.0.2.50"))
    assert not _accepts(udp, _ipv4(dst="255.255.255.255"), pkttype=BROADCAST)


def test_no_address_counts_only_broadcast_in_raw_mode():
    assert not _accepts(build_filter("raw", (2,), None, ()), _ipv4(dst=KEA_ADDR))
    assert not _accepts(build_filter("udp", (2,), None, ()), _ipv4(dst=KEA_ADDR))


def test_resolve_intake_uses_pinned_addresses_and_drops_missing_interfaces():
    lo = socket.if_nametoindex("lo")
    got = _resolve_intake(IntakeConfig("raw", ("lo", "nope0"), (("lo", "127.0.0.9"),)))
    assert got == Resolved((lo,), (0x7F000009,))
    # Unpinned: the interface's own primary address.
    assert _resolve_intake(IntakeConfig("raw", ("lo",))) == Resolved((lo,), (0x7F000001,))
    assert _resolve_intake(IntakeConfig("raw", ("nope0",))) == Resolved((), ())


def test_resolve_intake_star_skips_loopback():
    got = _resolve_intake(IntakeConfig("raw", ("*",)))
    assert got is not None
    assert socket.if_nametoindex("lo") not in got.ifindexes
    assert 0x7F000001 not in got.addresses


def test_real_kernel_counts_dhcp4_on_loopback():
    """The same program attached to a real AF_PACKET socket. Skips where the
    socket cannot be opened (no CAP_NET_RAW — CI runs unprivileged)."""
    lo = socket.if_nametoindex("lo")
    try:
        counter = _PacketCountingSocket(build_filter("raw", (lo,), None, (0x7F000001,)))
    except OSError as e:
        pytest.skip(f"AF_PACKET unavailable here: {e}")
    try:
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(5):
            tx.sendto(b"x" * 64, ("127.0.0.1", 67))
        for _ in range(3):
            tx.sendto(b"x" * 64, ("127.0.0.1", 68))
        # Far more than the minimum receive buffer holds: the kernel counts
        # what it drops, so the number is exact although nothing is read.
        for _ in range(1500):
            tx.sendto(b"x" * 64, ("127.0.0.1", 67))
        time.sleep(0.2)
        assert counter.read_and_clear() == 1505
        assert counter.read_and_clear() == 0  # read-and-clear
    finally:
        counter.close()


# ── kea_intake_config ──────────────────────────────────────────────────────


def _write(tmp_path, iface_cfg: dict | None) -> str:
    doc: dict = {"Dhcp4": {}}
    if iface_cfg is not None:
        doc["Dhcp4"]["interfaces-config"] = iface_cfg
    p = tmp_path / "kea.conf"
    p.write_text(json.dumps(doc))
    return str(p)


def test_intake_config_defaults_and_address_suffix(tmp_path):
    assert kea_intake_config(_write(tmp_path, None)) == IntakeConfig("raw", ("*",))
    got = kea_intake_config(
        _write(tmp_path, {"interfaces": ["eth0/192.0.2.1", "eth1"], "dhcp-socket-type": "udp"})
    )
    assert got == IntakeConfig("udp", ("eth0", "eth1"), (("eth0", "192.0.2.1"),))


def test_intake_config_unknown_is_none(tmp_path):
    assert kea_intake_config(tmp_path / "absent.conf") is None  # v6-only server
    assert kea_intake_config(_write(tmp_path, {"dhcp-socket-type": "bogus"})) is None
    (tmp_path / "bad.conf").write_text("{")
    assert kea_intake_config(tmp_path / "bad.conf") is None


# ── ArrivalCounter ─────────────────────────────────────────────────────────


class _ScriptedSocket:
    def __init__(self, values):
        self._values = list(values)
        self.closed = False

    def read_and_clear(self):
        v = self._values.pop(0)
        if isinstance(v, Exception):
            raise v
        return v

    def close(self):
        self.closed = True


def test_arrivals_first_sample_after_open_is_unmeasured():
    opened = []

    def opener(prog):
        s = _ScriptedSocket([40, 7])
        opened.append(s)
        return s

    c = ArrivalCounter(
        lambda: IntakeConfig("raw", ("eth0",)), opener, lambda cfg: Resolved((2,), KEA)
    )
    assert c.sample() is None  # the window began part-way through
    assert c.sample() == 40
    assert c.sample() == 7
    assert len(opened) == 1


def test_arrivals_reopen_when_interfaces_change():
    ifaces = {"v": Resolved((2,), KEA)}
    opened = []

    def opener(prog):
        s = _ScriptedSocket([10, 20])
        opened.append(s)
        return s

    c = ArrivalCounter(lambda: IntakeConfig("raw", ("eth0",)), opener, lambda cfg: ifaces["v"])
    assert c.sample() is None
    assert c.sample() == 10
    ifaces["v"] = Resolved((2, 3), KEA)
    assert c.sample() is None  # a different set of interfaces: a new window
    assert c.sample() == 10
    ifaces["v"] = Resolved((2, 3), (0x0A000003,))
    assert c.sample() is None  # a renumbered interface: a new window
    assert opened[0].closed
    assert c.sample() == 10


def test_arrivals_without_net_raw_are_unmeasured_not_zero():
    def opener(prog):
        raise PermissionError(1, "Operation not permitted")

    c = ArrivalCounter(lambda: IntakeConfig("raw", ("*",)), opener, lambda cfg: Resolved((2,), KEA))
    assert c.sample() is None
    assert c.sample() is None


def test_arrivals_unresolvable_interfaces_are_unmeasured():
    c = ArrivalCounter(
        lambda: IntakeConfig("raw", ("*",)), lambda prog: _ScriptedSocket([1]), lambda cfg: None
    )
    assert c.sample() is None
    assert c.sample() is None


def test_arrivals_without_kea4_config_are_unmeasured():
    c = ArrivalCounter(lambda: None, lambda prog: _ScriptedSocket([1]))
    assert c.sample() is None


def test_arrivals_read_failure_is_unmeasured_and_reopens():
    socks = [_ScriptedSocket([5, OSError("boom")]), _ScriptedSocket([9])]
    c = ArrivalCounter(
        lambda: IntakeConfig("raw", ("eth0",)),
        lambda prog: socks.pop(0),
        lambda cfg: Resolved((2,), KEA),
    )
    assert c.sample() is None
    assert c.sample() == 5
    assert c.sample() is None  # read failed
    assert c.sample() is None  # reopened
    assert c.sample() == 9


# ── QueueEvictionEstimator ─────────────────────────────────────────────────


def _feed(rows):
    est = QueueEvictionEstimator()
    return [est.update(*r) for r in rows]


def test_a_clean_server_reports_zero_every_bucket():
    assert _feed([(100, 0, 100)] * 4) == [0, 0, 0, 0]


def test_eviction_is_reported_once_one_bucket_later():
    # 1,000 arrive, 30 dropped by the kernel, 870 served: 100 evicted.
    out = _feed([(500, 0, 500), (1000, 30, 870), (200, 0, 200), (200, 0, 200)])
    assert out == [0, 0, 100, 0]
    assert sum(out) == 100


def test_a_backlog_in_flight_at_one_read_is_not_loss():
    """700 arrive and are still queued at the read; the worker serves them
    in the next bucket. Per-bucket arithmetic would report 700 lost — on a
    default-on alert with a floor of 1."""
    assert _feed([(100, 0, 100), (800, 0, 100), (100, 0, 800), (100, 0, 100)]) == [0, 0, 0, 0]


def test_a_dip_is_never_negative_and_never_counted_twice():
    """The worker served a packet before the arrivals were read: it lands in
    this bucket's ``received`` and next bucket's ``arrived``."""
    out = _feed([(100, 0, 100), (100, 0, 110), (110, 0, 100), (100, 0, 100)])
    assert out == [0, 0, 0, 0]
    assert all(v >= 0 for v in out)


def test_eviction_during_a_backlog_still_lands():
    out = _feed(
        [
            (100, 0, 100),
            (2000, 0, 600),  # 1,400 in flight or evicted — not yet known
            (100, 0, 1000),  # drained: 500 never came out of the queue
            (100, 0, 100),
        ]
    )
    assert sum(out) == 500
    assert out[1] == 0


def test_any_unmeasured_term_is_unmeasured_and_restarts_the_baseline():
    est = QueueEvictionEstimator()
    assert est.update(100, 0, 100) == 0
    assert est.update(None, 0, 100) is None  # arrivals socket reopened
    assert est.update(100, None, 100) is None  # socket_drop unreadable
    assert est.update(100, 0, None) is None  # Kea restarted: no received delta
    # A fresh baseline: nothing from before the gap is carried over.
    assert est.update(100, 0, 100) == 0
    assert est.update(100, 0, 40) == 0
    assert est.update(100, 0, 100) == 60


def test_a_baseline_taken_mid_backlog_does_not_hide_later_eviction():
    """Started with 800 queued: every later sum reads 800 low. Without the
    mark following that level down, the next 800 evictions would vanish."""
    out = _feed(
        [
            (0, 0, 800),  # the backlog that was queued before the baseline
            (100, 0, 100),
            (100, 0, 100),
            (300, 0, 100),  # 200 evicted
            (100, 0, 100),
        ]
    )
    assert out[-1] == 200
    assert sum(out) == 200


# ── read skew: arrivals bracketed around Kea's snapshot ─────────────────────


def _bracketed(true_x, lows, highs):
    """Per-bucket inputs for a server whose cumulative remainder at Kea's
    snapshot is ``true_x[k]``, read with ``lows[k]`` packets that arrived after
    the first arrivals read already counted received, and ``highs[k]``
    arriving between the snapshot and the second read."""
    rows = []
    prev_u = 0
    for x, lo, hi in zip(true_x, lows, highs, strict=True):
        lower = x - lo
        upper = x + hi
        received = 1000
        rows.append((lower - prev_u + received, 0, received, upper - lower))
        prev_u = upper
    return rows


def test_read_skew_is_never_loss_at_any_rate():
    """The defect the single-read estimator had: with arrivals read on ONE
    side of Kea's snapshot, the packets arriving in between are a bump or a
    dip at every read, and a low-low-high-high run re-reported the bump after
    the mark followed the lows down. Simulated at that time, a mean of 0.2
    packets of skew per read raised the default-on alert in 35 of 96
    15-minute windows a day. Bracketed, no amount of skew is loss."""
    import random

    rng = random.Random(2889)
    for lam in (1, 5, 50, 500):
        n = 1440
        lows = [rng.randint(0, lam) for _ in range(n)]
        highs = [rng.randint(0, lam) for _ in range(n)]
        out = _feed(_bracketed([0] * n, lows, highs))
        assert sum(out) == 0, lam


def test_the_old_false_alarm_pattern_is_quiet():
    """low, low, high, high, low, low, high, high — the shape that made the
    one-sided estimator report the same few packets again on every cycle."""
    lows = [0] * 12
    highs = [0, 0, 3, 3, 0, 0, 3, 3, 0, 0, 3, 3]
    assert sum(_feed(_bracketed([0] * 12, lows, highs))) == 0


def test_eviction_under_read_skew_is_counted_once():
    import random

    rng = random.Random(7)
    n = 60
    true_x = [0] * 20 + [250] * 40  # 250 evicted at bucket 20
    lows = [rng.randint(0, 20) for _ in range(n)]
    highs = [rng.randint(0, 20) for _ in range(n)]
    out = _feed(_bracketed(true_x, lows, highs))
    assert 210 <= sum(out) <= 250  # skew can only make it lower
    assert sum(out[:21]) == 0


def test_uncounted_arrivals_only_lower_the_estimate():
    """Kea reads 30 a minute the filter never sees (a path it does not
    count): the remainder falls forever. That must never read as loss."""
    out = _feed([(970, 0, 1000)] * 30)
    assert sum(out) == 0
    # ... and a real eviction during it is still not overstated.
    out = _feed([(970, 0, 1000)] * 10 + [(1500, 0, 1000)] + [(970, 0, 1000)] * 10)
    assert 0 <= sum(out) <= 500


def test_unmeasured_during_read_is_unmeasured():
    est = QueueEvictionEstimator()
    assert est.update(100, 0, 100, 3) == 0
    assert est.update(100, 0, 100, None) is None


# ── the aging wait (#2889, QA walk case 3) ─────────────────────────────────


def test_packet_queue_size_from_the_rendered_config(tmp_path):
    from spatium_dhcp_agent.intake import kea_packet_queue_size

    def cfg(mt):
        p = tmp_path / "k.conf"
        p.write_text(json.dumps({"Dhcp4": {} if mt is None else {"multi-threading": mt}}))
        return p

    assert kea_packet_queue_size(cfg({"packet-queue-size": 1024})) == 1024
    assert kea_packet_queue_size(cfg({})) == 64  # Kea's default
    assert kea_packet_queue_size(cfg(None)) == 64
    assert kea_packet_queue_size(cfg({"enable-multi-threading": False})) == 0
    assert kea_packet_queue_size(tmp_path / "absent.conf") is None


def test_arrival_age_covers_a_queue_below_its_depth():
    from spatium_dhcp_agent.intake import (
        MAX_ARRIVAL_AGE,
        MIN_ARRIVAL_AGE,
        SERVICE_RATE_FLOOR,
        arrival_age_seconds,
    )

    # A full rendered queue drains within this at the floor rate.
    assert arrival_age_seconds(1024) * SERVICE_RATE_FLOOR >= 1024
    assert arrival_age_seconds(0) == MIN_ARRIVAL_AGE  # no queue: socket only
    assert arrival_age_seconds(None) == arrival_age_seconds(64)
    assert arrival_age_seconds(10**6) == MAX_ARRIVAL_AGE
