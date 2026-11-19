"""Per-socket kernel drop counters (#980).

The parser reads field indices out of ``/proc/net/udp``. A fixture cannot
prove those indices are right — it can only prove they match the fixture —
so the load-bearing test here binds a **real socket**, overruns its receive
buffer, and checks that the number the parser returns is the number the
kernel just counted. The fixture tests cover the shapes a real kernel will
not produce on demand (a socket vanishing, an inode reused, procfs absent).
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time

import pytest

from spatium_dhcp_agent.socket_drops import (
    DHCP_PORTS,
    PacketSocket,
    SocketDropCounter,
    _packet_diag_request,
    _parse_packet_diag,
    _parse_proc_udp,
    dump_packet_sockets,
    kea_socket_type,
    read_packet_drops,
    read_socket_drops,
)

# One header line plus rows, exactly as the kernel formats them.
_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode ref pointer drops"
)


def _row(port_hex: str, inode: str, drops: int) -> str:
    return (
        f"  181: 00000000:{port_hex} 00000000:0000 07 00000000:00000000 "
        f"00:00000000 00000000     0        0 {inode} 2 0000000000000000 {drops}"
    )


def _proc(*rows: str) -> str:
    return "\n".join([_HEADER, *rows]) + "\n"


# ── the real-kernel test ────────────────────────────────────────────────────


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not os.path.exists("/proc/net/udp"),
    reason="/proc/net/udp is Linux-only",
)
def test_parser_reads_the_real_sk_drops_column():
    """Bind a socket, make the kernel drop into it, read the count back.

    This is the only test that can catch a wrong field index, and the only
    one that would notice a future kernel changing the row layout.

    Deliberately an ephemeral port rather than 67: binding a privileged port
    would need root, and the point of the check is the column offsets, which
    do not depend on which port the socket is on.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        inode = str(os.stat(f"/proc/self/fd/{sock.fileno()}").st_ino)
        ports = frozenset({port})

        before = read_socket_drops(ports=ports)
        assert before is not None
        assert inode in before, (
            "parser did not find a socket that is definitely bound — the "
            "local_address or inode field index is wrong"
        )
        assert before[inode] == 0

        # Smallest buffer the kernel will take, then overrun it. Nothing
        # reads from the socket, so the queue fills and every later datagram
        # is dropped with sk_drops incremented.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        for _ in range(200):
            try:
                sender.sendto(b"x" * 1400, ("127.0.0.1", port))
            except OSError:  # ENOBUFS on the send side; not what we measure
                pass

        after = read_socket_drops(ports=ports)
        assert after is not None
        assert after[inode] > 0, (
            "the kernel dropped datagrams but the parser reported none — the "
            "drops field index is wrong"
        )
    finally:
        sock.close()
        sender.close()


# ── parsing ─────────────────────────────────────────────────────────────────


def test_only_dhcp_ports_are_counted():
    text = _proc(
        _row("0043", "111", 7),  # 67  — DHCPv4 server
        _row("0223", "222", 3),  # 547 — DHCPv6 server
        _row("0044", "333", 99),  # 68  — a client port, not ours
        _row("0035", "444", 99),  # 53  — DNS on a host-networked node
    )
    assert _parse_proc_udp(text) == {"111": 7, "222": 3}


def test_malformed_rows_are_skipped_not_fatal():
    """procfs is a kernel interface, but the agent must not die on a short
    read or a row it does not understand — the counter is diagnostics, and
    taking the metrics poller down with it would cost more than it reports."""
    text = _proc(
        "  1: garbage",
        _row("0043", "111", 5),
        "  2: 00000000:ZZZZ 00000000:0000 07 x x x x x x x x x",
    )
    assert _parse_proc_udp(text) == {"111": 5}


def test_missing_procfs_reports_unknown_not_zero():
    """The distinction the whole feature rests on: None means nobody looked."""
    assert read_socket_drops(paths=("/nonexistent/net/udp",)) is None


def test_present_but_no_dhcp_socket_is_zero_not_unknown():
    """An empty answer from a readable procfs is a real measurement: Kea is
    starting, or bound raw-only. Reporting it as unknown would hide a working
    agent behind the same label as a broken one."""
    assert read_socket_drops(paths=("/proc/net/udp",), ports=frozenset({1})) == {}


def test_dhcp_ports_are_the_server_ports():
    assert DHCP_PORTS == frozenset({67, 547})


# ── delta accumulation ──────────────────────────────────────────────────────
#
# These drive the REAL ``SocketDropCounter.sample()`` by pointing it at
# fixture files on disk. An earlier version of this file subclassed it and
# reimplemented ``sample()``, which meant the five tests below asserted on a
# copy of the logic and would have passed with the production method
# arbitrarily broken.


def _write_proc(tmp_path, name, rows):
    """Write a /proc/net/udp-shaped file and return its path."""
    path = tmp_path / name
    path.write_text(_proc(*rows))
    return str(path)


def _counter_over(tmp_path, snapshots):
    """A real SocketDropCounter reading a file this helper rewrites per tick.

    ``read_socket_drops`` opens the path on every call, so rewriting the file
    between ``sample()`` calls is exactly what a changing kernel table looks
    like to it.
    """
    path = tmp_path / "udp"
    # ``udp`` socket mode, where the UDP sockets are the whole count: these
    # tests are about them. Raw mode has its own tests below (#1283).
    counter = SocketDropCounter(packet_drops=dict, socket_type=lambda: "udp")

    def tick(rows):
        # rows=None models procfs becoming unreadable: point the counter at a
        # path that does not exist.
        if rows is None:
            return counter.sample_from(("/nonexistent/net/udp",))
        path.write_text(_proc(*rows))
        return counter.sample_from((str(path),))

    return [tick(r) for r in snapshots]


def test_first_sample_has_no_baseline(tmp_path):
    (out,) = _counter_over(tmp_path, [[_row("0043", "1", 40)]])
    assert out is None


def test_delta_is_per_socket(tmp_path):
    out = _counter_over(
        tmp_path, [[_row("0043", "1", 40)], [_row("0043", "1", 47)]]
    )
    assert out == [None, 7]


def test_a_socket_disappearing_does_not_read_as_negative(tmp_path):
    """Kea closes and reopens its sockets on reconfiguration. Summing the
    totals would show the fleet-wide count falling, which looks exactly like
    a counter reset; summing per inode gives the right answer of 0."""
    out = _counter_over(
        tmp_path,
        [
            [_row("0043", "1", 500), _row("0223", "2", 500)],
            [_row("0223", "2", 500)],
        ],
    )
    assert out == [None, 0]


def test_a_new_socket_contributes_from_zero(tmp_path):
    out = _counter_over(
        tmp_path,
        [
            [_row("0043", "1", 500)],
            [_row("0043", "1", 500), _row("0223", "2", 12)],
        ],
    )
    assert out == [None, 12]


def test_unreadable_procfs_clears_the_baseline(tmp_path):
    """If a sample cannot be taken, the next one must not diff against a
    stale baseline and report a bucket's worth of drops as one spike."""
    out = _counter_over(
        tmp_path, [[_row("0043", "1", 10)], None, [_row("0043", "1", 900)]]
    )
    assert out == [None, None, None]


def test_a_partial_read_is_not_a_sample(tmp_path):
    """One of the two procfs files unreadable must fail the WHOLE sample.

    Returning the half that read as a valid snapshot drops the missing
    inodes out of the baseline; when the next read succeeds they come back
    as brand-new sockets and their entire lifetime ``sk_drops`` is charged
    to that one bucket — a fabricated spike, on a rule whose floor is one
    packet.
    """
    v4 = _write_proc(tmp_path, "udp", [_row("0043", "1", 5)])
    v6 = _write_proc(tmp_path, "udp6", [_row("0223", "2", 5000)])

    both = read_socket_drops(paths=(v4, v6))
    assert both == {"1": 5, "2": 5000}

    # v6 present but unreadable (a directory stands in for EISDIR — any
    # OSError that is not FileNotFoundError takes the same branch).
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    assert read_socket_drops(paths=(v4, str(unreadable))) is None

    # A genuinely absent file is different and stays a valid partial answer:
    # no IPv6 stack means no v6 sockets to miss.
    assert read_socket_drops(paths=(v4, str(tmp_path / "gone"))) == {"1": 5}


# ── kea's raw AF_PACKET sockets (#1283) ─────────────────────────────────────
#
# In ``dhcp-socket-type: raw``, kea-dhcp4 serves relayed unicast from an
# AF_PACKET socket and drains and discards the UDP copy, so the drops that
# cost a client a retransmit are on the raw socket. Measured on relayed
# bursts (AF_PACKET against UDP :67):
#   - +261 against +126;
#   - 41 against 0;
#   - +505 against +300, where the 505 were exactly the requests kea never
#     received.
# In all three, ``socket_drop`` reported only the UDP number.


def _nlmsg(mtype: int, body: bytes) -> bytes:
    length = 16 + len(body)
    return struct.pack("=IHHII", length, mtype, 2, 1, 0) + body + b"\0" * (-length % 4)


def _attr(atype: int, payload: bytes) -> bytes:
    alen = 4 + len(payload)
    return struct.pack("=HH", alen, atype) + payload + b"\0" * (-alen % 4)


def _diag(inode, sock_type=3, proto=0x0003, uid=100, drops=0, meminfo=True):
    """One packet_diag reply as the kernel lays it out: the message, then
    PACKET_DIAG_INFO (0), PACKET_DIAG_UID (5) and PACKET_DIAG_MEMINFO (6)."""
    msg = struct.pack("=BBHI2I", 17, sock_type, proto, inode, 0, 0)
    attrs = _attr(0, struct.pack("=6I", 2, 0, 0, 0, 0, 0)) + _attr(5, struct.pack("=I", uid))
    if meminfo:
        attrs += _attr(6, struct.pack("=9I", 0, 212992, 0, 212992, 0, 0, 888, 0, drops))
    return _nlmsg(20, msg + attrs)


_DONE = _nlmsg(3, struct.pack("=i", 0))


def test_the_dump_request_asks_for_info_and_meminfo():
    length, mtype, flags, _seq, _pid = struct.unpack_from("=IHHII", _packet_diag_request())
    family, _proto, _pad, _ino, show = struct.unpack_from("=BBHII", _packet_diag_request(), 16)
    assert (length, mtype, flags) == (36, 20, 0x301)
    assert (family, show) == (17, 0x11)


def test_the_parser_reads_type_protocol_uid_and_drops():
    rows, finished = _parse_packet_diag(_diag(386970, drops=302) + _diag(386972) + _DONE)
    assert finished is True
    assert rows == [
        PacketSocket(386970, 3, 0x0003, 100, 302),
        PacketSocket(386972, 3, 0x0003, 100, 0),
    ]


def test_a_dump_split_across_reads_is_not_finished_early():
    rows, finished = _parse_packet_diag(_diag(1, drops=5))
    assert (rows, finished) == ([PacketSocket(1, 3, 3, 100, 5)], False)


def test_a_refused_dump_raises_with_the_kernels_errno():
    with pytest.raises(OSError) as e:
        _parse_packet_diag(_nlmsg(2, struct.pack("=i", -2) + b"\0" * 16))
    assert e.value.errno == 2


def _sockets(*rows):
    return lambda: list(rows)


def test_only_keas_raw_sockets_are_counted():
    """kea's are the raw ETH_P_ALL sockets owned by this user that this
    process does not hold itself. The agent's own sniffers (inode 2 here)
    are threads of the agent; root's socket and any other shape are not
    kea's."""
    out = read_packet_drops(
        dump=_sockets(
            PacketSocket(1, 3, 0x0003, 100, 302),  # kea, enp1s0
            PacketSocket(2, 3, 0x0003, 100, 50),  # the agent's own sniffer
            PacketSocket(3, 3, 0x0003, 0, 9),  # someone else's, as root
            PacketSocket(4, 2, 0x0003, 100, 7),  # SOCK_DGRAM
            PacketSocket(5, 3, 0x0800, 100, 6),  # ETH_P_IP only
        ),
        own_inodes=lambda: {2},
        uid=100,
    )
    assert out == {"packet:1": 302}


def test_no_raw_socket_is_zero_not_unknown():
    """Kea holding no raw socket (starting, or a raw open that failed) is a
    real, empty answer."""
    assert read_packet_drops(dump=_sockets(), own_inodes=set, uid=100) == {}


def _refused():
    raise OSError(2, "No such file or directory")


def _proc_packet(tmp_path, *rows):
    path = tmp_path / "packet"
    head = "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"
    path.write_text(head + "".join(f"{r}\n" for r in rows))
    return str(path)


def test_unreadable_drops_with_a_kea_socket_open_are_unknown(tmp_path):
    """Without sock_diag the raw socket's drops cannot be read. If kea holds
    one, the sample is unknown: the UDP half alone would measure a copy."""
    listed = _proc_packet(tmp_path, "ffff8b2d00000000 3      3    0003   2     1 0      100    1")
    assert read_packet_drops(dump=_refused, own_inodes=set, proc_packet=listed, uid=100) is None


def test_unreadable_drops_with_nothing_to_miss_keep_the_udp_answer(tmp_path):
    """No raw socket of kea's open: nothing is missed, so a kernel without
    packet_diag must not turn a valid sample into unknown."""
    listed = _proc_packet(tmp_path, "ffff8b2d00000000 3      3    0003   2     1 0      0      3")
    assert read_packet_drops(dump=_refused, own_inodes=set, proc_packet=listed, uid=100) == {}


def test_a_socket_without_meminfo_is_unknown():
    out = read_packet_drops(
        dump=_sockets(PacketSocket(1, 3, 0x0003, 100, None)), own_inodes=set, uid=100
    )
    assert out is None


def _counter_with_packets(tmp_path, ticks):
    """A real SocketDropCounter over a UDP fixture, a scripted AF_PACKET read
    and a scripted socket mode. ``ticks`` is
    ``[(udp_rows, packet_answer, mode), ...]``. Returns each sample and
    whether that sample asked for the AF_PACKET read."""
    path = tmp_path / "udp"
    now: dict = {}

    def packet():
        now["asked"] = True
        return now["packet"]

    counter = SocketDropCounter(packet_drops=packet, socket_type=lambda: now["mode"])
    out, asked = [], []
    for rows, answer, mode in ticks:
        now.update(packet=answer, mode=mode, asked=False)
        path.write_text(_proc(*rows))
        out.append(counter.sample_from((str(path),)))
        asked.append(now["asked"])
    return out, asked


def test_raw_mode_counts_keas_packet_socket_not_its_udp_fallback(tmp_path):
    """The R64 run's shape. In raw mode the :67 socket is LPF's fallback. Its
    drops (+7 here) are copies kea would have thrown away, and the loss is on
    the AF_PACKET socket beside it (41 -> 302). DHCPv6's :547 socket is
    kea-dhcp6's own, and still counts (+3)."""
    out, _asked = _counter_with_packets(
        tmp_path,
        [
            ([_row("0043", "1", 40), _row("0223", "2", 2)], {"packet:9": 41}, "raw"),
            ([_row("0043", "1", 47), _row("0223", "2", 5)], {"packet:9": 302}, "raw"),
        ],
    )
    assert out == [None, 261 + 3]


def test_udp_mode_counts_the_udp_sockets_and_never_asks_sock_diag(tmp_path):
    """In ``udp`` mode (``dhcp_socket_mode: relay``) kea serves from its UDP
    sockets, so they are the whole count, as before #1283. The raw read is
    not made at all, so a kernel without packet_diag costs nothing here."""
    out, asked = _counter_with_packets(
        tmp_path,
        [
            ([_row("0043", "1", 40), _row("0223", "2", 2)], None, "udp"),
            ([_row("0043", "1", 47), _row("0223", "2", 5)], None, "udp"),
        ],
    )
    assert out == [None, 7 + 3]
    assert asked == [False, False]


def test_an_unknown_mode_counts_every_socket(tmp_path):
    """With no readable config, count both kinds rather than guess. No loss
    is left out, though copies may be counted with it."""
    out, _asked = _counter_with_packets(
        tmp_path,
        [
            ([_row("0043", "1", 40), _row("0223", "2", 2)], {"packet:9": 41}, None),
            ([_row("0043", "1", 47), _row("0223", "2", 5)], {"packet:9": 302}, None),
        ],
    )
    assert out == [None, 7 + 3 + 261]


def test_raw_mode_fallbacks_with_no_raw_socket_found_are_unknown_not_zero(tmp_path):
    """Kea opens its AF_PACKET socket beside every :67 fallback, and closes
    the fallback if the raw open fails. So fallbacks with no raw socket of
    kea's found mean kea's sockets could not be told apart, for example if
    kea and the agent ever ran as different users. That sample is unknown:
    reading DHCPv4 as 0 would be the false all-clear #980 exists to prevent."""
    out, _asked = _counter_with_packets(
        tmp_path,
        [
            ([_row("0043", "1", 40), _row("0223", "2", 2)], {}, "raw"),
            ([_row("0043", "1", 47), _row("0223", "2", 5)], {}, "raw"),
        ],
    )
    assert out == [None, None]


def test_raw_mode_with_no_dhcp4_socket_at_all_is_a_real_zero(tmp_path):
    """Kea starting, or not serving DHCPv4: no fallback and no raw socket. That
    is a real answer, and the DHCPv6 sockets still count."""
    out, _asked = _counter_with_packets(
        tmp_path,
        [
            ([_row("0223", "2", 2)], {}, "raw"),
            ([_row("0223", "2", 5)], {}, "raw"),
        ],
    )
    assert out == [None, 3]


def test_a_socket_mode_change_restarts_the_baseline(tmp_path):
    """Switching mode changes which sockets are summed. Diffing against the
    old baseline would charge the :67 socket's whole-lifetime count (450) to
    one bucket. So the sample at the change is unknown, and the next one
    counts from it."""
    out, _asked = _counter_with_packets(
        tmp_path,
        [
            ([_row("0043", "1", 400)], {"packet:9": 10}, "raw"),
            ([_row("0043", "1", 450)], {"packet:9": 15}, "raw"),
            ([_row("0043", "1", 450)], None, "udp"),
            ([_row("0043", "1", 452)], None, "udp"),
        ],
    )
    assert out == [None, 5, None, 2]


def test_kea_reopening_its_raw_socket_contributes_from_zero(tmp_path):
    """kea reopens its sockets on reconfiguration: a new inode counts from 0."""
    out, _asked = _counter_with_packets(
        tmp_path,
        [
            ([_row("0043", "1", 0)], {"packet:9": 500}, "raw"),
            ([_row("0043", "1", 0)], {"packet:10": 12}, "raw"),
        ],
    )
    assert out == [None, 12]


def test_an_unreadable_raw_half_fails_the_whole_sample(tmp_path):
    """As for the two procfs files: a partial read is no read, and the next
    sample must not diff against a stale baseline."""
    out, _asked = _counter_with_packets(
        tmp_path,
        [
            ([_row("0223", "1", 10)], {"packet:9": 10}, "raw"),
            ([_row("0223", "1", 20)], None, "raw"),
            ([_row("0223", "1", 900)], {"packet:9": 900}, "raw"),
        ],
    )
    assert out == [None, None, None]


def test_the_socket_mode_comes_from_the_rendered_config(tmp_path):
    conf = tmp_path / "kea-dhcp4.conf"

    def mode(doc):
        conf.write_text(doc if isinstance(doc, str) else json.dumps(doc))
        return kea_socket_type(conf)

    assert mode({"Dhcp4": {"interfaces-config": {"dhcp-socket-type": "raw"}}}) == "raw"
    assert mode({"Dhcp4": {"interfaces-config": {"dhcp-socket-type": "udp"}}}) == "udp"
    # kea's own default for DHCPv4; its config-get leaves the key out for it
    assert mode({"Dhcp4": {"interfaces-config": {"interfaces": ["*"], "re-detect": True}}}) == "raw"
    assert mode({"Dhcp4": {}}) == "raw"
    # unknown, never a guess
    assert mode('{ "Dhcp4": { // a comment kea accepts and JSON does not') is None
    assert mode({"Dhcp6": {}}) is None
    assert mode({"Dhcp4": {"interfaces-config": {"dhcp-socket-type": "bpf"}}}) is None
    assert kea_socket_type(tmp_path / "absent.conf") is None


def _raw_socket_or_skip():
    if not sys.platform.startswith("linux"):
        pytest.skip("AF_PACKET and sock_diag are Linux-only")
    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        pytest.skip("opening an AF_PACKET socket needs CAP_NET_RAW")
    return raw


def test_sock_diag_reads_a_real_raw_sockets_drops():
    """The load-bearing one, as for /proc/net/udp above: open a raw ETH_P_ALL
    socket on lo with the smallest receive buffer, overrun it, and check that
    the number sock_diag returns is the number the kernel counted on the
    socket itself (``PACKET_STATISTICS``, which only the owner can read).
    Only this can catch a wrong offset in the netlink structs."""
    raw = _raw_socket_or_skip()
    with raw:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
        raw.bind(("lo", 0))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
            for _ in range(200):
                tx.sendto(b"x" * 512, ("127.0.0.1", 9))
        time.sleep(0.2)
        inode = os.fstat(raw.fileno()).st_ino
        mine = [s for s in dump_packet_sockets() if s.inode == inode]
        # PACKET_STATISTICS (SOL_PACKET 263, option 6): tp_packets, tp_drops.
        _packets, tp_drops = struct.unpack("=II", raw.getsockopt(263, 6, 8))
    assert len(mine) == 1
    sock = mine[0]
    assert (sock.sock_type, sock.protocol, sock.uid) == (3, 0x0003, os.geteuid())
    assert sock.drops > 0
    assert sock.drops == tp_drops


def test_last_v4_is_the_dhcp4_share_of_the_total(tmp_path):
    """#2889 — ``queue_evicted`` subtracts kernel drops from DHCPv4 arrivals,
    so it needs the port-67 share without the port-547 one."""
    path = tmp_path / "udp"

    def rows(d67: int, d547: int) -> str:
        head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
        r67 = f"   1: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000   0        0 111 2 0000000000000000 {d67}\n"
        r547 = f"   2: 00000000:0223 00000000:0000 07 00000000:00000000 00:00000000 00000000   0        0 222 2 0000000000000000 {d547}\n"
        return head + r67 + r547

    c = SocketDropCounter(socket_type=lambda: "udp")
    path.write_text(rows(10, 100))
    assert c.sample_from((str(path),)) is None
    assert c.last_v4 is None
    path.write_text(rows(14, 107))
    assert c.sample_from((str(path),)) == 11
    assert c.last_v4 == 4
    # Raw mode: the AF_PACKET sockets are the DHCPv4 share, the :67 UDP
    # fallbacks are not counted at all.
    packets = iter([{"packet:9": 50}, {"packet:9": 58}])
    r = SocketDropCounter(packet_drops=lambda: next(packets), socket_type=lambda: "raw")
    path.write_text(rows(0, 0))
    r.sample_from((str(path),))
    path.write_text(rows(500, 2))
    assert r.sample_from((str(path),)) == 10
    assert r.last_v4 == 8
