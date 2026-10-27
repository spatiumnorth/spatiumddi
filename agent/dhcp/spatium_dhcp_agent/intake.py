"""DHCPv4 arrivals at Kea's intake, and the requests its queue evicted (#2889).

kea-dhcp4 3.0 with multi-threading reads packets off its socket into a
bounded queue (``packet-queue-size``, 1,024 as rendered) and a worker takes
them from there. When a burst outruns the worker the queue fills, and Kea
discards the OLDEST queued packet to make room — logged at DEBUG only
(``DHCP4_PACKET_QUEUE_FULL``), with no statistic. So none of the counters
#980 added move for it:

* ``socket_drop`` is the kernel dropping a datagram before Kea reads it.
  An evicted packet was read.
* ``receive_drop`` is ``pkt4-receive-drop``, which the WORKER increments.
  An evicted packet never reaches the worker.
* ``pkt4-received`` is also counted by the worker, after the queue.

What is left is arithmetic. Every DHCPv4 datagram that reaches Kea's intake
is either dropped by the kernel, processed by the worker, evicted, or still
in flight. So ``arrived - socket_drop - pkt4-received`` is the eviction,
plus whatever is still queued at the moment the counters are read. Measured
on a three-node cluster under the gate load (issue #2889), that identity
held to the packet over five runs.

**Counting the arrivals.** :class:`ArrivalCounter` holds an AF_PACKET socket
of its own with a classic-BPF filter matching what Kea's sockets admit, and
reads ``PACKET_STATISTICS`` from it. The kernel counts every packet the
filter accepts — queued or dropped, ``tp_packets`` includes ``tp_drops`` —
and the socket is never read, so its tiny receive buffer stays full and a
match costs a counter increment, not a copy. The socket is bound to no
interface, so the filter itself runs on EVERY inbound IPv4 packet on the host
(about 20 instructions each), not only on DHCP. It taps the receive path
ahead of netfilter, as Kea's own raw socket does — though one step later:
after VLAN untagging and bridge handling, where Kea's sees the frame on the
device first (see the 802.1p note in ``docs/features/DHCP.md``). It needs ``CAP_NET_RAW``, which this agent
already holds for the fingerprint sniffer and the rogue-DHCP probe (#370,
#383). Nothing new is granted.

That is why this is not the nftables counter the issue suggested. Reading an
nftables counter needs ``CAP_NET_ADMIN`` (nfnetlink refuses every message
without it, reads included), which neither this agent nor the supervisor pod
holds, so it would take a root host runner writing the value to a file on a
timer, skewed by however long that timer's period is against Kea's own
counters. A counter on the existing ``udp dport 67 accept`` rule would also
miss most of the traffic: ``ct state established,related accept`` sits ahead
of it, and every relay packet after the first in a flow is ESTABLISHED. And
the base ruleset is re-created whole on every firewall apply, resetting the
counter. Counting in the agent avoids all of that, reads either side of Kea's
own snapshot within one command round trip, and works on every deployment where the agent has
``CAP_NET_RAW`` and sees the host's interfaces — not only on the appliance.

**What is counted** (see :func:`build_filter`): IPv4 UDP to port 67, first
fragment only, arriving (not sent) on an interface Kea serves, addressed to
an address Kea serves from, and

* ``raw`` mode (the default, #365): unicast to one of those addresses, or to
  255.255.255.255 — the two destinations Kea's own LPF filter admits (it
  patches the interface address into its program, and drops anything else);
* ``udp`` mode: unicast to one of those addresses only. Kea's UDP sockets
  are bound to interface addresses and never see a broadcast.

The destination check matters on any host that receives udp/67 for an
address Kea is not serving: with a MetalLB relay VIP (#272) and
``externalTrafficPolicy: Cluster`` the announcing node receives every relayed
request addressed to the VIP and forwards most of them to another node's
Kea, so counting by MAC alone (``PACKET_HOST``) would report all of them as
evicted on the node that only forwarded them.

Unknown mode, no kea-dhcp4 config at all, or interfaces that cannot be
resolved, is unmeasured (``None``).

**Arithmetic** (see :class:`QueueEvictionEstimator`). Kea's counters are one
snapshot taken inside Kea at some instant ``t_s``; the arrivals cannot be read
at that same instant. So they are read on BOTH sides of it — once before the
``statistic-get-all`` command is sent, once after the reply (and the socket
drops) are in — which brackets the true remainder at ``t_s`` between a lower
and an upper bound. Read-ordering skew can then never be mistaken for an
eviction, at any packet rate: evictions are confirmed only from the lower
bound, the baseline is only ever lowered from the upper one.
"""

from __future__ import annotations

import ctypes
import fcntl
import json
import os
import socket
import struct
from collections.abc import Callable
from typing import NamedTuple, Protocol

import structlog

log = structlog.get_logger(__name__)

DHCP4_SERVER_PORT = 67

# <linux/if_ether.h>, <linux/if_packet.h>, <asm-generic/socket.h>
_ETH_P_IP = 0x0800
_SOL_PACKET = 263
_PACKET_STATISTICS = 6
_SO_ATTACH_FILTER = 26
_PACKET_HOST = 0
_PACKET_BROADCAST = 1

# <linux/filter.h> classic BPF opcodes.
_LD_W_ABS = 0x20
_LD_H_ABS = 0x28
_LD_B_ABS = 0x30
_LD_H_IND = 0x48
_LDX_B_MSH = 0xB1
_JEQ_K = 0x15
_JSET_K = 0x45
_RET_K = 0x06
# Ancillary loads: SKF_AD_OFF (-0x1000) + field, as an unsigned u32.
_SKF_AD_PKTTYPE = (-0x1000 + 4) & 0xFFFFFFFF
_SKF_AD_IFINDEX = (-0x1000 + 8) & 0xFFFFFFFF

# One jump offset is a u8, so neither the interface nor the address chain can
# be longer than this. More than that (a host with hundreds of addressed
# interfaces) is reported unmeasured rather than approximated.
MAX_FILTER_IFACES = 200
_IPV4_BROADCAST = 0xFFFFFFFF
_SIOCGIFADDR = 0x8915

_STATS = struct.Struct("=II")  # struct tpacket_stats: tp_packets, tp_drops


class Insn(NamedTuple):
    """One ``struct sock_filter``."""

    code: int
    jt: int
    jf: int
    k: int


class IntakeConfig(NamedTuple):
    """What kea-dhcp4 reads from, as rendered by this agent."""

    mode: str  # "raw" | "udp"
    interfaces: tuple[str, ...]  # names; ("*",) = every interface
    # ``(iface, address)`` for the entries written as kea's ``iface/address``
    # form: kea serves from exactly that address on that interface.
    pinned: tuple[tuple[str, str], ...] = ()


def kea_intake_config(path: str | os.PathLike[str]) -> IntakeConfig | None:
    """Socket mode + interfaces of the kea-dhcp4 config at ``path``.

    ``None`` means unknown: no file (a v6-only server has no kea-dhcp4
    config), unparseable, or a mode kea does not have. Interface entries
    may be ``"<iface>/<address>"`` (kea's per-address form): the name goes in
    ``interfaces``, the pair in ``pinned``. An absent list is ``*``, kea's
    default.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        iface = doc["Dhcp4"].get("interfaces-config") or {}
        mode = iface.get("dhcp-socket-type", "raw")
        raw_names = iface.get("interfaces") or ["*"]
        entries = [str(n).split("/", 1) for n in raw_names]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    if mode not in ("raw", "udp"):
        return None
    names = tuple(e[0] for e in entries)
    pinned = tuple((e[0], e[1]) for e in entries if len(e) == 2)
    return IntakeConfig(mode, names, pinned)


def build_filter(
    mode: str,
    ifindexes: tuple[int, ...] | None,
    loopback: int | None,
    addresses: tuple[int, ...],
) -> list[Insn]:
    """The classic-BPF program counting DHCPv4 server-bound arrivals.

    Runs on an ``AF_PACKET``/``SOCK_DGRAM`` socket, so offset 0 is the IPv4
    header. ``ifindexes=None`` means every interface except ``loopback``;
    a tuple means exactly those interfaces (possibly none: kea was told to
    listen on interfaces that do not exist, so nothing can reach it).
    ``addresses`` are the IPv4 destinations kea serves from, as integers; a
    packet to any other address is not counted (see the module docstring).
    """
    prog: list[tuple[int, object, object, int]] = []  # jt/jf: int or label

    def emit(code: int, k: int = 0, jt: object = 0, jf: object = 0) -> None:
        prog.append((code, jt, jf, k))

    emit(_LD_B_ABS, 9)  # ip protocol
    emit(_JEQ_K, 17, 0, "reject")  # UDP
    emit(_LD_H_ABS, 6)  # flags + fragment offset
    emit(_JSET_K, 0x1FFF, "reject", 0)  # a later fragment carries no UDP header
    emit(_LDX_B_MSH, 0)  # X = IP header length
    emit(_LD_H_IND, 2)  # UDP destination port
    emit(_JEQ_K, DHCP4_SERVER_PORT, 0, "reject")
    emit(_LD_W_ABS, _SKF_AD_PKTTYPE)
    if mode == "raw":
        emit(_JEQ_K, _PACKET_HOST, "dst", 0)
        emit(_JEQ_K, _PACKET_BROADCAST, "dst", "reject")
    else:
        emit(_JEQ_K, _PACKET_HOST, "dst", "reject")
    labels = {"dst": len(prog)}
    emit(_LD_W_ABS, 16)  # IPv4 destination address
    if mode == "raw":
        emit(_JEQ_K, _IPV4_BROADCAST, "iface", 0)
    for addr in addresses:
        emit(_JEQ_K, addr, "iface", 0)
    emit(_RET_K, 0)
    labels["iface"] = len(prog)
    emit(_LD_W_ABS, _SKF_AD_IFINDEX)
    if ifindexes is None:
        if loopback is None:
            emit(_RET_K, 1)
        else:
            emit(_JEQ_K, loopback, "reject", "accept")
    else:
        for idx in ifindexes:
            emit(_JEQ_K, idx, "accept", 0)
        emit(_RET_K, 0)
    labels["accept"] = len(prog)
    emit(_RET_K, 1)  # accept; a 1-byte snap, never read anyway
    labels["reject"] = len(prog)
    emit(_RET_K, 0)

    out: list[Insn] = []
    for pc, (code, jt, jf, k) in enumerate(prog):

        def resolve(target: object, pc: int = pc) -> int:
            if isinstance(target, int):
                return target
            off = labels[str(target)] - pc - 1
            if not 0 <= off <= 255:  # pragma: no cover — bounded by MAX_FILTER_IFACES
                raise ValueError(f"BPF jump out of range: {off}")
            return off

        out.append(Insn(code, resolve(jt), resolve(jf), k))
    return out


def pack_filter(prog: list[Insn]) -> bytes:
    return b"".join(struct.pack("=HBBI", i.code, i.jt, i.jf, i.k) for i in prog)


class _CountingSocket(Protocol):
    def read_and_clear(self) -> int: ...

    def close(self) -> None: ...


class _PacketCountingSocket:
    """An AF_PACKET socket that is only ever asked how much it matched."""

    def __init__(self, prog: list[Insn]) -> None:
        family = getattr(socket, "AF_PACKET", None)
        if family is None:  # not Linux
            raise OSError("AF_PACKET is not available on this platform")
        sock = socket.socket(family, socket.SOCK_DGRAM, socket.htons(_ETH_P_IP))
        try:
            # The kernel clamps this to its minimum. Nothing reads the queue,
            # so it only bounds what the few queued 1-byte snaps occupy.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
            raw = pack_filter(prog)
            buf = ctypes.create_string_buffer(raw, len(raw))

            class _Fprog(ctypes.Structure):
                _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

            fprog = _Fprog(len(prog), ctypes.addressof(buf))
            sock.setsockopt(socket.SOL_SOCKET, _SO_ATTACH_FILTER, bytes(fprog))
        except BaseException:
            sock.close()
            raise
        self._sock = sock
        # The socket was live (unfiltered) between socket() and the attach;
        # PACKET_STATISTICS is read-and-clear, so this discards that window.
        self.read_and_clear()

    def read_and_clear(self) -> int:
        packets, _drops = _STATS.unpack(
            self._sock.getsockopt(_SOL_PACKET, _PACKET_STATISTICS, _STATS.size)
        )
        # The kernel has already folded tp_drops into tp_packets on read.
        return int(packets)

    def close(self) -> None:
        self._sock.close()


def _ipv4_of(name: str) -> int | None:
    """The primary IPv4 address of interface ``name`` (``SIOCGIFADDR``).

    The primary address is the one kea's raw socket serves from when the
    config does not pin one. ``None`` when the interface has none — kea does
    not open a DHCPv4 socket on such an interface at all.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = struct.pack("256s", name.encode()[:15])
        res = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, req)
    except OSError:
        return None
    finally:
        sock.close()
    return int(struct.unpack_from("!I", res, 20)[0])


class Resolved(NamedTuple):
    ifindexes: tuple[int, ...]
    addresses: tuple[int, ...]


def _resolve_intake(cfg: IntakeConfig) -> Resolved | None:
    """Kea's interfaces -> the ifindexes and addresses it serves on.

    ``*`` is every non-loopback interface that has an IPv4 address. A listed
    interface that does not exist, or has no IPv4 address, is left out,
    which is right: kea cannot serve DHCPv4 on it either. ``None`` (so:
    unmeasured) when there are more of either than a filter can express.
    Both tuples are sorted so a re-resolve that finds the same interfaces
    compares equal.
    """
    pinned = dict(cfg.pinned)
    if "*" in cfg.interfaces:
        names = [n for _i, n in socket.if_nameindex() if n != "lo"]
    else:
        names = list(dict.fromkeys(cfg.interfaces))
    found: set[int] = set()
    addrs: set[int] = set()
    for name in names:
        try:
            idx = socket.if_nametoindex(name)
        except OSError:
            continue
        addr: int | None
        if name in pinned:
            try:
                addr = int.from_bytes(socket.inet_aton(pinned[name]), "big")
            except OSError:
                addr = None
        else:
            addr = _ipv4_of(name)
        if addr is None:
            continue
        found.add(idx)
        addrs.add(addr)
    if len(found) > MAX_FILTER_IFACES or len(addrs) > MAX_FILTER_IFACES:
        return None
    return Resolved(tuple(sorted(found)), tuple(sorted(addrs)))


class ArrivalCounter:
    """DHCPv4 arrivals at Kea's intake since the previous :meth:`sample`.

    ``config`` returns kea-dhcp4's intake as rendered (re-read every
    sample). The counting socket is (re)opened whenever that — or the
    interfaces and addresses it resolves to — changes, and the sample that
    opens it is ``None``: the window it would cover started part-way through.

    ``None`` throughout when the socket cannot be opened, which is the
    normal answer on a deployment that does not grant ``CAP_NET_RAW``: it
    is reported as unmeasured, never as zero. ``opener`` and ``resolve``
    are parameters only so the tests can script them.
    """

    def __init__(
        self,
        config: Callable[[], IntakeConfig | None],
        opener: Callable[[list[Insn]], _CountingSocket] = _PacketCountingSocket,
        resolve: Callable[[IntakeConfig], Resolved | None] = _resolve_intake,
    ) -> None:
        self._config = config
        self._opener = opener
        self._resolve = resolve
        self._sock: _CountingSocket | None = None
        self._key: tuple[object, ...] | None = None
        self._open_failed_key: tuple[object, ...] | None = None

    def _close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass  # closing a socket we are discarding; nothing to recover
            self._sock = None
        self._key = None

    def close(self) -> None:
        self._close()

    def sample(self) -> int | None:
        cfg = self._config()
        resolved = None if cfg is None else self._resolve(cfg)
        if cfg is None or resolved is None:
            self._close()
            return None
        key = (cfg.mode, resolved.ifindexes, resolved.addresses)
        if self._sock is not None and key == self._key:
            try:
                return self._sock.read_and_clear()
            except OSError as e:
                log.debug("intake_counter_read_failed", error=str(e))
                self._close()
                return None
        self._close()
        try:
            self._sock = self._opener(
                build_filter(cfg.mode, resolved.ifindexes, None, resolved.addresses)
            )
        except OSError as e:
            # Logged once per configuration, not every minute: on a
            # deployment without CAP_NET_RAW this is the steady state.
            if key != self._open_failed_key:
                log.info("intake_counter_unavailable", error=str(e))
                self._open_failed_key = key
            return None
        self._key = key
        self._open_failed_key = None
        return None  # the window this would cover began part-way through


class QueueEvictionEstimator:
    """Per-bucket requests evicted from Kea's packet queue (#2889).

    Fed once per bucket with the DHCPv4 deltas over the same interval:
    ``arrived`` (arrivals read just BEFORE Kea's counters were requested),
    ``socket_drop`` and ``received`` (Kea's snapshot, at some instant
    ``t_s``), and ``arrived_during`` (arrivals between that first read and
    one taken just AFTER the reply). Any of them ``None`` (unmeasured, a Kea
    restart, the counting socket reopened) returns ``None`` and restarts the
    baseline, because the sums below are only meaningful over an unbroken
    run of intervals.

    Let ``X(t)`` be arrivals - socket drops - received, cumulatively: every
    eviction so far, plus whatever is in flight (queued, or in Kea's socket
    buffer) at ``t``. It is never read at one instant, but it is bracketed:

    * ``L`` (arrivals as of the first read) ``<= X(t_s)`` — a packet that
      arrived after that read may already be counted received;
    * ``U`` (arrivals as of the second read) ``>= X(t_s)`` — every packet
      Kea had received by ``t_s`` arrived before the second read, and a
      socket drop is only ever of a packet arriving in the same window.

    Evictions only ever rise. So:

    * an eviction is confirmed from the LOWER bound held at two reads in a
      row (``min(L[prev], L[now])``), so a backlog in flight at one read is
      never loss and read skew can only make the estimate lower;
    * the zero point is the lowest UPPER bound held at two reads in a row,
      which is never below the true baseline (``U`` never is), so a baseline
      taken mid-backlog is corrected as the backlog drains without any
      packet of read skew ever being turned into loss;
    * the reported total is a high-water mark: reported once, never
      negative, and never re-reported when the inputs move down and back.

    That bounds the false part of the total, over the whole baseline, by the
    largest backlog still in flight at two consecutive reads (a minute
    apart), which needs sustained overload. A delivery path that counts
    fewer arrivals than Kea receives (traffic Kea reads that the filter does
    not see) only ever lowers the estimate. The cost is a one-bucket lag: an
    eviction is reported by the sample after the one that first saw it.
    """

    def __init__(self) -> None:
        self._u: int | None = None  # last upper bound; None = no baseline
        self._prev_l: int | None = None
        self._prev_u = 0
        self._zero = 0
        self._confirmed: int | None = None
        self._reported = 0

    def update(
        self,
        arrived: int | None,
        socket_drop: int | None,
        received: int | None,
        arrived_during: int | None = 0,
    ) -> int | None:
        if arrived is None or socket_drop is None or received is None or arrived_during is None:
            self._u = None
            return None
        if self._u is None:
            # The previous read is the zero point. It is an upper-bound
            # read, so it can only overstate the baseline.
            self._u = 0
            self._prev_l = None
            self._prev_u = 0
            self._zero = 0
            self._confirmed = None
            self._reported = 0
        lower = self._u + arrived - socket_drop - received
        upper = lower + arrived_during
        self._zero = min(self._zero, max(self._prev_u, upper))
        if self._prev_l is not None:
            pair = min(self._prev_l, lower)
            self._confirmed = pair if self._confirmed is None else max(self._confirmed, pair)
        if self._confirmed is not None and upper < self._confirmed:
            # Nothing is evicted after the fact: an upper bound below what
            # was confirmed means the confirmation was a backlog, or traffic
            # Kea reads that is not counted. Either way the confirmed level
            # was too high, and holding it would turn the gap into loss.
            self._confirmed = upper
        self._prev_l = lower
        self._prev_u = upper
        self._u = upper
        total = 0 if self._confirmed is None else max(0, self._confirmed - self._zero)
        out = max(0, total - self._reported)
        self._reported = max(self._reported, total)
        return out


__all__ = [
    "DHCP4_SERVER_PORT",
    "ArrivalCounter",
    "Insn",
    "IntakeConfig",
    "QueueEvictionEstimator",
    "Resolved",
    "build_filter",
    "kea_intake_config",
    "pack_filter",
]
