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
and the socket is never read, so its tiny receive buffer stays full and each
match costs a filter run and a counter increment, not a copy. The socket taps
the same point in the receive path Kea's own raw socket does (the protocol
handlers, ahead of netfilter), and it needs ``CAP_NET_RAW``, which this agent
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
counter. Counting in the agent avoids all of that, reads within microseconds
of Kea's counters, and works on every deployment where the agent has
``CAP_NET_RAW`` and sees the host's interfaces — not only on the appliance.

**What is counted** (see :func:`build_filter`): IPv4 UDP to port 67, first
fragment only, arriving (not sent) on an interface Kea serves, and

* ``raw`` mode (the default, #365): unicast to this host or broadcast —
  Kea's AF_PACKET socket reads both;
* ``udp`` mode: unicast to this host only. Kea's UDP sockets are bound to
  interface addresses and never see a broadcast.

Unknown mode, or no kea-dhcp4 config at all, is unmeasured (``None``).

**Arithmetic** (see :class:`QueueEvictionEstimator`). A per-bucket
``arrived - socket_drop - received`` is not the answer by itself, because
the three are read at slightly different instants and because a packet
still queued at the read is counted as arrived and not yet as anything
else. Both effects move counts between ADJACENT buckets and cancel in the
running sum; eviction is the part of that sum that never comes back down.
So the estimator reports only increases of the running sum that the NEXT
sample confirms, against a high-water mark: a transient dip is never
reported as negative loss, a transient bump (a backlog in flight at the
read) is never reported as loss, and nothing is reported twice. The price
is that an eviction lands in the bucket after the one it happened in.
"""

from __future__ import annotations

import ctypes
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

# One jump offset is a u8. An interface list longer than this cannot be
# expressed as a chain of compares to one accept, and is treated as "*".
MAX_FILTER_IFACES = 200

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


def kea_intake_config(path: str | os.PathLike[str]) -> IntakeConfig | None:
    """Socket mode + interfaces of the kea-dhcp4 config at ``path``.

    ``None`` means unknown: no file (a v6-only server has no kea-dhcp4
    config), unparseable, or a mode kea does not have. Interface entries
    may be ``"<iface>/<address>"`` (kea's per-address form); only the
    interface name matters here. An absent list is ``*``, kea's default.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        iface = doc["Dhcp4"].get("interfaces-config") or {}
        mode = iface.get("dhcp-socket-type", "raw")
        raw_names = iface.get("interfaces") or ["*"]
        names = tuple(str(n).split("/", 1)[0] for n in raw_names)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    if mode not in ("raw", "udp"):
        return None
    return IntakeConfig(mode, names)


def build_filter(mode: str, ifindexes: tuple[int, ...] | None, loopback: int | None) -> list[Insn]:
    """The classic-BPF program counting DHCPv4 server-bound arrivals.

    Runs on an ``AF_PACKET``/``SOCK_DGRAM`` socket, so offset 0 is the IPv4
    header. ``ifindexes=None`` means every interface except ``loopback``;
    a tuple means exactly those interfaces (possibly none: kea was told to
    listen on interfaces that do not exist, so nothing can reach it).
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
        emit(_JEQ_K, _PACKET_HOST, "iface", 0)
        emit(_JEQ_K, _PACKET_BROADCAST, "iface", "reject")
    else:
        emit(_JEQ_K, _PACKET_HOST, "iface", "reject")
    labels = {"iface": len(prog)}
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


def _resolve_ifindexes(names: tuple[str, ...]) -> tuple[int, ...] | None:
    """Interface names -> ifindexes; ``None`` for ``*`` (all but loopback).

    A listed interface that does not exist is left out, which is right: kea
    cannot listen on it either. The tuple is sorted so a re-resolve that
    finds the same interfaces compares equal.
    """
    if "*" in names:
        return None
    found: set[int] = set()
    for name in names:
        try:
            found.add(socket.if_nametoindex(name))
        except OSError:
            continue
    if len(found) > MAX_FILTER_IFACES:
        return None
    return tuple(sorted(found))


def _loopback_ifindex() -> int | None:
    try:
        return socket.if_nametoindex("lo")
    except OSError:
        return None


class ArrivalCounter:
    """DHCPv4 arrivals at Kea's intake since the previous :meth:`sample`.

    ``config`` returns kea-dhcp4's intake as rendered (re-read every
    sample). The counting socket is (re)opened whenever that — or the
    interfaces it resolves to — changes, and the sample that opens it is
    ``None``: the window it would cover started part-way through.

    ``None`` throughout when the socket cannot be opened, which is the
    normal answer on a deployment that does not grant ``CAP_NET_RAW``: it
    is reported as unmeasured, never as zero. ``opener`` and ``resolve``
    are parameters only so the tests can script them.
    """

    def __init__(
        self,
        config: Callable[[], IntakeConfig | None],
        opener: Callable[[list[Insn]], _CountingSocket] = _PacketCountingSocket,
        resolve: Callable[[tuple[str, ...]], tuple[int, ...] | None] = _resolve_ifindexes,
        loopback: Callable[[], int | None] = _loopback_ifindex,
    ) -> None:
        self._config = config
        self._opener = opener
        self._resolve = resolve
        self._loopback = loopback
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
        if cfg is None:
            self._close()
            return None
        ifindexes = self._resolve(cfg.interfaces)
        loopback = self._loopback() if ifindexes is None else None
        key = (cfg.mode, ifindexes, loopback)
        if self._sock is not None and key == self._key:
            try:
                return self._sock.read_and_clear()
            except OSError as e:
                log.debug("intake_counter_read_failed", error=str(e))
                self._close()
                return None
        self._close()
        try:
            self._sock = self._opener(build_filter(cfg.mode, ifindexes, loopback))
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

    Fed one bucket at a time with the three DHCPv4 deltas over the same
    interval. Any of them ``None`` (unmeasured, a Kea restart, the counting
    socket reopened) returns ``None`` and restarts the baseline, because the
    running sum below is only meaningful over an unbroken run of intervals.

    ``e = arrived - socket_drop - received`` for one bucket is eviction plus
    noise that moves between adjacent buckets: a packet read by the worker
    a moment before the arrivals were read is counted in this bucket's
    ``received`` and the next bucket's ``arrived``, and a packet still
    queued at the read is counted in this bucket's ``arrived`` and the next
    bucket's ``received``. In the running sum ``S`` that noise is a dip or a
    bump at one sample which the next sample undoes; eviction is a step
    that stays. So:

    * ``settled = min(S[prev], S[now])`` — a value the next sample has
      confirmed. A bump present at only one sample never gets into it.
    * Only ``settled`` above the high-water mark of everything already
      reported is reported. A dip followed by its recovery reports nothing,
      so nothing is counted twice and nothing is ever negative.
    * If the sum stays below the mark for two samples in a row it is not
      a one-sample dip but a level shift — the baseline started with a
      backlog in flight, or arrivals are counted that Kea never reads — and
      the mark follows it down. Otherwise every later eviction up to the
      size of the shift would be absorbed silently.

    The cost is a one-bucket lag: an eviction is reported by the sample
    after the one that first saw it. Under a backlog that outlasts two
    samples in a row the in-flight count is confirmed with it, overstating
    by at most the queue's depth once — under exactly the sustained
    overload in which the queue is evicting anyway.
    """

    def __init__(self) -> None:
        self._sum: int | None = None
        self._mark = 0

    def update(
        self, arrived: int | None, socket_drop: int | None, received: int | None
    ) -> int | None:
        if arrived is None or socket_drop is None or received is None:
            self._sum = None
            return None
        if self._sum is None:
            self._sum = 0
            self._mark = 0
        prev = self._sum
        now = prev + arrived - socket_drop - received
        self._sum = now
        settled = min(prev, now)
        out = max(0, settled - self._mark)
        if settled > self._mark:
            self._mark = settled
        elif prev < self._mark and now < self._mark:
            self._mark = max(prev, now)
        return out


__all__ = [
    "DHCP4_SERVER_PORT",
    "ArrivalCounter",
    "Insn",
    "IntakeConfig",
    "QueueEvictionEstimator",
    "build_filter",
    "kea_intake_config",
    "pack_filter",
]
