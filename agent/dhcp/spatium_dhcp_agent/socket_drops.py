"""Per-socket kernel receive-drop counters for the DHCP listen ports (#980).

Kea answers every packet it manages to read. When a burst arrives faster
than its receive thread is scheduled, the loss happens one layer down — the
kernel finds the socket's receive buffer full and drops the datagram before
``recvmsg()`` ever sees it. Nothing inside Kea observes that, so every
product surface reports a healthy server while clients retransmit.

**``pkt4-receive-drop`` is not this number.** Measured against kea-dhcp4
3.0.3 on 2026-09-06: a run that lost 9,700 datagrams to socket-buffer
overflow left ``pkt4-receive-drop`` at exactly 0, because that counter
covers packets Kea *read* and then discarded (unparseable, DROP class, no
subnet). Both are worth reporting and they name different failures — this
module supplies the one that moves when a node is out of CPU.

The kernel exposes it per socket as the last column of ``/proc/net/udp``
(``sk_drops``), which is the same event that increments the node-wide
``Udp: RcvbufErrors`` in ``/proc/net/snmp``. We read the per-socket form
deliberately: the node-wide counter is shared with every other UDP consumer
in the network namespace — and the DHCP pod runs with host networking — so
it cannot say the loss was ours.

Only sockets bound to a DHCP service port are counted (67 for DHCPv4, 547
for DHCPv6). One exception, since #1283: in ``dhcp-socket-type: raw``,
kea-dhcp4 serves from AF_PACKET sockets, relayed traffic included. Its
port-67 UDP sockets are then only fallbacks, whose packets it discards, so
the AF_PACKET sockets are counted in their place. See
:func:`read_packet_drops` and :class:`SocketDropCounter`.
"""

from __future__ import annotations

import json
import os
import socket
import struct
from collections.abc import Callable
from typing import NamedTuple

import structlog

log = structlog.get_logger(__name__)

# DHCPv4 server port and DHCPv6 server port. ``/proc/net/udp`` prints the
# local port in hex, so these are compared post-parse rather than as text.
DHCP_PORTS = frozenset({67, 547})
_DHCP4_PORT = 67
# Key prefix for a port-67 UDP socket inside :class:`SocketDropCounter`, so
# its DHCPv4 share can be summed apart from port 547 (#2889). AF_PACKET
# sockets are already ``packet:``-prefixed and are DHCPv4 by construction.
_V4_UDP_KEY = "udp67:"

_PROC_UDP = ("/proc/net/udp", "/proc/net/udp6")


def _parse_proc_udp(text: str, ports: frozenset[int] = DHCP_PORTS) -> dict[str, int]:
    """One ``/proc/net/udp`` body -> ``{inode: sk_drops}`` for DHCP ports.

    Row layout (both the v4 and v6 files), whitespace-separated::

        sl local_address rem_address st tx:rx tr:when retrnsmt uid
        timeout inode ref pointer drops

    ``local_address`` is ``<hex-addr>:<hex-port>``; ``drops`` is last.
    Keying by inode rather than by address means a socket that Kea closes
    and reopens on reconfiguration reads as a *new* counter starting at
    zero instead of as a counter that went backwards.

    ``ports`` is a parameter only so the tests can point it at an ephemeral
    port: binding 67 needs privilege, and a fixture cannot prove the field
    indices below are the ones this kernel actually uses. Production always
    passes the default.
    """
    out: dict[str, int] = {}
    for line in text.splitlines()[1:]:  # [0] is the column header
        fields = line.split()
        if len(fields) < 13:
            continue
        local = fields[1]
        if ":" not in local:
            continue
        try:
            port = int(local.rsplit(":", 1)[1], 16)
            drops = int(fields[-1])
        except ValueError:
            continue
        if port not in ports:
            continue
        out[fields[9]] = drops
    return out


def read_socket_drops(
    paths: tuple[str, ...] = _PROC_UDP, ports: frozenset[int] = DHCP_PORTS
) -> dict[str, int] | None:
    """Snapshot ``{inode: sk_drops}`` for every DHCP-port UDP socket.

    Returns ``None`` — never ``{}`` — when the counter cannot be read, so a
    caller can report UNKNOWN rather than a zero that reads as "no loss".
    A *partial* read is also ``None``: see the OSError branch below.
    ``{}`` is a real answer: procfs was readable and no DHCP socket is
    currently open (Kea starting, or bound raw-only).
    """
    merged: dict[str, int] = {}
    readable = False
    for path in paths:
        try:
            with open(path, encoding="ascii", errors="replace") as fh:
                text = fh.read()
        except FileNotFoundError:
            # No IPv6 stack, or not Linux. Not an error on its own: an
            # absent file has no sockets to account for, so the remaining
            # answer is still complete.
            continue
        except OSError as e:
            # A file that EXISTS and could not be read is different. Its
            # sockets are unaccounted for, and returning the rest as a valid
            # snapshot is worse than returning nothing: the missing inodes
            # drop out of the baseline, and when the next read succeeds they
            # come back as new sockets whose whole-lifetime sk_drops is
            # attributed to that one bucket. On a socket that has been up for
            # days that is a fabricated spike large enough to trip the
            # alert. Fail the whole sample instead.
            log.debug("socket_drops_unreadable", path=path, error=str(e))
            return None
        readable = True
        merged.update(_parse_proc_udp(text, ports))
    return merged if readable else None


# ── AF_PACKET: the socket kea serves from in raw mode (#1283) ──────────────
#
# With ``dhcp-socket-type: raw`` (the default, #365) kea-dhcp4 opens, per
# interface, an AF_PACKET socket (SOCK_RAW, ETH_P_ALL) whose BPF filter
# admits UDP to port 67 sent to the broadcast address OR to the interface's
# own address, so relayed unicast is read from it as well. Beside it sits a
# UDP "fallback" socket on <address>:67 that kea drains and DISCARDS on
# every receive, before reading one packet from the raw socket. So in raw
# mode the UDP numbers above are drops of copies kea throws away, and the
# drops that cost a client a retransmit are on the AF_PACKET socket. The
# counter therefore reads the AF_PACKET sockets instead of the port-67 ones
# in that mode (:class:`SocketDropCounter`). Which mode kea is in comes from
# the config this agent rendered (:func:`kea_socket_type`). Kea's own
# ``config-get`` leaves the key out when it holds kea's default, ``raw``.
#
# Its drop count is not in procfs (``/proc/net/packet`` has no drops column)
# and ``PACKET_STATISTICS`` needs the socket itself. sock_diag reports it for
# every AF_PACKET socket in the network namespace (``SK_MEMINFO_DROPS``, what
# ``ss -0 -e -m`` prints as ``d``), and answers the agent's unprivileged user
# (verified on the appliance). Which of those are kea's cannot be read from
# ``/proc/<kea>/fd``: kea is started from a binary with file capabilities,
# which makes it non-dumpable, and its fd table is closed to the agent and
# even to root inside the container (verified). So they are told apart
# instead: kea's are the raw ETH_P_ALL sockets owned by this user (the
# entrypoint runs kea and the agent as the same one) that this process does
# not hold itself (the agent's own sniffers are threads of this process).
#
# That rule also takes in another program's raw socket if its owner has the
# same numeric uid. On the appliance one does: the host's lldpd runs as uid
# 102, which is also the pod's ``spatium``. Its sockets carry a BPF filter
# that keeps everything but discovery frames out of their queues, so their
# drop counts stay 0 under DHCP load (verified: 0 on all ten while kea's
# enp1s0 socket counted 302). Over-counting there is the safe direction for
# a loss signal; leaving kea's raw socket out was not.

_NETLINK_SOCK_DIAG = 4
_SOCK_DIAG_BY_FAMILY = 20
_NLM_F_REQUEST = 0x1
_NLM_F_DUMP = 0x300
_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_AF_PACKET = 17
_SOCK_RAW = 3
_ETH_P_ALL = 0x0003
_PACKET_SHOW_INFO = 0x01
_PACKET_SHOW_MEMINFO = 0x10
_PACKET_DIAG_UID = 5
_PACKET_DIAG_MEMINFO = 6
_SK_MEMINFO_DROPS = 8

_NLMSG_HDR = struct.Struct("=IHHII")  # len, type, flags, seq, pid
_PACKET_DIAG_REQ = struct.Struct("=BBHII2I")  # family, protocol, pad, ino, show, cookie
_PACKET_DIAG_MSG = struct.Struct("=BBHI2I")  # family, type, num, ino, cookie
_NLATTR = struct.Struct("=HH")  # len, type

_PROC_PACKET = "/proc/net/packet"


class PacketSocket(NamedTuple):
    """One AF_PACKET socket as the kernel describes it."""

    inode: int
    sock_type: int
    protocol: int  # host byte order, e.g. 0x0003 for ETH_P_ALL
    uid: int | None
    drops: int | None


def _packet_diag_request(seq: int = 1) -> bytes:
    body = _PACKET_DIAG_REQ.pack(
        _AF_PACKET, 0, 0, 0, _PACKET_SHOW_INFO | _PACKET_SHOW_MEMINFO, 0, 0
    )
    flags = _NLM_F_REQUEST | _NLM_F_DUMP
    head = _NLMSG_HDR.pack(_NLMSG_HDR.size + len(body), _SOCK_DIAG_BY_FAMILY, flags, seq, 0)
    return head + body


def _parse_packet_diag(data: bytes) -> tuple[list[PacketSocket], bool]:
    """One ``recv()`` of a packet_diag dump -> ``(sockets, finished)``.

    Raises ``OSError`` with the kernel's errno for an ``NLMSG_ERROR`` (the
    dump was refused, e.g. a kernel without ``packet_diag``).
    """
    out: list[PacketSocket] = []
    off = 0
    while off + _NLMSG_HDR.size <= len(data):
        length, mtype, _flags, _seq, _pid = _NLMSG_HDR.unpack_from(data, off)
        if length < _NLMSG_HDR.size:
            break
        if mtype == _NLMSG_DONE:
            return out, True
        if mtype == _NLMSG_ERROR:
            err = -struct.unpack_from("=i", data, off + _NLMSG_HDR.size)[0]
            raise OSError(err, os.strerror(err))
        body = data[off + _NLMSG_HDR.size : off + length]
        if len(body) >= _PACKET_DIAG_MSG.size:
            _family, sock_type, protocol, inode, _c0, _c1 = _PACKET_DIAG_MSG.unpack_from(body)
            uid: int | None = None
            drops: int | None = None
            attr = _PACKET_DIAG_MSG.size
            while attr + _NLATTR.size <= len(body):
                alen, atype = _NLATTR.unpack_from(body, attr)
                if alen < _NLATTR.size:
                    break
                payload = body[attr + _NLATTR.size : attr + alen]
                if atype == _PACKET_DIAG_UID and len(payload) >= 4:
                    uid = struct.unpack_from("=I", payload)[0]
                elif atype == _PACKET_DIAG_MEMINFO and len(payload) >= 4 * (_SK_MEMINFO_DROPS + 1):
                    drops = struct.unpack_from("=I", payload, 4 * _SK_MEMINFO_DROPS)[0]
                attr += (alen + 3) & ~3
            out.append(PacketSocket(inode, sock_type, protocol, uid, drops))
        off += (length + 3) & ~3
    return out, False


def dump_packet_sockets(timeout: float = 2.0) -> list[PacketSocket]:
    """Every AF_PACKET socket in this network namespace, via sock_diag."""
    family = getattr(socket, "AF_NETLINK", None)
    if family is None:  # not Linux
        raise OSError("sock_diag needs AF_NETLINK")
    with socket.socket(family, socket.SOCK_RAW, _NETLINK_SOCK_DIAG) as nl:
        nl.settimeout(timeout)
        nl.sendall(_packet_diag_request())
        out: list[PacketSocket] = []
        while True:
            data = nl.recv(1 << 16)
            if not data:
                raise OSError("packet_diag dump ended without NLMSG_DONE")
            rows, finished = _parse_packet_diag(data)
            out.extend(rows)
            if finished:
                return out


def _proc_packet_sockets(path: str = _PROC_PACKET) -> list[PacketSocket] | None:
    """``/proc/net/packet``: every AF_PACKET socket, but with no drop count.

    Columns: ``sk RefCnt Type Proto Iface R Rmem User Inode``. Absent means
    no AF_PACKET support, so no sockets; unreadable means unknown (None).
    """
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            text = fh.read()
    except FileNotFoundError:
        return []
    except OSError:
        return None
    out: list[PacketSocket] = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 9:
            continue
        try:
            out.append(PacketSocket(int(f[8]), int(f[2]), int(f[3], 16), int(f[7]), None))
        except ValueError:
            continue
    return out


def _own_socket_inodes(fd_dir: str = "/proc/self/fd") -> set[int]:
    """Inodes of every socket this process holds (all of its threads)."""
    inodes: set[int] = set()
    for name in os.listdir(fd_dir):
        try:
            target = os.readlink(os.path.join(fd_dir, name))
        except OSError:
            continue  # closed between listdir and readlink
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(int(target[8:-1]))
    return inodes


def _is_keas(sock: PacketSocket, uid: int, own: set[int]) -> bool:
    return (
        sock.sock_type == _SOCK_RAW
        and sock.protocol == _ETH_P_ALL
        and sock.uid == uid
        and sock.inode not in own
    )


def read_packet_drops(
    dump: Callable[[], list[PacketSocket]] = dump_packet_sockets,
    own_inodes: Callable[[], set[int]] = _own_socket_inodes,
    proc_packet: str = _PROC_PACKET,
    uid: int | None = None,
) -> dict[str, int] | None:
    """Snapshot ``{"packet:<inode>": sk_drops}`` for kea's raw DHCPv4 sockets.

    ``{}`` is a real answer: no raw socket of kea's is open, because kea is
    starting or could not open one. ``None`` means they may exist and their
    drops could not be read. The caller then reports the whole sample as
    unknown, because in raw mode nothing else measures kea-dhcp4's intake.
    When sock_diag is refused, ``/proc/net/packet`` still says whether there
    was anything to miss: it lists the sockets, though not their drops.

    The parameters exist only so the tests can drive this function over
    fixtures; production passes none of them.
    """
    me = os.geteuid() if uid is None else uid
    try:
        own = own_inodes()
    except OSError as e:
        log.debug("packet_drops_own_fds_unreadable", error=str(e))
        return None
    try:
        rows = dump()
    except OSError as e:
        listed = _proc_packet_sockets(proc_packet)
        if listed is not None and not any(_is_keas(s, me, own) for s in listed):
            return {}
        log.debug("packet_drops_unreadable", error=str(e))
        return None
    out: dict[str, int] = {}
    for s in rows:
        if not _is_keas(s, me, own):
            continue
        if s.drops is None:
            return None
        out[f"packet:{s.inode}"] = s.drops
    return out


def kea_socket_type(path: str | os.PathLike[str]) -> str | None:
    """``dhcp-socket-type`` of the kea-dhcp4 config at ``path``: raw or udp.

    ``path`` is the file this agent renders and kea loads
    (``KEA_CONFIG_PATH``). A missing key is ``raw``, kea's own default for
    DHCPv4. ``None`` means unknown: the file cannot be read or parsed, or it
    names a mode kea does not have.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        iface = doc["Dhcp4"].get("interfaces-config") or {}
        mode = iface.get("dhcp-socket-type", "raw")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return mode if mode in ("raw", "udp") else None


class SocketDropCounter:
    """Turns per-socket monotonic ``sk_drops`` into a per-bucket delta.

    Each socket's counter is monotonic for the life of *that* socket and
    disappears with it, so the aggregate is summed per inode rather than in
    total: a socket that goes away must not make the fleet-wide sum fall
    (which would read as a counter reset), and a socket that appears
    contributes its own count from zero.

    Which sockets are counted follows kea-dhcp4's socket mode (#1283),
    which ``socket_type`` returns at every sample:

    * ``udp``: the DHCP-port UDP sockets, v4 and v6. sock_diag is not
      asked.
    * ``raw``: kea's AF_PACKET sockets, and the UDP sockets on port 547
      (kea-dhcp6 has no raw mode). The port-67 UDP sockets are left out:
      in this mode they are fallbacks whose packets kea reads only to
      discard, so their drops are copies of packets the AF_PACKET socket
      also received, or also dropped. If fallbacks are open and no raw
      socket of kea's is found, the sample is unknown, not 0.
    * ``None`` (unknown): all of them, so no loss is left out.

    A change of mode restarts the baseline. The set of sockets being
    counted changes, and kea reopens its sockets on that reconfiguration
    anyway.

    ``packet_drops`` and ``socket_type`` are parameters so the tests can
    script them. The metrics poller passes the rendered config's mode.
    """

    def __init__(
        self,
        packet_drops: Callable[[], dict[str, int] | None] | None = None,
        socket_type: Callable[[], str | None] | None = None,
    ) -> None:
        self._prev: dict[str, int] | None = None
        self._mode: str | None = None
        #: #2889 — the DHCPv4 share of the last :meth:`sample_from` result,
        #: or ``None`` whenever that result was ``None``. The queue-eviction
        #: estimate subtracts it from DHCPv4 arrivals, so it must not carry
        #: the port-547 drops the total folds in. Keyed by the same per-socket
        #: arithmetic as the total, so the two can never disagree about which
        #: interval they cover.
        self.last_v4: int | None = None
        self._packet_drops = read_packet_drops if packet_drops is None else packet_drops
        self._socket_type = (lambda: None) if socket_type is None else socket_type

    def sample(self) -> int | None:
        """Drops since the previous call, or ``None`` if not measurable."""
        return self.sample_from(_PROC_UDP)

    def sample_from(
        self, paths: tuple[str, ...], ports: frozenset[int] = DHCP_PORTS
    ) -> int | None:
        """Drops since the previous call, reading ``paths``.

        The first call after start returns ``None``: with no baseline, the
        counters standing on the sockets are however much was lost before
        the agent came up, which belongs to no bucket in particular.

        ``paths`` is a parameter only so the tests can drive this exact
        method over fixture files. Production calls :meth:`sample`, which
        supplies the real procfs paths — the tests must not reimplement the
        arithmetic below, or they assert on a copy of it.
        """
        mode = self._socket_type()
        if mode != self._mode:
            self._prev = None
            self._mode = mode
        # The port-67 UDP sockets are read apart from the rest and their keys
        # tagged, so the DHCPv4 share can be told out of the total (#2889).
        # In raw mode they are fallbacks and not counted at all (#1283).
        v4_udp_ports = ports & {_DHCP4_PORT} if mode != "raw" else frozenset()
        current = read_socket_drops(paths, ports - {_DHCP4_PORT})
        if current is not None and v4_udp_ports:
            v4_udp = read_socket_drops(paths, v4_udp_ports)
            current = (
                None
                if v4_udp is None
                else {**current, **{f"{_V4_UDP_KEY}{k}": v for k, v in v4_udp.items()}}
            )
        if current is not None and mode != "udp":
            # A partial read counts as no read, as for the two procfs files.
            # In raw mode the UDP half alone does not measure kea-dhcp4 at all.
            packet = self._packet_drops()
            if packet is None:
                current = None
            elif mode == "raw" and not packet and read_socket_drops(paths, ports & {_DHCP4_PORT}):
                # Kea opens its raw socket beside every :67 fallback, and
                # closes the fallback if the raw open fails. So fallbacks
                # with no raw socket of kea's found mean its raw sockets
                # could not be told apart. That is unknown, never a 0.
                current = None
            else:
                current = {**current, **packet}
        self.last_v4 = None
        if current is None:
            self._prev = None
            return None
        prev = self._prev
        self._prev = current
        if prev is None:
            return None
        total = 0
        v4 = 0
        for inode, value in current.items():
            baseline = prev.get(inode, 0)
            # max() guards a same-inode counter that appears to fall. It
            # cannot happen for sk_drops, but an inode number reused by a
            # different socket inside one interval would look exactly like
            # that, and a negative contribution is never the right answer.
            d = max(0, value - baseline)
            total += d
            if inode.startswith((_V4_UDP_KEY, "packet:")):
                v4 += d
        self.last_v4 = v4
        return total


__all__ = [
    "DHCP_PORTS",
    "PacketSocket",
    "SocketDropCounter",
    "dump_packet_sockets",
    "kea_socket_type",
    "read_packet_drops",
    "read_socket_drops",
]
