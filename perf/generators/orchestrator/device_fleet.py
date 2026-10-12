#!/usr/bin/env python3
"""The diurnal device-fleet orchestrator — the realistic 24h load (docs §3.2/§3.4/§4.5).

A single asyncio worker process modeling a disjoint shard of the 250-300k device
population as independent state machines driven by the §1 diurnal curve, generating
**real DHCPv4 packets** to Kea (so the full agent -> control-plane -> IPAM -> DDNS ->
DB path is exercised as production would), plus each ONLINE device's **DNS query
stream** (dnspython async, Poisson draws from a Zipfian name set), plus the
**propagation-lag probe** on a 1-in-1000 sampled arrival (lease -> IPAM mirror ->
A/PTR resolves, single-clock).

Per-device FSM (§3.2):

    OFFLINE -> DISCOVERING -(DORA)-> ONLINE -> RENEWING -ACK-> ONLINE
                                       |  (T1 fails) -> REBINDING -ACK-> ONLINE
                                       |  departure -> DEPARTING -> LEFT
    LEFT -> (re-arrival) -> DISCOVERING ...

HARD FSM CONTRACTS (the report turns these into named correctness FAILs):
  * T1 = 900s: RENEWING re-REQUESTs the CURRENT lease/IP (NOT a fresh DISCOVER); a
    renewal that lands on a different IP is a correctness FAIL (§3.2 / H3).
  * ~5% of departures send an explicit DHCPRELEASE; 95% leave silently (reaped by the
    server-side sweep). (§3.2)
  * DDNS short-circuit: renewals must NOT re-publish DNS — the short-circuit ratio on
    renewals must be ~0 (§3.4 #2 / §4.6); we only DDNS-couple on first DORA.

Scaling note (open_item): a single process is CPU-bound at the surge peak. This is a
correct, runnable, **shardable** first-cut — run K shards (K ~ vCPU) over a disjoint
MAC index range via ``--shard N --shards K`` (and disjoint from perfdhcp's range, by
convention perfdhcp owns the top of the index space). Multi-box if one box can't
sustain the peak. The device population is modeled as state structs on a timer-wheel
scheduler (NOT one coroutine per device) so a shard holds ~tens of thousands of
devices without 150k live coroutines.

CLI contract (workers.py REGISTRY -> orchestrator):
    device_fleet.py --run-id <id> --run-root <path> --manifest <path> [--shard N --shards K]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import random
import signal
import socket
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

# Dual-mode imports: the controller launches this as a bare script (no parent
# package), but it's also importable as ``generators.orchestrator.device_fleet``.
# Put our own dir on sys.path so the sibling modules resolve either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import spddi_perf.manifest as manifest_mod  # noqa: E402
import spddi_perf.setpoints as setpoints_mod  # noqa: E402
from spddi_perf import canonical, fleet  # noqa: E402
from spddi_perf.logging_util import append_ndjson, get_logger, read_json, utc_now_iso  # noqa: E402
from spddi_perf.runpaths import RunPaths  # noqa: E402

import dhcp_packet as dp  # noqa: E402
from lifecycle_log import LatencyAccumulator, LifecycleLog  # noqa: E402
from relay_sockets import open_relay_sockets  # noqa: E402

from accounting import (  # noqa: E402
    DORA_KINDS, KIND_DISCOVER, KIND_REBIND, KIND_RENEW, KIND_SELECT, Closed, DnsTally,
    Exchange, ExchangeLedger, rcode_name,
)
from spddi_perf.generator_tallies import dns_summary, handshake_summary  # noqa: E402

# dnspython is an off-box runtime dep (perf/requirements.txt: dnspython>=2.6); resolve
# it once at import so the per-query hot path doesn't re-run the import machinery. When
# absent (bare env) the DNS query stream + the IPAM->DNS propagation leg no-op cleanly.
try:
    import dns.asyncquery as _dns_aq  # type: ignore
    import dns.message as _dns_msg  # type: ignore
    import dns.rcode as _dns_rcode  # type: ignore
    from dns.exception import Timeout as _DnsTimeout  # type: ignore

    _HAVE_DNSPYTHON = True
    # A timed-out query is a timeout; every other exception is an error the
    # tally names by type (#1057 — the two used to share one counter).
    _DNS_TIMEOUT_EXC: tuple[type[BaseException], ...] = (
        _DnsTimeout, asyncio.TimeoutError, TimeoutError)
except Exception:  # pragma: no cover - exercised only in a bare env
    _dns_aq = _dns_msg = _dns_rcode = None  # type: ignore
    _HAVE_DNSPYTHON = False
    _DNS_TIMEOUT_EXC = (asyncio.TimeoutError, TimeoutError)

SERVICE = "orchestrator"

# --- timings (verified §0.A) ---
T1_RENEW_S = canonical.T1_RENEW_S      # 900
T2_REBIND_S = canonical.T2_REBIND_S    # 1800
# DORA retransmission, as an RFC 2131 §4.1 client does it: the wait for an
# OFFER/ACK after send n of a round (n = 0 for the first) is
# min(BASE * 2**n, CAP) seconds, each wait moved by a uniform draw in
# [-JITTER, +JITTER] from the shard's seeded RNG. With MAX_DORA_RETRIES = 3 a
# device sends 4 times (≈0, 4, 12, 28 s) and gives up ≈60 s after its first
# send, the shape of a Windows client's first minute. A fixed 4 s wait put
# every device that lost a packet in the same instant back on the wire
# together 4 s later, recreating the burst that lost it, and counted "no
# lease within 16 s" as a timeout.
DORA_BACKOFF_BASE_S = 4.0
DORA_BACKOFF_CAP_S = 64.0
DORA_BACKOFF_JITTER_S = 1.0
MAX_DORA_RETRIES = 3                    # resends after the first send: 4 waits a round
RENEW_TIMEOUT_S = 4.0
RELEASE_FRACTION = 0.05                 # §3.2: ~5% explicit RELEASE, 95% silent
PROPAGATION_SAMPLE = 1000              # 1-in-1000 arrivals get the propagation probe
SCHED_TICK_S = 0.05                     # timer-wheel resolution
STATS_INTERVAL_S = 10.0                # per-shard NDJSON cadence (§3.5)
STALE_TICKS = 3                         # setpoint staleness fail-safe (3 missed ticks)
SETPOINT_TICK_S = 60.0                 # controller publishes on a 60s tick
DNS_QPS_ACTIVE = 1.0                    # §1.7 per active-online device
ZIPF_S = 1.0                            # §1.7 Zipfian popularity exponent


def dora_retransmit_wait(sends_before: int, rng: random.Random) -> float:
    """Seconds to wait for a reply to a DORA send before retransmitting it.

    ``sends_before`` is how many times the device has already resent in this
    round (``Device.dora_retries``): 0 for the first send, so the waits run
    4, 8, 16, 32 s, then 64 s for good, each ± ``DORA_BACKOFF_JITTER_S``. The
    jitter comes from ``rng`` (the shard's seeded ``random.Random``), so a
    run's schedule is reproducible from its seed while devices that lost a
    packet together no longer resend together."""
    n = min(max(0, sends_before), 16)  # 4 * 2**16 is far past the cap already
    wait = min(DORA_BACKOFF_BASE_S * 2**n, DORA_BACKOFF_CAP_S)
    return wait + rng.uniform(-DORA_BACKOFF_JITTER_S, DORA_BACKOFF_JITTER_S)


class DState(Enum):
    OFFLINE = "OFFLINE"
    DISCOVERING = "DISCOVERING"
    ONLINE = "ONLINE"
    RENEWING = "RENEWING"
    REBINDING = "REBINDING"
    DEPARTING = "DEPARTING"
    LEFT = "LEFT"


@dataclass
class Device:
    index: int
    mac: str
    client_id_bytes: bytes
    hostname: str | None
    subnet_idx: int
    state: DState = DState.OFFLINE
    xid: int = 0
    leased_ip: str | None = None
    server_id: str | None = None
    lease_time: int = 7200
    # pre-built byte templates (built lazily on first need)
    discover_tpl: bytes | None = None
    # timing for latency attribution
    tx_at: float = 0.0
    dora_retries: int = 0
    # propagation-probe membership
    probe: bool = False
    # #1057 — exchange-correlated accounting: the DORA / renewal round this
    # device is on (retransmits keep it, a fresh arrival or a NAK bumps it), the
    # token of the live T1 timer (a re-ACKed lease invalidates the old one), and
    # whether a LEFT device got there by lapsing (a late rebind ACK revives it)
    # or by departing (it does not).
    episode: int = 0
    t1_token: int = 0
    lapsed: bool = False


@dataclass
class SubnetInfo:
    idx: int
    cidr: str
    network: int          # network address as int
    pool_first: int       # first usable pool IP as int
    pool_last: int        # last usable pool IP as int
    giaddr: str | None    # relay giaddr (None in broadcast topology)


@dataclass
class Counters:
    dora_sent: int = 0
    dora_ack: int = 0
    foreign_ack: int = 0   # ACKs whose IP is outside every seeded subnet (perf #454 — wrong DHCP server answered)
    nak: int = 0
    timeout: int = 0
    decline: int = 0
    renew_sent: int = 0
    renew_ack: int = 0
    rebind_sent: int = 0
    rebind_ack: int = 0
    departures: int = 0
    releases: int = 0
    lapses: int = 0
    rearrivals: int = 0
    dns_sent: int = 0
    dns_ok: int = 0
    dns_timeout: int = 0
    # DDNS short-circuit accounting: writes on first DORA vs (incorrect) writes on renew
    ddns_first_publish: int = 0
    ddns_renew_writes: int = 0   # MUST stay 0 (H3) — incremented only if a renewal IP-changes
    renew_ip_changed: int = 0    # named correctness FAIL signal
    # #1057 — exchange-correlated accounting. The fields above keep their
    # meaning (add, never rename: ddi-pg's load tier folds them by name); these
    # make the generator's tally reconcilable with kea's and BIND's own counters.
    dora_offer: int = 0            # OFFERs received, whatever the device was doing
    offer_ignored: int = 0         # OFFERs that found the device not DISCOVERING
    request_sent: int = 0          # SELECTING REQUESTs sent (one per accepted OFFER)
    dora_ack_over_budget: int = 0  # of dora_ack: its exchange's own timer had fired
    dora_ack_resent: int = 0       # of dora_ack: the round had to resend first (no reply in ~4 s)
    dora_ack_late: int = 0         # DORA ACKs after the device gave up (a `timeout` that was slow)
    renew_ack_late: int = 0        # renew ACKs after the renew timer escalated / the device left
    rebind_ack_late: int = 0       # rebind ACKs after the device lapsed (a `lapses` that was slow)
    ack_duplicate: int = 0         # a second ACK for an exchange already closed
    ack_unmatched: int = 0         # an ACK whose xid matches no exchange the ledger knows
    dns_answered: int = 0          # every DNS response received, any rcode (+ dns_rcode_<NAME>)
    dns_error: int = 0             # DNS exceptions that were not timeouts (types in the log)


def _derive_subnets(m: manifest_mod.Manifest, rp: RunPaths, log: Any) -> list[SubnetInfo]:
    """Resolve the seeded subnets — prefer seed-manifest.json, else derive from manifest.

    The seeder records authoritative CIDRs/pool ranges in ``rp.seed_manifest``. When
    it hasn't run yet (smoke / dry build) we derive the same deterministic layout from
    ``seed.ip_block`` + ``seed.subnets`` so the orchestrator is self-contained.
    """
    import ipaddress

    seed = read_json(rp.seed_manifest) or {}
    seeded = seed.get("subnets") or []
    giaddrs = list(m.target.dhcp.giaddr or [])
    relay = m.target.dhcp.topology == "relay"
    out: list[SubnetInfo] = []

    if seeded:
        for i, s in enumerate(seeded):
            cidr = s.get("cidr") or s.get("network")
            net = ipaddress.ip_network(cidr, strict=False)
            first = s.get("pool_first")
            last = s.get("pool_last")
            pf = int(ipaddress.ip_address(first)) if first else int(net.network_address) + 1
            pl = int(ipaddress.ip_address(last)) if last else int(net.broadcast_address) - 1
            out.append(SubnetInfo(
                idx=i, cidr=str(net), network=int(net.network_address),
                pool_first=pf, pool_last=pl,
                giaddr=(giaddrs[i] if relay and i < len(giaddrs) else None),
            ))
        log.info("derived %d subnets from seed-manifest", len(out),
                 extra={"fields": {"event": "subnets_from_seed", "count": len(out)}})
        return out

    # Fallback: carve seed.subnets.count subnets of /prefix from the block.
    block = ipaddress.ip_network(m.seed.ip_block, strict=False)
    count = int(m.seed.subnets.get("count", 8))
    prefix = int(m.seed.subnets.get("prefix", 16))
    pool_frac = float(m.seed.subnets.get("pool_fraction", 0.90))
    subs = list(block.subnets(new_prefix=prefix))[:count]
    for i, net in enumerate(subs):
        usable = max(1, net.num_addresses - 2)
        pool_size = int(usable * pool_frac)
        pf = int(net.network_address) + 1
        pl = pf + pool_size - 1
        out.append(SubnetInfo(
            idx=i, cidr=str(net), network=int(net.network_address),
            pool_first=pf, pool_last=pl,
            giaddr=(giaddrs[i] if relay and i < len(giaddrs) else None),
        ))
    log.info("derived %d subnets from manifest block %s", len(out), m.seed.ip_block,
             extra={"fields": {"event": "subnets_from_manifest", "count": len(out)}})
    return out


class _ZipfNames:
    """Pre-built Zipfian name set per subnet (§1.7: top ~1% absorbs ~50% of queries).

    Names are deterministic from the device fleet so >=95% hit real records:
    forward FQDNs for hostname-bearing device indices + a small NXDOMAIN slice of
    random labels UNDER a seeded zone (authoritative NXDOMAIN, never REFUSED — H4).
    """

    def __init__(self, m: manifest_mod.Manifest, indices: list[int]) -> None:
        zone = (m.seed.dns.forward_zones or ["campus.example.edu"])[0]
        self.zone = zone.rstrip(".")
        self.nxdomain_frac = setpoints_mod.DEFAULT_NXDOMAIN_FRAC
        # Forward names for the hostname-bearing fraction (DDNS-published) + a few
        # always-present seeded service names for SRV/MX coverage.
        names = [fleet.forward_fqdn(fleet.client_hostname(i), self.zone) for i in indices]
        names += [f"_ldap._tcp.{self.zone}", f"_kerberos._udp.{self.zone}",
                  f"mail.{self.zone}", self.zone]
        self.names = names or [self.zone]
        n = len(self.names)
        # Zipf weights (rank^-s) precomputed into a cumulative table for fast draw.
        weights = [1.0 / ((r + 1) ** ZIPF_S) for r in range(n)]
        total = sum(weights)
        cum, acc = [], 0.0
        for w in weights:
            acc += w / total
            cum.append(acc)
        self._cum = cum

    def draw(self, rng: random.Random) -> tuple[str, str, bool]:
        """Return (qname, qtype, expect_nxdomain)."""
        if rng.random() < self.nxdomain_frac:
            # deliberate-miss: random label UNDER the seeded zone (authoritative NXDOMAIN)
            return (f"nx-{rng.randrange(1 << 30)}.{self.zone}", "A", True)
        r = rng.random()
        lo, hi = 0, len(self._cum) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if self._cum[mid] < r:
                lo = mid + 1
            else:
                hi = mid
        name = self.names[lo]
        # qtype mix approximating §1.7 (A-dominant, some PTR/AAAA/SRV).
        qroll = rng.random()
        if name.startswith("_"):
            return (name, "SRV", False)
        if qroll < 0.65:
            return (name, "A", False)
        if qroll < 0.80:
            return (name, "AAAA", False)
        return (name, "A", False)


class Orchestrator:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.rp = RunPaths.for_run(args.run_id, args.run_root)
        self.m = manifest_mod.load(args.manifest)
        self.shard = int(args.shard)
        self.shards = int(args.shards)
        self.log = get_logger(
            f"{SERVICE}.shard{self.shard}", service=SERVICE, run_id=args.run_id,
            logfile=str(self.rp.worker_log(f"orchestrator.shard{self.shard}")),
        )
        self.stats_path = self.rp.generator(f"orchestrator.shard{self.shard}.ndjson")
        self.lifecycle = LifecycleLog(self.rp, self.shard)
        self.rng = random.Random(0xC0FFEE ^ self.shard)

        self.node_ip = self.m.target.node_ip
        self.dhcp_port = self.m.target.dhcp.port
        self.relay = self.m.target.dhcp.topology == "relay"

        self.subnets = _derive_subnets(self.m, self.rp, self.log)
        self.n_subnets = len(self.subnets)
        # perf #454 — foreign-responder guard. On a shared LAN the site's
        # production DHCP server can win the broadcast race and ACK from a
        # different subnet; a lease outside every seeded subnet means we're
        # measuring the wrong server. Precompute the seeded networks once.
        import ipaddress as _ipa  # noqa: PLC0415
        self._seeded_nets = [_ipa.ip_network(s.cidr, strict=False) for s in self.subnets]
        self._foreign_warned = False

        # Disjoint device index range for this shard (sharded over unique_devices).
        self.indices = list(fleet.shard_indices(self.m.scale.unique_devices, self.shard, self.shards))
        self.hostname_fraction = self.m.scale.hostname_fraction

        # Latency accumulators (DORA + renew SEPARATELY, DNS resolve, both prop legs).
        self.lat_dora = LatencyAccumulator("dhcp_dora_ack")
        # Late DORA ACKs (after the device gave up) get their own histogram so
        # the strict one keeps its meaning and the slow tail is still visible.
        self.lat_dora_late = LatencyAccumulator("dhcp_dora_ack_late")
        self.lat_renew = LatencyAccumulator("dhcp_renew_ack")
        self.lat_dns = LatencyAccumulator("dns_resolve")
        self.lat_prop_ipam = LatencyAccumulator("propagation_lease_to_ipam")
        self.lat_prop_dns = LatencyAccumulator("propagation_ipam_to_dns")

        self.counters = Counters()
        self.devices: dict[int, Device] = {}
        self.online_set: set[int] = set()
        # Every in-flight (and recently closed) DHCP exchange keyed by xid: the
        # reply is attributed to the exchange it answers, not to whatever the
        # device happens to be doing when it arrives (#1057).
        self.ledger = ExchangeLedger()
        self.dns_tally = DnsTally()
        # timer wheel: due_time -> list[(index, action)]
        self._timers: list[tuple[float, int, str]] = []  # min-heap of (when, index, action)

        self._stop = asyncio.Event()
        self._sock: socket.socket | None = None
        # Relay topology: giaddr -> the socket bound to that address (see
        # open_relay_sockets); a giaddr without its own socket sends and receives
        # on the wildcard ``_sock``.
        self._socks: dict[str, socket.socket] = {}
        self._last_seen_tick = -1
        self._tick_seen_at = time.monotonic()
        self._arrival_accum = 0.0
        self._dns_accum = 0.0
        self._zipf: dict[int, _ZipfNames] = {}
        self._sched_lag_max = 0.0
        self._probe_counter = 0

        # Build identity for our shard's devices (lazy template build on demand).
        for idx in self.indices:
            mac = fleet.device_mac(idx)
            cid = bytes.fromhex(fleet.client_id_for_mac(mac).replace(":", ""))
            has_host = (idx % 100) < int(round(self.hostname_fraction * 100))
            host = fleet.client_hostname(idx) if has_host else None
            self.devices[idx] = Device(
                index=idx, mac=mac, client_id_bytes=cid, hostname=host,
                subnet_idx=fleet.assign_subnet(idx, self.n_subnets),
            )
        # Per-subnet Zipf name sets from the hostname-bearing indices in that subnet.
        for s in self.subnets:
            hidx = [d.index for d in self.devices.values()
                    if d.subnet_idx == s.idx and d.hostname]
            self._zipf[s.idx] = _ZipfNames(self.m, hidx)

    # ---------------- socket ----------------
    def _open_socket(self) -> None:
        iface = getattr(self.m.target.dhcp, "iface", "") or ""
        # Relay topology: bind to the relay/server port (67) so Kea unicasts replies
        # to giaddr:67 back to us. Broadcast topology: bind to the client port (68).
        bind_port = 67 if self.relay else 68
        giaddrs = [s.giaddr for s in self.subnets if s.giaddr] if self.relay else []
        try:
            self._sock, self._socks = open_relay_sockets(
                iface, giaddrs, bind_port, self.log)
        except PermissionError:
            self.log.error(
                "binding UDP/%d needs CAP_NET_BIND_SERVICE (run the load-gen "
                "as root or grant the cap)", bind_port,
                extra={"fields": {"event": "bind_denied", "port": bind_port}},
            )
            raise
        self.log.info("dhcp socket bound", extra={"fields": {
            "event": "socket_open", "bind_port": bind_port,
            "topology": self.m.target.dhcp.topology,
            "giaddr_sockets": len(self._socks), "giaddrs": len(set(giaddrs))}})

    def _sock_for(self, dev: Device) -> socket.socket | None:
        if self.relay and self._socks:
            return self._socks.get(self.subnets[dev.subnet_idx].giaddr, self._sock)
        return self._sock

    # ---------------- timer wheel ----------------
    def _schedule(self, delay: float, index: int, action: str) -> None:
        import heapq
        heapq.heappush(self._timers, (time.monotonic() + delay, index, action))

    def _due(self, now: float) -> list[tuple[int, str]]:
        import heapq
        out = []
        while self._timers and self._timers[0][0] <= now:
            when, idx, action = heapq.heappop(self._timers)
            lag = now - when
            if lag > self._sched_lag_max:
                self._sched_lag_max = lag
            out.append((idx, action))
        return out

    # ---------------- DHCP send paths ----------------
    def _new_xid(self, dev: Device) -> int:
        # xid encodes the device index in the low 24 bits + a per-attempt nonce in the
        # high byte → cheap recv correlation while staying unique across re-sends.
        # The nonce must not collide with an exchange of this device the ledger
        # still knows, or the reply would be attributed to the older send.
        xid = dev.index & 0xFFFFFF
        for _ in range(8):
            nonce = self.rng.randrange(256)
            xid = ((nonce & 0xFF) << 24) | (dev.index & 0xFFFFFF)
            if self.ledger.get(xid) is None:
                break
        return xid

    def _send(self, pkt: bytes, dev: Device) -> None:
        sock = self._sock_for(dev)
        if sock is None:
            return
        if self.relay:
            # Unicast to Kea; subnet selection is by giaddr (kea.py:237-241). The
            # socket bound to this device's giaddr sends it, so the datagram's
            # source address is the relay address Kea answers to.
            dest = (self.node_ip, self.dhcp_port)
        else:
            # Broadcast on the local L2 segment (kea.py interfaces ["*"]).
            dest = ("255.255.255.255", self.dhcp_port)
        try:
            sock.sendto(pkt, dest)
        except OSError as exc:
            self.log.debug("send failed: %s", exc,
                           extra={"fields": {"event": "send_error", "index": dev.index}})

    def _dora_wait(self, dev: Device) -> float:
        """The reply wait for the DORA send about to go out: the round's backoff
        step for this device (``dora_retransmit_wait``), jittered from the
        shard's seeded RNG."""
        return dora_retransmit_wait(dev.dora_retries, self.rng)

    def _send_discover(self, dev: Device, *, new_round: bool) -> None:
        """A DISCOVER. ``new_round`` opens a fresh DORA round (arrival, re-arrival,
        NAK) and starts its backoff from the first step, as a client back in
        INIT does; a retransmit after ``dora_timeout`` keeps the round, so a
        reply to any of its sends still belongs to it."""
        if dev.discover_tpl is None:
            dev.discover_tpl = dp.build_discover(
                mac=dev.mac, client_id=dev.client_id_bytes,
                hostname=dev.hostname, broadcast=not self.relay,
            )
        pkt = bytearray(dev.discover_tpl)
        dev.xid = self._new_xid(dev)
        giaddr = self.subnets[dev.subnet_idx].giaddr if self.relay else None
        dp.patch_send_fields(pkt, xid=dev.xid, giaddr=giaddr)
        if new_round:
            dev.episode += 1
            dev.lapsed = False
            dev.dora_retries = 0
        dev.state = DState.DISCOVERING
        dev.tx_at = time.monotonic()
        self.ledger.open(dev.xid, dev.index, KIND_DISCOVER, dev.tx_at, dev.episode)
        self._send(bytes(pkt), dev)
        self.counters.dora_sent += 1
        # The timer belongs to THIS exchange (#1057): it retransmits only if this
        # send is still the device's live one when it fires — a DISCOVER's
        # deadline no longer fires over the REQUEST that answered its OFFER.
        self._schedule(self._dora_wait(dev), dev.index, f"dora_timeout:{dev.xid}")

    def _send_request_renew(self, dev: Device) -> None:
        assert dev.leased_ip
        pkt = bytearray(dp.build_request_renew(
            mac=dev.mac, client_id=dev.client_id_bytes,
            hostname=dev.hostname, leased_ip=dev.leased_ip))
        dev.xid = self._new_xid(dev)
        dp.patch_send_fields(pkt, xid=dev.xid)  # NO giaddr — renew is unicast direct
        dev.state = DState.RENEWING
        dev.episode += 1
        dev.tx_at = time.monotonic()
        self.ledger.open(dev.xid, dev.index, KIND_RENEW, dev.tx_at, dev.episode)
        self._send(bytes(pkt), dev)
        self.counters.renew_sent += 1
        self._schedule(RENEW_TIMEOUT_S, dev.index, f"renew_timeout:{dev.xid}")

    def _send_request_rebind(self, dev: Device) -> None:
        assert dev.leased_ip
        pkt = bytearray(dp.build_request_rebind(
            mac=dev.mac, client_id=dev.client_id_bytes,
            hostname=dev.hostname, leased_ip=dev.leased_ip))
        dev.xid = self._new_xid(dev)
        giaddr = self.subnets[dev.subnet_idx].giaddr if self.relay else None
        dp.patch_send_fields(pkt, xid=dev.xid, giaddr=giaddr)
        dev.state = DState.REBINDING
        dev.tx_at = time.monotonic()
        self.ledger.open(dev.xid, dev.index, KIND_REBIND, dev.tx_at, dev.episode)
        self._send(bytes(pkt), dev)
        self.counters.rebind_sent += 1
        self._schedule(RENEW_TIMEOUT_S, dev.index, f"rebind_timeout:{dev.xid}")

    def _send_request_selecting(self, dev: Device, offered_ip: str, server_id: str) -> None:
        pkt = bytearray(dp.build_request_selecting(
            mac=dev.mac, client_id=dev.client_id_bytes, hostname=dev.hostname,
            requested_ip=offered_ip, server_id=server_id, broadcast=not self.relay))
        dev.xid = self._new_xid(dev)
        giaddr = self.subnets[dev.subnet_idx].giaddr if self.relay else None
        dp.patch_send_fields(pkt, xid=dev.xid, giaddr=giaddr)
        dev.tx_at = time.monotonic()  # the DORA latency is the REQUEST->ACK leg (unchanged)
        self.ledger.open(dev.xid, dev.index, KIND_SELECT, dev.tx_at, dev.episode)
        self._send(bytes(pkt), dev)
        self.counters.request_sent += 1
        # Same step as the DISCOVER it answers: the REQUEST shares the round's
        # dora_retries, and an unanswered one falls back to a DISCOVER at the
        # next step, so a round still ends after 4 waits (≈60 s).
        self._schedule(self._dora_wait(dev), dev.index, f"dora_timeout:{dev.xid}")

    def _schedule_t1(self, dev: Device) -> None:
        """(Re)arm the T1 renewal for the lease the device holds now. The token
        retires any earlier T1 timer, so a lease re-ACKed twice (a late renew
        ACK and then the rebind's) renews once, not twice."""
        dev.t1_token += 1
        self._schedule(T1_RENEW_S, dev.index, f"t1_renew:{dev.t1_token}")

    def _send_release(self, dev: Device) -> None:
        if not (dev.leased_ip and dev.server_id):
            return
        pkt = bytearray(dp.build_release(
            mac=dev.mac, client_id=dev.client_id_bytes,
            leased_ip=dev.leased_ip, server_id=dev.server_id))
        dev.xid = self._new_xid(dev)
        dp.patch_send_fields(pkt, xid=dev.xid)
        self._send(bytes(pkt), dev)
        self.counters.releases += 1

    # ---------------- FSM event handlers ----------------
    def _on_offer(self, dev: Device, reply: dict, ex: Exchange | None, now: float) -> None:
        self.counters.dora_offer += 1
        if dev.state is not DState.DISCOVERING:
            # A late or duplicate OFFER: the device already took a lease or gave
            # up, so nobody is selecting. Counted so kea's OFFER tally reconciles
            # with ours; the FSM does not move.
            self.counters.offer_ignored += 1
            if ex is not None and ex.open:
                self.ledger.close(ex.xid, now, "offer")
            return
        # SELECTING: accept the OFFER with a REQUEST(opt-50/opt-54).
        offered = reply.get("yiaddr")
        sid = reply.get("server_id") or offered
        if not offered or offered == "0.0.0.0":
            return
        if ex is not None and ex.open:
            # The DISCOVER is answered: its own timer must not retransmit it.
            self.ledger.close(ex.xid, now, "offer")
        self._send_request_selecting(dev, offered, sid)

    def _ip_in_seeded_subnet(self, ip: str) -> bool:
        """True if ``ip`` falls within any seeded subnet (perf #454 foreign-responder guard)."""
        import ipaddress as _ipa  # noqa: PLC0415
        try:
            addr = _ipa.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._seeded_nets)

    def _on_ack(self, dev: Device, reply: dict, now: float, ex: Exchange | None) -> None:
        """Attribute an ACK to the exchange it answers (#1057). Before, the
        device's state at arrival decided what the ACK meant — and after
        MAX_DORA_RETRIES the device was OFFLINE, so the ACK that answered its
        last REQUEST matched no branch: counted as a timeout already, then
        dropped with the lease kea had just allocated."""
        if ex is None:
            self.counters.ack_unmatched += 1
            self.log.debug("ACK for an xid the ledger does not know",
                           extra={"fields": {"event": "ack_unmatched", "index": dev.index,
                                             "xid": reply.get("xid")}})
            return
        closed = self.ledger.close(ex.xid, now, "ack")
        if closed is None or closed.duplicate:
            self.counters.ack_duplicate += 1
            return
        latency_ms = (now - ex.tx_at) * 1000.0  # the leg this ACK actually closes
        if ex.kind in DORA_KINDS:
            self._on_dora_ack(dev, reply, ex, closed, latency_ms, now)
        else:
            self._on_renewal_ack(dev, reply, ex, closed, latency_ms, now)

    def _on_dora_ack(self, dev: Device, reply: dict, ex: Exchange, closed: Closed,
                     latency_ms: float, now: float) -> None:
        new_ip = reply.get("yiaddr")
        # perf #454 — foreign-responder guard. If the leased IP is outside
        # every seeded subnet, a DIFFERENT DHCP server answered (e.g. the
        # site router on a shared LAN) — we're not testing the appliance's
        # Kea. Count it and warn loudly (once) so the run isn't silently
        # measuring the wrong server. Use an isolated VLAN or relay topology.
        if new_ip and self._seeded_nets and not self._ip_in_seeded_subnet(new_ip):
            self.counters.foreign_ack += 1
            if not self._foreign_warned:
                self._foreign_warned = True
                self.log.error(
                    "DHCP ACK from a FOREIGN server — leased IP %s is outside "
                    "every seeded subnet. A non-appliance DHCP server is winning "
                    "the broadcast race; use an isolated test VLAN or relay "
                    "topology (perf #454).", new_ip,
                    extra={"fields": {"event": "foreign_dhcp_responder",
                                      "leased_ip": new_ip, "server_id": reply.get("server_id")}})
        if closed.late:
            # The device had given up (its `timeout` is already counted). Kea's
            # ACK still allocated the lease: count it under its own name, keep
            # its latency apart from the strict histogram, and take the lease
            # unless a newer round already holds one — the server holds it, and
            # a model that ignores it drifts from the server it measures.
            self.counters.dora_ack_late += 1
            self.lat_dora_late.record_ms(latency_ms)
            self.lifecycle.emit(mac=dev.mac, index=dev.index, event="dora_ack_late",
                                ip=new_ip, ack_ms=round(latency_ms, 2),
                                late_by_s=round(now - (ex.gave_up_at or now), 2),
                                ddns=bool(dev.hostname))
            if dev.leased_ip is not None:
                return
            if dev.hostname:
                self.counters.ddns_first_publish += 1
            self._take_lease(dev, reply, now)
            return
        # DORA ACK — first lease (or re-lease after re-arrival), before the
        # device gave up: the pre-#1057 meaning of dora_ack, retries included.
        self.counters.dora_ack += 1
        if closed.over_budget:
            self.counters.dora_ack_over_budget += 1
        # A lease that took a resend is a success the round had to work for:
        # with the backoff a round runs ≈60 s before it is a `timeout`, so
        # this is what keeps a slow handshake visible (read before
        # _take_lease clears the round's retry count).
        resends = dev.dora_retries
        if resends or closed.over_budget:
            self.counters.dora_ack_resent += 1
        self.lat_dora.record_ms(latency_ms)
        # DDNS coupling happens ONLY on first DORA (hostname-bearing devices).
        if dev.hostname:
            self.counters.ddns_first_publish += 1
        self.lifecycle.emit(mac=dev.mac, index=dev.index, event="dora_ack",
                            ip=new_ip, ack_ms=round(latency_ms, 2),
                            ddns=bool(dev.hostname), over_budget=closed.over_budget,
                            resends=resends)
        self._take_lease(dev, reply, now)
        # Propagation probe membership (1-in-1000 arrivals).
        if dev.probe:
            self._schedule(0.0, dev.index, "probe_start")

    def _take_lease(self, dev: Device, reply: dict, now: float) -> None:
        """The ACK's lease becomes the device's: ONLINE, T1 armed, every other
        exchange of the DORA round (a retransmit still in flight) settled."""
        dev.leased_ip = reply.get("yiaddr")
        dev.server_id = reply.get("server_id") or dev.server_id
        dev.lease_time = int(reply.get("lease_time", self.m.scale.lease_time_s))
        dev.state = DState.ONLINE
        dev.lapsed = False
        dev.dora_retries = 0
        self.online_set.add(dev.index)
        self.ledger.settle(dev.index, now, kinds=DORA_KINDS)
        # Self-schedule the next renewal at T1=900s (renewals self-track online).
        self._schedule_t1(dev)

    def _on_renewal_ack(self, dev: Device, reply: dict, ex: Exchange, closed: Closed,
                        latency_ms: float, now: float) -> None:
        new_ip = reply.get("yiaddr")
        # RENEW/REBIND ACK — HARD CONTRACT: same IP. A changed IP is a FAIL.
        if new_ip and dev.leased_ip and new_ip != dev.leased_ip:
            self.counters.renew_ip_changed += 1
            self.counters.ddns_renew_writes += 1  # would trigger the 6-write cascade
            self.log.error(
                "RENEWAL LANDED ON A DIFFERENT IP — correctness FAIL (H3)",
                extra={"fields": {"event": "renew_ip_changed", "index": dev.index,
                                  "old_ip": dev.leased_ip, "new_ip": new_ip}})
            self.lifecycle.emit(mac=dev.mac, index=dev.index, event="renew_ip_changed",
                                old_ip=dev.leased_ip, new_ip=new_ip)
            dev.leased_ip = new_ip
        renew = ex.kind == KIND_RENEW
        if closed.late:
            # After RENEW_TIMEOUT_S escalated the device (renew), after it lapsed
            # (rebind), or after it departed with the request in flight. Kea
            # answered; the count says so under its own name, whatever state
            # the reply found. Its latency stays out of the strict histogram.
            if renew:
                self.counters.renew_ack_late += 1
            else:
                self.counters.rebind_ack_late += 1
            event = "renew_ack_late"
        else:
            if renew:
                self.counters.renew_ack += 1
            else:
                self.counters.rebind_ack += 1
            self.lat_renew.record_ms(latency_ms)
            event = "renew_ack"
        self.lifecycle.emit(mac=dev.mac, index=dev.index, event=event,
                            ip=dev.leased_ip or new_ip, ack_ms=round(latency_ms, 2),
                            kind=ex.kind)
        if dev.state in (DState.RENEWING, DState.REBINDING):
            # The lease is renewed. A late renew ACK arriving while the rebind
            # is in flight leaves that exchange open: kea will ACK it too, and
            # that ACK counts on its own (two ACKs from kea, two here).
            dev.state = DState.ONLINE
            if dev.leased_ip is None:
                dev.leased_ip = new_ip
            self._schedule_t1(dev)
        elif dev.state is DState.LEFT and dev.lapsed and new_ip:
            # Lapsed (rebind timed out), then kea's rebind ACK arrived: the
            # server extended the lease, so the device is back ONLINE with it.
            # A device that DEPARTED is left alone — its lease expires
            # server-side exactly as a silent departure should (§3.2).
            self.lifecycle.emit(mac=dev.mac, index=dev.index, event="lapse_revived", ip=new_ip)
            dev.leased_ip = new_ip
            dev.state = DState.ONLINE
            dev.lapsed = False
            self.online_set.add(dev.index)
            self._schedule_t1(dev)

    def _on_nak(self, dev: Device, ex: Exchange | None, now: float) -> None:
        self.counters.nak += 1
        if ex is not None:
            self.ledger.close(ex.xid, now, "nak")
        self.lifecycle.emit(mac=dev.mac, index=dev.index, event="nak")
        # NAK → fall back to a fresh DISCOVER (lease invalid). Every other
        # exchange of the device is over with it.
        dev.leased_ip = None
        self.online_set.discard(dev.index)
        self.ledger.settle(dev.index, now, reason="abandoned")
        self._send_discover(dev, new_round=True)

    def _timer_exchange(self, dev: Device, arg: str, now: float) -> tuple[int, bool]:
        """(xid, live) for an exchange-scoped timer: ``live`` when the exchange
        is still open AND still the device's current send — the only case a
        deadline may act on. Anything else (answered, superseded by a later
        send of the same round, already retired) is marked expired and left."""
        xid = int(arg) if arg else dev.xid
        ex = self.ledger.get(xid)
        if ex is None or not ex.open:
            return xid, False
        self.ledger.expire(xid, now)
        return xid, dev.xid == xid

    def _handle_timer(self, idx: int, action: str, now: float) -> None:
        dev = self.devices.get(idx)
        if dev is None:
            return
        # Timers carry the exchange (or T1 token) they belong to: "name:arg".
        name, _sep, arg = action.partition(":")
        if name == "arrival":
            if dev.state in (DState.OFFLINE, DState.LEFT):
                if dev.state is DState.LEFT:
                    self.counters.rearrivals += 1
                    self.lifecycle.emit(mac=dev.mac, index=dev.index, event="rearrival")
                else:
                    self.lifecycle.emit(mac=dev.mac, index=dev.index, event="arrival")
                # sample propagation-probe membership
                self._probe_counter += 1
                dev.probe = (self._probe_counter % PROPAGATION_SAMPLE) == 0
                self._send_discover(dev, new_round=True)
        elif name == "dora_timeout":
            _xid, live = self._timer_exchange(dev, arg, now)
            if live and dev.state is DState.DISCOVERING:
                dev.dora_retries += 1
                if dev.dora_retries <= MAX_DORA_RETRIES:
                    self._send_discover(dev, new_round=False)
                else:
                    self.counters.timeout += 1
                    # Every open exchange of the round is marked: a reply that
                    # still arrives is a late ACK, counted as such (#1057).
                    self.ledger.give_up(dev.index, now, DORA_KINDS)
                    dev.state = DState.OFFLINE
                    dev.dora_retries = 0
                    self.lifecycle.emit(mac=dev.mac, index=dev.index, event="timeout")
        elif name == "t1_renew":
            if arg and int(arg) != dev.t1_token:
                return  # retired: the lease was re-ACKed since and re-armed T1
            if dev.state is DState.ONLINE and dev.leased_ip:
                self._send_request_renew(dev)
        elif name == "renew_timeout":
            _xid, live = self._timer_exchange(dev, arg, now)
            if live and dev.state is DState.RENEWING:
                # T1 unanswered → escalate to REBINDING at T2. The renew leg is
                # abandoned: its ACK, if it still comes, is a late renew ACK.
                self.ledger.give_up(dev.index, now, frozenset({KIND_RENEW}))
                self._send_request_rebind(dev)
        elif name == "rebind_timeout":
            _xid, live = self._timer_exchange(dev, arg, now)
            if live and dev.state is DState.REBINDING:
                self.counters.lapses += 1
                self.ledger.give_up(dev.index, now, frozenset({KIND_RENEW, KIND_REBIND}))
                self.online_set.discard(dev.index)
                dev.state = DState.LEFT
                dev.leased_ip = None
                dev.lapsed = True
                self.lifecycle.emit(mac=dev.mac, index=dev.index, event="lapse")
        elif name == "depart":
            if dev.state in (DState.ONLINE, DState.RENEWING, DState.REBINDING):
                self.counters.departures += 1
                if self.rng.random() < RELEASE_FRACTION:
                    self._send_release(dev)
                    self.lifecycle.emit(mac=dev.mac, index=dev.index, event="release",
                                        ip=dev.leased_ip)
                else:
                    self.lifecycle.emit(mac=dev.mac, index=dev.index, event="depart_silent",
                                        ip=dev.leased_ip)
                # A renewal still in flight is abandoned with the device: its
                # ACK, if it comes, is counted late and moves nothing.
                self.ledger.give_up(dev.index, now)
                self.online_set.discard(dev.index)
                dev.state = DState.LEFT
                dev.leased_ip = None
                dev.lapsed = False
        elif name == "probe_start":
            asyncio.ensure_future(self._run_propagation_probe(dev))

    # ---------------- receive loop ----------------
    async def _recv_loop(self, sock: socket.socket | None = None) -> None:
        loop = asyncio.get_running_loop()
        sock = sock or self._sock
        assert sock
        while not self._stop.is_set():
            try:
                data = await loop.sock_recv(sock, 2048)
            except (BlockingIOError, InterruptedError):
                await asyncio.sleep(0.001)
                continue
            except OSError:
                if self._stop.is_set():
                    break
                await asyncio.sleep(0.01)
                continue
            reply = dp.parse_reply(data)
            if not reply:
                continue
            xid = reply.get("xid")
            ex = self.ledger.get(xid)
            if ex is not None:
                idx = ex.index
            else:
                idx = xid & 0xFFFFFF if xid is not None else None  # recover from low bits
                if idx not in self.devices:
                    continue
            dev = self.devices[idx]
            mt = reply.get("msg_type")
            now = time.monotonic()
            if mt == dp.DHCPOFFER:
                self._on_offer(dev, reply, ex, now)
            elif mt == dp.DHCPACK:
                self._on_ack(dev, reply, now, ex)
            elif mt == dp.DHCPNAK:
                self._on_nak(dev, ex, now)

    # ---------------- scheduler loop ----------------
    async def _scheduler_loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            for idx, action in self._due(now):
                self._handle_timer(idx, action, now)
            self.ledger.purge(now)
            await asyncio.sleep(SCHED_TICK_S)

    # ---------------- arrival / departure / dns drivers (setpoint-driven) ----------------
    async def _control_loop(self) -> None:
        """Reads the setpoint each tick; trues-up arrivals + departures + DNS rate."""
        last_pace = time.monotonic()
        while not self._stop.is_set():
            if self.rp.stop_file.exists():
                self.log.warning("kill-switch present — stopping",
                                 extra={"fields": {"event": "kill_switch"}})
                self._stop.set()
                break
            sp = setpoints_mod.read_current(self.rp)
            sp = self._check_stale(sp)
            now = time.monotonic()
            dt = now - last_pace
            last_pace = now
            if sp is not None and not self._failsafe:
                self._drive_arrivals(sp, dt)
                self._drive_departures(sp)
                self._drive_dns(sp, dt)
            await asyncio.sleep(0.25)

    _failsafe = False

    def _check_stale(self, sp: setpoints_mod.Setpoint | None):
        now = time.monotonic()
        if sp is None:
            return None
        if sp.tick != self._last_seen_tick:
            self._last_seen_tick = sp.tick
            self._tick_seen_at = now
            self._failsafe = False
        elif now - self._tick_seen_at > STALE_TICKS * SETPOINT_TICK_S:
            if not self._failsafe:
                self.log.error(
                    "setpoint stale for >%ds — failing safe to OFF (no new load)",
                    int(STALE_TICKS * SETPOINT_TICK_S),
                    extra={"fields": {"event": "setpoint_stale", "tick": sp.tick}})
            self._failsafe = True
        return sp

    def _shard_share(self, total: float) -> float:
        """This shard's slice of a fleet-wide rate (even split across shards)."""
        return total / max(1, self.shards)

    def _drive_arrivals(self, sp: setpoints_mod.Setpoint, dt: float) -> None:
        # Bring devices toward sp.active_devices (this shard's share) AND honor the
        # explicit new_dora_per_s arrival rate. Arrivals = max(deficit-fill, dora rate).
        target_online = int(round(self._shard_share(sp.active_devices)))
        cur_online = len(self.online_set)
        dora_rate = self._shard_share(sp.new_dora_per_s)
        self._arrival_accum += dora_rate * dt
        # also fill a concurrency deficit faster during ramp (bounded per pass)
        deficit = max(0, target_online - cur_online)
        to_arrive = int(self._arrival_accum) + min(deficit, 200)
        self._arrival_accum -= int(self._arrival_accum)
        if to_arrive <= 0:
            return
        offline = [d for d in self.devices.values()
                   if d.state in (DState.OFFLINE, DState.LEFT)]
        self.rng.shuffle(offline)
        for dev in offline[:to_arrive]:
            self._schedule(self.rng.random() * 0.5, dev.index, "arrival")

    def _drive_departures(self, sp: setpoints_mod.Setpoint) -> None:
        # If online exceeds target, depart the surplus (commuters leave).
        target_online = int(round(self._shard_share(sp.active_devices)))
        surplus = len(self.online_set) - target_online
        if surplus <= 0:
            return
        leaving = list(self.online_set)[: min(surplus, 200)]
        for idx in leaving:
            self._schedule(self.rng.random() * 1.0, idx, "depart")

    def _drive_dns(self, sp: setpoints_mod.Setpoint, dt: float) -> None:
        # Aggregate Poisson DNS stream across online devices: target qps = min(setpoint
        # share, per-device model). We dispatch floor(rate*dt) queries this pass.
        if not _HAVE_DNSPYTHON:
            return  # no DNS client available — DNS stream is owned by dnsperf instead
        online = len(self.online_set)
        if online == 0:
            return
        model_qps = online * DNS_QPS_ACTIVE
        setpoint_qps = self._shard_share(sp.dns_qps)
        # The orchestrator emits the realistic per-device stream; cap at the setpoint
        # share so dnsperf owns the raw-ceiling headroom above it (§4.7).
        qps = min(model_qps, setpoint_qps) if setpoint_qps > 0 else model_qps
        self._dns_accum += qps * dt
        n = int(self._dns_accum)
        self._dns_accum -= n
        for _ in range(min(n, 500)):  # bound per pass; surplus rolls into accum
            idx = self.rng.choice(tuple(self.online_set))
            asyncio.ensure_future(self._dns_query(self.devices[idx]))

    # ---------------- DNS query (dnspython async) ----------------
    async def _dns_query(self, dev: Device) -> None:
        if not _HAVE_DNSPYTHON:
            return
        z = self._zipf[dev.subnet_idx]
        qname, qtype, _expect_nx = z.draw(self.rng)
        try:
            q = _dns_msg.make_query(qname, qtype)
        except Exception:
            return
        t0 = time.monotonic()
        self.counters.dns_sent += 1
        try:
            resp = await _dns_aq.udp(
                q, self.node_ip, port=self.m.target.dns.port, timeout=2.0)
        except _DNS_TIMEOUT_EXC:
            self.counters.dns_timeout += 1
            return
        except Exception as exc:  # noqa: BLE001 — every exception is counted, by type
            self.counters.dns_error += 1
            if self.dns_tally.error(type(exc).__name__):
                self.log.warning("DNS query failed: %s: %s", type(exc).__name__, exc,
                                 extra={"fields": {"event": "dns_query_error",
                                                   "error_type": type(exc).__name__}})
            return
        latency_ms = (time.monotonic() - t0) * 1000.0
        self.lat_dns.record_ms(latency_ms)
        # Every answer is counted under its rcode (#1057): before, REFUSED /
        # SERVFAIL / FORMERR answers were counted as nothing, and a run whose
        # 606k queries BIND refused read "ok 0, timeouts 46".
        rc = resp.rcode()
        self.counters.dns_answered += 1
        self.dns_tally.answered(rcode_name(rc, _dns_rcode.to_text))
        if rc in (_dns_rcode.NOERROR, _dns_rcode.NXDOMAIN):
            self.counters.dns_ok += 1

    # ---------------- propagation-lag probe (single-clock) ----------------
    async def _run_propagation_probe(self, dev: Device) -> None:
        """On a sampled arrival: t_lease -> poll IPAM mirror -> dig A/PTR (§3.4 #3).

        Both legs are timestamped by the orchestrator (single-clock) so they're robust
        to cross-box skew. lease->IPAM = the auto_from_lease row appears; IPAM->DNS =
        the A resolves (DDNS landed). Budget ~5-12s; we give up at 30s and record a
        miss so a stuck pipeline doesn't hang the probe forever.
        """
        if not dev.leased_ip:
            return
        t_lease = time.monotonic()
        ip = dev.leased_ip
        subnet = self.subnets[dev.subnet_idx]
        # leg 1: lease -> IPAM mirror row (API poll).
        ipam_seen = await self._poll_ipam_mirror(subnet, ip, deadline_s=30.0)
        if ipam_seen is not None:
            self.lat_prop_ipam.record_ms((ipam_seen - t_lease) * 1000.0)
        # leg 2: IPAM -> DNS resolves (only for DDNS hostname-bearing devices).
        if dev.hostname:
            zone = (self.m.seed.dns.forward_zones or ["campus.example.edu"])[0]
            fqdn = fleet.forward_fqdn(dev.hostname, zone)
            dns_seen = await self._poll_dns_resolves(fqdn, ip, deadline_s=30.0)
            if dns_seen is not None:
                self.lat_prop_dns.record_ms((dns_seen - t_lease) * 1000.0)
        self.lifecycle.emit(mac=dev.mac, index=dev.index, event="propagation_probe",
                            ip=ip, ipam_ok=ipam_seen is not None)

    async def _poll_ipam_mirror(self, subnet: SubnetInfo, ip: str, deadline_s: float):
        """Poll GET /ipam/subnets/{id}/addresses for the auto_from_lease row.

        Grounded: list_addresses at backend/app/api/v1/ipam/router.py:5957 returns
        IPAddressResponse{address, auto_from_lease, ...} (router.py:2269). No
        lookup-by-IP-string endpoint exists, so we scan the subnet's address list — an
        open_item at 150k rows (see module docstring); the probe is 1-in-1000 so the
        cost is bounded. We need the subnet's UUID; the seed-manifest carries it.
        """
        subnet_uuid = self._subnet_uuid(subnet.idx)
        if subnet_uuid is None:
            return None
        token = os.environ.get(self.m.observability.superadmin_token_env)
        if not token:
            return None
        import httpx
        url = f"{self.m.target.api_base}/ipam/subnets/{subnet_uuid}/addresses"
        verify = os.environ.get("SPDDI_PERF_CA_BUNDLE", False)
        deadline = time.monotonic() + deadline_s
        async with httpx.AsyncClient(verify=verify, timeout=5.0,
                                     headers={"Authorization": f"Bearer {token}"}) as c:
            while time.monotonic() < deadline and not self._stop.is_set():
                try:
                    r = await c.get(url, params={"status_filter": "dhcp"})
                    if r.status_code == 200:
                        for row in r.json():
                            if row.get("address") == ip and row.get("auto_from_lease"):
                                return time.monotonic()
                    # status_filter may not match the mirror status; fall back to full list
                    r2 = await c.get(url)
                    if r2.status_code == 200:
                        for row in r2.json():
                            if row.get("address") == ip:
                                return time.monotonic()
                except httpx.HTTPError:
                    # Transient API/network errors are expected while the IPAM mirror
                    # propagates; fall through to the sleep below and retry until deadline.
                    pass
                await asyncio.sleep(0.5)
        return None

    async def _poll_dns_resolves(self, fqdn: str, ip: str, deadline_s: float):
        """dig the A record every 250ms until it answers ``ip`` (§4.6.3)."""
        if not _HAVE_DNSPYTHON:
            return None
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline and not self._stop.is_set():
            try:
                q = _dns_msg.make_query(fqdn, "A")
                resp = await _dns_aq.udp(
                    q, self.node_ip, port=self.m.target.dns.port, timeout=1.0)
                for rrset in resp.answer:
                    for item in rrset:
                        if str(item) == ip:
                            return time.monotonic()
            except Exception:
                # Transient DNS errors (NXDOMAIN/timeout) are expected during
                # propagation; fall through to the sleep below and retry until deadline.
                pass
            await asyncio.sleep(0.25)
        return None

    def _subnet_uuid(self, idx: int) -> str | None:
        # seed_scaffold writes each subnet row as {"id","network","index"}
        # (seed_scaffold.py:356) — match those keys, not "idx"/"cidr".
        seed = read_json(self.rp.seed_manifest) or {}
        target_cidr = self.subnets[idx].cidr
        for s in seed.get("subnets", []):
            if s.get("index") == idx or (s.get("network") or s.get("cidr")) == target_cidr:
                return s.get("id") or s.get("subnet_id")
        return None

    # ---------------- per-shard stats emitter ----------------
    async def _stats_loop(self) -> None:
        last = dict(self._counter_snapshot())
        last_t = time.monotonic()
        while not self._stop.is_set():
            await asyncio.sleep(STATS_INTERVAL_S)
            now = time.monotonic()
            cur = self._counter_snapshot()
            dt = max(0.001, now - last_t)
            dora_s = (cur["dora_ack"] - last["dora_ack"]) / dt
            renew_s = (cur["renew_ack"] - last["renew_ack"]) / dt
            dns_s = (cur["dns_sent"] - last["dns_sent"]) / dt
            dora_p = self.lat_dora.window_percentiles()
            renew_p = self.lat_renew.window_percentiles()
            dns_p = self.lat_dns.window_percentiles()
            prop_ipam = self.lat_prop_ipam.window_percentiles()
            prop_dns = self.lat_prop_dns.window_percentiles()
            # DDNS short-circuit ratio on renewals: renew-driven DNS writes / renews.
            renew_total = max(1, cur["renew_ack"] + cur["rebind_ack"])
            ddns_short_ratio = round(cur["ddns_renew_writes"] / renew_total, 6)
            unique_macs = sum(1 for d in self.devices.values() if d.leased_ip is not None) \
                + cur["departures"] + cur["lapses"]  # approx distinct seen
            rec = {
                "ts": utc_now_iso(),
                "shard": self.shard,
                "online": len(self.online_set),
                "dora_s": round(dora_s, 3),
                "renew_s": round(renew_s, 3),
                "dns_s": round(dns_s, 3),
                "ack_dora_p50": dora_p["p50"], "ack_dora_p95": dora_p["p95"], "ack_dora_p99": dora_p["p99"],
                "ack_renew_p50": renew_p["p50"], "ack_renew_p95": renew_p["p95"], "ack_renew_p99": renew_p["p99"],
                "dns_p50": dns_p["p50"], "dns_p95": dns_p["p95"], "dns_p99": dns_p["p99"],
                "propagation_ipam_p50": prop_ipam["p50"], "propagation_ipam_p95": prop_ipam["p95"],
                "propagation_ipam_p99": prop_ipam["p99"],
                "propagation_dns_p50": prop_dns["p50"], "propagation_dns_p95": prop_dns["p95"],
                "propagation_dns_p99": prop_dns["p99"],
                "scheduler_lag": round(self._sched_lag_max, 4),
                "ddns_short_circuit_ratio": ddns_short_ratio,
                "renew_ip_changed": cur["renew_ip_changed"],
                "ddns_first_publish": cur["ddns_first_publish"],
                "unique_macs": unique_macs,
                "nak": cur["nak"], "timeout": cur["timeout"], "decline": cur["decline"],
                "departures": cur["departures"], "releases": cur["releases"],
                "lapses": cur["lapses"], "rearrivals": cur["rearrivals"],
                "dns_timeout": cur["dns_timeout"],
                # #1057 — the cumulative ledger at this window's end (cumulative
                # like the fields above: never sum these across windows).
                "dora_sent": cur["dora_sent"], "dora_offer": cur["dora_offer"],
                "request_sent": cur["request_sent"], "dora_ack": cur["dora_ack"],
                "dora_ack_late": cur["dora_ack_late"], "dora_ack_resent": cur["dora_ack_resent"],
                "renew_sent": cur["renew_sent"], "renew_ack": cur["renew_ack"],
                "renew_ack_late": cur["renew_ack_late"],
                "rebind_sent": cur["rebind_sent"], "rebind_ack": cur["rebind_ack"],
                "rebind_ack_late": cur["rebind_ack_late"],
                "ack_unmatched": cur["ack_unmatched"],
                "dns_sent": cur["dns_sent"], "dns_ok": cur["dns_ok"],
                "dns_answered": cur["dns_answered"], "dns_error": cur["dns_error"],
                "dns_rcodes": dict(sorted(self.dns_tally.rcodes.items())),
            }
            append_ndjson(self.stats_path, rec)
            self._sched_lag_max = 0.0  # reset window max
            last, last_t = cur, now

    def _counter_snapshot(self) -> dict[str, int]:
        c = self.counters
        out = {k: getattr(c, k) for k in c.__dataclass_fields__}
        out.update(self.dns_tally.counter_fields())  # dns_rcode_<NAME> per rcode seen
        return out

    # ---------------- lifecycle ----------------
    async def run(self) -> None:
        if not self.node_ip:
            self.log.error("target.node_ip empty — nothing to send to")
            return
        self._open_socket()
        self.log.info(
            "orchestrator shard online",
            extra={"fields": {"event": "start", "shard": self.shard, "shards": self.shards,
                              "devices": len(self.indices), "subnets": self.n_subnets,
                              "topology": self.m.target.dhcp.topology}})
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except (NotImplementedError, RuntimeError):
                # add_signal_handler isn't available on every platform / loop;
                # the _stop event still drives shutdown via other paths.
                self.log.debug("signal handler unavailable for %s", sig)
        # One reader per socket: the wildcard one plus every per-giaddr socket
        # (relay topology). Kea answers to giaddr:67, and each of those replies
        # lands on the socket bound to that address.
        readers = [self._sock] + [s for s in self._socks.values() if s is not self._sock]
        tasks = [
            *(asyncio.ensure_future(self._recv_loop(s)) for s in readers),
            asyncio.ensure_future(self._scheduler_loop()),
            asyncio.ensure_future(self._control_loop()),
            asyncio.ensure_future(self._stats_loop()),
        ]
        await self._stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._finalize()

    def _finalize(self) -> None:
        # Dump cumulative HdrHistograms + a final summary.
        for acc in (self.lat_dora, self.lat_dora_late, self.lat_renew, self.lat_dns,
                    self.lat_prop_ipam, self.lat_prop_dns):
            acc.dump_hdr(str(self.rp.generator(f"orchestrator.shard{self.shard}.{acc.name}.hdr")))
        counters = self._counter_snapshot()
        # A DORA round still open at stop has no verdict (ack, timeout or nak),
        # so it is in no handshake bucket. A round now runs ≈60 s before it
        # can time out, so that tail is counted rather than left out.
        counters["dora_in_flight"] = sum(
            1 for d in self.devices.values() if d.state is DState.DISCOVERING
        )
        summary = {
            "ts": utc_now_iso(),
            "shard": self.shard,
            "counters": counters,
            "dora_ack": self.lat_dora.cumulative_summary(),
            "dora_ack_late": self.lat_dora_late.cumulative_summary(),
            "renew_ack": self.lat_renew.cumulative_summary(),
            "dns_resolve": self.lat_dns.cumulative_summary(),
            "propagation_lease_to_ipam": self.lat_prop_ipam.cumulative_summary(),
            "propagation_ipam_to_dns": self.lat_prop_dns.cumulative_summary(),
            "unique_macs_with_lease_or_seen": sum(
                1 for d in self.devices.values()
                if d.state is not DState.OFFLINE),
            # #1057 — the two ledgers a consumer needs without re-deriving them:
            # the handshake at three strictnesses and the DNS outcome by rcode.
            "handshake": handshake_summary(counters),
            "dns": dns_summary(counters),
            "dns_error_types": dict(sorted(self.dns_tally.errors.items())),
        }
        append_ndjson(self.rp.generator(f"orchestrator.shard{self.shard}.summary.ndjson"), summary)
        # Every socket, not just the wildcard one: relay topology opens one per
        # giaddr (open_relay_sockets). A giaddr that could not be bound maps to
        # the wildcard socket, so the values can repeat it — dedupe by identity
        # rather than closing the same fd twice.
        seen: set[int] = set()
        for sock in [self._sock, *self._socks.values()]:
            if sock is None or id(sock) in seen:
                continue
            seen.add(id(sock))
            try:
                sock.close()
            except OSError as exc:
                # Best-effort close during teardown; a socket error here is non-fatal.
                self.log.debug("socket close failed during finalize: %s", exc)
        self.log.info("orchestrator shard stopped",
                      extra={"fields": {"event": "stop", "shard": self.shard,
                                        **summary["counters"]}})


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SpatiumDDI perf — diurnal device-fleet orchestrator (DHCP FSM + "
                    "DNS streams + propagation probe). Runs OFF-BOX.")
    p.add_argument("--run-id", required=True)
    p.add_argument("--run-root", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--shard", type=int, default=0, help="this shard index (0-based)")
    p.add_argument("--shards", type=int, default=1, help="total shard count (~vCPU)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    orch = Orchestrator(args)
    try:
        asyncio.run(orch.run())
    except KeyboardInterrupt:
        # Intentional: swallow Ctrl-C for a clean shutdown without a traceback.
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
