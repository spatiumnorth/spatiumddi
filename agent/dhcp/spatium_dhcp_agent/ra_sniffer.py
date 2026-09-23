"""Passive IPv6 Router-Advertisement sniffer — rogue-RA detection (issue #524).

The IPv6 twin of the rogue-DHCP probe: sniffs ICMPv6 Router Advertisements
(type 134) via scapy's ``AsyncSniffer``, extracts the source router + advertised
prefixes + M/O flags + router lifetime, and ships them to the control plane in
batches. The control plane classifies each source against the group's
expected-router allowlist and fires the ``rogue_ra`` alert on unknown routers.

Disabled by default — operators opt in by setting ``DHCP_RA_SNIFFER_ENABLED=1``
for the same reasons as the passive DHCP fingerprint sniffer:

  1. The container needs ``CAP_NET_RAW`` to bind the BPF socket.
  2. scapy is a heavyweight dependency.
  3. Sniffing every RA is a segment-wide observation operators should opt into.

Mirrors :class:`spatium_dhcp_agent.dhcp_fingerprint.DhcpFingerprintShipper` for
batch sizing / retry / re-bootstrap-on-401 semantics.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from .config import AgentConfig
from .push import CPPoster, disabled_spool
from .spool import Shipper, Spool

log = structlog.get_logger(__name__)

MAX_BATCH = 100
BATCH_INTERVAL = 10.0
MAX_BUFFER_SIZE = 5_000
# Dedupe window per source IP — an RA typically repeats every few minutes; we
# re-report at most once per this interval so the wire stays quiet.
_DEDUPE_SECONDS = 60.0
_LAST_SEEN_RETENTION = 300.0


@dataclass
class RAObservation:
    """Normalised view of one Router Advertisement."""

    source_ip: str
    source_mac: str | None = None
    prefixes: list[str] = field(default_factory=list)
    managed_flag: bool = False
    other_flag: bool = False
    router_lifetime: int | None = None
    iface: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "source_mac": self.source_mac,
            "prefixes": self.prefixes,
            "managed_flag": self.managed_flag,
            "other_flag": self.other_flag,
            "router_lifetime": self.router_lifetime,
            "iface": self.iface,
        }


def parse_ra_packet(packet: Any) -> RAObservation | None:
    """Pull RA fields off a scapy ICMPv6 packet. None for non-RA traffic."""
    try:
        from scapy.layers.inet6 import (  # type: ignore[import-not-found]
            ICMPv6ND_RA,
            ICMPv6NDOptPrefixInfo,
            ICMPv6NDOptSrcLLAddr,
            IPv6,
        )
        from scapy.layers.l2 import Ether  # type: ignore[import-not-found]
    except ImportError:
        return None

    if not packet.haslayer(ICMPv6ND_RA):
        return None
    ra = packet[ICMPv6ND_RA]

    source_ip = packet[IPv6].src if packet.haslayer(IPv6) else ""
    if not source_ip:
        return None

    source_mac: str | None = None
    if packet.haslayer(Ether):
        source_mac = packet[Ether].src
    if packet.haslayer(ICMPv6NDOptSrcLLAddr):
        # The RA's own source link-layer option is authoritative for the
        # router MAC (the Ether src may be rewritten by an intervening bridge).
        source_mac = getattr(packet[ICMPv6NDOptSrcLLAddr], "lladdr", None) or source_mac

    prefixes: list[str] = []
    layer = ra
    while layer is not None:
        if isinstance(layer, ICMPv6NDOptPrefixInfo):
            pfx = getattr(layer, "prefix", None)
            plen = getattr(layer, "prefixlen", None)
            if pfx is not None and plen is not None:
                prefixes.append(f"{pfx}/{plen}")
        layer = layer.payload if layer.payload else None

    return RAObservation(
        source_ip=str(source_ip),
        source_mac=str(source_mac).lower() if source_mac else None,
        prefixes=prefixes,
        managed_flag=bool(getattr(ra, "M", 0)),
        other_flag=bool(getattr(ra, "O", 0)),
        router_lifetime=int(getattr(ra, "routerlifetime", 0) or 0),
    )


@dataclass
class _ShipperState:
    buffer: list[RAObservation] = field(default_factory=list)
    last_seen: dict[str, float] = field(default_factory=dict)


class RASnifferShipper:
    """Sniffer thread + batching POST loop for observed RAs."""

    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        iface: str | None = None,
        spool: Spool | None = None,
    ) -> None:
        self.cfg = cfg
        self.token_ref = token_ref
        self.iface = (
            iface
            or os.environ.get("DHCP_RA_SNIFFER_IFACE")
            or os.environ.get("DHCP_FINGERPRINT_IFACE")
            or "any"
        )
        self._stop = threading.Event()
        self._state = _ShipperState()
        self._sniffer: Any = None
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()
        # #1077 — a batch the control plane does not take is spooled to disk
        # and replayed in order, instead of dropped.
        self._shipper = Shipper(
            spool if spool is not None else disabled_spool("ra_observations"),
            CPPoster(
                cfg, token_ref, "/api/v1/dhcp/agents/ra-observations", lambda: self._cp_client()
            ),
            event_prefix="ra_sniffer_ship",
            retry_backoff_seconds=BATCH_INTERVAL,
        )

    def stop(self) -> None:
        self._stop.set()

    def _on_packet(self, packet: Any) -> None:
        try:
            obs = parse_ra_packet(packet)
        except Exception as exc:  # noqa: BLE001
            log.debug("ra_sniffer_parse_error", error=str(exc))
            return
        if obs is None:
            return
        obs.iface = None if self.iface == "any" else self.iface
        now = time.monotonic()
        with self._lock:
            last = self._state.last_seen.get(obs.source_ip)
            if last is not None and now - last < _DEDUPE_SECONDS:
                return
            self._state.last_seen[obs.source_ip] = now
            if len(self._state.buffer) >= MAX_BUFFER_SIZE:
                drop = MAX_BUFFER_SIZE // 2
                self._state.buffer = self._state.buffer[drop:]
                log.warning("ra_sniffer_buffer_trimmed", dropped=drop)
            self._state.buffer.append(obs)

    def _start_sniffer(self) -> bool:
        try:
            from scapy.sendrecv import AsyncSniffer  # type: ignore[import-not-found]
        except ImportError as exc:
            log.warning("ra_sniffer_scapy_missing", error=str(exc))
            return False
        try:
            # BPF: ICMPv6 (next-header 58) where the ICMPv6 type byte is 134
            # (Router Advertisement). ip6[40] is the first byte past the fixed
            # 40-byte IPv6 header = the ICMPv6 type.
            self._sniffer = AsyncSniffer(
                iface=None if self.iface == "any" else self.iface,
                filter="icmp6 and ip6[40] == 134",
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:  # noqa: BLE001
            log.warning("ra_sniffer_start_failed", iface=self.iface, error=str(exc))
            self._sniffer = None
            return False
        log.info("ra_sniffer_started", iface=self.iface)
        return True

    def _cp_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _drain(self) -> list[RAObservation]:
        with self._lock:
            batch = self._state.buffer[:MAX_BATCH]
            self._state.buffer = self._state.buffer[MAX_BATCH:]
        return batch

    def _prune_last_seen(self, now: float) -> None:
        cutoff = now - _LAST_SEEN_RETENTION
        with self._lock:
            stale = [ip for ip, ts in self._state.last_seen.items() if ts < cutoff]
            for ip in stale:
                del self._state.last_seen[ip]

    def _should_flush(self) -> bool:
        with self._lock:
            buf_len = len(self._state.buffer)
        if buf_len == 0:
            return False
        if buf_len >= MAX_BATCH:
            return True
        return (time.monotonic() - self._last_flush) >= BATCH_INTERVAL

    def _flush(self) -> None:
        self._prune_last_seen(time.monotonic())
        batch = self._drain()
        if not batch:
            return
        payload = {"observations": [obs.to_payload() for obs in batch]}
        # Sent now, or spooled behind the backlog for replay. A 401 / 404 is
        # retried rather than dropped: the heartbeat thread is the canonical
        # re-bootstrap trigger, and the batch is good once the token is.
        self._shipper.ship(payload)
        self._last_flush = time.monotonic()

    def run(self) -> None:
        log.info("ra_sniffer_shipper_starting", iface=self.iface)
        started = self._start_sniffer()
        if not started:
            log.warning("ra_sniffer_disabled_no_sniffer")
            while not self._stop.is_set():
                self._stop.wait(timeout=30.0)
            return
        while not self._stop.is_set():
            if self._should_flush():
                self._flush()
            elif len(self._shipper.spool):
                # Idle tick with a backlog; the shipper's retry backoff
                # throttles this while the control plane is still away.
                self._shipper.drain()
            self._stop.wait(timeout=1.0)
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001
                pass
        self._flush()
        log.info("ra_sniffer_shipper_stopped")


__all__ = ["RASnifferShipper", "RAObservation", "parse_ra_packet"]
