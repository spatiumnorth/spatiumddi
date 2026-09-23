"""Arpwatch-style L2 sniffer — Phase 3 of new-device detection (#459).

Sniffs ARP frames + IPv6 Neighbor Discovery packets via scapy's
``AsyncSniffer``, pulls the source MAC + source IP off each, and ships
first-sightings to the control plane in batches. Unlike the DHCP
fingerprint sniffer (which only ever sees devices that do DHCP), this
observes *any* device that puts an ARP reply / request or an ICMPv6
NS/NA on the wire — including statically-addressed and link-local-only
hosts that never touch the DHCP server.

Disabled by default — operators opt in by setting
``DHCP_MAC_SIGHTING_ENABLED=1`` because:

  1. The container needs ``CAP_NET_RAW`` to bind the BPF socket (the
     same cap the passive fingerprint + rogue-probe sniffers need).
  2. Observing every host on the segment is privacy-sensitive in BYOD
     / guest-Wi-Fi shops, and we want operators to take an explicit
     action before turning that surface on.

The control-plane endpoint (``POST /api/v1/dhcp/agents/mac-sightings``)
is a no-op when the new-device-watch feature module is off, so shipping
costs nothing until the operator arms it server-side — the agent ships
unconditionally once enabled locally.

Mirrors :class:`spatium_dhcp_agent.dhcp_fingerprint.DhcpFingerprintShipper`
for batch sizing / dedupe-ledger pruning (#257) / retry /
re-bootstrap-on-401 semantics. See that module's docstring for the
resilience design.
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
from .push import CPPoster, disabled_spool, late_bound
from .spool import Shipper, Spool

log = structlog.get_logger(__name__)

# Tunables — keep these in sync with the fingerprint shipper values
# where they share semantics.
MAX_BATCH = 200
BATCH_INTERVAL = 5.0
MAX_BUFFER_SIZE = 5_000

# Issue #257 — retention window on ``_ShipperState.last_seen``. The
# dedupe window in ``_on_packet`` is 60 s; anything older than 5× that
# is dead weight that can be safely evicted on each flush.
_LAST_SEEN_RETENTION = 300.0

# Server max per POST is 500; our MAX_BATCH (200) sits comfortably under.


@dataclass
class MacSighting:
    """One observed ``(MAC, IP)`` pairing pulled off an ARP / ND frame."""

    mac_address: str
    ip_address: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
        }


def _normalize_mac(mac: Any) -> str | None:
    """Lower-case a ``aa:bb:cc:dd:ee:ff`` MAC and reject the ones we
    never want to record.

    Drops broadcast (``ff:ff:ff:ff:ff:ff``), the all-zero MAC (seen on
    ARP probes / gratuitous frames before an address is claimed), and
    any group/multicast MAC (low bit of the first octet set — IPv6
    solicited-node multicast, etc.). Those are never a real device's
    primary interface address.
    """
    if not mac:
        return None
    s = str(mac).strip().lower()
    parts = s.split(":")
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if all(o == 0 for o in octets):
        return None
    if all(o == 0xFF for o in octets):
        return None
    # Group/multicast bit (least-significant bit of the first octet).
    if octets[0] & 0x01:
        return None
    return ":".join(f"{o:02x}" for o in octets)


def _normalize_ip(ip: Any) -> str | None:
    """Reject the unspecified / link-scope addresses that carry no
    identifying value.

    ARP probes use ``0.0.0.0`` as the sender protocol address; IPv6
    ND from a still-configuring host can use ``::``. We also drop the
    IPv6 unspecified and obvious garbage. Anything else (RFC1918,
    link-local fe80::, GUA) is recorded — link-local is exactly the
    case this sniffer exists to catch.
    """
    if not ip:
        return None
    s = str(ip).strip().lower()
    if not s:
        return None
    if s in ("0.0.0.0", "::"):
        return None
    return s


def parse_sighting_packet(packet: Any) -> MacSighting | None:
    """Pull a ``(MAC, IP)`` pairing off a scapy ARP / IPv6-ND packet.

    Returns ``None`` for traffic we can't extract both a usable MAC and
    a usable IP from. Two shapes are handled:

      * **ARP** — ``Ether.src`` is the sender's hardware address and
        ``ARP.psrc`` is the sender's protocol (IPv4) address. Works for
        both requests and replies; both carry the sender's pairing.
      * **IPv6 Neighbor Discovery** (ICMPv6 NS / NA) — the source MAC is
        ``Ether.src`` and the source IP is ``IPv6.src``. We prefer the
        explicit source/target link-layer-address option when present
        (it's the authoritative L2 address) but fall back to
        ``Ether.src``.
    """
    # Lazy import — scapy is a runtime dep, gated on the
    # DHCP_MAC_SIGHTING_ENABLED toggle. We don't want to pay the import
    # cost on every agent boot.
    try:
        from scapy.layers.inet6 import (  # type: ignore[import-not-found]
            ICMPv6ND_NA,
            ICMPv6ND_NS,
            ICMPv6NDOptDstLLAddr,
            ICMPv6NDOptSrcLLAddr,
            IPv6,
        )
        from scapy.layers.l2 import ARP, Ether  # type: ignore[import-not-found]
    except ImportError:
        return None

    ether_mac = _normalize_mac(getattr(packet[Ether], "src", None)) if packet.haslayer(Ether) else None

    # --- ARP ---
    if packet.haslayer(ARP):
        arp = packet[ARP]
        # Prefer the ARP sender hardware address; fall back to Ether.src.
        mac = _normalize_mac(getattr(arp, "hwsrc", None)) or ether_mac
        ip = _normalize_ip(getattr(arp, "psrc", None))
        if mac and ip:
            return MacSighting(mac_address=mac, ip_address=ip)
        return None

    # --- IPv6 Neighbor Discovery (ICMPv6 NS / NA) ---
    if packet.haslayer(IPv6) and (packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_NA)):
        # The link-layer-address option is the authoritative L2 address
        # when present (NS carries src-LLA, NA carries tgt-LLA).
        opt_mac: str | None = None
        if packet.haslayer(ICMPv6NDOptSrcLLAddr):
            opt_mac = _normalize_mac(getattr(packet[ICMPv6NDOptSrcLLAddr], "lladdr", None))
        if opt_mac is None and packet.haslayer(ICMPv6NDOptDstLLAddr):
            opt_mac = _normalize_mac(getattr(packet[ICMPv6NDOptDstLLAddr], "lladdr", None))
        mac = opt_mac or ether_mac
        ip = _normalize_ip(getattr(packet[IPv6], "src", None))
        if mac and ip:
            return MacSighting(mac_address=mac, ip_address=ip)
        return None

    return None


@dataclass
class _ShipperState:
    buffer: list[MacSighting] = field(default_factory=list)
    last_seen: dict[tuple[str, str], float] = field(default_factory=dict)


class MacSightingShipper:
    """Sniffer thread + batching POST loop.

    The sniffer pushes sightings into an in-memory buffer; the main loop
    drains the buffer every ``BATCH_INTERVAL`` seconds (or sooner once
    the buffer hits ``MAX_BATCH``). A batch the control plane does not
    take — unreachable, 5xx, or a 401 / 404 while the token is stale — is
    kept in the ``mac_sightings`` spool and replayed in order (#1077). We
    never re-bootstrap from here: the heartbeat thread is the canonical
    trigger (it clears the on-disk token and exits so the container
    restarts), so duplicating that here would race the heartbeat.
    """

    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        iface: str | None = None,
        spool: Spool | None = None,
    ) -> None:
        self.cfg = cfg
        self.token_ref = token_ref
        # Default interface "any" matches scapy's wildcard binding —
        # works for host-networked containers. Operators on bridge
        # networks should set DHCP_MAC_SIGHTING_IFACE explicitly.
        self.iface = iface or os.environ.get("DHCP_MAC_SIGHTING_IFACE") or "any"
        self._stop = threading.Event()
        self._state = _ShipperState()
        self._sniffer: Any = None
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()
        # #1077 — a batch the control plane does not take is spooled to disk
        # and replayed in order, instead of dropped.
        self._shipper = Shipper(
            spool if spool is not None else disabled_spool("mac_sightings"),
            CPPoster(
                cfg,
                token_ref,
                "/api/v1/dhcp/agents/mac-sightings",
                late_bound(self, "_cp_client"),
            ),
            event_prefix="mac_sighting_ship",
            retry_backoff_seconds=BATCH_INTERVAL,
        )

    def stop(self) -> None:
        # ``run()`` owns the sniffer lifecycle and stops the scapy
        # AsyncSniffer in its shutdown block. Calling ``_sniffer.stop()``
        # from here too is harmless (idempotent) but dead — issue #261.
        self._stop.set()

    def _on_packet(self, packet: Any) -> None:
        try:
            obs = parse_sighting_packet(packet)
        except Exception as exc:  # noqa: BLE001
            log.debug("mac_sighting_parse_error", error=str(exc))
            return
        if obs is None:
            return
        # Deduplicate aggressively at the agent layer — a busy segment
        # sees the same (mac, ip) repeated continuously (ARP refresh,
        # ND reachability). We send at most one sighting per (mac, ip)
        # per minute; the control plane is idempotent on its end too but
        # this keeps the wire traffic small.
        key = (obs.mac_address, obs.ip_address)
        now = time.monotonic()
        with self._lock:
            last = self._state.last_seen.get(key)
            if last is not None and now - last < 60.0:
                return
            self._state.last_seen[key] = now
            if len(self._state.buffer) >= MAX_BUFFER_SIZE:
                drop = MAX_BUFFER_SIZE // 2
                self._state.buffer = self._state.buffer[drop:]
                log.warning("mac_sighting_buffer_trimmed", dropped=drop)
            self._state.buffer.append(obs)

    def _start_sniffer(self) -> bool:
        try:
            from scapy.sendrecv import AsyncSniffer  # type: ignore[import-not-found]
        except ImportError as exc:
            log.warning("mac_sighting_scapy_missing", error=str(exc))
            return False
        try:
            self._sniffer = AsyncSniffer(
                iface=None if self.iface == "any" else self.iface,
                # ARP frames carry the sender MAC+IP; ICMPv6 (which
                # includes ND NS/NA) carries the IPv6 pairing.
                filter="arp or icmp6",
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "mac_sighting_sniffer_start_failed",
                iface=self.iface,
                error=str(exc),
            )
            self._sniffer = None
            return False
        log.info("mac_sighting_sniffer_started", iface=self.iface)
        return True

    def _cp_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _drain(self) -> list[MacSighting]:
        with self._lock:
            batch = self._state.buffer[:MAX_BATCH]
            self._state.buffer = self._state.buffer[MAX_BATCH:]
        return batch

    def _prune_last_seen(self, now: float) -> None:
        """Drop entries from ``last_seen`` whose age exceeds
        ``_LAST_SEEN_RETENTION``.

        Issue #257 — ``last_seen`` is a dedupe ledger keyed on
        ``(mac, ip)`` with a 60 s dedupe window (see ``_on_packet``).
        Without pruning the dict accumulates one entry per unique pair
        for the lifetime of the agent; on a busy segment with thousands
        of hosts this is a steady memory leak. We retain 5× the dedupe
        window's worth of entries so a host re-ARPing every 60 s still
        gets deduped, but anything idle for >5 min is dead weight.
        """
        cutoff = now - _LAST_SEEN_RETENTION
        with self._lock:
            stale = [key for key, ts in self._state.last_seen.items() if ts < cutoff]
            for key in stale:
                del self._state.last_seen[key]
        if stale:
            log.debug("mac_sighting_pruned_last_seen", count=len(stale))

    def _should_flush(self) -> bool:
        with self._lock:
            buf_len = len(self._state.buffer)
        if buf_len == 0:
            return False
        if buf_len >= MAX_BATCH:
            return True
        return (time.monotonic() - self._last_flush) >= BATCH_INTERVAL

    def _flush(self) -> None:
        # Piggyback the dedupe-ledger prune on every flush — same cadence
        # as the wire-side batching.
        self._prune_last_seen(time.monotonic())
        batch = self._drain()
        if not batch:
            return
        payload = {"sightings": [obs.to_payload() for obs in batch]}
        # Sent now, or spooled behind the backlog for replay. A 401 / 404 is
        # retried rather than dropped: the heartbeat thread is the canonical
        # re-bootstrap trigger, and the batch is good once the token is.
        self._shipper.ship(payload)
        self._last_flush = time.monotonic()

    def run(self) -> None:
        log.info("mac_sighting_shipper_starting", iface=self.iface)
        started = self._start_sniffer()
        if not started:
            log.warning("mac_sighting_disabled_no_sniffer")
            # Spin in idle loop so the supervisor's thread-alive check
            # doesn't restart the container — operator can fix the
            # cap_add / iface issue at their leisure.
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
        # Final flush on shutdown so we don't drop the last bucket.
        self._flush()
        log.info("mac_sighting_shipper_stopped")


__all__ = [
    "MacSightingShipper",
    "MacSighting",
    "parse_sighting_packet",
]
