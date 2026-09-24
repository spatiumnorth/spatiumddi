"""Passive DHCP fingerprint sniffer — Phase 2 of device profiling.

Sniffs DHCP DISCOVER + REQUEST packets via scapy's ``AsyncSniffer``,
extracts the option-55 / option-60 / option-77 / option-61 fields,
and ships them to the control plane in batches.

Disabled by default — operators opt in by setting
``DHCP_FINGERPRINT_ENABLED=1`` because:

  1. The container needs ``CAP_NET_RAW`` to bind the BPF socket.
  2. scapy is a heavyweight dependency that pulls in a lot of code
     we otherwise don't need on the DHCP agent.
  3. Sniffing every DHCP transaction is privacy-sensitive in BYOD
     / guest-Wi-Fi shops, and we want operators to take an explicit
     action before turning that surface on.

Mirrors :class:`spatium_dhcp_agent.log_shipper.LogShipper` for batch
sizing / retry / re-bootstrap-on-401 semantics. See that module's
docstring for the resilience design.
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

# Tunables — keep these in sync with the LogShipper values where
# they share semantics.
MAX_BATCH = 50
BATCH_INTERVAL = 10.0
MAX_BUFFER_SIZE = 5_000

# Issue #257 — retention window on ``_ShipperState.last_seen_macs``.
# The dedupe window in ``_on_packet`` is 60 s; anything older than
# 5× that is dead weight that can be safely evicted on each flush.
_LAST_SEEN_RETENTION = 300.0

# DHCP message-type values (option 53). 1 = DISCOVER, 3 = REQUEST.
# We intentionally ignore OFFER / ACK / NAK / RELEASE because those
# come from the server side and don't carry the client's parameter
# request list.
DHCP_DISCOVER = 1
DHCP_REQUEST = 3


@dataclass
class FingerprintObservation:
    """Normalised view of one DHCP packet's fingerprint fields.

    All fields except ``mac_address`` are optional — the control
    plane endpoint accepts partial signatures, fingerbank just
    won't enrich them.
    """

    mac_address: str
    option_55: str | None = None
    option_60: str | None = None
    option_77: str | None = None
    client_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "mac_address": self.mac_address,
            "option_55": self.option_55,
            "option_60": self.option_60,
            "option_77": self.option_77,
            "client_id": self.client_id,
        }


def _format_mac(chaddr: bytes) -> str:
    """Render a 6-byte chaddr as ``aa:bb:cc:dd:ee:ff``.

    scapy's ``BOOTP.chaddr`` is padded to 16 bytes; we slice the
    first six (the MAC for hwtype=1 Ethernet).
    """
    if len(chaddr) < 6:
        return ""
    return ":".join(f"{b:02x}" for b in chaddr[:6])


def _option_to_string(value: Any) -> str | None:
    """Decode an option payload to a stable string form.

    scapy normalises option values into varied shapes — ``bytes``
    for opaque blobs, ``str`` for ASCII, ``list[int]`` for
    parameter request lists, ``int`` for single-byte values. We
    coerce each to a printable string so the JSON payload is
    homogeneous.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace") or None
        except (UnicodeDecodeError, AttributeError):
            return value.hex() or None
    if isinstance(value, list):
        return ",".join(str(int(v)) for v in value) or None
    if isinstance(value, int):
        return str(value)
    s = str(value).strip()
    return s or None


def parse_dhcp_packet(packet: Any) -> FingerprintObservation | None:
    """Pull the fingerprint fields off a scapy DHCP packet.

    Returns ``None`` for non-DHCP traffic, malformed packets, or
    OFFER/ACK/NAK/RELEASE messages. The "skip server-side messages"
    check is a defensive belt-and-braces; the BPF filter already
    narrows to UDP 67/68 but the operator's compose may host-network
    the container and pick up sibling traffic.
    """
    # Lazy import — scapy is a runtime dep, gated on the
    # DHCP_FINGERPRINT_ENABLED toggle. We don't want to pay the
    # import cost on every agent boot.
    try:
        from scapy.layers.dhcp import BOOTP, DHCP  # type: ignore[import-not-found]
    except ImportError:
        return None

    if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return None

    bootp = packet[BOOTP]
    dhcp = packet[DHCP]

    mac = _format_mac(bytes(bootp.chaddr or b""))
    if not mac:
        return None

    options = dhcp.options or []
    msg_type: int | None = None
    obs = FingerprintObservation(mac_address=mac)
    parameter_request_list: list[int] | None = None

    for opt in options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        name, value = opt[0], opt[1]
        if name == "message-type":
            try:
                msg_type = int(value)
            except (TypeError, ValueError):
                msg_type = None
        elif name == "param_req_list":
            if isinstance(value, list):
                parameter_request_list = [int(v) for v in value]
            elif isinstance(value, (bytes, bytearray)):
                parameter_request_list = list(value)
        elif name == "vendor_class_id":
            obs.option_60 = _option_to_string(value)
        elif name == "user_class":
            obs.option_77 = _option_to_string(value)
        elif name == "client_id":
            # Client id is opaque (RFC 2131 §4.1.1). Hex-encode for
            # JSON safety; the control-plane stores the same string.
            if isinstance(value, (bytes, bytearray)):
                obs.client_id = bytes(value).hex() or None
            else:
                obs.client_id = _option_to_string(value)

    if msg_type not in (DHCP_DISCOVER, DHCP_REQUEST):
        return None
    if parameter_request_list is None and obs.option_60 is None:
        # Nothing useful for fingerbank — drop it. A REQUEST without
        # option-55 or option-60 is unusual but not invalid; we just
        # save the round trip.
        return None

    if parameter_request_list is not None:
        obs.option_55 = ",".join(str(b) for b in parameter_request_list) or None
    return obs


@dataclass
class _ShipperState:
    buffer: list[FingerprintObservation] = field(default_factory=list)
    last_seen_macs: dict[str, float] = field(default_factory=dict)


class DhcpFingerprintShipper:
    """Sniffer thread + batching POST loop.

    The sniffer pushes observations into an in-memory buffer; the
    main loop drains the buffer every ``BATCH_INTERVAL`` seconds (or
    sooner once the buffer hits ``MAX_BATCH``). A batch the control
    plane does not take — unreachable, 5xx, or a 401 / 404 while the
    token is stale — is kept in the ``fingerprints`` spool and replayed
    in order (#1077). We never re-bootstrap from here: the heartbeat
    thread is the canonical trigger (it clears the on-disk token and
    exits so the container restarts), so duplicating that here would
    race the heartbeat.
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
        # networks should set DHCP_FINGERPRINT_IFACE explicitly.
        self.iface = iface or os.environ.get("DHCP_FINGERPRINT_IFACE") or "any"
        self._stop = threading.Event()
        self._state = _ShipperState()
        self._sniffer: Any = None
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()
        # #1077 — a batch the control plane does not take is spooled to disk
        # and replayed in order, instead of dropped.
        self._shipper = Shipper(
            spool if spool is not None else disabled_spool("fingerprints"),
            CPPoster(
                cfg,
                token_ref,
                "/api/v1/dhcp/agents/dhcp-fingerprints",
                late_bound(self, "_cp_client"),
            ),
            event_prefix="dhcp_fingerprint_ship",
            retry_backoff_seconds=BATCH_INTERVAL,
        )

    def stop(self) -> None:
        # ``run()`` owns the sniffer lifecycle and stops the scapy
        # AsyncSniffer in its shutdown block. Calling ``_sniffer.stop()``
        # from here too is harmless (idempotent) but dead — issue #261.
        self._stop.set()

    def _on_packet(self, packet: Any) -> None:
        try:
            obs = parse_dhcp_packet(packet)
        except Exception as exc:  # noqa: BLE001
            log.debug("dhcp_fingerprint_parse_error", error=str(exc))
            return
        if obs is None:
            return
        # Deduplicate aggressively at the agent layer — a busy
        # subnet sees DISCOVER + REQUEST per renewal, sometimes
        # multiple times under retries. We send at most one
        # observation per (mac) per minute; the control plane is
        # idempotent on its end too but this keeps the wire traffic
        # small.
        now = time.monotonic()
        with self._lock:
            last = self._state.last_seen_macs.get(obs.mac_address)
            if last is not None and now - last < 60.0:
                return
            self._state.last_seen_macs[obs.mac_address] = now
            if len(self._state.buffer) >= MAX_BUFFER_SIZE:
                drop = MAX_BUFFER_SIZE // 2
                self._state.buffer = self._state.buffer[drop:]
                log.warning("dhcp_fingerprint_buffer_trimmed", dropped=drop)
            self._state.buffer.append(obs)

    def _start_sniffer(self) -> bool:
        try:
            from scapy.sendrecv import AsyncSniffer  # type: ignore[import-not-found]
        except ImportError as exc:
            log.warning("dhcp_fingerprint_scapy_missing", error=str(exc))
            return False
        try:
            self._sniffer = AsyncSniffer(
                iface=None if self.iface == "any" else self.iface,
                filter="udp and (port 67 or port 68)",
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "dhcp_fingerprint_sniffer_start_failed",
                iface=self.iface,
                error=str(exc),
            )
            self._sniffer = None
            return False
        log.info("dhcp_fingerprint_sniffer_started", iface=self.iface)
        return True

    def _cp_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _drain(self) -> list[FingerprintObservation]:
        with self._lock:
            batch = self._state.buffer[:MAX_BATCH]
            self._state.buffer = self._state.buffer[MAX_BATCH:]
        return batch

    def _prune_last_seen(self, now: float) -> None:
        """Drop entries from ``last_seen_macs`` whose age exceeds
        ``LAST_SEEN_RETENTION``.

        Issue #257 — ``last_seen_macs`` is a dedupe ledger keyed on
        MAC address with a 60 s dedupe window (see ``_on_packet``).
        Pre-#257 the dict accumulated one entry per unique MAC for
        the lifetime of the agent and never pruned; on a busy DHCP
        server with thousands of clients this is a steady memory
        leak. We retain 5× the dedupe window's worth of entries so a
        client renewing every 60 s still gets deduped, but anything
        idle for >5 min is dead weight.
        """
        cutoff = now - _LAST_SEEN_RETENTION
        with self._lock:
            stale = [
                mac
                for mac, ts in self._state.last_seen_macs.items()
                if ts < cutoff
            ]
            for mac in stale:
                del self._state.last_seen_macs[mac]
        if stale:
            log.debug("dhcp_fingerprint_pruned_last_seen", count=len(stale))

    def _should_flush(self) -> bool:
        with self._lock:
            buf_len = len(self._state.buffer)
        if buf_len == 0:
            return False
        if buf_len >= MAX_BATCH:
            return True
        return (time.monotonic() - self._last_flush) >= BATCH_INTERVAL

    def _flush(self) -> None:
        # Piggyback the dedupe-ledger prune on every flush — same
        # cadence as the wire-side batching, single lock acquisition
        # we already take for ``_drain``.
        self._prune_last_seen(time.monotonic())
        batch = self._drain()
        if not batch:
            return
        payload = {"fingerprints": [obs.to_payload() for obs in batch]}
        # Sent now, or spooled behind the backlog for replay. A 401 / 404 is
        # retried rather than dropped: the heartbeat thread is the canonical
        # re-bootstrap trigger, and the batch is good once the token is.
        self._shipper.ship(payload)
        self._last_flush = time.monotonic()

    def run(self) -> None:
        log.info("dhcp_fingerprint_shipper_starting", iface=self.iface)
        started = self._start_sniffer()
        if not started:
            log.warning("dhcp_fingerprint_disabled_no_sniffer")
            # Spin in idle loop so the supervisor's thread-alive
            # check doesn't restart the container — operator can
            # fix the cap_add / iface issue at their leisure.
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
        log.info("dhcp_fingerprint_shipper_stopped")


__all__ = [
    "DhcpFingerprintShipper",
    "FingerprintObservation",
    "parse_dhcp_packet",
]
