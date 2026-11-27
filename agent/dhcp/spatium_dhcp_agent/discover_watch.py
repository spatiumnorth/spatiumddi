"""Per-MAC / per-relay DHCPDISCOVER rate watch (#4737).

Sniffs DHCPDISCOVERs with scapy's ``AsyncSniffer`` and counts them in a fixed
window: how many each client MAC sent, and how many distinct MACs each relay
(``giaddr``) forwarded. When a window closes, the sources above a floor are
shipped to ``POST /api/v1/dhcp/agents/discover-rates``; the control plane
decides what is a flood (the ``dhcp_discover_flood`` alert), so thresholds are
tuned in one place and never baked into an agent.

Disabled by default -- operators opt in with ``DHCP_DISCOVER_WATCH_ENABLED=1``
-- for the same reasons as the fingerprint sniffer: the container needs
``CAP_NET_RAW`` for the BPF socket, scapy is a heavy import, and watching every
DHCP transaction is privacy-sensitive in BYOD / guest-Wi-Fi shops.

**Wire compatibility.** The stream is new and optional. An older agent never
posts it and the control plane's table stays empty, so the rule has nothing to
fire on; an older control plane answers 404 and the batch is held in the spool
(``discover_rates``, which drops anything older than 15 minutes -- a window that
old is no longer evidence).

**Bounded memory.** A MAC-rotating flood is exactly the input that would grow
a per-MAC table without limit, so the window tracks at most ``MAX_MACS`` MACs
and ``MAX_RELAY_MACS`` distinct MACs per relay; past that a new source is still
counted in the relay's DISCOVER total but is not tracked individually.
"""

from __future__ import annotations

import os
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from .config import AgentConfig
from .dhcp_fingerprint import DHCP_DISCOVER, _format_mac
from .push import CPPoster, disabled_spool, late_bound
from .spool import Shipper, Spool

log = structlog.get_logger(__name__)

WINDOW_SECONDS = 60
#: Ship a MAC only at this many DISCOVERs in the window. A client waiting out a
#: slow OFFER sends a handful; the control plane's threshold is far above this,
#: the floor only keeps the wire quiet.
DEFAULT_CLIENT_FLOOR = 5
#: Ship a relay only when it forwarded this many distinct MACs in the window.
DEFAULT_RELAY_FLOOR = 10
MAX_MACS = 50_000
MAX_RELAY_MACS = 20_000
#: Server-side caps on one POST (``DiscoverRateBatch``).
MAX_CLIENTS = 500
MAX_RELAYS = 200


def parse_discover(packet: Any) -> tuple[str, str | None] | None:
    """``(client MAC, relay address or None)`` of a DHCPDISCOVER, else ``None``."""
    try:
        from scapy.layers.dhcp import BOOTP, DHCP  # type: ignore[import-not-found]
    except ImportError:
        return None
    if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return None
    bootp = packet[BOOTP]
    msg_type: int | None = None
    for opt in packet[DHCP].options or []:
        if isinstance(opt, tuple) and len(opt) >= 2 and opt[0] == "message-type":
            try:
                msg_type = int(opt[1])
            except (TypeError, ValueError):
                msg_type = None
    if msg_type != DHCP_DISCOVER:
        return None
    mac = _format_mac(bytes(bootp.chaddr or b""))
    if not mac:
        return None
    giaddr = str(getattr(bootp, "giaddr", "") or "")
    if giaddr in ("", "0.0.0.0"):
        giaddr = ""
    return mac, giaddr or None


class DiscoverWindow:
    """Counts for one window; :meth:`payload` renders and :meth:`reset` clears."""

    def __init__(
        self,
        client_floor: int = DEFAULT_CLIENT_FLOOR,
        relay_floor: int = DEFAULT_RELAY_FLOOR,
    ) -> None:
        self.client_floor = client_floor
        self.relay_floor = relay_floor
        self.reset()

    def reset(self) -> None:
        self.per_mac: Counter[str] = Counter()
        self.mac_relay: dict[str, str] = {}
        self.relay_macs: dict[str, set[str]] = {}
        self.relay_discovers: Counter[str] = Counter()

    def add(self, mac: str, giaddr: str | None) -> None:
        if mac in self.per_mac or len(self.per_mac) < MAX_MACS:
            self.per_mac[mac] += 1
            if giaddr:
                self.mac_relay[mac] = giaddr
        if giaddr:
            self.relay_discovers[giaddr] += 1
            seen = self.relay_macs.setdefault(giaddr, set())
            if mac in seen or len(seen) < MAX_RELAY_MACS:
                seen.add(mac)

    def payload(
        self, window_seconds: int, window_end: datetime
    ) -> dict[str, Any] | None:
        """The POST body, or ``None`` when nothing in the window cleared a floor."""
        clients = [
            {"mac": mac, "discovers": n, "giaddr": self.mac_relay.get(mac)}
            for mac, n in self.per_mac.most_common(MAX_CLIENTS)
            if n >= self.client_floor
        ]
        relays = [
            {
                "giaddr": giaddr,
                "discovers": self.relay_discovers[giaddr],
                "distinct_macs": len(macs),
            }
            for giaddr, macs in sorted(
                self.relay_macs.items(), key=lambda kv: len(kv[1]), reverse=True
            )[:MAX_RELAYS]
            if len(macs) >= self.relay_floor
        ]
        if not clients and not relays:
            return None
        return {
            "window_seconds": window_seconds,
            "window_end": window_end.isoformat(),
            "clients": clients,
            "relays": relays,
        }


def _load_layers() -> None:
    """Register scapy's Ethernet and DHCP layers.

    ``AsyncSniffer`` fixes the link layer it decodes with when its socket is
    opened, from the layers registered *at that moment*. ``scapy.sendrecv``
    alone registers none, so a sniffer opened before something imports
    ``scapy.layers.l2`` types every frame ``Raw`` ("Unable to guess type ...
    Using Raw") -- and :func:`parse_discover`, which imports the DHCP layer
    lazily, only does so after the first packet it can never read. Import them
    before the socket opens.
    """
    import scapy.layers.dhcp  # noqa: F401
    import scapy.layers.l2  # noqa: F401


def sniff_interfaces(iface: str) -> list[str] | str | None:
    """What to hand ``AsyncSniffer(iface=...)`` for the configured ``iface``.

    ``"any"`` must not become ``iface=None``: scapy 2.8 then opens one socket
    on every interface but types every frame it reads as ``Raw`` (the warning
    is "Unable to guess type ... Using Raw"), so ``udp and dst port 67`` never
    matches and the watch sees nothing -- silently, with the sniffer reported
    as started. Naming the interfaces parses them as Ethernet. Loopback is
    left out (no client DISCOVER arrives there). An interface that appears
    after start is not watched until the agent restarts; ``None`` means the
    host has no interface to name, and lets scapy pick its default.
    """
    if iface != "any":
        return iface
    try:
        names = sorted(n for n in os.listdir("/sys/class/net") if n != "lo")
    except OSError:
        return None
    return names or None


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


class DiscoverWatchShipper:
    """Sniffer thread + once-a-window POST loop for DISCOVER rates."""

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
            or os.environ.get("DHCP_DISCOVER_WATCH_IFACE")
            or os.environ.get("DHCP_FINGERPRINT_IFACE")
            or "any"
        )
        self._stop = threading.Event()
        self._window = DiscoverWindow(
            _env_int("DHCP_DISCOVER_WATCH_CLIENT_FLOOR", DEFAULT_CLIENT_FLOOR),
            _env_int("DHCP_DISCOVER_WATCH_RELAY_FLOOR", DEFAULT_RELAY_FLOOR),
        )
        self._sniffer: Any = None
        self._lock = threading.Lock()
        self._window_started = time.monotonic()
        self._shipper = Shipper(
            spool if spool is not None else disabled_spool("discover_rates"),
            CPPoster(
                cfg,
                token_ref,
                "/api/v1/dhcp/agents/discover-rates",
                late_bound(self, "_cp_client"),
            ),
            event_prefix="discover_watch_ship",
            retry_backoff_seconds=10.0,
        )

    def stop(self) -> None:
        self._stop.set()

    def _on_packet(self, packet: Any) -> None:
        try:
            parsed = parse_discover(packet)
        except Exception as exc:  # noqa: BLE001
            log.debug("discover_watch_parse_error", error=str(exc))
            return
        if parsed is None:
            return
        with self._lock:
            self._window.add(*parsed)

    def _start_sniffer(self) -> bool:
        try:
            from scapy.sendrecv import AsyncSniffer  # type: ignore[import-not-found]

            _load_layers()
        except ImportError as exc:
            log.warning("discover_watch_scapy_missing", error=str(exc))
            return False
        try:
            self._sniffer = AsyncSniffer(
                iface=sniff_interfaces(self.iface),
                filter="udp and dst port 67",
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "discover_watch_sniffer_start_failed", iface=self.iface, error=str(exc)
            )
            self._sniffer = None
            return False
        log.info("discover_watch_sniffer_started", iface=self.iface)
        return True

    def _cp_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _close_window(self) -> None:
        now = time.monotonic()
        seconds = max(10, min(3600, int(now - self._window_started)))
        self._window_started = now
        with self._lock:
            body = self._window.payload(seconds, datetime.now(UTC))
            self._window.reset()
        if body is not None:
            # Sent now, or spooled for replay; a 401 / 404 is retried rather
            # than dropped (the heartbeat thread owns re-bootstrap).
            self._shipper.ship(body)

    def run(self) -> None:
        log.info("discover_watch_starting", iface=self.iface)
        if not self._start_sniffer():
            log.warning("discover_watch_disabled_no_sniffer")
            while not self._stop.is_set():
                self._stop.wait(timeout=30.0)
            return
        while not self._stop.is_set():
            if time.monotonic() - self._window_started >= WINDOW_SECONDS:
                self._close_window()
            elif len(self._shipper.spool):
                self._shipper.drain()
            self._stop.wait(timeout=1.0)
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:  # noqa: BLE001
                log.debug("discover_watch_sniffer_stop_failed", error=str(exc))
        log.info("discover_watch_stopped")


__all__ = ["DiscoverWatchShipper", "DiscoverWindow", "parse_discover"]
