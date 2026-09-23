"""Active rogue-DHCP probe (issue #370).

Periodically broadcasts a DHCP DISCOVER on the managed interface and collects
every OFFER that comes back, shipping the observed responders to the control
plane (``POST /api/v1/dhcp/agents/dhcp-offers``). The control plane classifies
each responder against the group's known DHCP servers + the operator allowlist
and fires the ``rogue_dhcp`` alert on unknown ones.

Disabled by default — operators opt in with ``DHCP_ROGUE_PROBE_ENABLED=1``
because:

  1. The container needs ``CAP_NET_RAW`` to send + sniff raw frames (the same
     cap the passive fingerprint sniffer needs).
  2. Broadcasting a DISCOVER puts (tiny) extra traffic on the segment.

The probe is DISCOVER-only and uses a spoofed locally-administered source MAC +
a random transaction id, and never sends a REQUEST — so it never actually
consumes a lease. A failed ship is logged and dropped; the heartbeat thread
owns re-bootstrap on 401 / 404.

Deliberately NOT spooled (#1077), unlike the passive sniffers: each probe is a
fresh reading of what answers on the segment *now*, repeated every
``interval``, and the payload carries no observation time. A replayed batch
would be stamped with its arrival time on the control plane, reporting a
responder that may have left hours ago as currently present; a responder that
is still there is simply observed again on the next probe after reconnect.
"""

from __future__ import annotations

import os
import secrets
import threading
from typing import Any

import httpx
import structlog

from .config import AgentConfig

log = structlog.get_logger(__name__)

# How long to listen for OFFERs after each DISCOVER, and how often to probe.
COLLECT_WINDOW = 4.0
DEFAULT_INTERVAL = 300.0
DHCP_OFFER = 2


def _random_mac() -> str:
    """A locally-administered, unicast random MAC (bit 1 of first octet set,
    bit 0 clear) so the probe never collides with a real device's MAC."""
    b = bytearray(secrets.token_bytes(6))
    b[0] = (b[0] & 0xFC) | 0x02
    return ":".join(f"{x:02x}" for x in b)


class RogueProbeShipper:
    """Probe thread: broadcast DISCOVER → collect OFFERs → ship observed
    responders. One probe per ``interval`` seconds."""

    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        iface: str | None = None,
    ) -> None:
        self.cfg = cfg
        self.token_ref = token_ref
        self.iface = (
            iface
            or os.environ.get("DHCP_ROGUE_PROBE_IFACE")
            or os.environ.get("DHCP_FINGERPRINT_IFACE")
            or "any"
        )
        try:
            self.interval = float(
                os.environ.get("DHCP_ROGUE_PROBE_INTERVAL", str(DEFAULT_INTERVAL))
            )
        except ValueError:
            self.interval = DEFAULT_INTERVAL
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _cp_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _probe_once(self) -> list[dict[str, Any]]:
        """Broadcast one DISCOVER and return the observed OFFERs.

        Returns ``[]`` (and logs) when scapy is missing or the send fails —
        the run loop keeps spinning so a transient cap issue self-heals.
        """
        try:
            from scapy.layers.dhcp import BOOTP, DHCP  # type: ignore[import-not-found]
            from scapy.layers.inet import IP, UDP  # type: ignore[import-not-found]
            from scapy.layers.l2 import Ether  # type: ignore[import-not-found]
            from scapy.sendrecv import AsyncSniffer, sendp  # type: ignore[import-not-found]
        except ImportError as exc:
            log.warning("rogue_probe_scapy_missing", error=str(exc))
            return []

        src_mac = _random_mac()
        xid = secrets.randbits(32)
        offers: list[dict[str, Any]] = []

        def _on_pkt(pkt: Any) -> None:
            try:
                if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
                    return
                bootp = pkt[BOOTP]
                if int(getattr(bootp, "xid", -1)) != xid:
                    return  # not a reply to our probe
                opts = {
                    o[0]: o[1]
                    for o in pkt[DHCP].options
                    if isinstance(o, tuple) and len(o) >= 2
                }
                if int(opts.get("message-type", 0)) != DHCP_OFFER:
                    return
                server_id = opts.get("server_id")
                offers.append(
                    {
                        "server_identifier": str(server_id) if server_id else "",
                        "source_ip": pkt[IP].src if pkt.haslayer(IP) else "",
                        "source_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
                        "giaddr": str(getattr(bootp, "giaddr", "") or "") or None,
                        "offered_ip": str(getattr(bootp, "yiaddr", "") or "") or None,
                    }
                )
            except Exception as exc:  # noqa: BLE001 — never let one packet kill the probe
                log.debug("rogue_probe_parse_error", error=str(exc))

        iface = None if self.iface == "any" else self.iface
        sniffer = AsyncSniffer(
            iface=iface, filter="udp and (port 67 or port 68)", prn=_on_pkt, store=False
        )
        try:
            sniffer.start()
            discover = (
                Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src="0.0.0.0", dst="255.255.255.255")
                / UDP(sport=68, dport=67)
                / BOOTP(chaddr=bytes.fromhex(src_mac.replace(":", "")), xid=xid, flags=0x8000)
                / DHCP(options=[("message-type", "discover"), "end"])
            )
            sendp(discover, iface=iface, verbose=False)
            self._stop.wait(timeout=COLLECT_WINDOW)
        except Exception as exc:  # noqa: BLE001 — send/sniff failure is non-fatal
            log.warning("rogue_probe_send_failed", iface=self.iface, error=str(exc))
        finally:
            try:
                sniffer.stop()
            except Exception:  # noqa: BLE001 — sniffer never started cleanly
                pass
        # Dedupe by (server-id, source-ip).
        seen: set[tuple[str, str]] = set()
        uniq: list[dict[str, Any]] = []
        for o in offers:
            key = (o["server_identifier"], o["source_ip"])
            if key in seen or not o["source_ip"]:
                continue
            seen.add(key)
            uniq.append(o)
        return uniq

    def _ship(self, offers: list[dict[str, Any]]) -> None:
        if not offers:
            return
        try:
            with self._cp_client() as c:
                resp = c.post(
                    "/api/v1/dhcp/agents/dhcp-offers",
                    json={"offers": offers},
                    headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                )
        except httpx.HTTPError as exc:
            log.warning("rogue_probe_ship_http_error", error=str(exc), count=len(offers))
            return
        if resp.status_code in (401, 404):
            log.warning("rogue_probe_unauthorized", status=resp.status_code)
        elif resp.status_code not in (200, 204):
            log.warning("rogue_probe_ship_failed", status=resp.status_code)

    def run(self) -> None:
        log.info("rogue_probe_starting", iface=self.iface, interval=self.interval)
        while not self._stop.is_set():
            try:
                offers = self._probe_once()
                if offers:
                    log.info("rogue_probe_observed", count=len(offers))
                self._ship(offers)
            except Exception as exc:  # noqa: BLE001 — keep the loop alive
                log.warning("rogue_probe_cycle_failed", error=str(exc))
            self._stop.wait(timeout=self.interval)
        log.info("rogue_probe_stopped")
