"""Supervisor — runs sync + heartbeat + lease-watcher threads.

kea-dhcp4 itself runs as a sibling process under tini in the container; the
agent supervises its own tasks and reloads Kea via the control socket. If any
thread crashes (and doesn't recover), the process exits non-zero so the
container orchestrator restarts us.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time

import structlog

from .bootstrap import ensure_token
from .config import AgentConfig
from .dhcp_fingerprint import DhcpFingerprintShipper
from .rogue_probe import RogueProbeShipper
from .ha_status import HAStatusPoller
from .heartbeat import HeartbeatClient
from .leases import LeaseWatcher
from .log_shipper import LogShipper
from .mac_sighting import MacSightingShipper
from .metrics import MetricsPoller
from .peer_resolve import PeerResolveWatcher
from .ra_sniffer import RASnifferShipper
from .spool import SpoolManager
from .sync import SyncLoop, clear_ready_marker

log = structlog.get_logger(__name__)

#: #1077 — the control plane keeps DHCP activity logs 24 h (``prune_logs.py``);
#: a spooled batch older than that would be pruned on arrival.
DEFAULT_LOG_MAX_AGE_HOURS = 24.0

#: Stream → share of ``AGENT_SPOOL_MAX_BYTES``. Relative weights; the manager
#: normalises them. Activity logs dominate by volume. Lease events are the
#: correctness stream (the control plane has no other way to learn a Kea
#: lease), so they get a generous share and no age limit. Metrics are one
#: small row a minute — weeks fit in their share. The rogue-DHCP probe and the
#: HA-state poller are absent on purpose: both push a reading of the present
#: that the next cycle regenerates, so replaying one late would be wrong.
SPOOL_SHARES: dict[str, float] = {
    "dhcp_log": 0.55,
    "lease_events": 0.25,
    "metrics": 0.05,
    "mac_sightings": 0.05,
    "fingerprints": 0.04,
    "ra_observations": 0.06,
}


def _log_max_age_seconds() -> float | None:
    """``AGENT_SPOOL_LOG_MAX_AGE_HOURS`` as seconds; ``0`` disables expiry."""
    raw = os.environ.get("AGENT_SPOOL_LOG_MAX_AGE_HOURS", "")
    try:
        hours = float(raw) if raw.strip() else DEFAULT_LOG_MAX_AGE_HOURS
    except ValueError:
        log.warning("agent_spool_log_max_age_invalid", value=raw)
        hours = DEFAULT_LOG_MAX_AGE_HOURS
    return hours * 3600 if hours > 0 else None


def build_spool_manager(cfg: AgentConfig) -> SpoolManager:
    """The DHCP agent's durable push spool (#1077), one stream per shipper.

    Every stream is declared whether or not its shipper is enabled, so turning
    a sniffer on later never re-divides the byte budget under a backlog.
    """
    manager = SpoolManager(cfg.state_dir)
    for stream, share in SPOOL_SHARES.items():
        age = _log_max_age_seconds() if stream == "dhcp_log" else None
        manager.declare(stream, share, max_age_seconds=age)
    return manager


def run(cfg: AgentConfig) -> int:
    _agent_id, token = ensure_token(cfg)
    token_ref = [token]

    spools = build_spool_manager(cfg)
    heartbeat = HeartbeatClient(cfg, token_ref, spool_manager=spools)
    ha_poller = HAStatusPoller(cfg, token_ref)
    # Construct the watcher first (SyncLoop needs the reference in its
    # ``__init__``), then arm it once the SyncLoop exists. Issue #265 —
    # the old ``syncer_holder[0]`` closure could fire against an empty
    # list if anything in SyncLoop ever invoked the apply path during
    # construction; the explicit ``set_apply_fn`` setter rules that
    # footgun out at compile time.
    peer_watcher = PeerResolveWatcher()
    syncer = SyncLoop(
        cfg, token_ref, heartbeat, ha_poller=ha_poller, peer_watcher=peer_watcher
    )
    peer_watcher.set_apply_fn(
        lambda bundle, reload_kea=True: syncer._apply_bundle(
            bundle, reload_kea=reload_kea
        )
    )
    leases = LeaseWatcher(cfg, token_ref, heartbeat, spool=spools.get("lease_events"))
    metrics = MetricsPoller(cfg, token_ref, spool=spools.get("metrics"))
    log_shipper = LogShipper(cfg, token_ref, spool=spools.get("dhcp_log"))

    # Passive DHCP fingerprinting is opt-in (Phase 2 device profiling).
    # Default off because:
    #   1. The container needs CAP_NET_RAW to bind the BPF socket, and
    #      we don't want to silently fail when the cap isn't granted.
    #   2. scapy is a heavyweight import — we don't want the cost on
    #      deployments that aren't using fingerprinting.
    # Operators flip DHCP_FINGERPRINT_ENABLED=1 in their compose env
    # to turn it on; the cap_add must be set in the compose override
    # too (see docs/deployment/DOCKER.md).
    fingerprint_enabled = os.environ.get("DHCP_FINGERPRINT_ENABLED", "0") == "1"
    fingerprint_shipper: DhcpFingerprintShipper | None = None
    if fingerprint_enabled:
        fingerprint_shipper = DhcpFingerprintShipper(
            cfg, token_ref, spool=spools.get("fingerprints")
        )
        log.info("dhcp_fingerprint_enabled")

    # Active rogue-DHCP probe (issue #370) — opt-in for the same CAP_NET_RAW +
    # scapy reasons as fingerprinting. Broadcasts a DISCOVER on an interval and
    # ships observed OFFERs so the control plane can flag unknown responders.
    rogue_probe_enabled = os.environ.get("DHCP_ROGUE_PROBE_ENABLED", "0") == "1"
    rogue_probe: RogueProbeShipper | None = None
    if rogue_probe_enabled:
        rogue_probe = RogueProbeShipper(cfg, token_ref)
        log.info("dhcp_rogue_probe_enabled")

    # Arpwatch-style L2 sighting sniffer (issue #459, Phase 3) — opt-in for the
    # same CAP_NET_RAW + scapy reasons as fingerprinting. Observes source MACs
    # on the wire (ARP + IPv6 ND) even for devices that never do DHCP, and ships
    # first-sightings so the control plane can flag them as new devices.
    mac_sighting_enabled = os.environ.get("DHCP_MAC_SIGHTING_ENABLED", "0") == "1"
    mac_sighting_shipper: MacSightingShipper | None = None
    if mac_sighting_enabled:
        mac_sighting_shipper = MacSightingShipper(
            cfg, token_ref, spool=spools.get("mac_sightings")
        )
        log.info("dhcp_mac_sighting_enabled")

    # Passive IPv6 Router-Advertisement sniffer (issue #524) — opt-in for the
    # same CAP_NET_RAW + scapy reasons as fingerprinting. Observes ICMPv6
    # type-134 RAs and ships them so the control plane can flag unknown routers
    # (rogue_ra alert).
    ra_sniffer_enabled = os.environ.get("DHCP_RA_SNIFFER_ENABLED", "0") == "1"
    ra_sniffer_shipper: RASnifferShipper | None = None
    if ra_sniffer_enabled:
        ra_sniffer_shipper = RASnifferShipper(
            cfg, token_ref, spool=spools.get("ra_observations")
        )
        log.info("dhcp_ra_sniffer_enabled")

    threads = [
        threading.Thread(target=syncer.run, name="sync", daemon=True),
        threading.Thread(target=heartbeat.run, name="heartbeat", daemon=True),
        threading.Thread(target=leases.run, name="leases", daemon=True),
        threading.Thread(target=ha_poller.run, name="ha-status", daemon=True),
        threading.Thread(target=peer_watcher.run, name="peer-resolve", daemon=True),
        threading.Thread(target=metrics.run, name="metrics", daemon=True),
        threading.Thread(target=log_shipper.run, name="log-shipper", daemon=True),
    ]
    if fingerprint_shipper is not None:
        threads.append(
            threading.Thread(
                target=fingerprint_shipper.run,
                name="dhcp-fingerprint",
                daemon=True,
            )
        )
    if rogue_probe is not None:
        threads.append(
            threading.Thread(target=rogue_probe.run, name="rogue-probe", daemon=True)
        )
    if mac_sighting_shipper is not None:
        threads.append(
            threading.Thread(
                target=mac_sighting_shipper.run,
                name="mac-sighting",
                daemon=True,
            )
        )
    if ra_sniffer_shipper is not None:
        threads.append(
            threading.Thread(
                target=ra_sniffer_shipper.run,
                name="ra-sniffer",
                daemon=True,
            )
        )
    for t in threads:
        t.start()

    stopping = threading.Event()

    def _sig(_signum, _frame):  # noqa: ANN001
        log.info("dhcp_agent_signal_received")
        stopping.set()
        heartbeat.stop()
        syncer.stop()
        leases.stop()
        ha_poller.stop()
        peer_watcher.stop()
        metrics.stop()
        log_shipper.stop()
        if fingerprint_shipper is not None:
            fingerprint_shipper.stop()
        if rogue_probe is not None:
            rogue_probe.stop()
        if mac_sighting_shipper is not None:
            mac_sighting_shipper.stop()
        if ra_sniffer_shipper is not None:
            ra_sniffer_shipper.stop()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    while not stopping.is_set():
        time.sleep(1.0)
        # If any critical thread died, bubble up so the container restarts.
        dead = [t.name for t in threads if not t.is_alive()]
        if dead:
            log.error("dhcp_agent_thread_died", threads=dead)
            # #1043 — stop claiming readiness on the way out. The container
            # exit is what actually restarts us, but the kea entrypoint used
            # to outlive this return, leaving a Ready pod with no agent in it.
            # Clearing the marker makes that state visible rather than green.
            clear_ready_marker(cfg.state_dir)
            return 2

    log.info("dhcp_agent_exiting")
    return 0


def main_entry() -> int:
    cfg = AgentConfig.from_env()
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    return run(cfg)


if __name__ == "__main__":
    sys.exit(main_entry())
