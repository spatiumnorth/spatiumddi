"""Environment-driven config for the supervisor.

Phase A1 only consumes the bare-minimum surface — enough to log a
useful identity line and idle. Wave A2 will extend this with identity
state-dir handling + control-plane URL semantics.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SupervisorConfig:
    control_plane_url: str
    hostname: str
    state_dir: Path
    bootstrap_pairing_code: str
    heartbeat_interval_seconds: int
    k8s_proxy_enabled: bool
    in_pod_firewall_enabled: bool

    @classmethod
    def from_env(cls) -> "SupervisorConfig":
        return cls(
            control_plane_url=os.environ.get("CONTROL_PLANE_URL", "").rstrip("/"),
            hostname=os.environ.get("APPLIANCE_HOSTNAME") or socket.gethostname(),
            state_dir=Path(os.environ.get("STATE_DIR", "/var/lib/spatium-supervisor")),
            # Strip non-digit characters so a dash-separated code
            # (``1234-5678`` — how the frontend formats 8-digit codes
            # for readability) hashes to the same canonical form as
            # the bare ``12345678``. Backend validator does the same
            # strip; this is belt-and-braces so the env contract is
            # operator-friendly too.
            bootstrap_pairing_code="".join(
                ch
                for ch in os.environ.get("BOOTSTRAP_PAIRING_CODE", "")
                if ch.isdigit()
            ),
            heartbeat_interval_seconds=int(
                # 30s default cadence — operator feedback that 60s
                # felt sluggish on role-swap, since
                # ``reconcile_node_labels`` only fires per
                # heartbeat. 30s halves time-to-react and is still
                # well within control-plane budget on fleets up to
                # ~hundreds of appliances. Service-container
                # self-healing (the watchdog at 5 min) is a
                # separate cadence and doesn't change.
                os.environ.get("HEARTBEAT_INTERVAL_SECONDS", "30")
            ),
            # Phase 4 (#183) control-plane -> kubeapi proxy. It was
            # default-off while the control-plane half had not landed
            # (every poll 404'd); that half has shipped, and with the
            # loop off the Fleet pod list and pod logs always answer
            # 504 (#3618). Default on like the nettool / storage / pcap
            # loops; K8S_PROXY_ENABLED=false stays as the opt-out. The
            # loop only polls on a k3s runtime, so it is dormant elsewhere.
            k8s_proxy_enabled=os.environ.get("K8S_PROXY_ENABLED", "true").lower()
            in ("1", "true", "yes", "on"),
            # Phase 9 (#183) firewall management. The original in-pod
            # path tried to nft-write inside the pod (broken — pod fs
            # has no /etc/nftables.conf to reload) so this was gated
            # off. Phase 9 rewrote it to write a trigger file via the
            # /var/lib/spatiumddi-host/release-state hostPath mount;
            # the host-side spatium-firewall-reload.path watches that
            # file and fires the runner which does the actual nft
            # validate + apply. The trigger-file shape is benign on
            # docker / k8s deployments (the .path unit isn't there)
            # so default on; flip to off only as a panic-disable.
            in_pod_firewall_enabled=os.environ.get(
                "IN_POD_FIREWALL_ENABLED", "true"
            ).lower()
            in ("1", "true", "yes", "on"),
        )
