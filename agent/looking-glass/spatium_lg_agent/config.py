"""Agent runtime configuration loaded from env vars."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentConfig:
    """Runtime configuration for the BGP Looking Glass collector agent.

    Env vars:
        CONTROL_PLANE_URL         — control-plane base URL (required)
        LG_AGENT_KEY              — bootstrap pre-shared key (required)
        AGENT_STATE_DIR           — state directory (default /var/lib/spatium-lg-agent)
        GOBGPD_CONFIG_PATH        — rendered gobgpd config path (default /etc/gobgp/gobgpd.json)
        GOBGPD_BIN                — path to the ``gobgpd`` daemon binary (default /usr/local/bin/gobgpd)
        GOBGP_BIN                 — path to the ``gobgp`` CLI binary (default /usr/local/bin/gobgp)
        GOBGP_GRPC_HOST           — gobgpd's local gRPC listener host (default 127.0.0.1 — loopback only)
        GOBGP_GRPC_PORT           — gobgpd's local gRPC listener port (default 50051)
        RIB_POLL_INTERVAL         — seconds between RIB + neighbor-state polls (default 30)
        HEARTBEAT_INTERVAL        — seconds between heartbeats (default 30)
        LONGPOLL_TIMEOUT          — seconds the control plane holds the config long-poll (default 30)
        SERVER_NAME / AGENT_HOSTNAME — hostname reported to the control plane
        TLS_CA_PATH               — optional custom CA bundle
        SPATIUM_INSECURE_SKIP_TLS_VERIFY=1  — dev only
    """

    control_plane_url: str
    # Long-PSK bootstrap key. Mirrors DNS_AGENT_KEY / SPATIUM_AGENT_KEY —
    # issue #246 removed the pairing-code exchange via the now-gone
    # ``POST /api/v1/appliance/pair`` endpoint (retired in #170 Wave A3).
    # There is no equivalent ``/pair`` flow for a brand-new agent kind;
    # standalone agents paste the long hex key directly, Application
    # appliances receive it via the supervisor's ``role-compose.env``.
    lg_agent_key: str
    server_name: str
    state_dir: Path
    gobgpd_config_path: Path
    gobgpd_bin: str
    gobgp_bin: str
    gobgp_grpc_host: str
    gobgp_grpc_port: int
    tls_ca_path: str | None
    insecure_skip_tls_verify: bool
    heartbeat_interval: float = 30.0
    longpoll_timeout: float = 30.0
    rib_poll_interval: float = 30.0

    def httpx_verify(self) -> bool | str:
        """Resolve the ``verify=`` argument for every control-plane client.

        ``TLS_CA_PATH`` wins over ``SPATIUM_INSECURE_SKIP_TLS_VERIFY`` (#1220):
        an operator who mounted the control plane's CA meant it to be used,
        and the skip used to win silently, so following the documented CA
        setup while the compose default still said ``1`` verified nothing.
        """
        if self.tls_ca_path:
            return self.tls_ca_path
        return not self.insecure_skip_tls_verify

    def tls_warning(self) -> str | None:
        """What to warn about at every start, or None. Only for ``https``:
        against a plain-``http`` URL (the in-stack ``http://api:8000``)
        there is no certificate to verify either way."""
        if not self.control_plane_url.lower().startswith("https://"):
            return None
        if self.tls_ca_path and self.insecure_skip_tls_verify:
            return (
                "SPATIUM_INSECURE_SKIP_TLS_VERIFY=1 is ignored because TLS_CA_PATH is "
                "set: the control plane is verified against that CA"
            )
        if self.insecure_skip_tls_verify:
            return (
                "TLS verification of the control plane is OFF "
                "(SPATIUM_INSECURE_SKIP_TLS_VERIFY=1): anyone on the network path "
                "can read the agent key and serve this agent its configuration. "
                "Mount the control plane's CA and set TLS_CA_PATH instead"
            )
        return None

    @classmethod
    def from_env(cls) -> "AgentConfig":
        cp = os.environ.get("CONTROL_PLANE_URL", "").rstrip("/")
        if not cp:
            raise RuntimeError("CONTROL_PLANE_URL is required")
        key = os.environ.get("LG_AGENT_KEY", "")
        if not key:
            raise RuntimeError(
                "LG_AGENT_KEY is required. Issue #246 removed the "
                "pairing-code → PSK exchange (the underlying control-plane "
                "endpoint was retired in #170 Wave A3); paste the long hex "
                "key directly. Application appliances receive it via the "
                "supervisor's role-compose.env automatically."
            )
        return cls(
            control_plane_url=cp,
            lg_agent_key=key,
            server_name=(
                os.environ.get("SERVER_NAME")
                or os.environ.get("AGENT_HOSTNAME")
                or os.uname().nodename
            ),
            state_dir=Path(
                os.environ.get("AGENT_STATE_DIR", "/var/lib/spatium-lg-agent")
            ),
            gobgpd_config_path=Path(
                os.environ.get("GOBGPD_CONFIG_PATH", "/etc/gobgp/gobgpd.json")
            ),
            gobgpd_bin=os.environ.get("GOBGPD_BIN", "/usr/local/bin/gobgpd"),
            gobgp_bin=os.environ.get("GOBGP_BIN", "/usr/local/bin/gobgp"),
            gobgp_grpc_host=os.environ.get("GOBGP_GRPC_HOST", "127.0.0.1"),
            gobgp_grpc_port=int(os.environ.get("GOBGP_GRPC_PORT", "50051")),
            tls_ca_path=os.environ.get("TLS_CA_PATH") or None,
            insecure_skip_tls_verify=os.environ.get("SPATIUM_INSECURE_SKIP_TLS_VERIFY")
            == "1",
            heartbeat_interval=float(os.environ.get("HEARTBEAT_INTERVAL", "30")),
            longpoll_timeout=float(os.environ.get("LONGPOLL_TIMEOUT", "30")),
            rib_poll_interval=float(os.environ.get("RIB_POLL_INTERVAL", "30")),
        )
