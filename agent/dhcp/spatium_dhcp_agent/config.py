"""Agent runtime configuration loaded from env vars."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentConfig:
    """Runtime configuration for the DHCP agent.

    Env vars:
        SPATIUM_API_URL            — control-plane base URL (required)
        SPATIUM_AGENT_KEY          — bootstrap pre-shared key (required)
        SPATIUM_SERVER_NAME        — hostname reported to the control plane
        CACHE_DIR                  — state directory (default /var/lib/spatium-dhcp-agent)
        KEA_CONFIG_PATH            — Kea dhcp4 config path (default /etc/kea/kea-dhcp4.conf)
        KEA_CONTROL_SOCKET         — Kea dhcp4 control unix socket (default /run/kea/kea4-ctrl-socket)
        KEA_LEASE_FILE             — Kea dhcp4 leases memfile (default /var/lib/kea/kea-leases4.csv)
        KEA_CONFIG_PATH_V6         — Kea dhcp6 config path (default /etc/kea/kea-dhcp6.conf)
        KEA_CONTROL_SOCKET_V6      — Kea dhcp6 control unix socket (default /run/kea/kea6-ctrl-socket)
        LONGPOLL_TIMEOUT           — seconds the control plane holds a long-poll (default 30)
        HEARTBEAT_INTERVAL         — seconds between heartbeats (default 30)
        AGENT_GROUP                — optional DHCP server group to join
        AGENT_ROLES                — comma-separated: primary,secondary,failover
        TLS_CA_PATH                — optional custom CA bundle
        SPATIUM_INSECURE_SKIP_TLS_VERIFY=1  — dev only
    """

    control_plane_url: str
    # Long-PSK bootstrap key. Issue #246 — pairing-code exchange via the
    # removed ``POST /api/v1/appliance/pair`` endpoint is no longer
    # supported here; standalone agents paste ``SPATIUM_AGENT_KEY``
    # directly and Application appliances receive it via the
    # supervisor's ``role-compose.env``.
    agent_key: str
    server_name: str
    state_dir: Path
    kea_config_path: Path
    kea_control_socket: Path
    kea_lease_file: Path
    kea_config_path_v6: Path
    kea_control_socket_v6: Path
    group_name: str | None
    roles: list[str]
    tls_ca_path: str | None
    insecure_skip_tls_verify: bool
    heartbeat_interval: float = 30.0
    longpoll_timeout: float = 30.0

    @property
    def kea_lease_file_v6(self) -> Path:
        """kea-dhcp6's memfile: the v4 path with the family digit swapped
        (``kea-leases4.csv`` → ``kea-leases6.csv``), the derivation the
        render and the lease tailer share so they never disagree (#1141)."""
        return Path(str(self.kea_lease_file).replace("leases4", "leases6"))

    def httpx_verify(self) -> bool | str:
        """Resolve the ``verify=`` argument for ``httpx.Client`` calls.

        Issue #266 — was previously duplicated across 9 modules. Single
        source of truth: ``insecure_skip_tls_verify`` (dev-only override)
        wins over a custom CA bundle; the default is full verification.
        """
        if self.insecure_skip_tls_verify:
            return False
        if self.tls_ca_path:
            return self.tls_ca_path
        return True

    @classmethod
    def from_env(cls) -> "AgentConfig":
        cp = os.environ.get("SPATIUM_API_URL", "").rstrip("/")
        if not cp:
            raise RuntimeError("SPATIUM_API_URL is required")
        key = os.environ.get("SPATIUM_AGENT_KEY", "")
        if not key:
            raise RuntimeError(
                "SPATIUM_AGENT_KEY is required. Issue #246 removed the "
                "pairing-code → PSK exchange (the underlying control-plane "
                "endpoint was retired in #170 Wave A3); paste the long hex "
                "key directly. Application appliances receive it via the "
                "supervisor's role-compose.env automatically."
            )
        roles_raw = os.environ.get("AGENT_ROLES", "primary")
        roles = [r.strip() for r in roles_raw.split(",") if r.strip()]
        return cls(
            control_plane_url=cp,
            agent_key=key,
            server_name=(
                os.environ.get("SPATIUM_SERVER_NAME")
                or os.environ.get("AGENT_HOSTNAME")
                or os.uname().nodename
            ),
            state_dir=Path(os.environ.get("CACHE_DIR", "/var/lib/spatium-dhcp-agent")),
            kea_config_path=Path(
                os.environ.get("KEA_CONFIG_PATH", "/etc/kea/kea-dhcp4.conf")
            ),
            kea_control_socket=Path(
                os.environ.get("KEA_CONTROL_SOCKET", "/run/kea/kea4-ctrl-socket")
            ),
            kea_lease_file=Path(
                os.environ.get("KEA_LEASE_FILE", "/var/lib/kea/kea-leases4.csv")
            ),
            kea_config_path_v6=Path(
                os.environ.get("KEA_CONFIG_PATH_V6", "/etc/kea/kea-dhcp6.conf")
            ),
            kea_control_socket_v6=Path(
                os.environ.get("KEA_CONTROL_SOCKET_V6", "/run/kea/kea6-ctrl-socket")
            ),
            group_name=os.environ.get("AGENT_GROUP") or None,
            roles=roles,
            tls_ca_path=os.environ.get("TLS_CA_PATH") or None,
            insecure_skip_tls_verify=os.environ.get("SPATIUM_INSECURE_SKIP_TLS_VERIFY")
            == "1",
            heartbeat_interval=float(os.environ.get("HEARTBEAT_INTERVAL", "30")),
            longpoll_timeout=float(os.environ.get("LONGPOLL_TIMEOUT", "30")),
        )
