"""Agent runtime configuration loaded from env vars."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentConfig:
    control_plane_url: str
    # Long-PSK bootstrap key. Issue #246 — pairing-code exchange via the
    # removed ``POST /api/v1/appliance/pair`` endpoint is no longer
    # supported here; standalone agents paste ``DNS_AGENT_KEY``
    # directly and Application appliances receive it via the
    # supervisor's ``role-compose.env``.
    dns_agent_key: str
    server_name: str
    driver: str  # bind9 | powerdns | technitium (see supervisor.py for the registry)
    roles: list[str]
    group_name: str | None
    tls_ca_path: str | None
    insecure_skip_tls_verify: bool
    state_dir: Path
    heartbeat_interval: float = 30.0
    longpoll_timeout: float = 30.0

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
        key = os.environ.get("DNS_AGENT_KEY", "")
        if not key:
            raise RuntimeError(
                "DNS_AGENT_KEY is required. Issue #246 removed the "
                "pairing-code → PSK exchange (the underlying control-plane "
                "endpoint was retired in #170 Wave A3); paste the long hex "
                "key directly. Application appliances receive it via the "
                "supervisor's role-compose.env automatically."
            )
        roles_raw = os.environ.get("AGENT_ROLES", "authoritative")
        roles = [r.strip() for r in roles_raw.split(",") if r.strip()]
        return cls(
            control_plane_url=cp,
            dns_agent_key=key,
            server_name=os.environ.get("SERVER_NAME")
            or os.environ.get("AGENT_HOSTNAME")
            or os.uname().nodename,
            driver=os.environ.get("AGENT_DRIVER", "bind9"),
            roles=roles,
            group_name=os.environ.get("AGENT_GROUP") or None,
            tls_ca_path=os.environ.get("TLS_CA_PATH") or None,
            insecure_skip_tls_verify=os.environ.get("SPATIUM_INSECURE_SKIP_TLS_VERIFY")
            == "1",
            state_dir=Path(
                os.environ.get("AGENT_STATE_DIR", "/var/lib/spatium-dns-agent")
            ),
        )
