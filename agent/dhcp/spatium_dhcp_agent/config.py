"""Agent runtime configuration loaded from env vars."""

from __future__ import annotations

import os
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

# Whether the last pinned-trust read failed, so a missing pin is logged
# once when it goes missing and once when it arrives, not on every request.
# Every client-building thread passes through here, hence the lock.
_pin_lock = threading.Lock()
_pin_state = {"unavailable": False}


def _pin_changed(unavailable: bool) -> bool:
    """Record whether the pin is unavailable; True when that is a change."""
    with _pin_lock:
        changed = _pin_state["unavailable"] != unavailable
        _pin_state["unavailable"] = unavailable
        return changed


def pinned_context(path: str) -> ssl.SSLContext:
    """A TLS context that trusts exactly the certificate(s) in ``path`` (#1281).

    The same trust model as the supervisor's ``cp_tls.pinned_context``, whose
    pin file this reads on an appliance: ``VERIFY_X509_PARTIAL_CHAIN`` lets a
    pinned leaf be the trust anchor even when a CA issued it (an uploaded or
    ACME certificate), and the hostname is not checked, because the pinned
    certificate IS the identity and the operator may have typed an IP.
    ``TLS_CA_PATH`` cannot do this: it is a CA bundle checked with hostname
    verification, so a CA-issued pinned leaf fails there.

    Read on every call, which is every client build, so a certificate the
    supervisor re-pins is picked up without a restart. Fails CLOSED: a file
    that is missing, unreadable or holds no certificate yields a context with
    no trust anchor, so every handshake fails until the supervisor has pinned.
    No system CAs are loaded either way.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    try:
        pem = Path(path).read_text(encoding="ascii")
        if "BEGIN CERTIFICATE" not in pem:
            raise ValueError("no certificate in the file")
        ctx.load_verify_locations(cadata=pem)
    except (OSError, ValueError, ssl.SSLError) as exc:
        if _pin_changed(True):
            log.warning(
                "control_plane_pin_unavailable",
                path=path,
                error=str(exc),
                detail=(
                    "No pinned control-plane certificate to verify against yet, "
                    "so every request to the control plane fails until the "
                    "supervisor pins one."
                ),
            )
        return ctx
    if _pin_changed(False):
        log.info("control_plane_pin_loaded", path=path)
    return ctx


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
        TLS_PINNED_CERTS_PATH      — trust exactly these certificates (#1281)
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
    # #1281 — pinned trust (the supervisor's pin, on an appliance). Wins over
    # tls_ca_path and the skip; see ``pinned_context``.
    tls_pinned_certs_path: str | None = None

    @property
    def kea_lease_file_v6(self) -> Path:
        """kea-dhcp6's memfile: the v4 path with the family digit swapped
        (``kea-leases4.csv`` → ``kea-leases6.csv``), the derivation the
        render and the lease tailer share so they never disagree (#1141)."""
        return Path(str(self.kea_lease_file).replace("leases4", "leases6"))

    def httpx_verify(self) -> bool | str | ssl.SSLContext:
        """Resolve the ``verify=`` argument for every control-plane client.

        ``TLS_PINNED_CERTS_PATH`` wins over everything (#1281): it is what the
        appliance chart sets, pointing at the supervisor's pin, in place of the
        skip it used to set. ``TLS_CA_PATH`` wins over
        ``SPATIUM_INSECURE_SKIP_TLS_VERIFY`` (#1220): an operator who mounted
        the control plane's CA meant it to be used, and the skip used to win
        silently, so following the documented CA setup while the compose
        default still said ``1`` verified nothing.

        The pin is consulted only for an ``https://`` URL: over ``http://``
        there is no certificate, and building the context there would log
        ``control_plane_pin_unavailable`` (a supervisor pins nothing for a
        plain-http control plane) while every request in fact succeeds.
        """
        if self.tls_pinned_certs_path and self.control_plane_url.lower().startswith(
            "https://"
        ):
            return pinned_context(self.tls_pinned_certs_path)
        if self.tls_ca_path:
            return self.tls_ca_path
        return not self.insecure_skip_tls_verify

    def tls_warning(self) -> str | None:
        """What to warn about at every start, or None. Only for ``https``:
        against a plain-``http`` URL (the in-stack ``http://api:8000``)
        there is no certificate to verify either way."""
        if not self.control_plane_url.lower().startswith("https://"):
            return None
        if self.tls_pinned_certs_path:
            ignored = [
                name
                for name, is_set in (
                    ("TLS_CA_PATH", bool(self.tls_ca_path)),
                    (
                        "SPATIUM_INSECURE_SKIP_TLS_VERIFY=1",
                        self.insecure_skip_tls_verify,
                    ),
                )
                if is_set
            ]
            if not ignored:
                return None
            return (
                f"{' and '.join(ignored)} ignored because TLS_PINNED_CERTS_PATH is "
                "set: the control plane is verified against the certificates "
                "pinned there"
            )
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
            tls_pinned_certs_path=os.environ.get("TLS_PINNED_CERTS_PATH") or None,
            insecure_skip_tls_verify=os.environ.get("SPATIUM_INSECURE_SKIP_TLS_VERIFY")
            == "1",
            heartbeat_interval=float(os.environ.get("HEARTBEAT_INTERVAL", "30")),
            longpoll_timeout=float(os.environ.get("LONGPOLL_TIMEOUT", "30")),
        )
