"""Issue #154 — appliance NTP support (chrony).

Source-of-truth lives on ``platform_settings``; this module renders
an ``/etc/chrony/chrony.conf`` payload from those columns and folds
the rendered text into the DNS + DHCP ConfigBundle long-poll so
every appliance host picks it up the same way Issue #153 (SNMP)
distributes snmpd.conf.

Design notes:

* chrony already ships in mkosi.conf and the postinst enables it
  with a default ``pool pool.ntp.org iburst`` line (cloud-init's
  default). So unlike SNMP — which we ship disabled — NTP is
  always running. This module just lets operators steer the source
  list (air-gapped, internal NTP, compliance shops, …) and
  optionally turn the appliance into a time server.
* chrony supports a hot reload of the server lines via
  ``chronyc reload sources``, but reloading via the systemd unit
  re-reads the whole config — including ``allow`` lines — which
  is what we need for the ``ntp_allow_clients`` path. So the
  runner uses ``systemctl reload chrony`` for everything.
* No secrets — NTP hostnames are not sensitive. Contrast with
  SNMP where the v2c community is a Fernet-encrypted credential.
  The flat read endpoint returns the whole shape directly.
* Empty / inert configurations still produce a *valid* chrony.conf
  body so the runner can compare byte-for-byte against the on-disk
  file and skip the reload when nothing changed.
"""

from __future__ import annotations

import hashlib
from ipaddress import ip_network
from typing import Any

import structlog

from app.core.config_text import has_control_chars
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)


def _is_single_token(value: Any) -> bool:
    """True for a non-empty string with no whitespace and no control
    characters — the only shape that fits a chrony ``pool`` / ``server``
    argument without ending the line or adding arguments.

    The settings API enforces this on write; the renderer checks again for
    rows written before that, or by another path, because chrony.conf ends a
    directive at the newline."""
    return (
        isinstance(value, str)
        and bool(value)
        and not has_control_chars(value)
        and not any(c.isspace() for c in value)
    )


def render_chrony_conf(settings: PlatformSettings) -> str:
    """Return the full ``/etc/chrony/chrony.conf`` body for these settings.

    Deterministic — same inputs yield same bytes — so the agent's
    config-hash idempotency check stays stable across long-poll
    cycles. The runner re-reads the on-disk hash sidecar and skips
    the reload when the bundle hash matches.
    """
    lines: list[str] = [
        "# Managed by SpatiumDDI — edits will be overwritten on next config push.",
        "# Source of truth: /appliance → NTP in the SpatiumDDI UI.",
        "",
    ]

    mode = (settings.ntp_source_mode or "pool").strip()
    pool_servers = [h for h in (settings.ntp_pool_servers or []) if _is_single_token(h)]
    if len(pool_servers) != len(settings.ntp_pool_servers or []):
        logger.error("ntp_pool_server_dropped_illegal_chars")
    custom_servers = list(settings.ntp_custom_servers or [])

    has_pool = mode in ("pool", "mixed") and pool_servers
    has_custom = mode in ("servers", "mixed") and custom_servers

    if not has_pool and not has_custom:
        lines.append(
            "# No time sources configured — chrony will run but never sync. "
            "Add servers in the UI."
        )

    # ``pool`` is chrony's directive that takes a single DNS name
    # and expands it via the resolver's A-record / SRV-record list
    # (so ``pool pool.ntp.org`` is one line but four servers). Each
    # entry on its own line — chrony doesn't take a multi-arg pool.
    if has_pool:
        lines.append("# Pool servers (resolver-expanded)")
        for host in pool_servers:
            lines.append(f"pool {host} iburst")
        lines.append("")

    if has_custom:
        lines.append("# Unicast servers")
        for srv in custom_servers:
            host = (srv.get("host") or "").strip()
            if not host:
                continue
            if not _is_single_token(host):
                logger.error("ntp_custom_server_dropped_illegal_chars")
                continue
            parts: list[str] = ["server", host]
            if srv.get("iburst"):
                parts.append("iburst")
            if srv.get("prefer"):
                parts.append("prefer")
            lines.append(" ".join(parts))
        lines.append("")

    # Standard chrony hygiene that the Debian default ships, kept
    # here so a config push is self-contained (operators can't
    # observe stale ``driftfile`` / ``makestep`` lines from an old
    # config sneaking through).
    lines.extend(
        [
            "# Drift file lets chrony remember the rate it had to add to the system clock.",
            "driftfile /var/lib/chrony/chrony.drift",
            "",
            "# Allow chrony to step the clock if its offset is larger than 1 second,",
            "# during the first three updates after start. Standard Debian default.",
            "makestep 1.0 3",
            "",
            "# Save NTS keys + cookies + tracking state across restarts.",
            "ntsdumpdir /var/lib/chrony",
            "",
            "# Slew the kernel's RTC from the system clock, in case the BIOS",
            "# RTC has drifted while powered off.",
            "rtcsync",
            "",
            # #1003 item 5 — no `leapsectz right/UTC`. Debian's stock
            # chrony.conf carries it, but on trixie the `right/` zone tree
            # moved to `tzdata-legacy`, which the appliance image does not
            # install: /usr/share/zoneinfo/right is absent, and chrony logs
            # "Timezone right/UTC failed leap second check, ignoring" at
            # WARNING on every start. Dropping the directive costs nothing —
            # chrony then takes leap seconds from the NTP sources themselves,
            # which is what happens today anyway since the directive is
            # already being ignored.
            "",
        ]
    )

    # Serve NTP to clients — turns the appliance into a time source
    # on isolated networks. ``allow`` per CIDR; chrony's default is
    # to refuse client queries entirely when ``allow`` isn't set.
    if settings.ntp_allow_clients:
        client_nets = list(settings.ntp_allow_client_networks or [])
        if client_nets:
            lines.append("# Serve NTP to clients (issue #154)")
            for cidr in client_nets:
                # Written bare into an ``allow`` line; only a value that
                # parses as a network is emitted.
                try:
                    net = ip_network(str(cidr).strip(), strict=False)
                except ValueError:
                    logger.error("ntp_allow_network_dropped", network=repr(cidr))
                    continue
                lines.append(f"allow {net}")
        else:
            lines.append(
                "# ntp_allow_clients=true but no CIDRs configured — chrony "
                "will refuse every client. Add CIDRs in the UI."
            )
        lines.append("")

    # Trailing newline so editors don't add a "no newline at end of
    # file" diff if an operator SSHes in and inspects the file.
    return "\n".join(lines) + "\n"


def ntp_bundle(settings: PlatformSettings) -> dict[str, Any]:
    """Build the ``ntp_settings`` block shipped to agents.

    Carries:
      * ``enabled`` — always True for NTP (unlike SNMP); chrony is
        always running on the appliance. The flag is kept on the
        bundle so the agent-side glue mirrors the SNMP shape; future
        "disable chrony entirely" toggles could flip it. Today: True.
      * ``allow_clients`` — drives the host firewall drop-in (open
        UDP 123 inbound). Mirrors SNMP's ``snmp_enabled`` →
        nftables drop-in logic.
      * ``config_hash`` — sha256 of the rendered chrony.conf body;
        the agent compares against its on-disk sidecar to short-
        circuit re-firing the reload trigger when nothing changed.
      * ``chrony_conf`` — the rendered body, written verbatim by
        the host runner.
    """
    body = render_chrony_conf(settings)
    return {
        "enabled": True,
        "allow_clients": bool(settings.ntp_allow_clients),
        "config_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "chrony_conf": body,
    }
