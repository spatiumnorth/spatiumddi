"""Issue #343 — appliance LLDP support.

Source-of-truth lives on ``platform_settings`` (singleton); this module
renders the lldpd host config from those columns and folds it into the DNS +
DHCP ConfigBundle long-poll so every appliance host (local + remote agents)
picks it up the same way SNMP (#153) and chrony (#154) do.

Design notes:

* lldpd runs at the OS level on the appliance image, NOT in a container — it
  must see the host's real L2 interfaces and send/receive raw ethertype-0x88cc
  frames, which a container can't without host networking + CAP_NET_RAW.
* Two artefacts are rendered: ``/etc/lldpd.d/spatium.conf`` (a script of
  ``lldpcli configure …`` directives lldpd sources at start) and the
  ``/etc/default/lldpd`` DAEMON_ARGS string (the ``-c``/``-e``/``-f``/``-s``
  flags that turn on *reception* of CDP / EDP / FDP / SONMP alongside LLDP).
  Protocol reception is a daemon-arg, not an lldpcli directive, so it can't
  live in the conf body.
* UNLIKE SNMP / NTP there is no firewall change: LLDP is raw L2 multicast
  (01:80:c2:00:00:0e, ethertype 0x88cc), not IP/UDP — there is no port to
  open, so the host-side runner must NOT write an ``/etc/nftables.d`` drop-in.
* No Fernet: LLDP advertises public identity (hostname, mgmt IP, capabilities)
  to anything on the wire — there is nothing secret to encrypt. Mitigated by
  default-off + the per-interface allowlist that excludes container vNICs.
* A disabled / empty config still renders a *valid* body so the host-side
  runner can compare it byte-for-byte and skip the reload when nothing changed.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.models.settings import PlatformSettings

# lldp_protocols value → lldpd daemon flag enabling RECEPTION of that protocol.
# (LLDP itself is always on; these add the legacy/vendor neighbour protocols.)
_PROTOCOL_FLAGS: dict[str, str] = {
    "cdp": "-c",  # Cisco Discovery Protocol
    "edp": "-e",  # Extreme Discovery Protocol
    "fdp": "-f",  # Foundry Discovery Protocol
    "sonmp": "-s",  # Nortel/SynOptics
}


def _maybe_quote(s: str) -> str:
    """lldpcli uses shell-like word splitting — only values containing
    whitespace need quoting. Simple tokens (hostnames, single words) render
    bare to match the canonical lldpcli config style; anything with a space
    is double-quoted with embedded quotes/backslashes escaped."""
    if not any(c.isspace() for c in s):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_lldpd_conf(settings: PlatformSettings) -> str:
    """Return the ``/etc/lldpd.d/spatium.conf`` body (lldpcli directives).

    Deterministic — same settings → same bytes — so the host-side runner can
    diff against the on-disk file and skip the reload when nothing changed.
    """
    lines: list[str] = [
        "# Managed by SpatiumDDI — edits will be overwritten on next config push.",
        "# Source of truth: Appliance → LLDP in the SpatiumDDI UI.",
        "",
    ]

    sys_name = (settings.lldp_sys_name or "").strip()
    sys_desc = (settings.lldp_sys_description or "").strip()
    if sys_name:
        lines.append(f"configure system hostname {_maybe_quote(sys_name)}")
    if sys_desc:
        lines.append(f"configure system description {_maybe_quote(sys_desc)}")

    # tx-interval × tx-hold = the advertised TTL. Floor at sane minimums so a
    # zero never disables advertising silently.
    tx_interval = max(1, int(settings.lldp_tx_interval or 30))
    tx_hold = max(1, int(settings.lldp_tx_hold or 4))
    lines.append(f"configure lldp tx-interval {tx_interval}")
    lines.append(f"configure lldp tx-hold {tx_hold}")

    # Management-address pattern: empty → let lldpd auto-select the primary
    # routable IP (its default). Operators pin one (e.g. ``eth0`` / a CIDR)
    # to control which address upstream switches learn.
    mgmt = (settings.lldp_management_pattern or "").strip()
    if mgmt:
        lines.append(f"configure system ip management pattern {mgmt}")

    # Interface allowlist — always emitted. The default excludes docker / k3s
    # vNICs so we never advertise into the overlay network.
    iface = (settings.lldp_interface_pattern or "").strip()
    if iface:
        lines.append(f"configure system interface pattern {iface}")

    # Advertise the management address + capabilities (router/bridge/…) so the
    # appliance shows up usefully in upstream LLDP/NMS tables.
    lines.append("configure lldp management-addresses-advertisements")
    lines.append("configure lldp capabilities-advertisements")

    # LLDP-MED ELIN location (issue #348) — Emergency Location Identification
    # Number, advertised to MED-capable endpoints (IP phones) for E911 routing.
    # Coordinate / civic forms are richer and stay API-only for now; ELIN is a
    # single value with the clearest operator use.
    med = settings.lldp_med_location or {}
    elin = str(med.get("elin") or "").strip() if isinstance(med, dict) else ""
    if elin:
        lines.append(f"configure med location elin {elin}")

    return "\n".join(lines) + "\n"


def render_lldpd_daemon_args(settings: PlatformSettings) -> str:
    """Return the ``DAEMON_ARGS`` value for ``/etc/default/lldpd``.

    Enables reception of the operator-selected legacy/vendor protocols on top
    of LLDP, plus the SNMP AgentX subagent (``-x``) when requested. Deterministic
    flag order so the bundle hash is stable.
    """
    protocols = {str(p).strip().lower() for p in (settings.lldp_protocols or [])}
    flags = [_PROTOCOL_FLAGS[p] for p in ("cdp", "edp", "fdp", "sonmp") if p in protocols]
    # ``-x`` registers lldpd as an AgentX subagent so LLDP-MIB (lldpRemTable)
    # is queryable through the host's snmpd when both are enabled (issue #348).
    # Loopback AgentX socket — still no firewall change. Harmless if snmpd is
    # off (lldpd just can't connect to the master and logs a warning).
    if bool(getattr(settings, "lldp_snmp_agentx", False)):
        flags.append("-x")
    return " ".join(flags)


def lldp_bundle(settings: PlatformSettings) -> dict[str, Any]:
    """Build the ``lldp_settings`` block the DNS + DHCP ConfigBundle ships.

    Carries the rendered conf body + daemon args + a config-hash the agent
    short-circuits on (skip the trigger file when nothing changed since the
    last bundle). The hash spans both artefacts so a protocol-only change
    still shifts it.
    """
    enabled = bool(settings.lldp_enabled)
    body = render_lldpd_conf(settings) if enabled else ""
    daemon_args = render_lldpd_daemon_args(settings) if enabled else ""
    config_hash = (
        hashlib.sha256(f"{body}\n--args--\n{daemon_args}".encode()).hexdigest() if enabled else ""
    )
    return {
        "enabled": enabled,
        "config_hash": config_hash,
        "lldpd_conf": body,
        "daemon_args": daemon_args,
    }


__all__ = ["lldp_bundle", "render_lldpd_conf", "render_lldpd_daemon_args"]
