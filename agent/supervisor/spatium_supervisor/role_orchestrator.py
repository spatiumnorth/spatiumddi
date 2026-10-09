"""Role orchestration on the supervisor (#170 Wave C2).

Translates the control plane's ``role_assignment`` heartbeat block
into a docker-compose env file the supervisor uses to bring up /
down the service containers:

* ``COMPOSE_PROFILES`` carries the subset of
  ``dns-bind9`` / ``dns-powerdns`` / ``dhcp`` / ``looking-glass`` the
  supervisor needs to start.
* ``DNS_AGENT_KEY`` / ``DHCP_AGENT_KEY`` / ``LG_AGENT_KEY`` /
  ``AGENT_GROUP`` / ``CONTROL_PLANE_URL`` carry the service-container
  env so the dns-bind9 / dhcp-kea / looking-glass agent sidecar can
  register against the control plane's per-service
  ``/dns/agents/register`` / ``/dhcp/agents/register`` /
  ``/looking-glass/agents/register`` endpoints without operator input.
* ``DHCP_NETWORK_MODE`` toggles ``network_mode: host`` (default)
  vs ``ports: ["67:67/udp"]`` (bridged, for relay deployments).
  The compose template selects between two service definitions
  based on this env var.

C2 ships the **env-rendering half** — the supervisor writes the
target file but doesn't yet invoke ``docker compose up -d``. The
actual lifecycle (load baked image, atomic role-switch with
revert-on-failure) lands in C3 alongside the nftables renderer
since both need the same subprocess machinery.

A clean ``compute_target_env()`` separates the pure computation
from any I/O so it's unit-testable + the C3 commit just plugs the
subprocess piece in next to it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Roles the supervisor knows how to start a service container for.
# ``observer`` + ``custom`` are reserved (no compose profile yet);
# the supervisor recognises them on heartbeat but does nothing.
# ``looking-glass`` (#566) joined DNS/DHCP here — the BGP Looking
# Glass collector is a real service container (GoBGP), not a
# supervisor-side-only role like observer.
_SERVICE_ROLES = {"dns-bind9", "dns-powerdns", "dns-technitium", "dhcp", "looking-glass"}


# Issue #237 — values from the heartbeat response land in a docker-
# compose env file the supervisor writes to disk + hands off to
# ``docker compose --env-file``. A value containing a newline injects
# an additional ``KEY=VALUE`` line into the file. Validate every value
# against a strict allow-list pattern; reject anything that doesn't
# match.
#
# Patterns are intentionally tight:
#   * Agent keys (bootstrap PSK): #1566 — the key's *shape* is not part
#     of the contract. The control plane stores it as a plain string
#     and standalone Compose/Kubernetes agents accept any non-empty
#     value, so the old hex-only rule (32–128 lowercase hex) silently
#     dropped operator-chosen keys and the appliance's agents never
#     registered. This pattern's real job is env-file injection
#     defence (#237): forbid whitespace (incl. newlines), quotes,
#     backtick, ``$`` and ``\`` — the characters that could break out
#     of the ``KEY=VALUE`` line or be reinterpreted downstream — and
#     accept everything else, 1–512 chars. ``openssl rand -hex 32``
#     remains the recommended way to generate a key.
#   * Server group names / engine names: alphanumeric + hyphen / dot /
#     underscore, 1–128 chars. The control plane validates these on
#     create but defense-in-depth here keeps a compromised control
#     plane from injecting env lines through the supervisor.
_AGENT_KEY_RE = re.compile(r"""^[^\s"'`$\\]{1,512}$""")
_GROUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _safe_env_value(name: str, value: Any, pattern: re.Pattern[str]) -> str | None:
    """Return ``value`` cast to ``str`` if it matches ``pattern``,
    else log + return ``None`` so the caller can omit the line.

    Defends against control-plane payloads carrying ``\n`` or other
    metacharacters that would inject extra env-file lines (#237).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        log.warning(
            "supervisor.role_orchestrator.invalid_env_value_type",
            name=name,
            type=type(value).__name__,
        )
        return None
    if not pattern.match(value):
        log.warning(
            "supervisor.role_orchestrator.rejected_env_value",
            name=name,
            value_len=len(value),
        )
        return None
    return value


@dataclass(frozen=True)
class TargetEnv:
    """Result of computing the supervisor's target compose env.

    Lines are env-file format (``KEY=VALUE`` one per line, quoted
    when the value contains whitespace). ``profiles`` is included
    separately for callers that want to drive compose via CLI flags
    rather than env-var substitution.
    """

    env_lines: list[str]
    profiles: list[str]


def compute_target_env(role_assignment: dict[str, Any] | None) -> TargetEnv:
    """Translate the heartbeat response's ``role_assignment`` block
    into a list of env-file lines + the compose profile set.

    Empty / missing role list → empty profiles → supervisor brings
    down every service container (idle state). Same shape applies
    when the operator clears the role assignment via the API:
    the heartbeat returns ``roles=[]`` and the supervisor drops to
    idle on the next tick.

    Always emits ``COMPOSE_PROFILES`` so the env file can replace
    the operator-supplied one — never silently inherits.
    """
    role_assignment = role_assignment or {}
    roles = list(role_assignment.get("roles") or [])
    profiles: list[str] = []

    for role in roles:
        if role in _SERVICE_ROLES:
            profiles.append(role)

    env_lines: list[str] = []
    env_lines.append(f"COMPOSE_PROFILES={','.join(profiles)}")

    # DNS group config — only populated when a DNS role is assigned.
    dns_group_name = role_assignment.get("dns_group_name")
    # Issue #237 — every value from the heartbeat is validated against
    # a strict allow-list pattern before it lands in the env-file
    # line. A newline / null byte / quote in any value would otherwise
    # inject extra env-file entries.
    dns_engine_raw = role_assignment.get("dns_engine")
    dns_group = _safe_env_value("dns_group_name", dns_group_name, _GROUP_NAME_RE)
    dns_engine = _safe_env_value("dns_engine", dns_engine_raw, _GROUP_NAME_RE)
    # #170 Wave D follow-up — control-plane-provided bootstrap PSK so
    # the bind9 / powerdns service container can register against
    # /api/v1/dns/agents/register without operator-side .env edits.
    # ``None`` when the control plane hasn't configured the key.
    dns_agent_key = _safe_env_value(
        "dns_agent_key", role_assignment.get("dns_agent_key"), _AGENT_KEY_RE
    )
    if any(r in roles for r in ("dns-bind9", "dns-powerdns", "dns-technitium")):
        if dns_group:
            env_lines.append(f"AGENT_GROUP={dns_group}")
        if dns_engine:
            env_lines.append(f"DNS_ENGINE={dns_engine}")
        if dns_agent_key:
            env_lines.append(f"DNS_AGENT_KEY={dns_agent_key}")

    # DHCP group config.
    dhcp_group = _safe_env_value(
        "dhcp_group_name", role_assignment.get("dhcp_group_name"), _GROUP_NAME_RE
    )
    dhcp_network_mode_raw = role_assignment.get("dhcp_network_mode") or "host"
    # ``dhcp_network_mode`` is one of two known literals; validate
    # against an exact-match set rather than a regex.
    if dhcp_network_mode_raw in {"host", "bridged"}:
        dhcp_network_mode: str | None = dhcp_network_mode_raw
    else:
        log.warning(
            "supervisor.role_orchestrator.invalid_dhcp_network_mode",
            value=dhcp_network_mode_raw,
        )
        dhcp_network_mode = "host"
    dhcp_agent_key = _safe_env_value(
        "dhcp_agent_key", role_assignment.get("dhcp_agent_key"), _AGENT_KEY_RE
    )
    if "dhcp" in roles:
        if dhcp_group:
            # AGENT_GROUP is overloaded — DNS + DHCP can't be in the
            # same group anyway (different drivers), so when both
            # roles are assigned we still write one AGENT_GROUP and
            # let the compose templates per-role override via
            # role-specific env vars (Wave C3 reshape; for now we
            # emit a second AGENT_GROUP line — the later wins under
            # docker-compose's env-file parser).
            env_lines.append(f"DHCP_AGENT_GROUP={dhcp_group}")
        env_lines.append(f"DHCP_NETWORK_MODE={dhcp_network_mode}")
        if dhcp_agent_key:
            env_lines.append(f"DHCP_AGENT_KEY={dhcp_agent_key}")

    # Looking Glass (BGP collector, #566) — no group concept (LG peers
    # aren't grouped like DNS/DHCP server groups; peer config itself
    # rides the collector's own ConfigBundle long-poll, not this env
    # file). Only the bootstrap PSK is needed here so the GoBGP
    # sidecar can register against ``/looking-glass/agents/register``
    # without operator input — same shape + validation as DNS/DHCP.
    lg_agent_key = _safe_env_value(
        "lg_agent_key", role_assignment.get("lg_agent_key"), _AGENT_KEY_RE
    )
    if "looking-glass" in roles:
        if lg_agent_key:
            env_lines.append(f"LG_AGENT_KEY={lg_agent_key}")

    return TargetEnv(env_lines=env_lines, profiles=profiles)


def render_env_file(target: TargetEnv, header: str | None = None) -> str:
    """Format a TargetEnv as a docker-compose env-file. Includes a
    ``# generated by spatium-supervisor`` header by default so the
    operator inspecting the file knows it shouldn't be hand-edited
    (every heartbeat overwrites)."""
    lines: list[str] = []
    if header:
        lines.append(header.rstrip("\n"))
    else:
        lines.append("# Auto-generated by spatium-supervisor — do not hand-edit.")
        lines.append("# Overwritten on every supervisor heartbeat that returns a")
        lines.append("# role_assignment block from the control plane.")
    lines.extend(target.env_lines)
    return "\n".join(lines) + "\n"


# ── DHCP bridged-mode port-conflict pre-flight (#170 Phase E2) ────


@dataclass(frozen=True)
class PortConflict:
    """Result of probing for a competing UDP/67 listener on the host.

    ``users`` is the raw text of the matching ``ss`` users field (the
    process or socket-owner string), surfaced to the operator so they
    know which daemon to kill before flipping bridged DHCP on.
    """

    port: int
    users: str


# Match ``users:(...)`` field that ss appends with -p; falls back to
# the local-address column when ss was invoked without -p (root or
# CAP_NET_ADMIN is needed for -p to populate process names).
_SS_USERS_RE = re.compile(r"users:\((.+?)\)")


# Service ports the supervisor probes on every heartbeat. Maps the
# heartbeat-body key the control plane stores back into
# ``appliance.port_conflicts`` to a (proto, port) tuple. DNS binds
# UDP+TCP/53 on the host's network namespace regardless of role
# orchestration (the dns-bind9 / dns-powerdns service container uses
# network_mode: host); DHCP binds UDP/67 on host either via network_
# mode: host (default) or bridged-mode port-mapping.
_PROBE_PORTS: dict[str, tuple[str, int]] = {
    "udp_53": ("udp", 53),
    "tcp_53": ("tcp", 53),
    "udp_67": ("udp", 67),
}


def detect_port_conflict(
    proto: str,
    port: int,
    *,
    ss_argv: list[str] | None = None,
) -> PortConflict | None:
    """Return a :class:`PortConflict` if something is already listening
    on ``proto`` ``port`` on the host. ``None`` means the port is free
    or ``ss`` is unavailable.

    The supervisor calls this every heartbeat for UDP+TCP/53 and
    UDP/67 — the ports DNS-BIND9 / DNS-PowerDNS / DHCP-Kea each bind
    on the host's network namespace. When a conflict exists the
    operator should know *before* assigning the service role,
    otherwise the role-switch lands in a state where the supervisor
    has scheduled the service but the container's bind silently
    loses to whatever pre-existing daemon owned the port.

    ``ss`` lives at ``/usr/sbin/ss`` on Debian; runs in the supervisor
    container's PID namespace via the host bind-mount the supervisor
    compose entry should expose. When ``ss`` is missing entirely (dev
    laptop, or a stripped image), return ``None`` rather than refuse —
    the host-side compose lifecycle will still surface the bind error
    if there genuinely is a conflict.
    """
    if proto not in ("udp", "tcp"):
        raise ValueError(f"unsupported proto {proto!r}")
    if shutil.which("ss") is None:
        return None
    # ``-uln`` / ``-tln`` per proto; ``-p`` adds users field (best-
    # effort, needs root); ``sport = :<port>`` narrows the kernel
    # filter so the output is small.
    flag = "-uln" if proto == "udp" else "-tln"
    argv = ss_argv or ["ss", flag, "-p", f"sport = :{port}"]
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    # ss output: header line then one row per listener. The local-
    # address column is field index 4 on UDP rows (5 fields:
    # NetidState Recv-Q Send-Q LocalAddr PeerAddr) and field index 4
    # on TCP rows too (same shape with State in field 1).
    needle = f":{port}"
    matches: list[str] = []
    for line in result.stdout.splitlines()[1:]:
        if needle not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3] if proto == "udp" else parts[3]
        if not local.endswith(needle):
            continue
        users_match = _SS_USERS_RE.search(line)
        matches.append(users_match.group(1) if users_match else local)
    if not matches:
        return None
    return PortConflict(port=port, users="; ".join(matches))


def probe_port_conflicts() -> dict[str, str]:
    """Probe every port in :data:`_PROBE_PORTS`. Returns a dict keyed
    by the heartbeat-body field name (``udp_53`` / ``tcp_53`` /
    ``udp_67``) with the conflicting users string as the value. Ports
    that are free / unprobed are omitted from the dict — empty result
    means "no conflicts detected". The supervisor's heartbeat sends
    this verbatim; the control plane persists it as
    ``appliance.port_conflicts``.
    """
    out: dict[str, str] = {}
    for key, (proto, port) in _PROBE_PORTS.items():
        conflict = detect_port_conflict(proto, port)
        if conflict is not None:
            out[key] = conflict.users
    return out


__all__ = [
    "TargetEnv",
    "compute_target_env",
    "render_env_file",
    "PortConflict",
    "detect_port_conflict",
    "probe_port_conflicts",
]
