"""Read-only network / ops tools for the Operator Copilot
(issue #90 Wave 2). Covers SNMP devices, alerts, audit log.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.ipam import IPAddress
from app.models.network import (
    NetworkArpEntry,
    NetworkDevice,
    NetworkFdbEntry,
    NetworkInterface,
)
from app.services.ai.tools.base import register_tool
from app.services.oui import is_voip_phone_vendor, lookup_vendor

# ── network devices ───────────────────────────────────────────────────


class ListDevicesArgs(BaseModel):
    device_type: str | None = Field(
        default=None,
        description="Filter by device_type: router / switch / ap / firewall / l3_switch / other.",
    )
    space_id: str | None = Field(
        default=None,
        description="Filter by IPSpace UUID — only devices bound to this space.",
    )
    search: str | None = Field(
        default=None,
        description="Substring match on device name, hostname, or sys_descr.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_network_devices",
    permission=("read", "manage_network_devices"),
    module="network.device",
    description=(
        "List SNMP-polled network devices (routers / switches / APs / "
        "firewalls). Each summary includes name, IP, device type, "
        "vendor, sys_descr, last successful poll, and the IP space "
        "it's bound to."
    ),
    args_model=ListDevicesArgs,
    category="network",
)
async def list_network_devices(
    db: AsyncSession, user: User, args: ListDevicesArgs
) -> list[dict[str, Any]]:
    stmt = select(NetworkDevice)
    if args.device_type:
        stmt = stmt.where(NetworkDevice.device_type == args.device_type)
    if args.space_id:
        # ``ip_space_id`` — NetworkDevice has no ``space_id`` column, so the
        # old spelling raised AttributeError and this tool 500'd whenever the
        # documented space filter was supplied (#923).
        stmt = stmt.where(NetworkDevice.ip_space_id == args.space_id)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(NetworkDevice.name).like(like),
                func.lower(NetworkDevice.hostname).like(like),
                func.lower(NetworkDevice.sys_descr).like(like),
            )
        )
    stmt = stmt.order_by(NetworkDevice.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(d.id),
            "name": d.name,
            "hostname": d.hostname,
            "ip_address": str(d.ip_address),
            "device_type": d.device_type,
            "vendor": d.vendor,
            "sys_descr": d.sys_descr,
            "sys_uptime_seconds": d.sys_uptime_seconds,
            # ``last_poll_at`` — the column is not ``last_polled_at``, so
            # building this row raised AttributeError and the tool answered
            # nothing for any input (#923). The response key keeps its
            # published name so a copilot prompt written against it still
            # reads the same field.
            "last_polled_at": d.last_poll_at.isoformat() if d.last_poll_at else None,
            "last_poll_status": d.last_poll_status,
        }
        for d in rows
    ]


# ── alerts ────────────────────────────────────────────────────────────


class ListAlertsArgs(BaseModel):
    severity: str | None = Field(
        default=None,
        description="Filter by severity: info / warning / critical.",
    )
    open_only: bool = Field(
        default=True,
        description="If True (default), only currently-open alerts (resolved_at IS NULL).",
    )
    subject_type: str | None = Field(
        default=None,
        description="Filter by subject type — 'subnet' or 'server'.",
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="list_alerts",
    permission="authenticated",
    description=(
        "List alert events. Defaults to open (unresolved) alerts; "
        "set ``open_only=False`` for historical alerts. Each event "
        "includes severity, subject, message, fired / resolved "
        "timestamps."
    ),
    args_model=ListAlertsArgs,
    category="ops",
)
async def list_alerts(db: AsyncSession, user: User, args: ListAlertsArgs) -> list[dict[str, Any]]:
    stmt = select(AlertEvent)
    if args.open_only:
        stmt = stmt.where(AlertEvent.resolved_at.is_(None))
    if args.severity:
        stmt = stmt.where(AlertEvent.severity == args.severity)
    if args.subject_type:
        stmt = stmt.where(AlertEvent.subject_type == args.subject_type)
    stmt = stmt.order_by(AlertEvent.fired_at.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(e.id),
            "rule_id": str(e.rule_id),
            "subject_type": e.subject_type,
            "subject_id": e.subject_id,
            "subject_display": e.subject_display,
            "severity": e.severity,
            "message": e.message,
            "fired_at": e.fired_at.isoformat() if e.fired_at else None,
            "resolved_at": e.resolved_at.isoformat() if e.resolved_at else None,
        }
        for e in rows
    ]


class ListAlertRulesArgs(BaseModel):
    enabled_only: bool = True


@register_tool(
    name="list_alert_rules",
    permission="authenticated",
    description=(
        "List configured alert rules. Each summary includes name, "
        "rule type, enabled flag, and key thresholds."
    ),
    args_model=ListAlertRulesArgs,
    category="ops",
)
async def list_alert_rules(
    db: AsyncSession, user: User, args: ListAlertRulesArgs
) -> list[dict[str, Any]]:
    stmt = select(AlertRule)
    if args.enabled_only:
        stmt = stmt.where(AlertRule.enabled.is_(True))
    stmt = stmt.order_by(AlertRule.name.asc())
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "rule_type": r.rule_type,
            "enabled": r.enabled,
            "severity": r.severity,
        }
        for r in rows
    ]


# ── audit ─────────────────────────────────────────────────────────────


class GetAuditHistoryArgs(BaseModel):
    user_id: str | None = Field(default=None, description="Filter by acting user UUID.")
    resource_type: str | None = Field(
        default=None,
        description="Filter by resource type — e.g. 'subnet', 'dns_zone', 'ai_provider'.",
    )
    resource_id: str | None = Field(
        default=None,
        description="Filter by exact resource UUID. Use to retrieve the change history of one row.",
    )
    action: str | None = Field(
        default=None,
        description="Filter by action — create / update / delete / login / logout / etc.",
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="get_audit_history",
    permission=("read", "audit_log"),
    description=(
        "Query the append-only audit log. Filters: user, resource "
        "type, resource id, action. Returns chronological audit "
        "entries with old / new values when set. Useful for 'who "
        "changed X?' and 'show me recent activity by user Y'."
    ),
    args_model=GetAuditHistoryArgs,
    category="ops",
)
async def get_audit_history(
    db: AsyncSession, user: User, args: GetAuditHistoryArgs
) -> list[dict[str, Any]]:
    stmt = select(AuditLog)
    if args.user_id:
        stmt = stmt.where(AuditLog.user_id == args.user_id)
    if args.resource_type:
        stmt = stmt.where(AuditLog.resource_type == args.resource_type)
    if args.resource_id:
        stmt = stmt.where(AuditLog.resource_id == args.resource_id)
    if args.action:
        stmt = stmt.where(AuditLog.action == args.action)
    stmt = stmt.order_by(AuditLog.timestamp.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "user_id": str(r.user_id) if r.user_id else None,
            "user_display_name": r.user_display_name,
            "auth_source": r.auth_source,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "resource_display": r.resource_display,
            "result": r.result,
            "changed_fields": r.changed_fields,
        }
        for r in rows
    ]


# ── find_switchport ───────────────────────────────────────────────────


class FindSwitchportArgs(BaseModel):
    ip: str | None = Field(
        default=None,
        description=(
            "IPv4 / IPv6 address to look up. Resolved to a MAC via "
            "either the IPAM row or the ARP table, then matched "
            "against the FDB. One of ``ip`` or ``mac`` is required."
        ),
    )
    mac: str | None = Field(
        default=None,
        description=(
            "MAC address (any standard format). Bypasses the IP→MAC "
            "lookup and goes directly to the FDB. Useful when the "
            "operator already has the MAC."
        ),
    )


def _normalize_mac(value: str) -> str:
    hexdigits = "".join(c.lower() for c in value if c.isalnum())
    if len(hexdigits) != 12:
        return value.lower()
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


@register_tool(
    name="find_switchport",
    permission=("read", "manage_network_devices"),
    module="network.device",
    description=(
        "Find which switch port an IP / MAC is plugged into. Joins "
        "the SNMP-polled FDB (MAC→port) with the ARP table or IPAM "
        "row (IP→MAC) and returns every switch + port the MAC is "
        "currently learned on, with VLAN tag, port name / alias / "
        "description, oper status, and last_seen. Use for operator "
        "questions like 'what port is 192.168.0.6 connected to' or "
        "'find the switch port for aa:bb:cc:dd:ee:ff'. Pass either "
        "``ip`` or ``mac`` (mac is faster — skips the IP→MAC step)."
    ),
    args_model=FindSwitchportArgs,
    category="network",
)
async def find_switchport(db: AsyncSession, user: User, args: FindSwitchportArgs) -> dict[str, Any]:
    if not args.ip and not args.mac:
        return {
            "error": "Either ``ip`` or ``mac`` is required.",
        }

    # Step 1: resolve to MAC if only IP was given.
    target_mac: str | None = _normalize_mac(args.mac) if args.mac else None
    ip_source: str | None = None
    if target_mac is None and args.ip:
        # Prefer the IPAM row's MAC (operator-authoritative); fall back
        # to ARP if IPAM has no MAC recorded.
        ip_row = (
            await db.execute(select(IPAddress).where(IPAddress.address == args.ip).limit(1))
        ).scalar_one_or_none()
        if ip_row and ip_row.mac_address:
            target_mac = _normalize_mac(str(ip_row.mac_address))
            ip_source = "ipam"
        else:
            arp = (
                await db.execute(
                    select(NetworkArpEntry)
                    .where(func.text(NetworkArpEntry.ip_address) == args.ip)
                    .order_by(NetworkArpEntry.last_seen.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if arp:
                target_mac = _normalize_mac(str(arp.mac_address))
                ip_source = "arp"

    if target_mac is None:
        return {
            "error": f"No MAC found for IP {args.ip!r}.",
            "hint": (
                "The IP may not be in IPAM and may not have been seen "
                "by SNMP polling yet. Check list_network_devices for "
                "polled switches and verify SNMP credentials."
            ),
        }

    # Step 2: walk the FDB.
    fdb_rows = (
        await db.execute(
            select(NetworkFdbEntry, NetworkInterface, NetworkDevice)
            .join(NetworkInterface, NetworkFdbEntry.interface_id == NetworkInterface.id)
            .join(NetworkDevice, NetworkFdbEntry.device_id == NetworkDevice.id)
            .where(func.text(NetworkFdbEntry.mac_address) == target_mac)
            .order_by(NetworkFdbEntry.last_seen.desc())
        )
    ).all()

    # OUI vendor lookup for the resolved MAC — the operator usually
    # cares about the manufacturer of the host plugged into the
    # port (e.g. "this is a Raspberry Pi" or "this is a Cisco IP
    # phone"). Single MAC, one lookup. ``is_voip_phone`` flips the
    # Phone-icon flag in the UI / Copilot answer (issue #112 phase 3).
    mac_vendor = await lookup_vendor(db, target_mac)
    voip_phone = is_voip_phone_vendor(mac_vendor)

    if not fdb_rows:
        return {
            "mac_address": target_mac,
            "mac_vendor": mac_vendor,
            "is_voip_phone": voip_phone,
            "ip": args.ip,
            "ip_source": ip_source,
            "matches": [],
            "hint": (
                "MAC was resolved but no FDB entry matches it. The "
                "host's switch may not be SNMP-polled, the MAC may "
                "live behind a router (so only the router's MAC "
                "shows up in upstream FDB), or polling hasn't fired "
                "since the host last sent traffic."
            ),
        }

    # Filter out trunk / uplink ports — when a MAC is learned on a
    # link to another switch, every upstream switch will also show
    # the MAC. Best-effort heuristic: skip ports whose name looks
    # like a trunk uplink unless it's the only match. We don't have
    # a definitive "is this an access port" flag from SNMP; the
    # operator gets the full list and can spot the access port.
    return {
        "mac_address": target_mac,
        "mac_vendor": mac_vendor,
        "is_voip_phone": voip_phone,
        "ip": args.ip,
        "ip_source": ip_source,  # "ipam" | "arp" | None
        "match_count": len(fdb_rows),
        "matches": [
            {
                "device_name": dev.name,
                "device_id": str(dev.id),
                "device_type": dev.device_type,
                "device_ip": str(dev.ip_address) if dev.ip_address else None,
                "port_name": iface.name,
                "port_alias": iface.alias,
                "port_description": iface.description,
                "vlan_id": fdb.vlan_id,
                "fdb_type": fdb.fdb_type,
                "oper_status": iface.oper_status,
                "admin_status": iface.admin_status,
                "speed_bps": iface.speed_bps,
                "first_seen": fdb.first_seen.isoformat() if fdb.first_seen else None,
                "last_seen": fdb.last_seen.isoformat() if fdb.last_seen else None,
            }
            for fdb, iface, dev in fdb_rows
        ],
        "interpretation_hint": (
            (
                "Multiple matches usually means trunk uplinks between "
                "switches — every upstream switch sees the MAC. The "
                "actual access port is the one whose port_alias / "
                "port_description doesn't say 'uplink' or 'trunk', or "
                "the entry on the leaf switch."
            )
            if len(fdb_rows) > 1
            else None
        ),
    }


# ── ping_host ─────────────────────────────────────────────────────────


# Strict hostname pattern: a sequence of dot-separated labels, each
# label 1-63 chars, alnum + dash, no leading/trailing dash. Trailing
# dot allowed (FQDN canonical form). Caps total length at 253.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


def _validate_target(value: str) -> str | None:
    """Sanitise a ping target. Accept only IPs (any version) or RFC
    1123 hostnames — anything else is rejected to defend against
    shell-metachar injection even though we use ``argv``-mode
    ``asyncio.create_subprocess_exec`` (no shell).
    """
    v = value.strip()
    if not v:
        return None
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    if _HOSTNAME_RE.match(v):
        return v.rstrip(".")
    return None


_PING_RTT_RE = re.compile(
    r"min/avg/max/(?:mdev|stddev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms"
)
_PING_LOSS_RE = re.compile(
    r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received,\s+([\d.]+)%\s+packet loss"
)


class PingHostArgs(BaseModel):
    target: str = Field(
        description=(
            "IPv4 / IPv6 address or hostname to ping. Validated "
            "server-side — only well-formed IPs / RFC 1123 hostnames "
            "are accepted."
        ),
    )
    count: int = Field(
        default=4,
        ge=1,
        le=10,
        description="Number of ICMP echo requests (capped at 10).",
    )
    timeout_per_packet_seconds: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Per-packet timeout in seconds (capped at 5).",
    )


@register_tool(
    name="ping_host",
    permission=("read", "use_network_tools"),
    description=(
        "Send ICMP echo requests to a host and return liveness + RTT "
        "statistics. Use for 'ping 192.168.0.4' / 'is host X "
        "reachable' / 'what's the latency to gateway 10.0.0.1'. "
        "Read-only relative to SpatiumDDI state but does generate "
        "real network traffic from the SpatiumDDI host. Capped at "
        "10 packets per call. Returns alive flag, packet loss %, "
        "and min/avg/max RTT."
    ),
    args_model=PingHostArgs,
    category="network",
)
async def ping_host(db: AsyncSession, user: User, args: PingHostArgs) -> dict[str, Any]:
    target = _validate_target(args.target)
    if target is None:
        return {
            "error": (
                f"Invalid ping target {args.target!r}. Pass a valid "
                "IPv4 / IPv6 address or hostname."
            ),
        }

    # Pick the right binary for v4/v6. ``ping`` on modern Debian /
    # Alpine resolves both, but explicit ping6 is safer on some
    # distros for IPv6 literals. Detect by trying to parse the
    # target as an IP.
    binary = "ping"
    try:
        if isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address):
            binary = "ping6"
    except ValueError:
        # Hostname — let resolver decide via the default ping binary.
        pass

    argv = [
        binary,
        "-c",
        str(args.count),
        "-W",
        str(args.timeout_per_packet_seconds),
        target,
    ]

    # Hard wall-clock cap so a slow target can't hold the request
    # open: count * (timeout + 1s slack) + 5s overhead.
    overall_timeout = args.count * (args.timeout_per_packet_seconds + 1) + 5

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=overall_timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "target": target,
                "alive": False,
                "error": f"ping timed out after {overall_timeout}s",
            }
    except FileNotFoundError:
        return {
            "error": (
                f"{binary} not found in the SpatiumDDI api container. "
                "Add iputils-ping to the image build."
            ),
        }

    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")
    exit_code = proc.returncode

    # Parse common stats. Ping prints them in the trailing summary
    # block whose exact wording varies a touch between iputils and
    # busybox; the regexes match both.
    loss_match = _PING_LOSS_RE.search(stdout)
    rtt_match = _PING_RTT_RE.search(stdout)

    transmitted = int(loss_match.group(1)) if loss_match else None
    received = int(loss_match.group(2)) if loss_match else 0
    loss_pct = float(loss_match.group(3)) if loss_match else 100.0
    rtt = (
        {
            "min_ms": float(rtt_match.group(1)),
            "avg_ms": float(rtt_match.group(2)),
            "max_ms": float(rtt_match.group(3)),
            "mdev_ms": float(rtt_match.group(4)),
        }
        if rtt_match
        else None
    )

    # Exit 0 = at least one reply (alive). Exit 1 = no replies. Exit
    # 2 = error (resolver failure, permission denied, etc.). Use
    # received > 0 as the canonical alive signal so the operator's
    # "is X reachable" question maps cleanly.
    alive = received > 0

    return {
        "target": target,
        "alive": alive,
        "exit_code": exit_code,
        "packets_transmitted": transmitted,
        "packets_received": received,
        "packet_loss_pct": loss_pct,
        "rtt": rtt,
        "stdout_tail": stdout[-1000:] if stdout else None,
        "stderr_tail": stderr[-500:] if stderr else None,
    }
