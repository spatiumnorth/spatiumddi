"""What the appliance firewall must open for a Kea HA pair (#1167).

A DHCP server group with two or more Kea members, each with an
``ha_peer_url``, renders ``libdhcp_ha.so`` with a dedicated HTTP listener on
the port in that server's own URL. Peers send it heartbeats and lease
updates. On the appliance the host ``input`` chain is ``policy drop`` and
nothing opened that port, so two appliances in one HA group could not reach
each other's listener.

This answers the two things the firewall renderers need, per appliance:

* **the port** — from the appliance's OWN member's ``ha_peer_url``;
* **who may reach it** — every other Kea member of the group (a 3rd or later
  member plays ``backup`` and still receives lease updates, so all members,
  not one partner). Never ``any``: Kea's HA API is unauthenticated unless the
  operator configured TLS / basic auth, and it accepts lease updates.

A partner's address is, in order: the IP literal in its ``ha_peer_url`` (Kea
itself needs a literal, so a hostname URL is resolved by the agent at render
time — which the control plane cannot repeat); else the node IPs of the
appliance running it; else the address its agent last connected from. A
member with none of those contributes nothing rather than a guess.

The appliance's own member is found by hostname: the Kea DaemonSet runs with
host networking and registers under the node's hostname, and
``DHCPServer.appliance_id`` is never populated. Both hostname matches follow
the shared ownership rule (``services/appliance/ownership``, #1810):
case-blind, and only for an APPROVED appliance whose hostname no other
approved appliance shares — a revoked or pending duplicate of a re-paired box
carries the box's OLD node IPs, and opening the listener to those instead of
the live partner breaks the pair.

The rule mirrors ``services/dhcp/config_bundle._resolve_failover`` — an HA
group is exactly what that function renders HA for — so the firewall opens
precisely when Kea starts listening, and closes when a member leaves.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.appliance.ownership import hostname_is_unambiguous, hostname_sql, norm_host
from app.services.dhcp.ha_members import kea_ha_members

_DEFAULT_PORTS = {"http": 80, "https": 443}


def listener_port(url: str) -> int | None:
    """The TCP port a Kea HA URL listens on, or None if it has no usable one."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = _DEFAULT_PORTS.get(parts.scheme.lower())
    return port if port is not None and 1 <= port <= 65535 else None


def _host_cidr(value: str | None) -> str | None:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    return f"{addr}/{128 if addr.version == 6 else 32}"


def _appliance_cidrs(ap: Appliance) -> list[str]:
    ips = list(ap.node_ips or [])
    if not ips and ap.node_ip:
        ips = [ap.node_ip]
    return [c for c in (_host_cidr(str(ip)) for ip in ips) if c is not None]


def _member_cidrs(member: DHCPServer, appliance: Appliance | None) -> list[str]:
    try:
        url_host = urlsplit(member.ha_peer_url.strip()).hostname
    except ValueError:
        url_host = None
    literal = _host_cidr(url_host)
    if literal is not None:
        return [literal]
    if appliance is not None:
        found = _appliance_cidrs(appliance)
        if found:
            return found
    last = _host_cidr(member.last_seen_ip)
    return [last] if last is not None else []


async def dhcp_ha_firewall_inputs(
    db: AsyncSession, appliance: Appliance
) -> tuple[int | None, list[str]]:
    """``(listener port, partner host CIDRs)`` for this appliance's Kea HA
    member, or ``(None, [])`` when it is not in a rendered HA group."""
    if "dhcp" not in (appliance.assigned_roles or []) or appliance.assigned_dhcp_group_id is None:
        return None, []
    group = (
        await db.execute(
            select(DHCPServerGroup)
            .where(DHCPServerGroup.id == appliance.assigned_dhcp_group_id)
            .options(selectinload(DHCPServerGroup.servers))
        )
    ).scalar_one_or_none()
    if group is None:
        return None, []
    # Same rule as _resolve_failover: only the HA participants (members with a
    # peer URL, when at least two have one) render the hook. A sidelined
    # URL-less member (#3151) has no listener, and is no partner to open to.
    kea = kea_ha_members(group.mode, group.servers).participants
    if not kea:
        return None, []
    claim_by_host = (
        appliance.state == APPLIANCE_STATE_APPROVED
        and bool(appliance.hostname)
        and await hostname_is_unambiguous(db, appliance)
    )
    mine = norm_host(appliance.hostname or "")
    own = next(
        (
            s
            for s in kea
            if s.appliance_id == appliance.id
            or (claim_by_host and s.appliance_id is None and s.host and norm_host(s.host) == mine)
        ),
        None,
    )
    if own is None:
        return None, []
    port = listener_port(own.ha_peer_url)
    if port is None:
        return None, []

    others = [s for s in kea if s.id != own.id]
    # A partner's appliance: the FK, else the ONE approved appliance with its
    # hostname (case-blind). Several approved namesakes resolve to none — the
    # member then falls back to its agent's last address.
    by_id: dict[object, Appliance] = {}
    fk_ids = {s.appliance_id for s in others if s.appliance_id is not None}
    if fk_ids:
        for ap in (
            (await db.execute(select(Appliance).where(Appliance.id.in_(fk_ids)))).scalars().all()
        ):
            by_id[ap.id] = ap
    hosts = {norm_host(s.host) for s in others if s.appliance_id is None and s.host}
    hosts.discard("")
    by_host: dict[str, Appliance | None] = {}
    if hosts:
        for ap in (
            (
                await db.execute(
                    select(Appliance).where(
                        Appliance.state == APPLIANCE_STATE_APPROVED,
                        hostname_sql(Appliance.hostname).in_(hosts),
                    )
                )
            )
            .scalars()
            .all()
        ):
            key = norm_host(ap.hostname or "")
            by_host[key] = None if key in by_host else ap

    def _partner_appliance(member: DHCPServer) -> Appliance | None:
        if member.appliance_id is not None:
            return by_id.get(member.appliance_id)
        return by_host.get(norm_host(member.host or ""))

    cidrs: set[str] = set()
    for member in others:
        cidrs.update(_member_cidrs(member, _partner_appliance(member)))
    return port, sorted(cidrs)


__all__ = ["dhcp_ha_firewall_inputs", "listener_port"]
