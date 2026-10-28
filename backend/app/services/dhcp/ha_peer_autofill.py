"""Derive ``ha_peer_url`` for appliance-hosted Kea members (#2963).

Kea's HA hook listens on the host:port of the member's own peer URL, and the
config bundle renders HA only when every Kea member of a group has one. On an
appliance the address is already known (the supervisor reports the node's
k3s InternalIP(s)), so making the operator type ``http://<node IP>:8000/`` on
both servers was a manual step with no product-side reason, and a pair
without it silently never formed.

What is derived, and when it is NOT:

* **Only an empty URL is filled.** An operator-set value (compose
  deployments, a NAT'd address, a custom port) is never touched.
* **Only host-networked groups.** In ``bridged`` mode Kea runs behind the
  container network, where the node IP is not the address it listens on; there
  is no reliable derivation, so those members stay manual.
* **Only members that map to an approved appliance** with a usable address
  (``node_ips`` first, IPv4 before IPv6, then ``node_ip``). A member with no
  such appliance (a compose agent in a mixed group) is left alone.
* **Only in a group of two or more Kea members**: a lone Kea server is not an
  HA pair and a URL on it changes nothing the operator asked for.

The port is the one the agent image and every doc already use.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dhcp_group_channel, dhcp_server_channel
from app.models.appliance import Appliance
from app.models.audit import AuditLog
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.appliance.ownership import owning_appliance_for_dhcp_server

HA_LISTEN_PORT = 8000


@dataclass
class AutofillResult:
    filled: list[tuple[uuid.UUID, str, str]]  # (server id, name, url)


def appliance_ha_address(ap: Appliance) -> str | None:
    """The node address peers reach: first IPv4 of ``node_ips``, else the first
    address of any family, else ``node_ip``. None when none is a valid IP."""
    candidates = [str(i) for i in (ap.node_ips or [])]
    if ap.node_ip:
        candidates.append(str(ap.node_ip))
    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for c in candidates:
        try:
            parsed.append(ipaddress.ip_address(c.strip().strip("[]")))
        except ValueError:
            continue
    for a in parsed:
        if a.version == 4:
            return str(a)
    if parsed:
        return f"[{parsed[0]}]"
    return None


def derived_peer_url(ap: Appliance) -> str | None:
    addr = appliance_ha_address(ap)
    return f"http://{addr}:{HA_LISTEN_PORT}/" if addr else None


async def autofill_group_ha_peer_urls(
    db: AsyncSession, group_id: uuid.UUID | None, *, via: str
) -> AutofillResult:
    """Fill the empty ``ha_peer_url`` of appliance-hosted Kea members of the
    group, in the caller's transaction. Wakes after the caller's commit."""
    result = AutofillResult(filled=[])
    if group_id is None:
        return result
    group = await db.get(DHCPServerGroup, group_id)
    if group is None or group.network_mode != "host":
        return result
    kea = list(
        (
            await db.execute(
                select(DHCPServer).where(
                    DHCPServer.server_group_id == group_id, DHCPServer.driver == "kea"
                )
            )
        )
        .scalars()
        .all()
    )
    if len(kea) < 2:
        return result
    for member in kea:
        if member.ha_peer_url:
            continue
        ap = await owning_appliance_for_dhcp_server(db, member)
        if ap is None:
            continue
        url = derived_peer_url(ap)
        if url is None:
            continue
        member.ha_peer_url = url
        collect_wake(dhcp_server_channel(member.id))
        result.filled.append((member.id, member.name, url))
        db.add(
            AuditLog(
                user_id=None,
                user_display_name="system",
                auth_source="system",
                action="update",
                resource_type="dhcp_server",
                resource_id=str(member.id),
                resource_display=member.name,
                changed_fields=["ha_peer_url"],
                old_value={"ha_peer_url": ""},
                new_value={"ha_peer_url": url, "derived_from_appliance": str(ap.id), "via": via},
                result="success",
            )
        )
    if result.filled:
        collect_wake(dhcp_group_channel(group_id))
    return result
