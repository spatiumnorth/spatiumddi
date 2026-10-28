"""A DHCP group in ``direct`` socket mode cannot be served through the relay VIP (#2899).

The MetalLB relay VIP (#272 Phase 5) is a LoadBalancer Service on :67 whose
selector is every ``dhcp-kea`` pod in the appliance cluster, with
``externalTrafficPolicy: Cluster``. One node announces the VIP; kube-proxy on
that node DNATs each relay's flow to one of the Kea endpoints.

A flow DNATed to ANOTHER node arrives there addressed to that node's own
address, and Kea answers it in either socket mode. A flow kube-proxy keeps on
the ANNOUNCING node's own Kea is the one that breaks in ``direct`` mode
(``dhcp-socket-type: raw``):

* Kea's AF_PACKET socket sees the frame as it arrived, before netfilter, so
  it still carries the VIP as its destination. Kea's LPF filter admits UDP/67
  only to the broadcast address or to the address the socket was opened for,
  so it drops the frame.
* kube-proxy's DNAT then delivers the packet to Kea's UDP socket on the node
  address, which in raw mode is only a "fallback" Kea drains and discards.

So every relay whose flow lands on the announcer gets no answer, for as long
as its conntrack entry lives — about one relay in N for N nodes — and no
counter records it: the #2889 arrival counter deliberately excludes frames
addressed to the VIP, and Kea never counts what it never reads.

In ``relay`` mode (``dhcp-socket-type: udp``) Kea reads that UDP socket, so
the DNATed packet is served, and its reply leaves through the same conntrack
entry and is un-NATed to come from the VIP.

There is no way to keep ``direct`` mode and fix it. Kea cannot mix raw and UDP
sockets in one daemon, and making the raw filter admit the VIP would mean
adding the VIP to the announcer's interface — which MetalLB L2 deliberately
does not do — and then kube-proxy would STILL DNAT the same packet to some
endpoint, so the announcer and another node would both answer it. A group that
must also serve directly attached clients (which needs raw sockets) cannot be
fronted by the relay VIP at all: its relays should forward to every node's own
address instead (several ``ip helper-address`` lines), the usual setup for
redundant DHCP servers.

So SpatiumDDI does not change a group's socket mode on its own: switching to
``relay`` would silently stop direct-attached clients being served, trading one
black hole for another. It refuses the configurations that create the state,
and the default-on ``dhcp_relay_vip_direct_socket`` alert reports the state
whenever it exists (an install that had it before this check, or a path the
refusals do not cover).

"Behind the VIP" means a Kea pod the Service selects: an approved appliance
reporting ``deployment_kind = 'appliance'`` (a k3s node — the only place the
VIP exists) that holds the ``dhcp`` role in the group, or whose registered Kea
server row is in the group.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings

# The socket mode that renders ``dhcp-socket-type: raw``.
DIRECT_SOCKET_MODE = "direct"


def effective_relay_vip(settings: PlatformSettings | None) -> str:
    """The relay VIP the cluster is actually serving, or ``""``.

    A VIP stored while MetalLB is off renders no Service (the PUT validator
    refuses that combination, but a row written before it existed may hold
    one), so it fronts nothing.
    """
    if settings is None or not settings.metallb_enabled:
        return ""
    return (settings.dhcp_relay_vip or "").strip()


async def load_relay_vip(db: AsyncSession) -> str:
    settings = await db.get(PlatformSettings, 1)
    return effective_relay_vip(settings)


async def group_ids_behind_relay_vip(db: AsyncSession) -> set[uuid.UUID]:
    """Every DHCP server group with a Kea pod the relay VIP Service selects."""
    from app.services.appliance.ownership import (  # noqa: PLC0415
        orchestrated_server_condition,
    )

    assigned = (
        (
            await db.execute(
                select(Appliance.assigned_dhcp_group_id).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    Appliance.deployment_kind == "appliance",
                    Appliance.assigned_dhcp_group_id.is_not(None),
                    Appliance.assigned_roles.contains(["dhcp"]),
                )
            )
        )
        .scalars()
        .all()
    )
    registered = (
        (
            await db.execute(
                select(DHCPServer.server_group_id).where(
                    DHCPServer.driver == "kea",
                    DHCPServer.server_group_id.is_not(None),
                    orchestrated_server_condition(DHCPServer),
                )
            )
        )
        .scalars()
        .all()
    )
    return {gid for gid in (*assigned, *registered) if gid is not None}


async def direct_groups_behind_relay_vip(
    db: AsyncSession, vip: str | None = None
) -> list[DHCPServerGroup]:
    """Groups in ``direct`` mode behind the relay VIP, ordered by name.

    ``vip`` is the VIP to judge against — the stored, effective one when
    omitted, or the one a pending change is about to set. Empty when there is
    no VIP.
    """
    if vip is None:
        vip = await load_relay_vip(db)
    if not vip:
        return []
    ids = await group_ids_behind_relay_vip(db)
    if not ids:
        return []
    rows = (
        (
            await db.execute(
                select(DHCPServerGroup)
                .where(
                    DHCPServerGroup.id.in_(ids),
                    DHCPServerGroup.dhcp_socket_mode == DIRECT_SOCKET_MODE,
                )
                .order_by(DHCPServerGroup.name)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


_FIX = (
    "Set the group's client reachability to relay (dhcp_socket_mode=relay). "
    "If the group must also serve directly attached clients, which needs direct "
    "mode, leave the relay VIP empty and point each relay at every DHCP node's "
    "own address instead."
)

_WHY = (
    "In direct mode Kea reads raw sockets, which drop a request still addressed "
    "to the VIP, so relays whose flows kube-proxy keeps on the node announcing "
    "the VIP get no answer, and no counter shows it."
)


def refusal_for_groups(vip: str, group_names: Iterable[str]) -> str:
    """The 422 detail for a change that would put direct groups behind ``vip``."""
    names = ", ".join(repr(n) for n in group_names)
    return (
        f"DHCP server group(s) {names} would be served through the DHCP relay "
        f"VIP {vip} in direct socket mode. {_WHY} {_FIX}"
    )


async def appliance_join_refusal(
    db: AsyncSession,
    appliance: Appliance,
    group: DHCPServerGroup,
    roles: list[str] | None = None,
) -> str | None:
    """Why pointing ``appliance`` at ``group`` would put a ``direct`` group
    behind the relay VIP, or None.

    ``roles`` overrides the appliance's current roles (a preview). Only an
    approved appliance reporting ``deployment_kind = 'appliance'`` runs its
    Kea as a pod the VIP Service selects.
    """
    if group.dhcp_socket_mode != DIRECT_SOCKET_MODE:
        return None
    if "dhcp" not in ((appliance.assigned_roles if roles is None else roles) or []):
        return None
    if appliance.state != APPLIANCE_STATE_APPROVED or appliance.deployment_kind != "appliance":
        return None
    vip = await load_relay_vip(db)
    if not vip:
        return None
    return refusal_for_groups(vip, [group.name])


def alert_message(group_name: str, vip: str) -> str:
    """The ``dhcp_relay_vip_direct_socket`` event message for one group."""
    return (
        f"DHCP server group '{group_name}' is behind the DHCP relay VIP {vip} in "
        f"direct socket mode. {_WHY} {_FIX}"
    )
