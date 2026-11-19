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
the DNATed packet is served. Kea answers a relayed request to ``giaddr``:67
(not to the packet's IP source), from the node's own address. When the relay
sends from its ``giaddr`` the reply matches the flow's conntrack entry and
leaves un-NATed from the VIP; when it sends from another address (a Cisco
``ip helper-address`` sources from the interface facing the server by
default) the reply leaves from the node's own address — exactly as the
replies from the other nodes already do in both modes, since kube-proxy
masquerades a forwarded flow and the serving node replies to ``giaddr``
directly. Relays accept that (the other nodes' answers prove it); a stateful
firewall between relay and cluster that pins the reply to the VIP would not,
in either mode, and is out of scope here.

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

"Behind the VIP" means a Kea pod the Service selects. The Service lives in the
control plane's own k3s cluster and selects every ``dhcp-kea`` pod there,
whatever group it serves — so it is every group with a Kea on a node OF THAT
CLUSTER: the seed (a control-plane variant, which carries no ``cluster_role``
until its first promote) and every promoted or joining member. NOT an
approved-but-unpromoted Additional node: that one runs its own single-node
k3s with no MetalLB and no VIP Service (``network_mtu.in_cluster`` makes the
same distinction), and a branch DHCP appliance serving its own directly
attached VLAN in ``direct`` mode is exactly the setup ``direct`` exists for.
A group counts when such a node holds the ``dhcp`` role pointed at it, or
when such a node's registered Kea server row is in it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    DESIRED_CLUSTER_ROLE_MEMBER,
    Appliance,
)
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings

# The socket mode that renders ``dhcp-socket-type: raw``.
DIRECT_SOCKET_MODE = "direct"

# Install variants that self-bootstrap the control plane, i.e. the seed of the
# cluster the VIP lives in (``api/v1/appliance/supervisor._SELF_BOOTSTRAP_VARIANTS``).
_SEED_VARIANTS = ("control-plane", "full-stack", "frontend-core")
_CLUSTER_ROLES = (CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)


def in_vip_cluster(appliance: Appliance) -> bool:
    """Is ``appliance`` a node of the cluster the relay VIP Service lives in?"""
    return (
        appliance.state == APPLIANCE_STATE_APPROVED
        and appliance.revoked_at is None
        and appliance.deployment_kind == "appliance"
        and (
            appliance.appliance_variant in _SEED_VARIANTS
            or appliance.cluster_role in _CLUSTER_ROLES
            or appliance.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER
        )
    )


def _in_vip_cluster_sql(a: Any) -> Any:
    """SQL form of :func:`in_vip_cluster` over the (aliased) Appliance ``a``."""
    return and_(
        a.state == APPLIANCE_STATE_APPROVED,
        a.revoked_at.is_(None),
        a.deployment_kind == "appliance",
        or_(
            a.appliance_variant.in_(_SEED_VARIANTS),
            a.cluster_role.in_(_CLUSTER_ROLES),
            a.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER,
        ),
    )


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
    from app.services.appliance.ownership import hostname_sql  # noqa: PLC0415

    a = aliased(Appliance)
    assigned = (
        (
            await db.execute(
                select(a.assigned_dhcp_group_id).where(
                    _in_vip_cluster_sql(a),
                    a.assigned_dhcp_group_id.is_not(None),
                    a.assigned_roles.contains(["dhcp"]),
                )
            )
        )
        .scalars()
        .all()
    )
    # A Kea row owned by a cluster node: by the FK, or by the agent's reported
    # host against the node's hostname (agents register by hostname and never
    # set ``appliance_id``; the hostname branch of ``own_server_condition``).
    owner = aliased(Appliance)
    on_cluster = exists().where(
        _in_vip_cluster_sql(owner),
        or_(
            owner.id == DHCPServer.appliance_id,
            and_(
                DHCPServer.appliance_id.is_(None),
                DHCPServer.agent_id.is_not(None),
                hostname_sql(owner.hostname) == hostname_sql(DHCPServer.host),
            ),
        ),
    )
    registered = (
        (
            await db.execute(
                select(DHCPServer.server_group_id).where(
                    DHCPServer.driver == "kea",
                    DHCPServer.server_group_id.is_not(None),
                    on_cluster,
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

    ``roles`` overrides the appliance's current roles (a preview). Only a
    node of the VIP's own cluster (:func:`in_vip_cluster`) runs its Kea as a
    pod the VIP Service selects.
    """
    if group.dhcp_socket_mode != DIRECT_SOCKET_MODE:
        return None
    if "dhcp" not in ((appliance.assigned_roles if roles is None else roles) or []):
        return None
    if not in_vip_cluster(appliance):
        return None
    vip = await load_relay_vip(db)
    if not vip:
        return None
    return refusal_for_groups(vip, [group.name])


async def server_join_refusal(
    db: AsyncSession, server: DHCPServer, group_id: uuid.UUID | None
) -> str | None:
    """Why moving the Kea ``server`` into ``group_id`` would put a ``direct``
    group behind the relay VIP, or None. For the DHCP server PUT: the row's
    owner is a cluster node, so its Kea pod is behind the Service."""
    from app.services.appliance.ownership import (  # noqa: PLC0415
        owning_appliance_for_dhcp_server,
    )

    if group_id is None or server.driver != "kea":
        return None
    group = await db.get(DHCPServerGroup, group_id)
    if group is None or group.dhcp_socket_mode != DIRECT_SOCKET_MODE:
        return None
    vip = await load_relay_vip(db)
    if not vip:
        return None
    owner = await owning_appliance_for_dhcp_server(db, server)
    if owner is None or not in_vip_cluster(owner):
        return None
    return refusal_for_groups(vip, [group.name])


async def promote_refusal(db: AsyncSession, joiners: Iterable[Appliance]) -> str | None:
    """Why promoting ``joiners`` into the control-plane cluster would put a
    ``direct`` group behind the relay VIP, or None. A joiner's Kea pod joins
    the cluster's DaemonSet, and so the VIP Service, the moment it is a node."""
    from app.services.appliance.ownership import own_server_condition  # noqa: PLC0415

    vip = await load_relay_vip(db)
    if not vip:
        return None
    ids: set[uuid.UUID] = set()
    for a in joiners:
        if "dhcp" in (a.assigned_roles or []) and a.assigned_dhcp_group_id is not None:
            ids.add(a.assigned_dhcp_group_id)
        own = await own_server_condition(db, a, DHCPServer)
        ids.update(
            gid
            for gid in (
                await db.execute(
                    select(DHCPServer.server_group_id).where(own, DHCPServer.driver == "kea")
                )
            ).scalars()
            if gid is not None
        )
    if not ids:
        return None
    names = (
        (
            await db.execute(
                select(DHCPServerGroup.name)
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
    return refusal_for_groups(vip, names) if names else None


def alert_message(group_name: str, vip: str) -> str:
    """The ``dhcp_relay_vip_direct_socket`` event message for one group."""
    return (
        f"DHCP server group '{group_name}' is behind the DHCP relay VIP {vip} in "
        f"direct socket mode. {_WHY} {_FIX}"
    )
