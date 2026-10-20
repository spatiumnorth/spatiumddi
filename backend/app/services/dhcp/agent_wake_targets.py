"""Which DHCP group channels to wake when a non-DHCP row the bundle reads changes.

The DHCP config bundle (``config_bundle.build_config_bundle``) reads more than
the ``dhcp_*`` tables: a scope's subnet supplies its network, its DNS servers
and domain name (Router Advertisements, the DHCPv6 domain search), its VLAN and
site (the E911 location options 99 / 123), and the ``network.e911`` /
``ipv6.router_advertisements`` feature modules gate whole blocks of it. A change
to any of those shifts the bundle ETag, but the handlers that make them live
outside ``/dhcp`` and never woke a parked agent long-poll, so the change
reached agents only on the ``WAKE_TICK_SECONDS`` safety tick (#2040).

These helpers resolve the affected groups. They only READ; the caller decides
whether to stash the channels (``collect_wake``, inside a request that carries
``wake_publishing``) or publish them after its own commit (``publish_wake``).
Over-waking is cheap and safe: a woken poll rebuilds the bundle, compares the
ETag, and parks again when nothing changed.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import dhcp_group_channel
from app.models.dhcp import DHCPScope


async def dhcp_group_channels_for_subnets(
    db: AsyncSession, subnet_ids: Iterable[uuid.UUID]
) -> list[str]:
    """The group channel of every DHCP group serving a scope on these subnets."""
    ids = list(dict.fromkeys(subnet_ids))
    if not ids:
        return []
    rows = await db.execute(
        select(DHCPScope.group_id).where(DHCPScope.subnet_id.in_(ids)).distinct()
    )
    return [dhcp_group_channel(gid) for gid in rows.scalars().all()]


async def dhcp_group_channels_with_scopes(db: AsyncSession) -> list[str]:
    """The group channel of every DHCP group that serves at least one scope.

    For a change whose reach cannot be narrowed to a subnet without
    re-implementing the bundle's own resolution — an E911 binding on a site
    default or a VLAN, an ERL's civic address, a feature-module toggle. A group
    with no scope renders no subnet-derived config, so it is left asleep.
    """
    rows = await db.execute(select(DHCPScope.group_id).distinct())
    return [dhcp_group_channel(gid) for gid in rows.scalars().all()]


__all__ = ["dhcp_group_channels_for_subnets", "dhcp_group_channels_with_scopes"]
