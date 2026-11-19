"""One DNS server group per control-plane cluster (#1427).

A formed control-plane cluster has ONE ``spatiumddi-appliance`` HelmChart and
so ONE DNS agent group (``dnsBind9.serverGroupName``; the PowerDNS and
Technitium blocks carry the same value). Whichever member holding a DNS role
writes that chart last sets it, from its own ``assigned_dns_group_id``: with
members in two groups, every DNS agent of the cluster served the group of the
last writer, and the other group was accepted and ignored.

Per-node groups need per-node values a shared chart cannot hold, so for 1.0
the assignment is refused instead (mzac, on #1427). Every path that can set a
cluster member's DNS group goes through here, so the answer cannot depend on
which door the operator used:

* ``PUT /appliance/appliances/{id}/roles`` (the Fleet save);
* the Operator Copilot's ``assign_appliance_role`` operation;
* a DNS server move, which repoints its owning appliance's group (#934);
* a control-plane promote, which makes a DNS-holding appliance a member.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    DESIRED_CLUSTER_ROLE_MEMBER,
    DESIRED_CLUSTER_ROLE_NONE,
    Appliance,
)

DNS_ROLES = frozenset({"dns-bind9", "dns-powerdns", "dns-technitium"})


async def effective_cluster_members(db: AsyncSession) -> list[Appliance]:
    """Every approved appliance that is, or is becoming, a control-plane
    member: settled members plus in-flight joiners, minus in-flight leavers
    (the same set the promote / demote endpoints count)."""
    rows = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    or_(
                        Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
                        Appliance.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER,
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    return [r for r in rows if r.desired_cluster_role != DESIRED_CLUSTER_ROLE_NONE]


def dns_groups_of(appliances: Iterable[Appliance]) -> set[uuid.UUID]:
    """The DNS groups the given appliances serve: those holding a DNS role
    with a group assigned."""
    return {
        a.assigned_dns_group_id
        for a in appliances
        if a.assigned_dns_group_id is not None and DNS_ROLES.intersection(a.assigned_roles or [])
    }


async def _group_names(db: AsyncSession, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    from app.models.dns import DNSServerGroup  # noqa: PLC0415

    if not ids:
        return {}
    rows = await db.execute(
        select(DNSServerGroup.id, DNSServerGroup.name).where(DNSServerGroup.id.in_(ids))
    )
    return {gid: name for gid, name in rows.all()}


def _named(names: dict[uuid.UUID, str], ids: Iterable[uuid.UUID]) -> str:
    return " and ".join(sorted(repr(names.get(g, str(g))) for g in ids))


async def cluster_dns_group_refusal(
    db: AsyncSession,
    row: Appliance,
    *,
    roles: list[str],
    group_id: uuid.UUID | None,
    prev_roles: set[str],
    prev_group_id: uuid.UUID | None,
) -> str | None:
    """Why ``row`` may not run DNS in ``group_id`` with ``roles``, or None.

    Refused on a change only (gaining a DNS role, or a new group), so
    re-saving what is there never is; dropping DNS never is; an appliance
    outside the cluster has its own chart. An unknown group is left to the
    caller's existence check.
    """
    if group_id is None or not DNS_ROLES.intersection(roles):
        return None
    if DNS_ROLES.intersection(prev_roles) and group_id == prev_group_id:
        return None
    members = await effective_cluster_members(db)
    if all(m.id != row.id for m in members):
        return None
    others = dns_groups_of(m for m in members if m.id != row.id)
    if not others or others == {group_id}:
        return None
    names = await _group_names(db, others | {group_id})
    if group_id not in names:
        return None  # an unknown group: the caller's existence check answers it
    cluster = _named(names, others)
    return (
        f"Appliance {row.hostname!r} is a member of the control-plane cluster, and a "
        f"cluster serves one DNS server group: its other DNS members are in {cluster}. "
        f"It cannot run DNS in {names[group_id]!r}. Assign {cluster}, or take DNS off "
        "the other members first."
    )


async def promote_dns_group_refusal(
    db: AsyncSession, members: list[Appliance], joiners: list[Appliance]
) -> str | None:
    """Why promoting ``joiners`` into the cluster of ``members`` would leave
    it serving more than one DNS group, or None.

    Only the joiners' groups can be refused here: a cluster already split
    (from before #1427) is not made worse by a joiner without DNS, and is
    reported by the roles PUT when a member is next changed."""
    joining = dns_groups_of(joiners)
    if not joining:
        return None
    existing = dns_groups_of(m for m in members if all(m.id != j.id for j in joiners))
    together = existing | joining
    if len(together) <= 1:
        return None
    names = await _group_names(db, together)
    with_dns = sorted(
        j.hostname or str(j.id)
        for j in joiners
        if j.assigned_dns_group_id is not None and DNS_ROLES.intersection(j.assigned_roles or [])
    )
    if existing:
        clash = f"while the cluster's DNS members are in {_named(names, existing)}"
    else:
        clash = "between them"
    return (
        "A control-plane cluster serves one DNS server group, and this promote would "
        f"give it {_named(names, together)}: {', '.join(with_dns)} run DNS in "
        f"{_named(names, joining)} {clash}. Assign the joiners the cluster's group, "
        "or take DNS off them, first."
    )


__all__ = [
    "DNS_ROLES",
    "cluster_dns_group_refusal",
    "dns_groups_of",
    "effective_cluster_members",
    "promote_dns_group_refusal",
]
