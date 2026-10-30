"""Reverse-zone auto-creation for subnets that have DNS assignment.

When a subnet has a DNS assignment — its own ``dns_zone_id`` /
``dns_group_ids``, or the DNS it inherits from its block chain or space
(spatiumddi#1149) — SpatiumDDI creates the corresponding reverse zone
(``*.in-addr.arpa.`` or ``*.ip6.arpa.``) in the assigned server group if one
does not already exist.

Keeping the logic in the service layer (rather than inside the IPAM router)
satisfies the "driver abstraction / thin router" non-negotiable from
``CLAUDE.md``.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import select, text

from app.core.agent_wake import collect_wake, dns_group_channel
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import Subnet
from app.services.dns.new_object_defaults import load_dns_defaults
from app.services.dns.sync_check import (  # noqa: F401 — cidrs_overlap, reverse_zone_network re-exported
    _effective_dns,
    cidrs_overlap,
    ipam_authors_zone,
    reverse_zone_network,
    reverse_zone_pieces,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.auth import User
    from app.services.soft_delete import SoftDeleteBatch

logger = structlog.get_logger(__name__)

# #844 — log-dedupe for the cross-space refusal below. The ensure path runs
# per IP allocation, so an unfixed misconfig would otherwise emit one warning
# per allocation forever; warn once per (subnet, zone) pair per process, and
# demote repeats to debug. Log suppression only — never consulted for logic.
_cross_space_warned: set[tuple[str, str]] = set()
# #1932 — the same dedupe for the cloud opt-out skip below.
_cloud_optout_warned: set[tuple[str, str]] = set()


def cloud_reverse_optout_message(group_name: str, driver: str) -> str:
    """Why a subnet in a cloud DNS group gets no reverse zone (#1932). One
    sentence, shown in the IPAM DNS sync report and logged."""
    return (
        f"No reverse zone is created for this subnet: DNS group {group_name!r} "
        f"runs the cloud driver {driver!r}, which bills per hosted zone, and "
        f"auto-creating reverse zones there is off. PTR records are skipped. "
        f"Turn on 'Auto-create reverse zones at the provider' on the group to "
        f"create them, or create the reverse zone yourself."
    )


async def cloud_reverse_optout_driver(db: AsyncSession, group: DNSServerGroup) -> str | None:
    """The cloud driver that keeps reverse zones from being auto-created in
    ``group``, or None when they may be (#1932): the group runs a
    ``CLOUD_DNS_DRIVERS`` driver and has not opted in."""
    if group.auto_reverse_zones_at_provider:
        return None
    from app.drivers.dns import CLOUD_DNS_DRIVERS  # noqa: PLC0415
    from app.models.dns import DNSServer  # noqa: PLC0415

    drivers = (
        (await db.execute(select(DNSServer.driver).where(DNSServer.group_id == group.id)))
        .scalars()
        .all()
    )
    return next((d for d in sorted(set(drivers)) if d in CLOUD_DNS_DRIVERS), None)


def compute_reverse_zone_names(network: str) -> list[str]:
    """The reverse-zone FQDNs (trailing dot) that cover ``network``, in address
    order — one zone per /24 the subnet spans (spatiumddi#1840).

    One zone PER PIECE, never one enclosing zone: a /16 zone for a /23 would
    make SpatiumDDI authoritative for 510 addresses that are not the subnet's,
    shadowing reverse DNS someone else serves. The piece is the zone boundary
    that lies inside the subnet:

    * IPv4 /17–/32: the /24 (a /23 gets two zones, a /20 sixteen, a /17 128; a
      /25 or longer shares its /24's zone with its neighbours).
    * IPv4 /9–/16: the /16 (a /16 gets its one zone, a /12 sixteen). Per-/24
      would be up to 32,768 zones; each /16 here lies wholly inside the
      subnet, so the zone still claims nothing that is not its own.
    * IPv4 /0–/8: the /8 (up to 256 zones).
    * IPv6: the next nibble boundary at or past the prefix length — a /44,
      /48, /56 and /64 each get one zone, a non-aligned /55 its two /56 zones,
      a /45 its eight /48s (never more than 8 for a real prefix).
    """
    net = ipaddress.ip_network(network, strict=False)
    # bits per reverse label, and labels in a full reverse pointer
    bits, total = (8, 4) if isinstance(net, ipaddress.IPv4Network) else (4, 32)
    names: list[str] = []
    for piece in reverse_zone_pieces(net):
        parts = piece.network_address.reverse_pointer.split(".")
        labels = piece.prefixlen // bits  # octets (IPv4) or nibbles (IPv6) kept
        keep = parts[:total][total - labels :]
        names.append(".".join(keep + parts[total:]) + ".")
    return names


async def _inherited_dns_group(db: AsyncSession, subnet: Subnet) -> uuid.UUID | None:
    """The server group of the DNS ``subnet`` inherits (spatiumddi#1149): the
    effective forward zone's group, else the first effective ``dns_group_ids``
    entry, else ``None``.

    ``_effective_dns`` is the walk the drift check and ``GET
    /subnets/{id}/effective-dns`` share (subnet → block ancestors → space,
    honouring each level's inherit toggle), so the reverse zone lands in the
    group the subnet's forward records and PTR lookups already resolve to
    (``_resolve_effective_dns`` / ``_resolve_reverse_zone`` in the IPAM
    router).
    """
    group_ids, zone_id = await _effective_dns(db, subnet)
    if zone_id is not None:
        zone = await db.get(DNSZone, zone_id)
        if zone is not None:
            return zone.group_id
    for raw in group_ids:
        try:
            return uuid.UUID(str(raw))
        except (ValueError, TypeError):
            continue
    return None


async def ensure_reverse_zones_for_subnet(
    db: AsyncSession,
    subnet: Subnet,
    current_user: User | None,
    *,
    dns_group_id: uuid.UUID | None = None,
    dns_zone_id: uuid.UUID | None = None,
    honour_opt_out: bool = True,
) -> list[DNSZone]:
    """Create the matching reverse zones for ``subnet`` where they do not exist:
    one per /24 it spans (``compute_reverse_zone_names``, spatiumddi#1840).

    A subnet created with ``skip_reverse_zone`` opted out and stays out
    (spatiumddi#2735): every path here — the address-sync catch-up, a resize,
    the bulk backfills — returns ``[]`` for it. Only an operator asking for
    THIS subnet's zone by name (``honour_opt_out=False``, the per-subnet
    backfill endpoint) overrides it.

    Resolution of the server group:

    1. Explicit ``dns_group_id`` argument wins.
    2. Otherwise the subnet's own ``dns_zone_id`` (or the ``dns_zone_id``
       argument) names it through the zone's group, then the subnet's own
       ``dns_group_ids[0]``.
    3. Otherwise the DNS the subnet inherits — the first block up its chain
       with inheritance off, else its space — the same walk
       ``GET /subnets/{id}/effective-dns`` answers with: the effective zone's
       group, then the effective ``dns_group_ids[0]`` (spatiumddi#1149).
    4. If no group can be resolved the call is a no-op and returns ``[]``.

    The function is idempotent, per zone of the set: one that already exists
    in the resolved group is returned unchanged (or, #844,
    refused when an overlapping subnet in another IP space owns it — however
    the group was resolved). A zone of that name SpatiumDDI does not author —
    a forwarder, a secondary or a stub — is not adopted: another server owns
    the subnet's reverse names, so that zone is left out of the result and
    nothing is created beside it (spatiumddi#1419).

    Writes an ``audit_log`` entry on newly-created zones.
    """
    if honour_opt_out and getattr(subnet, "skip_reverse_zone", False):
        return []

    # 1. Resolve the server group
    group_id = dns_group_id
    if group_id is None:
        # Direct subnet-level zone assignment
        subnet_zone_id = getattr(subnet, "dns_zone_id", None) or dns_zone_id
        if subnet_zone_id:
            zone = await db.get(DNSZone, subnet_zone_id)
            if zone is not None:
                group_id = zone.group_id
    if group_id is None:
        subnet_groups = getattr(subnet, "dns_group_ids", None) or []
        if subnet_groups:
            try:
                group_id = uuid.UUID(str(subnet_groups[0]))
            except (ValueError, TypeError):
                group_id = None
    if group_id is None:
        # spatiumddi#1149 — nothing on the subnet itself: a subnet left on
        # "Inherit from parent" (the console's default, which sends no DNS
        # fields at all) takes its block's or space's group, so it gets the
        # reverse zone Getting Started promises "once the subnet has an
        # effective DNS group/zone". Consulted only when the subnet names no
        # DNS of its own, so every subnet that resolved a group before
        # resolves the same one now.
        group_id = await _inherited_dns_group(db, subnet)

    if group_id is None:
        logger.debug(
            "reverse_zone_skipped_no_group",
            subnet_id=str(subnet.id),
            network=str(subnet.network),
        )
        return []

    group = await db.get(DNSServerGroup, group_id)
    if group is None:
        logger.warning(
            "reverse_zone_group_missing",
            subnet_id=str(subnet.id),
            group_id=str(group_id),
        )
        return []

    # 2. Compute the reverse FQDNs — one per /24 (nibble piece) the subnet spans
    try:
        names = compute_reverse_zone_names(str(subnet.network))
    except ValueError:
        logger.warning(
            "reverse_zone_compute_failed",
            subnet_id=str(subnet.id),
            network=str(subnet.network),
        )
        return []

    # 3. Zones of the set that already exist (one query, not one per name)
    found = (
        (
            await db.execute(
                select(DNSZone).where(DNSZone.group_id == group.id, DNSZone.name.in_(names))
            )
        )
        .scalars()
        .all()
    )
    by_name = {z.name: z for z in found}
    # #1932 — a cloud group that has not opted in gets no NEW reverse zone.
    # Ones it already holds are still returned, as they were.
    optout_driver = (
        await cloud_reverse_optout_driver(db, group)
        if any(n not in by_name for n in names)
        else None
    )
    if optout_driver is not None:
        key = (str(subnet.id), str(group.id))
        log_fn = logger.debug if key in _cloud_optout_warned else logger.warning
        _cloud_optout_warned.add(key)
        log_fn(
            "reverse_zone_skipped_cloud_optout",
            subnet_id=str(subnet.id),
            network=str(subnet.network),
            group_id=str(group.id),
            driver=optout_driver,
            missing=sum(1 for n in names if n not in by_name),
        )
    out: list[DNSZone] = []
    for name in names:
        if optout_driver is not None and name not in by_name:
            continue
        zone = await _ensure_zone_named(db, subnet, group, name, by_name.get(name), current_user)
        if zone is not None:
            out.append(zone)
    if any(z.name not in by_name for z in out):
        # One wake for the whole set, however many zones it created (a /17
        # makes 128): the collector is a set, flushed once after the commit,
        # so the agents re-render once rather than waiting for the safety
        # tick. No-op outside a request (Celery callers converge on the
        # bundle-dirty render, which wakes its own servers).
        collect_wake(dns_group_channel(group.id))
    return out


async def ensure_reverse_zone_for_subnet(
    db: AsyncSession,
    subnet: Subnet,
    current_user: User | None,
    *,
    dns_group_id: uuid.UUID | None = None,
    dns_zone_id: uuid.UUID | None = None,
    honour_opt_out: bool = True,
) -> DNSZone | None:
    """:func:`ensure_reverse_zones_for_subnet`, returning the first zone of the
    set (or ``None``)."""
    zones = await ensure_reverse_zones_for_subnet(
        db,
        subnet,
        current_user,
        dns_group_id=dns_group_id,
        dns_zone_id=dns_zone_id,
        honour_opt_out=honour_opt_out,
    )
    return zones[0] if zones else None


async def _ensure_zone_named(
    db: AsyncSession,
    subnet: Subnet,
    group: DNSServerGroup,
    reverse_name: str,
    existing: DNSZone | None,
    current_user: User | None,
) -> DNSZone | None:
    """Idempotently ensure ONE reverse zone of ``subnet``'s set exists.
    ``existing`` is the zone of that name already in the group, if any."""
    # Idempotency — an existing zone with this FQDN in this group is returned.
    if existing is not None and not ipam_authors_zone(existing):
        # #1419 — a forwarder, a secondary or a stub of this name: another
        # server owns the subnet's reverse names. It is not the subnet's
        # reverse zone (IPAM writes no PTR into it), and the (group_id,
        # view_id, name) unique constraint leaves no room for a primary
        # beside it.
        logger.debug(
            "reverse_zone_not_authored",
            subnet_id=str(subnet.id),
            zone_id=str(existing.id),
            name=reverse_name,
            zone_type=existing.zone_type,
        )
        return None
    if existing is not None:
        # #844 — an OVERLAPPING CIDR in another IP space computes the same
        # reverse zone name, and the (group_id, view_id, name) unique
        # constraint means a second zone can't exist. Silently reusing the
        # other space's zone would merge two tenants' PTRs onto the same
        # names (cross-tenant hostname disclosure), so refuse: this subnet's
        # IPs simply get no PTR until the operator gives the overlapping
        # space its own DNS group. Non-overlapping subnets sharing an
        # aggregated /24 zone (even across spaces) keep working — their PTR
        # names are disjoint, so there is nothing to leak.
        if existing.linked_subnet_id is not None and existing.linked_subnet_id != subnet.id:
            linked = (
                await db.execute(
                    select(Subnet.space_id, Subnet.network).where(
                        Subnet.id == existing.linked_subnet_id
                    )
                )
            ).first()
            if linked is None:
                # Dangling link — the owning subnet was deleted but its zone
                # survived (linked_subnet_id is ondelete=SET NULL on hard
                # delete, but a stale id can linger). Re-link to the live
                # subnet so the zone is attributable again instead of
                # becoming permanently "shared with everyone".
                existing.linked_subnet_id = subnet.id
                await db.flush()
                logger.info(
                    "reverse_zone_relinked",
                    zone_id=str(existing.id),
                    subnet_id=str(subnet.id),
                    name=reverse_name,
                )
            elif linked[0] != subnet.space_id and cidrs_overlap(linked[1], subnet.network):
                key = (str(subnet.id), str(existing.id))
                log_fn = logger.debug if key in _cross_space_warned else logger.warning
                _cross_space_warned.add(key)
                log_fn(
                    "reverse_zone_cross_space_conflict",
                    subnet_id=str(subnet.id),
                    space_id=str(subnet.space_id),
                    zone_id=str(existing.id),
                    name=reverse_name,
                    linked_subnet_id=str(existing.linked_subnet_id),
                    note="reverse zone owned by an overlapping subnet in "
                    "another IP space; refusing to share it — use a separate "
                    "DNS server group per overlapping IP space (#844)",
                )
                return None
        logger.debug(
            "reverse_zone_already_exists",
            subnet_id=str(subnet.id),
            zone_id=str(existing.id),
            name=reverse_name,
        )
        return existing

    # 4. Create the reverse zone
    zone = DNSZone(
        group_id=group.id,
        name=reverse_name,
        zone_type="primary",
        kind="reverse",
        ttl=(await load_dns_defaults(db)).ttl,  # #3087
        is_auto_generated=True,
        linked_subnet_id=subnet.id,
    )
    db.add(zone)
    await db.flush()
    # #1932 — an agentless group (technitium_api / Windows Path B / cloud)
    # only gets the zone when it is pushed; the zone endpoints do that, this
    # path used to create the row alone, so every PTR op failed with "No such
    # zone". Marked and queued for after the commit, ahead of the record ops;
    # every create path that reaches the provider for an auto zone is here
    # (IPAM create / auto-sync / DDNS / subnet create all call this).
    from app.services.dns.record_ops import (  # noqa: PLC0415
        provision_zone_at_agentless_servers,
    )

    await provision_zone_at_agentless_servers(db, zone)

    db.add(
        AuditLog(
            user_id=current_user.id if current_user else None,
            user_display_name=(current_user.display_name if current_user else "system"),
            auth_source=current_user.auth_source if current_user else "system",
            action="create",
            resource_type="dns_zone",
            resource_id=str(zone.id),
            resource_display=f"{reverse_name} (auto-reverse for {subnet.network})",
            result="success",
            new_value={
                "auto_generated": True,
                "linked_subnet_id": str(subnet.id),
                "kind": "reverse",
                "group_id": str(group.id),
            },
        )
    )
    logger.info(
        "reverse_zone_auto_created",
        subnet_id=str(subnet.id),
        zone_id=str(zone.id),
        name=reverse_name,
        group_id=str(group.id),
        at=datetime.now(UTC).isoformat(),
    )
    return zone


# ── Retirement (spatiumddi#1066) ──────────────────────────────────────────────
#
# A subnet's auto-created reverse zone used to outlive the subnet on the
# default (soft) delete: the batch carried the subnet and its DHCP scopes only,
# so the zone stayed listed, linked to a subnet the API answered 404 for, still
# rendered to the agents. The permanent path deleted it with a bare set-based
# DELETE — no queued-op sweep, no agent wake, and no thought for a sibling
# subnet sharing the aggregated /24. Both paths now go through here.


async def surviving_sharer(
    db: AsyncSession,
    zone: DNSZone,
    subnet: Subnet,
    *,
    exclude_ids: frozenset[uuid.UUID] = frozenset(),
) -> uuid.UUID | None:
    """The id of another live subnet whose addresses fall inside the network
    ``zone`` covers — a /25 beside the one being deleted in an aggregated /24
    zone — or ``None``. Such a zone must outlive the subnet: it is re-linked
    to the survivor (the same-space one first) instead of retired, the way
    :func:`ensure_reverse_zone_for_subnet` already re-links a dangling zone
    to the next subnet that needs it.

    ``exclude_ids`` are subnets going away in the same operation (a block or
    space delete, not yet stamped): none of them can be the survivor."""
    covered = reverse_zone_network(zone.name)
    if covered is None:
        return None
    row = (
        await db.execute(
            text(
                "SELECT id FROM subnet WHERE id != CAST(:sid AS uuid) "
                "AND id != ALL(CAST(:excl AS uuid[])) "
                "AND deleted_at IS NULL AND network <<= CAST(:covered AS cidr) "
                "ORDER BY (space_id = CAST(:space AS uuid)) DESC, network LIMIT 1"
            ),
            {
                "sid": str(subnet.id),
                "covered": str(covered),
                "space": str(subnet.space_id),
                "excl": [str(i) for i in exclude_ids],
            },
        )
    ).first()
    return row[0] if row else None


async def retire_auto_reverse_zones(
    db: AsyncSession,
    subnet: Subnet,
    *,
    batch: SoftDeleteBatch | None = None,
    exclude_ids: frozenset[uuid.UUID] = frozenset(),
) -> tuple[list[DNSZone], list[DNSZone], set[uuid.UUID]]:
    """Take the reverse zones ``subnet`` auto-created out of service with it.

    For every zone linked to the subnet and marked ``is_auto_generated``:

    * a zone another live subnet still lives in is re-linked to that
      survivor and stays (``reverse_zone_relinked``);
    * otherwise it is retired — with ``batch`` (the soft path) it is appended
      to the subnet's own deletion batch with its records, so the trash shows
      one deletion and a restore brings subnet and zone back together; without
      one (the permanent path) it is hard-deleted the way the zone-delete
      operation does it: agentless servers told, queued ops swept, records
      deleted set-based, the zone row deleted.

    Returns ``(retired, relinked, dns_group_ids_to_wake)``; the caller wakes
    the groups after its commit so the agents re-render without waiting for
    the safety tick.
    """
    from sqlalchemy import delete as sa_delete  # noqa: PLC0415

    from app.models.dns import DNSRecord  # noqa: PLC0415
    from app.services.dns.record_ops import sweep_zone_ops  # noqa: PLC0415
    from app.services.soft_delete import add_to_batch  # noqa: PLC0415

    zones = (
        (
            await db.execute(
                select(DNSZone).where(
                    DNSZone.linked_subnet_id == subnet.id,
                    DNSZone.is_auto_generated.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    retired: list[DNSZone] = []
    relinked: list[DNSZone] = []
    wake: set[uuid.UUID] = set()
    for zone in zones:
        survivor = await surviving_sharer(db, zone, subnet, exclude_ids=exclude_ids)
        if survivor is not None:
            zone.linked_subnet_id = survivor
            relinked.append(zone)
            logger.info(
                "reverse_zone_relinked",
                zone_id=str(zone.id),
                name=zone.name,
                from_subnet_id=str(subnet.id),
                subnet_id=str(survivor),
                reason="linked subnet deleted; a live subnet still lives in the zone",
            )
            continue
        await sweep_zone_ops(db, zone, zone.group_id)
        if batch is not None:
            await add_to_batch(db, batch, zone)
        else:
            from app.api.v1.dns.router import _push_zone_to_agentless_servers  # noqa: PLC0415

            await _push_zone_to_agentless_servers(db, zone, "delete")
            await db.execute(sa_delete(DNSRecord).where(DNSRecord.zone_id == zone.id))
            await db.delete(zone)
        wake.add(zone.group_id)
        retired.append(zone)
        logger.info(
            "reverse_zone_retired",
            zone_id=str(zone.id),
            name=zone.name,
            subnet_id=str(subnet.id),
            mode="trash" if batch is not None else "delete",
        )
    return retired, relinked, wake


async def retire_auto_reverse_zones_for_batch(
    db: AsyncSession, batch: SoftDeleteBatch
) -> set[uuid.UUID]:
    """The block / space delete's half of :func:`retire_auto_reverse_zones`
    (spatiumddi#2734): every subnet the batch is about to trash takes the
    reverse zones it auto-created into the same batch, so the Trash shows one
    deletion and one restore brings all of it back. Call BEFORE
    ``apply_soft_delete``. The batch's own subnets are never a survivor — they
    are all going — so only a subnet outside the batch keeps a shared zone
    alive. Returns the DNS group ids to wake after the commit."""
    subnets = [row.obj for row in batch.rows if isinstance(row.obj, Subnet)]
    going = frozenset(sub.id for sub in subnets)
    wake: set[uuid.UUID] = set()
    for sub in subnets:
        _retired, _relinked, groups = await retire_auto_reverse_zones(
            db, sub, batch=batch, exclude_ids=going
        )
        wake |= groups
    return wake


async def purge_auto_reverse_zones(
    db: AsyncSession,
    subnets: list[Subnet],
    *,
    audit: Callable[[DNSZone], None] | None = None,
) -> set[uuid.UUID]:
    """Take the auto-created reverse zones of subnets being purged from the
    Trash with them (spatiumddi#2734). Two shapes, both reached before the
    subnet rows go (``dns_zone.linked_subnet_id`` is SET NULL, so afterwards
    nothing says whose zone it was):

    * a zone that went to the Trash with its subnet is purged through the one
      teardown every trashed zone uses (agentless servers told first; raises
      without touching the row when a provider refuses, or while a live record
      sits under it);
    * a zone still LIVE and linked to a trashed subnet — what the block and
      space deletes used to leave behind — is retired the way a permanent
      subnet delete does it (re-linked to a surviving sharer, else deleted).

    The caller owns the commit; ``audit`` is called with each trashed zone
    purged, for the caller's own audit row. Returns the group ids to wake."""
    if not subnets:
        return set()
    from app.services.dns.zone_purge import purge_trashed_zone  # noqa: PLC0415

    ids = [sub.id for sub in subnets]
    going = frozenset(ids)
    wake: set[uuid.UUID] = set()
    trashed = (
        (
            await db.execute(
                select(DNSZone)
                .where(
                    DNSZone.linked_subnet_id.in_(ids),
                    DNSZone.is_auto_generated.is_(True),
                    DNSZone.deleted_at.is_not(None),
                )
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    for zone in trashed:
        await purge_trashed_zone(db, zone)
        if audit is not None:
            audit(zone)
        wake.add(zone.group_id)
    for sub in subnets:
        _retired, _relinked, groups = await retire_auto_reverse_zones(db, sub, exclude_ids=going)
        wake |= groups
    return wake
