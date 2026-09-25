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
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import select, text

from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import Subnet
from app.services.dns.sync_check import _effective_dns

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


def cidrs_overlap(a: object, b: object) -> bool:
    """True when two CIDR strings are the same address family and overlap.

    #844 uses this instead of a bare space-id comparison: IPv4 reverse zones
    aggregate to /24 (``compute_reverse_zone_name``), so two NON-overlapping
    subnets in different spaces legitimately share one reverse zone — their
    PTR names are disjoint and nothing leaks. Only an actual CIDR overlap
    can fold two tenants' PTRs onto the same names.
    """
    try:
        na = ipaddress.ip_network(str(a), strict=False)
        nb = ipaddress.ip_network(str(b), strict=False)
    except (ValueError, TypeError):
        return False
    return na.version == nb.version and na.overlaps(nb)


def compute_reverse_zone_name(network: str) -> str:
    """Return the canonical reverse-zone FQDN (with trailing dot) for ``network``.

    Uses ``ipaddress.ip_network(...).reverse_pointer`` which always produces a
    properly aligned in-addr.arpa / ip6.arpa name for byte/nibble-aligned
    prefixes. For non-aligned IPv4 prefixes (e.g. /23) we fall back to the
    nearest enclosing octet boundary, which is the standard BIND convention for
    an "aggregated" reverse zone covering multiple smaller subnets.
    """
    net = ipaddress.ip_network(network, strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        # Align to the next-smaller /8, /16, or /24 boundary.
        if net.prefixlen <= 8:
            aligned_prefix = 8
        elif net.prefixlen <= 16:
            aligned_prefix = 16
        elif net.prefixlen <= 24:
            aligned_prefix = 24
        else:
            aligned_prefix = 24  # zones at /24 cover sub-prefixes
        aligned = ipaddress.ip_network(f"{net.network_address}/{aligned_prefix}", strict=False)
        name = aligned.network_address.reverse_pointer
        # reverse_pointer for 10.0.0.0 returns "0.0.0.10.in-addr.arpa"
        # We need to drop leading octets outside the /aligned_prefix.
        octets_kept = aligned_prefix // 8
        parts = name.split(".")
        # first 4 entries are the 4 IPv4 octets in reverse
        reversed_octets = parts[:4]
        suffix = ".".join(parts[4:])  # "in-addr.arpa"
        keep = reversed_octets[4 - octets_kept :]
        fqdn = ".".join(keep + [suffix])
    else:
        # IPv6 — reverse_pointer already yields a full nibble-aligned name.
        # For prefixes that aren't nibble-aligned, round up to the next nibble.
        aligned_prefix = ((net.prefixlen + 3) // 4) * 4
        aligned = ipaddress.ip_network(f"{net.network_address}/{aligned_prefix}", strict=False)
        name = aligned.network_address.reverse_pointer
        nibbles_kept = aligned_prefix // 4
        parts = name.split(".")
        reversed_nibbles = parts[:32]
        suffix = ".".join(parts[32:])  # "ip6.arpa"
        keep = reversed_nibbles[32 - nibbles_kept :]
        fqdn = ".".join(keep + [suffix])
    return fqdn if fqdn.endswith(".") else fqdn + "."


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


async def ensure_reverse_zone_for_subnet(
    db: AsyncSession,
    subnet: Subnet,
    current_user: User | None,
    *,
    dns_group_id: uuid.UUID | None = None,
    dns_zone_id: uuid.UUID | None = None,
) -> DNSZone | None:
    """Create the matching reverse zone for ``subnet`` if one does not exist.

    Resolution of the server group:

    1. Explicit ``dns_group_id`` argument wins.
    2. Otherwise the subnet's own ``dns_zone_id`` (or the ``dns_zone_id``
       argument) names it through the zone's group, then the subnet's own
       ``dns_group_ids[0]``.
    3. Otherwise the DNS the subnet inherits — the first block up its chain
       with inheritance off, else its space — the same walk
       ``GET /subnets/{id}/effective-dns`` answers with: the effective zone's
       group, then the effective ``dns_group_ids[0]`` (spatiumddi#1149).
    4. If no group can be resolved the call is a no-op and returns ``None``.

    The function is idempotent: if a reverse zone with the computed FQDN
    already exists in the resolved group it is returned unchanged (or, #844,
    refused when an overlapping subnet in another IP space owns it — however
    the group was resolved).

    Writes an ``audit_log`` entry on newly-created zones.
    """
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
        return None

    group = await db.get(DNSServerGroup, group_id)
    if group is None:
        logger.warning(
            "reverse_zone_group_missing",
            subnet_id=str(subnet.id),
            group_id=str(group_id),
        )
        return None

    # 2. Compute reverse FQDN
    try:
        reverse_name = compute_reverse_zone_name(str(subnet.network))
    except ValueError:
        logger.warning(
            "reverse_zone_compute_failed",
            subnet_id=str(subnet.id),
            network=str(subnet.network),
        )
        return None

    # 3. Idempotency — return any existing zone with this FQDN in this group
    existing_q = await db.execute(
        select(DNSZone).where(
            DNSZone.group_id == group.id,
            DNSZone.name == reverse_name,
        )
    )
    existing = existing_q.scalar_one_or_none()
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
        is_auto_generated=True,
        linked_subnet_id=subnet.id,
    )
    db.add(zone)
    await db.flush()

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


def reverse_zone_network(name: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The network an octet-aligned ``in-addr.arpa`` (nibble-aligned
    ``ip6.arpa``) zone name covers — the inverse of
    :func:`compute_reverse_zone_name`. ``None`` for any other name."""
    labels = name.lower().rstrip(".").split(".")
    if labels[-2:] == ["in-addr", "arpa"]:
        octets = labels[:-2][::-1]
        if not 1 <= len(octets) <= 3 or not all(o.isdigit() and int(o) <= 255 for o in octets):
            return None
        addr = ".".join(octets + ["0"] * (4 - len(octets)))
        return ipaddress.ip_network(f"{addr}/{8 * len(octets)}")
    if labels[-2:] == ["ip6", "arpa"]:
        nibbles = labels[:-2][::-1]
        if not 1 <= len(nibbles) <= 32 or not all(
            len(n) == 1 and n in "0123456789abcdef" for n in nibbles
        ):
            return None
        hexstr = "".join(nibbles).ljust(32, "0")
        addr = ":".join(hexstr[i : i + 4] for i in range(0, 32, 4))
        return ipaddress.ip_network(f"{addr}/{4 * len(nibbles)}")
    return None


async def surviving_sharer(db: AsyncSession, zone: DNSZone, subnet: Subnet) -> uuid.UUID | None:
    """The id of another live subnet whose addresses fall inside the network
    ``zone`` covers — a /25 beside the one being deleted in an aggregated /24
    zone — or ``None``. Such a zone must outlive the subnet: it is re-linked
    to the survivor (the same-space one first) instead of retired, the way
    :func:`ensure_reverse_zone_for_subnet` already re-links a dangling zone
    to the next subnet that needs it."""
    covered = reverse_zone_network(zone.name)
    if covered is None:
        return None
    row = (
        await db.execute(
            text(
                "SELECT id FROM subnet WHERE id != CAST(:sid AS uuid) "
                "AND deleted_at IS NULL AND network <<= CAST(:covered AS cidr) "
                "ORDER BY (space_id = CAST(:space AS uuid)) DESC, network LIMIT 1"
            ),
            {"sid": str(subnet.id), "covered": str(covered), "space": str(subnet.space_id)},
        )
    ).first()
    return row[0] if row else None


async def retire_auto_reverse_zones(
    db: AsyncSession, subnet: Subnet, *, batch: SoftDeleteBatch | None = None
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
        survivor = await surviving_sharer(db, zone, subnet)
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
