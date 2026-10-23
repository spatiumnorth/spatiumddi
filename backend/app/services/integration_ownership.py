"""Which integration owns an IPAM row (#1135).

Every read-only integration mirror stamps its own provenance FK on the
``IPAddress`` / ``Subnet`` / ``IPBlock`` rows it creates or claims, and must
never claim a row that another integration already owns. The FKs live here
and nowhere else.

Before #1135 each of the seven older reconcilers kept its own hand-written
``row.x_id is not None or …`` chain, and every one had fallen behind as
integrations were added after it. A mirror that misses another's FK claims
that row and stamps ``user_modified_at``, which freezes it for both
integrations and keeps it alive after both let go.

``tests/test_integration_ownership.py`` derives the FK set from the models,
so a new integration's column fails CI until it is added here. It also fails
on any hand-written chain of these columns elsewhere in ``app/``.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, Subnet

# Ownership FK → the integration's name, as block-sync targets and the
# block-move blockers report it.
INTEGRATION_OWNERSHIP: dict[str, str] = {
    "kubernetes_cluster_id": "kubernetes",
    "docker_host_id": "docker",
    "proxmox_node_id": "proxmox",
    "tailscale_tenant_id": "tailscale",
    "unifi_controller_id": "unifi",
    "cloud_endpoint_id": "cloud",
    "opnsense_router_id": "opnsense",
    "netbird_instance_id": "netbird",
    "panos_firewall_id": "paloalto",
    "fortinet_firewall_id": "fortinet",
    "meraki_org_id": "meraki",
}

INTEGRATION_OWNERSHIP_FKS: frozenset[str] = frozenset(INTEGRATION_OWNERSHIP)


def owning_integration(row: object) -> str | None:
    """The name of the integration that owns ``row``, or None if none does.

    A row should have at most one owner. If a pre-#1135 cross-claim left it
    with two, this names one of them.
    """
    for fk, name in INTEGRATION_OWNERSHIP.items():
        if getattr(row, fk) is not None:
            return name
    return None


def owned_by_other_integration(row: object, own_fk: str) -> bool:
    """True if an integration other than the one whose FK is ``own_fk`` owns
    ``row``. Another target of the SAME integration is the caller's check:
    each reconciler words that warning for its own kind of target."""
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    return any(getattr(row, fk) is not None for fk in INTEGRATION_OWNERSHIP if fk != own_fk)


async def subnet_has_surviving_addresses(
    db: AsyncSession, subnet_id: uuid.UUID, own_fk: str
) -> bool:
    """Whether deleting the subnet would cascade-delete addresses that are
    not purely the caller's own (#1558).

    ``IPAddress.subnet_id`` is ON DELETE CASCADE, so deleting a mirrored
    ``Subnet`` takes every address in it with it — including operator
    allocations, rows another integration owns, and the caller's own rows
    an operator edited (``user_modified_at`` set), which the address pass
    would otherwise un-claim and keep. A mirror whose upstream network
    left the desired set must check here first and un-claim the subnet
    (clear its own FK) instead of deleting it when this returns True.
    The OPNsense and firewall-mirror reconcilers hand-rolled this check
    first; every other mirror goes through here so the predicate can't
    drift again.
    """
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    survivor = or_(
        IPAddress.user_modified_at.is_not(None),
        getattr(IPAddress, own_fk).is_(None),
        *(getattr(IPAddress, fk).is_not(None) for fk in INTEGRATION_OWNERSHIP if fk != own_fk),
    )
    count = await db.scalar(
        select(func.count())
        .select_from(IPAddress)
        .where(IPAddress.subnet_id == subnet_id)
        .where(survivor)
    )
    return bool(count)


# Ownership FKs stamped on ``DNSRecord`` rows by a non-IPAM owner: the
# three integration mirrors plus the DNS pool health-check pipeline.
# IPAM's DNS drift sweep must never treat these rows as its own stale
# output (#1554).
DNS_RECORD_OWNER_FKS: tuple[str, ...] = (
    "kubernetes_cluster_id",
    "tailscale_tenant_id",
    "netbird_instance_id",
    "pool_member_id",
)

# ``DNSRecord.tags`` key marking a record as an ACME challenge TXT
# (acme-dns provider or the DNS-01 client). ACME records are not IPAM
# sync output — they have their own writers and janitor (#1554).
ACME_RECORD_TAG = "acme_challenge"


def dns_record_owned_elsewhere(record: object) -> bool:
    """True if a ``DNSRecord`` belongs to something other than IPAM DNS
    sync (#1554): an integration mirror's FK, the DNS pool pipeline, or
    the ACME challenge marker. Such rows carry no ``ip_address_id``, so
    the drift sweep's orphan query would otherwise report (and, with
    auto-delete on, delete) them as stale IPAM output."""
    if any(getattr(record, fk, None) is not None for fk in DNS_RECORD_OWNER_FKS):
        return True
    tags = getattr(record, "tags", None) or {}
    return bool(tags.get(ACME_RECORD_TAG))


async def address_taken(
    db: AsyncSession, subnet_id: Any, address: str, *, exclude_id: Any = None
) -> bool:
    """True if a row already holds ``address`` in ``subnet_id``.

    A mirror checks this before it inserts a row or moves one of its own
    rows into ``subnet_id``. After its claim pass, a row still sitting
    there belongs to another integration or another target of the same
    one; writing next to it would hit ``uq_ip_address_subnet_address``
    and roll back the whole sync (#1622, #1677).
    """
    stmt = select(IPAddress.id).where(
        IPAddress.subnet_id == subnet_id, IPAddress.address == address
    )
    if exclude_id is not None:
        stmt = stmt.where(IPAddress.id != exclude_id)
    return (await db.execute(stmt.limit(1))).scalar_one_or_none() is not None


# ── Space scoping (#2577) ─────────────────────────────────────────────────
#
# IP spaces are independent: the same address, MAC and hostname may exist in
# two of them and mean two different hosts. Every integration mirror targets
# exactly one space (``<target>.ipam_space_id``; a Cloud endpoint may add a
# ``public_space_id``), and must never look at, adopt, move, dedupe or delete
# an ``IPAddress`` row outside it.
#
# Before #2577 seven of the eight reconcilers looked rows up by bare address
# across EVERY space, adopted any operator row they found, re-parented it into
# their own space and could then delete it — so enabling an integration on an
# overlapping range silently stole operator rows (and, by the
# ``ondelete=SET NULL`` on ``DNSRecord.ip_address_id``, orphaned their DNS
# records). OPNsense alone had been fixed, by hand, in its own file. These two
# helpers are the only way a reconciler loads ``IPAddress`` rows, so an eighth
# reconciler gets the scoping for free; ``tests/test_integration_space_scoping.py``
# fails any reconciler query that bypasses them.


def _space_id_list(space_ids: Any | Iterable[Any]) -> list[Any]:
    if isinstance(space_ids, Collection) and not isinstance(space_ids, (str, bytes)):
        return [s for s in space_ids if s is not None]
    return [space_ids] if space_ids is not None else []


def scope_addresses_to_space(stmt: Select[Any], space_ids: Any | Iterable[Any]) -> Select[Any]:
    """Restrict an ``IPAddress`` select to rows whose subnet sits in one of
    ``space_ids``. A statement narrowed this way can never return a row from
    another space, whatever else it filters on. An empty / ``None`` space
    list matches nothing — a target with no space owns no rows."""
    ids = _space_id_list(space_ids)
    return stmt.join(Subnet, IPAddress.subnet_id == Subnet.id).where(Subnet.space_id.in_(ids))


async def addresses_in_space(
    db: AsyncSession, space_ids: Any | Iterable[Any], addresses: Iterable[str]
) -> list[IPAddress]:
    """Every row at one of ``addresses`` inside ``space_ids`` — the adoption
    candidates for a reconciler. Rows at the same address in any OTHER space
    are not returned, so they cannot be claimed, moved or deleted."""
    addrs = list(addresses)
    if not addrs:
        return []
    stmt = scope_addresses_to_space(select(IPAddress), space_ids).where(
        IPAddress.address.in_(addrs)
    )
    return list((await db.execute(stmt)).scalars().all())


async def owned_addresses_in_space(
    db: AsyncSession,
    own_fk: str,
    target_id: Any,
    space_ids: Any | Iterable[Any],
    *,
    warnings: list[str] | None = None,
) -> list[IPAddress]:
    """The rows the target owns (``own_fk == target_id``) inside ``space_ids``.

    This is a reconciler's "current" set: the rows it may update, move,
    dedupe and absence-delete. A row carrying the target's FK in another
    space — left behind when the target's space was changed, or stolen by a
    pre-#2577 build — is excluded and therefore left exactly where it is;
    ``find_cross_space_adoptions`` reports such rows for an operator to
    repair by hand.

    Pass the sync summary's ``warnings`` to have such rows counted into it,
    so a frozen row is visible on the integration's own sync status rather
    than only in that report."""
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    owned = getattr(IPAddress, own_fk) == target_id
    stmt = scope_addresses_to_space(select(IPAddress), space_ids).where(owned)
    rows = list((await db.execute(stmt)).scalars().all())
    if warnings is not None:
        outside = await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .join(Subnet, IPAddress.subnet_id == Subnet.id)
            .where(owned, Subnet.space_id.not_in(_space_id_list(space_ids)))
        )
        if outside:
            warnings.append(
                f"{outside} address row(s) owned by this target sit outside its IP space "
                "and were left untouched; see GET /api/v1/ipam/integration-space-audit (#2577)"
            )
    return rows


def move_stays_in_space(current_subnet_id: Any, space_subnet_ids: Collection[Any]) -> bool:
    """Whether a reconciler may re-parent a row it owns, given the ids of
    every subnet in its target space. A row whose CURRENT subnet is outside
    that set lives in another space and is never moved: re-parenting it is
    exactly how #2577 made operator rows vanish from their own space.
    ``owned_addresses_in_space`` already keeps such rows out of a
    reconciler's current set; this is the guard at the write itself."""
    return current_subnet_id in space_subnet_ids


__all__ = [
    "ACME_RECORD_TAG",
    "DNS_RECORD_OWNER_FKS",
    "INTEGRATION_OWNERSHIP",
    "INTEGRATION_OWNERSHIP_FKS",
    "address_taken",
    "addresses_in_space",
    "dns_record_owned_elsewhere",
    "move_stays_in_space",
    "owned_addresses_in_space",
    "owned_by_other_integration",
    "owning_integration",
    "scope_addresses_to_space",
    "subnet_has_surviving_addresses",
]
