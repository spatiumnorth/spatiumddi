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
from dataclasses import dataclass
from typing import Any

from sqlalchemy import exists, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress

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


@dataclass
class ReleaseSummary:
    """What :func:`release_integration_rows` did, for the audit row."""

    addresses_released: int = 0
    addresses_removed: int = 0
    subnets_released: int = 0
    subnets_removed: int = 0
    blocks_released: int = 0
    blocks_removed: int = 0

    def as_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


async def release_integration_rows(
    db: AsyncSession,
    *,
    own_fk: str,
    target_id: uuid.UUID,
    user: Any = None,
    target_name: str = "",
) -> ReleaseSummary:
    """Hand back everything operator-made before an integration target is
    deleted (#2287).

    Every ownership FK is ``ON DELETE CASCADE``, and ``IPAddress.subnet_id`` /
    ``DHCPScope.subnet_id`` cascade from the subnet, so a bare ``db.delete``
    of the target destroyed operator addresses, DHCP scopes, pools and
    reservations inside mirrored subnets (the reconcilers got the guard in
    #1558; target deletion did not). Call this in every target delete
    handler, in the same transaction, immediately before ``db.delete``.

    * Addresses the target owns that an operator touched
      (``user_modified_at``), another integration owns, or that carry a DNS
      record / static reservation are un-claimed (FK cleared, row kept).
    * A subnet is un-claimed when any address in it survives, a DHCP scope
      or a subnet-domain link hangs off it, or it carries tags / custom
      fields. Otherwise it is purely mirrored and removed.
    * A block is un-claimed when it carries tags / custom fields or still
      has a child block or subnet that is not being removed.
    * Soft-deleted (Trash) rows are un-claimed so the cascade cannot
      hard-delete them.

    Purely mirrored rows are removed the way the reconcilers remove them.
    """
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    from app.models.address_set import AddressSet  # noqa: PLC0415
    from app.models.bacnet import BACnetDevice  # noqa: PLC0415
    from app.models.dhcp import DHCPScope, DHCPStaticAssignment  # noqa: PLC0415
    from app.models.dns import DNSRecord  # noqa: PLC0415
    from app.models.e911 import ERLBinding  # noqa: PLC0415
    from app.models.ipam import IPBlock, Subnet, SubnetDomain  # noqa: PLC0415
    from app.models.multicast import MulticastMembership  # noqa: PLC0415
    from app.models.ot import OTDevice, OTZone  # noqa: PLC0415

    summary = ReleaseSummary()
    fk_addr = getattr(IPAddress, own_fk)

    # Operator registries whose FK to ip_address / subnet is ON DELETE CASCADE:
    # a row one of them points at is operator content even when purely mirrored.
    registry_ref = or_(
        exists().where(OTDevice.ip_address_id == IPAddress.id),
        exists().where(BACnetDevice.ip_address_id == IPAddress.id),
        exists().where(ERLBinding.ip_address_id == IPAddress.id),
        exists().where(MulticastMembership.ip_address_id == IPAddress.id),
    )

    # 1. Addresses. A purely mirrored one is left for the FK cascade.
    survivor = or_(
        IPAddress.user_modified_at.is_not(None),
        *(getattr(IPAddress, fk).is_not(None) for fk in INTEGRATION_OWNERSHIP if fk != own_fk),
        exists().where(DNSRecord.ip_address_id == IPAddress.id),
        exists().where(DHCPStaticAssignment.ip_address_id == IPAddress.id),
        registry_ref,
    )
    summary.addresses_removed = (
        await db.scalar(
            select(func.count()).select_from(IPAddress).where(fk_addr == target_id).where(~survivor)
        )
        or 0
    )
    res = await db.execute(
        update(IPAddress)
        .where(fk_addr == target_id)
        .where(survivor)
        .values({own_fk: None, "user_modified_at": None})
        .execution_options(synchronize_session=False)
    )
    summary.addresses_released = res.rowcount or 0

    # 2. Subnets.
    opts = {"include_deleted": True}
    subnets = (
        (
            await db.execute(
                select(Subnet).where(getattr(Subnet, own_fk) == target_id).execution_options(**opts)
            )
        )
        .scalars()
        .all()
    )
    removed_subnets: list[Subnet] = []
    for sn in subnets:
        keep = (
            sn.deleted_at is not None
            or bool(sn.tags)
            or bool(sn.custom_fields)
            or await subnet_has_surviving_addresses(db, sn.id, own_fk)
            or bool(
                await db.scalar(
                    select(func.count())
                    .select_from(IPAddress)
                    .where(IPAddress.subnet_id == sn.id)
                    .where(registry_ref)
                )
            )
            or bool(
                await db.scalar(
                    select(
                        exists().where(OTZone.subnet_id == sn.id)
                        | exists().where(ERLBinding.subnet_id == sn.id)
                        | exists().where(AddressSet.subnet_id == sn.id)
                    )
                )
            )
            or bool(
                await db.scalar(
                    select(func.count())
                    .select_from(DHCPScope)
                    .where(DHCPScope.subnet_id == sn.id)
                    .execution_options(**opts)
                )
            )
            or bool(
                await db.scalar(
                    select(func.count())
                    .select_from(SubnetDomain)
                    .where(SubnetDomain.subnet_id == sn.id)
                )
            )
        )
        if keep:
            setattr(sn, own_fk, None)
            summary.subnets_released += 1
        else:
            removed_subnets.append(sn)
    removed_subnet_ids = {sn.id for sn in removed_subnets}

    # 3. Blocks, to a fixpoint: a block holding anything that stays stays.
    blocks = (
        (
            await db.execute(
                select(IPBlock)
                .where(getattr(IPBlock, own_fk) == target_id)
                .execution_options(**opts)
            )
        )
        .scalars()
        .all()
    )
    candidates = {
        b.id: b for b in blocks if b.deleted_at is None and not b.tags and not b.custom_fields
    }
    changed = True
    while changed:
        changed = False
        for bid in list(candidates):
            child_blocks = (
                await db.execute(
                    select(IPBlock.id)
                    .where(IPBlock.parent_block_id == bid)
                    .execution_options(**opts)
                )
            ).scalars()
            child_subnets = (
                await db.execute(
                    select(Subnet.id).where(Subnet.block_id == bid).execution_options(**opts)
                )
            ).scalars()
            if any(c not in candidates for c in child_blocks) or any(
                c not in removed_subnet_ids for c in child_subnets
            ):
                del candidates[bid]
                changed = True
    for b in blocks:
        if b.id not in candidates:
            setattr(b, own_fk, None)
            summary.blocks_released += 1

    # Removal: subnets, then blocks deepest-first, flushing between so
    # RESTRICT / self-referential cascades never see a half-ordered batch.
    await db.flush()
    for sn in removed_subnets:
        await db.delete(sn)
        summary.subnets_removed += 1
    await db.flush()
    for b in sorted(candidates.values(), key=lambda x: _prefixlen(str(x.network)), reverse=True):
        await db.delete(b)
        summary.blocks_removed += 1
        await db.flush()

    # The mirrored rows go without per-row audit (they are regenerable
    # provenance), so record what was kept and what was dropped.
    from app.models.audit import AuditLog  # noqa: PLC0415

    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action="update",
            resource_type="integration_mirror_release",
            resource_id=str(target_id),
            resource_display=target_name or INTEGRATION_OWNERSHIP[own_fk],
            changed_fields=["integration_owner"],
            new_value={"integration": INTEGRATION_OWNERSHIP[own_fk], **summary.as_dict()},
        )
    )
    return summary


def _prefixlen(network: str) -> int:
    try:
        return int(network.rsplit("/", 1)[1])
    except (IndexError, ValueError):
        return 0


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


__all__ = [
    "ACME_RECORD_TAG",
    "DNS_RECORD_OWNER_FKS",
    "INTEGRATION_OWNERSHIP",
    "INTEGRATION_OWNERSHIP_FKS",
    "address_taken",
    "dns_record_owned_elsewhere",
    "owned_by_other_integration",
    "ReleaseSummary",
    "owning_integration",
    "release_integration_rows",
    "subnet_has_surviving_addresses",
]
