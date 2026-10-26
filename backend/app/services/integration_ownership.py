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

import ipaddress
import uuid
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import Select, String, and_, cast, exists, func, not_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.audit import AuditLog
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

logger = structlog.get_logger(__name__)

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

# #2577 — the audit action of the row ``release_outside_space`` writes for each
# release, one per target per sync that released anything. The Integrations
# dashboard lists these as reconciler warnings.
RELEASE_AUDIT_ACTION = "integration.release_outside_space"

# #2577 — the sync error of a target whose IP space is in Trash. The sync
# stops before it fetches or writes anything, so it cannot rebuild blocks,
# subnets and addresses inside a space the operator deleted.
SPACE_IN_TRASH_ERROR = (
    "its IP space is in Trash: nothing was synced. Restore the space, or point "
    "this integration at another IP space (#2577)"
)


def ownership_resource_type(own_fk: str) -> str:
    """The audit ``resource_type`` of the target ``own_fk`` points at —
    ``kubernetes_cluster`` for ``kubernetes_cluster_id``, … — the same string
    each reconciler stamps on its own sync audit row."""
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    return own_fk.removesuffix("_id")


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


def address_registry_ref(address_id: Any) -> Any:
    """An operator registry row points at this address (#2334, #2577).

    OT devices, BACnet devices, E911 bindings and multicast memberships all
    reference ``ip_address`` with ``ON DELETE CASCADE``: deleting the address
    deletes the operator's registry row with it. So an address one of them
    points at is operator content, however purely mirrored it otherwise is.
    ``address_id`` is a column (correlated) or a value."""
    from app.models.bacnet import BACnetDevice  # noqa: PLC0415
    from app.models.e911 import ERLBinding  # noqa: PLC0415
    from app.models.multicast import MulticastMembership  # noqa: PLC0415
    from app.models.ot import OTDevice  # noqa: PLC0415

    return or_(
        exists().where(OTDevice.ip_address_id == address_id),
        exists().where(BACnetDevice.ip_address_id == address_id),
        exists().where(ERLBinding.ip_address_id == address_id),
        exists().where(MulticastMembership.ip_address_id == address_id),
    )


def address_operator_ref(address_id: Any) -> Any:
    """Anything operator-made hangs off this address: a registry row
    (:func:`address_registry_ref`), a DNS record or a DHCP static
    reservation. The one test both :func:`release_integration_rows` (target
    delete) and :func:`release_outside_space` (re-target) use to decide that
    an address must be un-claimed rather than deleted, so the two cannot
    drift."""
    from app.models.dhcp import DHCPStaticAssignment  # noqa: PLC0415
    from app.models.dns import DNSRecord  # noqa: PLC0415

    return or_(
        exists().where(DNSRecord.ip_address_id == address_id),
        exists().where(DHCPStaticAssignment.ip_address_id == address_id),
        address_registry_ref(address_id),
    )


def subnet_registry_ref(subnet_id: Any) -> Any:
    """An operator registry row hangs off this subnet with ``ON DELETE
    CASCADE``: an OT zone, an E911 binding or an address set (#2334, #2577)."""
    from app.models.address_set import AddressSet  # noqa: PLC0415
    from app.models.e911 import ERLBinding  # noqa: PLC0415
    from app.models.ot import OTZone  # noqa: PLC0415

    return or_(
        exists().where(OTZone.subnet_id == subnet_id),
        exists().where(ERLBinding.subnet_id == subnet_id),
        exists().where(AddressSet.subnet_id == subnet_id),
    )


def subnet_operator_ref(subnet_id: Any) -> Any:
    """:func:`subnet_registry_ref` plus a subnet-domain link: what makes a
    subnet operator content regardless of the addresses in it."""
    from app.models.ipam import SubnetDomain  # noqa: PLC0415

    return or_(
        subnet_registry_ref(subnet_id),
        exists().where(SubnetDomain.subnet_id == subnet_id),
    )


def _jsonb_nonempty(col: Any) -> Any:
    """SQL twin of ``bool(row.tags)`` / ``bool(row.custom_fields)``."""
    return and_(col.is_not(None), cast(col, String).not_in(("{}", "[]", "null")))


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
    from app.models.dhcp import DHCPScope  # noqa: PLC0415
    from app.models.ipam import IPBlock, Subnet, SubnetDomain  # noqa: PLC0415

    summary = ReleaseSummary()
    fk_addr = getattr(IPAddress, own_fk)

    # Operator registries whose FK to ip_address / subnet is ON DELETE CASCADE:
    # a row one of them points at is operator content even when purely mirrored.
    registry_ref = address_registry_ref(IPAddress.id)

    # 1. Addresses. A purely mirrored one is left for the FK cascade.
    survivor = or_(
        IPAddress.user_modified_at.is_not(None),
        *(getattr(IPAddress, fk).is_not(None) for fk in INTEGRATION_OWNERSHIP if fk != own_fk),
        address_operator_ref(IPAddress.id),
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
            or bool(await db.scalar(select(subnet_registry_ref(sn.id))))
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
# records). OPNsense alone had been fixed, by hand, in its own file. These
# helpers are the only way a reconciler loads ``IPAddress`` rows (and the
# ``Subnet`` rows it owns), so an eighth reconciler gets the scoping — and the
# release of whatever it owns outside its space — for free;
# ``tests/test_integration_space_scoping.py`` fails any reconciler query that
# bypasses them.


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


def ownership_target_model(own_fk: str) -> Any:
    """The integration target model ``own_fk`` points at (``DockerHost`` for
    ``docker_host_id``, …), read off the column's foreign key so a new
    integration is covered without a second list."""
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    import app.models  # noqa: F401, PLC0415  — registers every mapper
    from app.models.base import Base  # noqa: PLC0415

    (ref,) = IPAddress.__table__.c[own_fk].foreign_keys
    table = ref.column.table.name
    for mapper in Base.registry.mappers:
        if getattr(mapper.class_, "__tablename__", None) == table:
            return mapper.class_
    raise LookupError(f"no model for table {table!r}")  # pragma: no cover


@dataclass
class SpaceRelease:
    """What ``release_outside_space`` did with a target's rows that sat
    outside its IP space (#2577)."""

    addresses_deleted: int = 0
    addresses_unclaimed: int = 0
    subnets_deleted: int = 0
    subnets_unclaimed: int = 0
    blocks_deleted: int = 0
    blocks_unclaimed: int = 0

    @property
    def total(self) -> int:
        return (
            self.addresses_deleted
            + self.addresses_unclaimed
            + self.subnets_deleted
            + self.subnets_unclaimed
            + self.blocks_deleted
            + self.blocks_unclaimed
        )

    def add(self, other: SpaceRelease) -> None:
        self.addresses_deleted += other.addresses_deleted
        self.addresses_unclaimed += other.addresses_unclaimed
        self.subnets_deleted += other.subnets_deleted
        self.subnets_unclaimed += other.subnets_unclaimed
        self.blocks_deleted += other.blocks_deleted
        self.blocks_unclaimed += other.blocks_unclaimed

    def as_dict(self) -> dict[str, int]:
        """The counts, for a sync's audit row, log line and task result."""
        return {
            "addresses_deleted": self.addresses_deleted,
            "addresses_unclaimed": self.addresses_unclaimed,
            "subnets_deleted": self.subnets_deleted,
            "subnets_unclaimed": self.subnets_unclaimed,
            "blocks_deleted": self.blocks_deleted,
            "blocks_unclaimed": self.blocks_unclaimed,
        }

    def log_fields(self) -> dict[str, int]:
        """``as_dict`` with a ``released_`` prefix, for a structlog line."""
        return {f"released_{k}": v for k, v in self.as_dict().items()}

    def describe(self) -> str:
        parts = []
        for noun, deleted, unclaimed in (
            ("address row(s)", self.addresses_deleted, self.addresses_unclaimed),
            ("subnet(s)", self.subnets_deleted, self.subnets_unclaimed),
            ("block(s)", self.blocks_deleted, self.blocks_unclaimed),
        ):
            if deleted or unclaimed:
                parts.append(
                    f"{deleted + unclaimed} {noun} ({deleted} deleted as pure mirror rows, "
                    f"{unclaimed} un-claimed and left in place)"
                )
        return (
            "released what this target owned outside its IP space: "
            + "; ".join(parts)
            + ". Nothing was moved between spaces (#2577)"
        )


def _operator_touched(resource_type: str, id_col: Any) -> Any:
    """An audit row written by a user (not the system) about this row: an
    IPAM create, an edit, a profile scan — any of them means a person has
    had a hand in it, so it is not a pure mirror row."""
    return exists().where(
        AuditLog.resource_type == resource_type,
        AuditLog.resource_id == cast(id_col, String),
        AuditLog.user_id.is_not(None),
    )


def _no_other_owner(model: Any, own_fk: str) -> list[Any]:
    return [
        getattr(model, fk).is_(None)
        for fk in INTEGRATION_OWNERSHIP
        if fk != own_fk and hasattr(model, fk)
    ]


async def release_outside_space(
    db: AsyncSession,
    own_fk: str,
    target_id: Any,
    space_ids: Any | Iterable[Any],
    *,
    summary: Any = None,
    warnings: list[str] | None = None,
) -> SpaceRelease:
    """Release every ``IPAddress`` / ``Subnet`` / ``IPBlock`` the target owns
    outside ``space_ids`` (#2577).

    Such rows are what a change of the target's ``ipam_space_id`` leaves
    behind in the old space, or an operator row a pre-#2577 build claimed
    and never managed to move. (A row a pre-#2577 build DID move sits in the
    target's space, so it is not outside and is not touched here; the audit
    report finds those.) Each is released, never moved across spaces:

    * a **pure mirror row** — created by the integration and never touched
      by a person — is deleted; the integration re-creates its rows in its
      current space;
    * anything else is **un-claimed in place**: the ownership FK is cleared,
      the row stays in its space, ``user_modified_at`` stays as it is.

    "Pure mirror" needs positive evidence on every count and fails towards
    un-claiming: no audit row written by a user (create, edit, anything), no
    other integration's FK, and created after the target itself (an
    integration cannot have created a row older than itself). An address
    also needs no ``user_modified_at``, no ``created_by_user_id``, no import
    provenance, and nothing operator-made hanging off it — no DNS record, DHCP
    reservation, OT / BACnet device, E911 binding or multicast membership
    (:func:`address_operator_ref`, the same test a target delete uses). A
    subnet or block must hold nothing — no addresses, DHCP scopes, subnets or
    child blocks — and carry no tags or custom fields to be deleted; a subnet
    also no address set, OT zone, E911 binding or domain link
    (:func:`subnet_operator_ref`).

    An empty space list releases nothing: a target always has a space, and
    treating "unknown" as "everything is outside" would release it all.

    A release is reported three ways, so it is never silent: a system audit
    row (``RELEASE_AUDIT_ACTION``, with the counts) that the Integrations
    dashboard lists as a warning; and, when the sync's ``summary`` is passed,
    its counts folded into the summary — ``summary.released`` (a
    ``SpaceRelease``), the summary's own ``addresses_deleted`` /
    ``subnets_deleted`` / ``blocks_deleted`` where it has them, so the sync's
    audit row, log line and task result count what was deleted — and the
    description appended to ``summary.warnings``. ``warnings`` alone (no
    summary) only appends the description.
    """
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    from app.models.dhcp import DHCPScope  # noqa: PLC0415

    out = SpaceRelease()
    ids = _space_id_list(space_ids)
    if not ids:
        return out
    target_model = ownership_target_model(own_fk)
    target_created = (
        select(target_model.created_at).where(target_model.id == target_id).scalar_subquery()
    )

    # Addresses first, so a subnet left empty by them can go too.
    addr_fk = getattr(IPAddress, own_fk)
    addr_pure = and_(
        IPAddress.user_modified_at.is_(None),
        IPAddress.created_by_user_id.is_(None),
        IPAddress.import_source.is_(None),
        IPAddress.static_assignment_id.is_(None),
        IPAddress.created_at >= target_created,
        not_(_operator_touched("ip_address", IPAddress.id)),
        # An operator registry row, DNS record or reservation on it (#2334's
        # test, shared): deleting the address would cascade into them.
        not_(address_operator_ref(IPAddress.id)),
        *_no_other_owner(IPAddress, own_fk),
    )
    rows = (
        await db.execute(
            select(IPAddress, addr_pure.label("pure"))
            .join(Subnet, IPAddress.subnet_id == Subnet.id)
            .where(addr_fk == target_id, Subnet.space_id.not_in(ids))
        )
    ).all()
    for row, pure in rows:
        if pure:
            await db.delete(row)
            out.addresses_deleted += 1
        else:
            setattr(row, own_fk, None)
            out.addresses_unclaimed += 1
    if rows:
        await db.flush()

    if hasattr(Subnet, own_fk):
        subnet_pure = and_(
            Subnet.created_at >= target_created,
            not_(_operator_touched("subnet", Subnet.id)),
            not_(exists().where(IPAddress.subnet_id == Subnet.id)),
            not_(exists().where(DHCPScope.subnet_id == Subnet.id)),
            not_(subnet_operator_ref(Subnet.id)),
            not_(_jsonb_nonempty(Subnet.tags)),
            not_(_jsonb_nonempty(Subnet.custom_fields)),
            *_no_other_owner(Subnet, own_fk),
        )
        subnets = (
            await db.execute(
                select(Subnet, subnet_pure.label("pure")).where(
                    getattr(Subnet, own_fk) == target_id, Subnet.space_id.not_in(ids)
                )
            )
        ).all()
        for subnet, pure in subnets:
            if pure:
                await db.delete(subnet)
                out.subnets_deleted += 1
            else:
                setattr(subnet, own_fk, None)
                out.subnets_unclaimed += 1
        if subnets:
            await db.flush()

    if hasattr(IPBlock, own_fk):
        child = aliased(IPBlock)
        block_pure = and_(
            IPBlock.created_at >= target_created,
            not_(_operator_touched("ip_block", IPBlock.id)),
            not_(exists().where(Subnet.block_id == IPBlock.id)),
            not_(exists().where(child.parent_block_id == IPBlock.id)),
            not_(_jsonb_nonempty(IPBlock.tags)),
            not_(_jsonb_nonempty(IPBlock.custom_fields)),
            *_no_other_owner(IPBlock, own_fk),
        )
        blocks = (
            await db.execute(
                select(IPBlock, block_pure.label("pure")).where(
                    getattr(IPBlock, own_fk) == target_id, IPBlock.space_id.not_in(ids)
                )
            )
        ).all()
        for block, pure in blocks:
            if pure:
                await db.delete(block)
                out.blocks_deleted += 1
            else:
                setattr(block, own_fk, None)
                out.blocks_unclaimed += 1
        if blocks:
            await db.flush()

    if out.total:
        await _report_release(db, own_fk, target_id, ids, out)
        if summary is not None:
            fold_release(summary, out)
        elif warnings is not None:
            warnings.append(out.describe())
    return out


def fold_release(summary: Any, out: SpaceRelease) -> None:
    """Fold one release into a reconciler's sync summary (#2577): its
    ``released`` total, its own deleted counters where it has them, and its
    warnings. Rows a release deletes are rows the sync deleted — a sync that
    released 11 mirror rows must not report 0 deleted."""
    released = getattr(summary, "released", None)
    if isinstance(released, SpaceRelease):
        released.add(out)
    for attr, n in (
        ("addresses_deleted", out.addresses_deleted),
        ("subnets_deleted", out.subnets_deleted),
        ("blocks_deleted", out.blocks_deleted),
    ):
        if n and isinstance(getattr(summary, attr, None), int):
            setattr(summary, attr, getattr(summary, attr) + n)
    summary_warnings = getattr(summary, "warnings", None)
    if isinstance(summary_warnings, list):
        summary_warnings.append(out.describe())


async def _report_release(
    db: AsyncSession, own_fk: str, target_id: Any, space_ids: list[Any], out: SpaceRelease
) -> None:
    """The audit row of one release: a system row on the target, with the
    counts and the space(s) the target was bound to, that the Integrations
    dashboard lists among its reconciler warnings."""
    target_model = ownership_target_model(own_fk)
    name = (
        await db.execute(select(target_model.name).where(target_model.id == target_id))
    ).scalar_one_or_none()
    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action=RELEASE_AUDIT_ACTION,
            resource_type=ownership_resource_type(own_fk),
            resource_id=str(target_id),
            resource_display=str(name) if name is not None else str(target_id),
            result="success",
            new_value={
                "released": out.as_dict(),
                "space_ids": [str(i) for i in space_ids],
                "message": out.describe(),
            },
        )
    )


async def target_space_in_trash(db: AsyncSession, space_ids: Any | Iterable[Any]) -> bool:
    """Whether any of a target's IP spaces is soft-deleted (in Trash), or gone.

    A reconciler checks this before it fetches or writes anything: a space in
    Trash hides its rows from every ORM read, so a sync left running would
    rebuild its block, subnets and addresses as live rows inside the trashed
    space (#2577). Reads with ``include_deleted`` — the plain read would see a
    trashed space as missing."""
    ids = [i for i in _space_id_list(space_ids) if i is not None]
    if not ids:
        return False
    rows = (
        await db.execute(
            select(IPSpace.id, IPSpace.deleted_at)
            .where(IPSpace.id.in_(ids))
            .execution_options(include_deleted=True)
        )
    ).all()
    found = {r[0] for r in rows}
    return any(r[1] is not None for r in rows) or any(i not in found for i in ids)


async def refuse_sync_into_trashed_space(
    db: AsyncSession, target: Any, summary: Any, space_ids: Any | Iterable[Any] = None
) -> bool:
    """Stop a sync whose target's IP space is in Trash (#2577).

    Sets ``SPACE_IN_TRASH_ERROR`` as the sync error on the summary and the
    target, stamps ``last_synced_at`` and commits — nothing else is written.
    Returns True when the sync must stop. ``space_ids`` defaults to the
    target's ``ipam_space_id``."""
    if space_ids is None:
        space_ids = target.ipam_space_id
    if not await target_space_in_trash(db, space_ids):
        return False
    summary.error = SPACE_IN_TRASH_ERROR
    target.last_sync_error = SPACE_IN_TRASH_ERROR
    target.last_synced_at = datetime.now(UTC)
    await db.commit()
    logger.warning(
        "integration_sync_space_in_trash",
        target_type=type(target).__name__,
        target=str(target.id),
        space_ids=[str(i) for i in _space_id_list(space_ids)],
    )
    return True


async def owned_addresses_in_space(
    db: AsyncSession,
    own_fk: str,
    target_id: Any,
    space_ids: Any | Iterable[Any],
    *,
    summary: Any = None,
    warnings: list[str] | None = None,
) -> list[IPAddress]:
    """The rows the target owns (``own_fk == target_id``) inside ``space_ids``.

    This is a reconciler's "current" set: the rows it may update, move,
    dedupe and absence-delete. Whatever the target owns OUTSIDE its space —
    left behind when the target's space was changed, or an operator row a
    pre-#2577 build claimed in its home space — is released first by
    ``release_outside_space`` (pure mirror rows deleted, everything else
    un-claimed in place, nothing moved across spaces), so every reconciler
    gets the same treatment.

    Pass the sync ``summary`` to have what was released counted and reported
    on it (see ``release_outside_space``)."""
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    await release_outside_space(
        db, own_fk, target_id, space_ids, summary=summary, warnings=warnings
    )
    owned = getattr(IPAddress, own_fk) == target_id
    stmt = scope_addresses_to_space(select(IPAddress), space_ids).where(owned)
    return list((await db.execute(stmt)).scalars().all())


async def owned_subnets_in_space(
    db: AsyncSession,
    own_fk: str,
    target_id: Any,
    space_ids: Any | Iterable[Any],
    *,
    summary: Any = None,
    warnings: list[str] | None = None,
) -> list[Subnet]:
    """The subnets the target owns inside ``space_ids`` — a reconciler's
    current subnet set. Owned subnets (and addresses and blocks) outside the
    space are released first, exactly as ``owned_addresses_in_space`` does,
    so a subnet left in a target's old space is never updated, re-parented
    under a block of the new space, or cascade-deleted with what it holds."""
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    await release_outside_space(
        db, own_fk, target_id, space_ids, summary=summary, warnings=warnings
    )
    stmt = select(Subnet).where(
        getattr(Subnet, own_fk) == target_id, Subnet.space_id.in_(_space_id_list(space_ids))
    )
    return list((await db.execute(stmt)).scalars().all())


def move_stays_in_space(current_subnet_id: Any, space_subnet_ids: Collection[Any]) -> bool:
    """Whether a reconciler may re-parent a row it owns, given the ids of
    every subnet in its target space. A row whose CURRENT subnet is outside
    that set lives in another space and is never moved: re-parenting it is
    exactly how #2577 made operator rows vanish from their own space.
    ``owned_addresses_in_space`` already keeps such rows out of a
    reconciler's current set; this is the guard at the write itself."""
    return current_subnet_id in space_subnet_ids


# ── Kept subnets and address placement (#2601, #2790) ─────────────────────
#
# A mirror's subnet is kept with no owner when its network leaves the desired
# set while an address in it survives (#1558), and when its target is deleted
# while it holds operator content (#2287). A sync that wants that CIDR again
# must reuse the kept subnet rather than put a second one with the same CIDR
# beside it, and its address pass must not choose between two rows at one
# CIDR by the order the database returned them in. The mirrors that create
# their own subnets (Docker, Kubernetes, UniFi, Tailscale, NetBird) share
# these two helpers.


async def unowned_subnets_at(
    db: AsyncSession, space_id: Any, networks: Iterable[str]
) -> dict[str, Subnet]:
    """The subnet that no integration owns at exactly each of ``networks`` in
    ``space_id``, keyed by the network as given (#2601, #2790).

    A mirror reuses such a subnet as it stands instead of creating a second
    one at that CIDR: it neither claims nor renames it, as the Proxmox
    (#177), Cloud and OPNsense reconcilers treat an operator's subnet.
    Nothing on the row says whether #1558 or #2287 handed it back or an
    operator made it, and claiming it would put an operator's subnet under
    the mirror's lifecycle (renamed on sync, deleted with its network).
    A network that does not parse is skipped. Where two un-owned subnets sit
    at one CIDR, the one with the lowest id is returned."""
    wanted: dict[str, list[str]] = {}
    for given in networks:
        try:
            canonical = str(ipaddress.ip_network(given, strict=False))
        except (ValueError, TypeError):
            continue
        wanted.setdefault(canonical, []).append(given)
    if not wanted:
        return {}
    res = await db.execute(
        select(Subnet).where(
            Subnet.space_id == space_id,
            Subnet.network.in_(list(wanted)),
            *(getattr(Subnet, fk).is_(None) for fk in INTEGRATION_OWNERSHIP),
        )
    )
    out: dict[str, Subnet] = {}
    for subnet in sorted(res.scalars().all(), key=lambda s: str(s.id)):
        for given in wanted.get(str(subnet.network), []):
            out.setdefault(given, subnet)
    return out


def subnet_for_address(
    subnets: Iterable[Subnet],
    address: str,
    own_fk: str,
    target_id: Any,
    *,
    held: IPAddress | None = None,
) -> Subnet | None:
    """The subnet, among ``subnets`` (the target space's), that a mirror puts
    or keeps its row for ``address`` in (#2601, #2790).

    ``held`` is the target's current row at ``address``, if any. When an
    operator has edited it (``user_modified_at``), it stays in its subnet,
    as its status, hostname and description do. Otherwise the target's own
    subnets come first, then the longest prefix. On a tie (two rows at one
    CIDR) an un-owned subnet beats one another target or integration owns,
    then the lowest id wins, so the choice never follows the order the
    database returned the rows in."""
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    keep = held.subnet_id if held is not None and held.user_modified_at is not None else None
    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(address)
    except ValueError:
        addr = None
    best: Subnet | None = None
    best_key: tuple[bool, int, bool, str] | None = None
    for subnet in subnets:
        if keep is not None and subnet.id == keep:
            return subnet
        if addr is None:
            continue
        try:
            net = ipaddress.ip_network(str(subnet.network), strict=False)
        except (ValueError, TypeError):
            continue
        if addr not in net:
            continue
        own = target_id is not None and getattr(subnet, own_fk) == target_id
        owned_elsewhere = not own and owning_integration(subnet) is not None
        key = (not own, -net.prefixlen, owned_elsewhere, str(subnet.id))
        if best_key is None or key < best_key:
            best, best_key = subnet, key
    return best


__all__ = [
    "ACME_RECORD_TAG",
    "RELEASE_AUDIT_ACTION",
    "SPACE_IN_TRASH_ERROR",
    "fold_release",
    "ownership_resource_type",
    "refuse_sync_into_trashed_space",
    "target_space_in_trash",
    "DNS_RECORD_OWNER_FKS",
    "INTEGRATION_OWNERSHIP",
    "INTEGRATION_OWNERSHIP_FKS",
    "address_operator_ref",
    "address_registry_ref",
    "address_taken",
    "addresses_in_space",
    "dns_record_owned_elsewhere",
    "move_stays_in_space",
    "owned_addresses_in_space",
    "owned_subnets_in_space",
    "ownership_target_model",
    "release_outside_space",
    "SpaceRelease",
    "owned_by_other_integration",
    "ReleaseSummary",
    "owning_integration",
    "release_integration_rows",
    "scope_addresses_to_space",
    "subnet_for_address",
    "subnet_has_surviving_addresses",
    "subnet_operator_ref",
    "subnet_registry_ref",
    "unowned_subnets_at",
]
