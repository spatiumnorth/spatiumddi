"""Shared soft-delete + restore primitives.

Soft-deletable models live in IPAM / DNS / DHCP — see ``TYPE_TO_MODEL``.
The default ORM query filter (``app.db._filter_soft_deleted``) hides any row
with a non-null ``deleted_at`` from every SELECT unless the caller opts in
via ``execution_options(include_deleted=True)``.

Cascading: when soft-deleting a parent (IPSpace / IPBlock / Subnet / DNSZone /
DHCPScope) we walk every descendant in scope and stamp them with the same
``deleted_at`` + ``deletion_batch_id``. ``DNSRecord`` cascades from a parent
DNSZone, stamped set-based rather than walked (``BulkChild``, #1231); ``DHCPPool`` + ``DHCPStaticAssignment`` cascade from a parent
DHCPScope (#617 — a scope used to be treated as a leaf, which left its pools
and reservations as live, un-stamped rows pointing at a hidden parent: still
enforcing group-wide MAC uniqueness and still answering ``GET
/scopes/{id}/statics`` for a scope the operator could no longer see).

Root vs child: ``SOFT_DELETE_RESOURCE_TYPES`` is the set of types the trash UI
*browses* and can restore/purge individually. ``TYPE_TO_MODEL`` is the wider
set that :func:`restore_batch` sweeps — it also carries the cascade-only
children, which are restored with their parent's batch but are never addressed
on their own.

A standalone soft-delete still gets a fresh batch UUID, which keeps the
restore-by-batch lookup uniform on the wire.

This module is import-safe from the ORM layer — it only imports models, no
API routers or tasks.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.dhcp import DHCPPool, DHCPScope, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet

# Types the trash UI browses, and that ``restore_row`` /
# ``permanent_delete_from_trash`` accept as an addressable target. Cascade-only
# children (DHCPPool / DHCPStaticAssignment) are deliberately NOT here: they
# ride their parent's batch and would otherwise spam the trash list with one
# row per reservation.
SOFT_DELETE_RESOURCE_TYPES: tuple[str, ...] = (
    "ip_space",
    "ip_block",
    "subnet",
    "dns_zone",
    "dns_record",
    "dhcp_scope",
)


# Map URL-friendly type strings to the ORM class. Used by the trash router
# to look up rows generically. Kept here so the canonical names live in one
# place — anywhere outside this module that needs the mapping should import
# it rather than hand-rolling its own copy.
#
# Superset of SOFT_DELETE_RESOURCE_TYPES: this is what ``restore_batch`` sweeps,
# so it must carry the cascade-only children too or a restore would bring the
# scope back without its pools and reservations.
TYPE_TO_MODEL: dict[str, type] = {
    "ip_space": IPSpace,
    "ip_block": IPBlock,
    "subnet": Subnet,
    "dns_zone": DNSZone,
    "dns_record": DNSRecord,
    "dhcp_scope": DHCPScope,
    # Cascade-only children — restored with the batch, never addressed alone.
    "dhcp_pool": DHCPPool,
    "dhcp_static_assignment": DHCPStaticAssignment,
}


@dataclass
class SoftDeleteRow:
    """One soft-deleted row, prepared but not yet stamped with deleted_at.

    Pre-stamping snapshot used for blast-radius preview + audit trail. The
    actual ``deleted_at`` / ``deleted_by_user_id`` / ``deletion_batch_id``
    write happens in :func:`apply_soft_delete`.
    """

    obj: Any
    resource_type: str
    display: str


@dataclass
class BulkChild:
    """Children stamped by one set-based UPDATE instead of being loaded (#1231).

    A zone's records. Loading each one, stamping it through the ORM and
    writing one audit row per record made the default zone delete a single
    transaction proportional to the zone, holding the global audit lock for
    every hash: on a 250k-record zone, minutes. The records are stamped with
    one statement instead, and counted on the parent's own audit row.
    """

    parent: Any
    model: type
    fk_column: str
    resource_type: str
    count: int


@dataclass
class SoftDeleteBatch:
    batch_id: uuid.UUID
    rows: list[SoftDeleteRow] = field(default_factory=list)
    bulk: list[BulkChild] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        """Rows per resource type, set-based children included."""
        out: dict[str, int] = {}
        for row in self.rows:
            out[row.resource_type] = out.get(row.resource_type, 0) + 1
        for child in self.bulk:
            out[child.resource_type] = out.get(child.resource_type, 0) + child.count
        return out

    def audit_old_value(self, row: SoftDeleteRow) -> dict[str, Any]:
        """The ``old_value`` for ``row``'s soft-delete audit entry.

        A parent whose children were stamped set-based carries their count,
        since they get no audit row of their own (#1231).
        """
        value: dict[str, Any] = {"deletion_batch_id": str(self.batch_id)}
        cascaded = {
            child.resource_type: child.count
            for child in self.bulk
            if child.parent is row.obj and child.count
        }
        if cascaded:
            value["cascaded"] = cascaded
        return value


def _row_display(obj: Any) -> str:
    """Best-effort one-line label for audit + UI."""

    if isinstance(obj, IPSpace):
        return obj.name
    if isinstance(obj, (IPBlock, Subnet)):
        return f"{obj.network}{(' ' + obj.name) if getattr(obj, 'name', '') else ''}".strip()
    if isinstance(obj, DNSZone):
        return obj.name
    if isinstance(obj, DNSRecord):
        return f"{obj.fqdn} {obj.record_type}"
    if isinstance(obj, DHCPScope):
        return obj.name or str(obj.id)
    if isinstance(obj, DHCPPool):
        return f"{obj.pool_type} pool {obj.start_ip}-{obj.end_ip}"
    if isinstance(obj, DHCPStaticAssignment):
        return f"{obj.mac_address} → {obj.ip_address}"
    return str(getattr(obj, "id", obj))


def _resource_type(obj: Any) -> str:
    if isinstance(obj, IPSpace):
        return "ip_space"
    if isinstance(obj, IPBlock):
        return "ip_block"
    if isinstance(obj, Subnet):
        return "subnet"
    if isinstance(obj, DNSZone):
        return "dns_zone"
    if isinstance(obj, DNSRecord):
        return "dns_record"
    if isinstance(obj, DHCPScope):
        return "dhcp_scope"
    if isinstance(obj, DHCPPool):
        return "dhcp_pool"
    if isinstance(obj, DHCPStaticAssignment):
        return "dhcp_static_assignment"
    raise ValueError(f"Not a soft-deletable model: {type(obj).__name__}")


async def _collect_descendants(db: AsyncSession, root: Any) -> list[Any]:
    """Walk descendants of ``root`` that should cascade-soft-delete.

    Order in the returned list is parent-first (root last) so the caller
    can stamp them in any order; restore reverses to root-first if it
    matters. Recursion is bounded by the tree depth, which in practice
    stays under a handful of levels.
    """

    out: list[Any] = []
    if isinstance(root, IPSpace):
        # All blocks + subnets in the space.
        block_res = await db.execute(select(IPBlock).where(IPBlock.space_id == root.id))
        for block in block_res.scalars().all():
            out.extend(await _collect_descendants(db, block))
            out.append(block)
        subnet_res = await db.execute(select(Subnet).where(Subnet.space_id == root.id))
        for subnet in subnet_res.scalars().all():
            # Skip subnets already absorbed via their parent block above
            if any(getattr(x, "id", None) == subnet.id for x in out):
                continue
            out.extend(await _collect_descendants(db, subnet))
            out.append(subnet)
    elif isinstance(root, IPBlock):
        child_res = await db.execute(select(IPBlock).where(IPBlock.parent_block_id == root.id))
        for child in child_res.scalars().all():
            out.extend(await _collect_descendants(db, child))
            out.append(child)
        subnet_res = await db.execute(select(Subnet).where(Subnet.block_id == root.id))
        for subnet in subnet_res.scalars().all():
            out.extend(await _collect_descendants(db, subnet))
            out.append(subnet)
    elif isinstance(root, Subnet):
        scope_res = await db.execute(select(DHCPScope).where(DHCPScope.subnet_id == root.id))
        for scope in scope_res.scalars().all():
            out.extend(await _collect_descendants(db, scope))
            out.append(scope)
    elif isinstance(root, DHCPScope):
        # A scope's pools + reservations are cascade children, not independent
        # rows: the FK is NOT NULL / ON DELETE CASCADE, uniqueness is keyed on
        # the scope, and Kea renders reservations nested inside the scope's
        # subnet4 stanza. They must ride the same batch so a restore brings the
        # scope back whole (#617).
        pool_res = await db.execute(select(DHCPPool).where(DHCPPool.scope_id == root.id))
        out.extend(pool_res.scalars().all())
        static_res = await db.execute(
            select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == root.id)
        )
        out.extend(static_res.scalars().all())
    # A DNSZone's records are not loaded here: they are stamped set-based by
    # ``apply_soft_delete`` (see ``BulkChild`` and ``_attach_bulk``).
    return out


async def _attach_bulk(db: AsyncSession, batch: SoftDeleteBatch, objs: list[Any]) -> None:
    """Register the set-based children of every zone among ``objs`` (#1231)."""
    for obj in objs:
        if isinstance(obj, DNSZone):
            count = (
                await db.execute(
                    select(func.count())
                    .select_from(DNSRecord)
                    .where(DNSRecord.zone_id == obj.id, DNSRecord.deleted_at.is_(None))
                )
            ).scalar_one()
            batch.bulk.append(
                BulkChild(
                    parent=obj,
                    model=DNSRecord,
                    fk_column="zone_id",
                    resource_type="dns_record",
                    count=int(count or 0),
                )
            )


async def collect_soft_delete_batch(db: AsyncSession, root: Any) -> SoftDeleteBatch:
    """Build a fresh batch covering ``root`` + every cascade descendant."""

    batch = SoftDeleteBatch(batch_id=uuid.uuid4())
    await add_to_batch(db, batch, root)
    return batch


async def add_to_batch(db: AsyncSession, batch: SoftDeleteBatch, root: Any) -> None:
    """Append ``root`` and its cascade descendants to an existing batch.

    For a row that must ride ANOTHER root's deletion: a subnet's auto-created
    reverse zone goes into the subnet's batch (spatiumddi#1066) so the trash
    shows one deletion and one restore brings both back, records included.
    """

    objs = [*await _collect_descendants(db, root), root]
    for obj in objs:
        batch.rows.append(
            SoftDeleteRow(obj=obj, resource_type=_resource_type(obj), display=_row_display(obj))
        )
    await _attach_bulk(db, batch, objs)


async def apply_soft_delete(
    db: AsyncSession, batch: SoftDeleteBatch, user_id: uuid.UUID | None
) -> datetime:
    """Stamp every row in the batch. Caller is responsible for the audit log + commit.

    Set-based children are stamped with one UPDATE per parent. Only rows
    still live are touched, so a record trashed earlier keeps its own batch
    and comes back with that one, not this.
    """

    now = datetime.now(UTC)
    for row in batch.rows:
        row.obj.deleted_at = now
        row.obj.deleted_by_user_id = user_id
        row.obj.deletion_batch_id = batch.batch_id
    for child in batch.bulk:
        fk = getattr(child.model, child.fk_column)
        # "evaluate", not False: it walks only the identity map, never the
        # matched rows, and keeps any record already loaded in this session
        # from reading as live after the stamp.
        result = await db.execute(
            update(child.model)
            .where(fk == child.parent.id, child.model.deleted_at.is_(None))
            .values(
                deleted_at=now,
                deleted_by_user_id=user_id,
                deletion_batch_id=batch.batch_id,
            )
            .execution_options(synchronize_session="evaluate")
        )
        # The rows actually stamped, not the count taken at collect time: a
        # record committed in between rides this batch and must be counted
        # on the parent's audit row.
        if result.rowcount is not None and result.rowcount >= 0:
            child.count = int(result.rowcount)
    return now


async def batch_resource_types(db: AsyncSession, batch_id: uuid.UUID) -> set[str]:
    """Which resource types a deletion batch holds.

    Lets a caller tell a FLAT batch of independent siblings (a #963 bulk
    record delete — every row a ``dns_record``) from a CASCADE batch (a zone
    and its records, a scope and its pools), which is the difference between
    a partial restore being safe and it leaving a dangling child.
    """
    types: set[str] = set()
    for resource_type, model in TYPE_TO_MODEL.items():
        stmt: Any = (
            select(model.id)
            .where(model.deletion_batch_id == batch_id)
            .limit(1)
            .execution_options(include_deleted=True)
        )
        if (await db.execute(stmt)).first() is not None:
            types.add(resource_type)
    return types


@dataclass
class RestoreResult:
    """What :func:`restore_batch` did.

    ``restored`` are the rows un-stamped through the ORM. A restored zone's
    records are not among them: they are un-stamped by one UPDATE per zone
    and counted in ``bulk`` under the zone's id (#1389), mirroring how the
    delete stamped them (#1231).
    """

    restored: list[Any] = field(default_factory=list)
    conflicts: list[dict[str, str]] = field(default_factory=list)
    bulk: dict[uuid.UUID, dict[str, int]] = field(default_factory=dict)

    @property
    def total(self) -> int:
        """Every row restored, set-based children included."""
        return len(self.restored) + sum(n for c in self.bulk.values() for n in c.values())

    def audit_new_value(self, obj: Any, batch_id: uuid.UUID) -> dict[str, Any]:
        """The ``new_value`` for ``obj``'s restore audit entry.

        A parent whose children were restored set-based carries their count,
        since they get no audit row of their own.
        """
        value: dict[str, Any] = {"deletion_batch_id": str(batch_id)}
        children = self.bulk.get(getattr(obj, "id", None))  # type: ignore[arg-type]
        if children:
            value["restored"] = dict(children)
        return value


async def _record_conflicts(db: AsyncSession, batch_id: uuid.UUID) -> dict[uuid.UUID, str]:
    """The batch's records that a live record already duplicates, in one query.

    The set-based form of ``default_conflict_check``'s record rule (#1389):
    a per-record ``SELECT`` made restoring a 250k-record zone 250k queries.
    Identity is the zone, name, type and value, plus the view: under
    split-horizon the same record in two views is two records, not a clash.
    Returns ``{record id: label}``.
    """
    live = aliased(DNSRecord)
    stmt: Any = (
        select(DNSRecord.id, DNSRecord.fqdn, DNSRecord.record_type)
        .where(
            DNSRecord.deletion_batch_id == batch_id,
            select(live.id)
            .where(
                live.deleted_at.is_(None),
                live.zone_id == DNSRecord.zone_id,
                live.name == DNSRecord.name,
                live.record_type == DNSRecord.record_type,
                live.value == DNSRecord.value,
                live.view_id.is_not_distinct_from(DNSRecord.view_id),
                live.id != DNSRecord.id,
            )
            .exists(),
        )
        .execution_options(include_deleted=True)
    )
    return {
        row_id: f"{fqdn} {record_type}"
        for row_id, fqdn, record_type in (await db.execute(stmt)).tuples()
    }


async def restore_batch(
    db: AsyncSession,
    batch_id: uuid.UUID,
    *,
    conflict_check: Callable[[Any], Awaitable[str | None]] | None = None,
    skip_conflicts: bool = False,
) -> RestoreResult:
    """Restore every row sharing ``batch_id``.

    By default a non-empty ``conflicts`` means NOTHING was restored and the
    caller should 409 with the list — right for a cascade batch (a zone with a
    hole is worse than a refusal). With ``skip_conflicts`` the conflicting rows
    are left in the trash and every other row is restored — the shape a bulk
    record delete (#963) needs, where the rows are independent siblings and one
    hand-made duplicate must not pin the other N in the trash forever.

    Records are checked set-based by ``_record_conflicts`` whenever
    ``conflict_check`` is given, not by ``conflict_check`` itself, and the
    records of a zone restored in the same batch are un-stamped by one UPDATE
    per zone rather than loaded (#1389). Records whose zone is not in the batch
    (a #963 bulk record delete) are still loaded: the caller re-pushes them to
    agentless providers. Every other type keeps the per-row path, where the
    conflict rules are richer and the batches small.
    """

    result = RestoreResult()
    record_conflicts: dict[uuid.UUID, str] = {}
    if conflict_check is not None:
        record_conflicts = await _record_conflicts(db, batch_id)
        result.conflicts.extend(
            {
                "type": "dns_record",
                "id": str(rid),
                "display": label,
                "reason": "An identical record already exists in zone",
            }
            for rid, label in record_conflicts.items()
        )

    # Look up every row across all in-scope models. Each query opts into
    # include_deleted so it can see soft-deleted rows; without that the
    # global filter hides them.
    zone_ids: list[uuid.UUID] = []
    for resource_type, model in TYPE_TO_MODEL.items():
        if model is DNSRecord:
            continue  # below, once every zone in the batch is known
        stmt: Any = (
            select(model)
            .where(model.deletion_batch_id == batch_id)
            .execution_options(include_deleted=True)
        )
        res = await db.execute(stmt)
        for obj in res.scalars().all():
            if conflict_check is not None:
                reason = await conflict_check(obj)
                if reason:
                    result.conflicts.append(
                        {
                            "type": resource_type,
                            "id": str(obj.id),
                            "display": _row_display(obj),
                            "reason": reason,
                        }
                    )
                    continue
            result.restored.append(obj)
            if isinstance(obj, DNSZone):
                zone_ids.append(obj.id)

    # Records whose zone is restored with them are left to the UPDATE below;
    # the rest are loaded.
    rec_stmt: Any = select(DNSRecord).where(DNSRecord.deletion_batch_id == batch_id)
    if zone_ids:
        rec_stmt = rec_stmt.where(DNSRecord.zone_id.not_in(zone_ids))
    records = await db.execute(rec_stmt.execution_options(include_deleted=True))
    result.restored.extend(r for r in records.scalars().all() if r.id not in record_conflicts)

    if result.conflicts and not skip_conflicts:
        return RestoreResult(conflicts=result.conflicts)

    for zone_id in zone_ids:
        where = [DNSRecord.zone_id == zone_id, DNSRecord.deletion_batch_id == batch_id]
        if record_conflicts:
            where.append(DNSRecord.id.not_in(list(record_conflicts)))
        # "evaluate" walks only the identity map, so a record already loaded
        # in this session does not keep reading as trashed after the UPDATE.
        updated = await db.execute(
            update(DNSRecord)
            .where(*where)
            .values(deleted_at=None, deleted_by_user_id=None, deletion_batch_id=None)
            .execution_options(synchronize_session="evaluate")
        )
        if updated.rowcount:
            result.bulk[zone_id] = {"dns_record": int(updated.rowcount)}

    for obj in result.restored:
        obj.deleted_at = None
        obj.deleted_by_user_id = None
        obj.deletion_batch_id = None

    return result


async def default_conflict_check(db: AsyncSession, obj: Any) -> str | None:
    """Reject restore when a current (non-deleted) row would clash.

    The global filter hides soft-deleted rows, so we just look up by the
    same uniqueness key the live tables enforce. Any hit means a live
    row already occupies the slot; the operator must rename / delete it
    first.
    """

    if isinstance(obj, IPSpace):
        existing = (
            await db.execute(select(IPSpace).where(IPSpace.name == obj.name, IPSpace.id != obj.id))
        ).scalar_one_or_none()
        if existing is not None:
            return f"An active IP space named {obj.name!r} already exists"

    elif isinstance(obj, IPBlock):
        existing = (
            await db.execute(
                select(IPBlock).where(
                    IPBlock.space_id == obj.space_id,
                    IPBlock.network == obj.network,
                    IPBlock.id != obj.id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return f"An active block with CIDR {obj.network} already exists in this space"

    elif isinstance(obj, Subnet):
        existing = (
            await db.execute(
                select(Subnet).where(
                    Subnet.space_id == obj.space_id,
                    Subnet.network == obj.network,
                    Subnet.id != obj.id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return f"An active subnet with CIDR {obj.network} already exists in this space"

    elif isinstance(obj, DNSZone):
        existing = (
            await db.execute(
                select(DNSZone).where(
                    DNSZone.group_id == obj.group_id,
                    DNSZone.view_id == obj.view_id,
                    DNSZone.name == obj.name,
                    DNSZone.id != obj.id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return f"An active zone {obj.name!r} already exists in this group/view"

    # DNSRecord is checked set-based for the whole batch by
    # ``_record_conflicts`` (#1389), which ``restore_batch`` runs itself.

    elif isinstance(obj, DHCPScope):
        existing = (
            await db.execute(
                select(DHCPScope).where(
                    DHCPScope.group_id == obj.group_id,
                    DHCPScope.subnet_id == obj.subnet_id,
                    DHCPScope.id != obj.id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return "An active DHCP scope already exists for this group + subnet"

    elif isinstance(obj, DHCPStaticAssignment):
        # A reservation's MAC is unique across the whole group, not just the
        # scope (see ``_conflict_check`` on the create path). While the scope
        # sat in the trash, a live scope in the same group may have claimed
        # this MAC — restoring would resurrect a group-wide duplicate that the
        # create path would have refused (#617).
        parent = (
            await db.execute(
                select(DHCPScope)
                .where(DHCPScope.id == obj.scope_id)
                .execution_options(include_deleted=True)
            )
        ).scalar_one_or_none()
        if parent is not None:
            clash = (
                await db.execute(
                    select(DHCPStaticAssignment)
                    .join(DHCPScope, DHCPStaticAssignment.scope_id == DHCPScope.id)
                    .where(
                        DHCPScope.group_id == parent.group_id,
                        DHCPStaticAssignment.mac_address == obj.mac_address,
                        DHCPStaticAssignment.id != obj.id,
                    )
                )
            ).first()
            if clash is not None:
                return (
                    f"MAC {obj.mac_address} has since been reserved by a live scope in this group"
                )

    return None
