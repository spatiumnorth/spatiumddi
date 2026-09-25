"""Trash — list, restore, and (via the existing handlers) permanent-delete
soft-deleted IPAM / DNS / DHCP rows.

The soft-delete stamping happens in the per-resource delete handlers; this
router gives operators a unified view of "what's recoverable", a one-click
restore (atomic on the whole batch), and the housekeeping endpoints the
admin UI needs.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import Select, func, select

from app.api.deps import DB, SuperAdmin
from app.core.agent_wake import dns_group_channel, publish_wake
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPScope
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import Subnet
from app.services.dhcp.lease_cleanup import delete_leases_for_scope
from app.services.dhcp.static_ipam import (
    remirror_scope_statics,
    remove_ipam_for_scope_statics,
)
from app.services.dhcp.windows_writethrough import push_scope_restore
from app.services.dns.record_ops import push_records_restore, retract_address_records
from app.services.soft_delete import (  # noqa: PLC2701 — canonical labels, keep in one place
    SOFT_DELETE_RESOURCE_TYPES,
    TYPE_TO_MODEL,
    batch_resource_types,
    default_conflict_check,
    restore_batch,
)
from app.services.soft_delete import (
    _resource_type as resource_type_for,
)
from app.services.soft_delete import (
    _row_display as _row_label,
)

logger = structlog.get_logger(__name__)


router = APIRouter()


# ── Response shapes ───────────────────────────────────────────────────────


class TrashEntry(BaseModel):
    id: uuid.UUID
    type: str
    name_or_cidr: str
    deleted_at: datetime
    deleted_by_user_id: uuid.UUID | None
    deleted_by_username: str | None
    deletion_batch_id: uuid.UUID | None
    batch_size: int


class TrashListResponse(BaseModel):
    items: list[TrashEntry]
    total: int


class RestoreConflict(BaseModel):
    type: str
    id: str
    display: str
    reason: str


class RestoreResponse(BaseModel):
    batch_id: uuid.UUID
    restored: int
    # Rows left in the trash because a live duplicate exists — only ever
    # non-empty with ``?skip_conflicts=true``; without it a conflict is a 409.
    skipped: list[RestoreConflict] = []


# ── Helpers ───────────────────────────────────────────────────────────────


async def _resolve_usernames(db: Any, user_ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not user_ids:
        return {}
    res = await db.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
    return {row.id: row.username for row in res.all()}


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.get("/trash", response_model=TrashListResponse)
async def list_trash(
    db: DB,
    current_user: SuperAdmin,
    type: str | None = Query(None, description="Filter to one resource type"),
    since: datetime | None = Query(None, description="Only show rows deleted after this UTC time"),
    until: datetime | None = Query(None, description="Only show rows deleted before this UTC time"),
    q: str | None = Query(None, description="Substring match on name / CIDR / FQDN"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> TrashListResponse:
    """Paginated list of soft-deleted rows across every in-scope type."""

    if type is not None and type not in SOFT_DELETE_RESOURCE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown type {type!r}. Valid: {sorted(SOFT_DELETE_RESOURCE_TYPES)}",
        )

    types_to_query = [type] if type else list(SOFT_DELETE_RESOURCE_TYPES)
    items: list[TrashEntry] = []
    user_ids: set[uuid.UUID] = set()
    batch_size_cache: dict[uuid.UUID, int] = {}

    # Collect rows from every requested model. Each query opts into
    # include_deleted so it sees soft-deleted rows; without that, the
    # global filter hides them.
    for resource_type in types_to_query:
        model = TYPE_TO_MODEL[resource_type]
        stmt: Select[Any] = (
            select(model)
            .where(model.deleted_at.is_not(None))
            .execution_options(include_deleted=True)
        )
        if since is not None:
            stmt = stmt.where(model.deleted_at >= since)
        if until is not None:
            stmt = stmt.where(model.deleted_at <= until)
        res = await db.execute(stmt)
        for row in res.scalars().all():
            label = _row_label(row)
            if q and q.lower() not in label.lower():
                continue
            if row.deleted_by_user_id is not None:
                user_ids.add(row.deleted_by_user_id)
            items.append(
                TrashEntry(
                    id=row.id,
                    type=resource_type,
                    name_or_cidr=label,
                    deleted_at=row.deleted_at,
                    deleted_by_user_id=row.deleted_by_user_id,
                    deleted_by_username=None,
                    deletion_batch_id=row.deletion_batch_id,
                    batch_size=0,  # filled after we collect everything
                )
            )

    # Resolve usernames once for all collected rows.
    username_map = await _resolve_usernames(db, user_ids)

    # Compute batch sizes by counting rows per batch_id across every model.
    seen_batches: set[uuid.UUID] = {
        item.deletion_batch_id for item in items if item.deletion_batch_id is not None
    }
    for batch_id in seen_batches:
        size = 0
        # TYPE_TO_MODEL, not SOFT_DELETE_RESOURCE_TYPES: the batch carries
        # cascade-only children (a scope's pools + reservations) that the trash
        # list deliberately doesn't browse, but that must still be counted or
        # the blast radius under-reports (#617).
        for model in TYPE_TO_MODEL.values():
            count_stmt: Select[int] = (
                select(func.count())
                .select_from(model)
                .where(model.deletion_batch_id == batch_id)
                .execution_options(include_deleted=True)
            )
            size += int((await db.execute(count_stmt)).scalar_one() or 0)
        batch_size_cache[batch_id] = size

    for item in items:
        if item.deletion_batch_id is not None:
            item.batch_size = batch_size_cache.get(item.deletion_batch_id, 1)
        else:
            item.batch_size = 1
        if item.deleted_by_user_id is not None:
            item.deleted_by_username = username_map.get(item.deleted_by_user_id)

    items.sort(key=lambda i: i.deleted_at, reverse=True)
    total = len(items)
    return TrashListResponse(items=items[offset : offset + limit], total=total)


# Types a partial restore is safe for (#963 review). ``skip_conflicts`` leaves
# the clashing rows in the trash, which is only sound when the batch is a FLAT
# set of independent siblings — every row a leaf, none the parent of another.
#
# ``dns_record`` is the only such batch anyone produces today: bulk record
# delete stamps N records under one id, and ``_collect_descendants`` has no
# DNSRecord branch, so a record never drags children along. Every other batch
# is a cascade (a zone AND its records, a scope AND its pools), where skipping
# a row can restore a child whose parent stayed deleted — records pointing at
# a soft-deleted zone, hidden by the zone's own filter and re-pushed to the
# provider as if live. Add a type here only with the same argument.
_PARTIAL_RESTORE_TYPES = frozenset({"dns_record"})


@router.post("/trash/{type}/{row_id}/restore", response_model=RestoreResponse)
async def restore_row(
    type: str,
    row_id: uuid.UUID,
    db: DB,
    current_user: SuperAdmin,
    skip_conflicts: bool = False,
) -> RestoreResponse:
    """Restore a soft-deleted row and every sibling in its deletion batch.

    ``skip_conflicts`` restores every sibling that does NOT clash with a live
    row and reports the ones left behind, instead of refusing the whole batch
    — for a bulk record delete (#963), where one record re-created by hand
    must not make the other N unrestorable. It is refused (422) on a cascade
    batch; see ``_PARTIAL_RESTORE_TYPES``.
    """

    if type not in SOFT_DELETE_RESOURCE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown type {type!r}. Valid: {sorted(SOFT_DELETE_RESOURCE_TYPES)}",
        )

    model = TYPE_TO_MODEL[type]
    stmt: Select[Any] = (
        select(model)
        .where(model.id == row_id, model.deleted_at.is_not(None))
        .execution_options(include_deleted=True)
    )
    target = (await db.execute(stmt)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Soft-deleted row not found")

    batch_id = target.deletion_batch_id
    if batch_id is None:
        # Defensive: stamp a fresh batch and restore just this row.
        batch_id = uuid.uuid4()
        target.deletion_batch_id = batch_id

    if skip_conflicts:
        # Checked BEFORE the restore: a partial restore of a cascade batch is
        # not something to undo afterwards. The UI hides the option for these
        # types; this is what enforces it.
        cascade = await batch_resource_types(db, batch_id) - _PARTIAL_RESTORE_TYPES
        if cascade:
            raise HTTPException(
                status_code=422,
                detail=(
                    "skip_conflicts is only available for a flat batch of independent "
                    f"rows; this batch also holds {', '.join(sorted(cascade))}, whose "
                    "children would be restored without their parent. Resolve the "
                    "clash and restore the batch whole."
                ),
            )

    async def _check(obj: Any) -> str | None:
        return await default_conflict_check(db, obj)

    restored, conflicts = await restore_batch(
        db, batch_id, conflict_check=_check, skip_conflicts=skip_conflicts
    )
    if conflicts and not skip_conflicts:
        raise HTTPException(
            status_code=409,
            detail={"message": "Restore would clash with active rows", "conflicts": conflicts},
        )

    # Soft-delete pushed a remove-scope to every agentless (Windows) member
    # (#616); the restore owes them the inverse or the scope comes back in
    # SpatiumDDI only and the two silently diverge. Runs after restore_batch has
    # un-stamped the rows, so the per-object helpers' scope lookups resolve.
    #
    # DNS records are the analogue (#632): an individually soft-deleted record
    # was retracted from agentless providers on delete, so restoring it owes the
    # inverse ``create``. A record restored as part of a *zone* restore is
    # skipped — the zone-delete path never retracts the provider (no hosted-zone
    # teardown on soft-delete, to avoid cloud zone-ID / NS churn), so its
    # cascade-deleted records are still live there and need no re-push.
    restored_has_zone = any(isinstance(o, DNSZone) for o in restored)
    # Records re-push per ZONE in one batch, not per record: a #963 bulk delete
    # restores as one batch of N independent records, and N singular pushes
    # would be N serial bumps and, on an agentless driver, N WinRM round trips
    # inside one request — the cost the bulk-delete route exists to avoid.
    records_by_zone: dict[uuid.UUID, list[DNSRecord]] = {}
    for obj in restored:
        if isinstance(obj, DHCPScope):
            await push_scope_restore(db, obj)
            # Soft-delete deleted this scope's static_dhcp mirror rows (so the
            # IPs folded into free gaps); a restore has to re-create them —
            # re-asserting status + back-link + DNS. Leases need no restore work:
            # push_scope_restore re-creates the device scope and the next poll
            # re-populates them.
            await remirror_scope_statics(db, obj)
        elif isinstance(obj, DNSRecord) and not restored_has_zone:
            records_by_zone.setdefault(obj.zone_id, []).append(obj)
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="restore",
                resource_type=resource_type_for(obj),
                resource_id=str(obj.id),
                resource_display=_row_label(obj),
                new_value={"deletion_batch_id": str(batch_id)},
                result="success",
            )
        )

    for zone_id, recs in records_by_zone.items():
        await push_records_restore(db, zone_id, recs)

    await db.commit()
    logger.info(
        "trash.restore",
        batch_id=str(batch_id),
        restored=len(restored),
        skipped=len(conflicts),
        user_id=str(current_user.id),
    )
    return RestoreResponse(
        batch_id=batch_id,
        restored=len(restored),
        skipped=[RestoreConflict(**c) for c in conflicts],
    )


@router.delete("/trash/{type}/{row_id}", status_code=status.HTTP_204_NO_CONTENT)
async def permanent_delete_from_trash(
    type: str,
    row_id: uuid.UUID,
    db: DB,
    current_user: SuperAdmin,
) -> None:
    """Hard-delete a soft-deleted row from the trash.

    The agentless write-through (Windows DHCP scope removal, DNS zone delete)
    already fired at soft-delete time — deleted means deleted on every backend
    the moment the operator asks for it (#616) — so this endpoint only has to
    remove the DB row.

    It does still have to release the IPAM mirror of any reservation it is about
    to destroy: the rows go via FK CASCADE, which runs no Python, so nothing else
    would (#618). The same goes for a subnet's addresses and the DNS records
    IPAM published for them: the addresses cascade, the records only lose their
    ``ip_address_id`` (SET NULL) and stay published — so they are withdrawn
    first (spatiumddi#1151).
    """

    if type not in SOFT_DELETE_RESOURCE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown type {type!r}. Valid: {sorted(SOFT_DELETE_RESOURCE_TYPES)}",
        )

    model = TYPE_TO_MODEL[type]
    stmt: Select[Any] = (
        select(model)
        .where(model.id == row_id, model.deleted_at.is_not(None))
        .execution_options(include_deleted=True)
    )
    target = (await db.execute(stmt)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Soft-deleted row not found")

    label = _row_label(target)
    records_retracted = 0
    dns_wake_group_ids: set[uuid.UUID] = set()
    if isinstance(target, DHCPScope):
        # Delete the reservation mirror rows (not just free them) so the IPs fold
        # back into free gaps, and purge any dynamic leases still pointing here —
        # defense-in-depth for pre-fix strays / convergence-race leftovers (the
        # first soft-delete normally already cleaned both up).
        await remove_ipam_for_scope_statics(db, target.id)
        await delete_leases_for_scope(db, target.id)
    elif isinstance(target, Subnet):
        # spatiumddi#1151 — the subnet's addresses go with it (FK CASCADE); the
        # auto-generated A / AAAA / PTR / alias records IPAM published for them
        # would survive as ownerless rows the agents keep serving. Withdraw
        # them first, through the record-op queue. (A block or space can't
        # reach addresses from here: subnet.block_id / space_id are RESTRICT.)
        records_retracted, dns_wake_group_ids = await retract_address_records(db, [target.id])
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="permanent_delete",
            resource_type=type,
            resource_id=str(target.id),
            resource_display=label,
            result="success",
            new_value=({"dns_records_retracted": records_retracted} if records_retracted else None),
        )
    )
    await db.delete(target)
    await db.commit()
    # This router carries no wake_publishing dependency, so the enqueue's
    # collect_wake had no collector; tell the agents now the ops are committed
    # instead of leaving them to the safety tick.
    for gid in dns_wake_group_ids:
        await publish_wake(dns_group_channel(gid))
