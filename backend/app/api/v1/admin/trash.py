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
from typing import Any, Literal

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import String, cast, func, literal, select, union_all
from sqlalchemy import delete as sa_delete
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, SuperAdmin
from app.core.agent_wake import dns_group_channel, publish_wake
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPPool, DHCPScope, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.network_service import NetworkService
from app.models.overlay import OverlayNetwork
from app.models.ownership import Customer
from app.services.dhcp.lease_cleanup import delete_leases_for_scope
from app.services.dhcp.static_ipam import (
    remirror_scope_statics,
    remove_ipam_for_scope_statics,
)
from app.services.dhcp.windows_writethrough import push_scope_restore
from app.services.dns.record_ops import push_records_restore, retract_address_records
from app.services.dns.view_collisions import RenderGuard, collision_detail
from app.services.ipam.orphan_aliases import (
    is_withdrawn_alias,
    orphan_record_owners,
    orphan_record_reason,
    refusal_reason,
    withdrawn_alias_owners,
)
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
    limit: int = 200
    offset: int = 0


class RestoreConflict(BaseModel):
    type: str
    id: str
    display: str
    reason: str
    # Set when the clash is a parent still in the Trash (#1957): the Trash row
    # to restore first, so the page can offer it instead of a dead end.
    parent_type: str | None = None
    parent_id: str | None = None
    parent_display: str | None = None


class RestoreResponse(BaseModel):
    batch_id: uuid.UUID
    restored: int
    # Rows left in the trash because a live duplicate exists — only ever
    # non-empty with ``?skip_conflicts=true``; without it a conflict is a 409.
    skipped: list[RestoreConflict] = []
    # IPAM records not restored because their address's subnet is still in the
    # Trash (#2732): moved into that subnet's batch, one entry per subnet. They
    # come back when the subnet is restored and go if it is purged.
    held_back: list[RestoreConflict] = []


# ── Helpers ───────────────────────────────────────────────────────────────


async def _resolve_usernames(db: Any, user_ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not user_ids:
        return {}
    res = await db.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
    return {row.id: row.username for row in res.all()}


# Exactly the characters Python's ``str.strip()`` removes, Unicode included
# (NBSP, U+3000, ...), so the SQL label below matches ``_row_display`` for
# any name. Derived rather than spelled out so the two cannot drift.
_WHITESPACE = "".join(c for c in map(chr, range(0x110000)) if c.isspace())


def _label_expr(model: type) -> Any:
    """The SQL twin of ``soft_delete._row_display`` for the trash listing.

    The two must agree, or the ``q`` filter would match a different string
    from the one shown; ``test_trash_listing_label_matches_row_display``
    pins that.
    """
    if model in (IPSpace, Customer, OverlayNetwork, NetworkService):
        return model.name
    if model in (IPBlock, Subnet):
        network = cast(model.network, String)
        # btrim over the whitespace set, not trim(): Python's ``str.strip``
        # also drops a trailing tab or newline in the name.
        return func.btrim(
            network + func.coalesce(literal(" ") + func.nullif(model.name, ""), ""),
            _WHITESPACE,
        )
    if model is DNSZone:
        return model.name
    if model is DNSRecord:
        return model.fqdn + literal(" ") + model.record_type
    if model is DHCPScope:
        return func.coalesce(func.nullif(model.name, ""), cast(model.id, String))
    raise ValueError(f"no trash label for {model.__name__}")


# ── Endpoints ─────────────────────────────────────────────────────────────


# ── Purge helpers (#1957, #1958) ──────────────────────────────────────────


def _purge_audit(current_user: Any, resource_type: str, row: Any) -> AuditLog:
    return AuditLog(
        user_id=current_user.id,
        user_display_name=current_user.display_name,
        auth_source=current_user.auth_source,
        action="permanent_delete",
        resource_type=resource_type,
        resource_id=str(row.id),
        resource_display=_row_label(row),
        result="success",
        new_value={"purged_with": "parent"},
    )


def _handover_audit(current_user: Any, zone: Any, heir: Any) -> AuditLog:
    """The auto reverse zone a subnet purge left in the Trash for another
    trashed subnet whose records still sit in it (spatiumddi#3190)."""
    return AuditLog(
        user_id=current_user.id,
        user_display_name=current_user.display_name,
        auth_source=current_user.auth_source,
        action="update",
        resource_type="dns_zone",
        resource_id=str(zone.id),
        resource_display=_row_label(zone),
        result="success",
        new_value={
            "handed_over_to_subnet": str(heir.id),
            "deletion_batch_id": str(heir.deletion_batch_id),
            "reason": "another trashed subnet's records still sit in the zone",
        },
    )


def _refuse_live_children(label: str, live: list[str]) -> None:
    shown = ", ".join(live[:5]) + (f" and {len(live) - 5} more" if len(live) > 5 else "")
    raise HTTPException(
        status_code=409,
        detail=(
            f"Cannot permanently delete {label}: it still holds live rows that are not in "
            f"the Trash ({shown}). Restore {label} from the Trash or move or delete those "
            "rows first; a permanent delete never takes live rows with it."
        ),
    )


async def _trashed_ipam_subtree(db: Any, target: Any) -> tuple[list[Any], list[Any]]:
    """Every block (deepest first, ``target`` included when a block) and every
    subnet under a trashed block or space, whatever batch each was trashed in.

    Live rows are returned too, so the caller can refuse; the soft-delete filter
    is off because the point is to see what the database will refuse over.
    """
    if isinstance(target, IPSpace):
        blocks = list(
            (
                await db.execute(
                    select(IPBlock)
                    .where(IPBlock.space_id == target.id)
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
        subnets = list(
            (
                await db.execute(
                    select(Subnet)
                    .where(Subnet.space_id == target.id)
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
    else:
        blocks = [target]
        frontier = [target.id]
        while frontier:
            kids = list(
                (
                    await db.execute(
                        select(IPBlock)
                        .where(IPBlock.parent_block_id.in_(frontier))
                        .execution_options(include_deleted=True)
                    )
                )
                .scalars()
                .all()
            )
            blocks.extend(kids)
            frontier = [k.id for k in kids]
        subnets = list(
            (
                await db.execute(
                    select(Subnet)
                    .where(Subnet.block_id.in_([b.id for b in blocks]))
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
    # Deepest first: a block's depth is the length of its parent chain.
    by_id = {b.id: b for b in blocks}

    def depth(b: Any) -> int:
        d = 0
        while b.parent_block_id in by_id and d < 1000:
            b = by_id[b.parent_block_id]
            d += 1
        return d

    blocks.sort(key=depth, reverse=True)
    return blocks, subnets


async def _live_children(
    db: Any, targets: list[Any], blocks: list[Any], subnets: list[Any]
) -> list[str]:
    """Labels of rows a purge of ``targets`` would destroy that are NOT in the Trash.

    Every level the FK CASCADEs reach is looked at: blocks and subnets (handed
    in by the caller, trashed or not), the DHCP scopes on those subnets, and the
    pools and reservations on any of those scopes, trashed scopes included — a
    live reservation restored onto a trashed scope before #1957 is still live.
    """
    live = [f"block {_row_label(b)}" for b in blocks if b.deleted_at is None]
    live += [f"subnet {_row_label(sub)}" for sub in subnets if sub.deleted_at is None]
    subnet_ids = [sub.id for sub in subnets] + [t.id for t in targets if isinstance(t, Subnet)]
    scope_ids = [t.id for t in targets if isinstance(t, DHCPScope)]
    if subnet_ids:
        scopes = (
            (
                await db.execute(
                    select(DHCPScope)
                    .where(DHCPScope.subnet_id.in_(subnet_ids))
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
        live += [f"DHCP scope {_row_label(sc)}" for sc in scopes if sc.deleted_at is None]
        scope_ids += [sc.id for sc in scopes]
    if scope_ids:
        # The soft-delete filter is on: only LIVE pools / reservations show up.
        pools = (
            (await db.execute(select(DHCPPool).where(DHCPPool.scope_id.in_(scope_ids)).limit(5)))
            .scalars()
            .all()
        )
        live += [f"DHCP pool {_row_label(p)}" for p in pools]
        statics = (
            (
                await db.execute(
                    select(DHCPStaticAssignment)
                    .where(DHCPStaticAssignment.scope_id.in_(scope_ids))
                    .limit(5)
                )
            )
            .scalars()
            .all()
        )
        live += [f"DHCP reservation {_row_label(st)}" for st in statics]
    return live


async def _audit_scopes_under(db: Any, current_user: Any, subnet_ids: list[uuid.UUID]) -> None:
    """One audit row per trashed DHCP scope a subnet purge takes with it (#1957).

    The scope rows go by FK CASCADE, which runs no Python, so without this the
    scope and its reservations vanished with no record of it.
    """
    if not subnet_ids:
        return
    scopes = (
        (
            await db.execute(
                select(DHCPScope)
                .where(DHCPScope.subnet_id.in_(subnet_ids), DHCPScope.deleted_at.is_not(None))
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    for sc in scopes:
        db.add(_purge_audit(current_user, "dhcp_scope", sc))


async def _prepare_subnet_purge(
    db: Any, subnets: list[Any], current_user: Any
) -> tuple[int, set[uuid.UUID]]:
    """Withdraw what IPAM published for ``subnets`` before they are hard-deleted.

    spatiumddi#1151 — the addresses go with the subnet (FK CASCADE); the
    auto-generated A / AAAA / PTR / alias records IPAM published for them would
    survive as ownerless rows the agents keep serving. Withdraw them first,
    through the record-op queue.
    spatiumddi#1906 / #2732 — the ones already in the Trash (under the subnet's
    batch, or a zone's deleted before it) are dropped with the subnet by the
    same helper, instead of surviving ownerless for a later restore to publish.
    """
    if not subnets:
        return 0, set()
    retracted, groups = await retract_address_records(db, [sub.id for sub in subnets])
    # spatiumddi#2734 — the reverse zones IPAM auto-created for them go too.
    from app.services.dns.reverse_zone import purge_auto_reverse_zones  # noqa: PLC0415

    groups = groups | await purge_auto_reverse_zones(
        db,
        subnets,
        audit=lambda z: db.add(_purge_audit(current_user, "dns_zone", z)),
        audit_handover=lambda z, heir: db.add(_handover_audit(current_user, z, heir)),
    )
    return retracted, groups


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
    sort: Literal["newest", "oldest"] = Query(
        "newest",
        description="``oldest`` lists the rows the retention purge will remove first (#1961)",
    ),
) -> TrashListResponse:
    """Paginated list of soft-deleted rows across every in-scope type."""

    if type is not None and type not in SOFT_DELETE_RESOURCE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown type {type!r}. Valid: {sorted(SOFT_DELETE_RESOURCE_TYPES)}",
        )

    types_to_query = [type] if type else list(SOFT_DELETE_RESOURCE_TYPES)

    # Filter, count, sort and paginate in SQL (#1231). This used to load
    # every soft-deleted row of every type into Python on every page view,
    # so one trashed 250k-record zone meant 250k ORM objects per load, plus
    # a COUNT per batch per model. One UNION of light column selects now,
    # and the batch sizes for the page's rows only.
    withdrawn = await withdrawn_alias_owners(db) if "dns_record" in types_to_query else {}
    branches = []
    for resource_type in types_to_query:
        model = TYPE_TO_MODEL[resource_type]
        label = _label_expr(model)
        branch: Any = select(
            model.id.label("id"),
            literal(resource_type).label("type"),
            label.label("label"),
            model.deleted_at.label("deleted_at"),
            model.deleted_by_user_id.label("deleted_by_user_id"),
            model.deletion_batch_id.label("deletion_batch_id"),
        ).where(model.deleted_at.is_not(None))
        if model is DNSRecord and withdrawn:
            # #3189 — an orphan's withdrawn aliases follow the address, not
            # the Trash: restored or purged with it, never alone.
            branch = branch.where(~is_withdrawn_alias(withdrawn))
        if since is not None:
            branch = branch.where(model.deleted_at >= since)
        if until is not None:
            branch = branch.where(model.deleted_at <= until)
        if q:
            branch = branch.where(func.lower(label).contains(q.lower(), autoescape=True))
        branches.append(branch)
    listing = union_all(*branches).subquery()

    # include_deleted on the outer statement: the global soft-delete filter
    # would otherwise hide exactly the rows this page exists to show. The
    # total rides the page as a window count, so the UNION is evaluated once;
    # only a page past the end needs a separate count.
    page = (
        await db.execute(
            select(listing, func.count().over().label("total"))
            .order_by(
                listing.c.deleted_at.asc() if sort == "oldest" else listing.c.deleted_at.desc(),
                listing.c.id,
            )
            .limit(limit)
            .offset(offset)
            .execution_options(include_deleted=True)
        )
    ).all()
    if page:
        total = int(page[0].total)
    elif offset == 0:
        total = 0
    else:
        total = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(listing)
                    .execution_options(include_deleted=True)
                )
            ).scalar_one()
            or 0
        )

    username_map = await _resolve_usernames(
        db, {r.deleted_by_user_id for r in page if r.deleted_by_user_id is not None}
    )
    batch_ids = {r.deletion_batch_id for r in page if r.deletion_batch_id is not None}
    batch_sizes: dict[uuid.UUID, int] = {}
    if batch_ids:
        # TYPE_TO_MODEL, not SOFT_DELETE_RESOURCE_TYPES: the batch carries
        # cascade-only children (a scope's pools + reservations) that the trash
        # list deliberately doesn't browse, but that must still be counted or
        # the blast radius under-reports (#617).
        for model in TYPE_TO_MODEL.values():
            res = await db.execute(
                select(model.deletion_batch_id, func.count())
                .where(model.deletion_batch_id.in_(batch_ids))
                .group_by(model.deletion_batch_id)
                .execution_options(include_deleted=True)
            )
            for batch_id, n in res.all():
                batch_sizes[batch_id] = batch_sizes.get(batch_id, 0) + int(n)

    items = [
        TrashEntry(
            id=r.id,
            type=r.type,
            name_or_cidr=r.label,
            deleted_at=r.deleted_at,
            deleted_by_user_id=r.deleted_by_user_id,
            deleted_by_username=(
                username_map.get(r.deleted_by_user_id) if r.deleted_by_user_id else None
            ),
            deletion_batch_id=r.deletion_batch_id,
            batch_size=(
                batch_sizes.get(r.deletion_batch_id, 1) if r.deletion_batch_id is not None else 1
            ),
        )
        for r in page
    ]
    return TrashListResponse(items=items, total=total, limit=limit, offset=offset)


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


async def _capture_render_guards(db: Any, batch_id: uuid.UUID) -> list[RenderGuard]:
    """Baselines for the zone names a restore of ``batch_id`` can re-place (#2275).

    A restored zone renders into its view (or, when it has none, every view),
    and a restored view-scoped record places its zone in that view too. Either
    can put a second copy of a zone name into one view.
    """
    pairs = (
        await db.execute(
            select(DNSZone.group_id, DNSZone.name)
            .where(DNSZone.deletion_batch_id == batch_id)
            .execution_options(include_deleted=True)
        )
    ).all()
    pairs += (
        await db.execute(
            select(DNSZone.group_id, DNSZone.name)
            .join(DNSRecord, DNSRecord.zone_id == DNSZone.id)
            .where(DNSRecord.deletion_batch_id == batch_id, DNSRecord.view_id.is_not(None))
            .distinct()
            .execution_options(include_deleted=True)
        )
    ).all()
    by_group: dict[uuid.UUID, set[str]] = {}
    for gid, name in pairs:
        by_group.setdefault(gid, set()).add(name)
    return [
        await RenderGuard.capture(db, gid, names, savepoint=False)
        for gid, names in by_group.items()
    ]


async def _refuse_render_collisions(db: Any, guards: list[RenderGuard], savepoint: Any) -> None:
    found = []
    for guard in guards:
        found.extend(await guard.new_collisions(db))
    if not found:
        await savepoint.commit()
        return
    await savepoint.rollback()
    raise HTTPException(
        status_code=409,
        detail={
            "message": collision_detail(found, "restore"),
            "conflicts": [
                {
                    "type": "dns_zone",
                    "id": c.zone_ids[0],
                    "display": f"{c.zone_name}.",
                    "reason": c.describe(),
                }
                for c in found
            ],
            "skip_conflicts_allowed": False,
        },
    )


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
    stmt: Any = (
        select(model)
        .where(model.id == row_id, model.deleted_at.is_not(None))
        .execution_options(include_deleted=True)
    )
    target = (await db.execute(stmt)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Soft-deleted row not found")

    if isinstance(target, DNSRecord):
        orphan_address = (await withdrawn_alias_owners(db, [target.id])).get(target.id)
        if orphan_address is not None:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot restore {_row_label(target)}: {refusal_reason(orphan_address)}.",
            )
        # #3189 — a record trashed on its own, whose address was then marked
        # as orphan. Its siblings in a bulk delete are refused by
        # ``restore_batch``.
        owner = (await orphan_record_owners(db, record_ids=[target.id])).get(target.id)
        if owner is not None:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot restore {_row_label(target)}: {orphan_record_reason(owner[2])}.",
            )

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

    render_guards = await _capture_render_guards(db, batch_id)
    # #2275 — the restore runs in a SAVEPOINT so a refused one leaves nothing.
    restore_sp = await db.begin_nested() if render_guards else None
    result = await restore_batch(db, batch_id, conflict_check=_check, skip_conflicts=skip_conflicts)
    restored, conflicts = result.restored, result.conflicts
    if restore_sp is not None and (not conflicts or skip_conflicts):
        await _refuse_render_collisions(db, render_guards, restore_sp)
    if conflicts and not skip_conflicts:
        # Tell the client whether ``skip_conflicts`` would be accepted, so the
        # page offers "Restore the others" only where the 422 above will not
        # answer it (#1960). The same test as the guard at the top.
        cascade_types = await batch_resource_types(db, batch_id) - _PARTIAL_RESTORE_TYPES
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Restore would clash with active rows",
                "conflicts": conflicts,
                "skip_conflicts_allowed": not cascade_types,
            },
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
    # A record rides the zone's own un-stamp only when its ZONE is restored in
    # this batch. A subnet's records in a zone that stayed (#1906) restore beside
    # a retired reverse zone and still owe the provider their ``create``.
    restored_zone_ids = {o.id for o in restored if isinstance(o, DNSZone)}
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
        elif isinstance(obj, DNSRecord) and obj.zone_id not in restored_zone_ids:
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
                # A zone's records get no row of their own: they were restored
                # by one UPDATE and are counted here (#1389).
                new_value=result.audit_new_value(obj, batch_id),
                result="success",
            )
        )

    # A restored subnet / block is back in its parent chain's rollup (#2412).
    from app.api.v1.ipam.router import (  # noqa: PLC0415
        _update_block_utilization,
        _update_utilization,
    )

    await db.flush()
    restored_subnets = [o for o in restored if isinstance(o, Subnet)]
    for sn in restored_subnets:
        await _update_utilization(db, sn.id)
    await db.flush()
    for bid in {sn.block_id for sn in restored_subnets} | {
        o.id for o in restored if isinstance(o, IPBlock)
    }:
        await _update_block_utilization(db, bid)

    restore_wake_groups: set[uuid.UUID] = set()
    for zone_id, recs in records_by_zone.items():
        await push_records_restore(db, zone_id, recs)
        zone_row = await db.get(DNSZone, zone_id)
        if zone_row is not None:
            restore_wake_groups.add(zone_row.group_id)

    await db.commit()
    # This router carries no wake_publishing dependency (see the purge below),
    # so the create ops queued above are announced here, after the commit.
    for gid in restore_wake_groups:
        await publish_wake(dns_group_channel(gid))
    logger.info(
        "trash.restore",
        batch_id=str(batch_id),
        restored=result.total,
        skipped=len(conflicts),
        held_back=len(result.held_back),
        user_id=str(current_user.id),
    )
    return RestoreResponse(
        batch_id=batch_id,
        restored=result.total,
        skipped=[RestoreConflict(**c) for c in conflicts],
        held_back=[RestoreConflict(**c) for c in result.held_back],
    )


@router.delete("/trash/{type}/{row_id}", status_code=status.HTTP_204_NO_CONTENT)
async def permanent_delete_from_trash(
    type: str,
    row_id: uuid.UUID,
    db: DB,
    current_user: SuperAdmin,
) -> None:
    """Hard-delete a soft-deleted row from the trash.

    The agentless write-through for a Windows DHCP scope already fired at
    soft-delete time (#616). A DNS zone's did NOT: a zone is the one object
    never torn down at soft-delete (a hosted zone re-created on restore gets a
    new id + NS set, #632), so this endpoint is its retraction point — it is
    pushed to every agentless server (Windows DNS, cloud, ``technitium_api``)
    BEFORE the row goes, and a failing provider keeps the zone in the trash
    with a 409/502 so it can be retried, never orphaned (#1830).

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
    stmt: Any = (
        select(model)
        .where(model.id == row_id, model.deleted_at.is_not(None))
        .execution_options(include_deleted=True)
    )
    target = (await db.execute(stmt)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Soft-deleted row not found")

    if isinstance(target, DNSRecord):
        orphan_address = (await withdrawn_alias_owners(db, [target.id])).get(target.id)
        if orphan_address is not None:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot permanently delete {_row_label(target)}: {refusal_reason(orphan_address)}.",
            )

    label = _row_label(target)
    records_retracted = 0
    purged_extra: dict[str, int] = {}
    dns_wake_group_ids: set[uuid.UUID] = set()
    try:
        if isinstance(target, DHCPScope):
            live = await _live_children(db, [target], [], [])
            if live:
                _refuse_live_children(label, live)
            # Delete the reservation mirror rows (not just free them) so the IPs fold
            # back into free gaps, and purge any dynamic leases still pointing here —
            # defense-in-depth for pre-fix strays / convergence-race leftovers (the
            # first soft-delete normally already cleaned both up).
            await remove_ipam_for_scope_statics(db, target.id)
            await delete_leases_for_scope(db, target.id)
        elif isinstance(target, Customer):
            # network_service.customer_id is RESTRICT, so a customer that still
            # has services (live or in the Trash) cannot go; say which, rather
            # than answering the generic "something references it" (#2738).
            held = (
                (
                    await db.execute(
                        select(NetworkService.name, NetworkService.deleted_at)
                        .where(NetworkService.customer_id == target.id)
                        .execution_options(include_deleted=True)
                    )
                )
                .tuples()
                .all()
            )
            if held:
                names = [n if d is None else f"{n} (in the Trash)" for n, d in held]
                shown = ", ".join(names[:5]) + (
                    f" and {len(names) - 5} more" if len(names) > 5 else ""
                )
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Cannot permanently delete customer {label}: it still has "
                        f"services ({shown}). Delete the live ones, then purge them "
                        "from the Trash first."
                    ),
                )
        elif isinstance(target, DNSZone):
            # #1830 — retract from agentless servers first; raises (row + audit
            # untouched) when the provider refuses. Same helper as the 30-day sweep.
            from app.services.dns.zone_purge import purge_trashed_zone  # noqa: PLC0415

            # Refuses (409) while a LIVE record sits under the trashed zone (#1957).
            await purge_trashed_zone(db, target)
            dns_wake_group_ids.add(target.group_id)
        elif isinstance(target, Subnet):
            live = await _live_children(db, [target], [], [])
            if live:
                _refuse_live_children(label, live)
            records_retracted, dns_wake_group_ids = await _prepare_subnet_purge(
                db, [target], current_user
            )
            await _audit_scopes_under(db, current_user, [target.id])
        elif isinstance(target, (IPBlock, IPSpace)):
            # #1958 — a block or space is purged WITH the trashed subnets and
            # blocks under it, leaf first (the nightly sweep's order): subnet.block_id
            # / space_id are RESTRICT, and the soft-delete filter hides the trashed
            # subnets from the ORM, so a bare delete of the parent only ever met the
            # database's refusal.
            blocks, subnets = await _trashed_ipam_subtree(db, target)
            live = await _live_children(db, [target], blocks, subnets)
            if live:
                _refuse_live_children(label, live)
            records_retracted, dns_wake_group_ids = await _prepare_subnet_purge(
                db, subnets, current_user
            )
            await _audit_scopes_under(db, current_user, [sub.id for sub in subnets])
            for sub in subnets:
                db.add(_purge_audit(current_user, "subnet", sub))
            for blk in blocks:
                if blk.id != target.id:
                    db.add(_purge_audit(current_user, "ip_block", blk))
            subnet_ids = [sub.id for sub in subnets]
            if subnet_ids:
                await db.execute(
                    sa_delete(Subnet)
                    .where(Subnet.id.in_(subnet_ids))
                    .execution_options(include_deleted=True, synchronize_session=False)
                )
            # Deepest blocks first: a child block is removed before the block it
            # hangs from, so no delete relies on the parent_block_id CASCADE.
            for blk in blocks:
                if blk.id != target.id:
                    await db.execute(
                        sa_delete(IPBlock)
                        .where(IPBlock.id == blk.id)
                        .execution_options(include_deleted=True, synchronize_session=False)
                    )
            if subnets or len(blocks) > 1:
                purged_extra = {"subnets": len(subnets), "blocks": max(len(blocks) - 1, 0)}
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
                new_value=(
                    {
                        **(
                            {"dns_records_retracted": records_retracted}
                            if records_retracted
                            else {}
                        ),
                        **purged_extra,
                    }
                    or None
                ),
            )
        )
        if isinstance(target, (IPBlock, IPSpace)):
            # Core, not ``db.delete``: the ORM would lazy-load the parent's
            # relationships inside an async session, and everything under it is
            # already gone above.
            await db.execute(
                sa_delete(model)
                .where(model.id == target.id)
                .execution_options(include_deleted=True, synchronize_session=False)
            )
        elif not isinstance(target, DNSZone):
            await db.delete(target)
        await db.commit()
    except IntegrityError as exc:
        # Something we did not account for still references the row. Never a 500
        # for a refusal the operator can act on (#922's mapping, kept local: the
        # key it names may not be the row in the path).
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot permanently delete {label}: another row still references it "
                "or something under it. Nothing was deleted."
            ),
        ) from exc
    # This router carries no wake_publishing dependency, so the enqueue's
    # collect_wake had no collector; tell the agents now the ops are committed
    # instead of leaving them to the safety tick.
    for gid in dns_wake_group_ids:
        await publish_wake(dns_group_channel(gid))
