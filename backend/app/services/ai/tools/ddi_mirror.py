"""Operator Copilot read tools for the commercial-DDI mirror (#4729).

Four reads over the mirror store and the cutover-rehearsal diff, all tagged
``module="migration.ddi_mirror"`` so turning the module off strips them from
the AI surface with the REST surface (non-negotiable #14). They read stored
rows (and, for the rehearsal, live IPAM / DNS rows) and make no outbound call,
so they ship enabled. The stored password never enters a response.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.ddi_mirror import DDIMirrorObject, DDIMirrorTarget
from app.services.ai.tools.base import register_tool
from app.services.ddi_mirror.base import ALL_KINDS
from app.services.ddi_mirror.rehearsal import ACTIONS, build_rehearsal

MODULE = "migration.ddi_mirror"
_PERM = ("read", "ddi_mirror_target")


def _target_id(raw: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


class ListTargetsArgs(BaseModel):
    search: str | None = Field(default=None, description="Substring match on name / URL.")
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="list_ddi_mirror_targets",
    permission=_PERM,
    module=MODULE,
    category="integrations",
    description=(
        "List the commercial DDI estates (Infoblox today) SpatiumDDI mirrors read-only "
        "to rehearse a cutover: id, name, vendor, endpoint, enabled, sync interval, "
        "last_synced_at, last_sync_error, last_sync_warning, source version, mirrored "
        "object_count and the per-kind report of the last sync (counts and what could "
        "not be mapped). Credentials never appear."
    ),
    args_model=ListTargetsArgs,
)
async def list_ddi_mirror_targets(
    db: AsyncSession, user: User, args: ListTargetsArgs
) -> list[dict[str, Any]]:
    stmt = select(DDIMirrorTarget)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(DDIMirrorTarget.name).like(like),
                func.lower(DDIMirrorTarget.base_url).like(like),
            )
        )
    rows = (await db.execute(stmt.order_by(DDIMirrorTarget.name).limit(args.limit))).scalars()
    return [
        {
            "id": str(t.id),
            "name": t.name,
            "description": t.description,
            "vendor": t.vendor,
            "endpoint": t.base_url,
            "enabled": t.enabled,
            "sync_interval_seconds": t.sync_interval_seconds,
            "last_synced_at": t.last_synced_at.isoformat() if t.last_synced_at else None,
            "last_sync_error": t.last_sync_error,
            "last_sync_warning": t.last_sync_warning,
            "source_version": t.source_version,
            "object_count": t.object_count,
            "last_report": t.last_report,
        }
        for t in rows.all()
    ]


class FindObjectsArgs(BaseModel):
    target_id: str = Field(description="Mirror target UUID (from list_ddi_mirror_targets).")
    kind: str | None = Field(default=None, description=f"One of: {', '.join(ALL_KINDS)}.")
    search: str | None = Field(default=None, description="Substring on name / value / comment.")
    limit: int = Field(default=50, ge=1, le=200)


def _object_filter(args: Any, tid: uuid.UUID) -> list[Any]:
    cond: list[Any] = [DDIMirrorObject.target_id == tid]
    if args.kind:
        cond.append(DDIMirrorObject.kind == args.kind)
    if getattr(args, "search", None):
        like = f"%{args.search.lower()}%"
        cond.append(
            or_(
                func.lower(DDIMirrorObject.name).like(like),
                func.lower(DDIMirrorObject.value).like(like),
                func.lower(DDIMirrorObject.comment).like(like),
            )
        )
    return cond


def _bad(args: Any) -> dict[str, Any] | None:
    if _target_id(args.target_id) is None:
        return {"error": "target_id is not a valid UUID"}
    if args.kind and args.kind not in ALL_KINDS:
        return {"error": f"kind must be one of {', '.join(ALL_KINDS)}"}
    return None


@register_tool(
    name="find_ddi_mirror_objects",
    permission=_PERM,
    module=MODULE,
    category="integrations",
    description=(
        "Search the objects mirrored from a commercial DDI estate: networks, containers, "
        "ranges, fixed addresses (reservation), host / A / PTR records, zones and views. "
        "Each row has kind, name, view, value (CIDR / start-end / IP / record data), comment "
        "and the source's own object ref. Use for 'is 10.1.0.0/16 on the old Infoblox?'."
    ),
    args_model=FindObjectsArgs,
)
async def find_ddi_mirror_objects(
    db: AsyncSession, user: User, args: FindObjectsArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    if (err := _bad(args)) is not None:
        return err
    tid = _target_id(args.target_id)
    assert tid is not None
    if await db.get(DDIMirrorTarget, tid) is None:
        return {"error": "mirror target not found"}
    rows = (
        (
            await db.execute(
                select(DDIMirrorObject)
                .where(*_object_filter(args, tid))
                .order_by(DDIMirrorObject.kind, DDIMirrorObject.name)
                .limit(args.limit)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "kind": o.kind,
            "name": o.name,
            "view": o.view,
            "value": o.value,
            "comment": o.comment,
            "source_ref": o.source_ref,
        }
        for o in rows
    ]


class CountObjectsArgs(BaseModel):
    target_id: str = Field(description="Mirror target UUID.")
    kind: str | None = Field(default=None, description=f"One of: {', '.join(ALL_KINDS)}.")


@register_tool(
    name="count_ddi_mirror_objects",
    permission=_PERM,
    module=MODULE,
    category="integrations",
    description="Count mirrored objects of one commercial DDI target, grouped by kind.",
    args_model=CountObjectsArgs,
)
async def count_ddi_mirror_objects(
    db: AsyncSession, user: User, args: CountObjectsArgs
) -> dict[str, Any]:
    if (err := _bad(args)) is not None:
        return err
    tid = _target_id(args.target_id)
    assert tid is not None
    if await db.get(DDIMirrorTarget, tid) is None:
        return {"error": "mirror target not found"}
    rows = (
        await db.execute(
            select(DDIMirrorObject.kind, func.count())
            .where(*_object_filter(args, tid))
            .group_by(DDIMirrorObject.kind)
        )
    ).all()
    by_kind = {k: int(n) for k, n in rows}
    return {"total": sum(by_kind.values()), "by_kind": by_kind}


class RehearsalArgs(BaseModel):
    target_id: str = Field(description="Mirror target UUID.")
    kind: str | None = Field(default=None, description=f"One of: {', '.join(ALL_KINDS)}.")
    action: str | None = Field(
        default=None, description=f"Only items an import would: {', '.join(ACTIONS)}."
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_ddi_mirror_rehearsal",
    permission=_PERM,
    module=MODULE,
    category="integrations",
    description=(
        "Cutover rehearsal for a mirrored commercial DDI estate: per-kind counts of what "
        "importing it into live SpatiumDDI would create, what already exists and what "
        "differs, plus the matching items with the differences spelled out. Read-only."
    ),
    args_model=RehearsalArgs,
)
async def find_ddi_mirror_rehearsal(
    db: AsyncSession, user: User, args: RehearsalArgs
) -> dict[str, Any]:
    if (err := _bad(args)) is not None:
        return err
    if args.action and args.action not in ACTIONS:
        return {"error": f"action must be one of {', '.join(ACTIONS)}"}
    tid = _target_id(args.target_id)
    assert tid is not None
    if await db.get(DDIMirrorTarget, tid) is None:
        return {"error": "mirror target not found"}
    counts, total, items = await build_rehearsal(
        db, tid, kind=args.kind, action=args.action, limit=args.limit
    )
    return {
        "kinds": {
            k: {"total": c.total, "create": c.create, "exists": c.exists, "differs": c.differs}
            for k, c in counts.items()
        },
        "matching_items": total,
        "items": [
            {
                "kind": i.kind,
                "name": i.name,
                "value": i.value,
                "view": i.view,
                "action": i.action,
                "differences": i.differences,
            }
            for i in items
        ],
    }
