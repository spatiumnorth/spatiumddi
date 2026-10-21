"""Two zones of one name rendered into one view (#2275).

A zone's view placement is not just ``DNSZone.view_id``. The bundle builder
renders a zone into every view named by its own ``view_id`` and by the
``view_id`` of each view-scoped record in it; a zone with neither is *shared*
and renders into every operator view, and geo views (#530) render every zone
(``pool_geo.views_rendering_zone``, the call the bundle builder makes). A group with no views renders each zone once,
flat.

The unique constraint ``(group_id, view_id, name)`` cannot see any of that:
NULL is distinct from NULL, and from every view. So ``corp.example`` shared and
``corp.example`` pinned to ``internal`` both pass it, and both land in
``internal``. BIND refuses a view that declares one zone twice, ``named-checkconf``
fails, and the agent declines the bundle for the whole group (#882).

This module answers "which zone names would be rendered twice into one view",
from the same rule the bundle builder uses, so the guard and the renderer
cannot disagree. ``RenderGuard`` wraps it for a mutation: take a baseline before
the change, check after it, and refuse only collisions the change introduced.
Refusing pre-existing ones would block the unrelated edit that is meant to fix
them.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSView, DNSZone
from app.services.dns.pool_geo import (
    build_geo_steering,
    build_view_descriptors,
    views_rendering_zone,
)

# The label a collision carries when the group has no views and every zone
# renders flat, outside any ``view`` block.
FLAT = "(no view)"


def normalise_zone_name(name: str) -> str:
    return (name or "").strip().rstrip(".").lower()


@dataclass(frozen=True)
class ZoneRenderCollision:
    view: str
    zone_name: str
    zone_ids: tuple[str, ...]

    @property
    def key(self) -> tuple[str, str]:
        return (self.view, self.zone_name)

    def describe(self) -> str:
        where = "the group's flat config" if self.view == FLAT else f"view {self.view!r}"
        return f"{self.zone_name}. in {where} ({len(self.zone_ids)} zones)"


@dataclass
class ExtraZone:
    """A zone that is not live yet but would be after the change (a restore)."""

    id: uuid.UUID
    name: str
    view_id: uuid.UUID | None
    record_view_ids: set[uuid.UUID] = field(default_factory=set)


async def zone_render_collisions(
    db: AsyncSession,
    group_id: uuid.UUID,
    *,
    names: Iterable[str] | None = None,
    extra_zones: Iterable[ExtraZone] = (),
) -> list[ZoneRenderCollision]:
    """Every (view, zone name) the group's bundle would render more than once.

    ``names`` limits the scan to those zone names (any spelling); None scans the
    whole group. ``extra_zones`` are counted as if they were live.
    """
    wanted = None if names is None else {normalise_zone_name(n) for n in names if n}
    if wanted is not None and not wanted:
        return []

    stmt: Any = select(DNSZone.id, DNSZone.name, DNSZone.view_id).where(
        DNSZone.group_id == group_id
    )
    if wanted is not None:
        stmt = stmt.where(func.lower(func.rtrim(DNSZone.name, ".")).in_(wanted))
    zones: list[ExtraZone] = [
        ExtraZone(id=z.id, name=normalise_zone_name(z.name), view_id=z.view_id)
        for z in (await db.execute(stmt)).all()
    ]
    live_ids = {z.id for z in zones}
    for extra in extra_zones:
        zname = normalise_zone_name(extra.name)
        if extra.id in live_ids or (wanted is not None and zname not in wanted):
            continue
        zones.append(
            ExtraZone(
                id=extra.id,
                name=zname,
                view_id=extra.view_id,
                record_view_ids=set(extra.record_view_ids),
            )
        )

    # Only a name held by two zones or more can render twice anywhere. Most
    # names are held by one, so the record scan below (the expensive part: it
    # reads every record of the zone, and a zone can hold millions) runs only
    # for the twins that can actually collide.
    per_name = Counter(z.name for z in zones)
    zones = [z for z in zones if per_name[z.name] > 1]
    if not zones:
        return []

    views = (await db.execute(select(DNSView).where(DNSView.group_id == group_id))).scalars().all()
    geo = await build_geo_steering(db, group_id)
    has_views = bool(views) or geo.active
    descs = build_view_descriptors(sorted(views, key=lambda v: (v.order, v.name)), geo)

    live_twin_ids = [z.id for z in zones if z.id in live_ids]
    if live_twin_ids and has_views:
        rows = await db.execute(
            select(DNSRecord.zone_id, DNSRecord.view_id)
            .where(DNSRecord.zone_id.in_(live_twin_ids), DNSRecord.view_id.is_not(None))
            .distinct()
        )
        by_id = {z.id: z for z in zones}
        for zid, vid in rows.all():
            by_id[zid].record_view_ids.add(vid)

    placements: dict[tuple[str, str], list[str]] = {}
    for z in zones:
        if not has_views:
            placements.setdefault((FLAT, z.name), []).append(str(z.id))
            continue
        for vd in views_rendering_zone(descs, z.view_id, z.record_view_ids):
            placements.setdefault((vd["name"], z.name), []).append(str(z.id))

    return [
        ZoneRenderCollision(view=v, zone_name=n, zone_ids=tuple(sorted(ids)))
        for (v, n), ids in sorted(placements.items())
        if len(ids) > 1
    ]


def collision_detail(collisions: list[ZoneRenderCollision], action: str) -> str:
    shown = "; ".join(c.describe() for c in collisions[:5])
    more = f" and {len(collisions) - 5} more" if len(collisions) > 5 else ""
    return (
        f"Cannot {action}: the group would render the same zone twice in one view "
        f"({shown}{more}). BIND refuses a view that declares a zone twice, and the "
        "agent then declines the whole group's config. Pin one of the zones to a "
        "different view, rename it, or delete it first."
    )


class RenderGuard:
    """Refuse a mutation that makes a group render one zone name twice in a view.

    ``await RenderGuard.capture(db, group_id, names)`` BEFORE the change, then
    ``await guard.check(db, action)`` after it. ``check`` flushes, recomputes,
    and refuses only collisions that were not already there.

    ``capture`` opens a SAVEPOINT that the change runs inside. A refusal rolls
    back to it, so the refused change is gone from the session whatever the
    caller does next (a caller that catches the error and carries on, like an
    importer moving to its next zone, must not commit it); success releases it.
    """

    def __init__(
        self,
        group_id: uuid.UUID,
        names: set[str] | None,
        baseline: set[tuple[str, str]],
        savepoint: Any = None,
    ) -> None:
        self.group_id = group_id
        self.names = names
        self.baseline = baseline
        self._savepoint = savepoint

    @classmethod
    async def capture(
        cls,
        db: AsyncSession,
        group_id: uuid.UUID,
        names: Iterable[str] | None,
        *,
        savepoint: bool = True,
    ) -> RenderGuard:
        """``names=None`` guards every zone in the group."""
        wanted = None if names is None else {normalise_zone_name(n) for n in names if n}
        before = await zone_render_collisions(db, group_id, names=wanted)
        sp = await db.begin_nested() if savepoint else None
        return cls(group_id, wanted, {c.key for c in before}, sp)

    async def new_collisions(self, db: AsyncSession) -> list[ZoneRenderCollision]:
        await db.flush()
        after = await zone_render_collisions(db, self.group_id, names=self.names)
        return [c for c in after if c.key not in self.baseline]

    async def check(
        self,
        db: AsyncSession,
        action: str,
        *,
        error: Callable[[str], Exception] | None = None,
    ) -> None:
        """Raise (409 by default, or ``error(detail)``) on a new collision."""
        new = await self.new_collisions(db)
        sp, self._savepoint = self._savepoint, None
        if new:
            if sp is not None and sp.is_active:
                await sp.rollback()
            detail = collision_detail(new, action)
            raise error(detail) if error else HTTPException(status_code=409, detail=detail)
        if sp is not None and sp.is_active:
            await sp.commit()
