"""Daily purge sweep — hard-delete soft-deleted rows older than the
retention window.

Gated on ``PlatformSettings.soft_delete_purge_days`` (default 30). Setting
the value to 0 disables the purge entirely (rows accumulate forever; manual
permanent-delete via the trash UI is still available).

Counters are emitted per resource type and logged at the end of the run.
A single audit-log row records the summary so operators can see in one
place "the trash sweep ran, here's what it removed".
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import and_, delete, or_, select

from app.celery_app import celery_app
from app.core.agent_wake import dns_group_channel, publish_wake
from app.db import task_session
from app.models.audit import AuditLog
from app.models.dhcp import DHCPPool, DHCPScope, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.settings import PlatformSettings
from app.services.dhcp.static_ipam import remove_ipam_for_static

logger = structlog.get_logger(__name__)

# Order matters — descendants first, ancestors last. ``DHCPStaticAssignment`` /
# ``DHCPPool`` cascade from ``DHCPScope`` (#617); ordering them leaf-first keeps
# the per-type counters honest (a parent DELETE's FK CASCADE would otherwise
# remove the children before they're counted, under-reporting the row count).
#
# Neither DNS model is in this generic bulk-DELETE tuple (#632). ``DNSRecord`` is
# deleted explicitly in ``_sweep`` so records whose zone is being purged THIS
# sweep can be excluded — they ride the zone's own delete + FK CASCADE, staying
# atomic with a teardown that might fail (deleting them here would strand them at
# the provider if that zone's teardown then fails and the row is kept). And
# ``DNSZone`` is purged per-row by ``_purge_dns_zones`` so the agentless-provider
# teardown gates each zone's DB delete.
_PURGE_MODELS_LEAF_FIRST: tuple[type, ...] = (
    DHCPStaticAssignment,
    DHCPPool,
    DHCPScope,
    Subnet,
    IPBlock,
    IPSpace,
)


async def _release_ipam_mirrors(db: Any, cutoff: datetime) -> int:
    """Release the IPAM row behind every reservation this sweep is about to purge.

    The purge is a Core ``DELETE`` — it runs no per-row Python, so nothing would
    otherwise call the detach and the mirrored ``ip_address`` row would be left
    stranded at ``status="static_dhcp"`` pointing at a reservation Postgres had
    already removed: not allocated, not free, not reclaimable by any sweeper
    (#618). Run before the deletes, while the reservations are still readable.

    Selected by what the sweep will actually destroy, NOT by the reservation's
    own tombstone: the ``dhcp_scope`` DELETE below FK-cascades its reservations
    regardless of their ``deleted_at``, so keying only on the child's timestamp
    would miss any reservation whose stamp is absent or newer than its scope's
    (a pre-#617 row the migration backfill didn't reach, a clock skew, a future
    path that stamps parent and child separately) and strand its mirror.

    ``include_deleted`` because these rows are soft-deleted by definition — the
    global filter would hide the very rows we need to clean up.
    """
    res = await db.execute(
        select(DHCPStaticAssignment)
        .join(DHCPScope, DHCPStaticAssignment.scope_id == DHCPScope.id)
        .where(
            or_(
                and_(
                    DHCPStaticAssignment.deleted_at.is_not(None),
                    DHCPStaticAssignment.deleted_at < cutoff,
                ),
                and_(DHCPScope.deleted_at.is_not(None), DHCPScope.deleted_at < cutoff),
            )
        )
        .execution_options(include_deleted=True)
    )
    statics = list(res.scalars().all())
    for st in statics:
        await remove_ipam_for_static(db, st)
    if statics:
        await db.flush()
    return len(statics)


async def _retract_records_from_providers(
    db: Any, cutoff: datetime, purged_zone_ids: set[Any]
) -> int:
    """Best-effort retract soft-deleted records from AGENTLESS providers before
    the Core DELETE removes them (#632).

    Post-#632 an agentless record is retracted at soft-delete time, so this is
    the backstop for the two cases the purge is the last chance to fix: records
    soft-deleted *before* #632 shipped, and records whose day-0 push failed
    (each already left a ``failed`` op-row trace). Without it those rows Core-
    DELETE at day 30 while the provider keeps resolving the name — with no DB
    trace left — a subdomain-takeover vector once the IP is reclaimed.

    Scoped to records whose zone's *primary* is agentless AND enabled: that
    mirrors ``enqueue_record_op``'s dispatch (agent-based BIND9 / PowerDNS records
    dropped from their bundle 30 days ago, and a disabled agentless primary, both
    push nothing), so ``retracted`` only counts pushes that actually applied.
    Records whose whole zone is being purged this sweep are excluded in the query
    — the zone teardown in ``_purge_dns_zones`` retracts them wholesale, and the
    explicit record DELETE in ``_sweep`` likewise skips them.

    Best-effort by design: ``enqueue_record_op`` records a ``failed`` op-row
    rather than raising, so a dead provider can't wedge the sweep; the record row
    is still Core-DELETEd (it was retracted at day 0 in the common case).
    ``include_deleted`` because these rows are soft-deleted by definition.
    """
    from app.drivers.dns import is_agentless  # noqa: PLC0415
    from app.services.dns.record_ops import (  # noqa: PLC0415
        enqueue_record_op,
        record_op_payload,
        resolve_primary_server,
    )

    stmt = select(DNSRecord).where(DNSRecord.deleted_at.is_not(None), DNSRecord.deleted_at < cutoff)
    if purged_zone_ids:
        # Records inside a zone being purged this sweep ride the zone teardown;
        # keep them out of both the load here and the DELETE in _sweep.
        stmt = stmt.where(DNSRecord.zone_id.notin_(purged_zone_ids))
    res = await db.execute(stmt.execution_options(include_deleted=True))
    zone_cache: dict[Any, DNSZone | None] = {}
    retracted = 0
    for record in res.scalars().all():
        if record.zone_id not in zone_cache:
            zr = await db.execute(
                select(DNSZone)
                .where(DNSZone.id == record.zone_id)
                .execution_options(include_deleted=True)
            )
            zone_cache[record.zone_id] = zr.scalar_one_or_none()
        zone = zone_cache[record.zone_id]
        if zone is None:
            continue
        primary = await resolve_primary_server(db, zone)
        if primary is None or not is_agentless(primary.driver) or not primary.is_enabled:
            continue
        op = await enqueue_record_op(db, zone, "delete", record_op_payload(record))
        # Count only pushes that actually landed — a disabled primary returns
        # None (handled above) and a rejecting provider lands ``failed``.
        if op is not None and op.state == "applied":
            retracted += 1
    if retracted:
        await db.flush()
    return retracted


async def _purge_dns_records(db: Any, cutoff: datetime, purged_zone_ids: set[Any]) -> int:
    """Core-DELETE soft-deleted records past cutoff, EXCLUDING those whose zone is
    being purged this sweep (#632).

    In-zone records ride their zone's own delete + FK CASCADE (``_purge_dns_zones``)
    so their removal stays atomic with a teardown that might fail — deleting them
    here would strand them at the provider if that zone's teardown then failed and
    the row were kept. Returns the count of standalone records removed; in-zone
    ones are counted by the zone CASCADE, not here. ``include_deleted`` because
    these are soft-deleted rows by definition.
    """
    stmt = delete(DNSRecord).where(DNSRecord.deleted_at.is_not(None), DNSRecord.deleted_at < cutoff)
    if purged_zone_ids:
        stmt = stmt.where(DNSRecord.zone_id.notin_(purged_zone_ids))
    res = await db.execute(stmt.execution_options(include_deleted=True))
    return int(res.rowcount or 0)


async def _purge_dns_zones(db: Any, cutoff: datetime) -> tuple[int, int]:
    """Per-row purge for soft-deleted zones so the provider retraction gates the
    DB delete (#632).

    Zones are the one DNS object never retracted at soft-delete — tearing down a
    hosted zone mints a new zone ID + NS records on any later restore, so the
    delete is deferred to here. That makes the purge the *sole* retraction point:
    a blind Core DELETE would leave the hosted zone live + billed forever with no
    DB trace. So push the teardown first and delete the row only when it lands;
    on failure leave the row soft-deleted and let the next daily sweep retry
    rather than orphan it. Runs AFTER the bulk record DELETE so the zone's FK
    CASCADE has nothing left to silently drop from the ``dns_record`` counter.

    ``_push_zone_to_agentless_servers`` is a no-op (no error) for a pure
    agent-based zone, so those purge normally. Returns ``(purged, skipped)``.
    ``include_deleted`` because these rows are soft-deleted by definition.

    Retry caveat (#632): the provider teardown is not transactional with the DB,
    and the cloud / Windows drivers raise "zone not found" on a delete of an
    already-absent zone (they resolve the provider zone-id first). So a zone that
    was partially torn down (one agentless member deleted, another failed) — or
    torn down just before a failed terminal ``_sweep`` commit — can stay
    ``skipped`` every later sweep, lingering soft-deleted rather than orphaning at
    the provider. That is the safe failure (the DB keeps the row; an operator can
    permanent-delete it). Making the drivers treat absent-on-delete as success —
    which also hardens the permanent zone-delete path — is the real fix, tracked
    separately.
    """
    from app.api.v1.dns.router import _push_zone_to_agentless_servers  # noqa: PLC0415
    from app.services.dns.record_ops import sweep_zone_ops  # noqa: PLC0415

    res = await db.execute(
        select(DNSZone)
        .where(DNSZone.deleted_at.is_not(None), DNSZone.deleted_at < cutoff)
        .execution_options(include_deleted=True)
    )
    purged = 0
    skipped = 0
    for zone in res.scalars().all():
        try:
            await _push_zone_to_agentless_servers(db, zone, "delete")
        except Exception as exc:  # noqa: BLE001 — best-effort; retry next sweep
            # A dead / rejecting provider must NOT let the row Core-DELETE (that
            # orphans the hosted zone forever). Leave it soft-deleted + logged;
            # the next daily sweep re-attempts the push.
            skipped += 1
            logger.warning(
                "trash_purge.zone_retract_failed",
                zone=zone.name,
                zone_id=str(zone.id),
                error=str(exc),
                hint="left soft-deleted; next daily sweep retries the provider push",
            )
            continue
        # Ops queued before the soft-delete started sweeping them (#964 review)
        # have no zone FK to cascade through; sweep defensively so a pre-fix
        # trash row does not leave a failed queue behind.
        await sweep_zone_ops(db, zone, zone.group_id)
        # Core DELETE (not ORM ``db.delete``) — leans on the DB-level FK ON
        # DELETE CASCADE to remove this zone's still-present soft-deleted records
        # (they were excluded from the record pass precisely so they'd ride this
        # delete, atomic with the teardown). An ORM delete would instead fire an
        # ``all, delete-orphan`` cascade lazy-load per zone — wasted work that
        # also couples correctness to the soft-delete filter hiding those rows.
        # ``include_deleted`` bypasses that filter so the WHERE matches this
        # tombstoned row.
        await db.execute(
            delete(DNSZone).where(DNSZone.id == zone.id).execution_options(include_deleted=True)
        )
        purged += 1
    if purged:
        await db.flush()
    return purged, skipped


async def _sweep() -> dict[str, Any]:
    async with task_session() as db:
        ps_res = await db.execute(select(PlatformSettings).limit(1))
        ps = ps_res.scalar_one_or_none()
        purge_days = 30
        if ps is not None:
            configured = getattr(ps, "soft_delete_purge_days", None)
            if isinstance(configured, int):
                purge_days = configured

        if purge_days <= 0:
            logger.info("trash_purge.disabled", purge_days=purge_days)
            return {"removed": 0, "purge_days": purge_days, "skipped": True}

        cutoff = datetime.now(UTC) - timedelta(days=purge_days)
        per_type: dict[str, int] = {}
        total_removed = 0

        # Release IPAM mirrors before the Core DELETEs wipe the reservations.
        ipam_released = await _release_ipam_mirrors(db, cutoff)

        # Zones about to be per-row purged — records inside them are retracted
        # by the zone teardown, so the record pre-pass skips them (#632).
        zid_res = await db.execute(
            select(DNSZone.id)
            .where(DNSZone.deleted_at.is_not(None), DNSZone.deleted_at < cutoff)
            .execution_options(include_deleted=True)
        )
        purged_zone_ids = set(zid_res.scalars().all())

        # Retract agentless records at the provider before their rows are removed
        # (#632); best-effort (see the helper's docstring).
        records_retracted = await _retract_records_from_providers(db, cutoff, purged_zone_ids)

        # Records purge explicitly (not via the generic loop) so those inside a
        # zone being purged this sweep are EXCLUDED — they ride that zone's own
        # delete + FK CASCADE, staying atomic with a teardown that might fail
        # (#632). Runs before the zone pass.
        per_type["dns_record"] = await _purge_dns_records(db, cutoff, purged_zone_ids)
        total_removed += per_type["dns_record"]

        # spatiumddi#1151 — the Subnet DELETE below cascades each purged
        # subnet's ip_address rows, and dns_record.ip_address_id is SET NULL:
        # withdraw the LIVE auto-generated records IPAM published for those
        # addresses first, or they stay in their zones, ownerless and served.
        # Selected by what the DELETE will destroy — the same predicate — and
        # no block / space pass can reach a subnet (its FKs are RESTRICT).
        from app.services.dns.record_ops import retract_address_records  # noqa: PLC0415

        purged_subnet_ids = (
            (
                await db.execute(
                    select(Subnet.id)
                    .where(Subnet.deleted_at.is_not(None), Subnet.deleted_at < cutoff)
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
        address_records_retracted, dns_wake_group_ids = await retract_address_records(
            db, purged_subnet_ids
        )

        for model in _PURGE_MODELS_LEAF_FIRST:
            stmt = (
                delete(model)
                .where(model.deleted_at.is_not(None))
                .where(model.deleted_at < cutoff)
                .execution_options(include_deleted=True)
            )
            res = await db.execute(stmt)
            removed = int(res.rowcount or 0)
            per_type[model.__tablename__] = removed
            total_removed += removed

        # Zones purge per-row AFTER the record DELETE so the provider teardown
        # gates each DB delete and (for excluded in-zone records) the CASCADE has
        # something to remove.
        zones_purged, zones_skipped = await _purge_dns_zones(db, cutoff)
        per_type["dns_zone"] = zones_purged
        total_removed += zones_purged

        if total_removed:
            db.add(
                AuditLog(
                    user_id=None,
                    user_display_name="system",
                    auth_source="system",
                    action="purge",
                    resource_type="trash",
                    resource_id="sweep",
                    resource_display=f"{total_removed} rows purged",
                    new_value={
                        "counts": per_type,
                        "purge_days": purge_days,
                        "ipam_mirrors_released": ipam_released,
                        "records_retracted_at_provider": records_retracted,
                        "address_records_retracted": address_records_retracted,
                        "zones_retract_skipped": zones_skipped,
                    },
                    result="success",
                )
            )
        await db.commit()
        # The ops above are committed; wake the agents rather than leave the
        # withdrawal to their safety tick (a task has no request collector).
        for gid in dns_wake_group_ids:
            await publish_wake(dns_group_channel(gid))

        return {
            "removed": total_removed,
            "per_type": per_type,
            "ipam_mirrors_released": ipam_released,
            "records_retracted_at_provider": records_retracted,
            "address_records_retracted": address_records_retracted,
            "zones_retract_skipped": zones_skipped,
            "purge_days": purge_days,
            "skipped": False,
        }


@celery_app.task(name="app.tasks.trash_purge.purge_expired_soft_deletes")
def purge_expired_soft_deletes() -> dict[str, Any]:
    result = asyncio.run(_sweep())
    logger.info("trash_purge.completed", **result)
    return result
