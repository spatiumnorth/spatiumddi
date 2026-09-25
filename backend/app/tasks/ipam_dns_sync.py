"""Periodic IPAM ↔ DNS reconciliation task.

Fired every 60 seconds by Celery Beat. The task itself is a fast no-op when
``PlatformSettings.dns_auto_sync_enabled`` is False or when the configured
interval hasn't elapsed since the last run — this keeps the beat schedule
static while allowing the user to change the run cadence from the UI.

Scope per run:
  * iterates every ``Subnet`` that has an effective forward or reverse DNS
    zone (``compute_subnet_dns_drift`` early-returns on the rest);
  * creates records for every "missing" row and updates every "mismatched"
    row using the existing ``_sync_dns_record`` helper (so the auto-sync
    path and the manual commit path stay bit-identical);
  * optionally deletes auto-generated "stale" records when
    ``dns_auto_sync_delete_stale`` is on;
  * writes a single audit row per run with a per-subnet tally.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_group_channel, publish_wake
from app.models.audit import AuditLog
from app.models.ipam import IPAddress, Subnet
from app.models.settings import PlatformSettings
from app.services.feature_modules import is_module_enabled

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1

# Pre-filter (issue #522): only subnets that could resolve an effective DNS
# zone/group — or fire DDNS — do any work inside ``compute_subnet_dns_drift``
# / the DDNS re-apply. Walking every subnet ran the (multi-query) drift
# computation for subnets with no DNS binding anywhere in their inheritance
# chain, which is the common case on integration-mirrored / lab spaces.
#
# This returns a deliberate SUPERSET of the truly-eligible set — including a
# subnet that turns out to resolve no zone is behaviour-preserving (the drift
# computation early-returns empty for it, exactly as before); EXCLUDING one
# that would resolve a zone would change behaviour, so we never do that. A
# subnet is a candidate when ANY of these carries a binding:
#   * the subnet's own dns_zone_id / dns_group_ids / dns_additional_zone_ids,
#     or ddns_enabled;
#   * any ancestor block (or the subnet's own block) carries one — captured
#     via the recursive descendant walk from every DNS/DDNS-bearing block;
#   * the containing IPSpace carries one;
#   * a reverse DNSZone is linked to the subnet.
# The inherit flags are intentionally ignored here (over-inclusion is safe);
# ``_resolve_effective_dns`` / ``resolve_effective_ddns`` remain the source of
# truth for what a candidate actually publishes.
_CANDIDATE_SUBNET_SQL = text("""
    WITH RECURSIVE dns_block AS (
        SELECT id FROM ip_block
        WHERE deleted_at IS NULL
          AND (
            dns_zone_id IS NOT NULL
            OR (dns_group_ids IS NOT NULL AND dns_group_ids <> '[]'::jsonb)
            OR (dns_additional_zone_ids IS NOT NULL
                AND dns_additional_zone_ids <> '[]'::jsonb)
            OR ddns_enabled = true
          )
    ),
    dns_block_subtree AS (
        SELECT id FROM dns_block
        UNION
        SELECT b.id FROM ip_block b
            JOIN dns_block_subtree t ON b.parent_block_id = t.id
        WHERE b.deleted_at IS NULL
    )
    SELECT s.id
    FROM subnet s
    JOIN ip_space sp ON sp.id = s.space_id
    WHERE s.deleted_at IS NULL
      AND (
        s.block_id IN (SELECT id FROM dns_block_subtree)
        OR s.dns_zone_id IS NOT NULL
        OR (s.dns_group_ids IS NOT NULL AND s.dns_group_ids <> '[]'::jsonb)
        OR (s.dns_additional_zone_ids IS NOT NULL
            AND s.dns_additional_zone_ids <> '[]'::jsonb)
        OR s.ddns_enabled = true
        OR sp.dns_zone_id IS NOT NULL
        OR (sp.dns_group_ids IS NOT NULL AND sp.dns_group_ids <> '[]'::jsonb)
        OR (sp.dns_additional_zone_ids IS NOT NULL
            AND sp.dns_additional_zone_ids <> '[]'::jsonb)
        OR sp.ddns_enabled = true
        OR EXISTS (
            SELECT 1 FROM dns_zone z
            WHERE z.linked_subnet_id = s.id AND z.kind = 'reverse'
        )
      )
""")


async def _auto_from_lease_ip_ids(db: Any, subnet_id: Any) -> set[Any]:
    """IDs of the DHCP-lease-mirrored IPAM rows in a subnet (#428). The
    backstop uses this to honor the DDNS opt-in: lease-mirrored rows are
    only DNS-published when the subnet has DDNS enabled — manual
    allocations always sync."""
    rows = await db.execute(
        select(IPAddress.id).where(
            IPAddress.subnet_id == subnet_id,
            IPAddress.auto_from_lease.is_(True),
        )
    )
    return set(rows.scalars().all())


async def _reapply_ddns_for_active_leases(db: Any, subnet: Subnet) -> tuple[int, list[str]]:
    """#428 — eventual-consistency net for DDNS-enabled subnets. Re-runs
    the DDNS policy for every active lease-mirrored row so a record that a
    swallowed inline ``apply_ddns_for_lease`` failure missed — including a
    generated ``dhcp-<x-y>`` name the hostname-driven drift check can't
    see — gets regenerated. Idempotent: ``apply_ddns_for_lease`` skips a
    row whose hostname is unchanged and already has a linked record.
    Returns (records_fired, errors)."""
    from app.services.dns.ddns import apply_ddns_for_lease  # noqa: PLC0415

    rows = (
        (
            await db.execute(
                select(IPAddress).where(
                    IPAddress.subnet_id == subnet.id,
                    IPAddress.auto_from_lease.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    fired = 0
    errors: list[str] = []
    for row in rows:
        try:
            if await apply_ddns_for_lease(
                db, subnet=subnet, ipam_row=row, client_hostname=row.hostname or None
            ):
                fired += 1
        except Exception as exc:  # noqa: BLE001 — one lease must not poison the run
            errors.append(f"ddns-reapply({subnet.id}/{row.address}): {exc}")
    return fired, errors


async def _run_auto_sync() -> dict[str, Any]:
    # Imports are intentionally deferred so loading this module from the
    # Celery worker doesn't drag in the full FastAPI router graph at import
    # time — the router has its own side-effectful imports.
    from app.api.v1.ipam.router import (
        DnsSyncCommitRequest,  # noqa: PLC0415
        _apply_dns_sync,  # noqa: PLC0415
        _resolve_effective_dns,  # noqa: PLC0415
    )
    from app.services.dns.ddns import resolve_effective_ddns  # noqa: PLC0415
    from app.services.dns.sync_check import compute_subnet_dns_drift  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                return {"status": "disabled"}
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is None or not ps.dns_auto_sync_enabled:
                return {"status": "disabled"}

            now = datetime.now(UTC)
            interval = timedelta(minutes=max(1, ps.dns_auto_sync_interval_minutes))
            if ps.dns_auto_sync_last_run_at is not None:
                elapsed = now - ps.dns_auto_sync_last_run_at
                if elapsed < interval:
                    return {
                        "status": "skipped",
                        "reason": "interval_not_elapsed",
                        "wait_seconds": int((interval - elapsed).total_seconds()),
                    }

            # Only subnets with some DNS/DDNS binding do work (issue #522) —
            # skip the drift computation for the (common) no-binding majority.
            subnets: list[uuid.UUID] = list(
                (await db.execute(_CANDIDATE_SUBNET_SQL)).scalars().all()
            )

            total_created = 0
            total_updated = 0
            total_deleted = 0
            errors: list[str] = []
            subnets_touched = 0
            # Subnets whose records actually changed this run — used after the
            # commit to wake the parked agent long-polls for the affected DNS
            # groups (worker process: no request collector, publish directly).
            touched_subnet_ids: set[Any] = set()

            total_ddns_reapplied = 0
            for subnet_id in subnets:
                subnet_obj = await db.get(Subnet, subnet_id)
                if subnet_obj is None:
                    continue
                ddns_on = (await resolve_effective_ddns(db, subnet_obj)).enabled

                try:
                    report = await compute_subnet_dns_drift(db, subnet_id)
                except Exception as exc:  # noqa: BLE001 — never let one subnet poison the run
                    errors.append(f"drift({subnet_id}): {exc}")
                    continue

                # #428 — honor the DDNS opt-in (Q1): when a subnet's DDNS is
                # OFF, the backstop must not publish lease-mirrored rows.
                # Manual allocations still sync regardless. (When DDNS is ON,
                # the re-apply pass below is the authority for lease rows.)
                if not ddns_on and (report.missing or report.mismatched):
                    lease_ip_ids = await _auto_from_lease_ip_ids(db, subnet_id)
                    report.missing = [m for m in report.missing if m.ip_id not in lease_ip_ids]
                    report.mismatched = [
                        m for m in report.mismatched if m.ip_id not in lease_ip_ids
                    ]

                # #428 — eventual-consistency net (Q3): regenerate any lease
                # DDNS record a swallowed inline apply missed.
                if ddns_on:
                    fired, ddns_errors = await _reapply_ddns_for_active_leases(db, subnet_obj)
                    total_ddns_reapplied += fired
                    errors.extend(ddns_errors)
                    if fired:
                        total_created += fired
                        touched_subnet_ids.add(subnet_id)

                if (
                    not report.missing
                    and not report.mismatched
                    and not (ps.dns_auto_sync_delete_stale and report.stale)
                ):
                    continue

                body = DnsSyncCommitRequest(
                    create_for_ip_ids=[m.ip_id for m in report.missing],
                    update_record_ids=[m.record_id for m in report.mismatched],
                    delete_stale_record_ids=(
                        [s.record_id for s in report.stale] if ps.dns_auto_sync_delete_stale else []
                    ),
                )
                try:
                    created, updated, deleted, subnet_errors = await _apply_dns_sync(
                        db, body, restrict_subnet_id=subnet_id
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"apply({subnet_id}): {exc}")
                    continue

                total_created += created
                total_updated += updated
                total_deleted += deleted
                errors.extend(subnet_errors)
                if created or updated or deleted:
                    touched_subnet_ids.add(subnet_id)

            # Dedup-accurate count (a subnet touched by both the drift sync
            # and the DDNS re-apply is one touched subnet, #428).
            subnets_touched = len(touched_subnet_ids)
            ps.dns_auto_sync_last_run_at = now

            if total_created or total_updated or total_deleted or errors:
                db.add(
                    AuditLog(
                        user_display_name="<system>",
                        auth_source="system",
                        action="dns-sync",
                        resource_type="platform",
                        resource_id=str(_SINGLETON_ID),
                        resource_display="auto-sync",
                        result="success" if not errors else "error",
                        new_value={
                            "created": total_created,
                            "updated": total_updated,
                            "deleted": total_deleted,
                            "ddns_reapplied": total_ddns_reapplied,
                            "subnets_touched": subnets_touched,
                            "subnets_scanned": len(subnets),
                            "errors": errors[:20],
                        },
                    )
                )
            # Resolve the DNS groups whose zones received records this run.
            # Done BEFORE commit (read-only inheritance walk on the live
            # session) but published AFTER, per the wake contract.
            wake_group_ids: set[str] = set()
            for sid in touched_subnet_ids:
                sn = await db.get(Subnet, sid)
                if sn is None:
                    continue
                group_ids, _, _ = await _resolve_effective_dns(db, sn)
                wake_group_ids.update(group_ids)

            await db.commit()

            for gid in wake_group_ids:
                await publish_wake(dns_group_channel(gid))

            logger.info(
                "ipam_dns_auto_sync_completed",
                created=total_created,
                updated=total_updated,
                deleted=total_deleted,
                subnets_touched=subnets_touched,
                subnets_scanned=len(subnets),
                error_count=len(errors),
            )
            return {
                "status": "ran",
                "created": total_created,
                "updated": total_updated,
                "deleted": total_deleted,
                "ddns_reapplied": total_ddns_reapplied,
                "subnets_touched": subnets_touched,
                "subnets_scanned": len(subnets),
                "errors": len(errors),
            }
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.ipam_dns_sync.auto_sync_ipam_dns", bind=True)
def auto_sync_ipam_dns(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Celery beat entrypoint — fires every 60 s; the task itself checks
    the platform-settings gate and the per-run interval."""
    try:
        return asyncio.run(_run_auto_sync())
    except Exception as exc:  # noqa: BLE001
        logger.exception("ipam_dns_auto_sync_failed", error=str(exc))
        raise
