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
    ``dns_auto_sync_delete_stale`` is on — except a live address's own host
    record and PTR when its name is blank, which are always retracted (the
    address publishes nothing);
  * commits each subnet in batches of ``SYNC_BATCH_SIZE`` addresses, each
    batch locking the address rows it will write and then their zones
    (#3724), so a run holds one batch's locks at a time (a zone delete waits
    at most one batch) and a batch that fails is rolled back alone and
    reported, with its subnet and size, in the run's errors;
  * writes a single audit row per run with the run's totals.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_group_channel, publish_wake
from app.db import task_connect_args
from app.models.audit import AuditLog
from app.models.ipam import IPAddress, Subnet
from app.models.settings import PlatformSettings
from app.services.feature_modules import is_module_enabled
from app.tasks._interval_gate import interval_skip
from app.tasks.module_gate import module_gated

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


async def _reapply_ddns_for_active_leases(
    db: Any, subnet: Subnet, *, locked_ids: set[Any] | None = None
) -> tuple[int, list[str]]:
    """#428 — eventual-consistency net for DDNS-enabled subnets. Re-runs
    the DDNS policy for every active lease-mirrored row so a record that a
    swallowed inline ``apply_ddns_for_lease`` failure missed — including a
    generated ``dhcp-<a-b-c-d>`` name the hostname-driven drift check can't
    see — gets regenerated. Idempotent: ``apply_ddns_for_lease`` skips a
    row whose hostname is unchanged and already published under that name.
    ``locked_ids`` are the rows the caller has already locked, addresses
    then zones (#3724); only those are re-applied, so a mirror created since
    is not written after a zone is held. Without it the subnet's mirrors are
    locked here first.

    Returns (records_fired, errors)."""
    from app.api.v1.ipam.router import _lock_dns_sync_rows  # noqa: PLC0415
    from app.services.dns.ddns import apply_ddns_for_lease  # noqa: PLC0415

    if locked_ids is None:
        locked_ids = set(
            await _lock_dns_sync_rows(
                db,
                await _auto_from_lease_ip_ids(db, subnet.id),
                ddns=True,
                restrict_subnet_id=subnet.id,
            )
        )
    ordered = sorted(locked_ids)
    rows: list[IPAddress] = []
    for i in range(0, len(ordered), 1000):
        res = await db.execute(
            select(IPAddress)
            .where(
                IPAddress.id.in_(ordered[i : i + 1000]),
                IPAddress.subnet_id == subnet.id,
                IPAddress.auto_from_lease.is_(True),
            )
            .order_by(IPAddress.id)
        )
        rows.extend(res.scalars().all())
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


# #3724 — addresses per auto-sync transaction. A batch holds its address rows
# (and then their zones) until it commits, and a permanent zone delete that
# meets one waits for it, so the batch must finish well inside the API's 30 s
# statement timeout. On the appliance a rename costs ~0.11 s (1,000 of them
# took 105-120 s), so 100 addresses is ~11 s: under the timeout with ~2.5x
# headroom for a slower box, where 200 (~22 s) would not have it.
SYNC_BATCH_SIZE = 100


def _first_line(exc: BaseException) -> str:
    """``Type: first line`` of an exception. A cancelled statement's message
    carries the whole SQL text and its parameters (~6 KB for a batch), which
    would fill the run's audit row."""
    lines = str(exc).strip().splitlines()
    return f"{type(exc).__name__}: {lines[0]}" if lines else type(exc).__name__


@dataclass
class _Unit:
    """One address's share of a subnet's auto-sync, or one orphan record.
    An address's records stay in one unit (so one batch): the apply holds back
    the records of an address that the request does not name."""

    create_ip_ids: list[Any] = field(default_factory=list)
    update_record_ids: list[Any] = field(default_factory=list)
    delete_record_ids: list[Any] = field(default_factory=list)
    mirror_ip_ids: list[Any] = field(default_factory=list)


async def _plan_subnet(db: Any, subnet_id: Any, *, delete_stale: bool) -> list[_Unit]:
    """A subnet's auto-sync work, read-only: one :class:`_Unit` per address
    (or orphan record) that needs a create, update, delete or DDNS re-apply,
    ordered by id. Locks nothing; each batch re-reads what it writes."""
    from app.services.dns.ddns import resolve_effective_ddns  # noqa: PLC0415
    from app.services.dns.sync_check import compute_subnet_dns_drift  # noqa: PLC0415

    subnet_obj = await db.get(Subnet, subnet_id)
    if subnet_obj is None:
        return []
    ddns_on = (await resolve_effective_ddns(db, subnet_obj)).enabled

    report = await compute_subnet_dns_drift(db, subnet_id)

    # #428 — honor the DDNS opt-in (Q1): when a subnet's DDNS is OFF, the
    # backstop must not publish lease-mirrored rows. Manual allocations still
    # sync regardless. (When DDNS is ON, the re-apply pass is the authority
    # for lease rows.)
    if not ddns_on and (report.missing or report.mismatched):
        lease_ip_ids = await _auto_from_lease_ip_ids(db, subnet_id)
        report.missing = [m for m in report.missing if m.ip_id not in lease_ip_ids]
        report.mismatched = [m for m in report.mismatched if m.ip_id not in lease_ip_ids]

    units: dict[Any, _Unit] = {}

    def unit(key: Any) -> _Unit:
        return units.setdefault(key, _Unit())

    for m in report.missing:
        unit(m.ip_id).create_ip_ids.append(m.ip_id)
    for mm in report.mismatched:
        unit(mm.ip_id).update_record_ids.append(mm.record_id)
    # A live address with no name publishes nothing, so its own host record
    # and PTR are retracted whatever ``dns_auto_sync_delete_stale`` says: that
    # setting governs records left behind by deleted or orphaned addresses,
    # not the withdrawal an address's own blank name asks for (the edit path
    # does the same when a name is cleared).
    for st in report.stale:
        if delete_stale or st.blank_name_host_record:
            unit(st.ip_id if st.ip_id is not None else st.record_id).delete_record_ids.append(
                st.record_id
            )
    if ddns_on:
        for ip_id in await _auto_from_lease_ip_ids(db, subnet_id):
            unit(ip_id).mirror_ip_ids.append(ip_id)
    return [units[k] for k in sorted(units, key=str)]


async def _sync_batch(
    db: Any,
    subnet_id: Any,
    batch: list[_Unit],
    *,
    errors: list[str],
) -> tuple[int, int, int, int]:
    """One batch of a subnet's auto-sync, uncommitted: lock the batch's
    address rows (ascending) and then their zones, run the DDNS re-apply for
    its lease mirrors and the drift apply for the rest. Returns
    (created, updated, deleted, ddns_reapplied); per-address failures go to
    ``errors``, anything else raises. Subnet and DDNS state are re-read here,
    so a zone or subnet removed since the plan writes nothing."""
    from app.api.v1.ipam.router import (  # noqa: PLC0415
        DnsSyncCommitRequest,
        _apply_dns_sync,
        _dns_sync_lock_targets,
        _lock_dns_sync_rows,
    )
    from app.services.dns.ddns import resolve_effective_ddns  # noqa: PLC0415

    subnet_obj = await db.get(Subnet, subnet_id)
    if subnet_obj is None:
        return 0, 0, 0, 0
    ddns_on = (await resolve_effective_ddns(db, subnet_obj)).enabled

    body = DnsSyncCommitRequest(
        create_for_ip_ids=[i for u in batch for i in u.create_ip_ids],
        update_record_ids=[i for u in batch for i in u.update_record_ids],
        delete_stale_record_ids=[i for u in batch for i in u.delete_record_ids],
    )
    # #2577 — the plan is this subnet's own, so the stale records it asks to
    # delete are what may be deleted.
    allowed_stale = list(body.delete_stale_record_ids)
    mirror_ids = {i for u in batch for i in u.mirror_ip_ids} if ddns_on else set()

    # #3724 — lock every row this batch will write (the re-apply's mirrors
    # and the drift apply's addresses, ascending, then all their zones,
    # ascending) before the first sync takes a zone. The zones' sync gates
    # go first (shared): a permanent zone delete takes them exclusive, so the
    # batch after the one it waits for queues behind it.
    lock_ids, lock_zones = await _dns_sync_lock_targets(db, body, allowed_stale_ids=allowed_stale)
    locked = set(
        await _lock_dns_sync_rows(
            db,
            lock_ids | mirror_ids,
            zone_ids=lock_zones,
            ddns=ddns_on,
            restrict_subnet_id=subnet_id,
            gate_zones=True,
        )
    )

    # The subnet object is the one read before the locks, and its zone binding
    # may have been cleared by a zone delete this batch waited for: re-read it
    # now, or the re-apply publishes into a zone that is gone, counts the
    # rows as re-applied, and writes nothing.
    subnet_obj = await db.get(Subnet, subnet_id, populate_existing=True)
    if subnet_obj is None:
        return 0, 0, 0, 0

    reapplied = 0
    if ddns_on and mirror_ids:
        # #428 — eventual-consistency net (Q3): regenerate any lease DDNS
        # record a swallowed inline apply missed.
        reapplied, ddns_errors = await _reapply_ddns_for_active_leases(
            db, subnet_obj, locked_ids=locked & mirror_ids
        )
        errors.extend(ddns_errors)

    if not (body.create_for_ip_ids or body.update_record_ids or body.delete_stale_record_ids):
        return 0, 0, 0, reapplied

    created, updated, deleted, apply_errors = await _apply_dns_sync(
        db,
        body,
        allowed_stale_ids=allowed_stale,
        restrict_subnet_id=subnet_id,
        prelocked=True,
    )
    errors.extend(apply_errors)
    return created, updated, deleted, reapplied


async def _run_auto_sync() -> dict[str, Any]:
    # Imports are intentionally deferred so loading this module from the
    # Celery worker doesn't drag in the full FastAPI router graph at import
    # time — the router has its own side-effectful imports.
    from app.api.v1.ipam.router import _resolve_effective_dns  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
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
            skip = interval_skip(now, ps.dns_auto_sync_last_run_at, interval)
            if skip is not None:
                return skip

            # Only subnets with some DNS/DDNS binding do work (issue #522) —
            # skip the drift computation for the (common) no-binding majority.
            subnets = list((await db.execute(_CANDIDATE_SUBNET_SQL)).scalars().all())

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
            delete_stale = ps.dns_auto_sync_delete_stale
            for subnet_id in subnets:
                # #3724 — plan the subnet read-only, then commit it in batches
                # of SYNC_BATCH_SIZE addresses: a batch's row locks are held to
                # its commit, so a zone delete waits at most one batch, and the
                # next batch (or subnet) starts with none held (a lock taken
                # after another's zone would break the global order). A batch
                # that fails is rolled back alone, and only committed work is
                # counted.
                try:
                    units = await _plan_subnet(db, subnet_id, delete_stale=delete_stale)
                    await db.commit()
                except Exception as exc:  # noqa: BLE001 — one subnet must not poison the run
                    await db.rollback()
                    errors.append(f"subnet({subnet_id}): {_first_line(exc)}")
                    continue
                n_batches = -(-len(units) // SYNC_BATCH_SIZE)
                for k in range(n_batches):
                    batch = units[k * SYNC_BATCH_SIZE : (k + 1) * SYNC_BATCH_SIZE]
                    batch_errors: list[str] = []
                    try:
                        counts = await _sync_batch(db, subnet_id, batch, errors=batch_errors)
                        await db.commit()
                    except Exception as exc:  # noqa: BLE001 — one batch must not poison the run
                        await db.rollback()
                        errors.extend(batch_errors)
                        errors.append(
                            f"subnet({subnet_id}) batch {k + 1}/{n_batches} "
                            f"({len(batch)} addresses): {_first_line(exc)}"
                        )
                        continue
                    errors.extend(batch_errors)
                    created, updated, deleted, reapplied = counts
                    total_created += created + reapplied
                    total_updated += updated
                    total_deleted += deleted
                    total_ddns_reapplied += reapplied
                    if created or updated or deleted or reapplied:
                        touched_subnet_ids.add(subnet_id)

            # Dedup-accurate count (a subnet touched by both the drift sync
            # and the DDNS re-apply is one touched subnet, #428).
            subnets_touched = len(touched_subnet_ids)
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is not None:
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
@module_gated("core.dns")
def auto_sync_ipam_dns(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Celery beat entrypoint — fires every 60 s; the task itself checks
    the platform-settings gate and the per-run interval."""
    try:
        return asyncio.run(_run_auto_sync())
    except Exception as exc:  # noqa: BLE001
        logger.exception("ipam_dns_auto_sync_failed", error=str(exc))
        raise


# ── #3787 — DDNS for the lease mirrors a restore brings back ───────────────


async def active_lease_mirror_ids(db: Any, subnet_id: Any) -> list[Any]:
    """IDs of a subnet's lease-mirrored IPAM rows whose lease is still active
    and unexpired, in a live scope of the subnet. A subnet delete withdraws the
    A / PTR of the mirrors its scopes' teardown has yet to remove (#3744, so
    the stamp does not trash them); a restore that brings the lease back owes
    those mirrors their records. Ascending, for the lock order."""
    from sqlalchemy import and_, exists, or_  # noqa: PLC0415

    from app.models.dhcp import DHCPLease, DHCPScope  # noqa: PLC0415

    now = datetime.now(UTC)
    live_lease = (
        select(DHCPLease.id)
        .join(DHCPScope, DHCPScope.id == DHCPLease.scope_id)
        .where(
            DHCPScope.subnet_id == subnet_id,
            DHCPScope.deleted_at.is_(None),
            DHCPLease.ip_address == IPAddress.address,
            DHCPLease.state == "active",
            or_(DHCPLease.expires_at.is_(None), DHCPLease.expires_at > now),
        )
    )
    rows = await db.execute(
        select(IPAddress.id)
        .where(
            and_(
                IPAddress.subnet_id == subnet_id,
                IPAddress.auto_from_lease.is_(True),
                exists(live_lease),
            )
        )
        .order_by(IPAddress.id)
    )
    return list(rows.scalars().all())


async def republish_restored_lease_ddns(db: Any, subnet_ids: list[Any]) -> tuple[int, set[Any]]:
    """Re-run the DDNS policy for the active lease mirrors of ``subnet_ids``
    (the subnets a Trash restore brought back), ``SYNC_BATCH_SIZE`` addresses
    per transaction, address rows then zones locked first as the auto-sync does
    (#3724). Idempotent: a mirror whose records are already published is
    skipped, and a subnet whose effective DDNS is off publishes nothing.
    Commits per batch; a failed batch is rolled back and logged alone. Returns
    ``(records_fired, dns_group_ids_to_wake)``."""
    from app.api.v1.ipam.router import _lock_dns_sync_rows, _resolve_effective_dns  # noqa: PLC0415
    from app.services.dns.ddns import resolve_effective_ddns  # noqa: PLC0415

    fired = 0
    wake: set[Any] = set()
    for subnet_id in subnet_ids:
        subnet = await db.get(Subnet, subnet_id)
        if subnet is None or not (await resolve_effective_ddns(db, subnet)).enabled:
            await db.rollback()
            continue
        ids = await active_lease_mirror_ids(db, subnet_id)
        await db.rollback()
        for i in range(0, len(ids), SYNC_BATCH_SIZE):
            try:
                locked = set(
                    await _lock_dns_sync_rows(
                        db,
                        ids[i : i + SYNC_BATCH_SIZE],
                        ddns=True,
                        restrict_subnet_id=subnet_id,
                        gate_zones=True,
                    )
                )
                # Re-read under the locks: a zone delete this batch waited for
                # may have cleared the subnet's zone binding.
                subnet = await db.get(Subnet, subnet_id, populate_existing=True)
                if subnet is None:
                    await db.rollback()
                    break
                n, errors = await _reapply_ddns_for_active_leases(db, subnet, locked_ids=locked)
                if n:
                    group_ids, _, _ = await _resolve_effective_dns(db, subnet)
                    wake.update(group_ids)
                await db.commit()
                fired += n
                for err in errors:
                    logger.warning("restore_ddns_republish_failed", error=err)
            except Exception as exc:  # noqa: BLE001 — one batch must not stop the rest
                await db.rollback()
                logger.warning(
                    "restore_ddns_republish_batch_failed",
                    subnet=str(subnet_id),
                    size=len(ids[i : i + SYNC_BATCH_SIZE]),
                    error=_first_line(exc),
                )
    return fired, wake


async def _run_republish_restored(subnet_ids: list[str]) -> dict[str, Any]:
    import uuid  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            fired, wake = await republish_restored_lease_ddns(
                db, [uuid.UUID(s) for s in subnet_ids]
            )
        for gid in wake:
            await publish_wake(dns_group_channel(gid))
        return {"status": "ok", "records_fired": fired}
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.ipam_dns_sync.republish_restored_lease_ddns", bind=True)
@module_gated("core.dns")
def republish_restored_lease_ddns_task(  # type: ignore[type-arg]
    self: object, subnet_ids: list[str]
) -> dict[str, Any]:
    """#3787 — post-commit follow-up of a Trash restore of a subnet, block,
    space or scope: re-publish the A / PTR of the lease mirrors it brought back."""
    try:
        return asyncio.run(_run_republish_restored(subnet_ids))
    except Exception as exc:  # noqa: BLE001
        logger.exception("restore_ddns_republish_failed", error=str(exc))
        raise
