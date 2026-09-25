"""TLS certificate monitoring tasks (issue #118).

Three beat-driven tasks:

* :func:`probe_due_certs` — 60 s tick; probes every enabled target whose
  ``next_check_at`` has elapsed (default cadence
  ``PlatformSettings.tls_cert_check_interval_hours`` = 6 h, read every run
  so UI changes take effect without restarting beat; per-target override
  via ``tls_cert_target.interval_hours``). Per-row isolation — one bad
  endpoint never poisons the sweep. Per-row audit only on a meaningful
  change; one summary audit per sweep.
* :func:`reconcile_discovered` — 5 min tick; projects probe targets from
  opted-in DNS A/AAAA records + relinks targets to zones/domains by SAN.
* :func:`prune_probes` — daily; drops ``tls_cert_probe`` rows older than
  the retention window (the latest cert identity is denormalised onto the
  target, so pruning all old probe history is safe).

All idempotent. Network probe failures are recorded as data
(``state='unreachable'``) by the probe service, not raised, so they never
trigger Celery autoretry.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import delete, or_, select
from sqlalchemy.dialects.postgresql import distinct_on

from app.celery_app import celery_app
from app.db import task_session
from app.models.audit import AuditLog
from app.models.settings import PlatformSettings
from app.models.tls_cert import TLSCertProbe, TLSCertTarget
from app.services.ipam.probe_policy import check_probe_target
from app.services.tls_cert.discovery import reconcile_discovered_targets
from app.services.tls_cert.probe import probe_one

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1
_MIN_INTERVAL_HOURS = 1
_MAX_INTERVAL_HOURS = 168
_DEFAULT_INTERVAL_HOURS = 6
_PROBE_RETENTION_DAYS = 90
# Defensive cap on probes per sweep so a sudden flood of new targets can't
# blow a single 60 s tick into a multi-minute network stall.
_MAX_PROBES_PER_SWEEP = 200


def _clamp_interval(hours: int | None) -> int:
    if hours is None or hours < _MIN_INTERVAL_HOURS:
        return _DEFAULT_INTERVAL_HOURS if hours is None else _MIN_INTERVAL_HOURS
    if hours > _MAX_INTERVAL_HOURS:
        return _MAX_INTERVAL_HOURS
    return hours


async def _probe_due_async() -> dict[str, Any]:
    async with task_session() as db:
        ps = await db.get(PlatformSettings, _SINGLETON_ID)
        interval = _clamp_interval(ps.tls_cert_check_interval_hours if ps is not None else None)
        now = datetime.now(UTC)

        rows = (
            (
                await db.execute(
                    select(TLSCertTarget)
                    .where(
                        TLSCertTarget.enabled.is_(True),
                        or_(
                            TLSCertTarget.next_check_at.is_(None),
                            TLSCertTarget.next_check_at <= now,
                        ),
                    )
                    .order_by(TLSCertTarget.next_check_at.asc().nulls_first())
                    .limit(_MAX_PROBES_PER_SWEEP)
                )
            )
            .scalars()
            .all()
        )

        scanned = changed = unreachable = 0
        suppressed = 0
        errors: list[str] = []
        for t in rows:
            label = t.display_name or t.host
            # Fragile-device suppression (#722). A TLS handshake is an
            # active probe like any other, and a BMC / imaging console
            # that answers 443 is exactly the class the flag protects.
            # Skipped silently — a scheduled sweep withheld on purpose is
            # not an error, and logging one per target every 6 h would
            # bury the real failures.
            if (await check_probe_target(db, t.host)).blocked:
                suppressed += 1
                continue
            try:
                result = await probe_one(db, t, default_interval_hours=interval, now=now)
                if not result.ok:
                    unreachable += 1
                if result.any_meaningful_change:
                    changed += 1
                    db.add(
                        AuditLog(
                            user_display_name="<system>",
                            auth_source="system",
                            action="probe",
                            resource_type="tls_cert",
                            resource_id=str(t.id),
                            resource_display=label,
                            result="success" if result.ok else "error",
                            new_value={
                                "state": result.state,
                                "ok": result.ok,
                                "fingerprint_changed": result.fingerprint_changed,
                                "chain_valid_changed": result.chain_valid_changed,
                                "error": result.error,
                            },
                        )
                    )
                await db.commit()
                scanned += 1
            except Exception as exc:  # noqa: BLE001 — isolate one bad row
                await db.rollback()
                errors.append(f"{label}: {exc}")
                logger.warning("tls_cert_probe_row_failed", target=label, error=str(exc))
                # Advance next_check_at in a fresh tx so a row that
                # repeatably *raises* (not a network failure, which probe_one
                # records as data) backs off instead of re-probing every tick.
                try:
                    fresh = await db.get(TLSCertTarget, t.id)
                    if fresh is not None:
                        fresh.last_checked_at = now
                        fresh.next_check_at = now + timedelta(hours=interval)
                        fresh.last_error = str(exc)
                        fresh.consecutive_failures = (fresh.consecutive_failures or 0) + 1
                        await db.commit()
                except Exception:  # noqa: BLE001
                    await db.rollback()

        if scanned and (changed or errors):
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="tls-cert-probe-sweep",
                    resource_type="platform",
                    resource_id=str(_SINGLETON_ID),
                    resource_display="auto-probe",
                    result="error" if errors else "success",
                    new_value={
                        "scanned": scanned,
                        "changed": changed,
                        "unreachable": unreachable,
                        "interval_hours": interval,
                        "errors": errors[:20],
                    },
                )
            )
            await db.commit()

        if scanned:
            logger.info(
                "tls_cert_probe_sweep_completed",
                scanned=scanned,
                changed=changed,
                unreachable=unreachable,
                interval_hours=interval,
                error_count=len(errors),
            )
        return {
            "status": "ran" if scanned else "idle",
            "scanned": scanned,
            "changed": changed,
            "unreachable": unreachable,
            "suppressed": suppressed,
            "interval_hours": interval,
            "errors": len(errors),
        }


@celery_app.task(name="app.tasks.tls_certs.probe_due_certs", bind=True)
def probe_due_certs(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    import asyncio  # noqa: PLC0415

    try:
        return asyncio.run(_probe_due_async())
    except Exception as exc:  # noqa: BLE001
        logger.exception("tls_cert_probe_sweep_failed", error=str(exc))
        raise


async def _reconcile_async() -> dict[str, Any]:
    async with task_session() as db:
        result = await reconcile_discovered_targets(db)
        await db.commit()
        return {"status": "ran", **result}


@celery_app.task(name="app.tasks.tls_certs.reconcile_discovered", bind=True)
def reconcile_discovered(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    import asyncio  # noqa: PLC0415

    try:
        return asyncio.run(_reconcile_async())
    except Exception as exc:  # noqa: BLE001
        logger.exception("tls_cert_discovery_failed", error=str(exc))
        raise


async def _prune_async() -> dict[str, Any]:
    async with task_session() as db:
        cutoff = datetime.now(UTC) - timedelta(days=_PROBE_RETENTION_DAYS)
        # Keep each target's most-recent successful probe regardless of age,
        # so the /chain endpoint + history aren't left empty for a target
        # that hasn't been re-probed in >90d (e.g. a disabled one).
        keep_ids = list(
            (
                await db.execute(
                    select(TLSCertProbe.id)
                    .ext(distinct_on(TLSCertProbe.target_id))
                    .where(TLSCertProbe.ok.is_(True))
                    .order_by(TLSCertProbe.target_id, TLSCertProbe.probed_at.desc())
                )
            )
            .scalars()
            .all()
        )
        stmt = delete(TLSCertProbe).where(TLSCertProbe.probed_at < cutoff)
        if keep_ids:
            stmt = stmt.where(TLSCertProbe.id.not_in(keep_ids))
        res = await db.execute(stmt)
        await db.commit()
        deleted = res.rowcount or 0
        if deleted:
            logger.info("tls_cert_probe_prune_completed", deleted=deleted)
        return {"status": "ran", "deleted": deleted}


@celery_app.task(name="app.tasks.tls_certs.prune_probes", bind=True)
def prune_probes(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    import asyncio  # noqa: PLC0415

    try:
        return asyncio.run(_prune_async())
    except Exception as exc:  # noqa: BLE001
        logger.exception("tls_cert_probe_prune_failed", error=str(exc))
        raise


# Dispatched right after a target is created (router) so the first probe
# lands within seconds instead of waiting for the next sweep.
async def _probe_one_by_id_async(target_id: str) -> dict[str, Any]:
    import uuid  # noqa: PLC0415

    async with task_session() as db:
        t = await db.get(TLSCertTarget, uuid.UUID(target_id))
        if t is None:
            return {"status": "missing", "target_id": target_id}
        # Same gate as the sweep (#722) — this fires on target create, so
        # without it the very first probe of a flagged host still goes out.
        verdict = await check_probe_target(db, t.host)
        if verdict.blocked:
            return {"status": "suppressed", "reason": verdict.reason, "source": verdict.source}
        ps = await db.get(PlatformSettings, _SINGLETON_ID)
        interval = _clamp_interval(ps.tls_cert_check_interval_hours if ps is not None else None)
        result = await probe_one(db, t, default_interval_hours=interval)
        await db.commit()
        return {"status": "ran", "state": result.state, "ok": result.ok}


@celery_app.task(name="app.tasks.tls_certs.probe_one_target_by_id", bind=True)
def probe_one_target_by_id(self: object, target_id: str) -> dict[str, Any]:  # type: ignore[type-arg]
    import asyncio  # noqa: PLC0415

    try:
        return asyncio.run(_probe_one_by_id_async(target_id))
    except Exception as exc:  # noqa: BLE001
        logger.exception("tls_cert_probe_one_failed", target_id=target_id, error=str(exc))
        raise


__all__ = ["probe_due_certs", "reconcile_discovered", "prune_probes"]
