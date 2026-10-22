"""Active block-sync convergence tasks (#601).

* ``sweep_block_sync`` — beat-driven fan-out over every armed OPNsense /
  UniFi / Palo Alto PAN-OS / Cisco Meraki target. Gated on the ``security.block_sync``
  feature module (the discovery/master gate) — each target additionally
  carries its own ``block_sync_enabled`` switch (enforced in the reconciler).
* ``reconcile_target_now`` — fired immediately after a block is created /
  lifted / a target is armed, so enforcement converges within seconds
  instead of waiting for the next sweep tick.

Idempotent (NN#9): re-running converges to the same device state.
"""

from __future__ import annotations

import asyncio
import uuid as _uuid
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.models.meraki import MerakiOrg
from app.models.opnsense import OPNsenseRouter
from app.models.panos import PANOSFirewall
from app.models.unifi import UnifiController
from app.services.feature_modules import is_module_enabled
from app.services.integration_sync_failure import record_sync_crash

logger = structlog.get_logger(__name__)

_MODULE_ID = "security.block_sync"


async def _run_sweep() -> dict[str, Any]:
    from app.services.block_sync.reconcile import (  # noqa: PLC0415
        armed_targets,
        reconcile_meraki,
        reconcile_opnsense,
        reconcile_panos,
        reconcile_unifi,
    )

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            if not await is_module_enabled(db, _MODULE_ID):
                return {"status": "disabled"}

            routers, controllers, firewalls, orgs = await armed_targets(db)
            router_ids = [r.id for r in routers]
            controller_ids = [c.id for c in controllers]
            firewall_ids = [f.id for f in firewalls]
            org_ids = [o.id for o in orgs]

            ran = ok = errors = 0
            messages: list[str] = []

            for rid in router_ids:
                router = await db.get(OPNsenseRouter, rid)
                if router is None:
                    continue
                try:
                    summary = await reconcile_opnsense(db, router)
                    await db.commit()
                except Exception as exc:  # noqa: BLE001 — one target can't poison the sweep
                    await db.rollback()
                    errors += 1
                    crash = await record_sync_crash(
                        db,
                        OPNsenseRouter,
                        rid,
                        resource_type="opnsense_router",
                        action="block_sync_push",
                        exc=exc,
                        error_field="last_block_sync_error",
                        stamp_field="last_block_sync_at",
                    )
                    messages.append(f"{rid}: {crash}")
                    logger.warning("block_sync_opnsense_crash", target=str(rid), error=str(exc))
                    continue
                ran += 1
                ok += 1 if summary.ok else 0
                errors += 0 if summary.ok else 1
                if summary.error:
                    messages.append(f"opnsense {router.name}: {summary.error}")

            for cid in controller_ids:
                controller = await db.get(UnifiController, cid)
                if controller is None:
                    continue
                try:
                    summary = await reconcile_unifi(db, controller)
                    await db.commit()
                except Exception as exc:  # noqa: BLE001
                    await db.rollback()
                    errors += 1
                    crash = await record_sync_crash(
                        db,
                        UnifiController,
                        cid,
                        resource_type="unifi_controller",
                        action="block_sync_push",
                        exc=exc,
                        error_field="last_block_sync_error",
                        stamp_field="last_block_sync_at",
                    )
                    messages.append(f"{cid}: {crash}")
                    logger.warning("block_sync_unifi_crash", target=str(cid), error=str(exc))
                    continue
                ran += 1
                ok += 1 if summary.ok else 0
                errors += 0 if summary.ok else 1
                if summary.error:
                    messages.append(f"unifi {controller.name}: {summary.error}")

            for fid in firewall_ids:
                fw = await db.get(PANOSFirewall, fid)
                if fw is None:
                    continue
                try:
                    summary = await reconcile_panos(db, fw)
                    await db.commit()
                except Exception as exc:  # noqa: BLE001
                    await db.rollback()
                    errors += 1
                    crash = await record_sync_crash(
                        db,
                        PANOSFirewall,
                        fid,
                        resource_type="panos_firewall",
                        action="block_sync_push",
                        exc=exc,
                        error_field="last_block_sync_error",
                        stamp_field="last_block_sync_at",
                    )
                    messages.append(f"{fid}: {crash}")
                    logger.warning("block_sync_panos_crash", target=str(fid), error=str(exc))
                    continue
                ran += 1
                ok += 1 if summary.ok else 0
                errors += 0 if summary.ok else 1
                if summary.error:
                    messages.append(f"paloalto {fw.name}: {summary.error}")

            for oid in org_ids:
                org = await db.get(MerakiOrg, oid)
                if org is None:
                    continue
                try:
                    summary = await reconcile_meraki(db, org)
                    await db.commit()
                except Exception as exc:  # noqa: BLE001
                    await db.rollback()
                    errors += 1
                    crash = await record_sync_crash(
                        db,
                        MerakiOrg,
                        oid,
                        resource_type="meraki_org",
                        action="block_sync_push",
                        exc=exc,
                        error_field="last_block_sync_error",
                        stamp_field="last_block_sync_at",
                    )
                    messages.append(f"{oid}: {crash}")
                    logger.warning("block_sync_meraki_crash", target=str(oid), error=str(exc))
                    continue
                ran += 1
                ok += 1 if summary.ok else 0
                errors += 0 if summary.ok else 1
                if summary.error:
                    messages.append(f"meraki {org.name}: {summary.error}")

            return {
                "status": "ok",
                "ran": ran,
                "ok": ok,
                "errors": errors,
                "messages": messages[:20],
            }
    finally:
        await engine.dispose()


async def _run_one(target_kind: str, target_id: str) -> dict[str, Any]:
    from app.services.block_sync.reconcile import (  # noqa: PLC0415
        reconcile_meraki,
        reconcile_opnsense,
        reconcile_panos,
        reconcile_unifi,
    )

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            if not await is_module_enabled(db, _MODULE_ID):
                return {"status": "disabled"}
            tid = _uuid.UUID(target_id)
            targets: dict[str, tuple[type[Any], str, Any]] = {
                "opnsense": (OPNsenseRouter, "opnsense_router", reconcile_opnsense),
                "unifi": (UnifiController, "unifi_controller", reconcile_unifi),
                "paloalto": (PANOSFirewall, "panos_firewall", reconcile_panos),
                "meraki": (MerakiOrg, "meraki_org", reconcile_meraki),
            }
            if target_kind not in targets:
                return {"status": "bad_target_kind"}
            model, resource_type, reconcile = targets[target_kind]
            target = await db.get(model, tid)
            if target is None:
                return {"status": "not_found"}
            try:
                summary = await reconcile(db, target)
            except Exception as exc:  # noqa: BLE001 — record it, don't lose it (#2141)
                await db.rollback()
                crash = await record_sync_crash(
                    db,
                    model,
                    tid,
                    resource_type=resource_type,
                    action="block_sync_push",
                    exc=exc,
                    error_field="last_block_sync_error",
                    stamp_field="last_block_sync_at",
                )
                logger.warning("block_sync_now_crash", target=str(tid), error=crash)
                return {"status": "error", "error": crash}
            await db.commit()
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "added": summary.added,
                "removed": summary.removed,
                "errors": summary.errors,
            }
    finally:
        await engine.dispose()


async def _run_lift(target_kind: str, target_id: str) -> dict[str, Any]:
    """Disarm cleanup — lift everything pushed to a target. NOT gated on the
    feature module or the per-target switch (the target is being disarmed;
    leaving its blocks stuck on the device is the bug we're fixing)."""
    from app.services.block_sync.reconcile import lift_all_for_target  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            tid = _uuid.UUID(target_id)
            target: OPNsenseRouter | UnifiController | PANOSFirewall | MerakiOrg | None
            if target_kind == "opnsense":
                target = await db.get(OPNsenseRouter, tid)
            elif target_kind == "unifi":
                target = await db.get(UnifiController, tid)
            elif target_kind == "paloalto":
                target = await db.get(PANOSFirewall, tid)
            elif target_kind == "meraki":
                target = await db.get(MerakiOrg, tid)
            else:
                return {"status": "bad_target_kind"}
            if target is None:
                return {"status": "not_found"}
            summary = await lift_all_for_target(db, target_kind, target)
            await db.commit()
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "removed": summary.removed,
            }
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.block_sync.sweep_block_sync", bind=True)
def sweep_block_sync(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(name="app.tasks.block_sync.lift_target_now", bind=True)
def lift_target_now(self: Any, target_kind: str, target_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_lift(target_kind, target_id))


@celery_app.task(name="app.tasks.block_sync.reconcile_target_now", bind=True)
def reconcile_target_now(
    self: Any, target_kind: str, target_id: str
) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(target_kind, target_id))


__all__ = ["lift_target_now", "reconcile_target_now", "sweep_block_sync"]
