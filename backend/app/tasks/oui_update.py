"""IEEE OUI database refresh — opt-in daily (configurable) pull.

Fired every hour by Celery Beat. Gates on
``PlatformSettings.oui_lookup_enabled`` and honours
``oui_update_interval_hours`` as the minimum gap between real runs, so
the beat schedule stays static while the UI can change cadence live.

Source: ``https://standards-oui.ieee.org/oui/oui.csv`` (~5 MB, updated
~daily by the IEEE). Each run parses the CSV, computes a diff against
the existing ``oui_vendor`` snapshot, and applies
inserts/updates/deletes inside one transaction. Unchanged rows stay
untouched, which keeps each row's ``updated_at`` meaningful (it
tracks actual vendor re-assignments, not cron ticks). Failures roll
back to the previous snapshot so lookups never serve partial data.

Return payload on success: ``{"status": "ran", "total", "added",
"updated", "removed", "unchanged", "forced"}`` — consumed by the
polling endpoint that drives the Settings-page refresh modal.

Idempotent: re-running is a no-op until the interval elapses; a
forced run against an already-synced CSV returns zero added / updated
/ removed.
"""

from __future__ import annotations

import asyncio
import csv
import io
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.models.audit import AuditLog
from app.models.oui import OUIVendor
from app.models.settings import PlatformSettings
from app.tasks._interval_gate import interval_skip

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1
_OUI_SOURCE_URL = "https://standards-oui.ieee.org/oui/oui.csv"
# Insert in chunks to keep a single statement's parameter list manageable —
# the IEEE CSV currently has ~35k rows and bulk inserting the lot in one go
# works on Postgres but risks a statement-parameter cap on smaller setups.
_CHUNK_SIZE = 1000


def _parse_oui_csv(text: str) -> list[dict[str, str]]:
    """Return ``[{"prefix": "001122", "vendor_name": "…"}, …]``.

    The IEEE CSV schema is: ``Registry,Assignment,Organization Name,
    Organization Address``. We only keep rows with a 6-hex-char
    ``Assignment``. Duplicate prefixes (rare but possible during IEEE
    re-assignment) — last one wins.
    """
    out: dict[str, str] = {}
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        prefix_raw = (row.get("Assignment") or "").strip().lower()
        if len(prefix_raw) != 6 or not all(c in "0123456789abcdef" for c in prefix_raw):
            continue
        vendor = (row.get("Organization Name") or "").strip()
        if not vendor:
            continue
        # Trim to the DB column width so a pathologically long org name
        # can't blow the insert. IEEE entries run well under 255 today.
        out[prefix_raw] = vendor[:255]
    return [{"prefix": p, "vendor_name": v} for p, v in out.items()]


async def _run_update(force: bool = False) -> dict[str, Any]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is None or not ps.oui_lookup_enabled:
                return {"status": "disabled"}

            now = datetime.now(UTC)
            interval = timedelta(hours=max(1, ps.oui_update_interval_hours))
            if not force:
                skip = interval_skip(now, ps.oui_last_updated_at, interval)
                if skip is not None:
                    return skip

            logger.info("oui_update_fetching", url=_OUI_SOURCE_URL, force=force)
            try:
                # IEEE returns HTTP 418 to clients that look like automated
                # scrapers (no User-Agent, Python-urllib default, etc).
                # Present as a regular HTTP client; no cookies, no JS, just
                # a static CSV fetch.
                headers = {
                    "User-Agent": "SpatiumDDI-OUI-Fetcher/1.0 (+https://github.com/spatiumnorth/spatiumddi)",
                    "Accept": "text/csv,text/plain,*/*",
                }
                async with httpx.AsyncClient(
                    timeout=120, follow_redirects=True, headers=headers
                ) as client:
                    resp = await client.get(_OUI_SOURCE_URL)
                    resp.raise_for_status()
                    csv_text = resp.text
            except Exception as exc:  # noqa: BLE001
                logger.warning("oui_update_fetch_failed", error=str(exc))
                return {"status": "error", "reason": "fetch_failed", "detail": str(exc)}

            entries = _parse_oui_csv(csv_text)
            if not entries:
                logger.warning("oui_update_empty_csv", url=_OUI_SOURCE_URL)
                return {"status": "error", "reason": "empty_csv"}

            # Incremental diff: load the existing snapshot and categorise
            # each prefix into add / update / remove / unchanged. A typical
            # IEEE daily diff is small (~20-100 rows out of ~35k), so
            # skipping the unchanged majority keeps ``updated_at`` meaningful
            # (you can see when a specific prefix last actually changed).
            existing_rows = (
                await db.execute(select(OUIVendor.prefix, OUIVendor.vendor_name))
            ).all()
            existing = {p: v for p, v in existing_rows}
            incoming = {e["prefix"]: e["vendor_name"] for e in entries}

            to_insert = [
                {"prefix": p, "vendor_name": v} for p, v in incoming.items() if p not in existing
            ]
            to_update = [(p, v) for p, v in incoming.items() if p in existing and existing[p] != v]
            to_remove = [p for p in existing if p not in incoming]
            unchanged = len(incoming) - len(to_insert) - len(to_update)

            # One transaction covers everything so either we commit the
            # full diff or roll back to the previous snapshot — no half-
            # applied state visible to concurrent lookups.
            for i in range(0, len(to_insert), _CHUNK_SIZE):
                await db.execute(insert(OUIVendor), to_insert[i : i + _CHUNK_SIZE])
            for prefix, vendor in to_update:
                await db.execute(
                    update(OUIVendor)
                    .where(OUIVendor.prefix == prefix)
                    .values(vendor_name=vendor, updated_at=func.now())
                )
            if to_remove:
                for i in range(0, len(to_remove), _CHUNK_SIZE):
                    await db.execute(
                        delete(OUIVendor).where(
                            OUIVendor.prefix.in_(to_remove[i : i + _CHUNK_SIZE])
                        )
                    )

            ps.oui_last_updated_at = now

            summary = {
                "total": len(incoming),
                "added": len(to_insert),
                "updated": len(to_update),
                "removed": len(to_remove),
                "unchanged": unchanged,
                "forced": force,
            }
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="oui-update",
                    resource_type="platform",
                    resource_id=str(_SINGLETON_ID),
                    resource_display="oui-database",
                    result="success",
                    new_value=summary,
                )
            )
            await db.commit()

            logger.info("oui_update_completed", **summary)
            return {"status": "ran", **summary}
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.oui_update.auto_update_oui_database", bind=True)
def auto_update_oui_database(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Celery beat entrypoint. Fires hourly; the task itself gates on
    ``oui_lookup_enabled`` and ``oui_update_interval_hours``."""
    try:
        return asyncio.run(_run_update(force=False))
    except Exception as exc:  # noqa: BLE001
        logger.exception("oui_update_failed", error=str(exc))
        raise


@celery_app.task(name="app.tasks.oui_update.update_oui_database_now", bind=True)
def update_oui_database_now(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Manual kick from the Settings UI — ignores the interval gate but
    still requires the feature to be enabled."""
    try:
        return asyncio.run(_run_update(force=True))
    except Exception as exc:  # noqa: BLE001
        logger.exception("oui_update_failed", error=str(exc))
        raise
