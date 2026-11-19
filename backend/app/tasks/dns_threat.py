"""Beat-driven DNS threat rollup (issue #699).

Runs every 15 minutes, recomputing the current and previous hourly
buckets. Far more often than the bucket width on purpose: each run
upserts, so frequent runs mean the current hour's picture is close to
live rather than up to an hour stale, without any extra rows.

Double-gated, and both gates matter:

* the ``security.dns_threat`` feature module is default-OFF, because
  scoring reads query *content* and that is a privacy posture rather
  than a default;
* even enabled, there is nothing to roll up unless a DNS server group
  has query logging turned on.
"""

from __future__ import annotations

import asyncio

import structlog
from sqlalchemy.exc import SQLAlchemyError

from app.celery_app import celery_app
from app.config import settings
from app.db import task_session
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)


async def _run() -> dict[str, object]:
    from app.services.dns_threat.aggregate import run_aggregation  # noqa: PLC0415
    from app.services.feature_modules import is_module_enabled  # noqa: PLC0415

    # Long bound (#1719): ``aggregate_window`` streams an hour of raw query
    # log ORDER BY client_ip, and the sort completes before the first row
    # arrives, so on a busy install that first fetch is one statement that
    # can run past the 120 s default. The once-per-process backfill repeats
    # it for up to 24 buckets in this same session.
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
        if not await is_module_enabled(db, "security.dns_threat"):
            return {"status": "module_disabled"}
        result = await run_aggregation(db)
        return {"status": "ok", **result}


@celery_app.task(
    name="app.tasks.dns_threat.aggregate_dns_client_windows",
    bind=True,
    # SQLAlchemyError included because this task is entirely DB-bound:
    # a CNPG failover or pool exhaustion raises OperationalError, which
    # without this loses the tick outright. Matches the set standardised
    # across the other beat tasks in #221/#222.
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=600,
    max_retries=3,
)
@module_gated("security.dns_threat")
def aggregate_dns_client_windows(self) -> dict[str, object]:  # type: ignore[no-untyped-def]
    result = asyncio.run(_run())
    if result.get("status") == "ok" and (
        result.get("windows_current") or result.get("windows_previous")
    ):
        logger.info("dns_threat_rollup_tick", **result)
    return result
