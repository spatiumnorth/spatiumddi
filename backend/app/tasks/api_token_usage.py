"""Fold Redis API-token usage counters into the database (#4491).

Idempotent (non-negotiable #9): a count is subtracted from Redis only after
the row that holds it has committed, so a retry after a crash can at worst
count a call twice, never lose one.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, date, datetime, timedelta

import structlog
from sqlalchemy import delete, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.celery_app import celery_app
from app.db import task_session
from app.models.auth import APIToken, APITokenUsageDaily
from app.services import api_token_usage as usage

logger = structlog.get_logger(__name__)


async def _flush() -> dict[str, int]:
    r = usage._redis()
    folded = 0
    async with task_session() as db:
        async for raw_key in r.scan_iter(match=usage.CALLS_PREFIX + "*"):
            key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
            try:
                day = date.fromisoformat(key[len(usage.CALLS_PREFIX) :])
            except ValueError:
                continue
            counts = await r.hgetall(key)
            done: dict[str, int] = {}
            for tid, n in counts.items():
                tid_s = tid.decode() if isinstance(tid, bytes) else tid
                try:
                    token_id = uuid.UUID(tid_s)
                    calls = int(n)
                except ValueError:
                    await r.hdel(key, tid)
                    continue
                if calls <= 0:
                    continue
                # A deleted token's FK would fail the insert; skip it.
                exists = await db.get(APIToken, token_id)
                if exists is None:
                    await r.hdel(key, tid)
                    continue
                stmt = pg_insert(APITokenUsageDaily).values(token_id=token_id, day=day, calls=calls)
                await db.execute(
                    stmt.on_conflict_do_update(
                        index_elements=["token_id", "day"],
                        set_={"calls": APITokenUsageDaily.calls + stmt.excluded.calls},
                    )
                )
                done[tid_s] = calls
                folded += calls
            await db.commit()
            for tid_s, calls in done.items():
                await r.hincrby(key, tid_s, -calls)
        ips = await r.hgetall(usage.LAST_IP_KEY)
        for tid, ip in ips.items():
            tid_s = tid.decode() if isinstance(tid, bytes) else tid
            ip_s = ip.decode() if isinstance(ip, bytes) else ip
            try:
                token_id = uuid.UUID(tid_s)
            except ValueError:
                continue
            await db.execute(
                update(APIToken)
                .where(APIToken.id == token_id, APIToken.last_client_ip.is_distinct_from(ip_s))
                .values(last_client_ip=ip_s)
            )
        cutoff = datetime.now(UTC).date() - timedelta(days=usage.RETENTION_DAYS)
        pruned = await db.execute(delete(APITokenUsageDaily).where(APITokenUsageDaily.day < cutoff))
        await db.commit()
    return {"calls_folded": folded, "rows_pruned": max(int(pruned.rowcount or 0), 0)}


@celery_app.task(name="app.tasks.api_token_usage.flush_api_token_usage")
def flush_api_token_usage() -> dict[str, int]:
    result = asyncio.run(_flush())
    logger.info("api_token_usage_flushed", **result)
    return result


__all__ = ["flush_api_token_usage"]
