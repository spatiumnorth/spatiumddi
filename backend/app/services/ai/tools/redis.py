"""Operator Copilot tool — Redis health + config-wake bus (#358).

Read-only, superadmin-gated mirror of the ``admin/redis.py`` dashboard
surface: lets the copilot answer "is Redis healthy?" / "how busy is the
agent config-wake bus?" / "how many agents are parked on a long-poll?"
without the operator opening Platform Insights.

Default-disabled per CLAUDE.md non-negotiable #13 — it's operationally-
sensitive infra telemetry (and superadmin-gated like the backup /
diagnostics tools) — but returns NO secrets (Redis ``INFO`` numbers +
wake-bus counters only), so a superadmin can safely opt in.
"""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.agent_wake import get_wake_metrics
from app.core.permissions import is_effective_superadmin
from app.core.redis_client import is_sentinel_url, make_async_redis
from app.models.auth import User
from app.services.ai.tools.base import register_tool

logger = structlog.get_logger(__name__)


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {
            "error": (
                "Redis diagnostics are restricted to superadmin users. "
                "Ask your platform admin, or open Platform Insights → Redis."
            )
        }
    return None


class GetRedisStatsArgs(BaseModel):
    pass


@register_tool(
    name="get_redis_stats",
    permission="superadmin",
    description=(
        "Redis health + the agent config-wake bus (superadmin only). "
        "Returns Redis INFO summary (version, role, used/peak memory, "
        "connected clients, ops/sec, keyspace hit/miss, connected "
        "replicas) plus the #358 wake-bus state (publishes-by-class, the "
        "currently-subscribed wake channels, and total subscribers — one "
        "per parked agent long-poll). Use for 'is Redis healthy?', 'how "
        "busy is the config-wake bus?', or 'how many agents are connected "
        "to the wake bus right now?'. No secrets are returned."
    ),
    args_model=GetRedisStatsArgs,
    category="ops",
    default_enabled=False,
)
async def get_redis_stats(
    db: AsyncSession,
    user: User,
    args: GetRedisStatsArgs,
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate:
        return gate

    info_summary: dict[str, Any] = {"available": False}
    client = None
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=2.0)
        info = await client.info()
        info_summary = {
            "available": True,
            "sentinel": is_sentinel_url(settings.redis_url),
            "redis_version": info.get("redis_version"),
            "role": info.get("role"),
            "uptime_seconds": info.get("uptime_in_seconds"),
            "connected_clients": info.get("connected_clients"),
            # Raw byte counters (not the *_human strings) for consistency
            # with the /admin/redis dashboard shape — the model can format.
            "used_memory_bytes": info.get("used_memory"),
            "used_memory_peak_bytes": info.get("used_memory_peak"),
            "instantaneous_ops_per_sec": info.get("instantaneous_ops_per_sec"),
            "keyspace_hits": info.get("keyspace_hits"),
            "keyspace_misses": info.get("keyspace_misses"),
            "connected_replicas": info.get("connected_slaves"),
        }
    except Exception as exc:  # noqa: BLE001 — degrade, never raise into chat
        logger.warning("get_redis_stats_info_failed", error=str(exc))
        info_summary = {"available": False, "hint": str(exc)}
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass

    return {"redis": info_summary, "wake_bus": await get_wake_metrics()}
