"""The Looking Glass collector's config version key (#1109); mechanism in ``agents/config_version``.

The bundle is the collector's ``enabled`` / ``name`` plus its enabled peers'
session config. A peer row is also rewritten on every heartbeat with the
session's runtime state, so the peer table is fingerprinted by its rows minus
those columns (any other column, ``modified_at`` excepted, counts as config).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.bgp_looking_glass import LookingGlassCollector
from app.services.agents.config_version import Probe, config_version, row_probe

#: bgp_lg_peer / looking_glass_collector columns the collector's heartbeat
#: rewrites; the bundle reads none of them.
LG_PEER_VOLATILE = (
    "session_state",
    "uptime_started_at",
    "prefixes_received",
    "prefixes_accepted",
    "last_state_change",
    "last_flap_at",
    "rpki_invalid_count",
    "down_since",
    "modified_at",
)
LG_COLLECTOR_VOLATILE = (
    "status",
    "last_seen_at",
    "last_seen_ip",
    "last_health_check_at",
    "agent_version",
    "config_apply_status",
    "config_apply_error",
    "config_failed_etag",
    "config_apply_at",
    "modified_at",
)

LG_CONFIG_PROBES: list[Probe] = [
    row_probe(
        "looking_glass_collector",
        exclude=LG_COLLECTOR_VOLATILE,
        where="id = CAST(:cid AS uuid)",
    ),
    row_probe("bgp_lg_peer", exclude=LG_PEER_VOLATILE, where="collector_id = CAST(:cid AS uuid)"),
]


async def lg_config_version(db: AsyncSession, collector: LookingGlassCollector) -> str:
    return await config_version(db, LG_CONFIG_PROBES, cid=str(collector.id))
