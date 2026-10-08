"""#1171 — when a group's BIND9 servers serve each zone's own SOA timers.

Before #1171 the BIND9 agent wrote ``3600 600 86400 300`` (REFRESH RETRY EXPIRE
MINIMUM) into every zone's SOA, whatever the zone held. An agent of this release
writes the zone's own timers when its bundle carries them. While agents of both
kinds serve one group, a zone whose timers were edited would be served two ways
under one serial: during an upgrade until the old DNS pod is replaced, on a
cluster until its last node's pod is, or for as long as an external agent of an
older release stays in the group. A secondary that transferred the literal is
then told it is up to date, and keeps it.

So a group's bundles carry each zone's own timers only while every BIND9 agent
in it renders them (``DNSServerGroup.serves_soa_timers``). Until then they
carry the literal, which agents old and new write identically, so every serial
the group serves has one SOA. Whenever that changes, either way, the serial of
each of the group's zones whose timers differ from the literal moves in the
same transaction (``bump_zone_serial``'s rule): the changed SOA goes out under
a serial no agent ever served with the other one, and NOTIFY sends the zone's
secondaries to transfer it. Nothing is withheld from an agent meanwhile: a
stalled roll delays the timers, never a record.

An agent says it renders them with the ``soa-timers`` token of the
``X-Spatium-Agent-Features`` header on its register and heartbeat requests. A
header, not a body field: the heartbeat body is ``extra="forbid"``, so a field
would 422 every heartbeat of an agent upgraded before its control plane (a
cluster's DNS pods can roll before its control plane does). An agent that
sends none writes the literal.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from sqlalchemy import exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.services.dns.serial import bump_zone_serial

logger = structlog.get_logger(__name__)

AGENT_FEATURES_HEADER = "X-Spatium-Agent-Features"
FEATURE_SOA_TIMERS = "soa-timers"

# What every BIND9 agent before #1171 wrote into every zone's SOA. Also the
# zone defaults (``ZONE_DEFAULT_*``), so a zone left at them is shipped the same
# values whether its group serves its own timers or not, and never moves.
LITERAL_SOA_TIMERS: dict[str, int] = {
    "refresh": 3600,
    "retry": 600,
    "expire": 86400,
    "minimum": 300,
}


def agent_features(header: str | None) -> frozenset[str]:
    """The tokens of an ``X-Spatium-Agent-Features`` header (a comma list)."""
    if not header:
        return frozenset()
    return frozenset(t.strip().lower() for t in header.split(",") if t.strip())


def renders_soa_timers(header: str | None) -> bool:
    return FEATURE_SOA_TIMERS in agent_features(header)


def served_soa_timers(zone: Any, group_serves: bool) -> dict[str, int]:
    """The SOA timers a zone's bundle copy carries: its own once its group
    serves them, else the literal every agent of the group writes alike."""
    if not group_serves:
        return dict(LITERAL_SOA_TIMERS)
    return {k: getattr(zone, k, literal) for k, literal in LITERAL_SOA_TIMERS.items()}


def _timers_not_literal() -> Any:
    return or_(*(getattr(DNSZone, k) != v for k, v in LITERAL_SOA_TIMERS.items()))


async def _every_bind9_agent_renders(db: AsyncSession, group_id: uuid.UUID) -> bool:
    """No server of the group renders a BIND9 bundle with the literal.

    Counted: BIND9 servers an agent runs (``agent_id``) that are sent bundles
    (enabled, approved). Not counted: other drivers (PowerDNS and Technitium
    keep their own SOA; agentless servers get no bundle), a row no agent has
    registered into, and a disabled or unapproved server, which is sent none.
    """
    lagging = await db.scalar(
        select(
            exists().where(
                DNSServer.group_id == group_id,
                DNSServer.driver == "bind9",
                DNSServer.agent_id.is_not(None),
                DNSServer.is_enabled.is_(True),
                DNSServer.pending_approval.is_(False),
                DNSServer.agent_renders_soa_timers.is_(False),
            )
        )
    )
    return not lagging


async def reconcile_soa_timers(db: AsyncSession, group_id: uuid.UUID) -> bool | None:
    """Switch the group's timers to what its BIND9 agents can render.

    Returns the new ``serves_soa_timers`` when it changed (the serials moved
    with it), else ``None``. The caller commits. Cheap when nothing changes,
    which is every call but the one that finishes a roll: one read of the
    group, one EXISTS over its servers.
    """
    serves = await db.scalar(
        select(DNSServerGroup.serves_soa_timers).where(DNSServerGroup.id == group_id)
    )
    if serves is None or serves == await _every_bind9_agent_renders(db, group_id):
        return None

    # Decide again under the group's row lock, so that two agents reporting in
    # the same instant switch the group, and move its serials, once.
    group = (
        await db.execute(
            select(DNSServerGroup)
            .where(DNSServerGroup.id == group_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    serves_now = await _every_bind9_agent_renders(db, group_id)
    if group.serves_soa_timers == serves_now:
        return None

    # Soft-deleted zones too: a restore must not bring one back under a serial
    # it was served with the other way.
    zones = (
        (
            await db.execute(
                select(DNSZone)
                .where(DNSZone.group_id == group_id, _timers_not_literal())
                .with_for_update()
                .execution_options(include_deleted=True, populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    for zone in zones:
        bump_zone_serial(zone)
    # An ORM write, so the bundle-dirty listener re-renders the group's servers
    # (``DNSServerGroup`` is a bundle contributor).
    group.serves_soa_timers = serves_now
    db.add(
        AuditLog(
            user_display_name="system:dns-agent",
            auth_source="system",
            action="dns.group.soa_timers",
            resource_type="dns_server_group",
            resource_id=str(group.id),
            resource_display=group.name,
            old_value={"serves_soa_timers": not serves_now},
            new_value={"serves_soa_timers": serves_now, "zones_serial_moved": len(zones)},
            result="success",
        )
    )
    logger.info(
        "dns_group_soa_timers",
        group_id=str(group.id),
        serves_soa_timers=serves_now,
        zones_serial_moved=len(zones),
    )
    return serves_now


__all__ = [
    "AGENT_FEATURES_HEADER",
    "FEATURE_SOA_TIMERS",
    "LITERAL_SOA_TIMERS",
    "agent_features",
    "reconcile_soa_timers",
    "renders_soa_timers",
    "served_soa_timers",
]
