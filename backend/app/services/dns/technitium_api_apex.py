"""Write a zone's SOA, apex NS set and serial to ``technitium_api`` servers (#1774, #1779).

The agentless driver used to send only ``{zone, type: Primary}`` on create and
never touched a zone again, so Technitium's own apex stood: the server's host
name as MNAME, a placeholder RNAME, minimum 900 and a serial of 1, whatever the
zone row said (#1490 was the same defect on the agent path).

The serial each server SERVES is read back from it after the write and stored
in ``dns_server_zone_state``. It is never the serial that was asked for:
Technitium owns the number and numbers it itself, so two servers of a zone
serve different ones, and a re-created zone restarts at 1.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServer, DNSServerZoneState, DNSZone
from app.services.technitium.apex import zone_apex

DRIVER = "technitium_api"


async def _apex_inputs(db: AsyncSession, zone: DNSZone) -> dict[str, Any]:
    ns_rows = (
        (
            await db.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id == zone.id,
                    DNSRecord.record_type == "NS",
                )
            )
        )
        .scalars()
        .all()
    )
    return {
        "primary_ns": zone.primary_ns,
        "admin_email": zone.admin_email,
        "ttl": zone.ttl,
        "refresh": zone.refresh,
        "retry": zone.retry,
        "expire": zone.expire,
        "minimum": zone.minimum,
        "records": [
            {"type": "NS", "name": r.name, "value": r.value, "ttl": r.ttl} for r in ns_rows
        ],
    }


async def record_served_serial(
    db: AsyncSession, server_id: uuid.UUID, zone_id: uuid.UUID, serial: int | None
) -> None:
    """Store the serial a server was READ serving; nothing when it could not be read.

    A missing row reads as "not reported" in the zone's sync pill, which is
    the honest answer for a zone nobody could read back.
    """
    if serial is None:
        return
    row = (
        await db.execute(
            select(DNSServerZoneState).where(
                DNSServerZoneState.server_id == server_id,
                DNSServerZoneState.zone_id == zone_id,
            )
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None:
        db.add(
            DNSServerZoneState(
                server_id=server_id, zone_id=zone_id, current_serial=serial, reported_at=now
            )
        )
    else:
        row.current_serial = serial
        row.reported_at = now


async def sync_zone_apex(db: AsyncSession, zone: DNSZone, server: DNSServer, driver: Any) -> None:
    """Bring ``zone``'s apex on one ``technitium_api`` server in line with its row.

    Raises the driver's error when the server refuses or is unreachable, so the
    caller can fail the request rather than save a zone the server does not serve.
    """
    apex = zone_apex(zone.name, await _apex_inputs(db, zone))
    served = await driver.apply_zone_apex(
        server, zone.name, apex, serial=int(zone.last_serial or 0) or None
    )
    await record_served_serial(db, server.id, zone.id, served)


async def technitium_api_servers(db: AsyncSession, group_id: uuid.UUID) -> list[DNSServer]:
    return list(
        (
            await db.execute(
                select(DNSServer).where(
                    DNSServer.group_id == group_id,
                    DNSServer.driver == DRIVER,
                    DNSServer.credentials_encrypted.isnot(None),
                    DNSServer.is_enabled.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
