"""Per-secondary zone health (#4732).

The primary side has drift (#61) and the transfer log (#4495); neither says
whether a secondary actually received a zone and kept it current. A BIND9
agent reports, per secondary / stub zone it holds, the serial, the time the
copy expires and is next due a refresh, and the SOA timers it runs on
(``DNSSecondaryZoneState``). This module turns those rows into a state, and
is the one place the two ``dns_secondary_*`` alert rules, the REST read
endpoints and the MCP tool read it from, so they cannot disagree.

Everything is derived from the receiving side's own clock arithmetic:

* ``expires_at`` is the last successful refresh plus the SOA expire, so the
  last refresh that worked is ``expires_at - soa_expire``.
* A refresh is due ``soa_refresh`` after that and is retried every
  ``soa_retry`` while it fails, so the number of attempts missed since is
  ``(now - due) // soa_retry``: an estimate of consecutive failures, not a
  count the daemon kept. rndc reports no failure reason, so none is shown.
* A zone that never transferred has no ``expires_at``; its clock starts at
  the first report, and the zone's own SOA timers stand in for the ones it
  has not read yet.

NULL always means unknown: a row with nothing to measure from reads
``never_transferred`` or ``unknown``, never "in sync".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSSecondaryZoneState, DNSServer, DNSZone

# Zone types a server receives by transfer.
SECONDARY_ZONE_TYPES = frozenset({"secondary", "slave", "stub"})

# A report older than this is the agent's silence, not the zone's: the
# server-unreachable rule owns that, and an old snapshot would keep a
# resolved transfer failure open.
REPORT_MAX_AGE = timedelta(minutes=30)

DEFAULT_FAILURE_THRESHOLD = 3  # consecutive missed refresh attempts
DEFAULT_STALE_MULTIPLE = 3  # x the SOA refresh
DEFAULT_EXPIRY_DAYS = 1

# Grace after a refresh falls due before it counts as missed: the transfer
# itself takes time and named does not start it on the dot.
_MIN_RETRY_SECONDS = 60


@dataclass
class SecondaryHealth:
    server_id: uuid.UUID
    server_name: str
    zone_id: uuid.UUID
    zone_name: str
    state: str  # in_sync | lagging | stale | failing | expiring | expired | never_transferred
    detail: str
    serial: int | None
    lag_serials: int | None
    last_refresh_at: datetime | None
    next_refresh_at: datetime | None
    expires_at: datetime | None
    expires_in_seconds: int | None
    failed_attempts: int
    refresh_age_seconds: int | None
    soa_refresh: int | None
    reported_at: datetime


def _serial_behind(held: int, best: int) -> int:
    """RFC 1982: how many serials ``held`` is below ``best``, 0 when equal or
    ahead."""
    diff = (best - held) % 2**32
    return diff if 0 < diff < 2**31 else 0


def _timers(st: DNSSecondaryZoneState, zone: DNSZone) -> tuple[int, int, int]:
    refresh = st.soa_refresh or int(zone.refresh or 0) or 3600
    retry = max(st.soa_retry or int(zone.retry or 0) or 600, _MIN_RETRY_SECONDS)
    expire = st.soa_expire or int(zone.expire or 0) or 604800
    return refresh, retry, expire


def assess(
    st: DNSSecondaryZoneState,
    zone: DNSZone,
    server: DNSServer,
    now: datetime,
    *,
    best_serial: int | None = None,
    stale_multiple: int = DEFAULT_STALE_MULTIPLE,
    expiry_window: timedelta = timedelta(days=DEFAULT_EXPIRY_DAYS),
) -> SecondaryHealth:
    refresh, retry, expire = _timers(st, zone)
    last_refresh = st.expires_at - timedelta(seconds=expire) if st.expires_at is not None else None
    # The clock failures are counted from: the last refresh that worked, or
    # the first report of a zone that never has.
    origin = last_refresh if last_refresh is not None else st.created_at
    due = origin + timedelta(seconds=refresh)
    overdue = (now - due).total_seconds()
    failed = int(overdue // retry) if overdue > retry else 0
    age = int((now - origin).total_seconds()) if origin is not None else None
    expires_in = int((st.expires_at - now).total_seconds()) if st.expires_at is not None else None
    lag = (
        _serial_behind(int(st.serial), best_serial)
        if st.serial is not None and best_serial is not None
        else None
    )

    if expires_in is not None and expires_in <= 0:
        state, detail = "expired", "the copy has expired; the server answers SERVFAIL for it"
    elif st.expires_at is None and st.serial is None:
        state = "never_transferred"
        detail = f"no copy yet; first seen {_ago(now - st.created_at)} ago"
    elif expires_in is not None and timedelta(seconds=expires_in) <= expiry_window:
        state = "expiring"
        detail = f"expires in {_ago(timedelta(seconds=expires_in))} without a refresh"
    elif failed >= 1:
        state = "failing"
        detail = f"{failed} refresh attempt(s) missed since the last good transfer"
    elif age is not None and age > stale_multiple * refresh:
        state = "stale"
        detail = f"last refreshed {_ago(timedelta(seconds=age))} ago"
    elif lag:
        state, detail = "lagging", f"{lag} serial(s) behind the group's newest copy"
    else:
        state, detail = "in_sync", "refreshed on schedule"

    return SecondaryHealth(
        server_id=server.id,
        server_name=server.name,
        zone_id=zone.id,
        zone_name=zone.name,
        state=state,
        detail=detail,
        serial=int(st.serial) if st.serial is not None else None,
        lag_serials=lag,
        last_refresh_at=last_refresh,
        next_refresh_at=st.next_refresh_at,
        expires_at=st.expires_at,
        expires_in_seconds=expires_in,
        failed_attempts=failed,
        refresh_age_seconds=age,
        soa_refresh=refresh,
        reported_at=st.reported_at,
    )


def _ago(delta: timedelta) -> str:
    secs = max(int(delta.total_seconds()), 0)
    if secs >= 86400:
        return f"{secs // 86400} d {secs % 86400 // 3600} h"
    if secs >= 3600:
        return f"{secs // 3600} h {secs % 3600 // 60} min"
    return f"{secs // 60} min"


async def load_health(
    db: AsyncSession,
    *,
    zone_id: uuid.UUID | None = None,
    server_id: uuid.UUID | None = None,
    now: datetime | None = None,
    live_only: bool = False,
    stale_multiple: int = DEFAULT_STALE_MULTIPLE,
    expiry_window: timedelta = timedelta(days=DEFAULT_EXPIRY_DAYS),
) -> list[SecondaryHealth]:
    """Health of every reported secondary zone copy, optionally for one zone
    or one server.

    A zone in the Trash is never read, and a server whose removal is under
    way is not either. ``live_only`` is what the alert rules pass: it also
    drops paused servers, servers in maintenance and reports older than ``REPORT_MAX_AGE``, which
    are not evidence of a transfer problem.
    """
    now = now or datetime.now(UTC)
    stmt = (
        select(DNSSecondaryZoneState, DNSZone, DNSServer)
        .join(DNSZone, DNSZone.id == DNSSecondaryZoneState.zone_id)
        .join(DNSServer, DNSServer.id == DNSSecondaryZoneState.server_id)
        .where(DNSZone.deleted_at.is_(None), DNSServer.removing_at.is_(None))
        .order_by(DNSZone.name, DNSServer.name)
    )
    if zone_id is not None:
        stmt = stmt.where(DNSSecondaryZoneState.zone_id == zone_id)
    if live_only:
        stmt = stmt.where(
            DNSServer.is_enabled.is_(True),
            DNSServer.maintenance_mode.is_(False),
            DNSSecondaryZoneState.reported_at >= now - REPORT_MAX_AGE,
        )
    rows = (await db.execute(stmt)).all()
    # The newest serial any server of the zone holds, the yardstick for "lagging".
    best: dict[uuid.UUID, int] = {}
    for st, zone, _srv in rows:
        if st.serial is None:
            continue
        cur = best.get(zone.id)
        if cur is None or _serial_behind(cur, int(st.serial)):
            best[zone.id] = int(st.serial)
    # Filtered after the yardstick is taken: one server's rows are measured
    # against every server's copy of the zone.
    return [
        assess(
            st,
            zone,
            srv,
            now,
            best_serial=best.get(zone.id),
            stale_multiple=stale_multiple,
            expiry_window=expiry_window,
        )
        for st, zone, srv in rows
        if server_id is None or srv.id == server_id
    ]
