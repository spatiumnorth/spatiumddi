"""Calendar-refresh reconciler for the Scheduled Wake-on-LAN calendar gate —
Phase 2 (issue #586).

Pulls a :class:`WolCalendar`'s feed (iCal ``.ics`` URL or authenticated CalDAV
collection), flattens it into all-day :class:`~app.services.wol_scheduler.calendar.ParsedEvent`
spans (recurrence expanded over a bounded horizon), and **set-reconciles** the
child ``wol_calendar_event`` rows — add new spans, delete gone ones — exactly
like the DNS blocklist feed pull (:func:`app.tasks.dns.refresh_blocklist_feed`).

Contract (mirrors the blocklist reconciler):

* Transient failure (``httpx.HTTPError`` / ``socket.gaierror`` / CalDAV network
  or auth error) → persist ``last_sync_status='error'`` + ``last_sync_error``
  then **re-raise** so the Celery task's ``autoretry_for`` backs off.
* Permanent failure (parse / shape error) → persist the same error state but
  **swallow** (retrying a malformed feed won't help).
* Success → ``last_sync_status='success'``, ``last_sync_error=None``,
  ``last_synced_at=now``, ``event_count`` recomputed.

Idempotent + safe to retry (non-negotiable #9): the reconcile is a pure diff of
the current horizon's event set against what's stored, keyed by
``(uid, starts_on, ends_on)``.
"""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo

import httpx
import structlog
from sqlalchemy import select

from app.core.crypto import decrypt_str
from app.models.wol_schedule import WolCalendar, WolCalendarEvent, WolSchedule
from app.services.wol_scheduler.calendar import (
    DEFAULT_HORIZON_DAYS,
    ParsedEvent,
    fetch_caldav_events,
    fetch_ical_url,
    parse_ical,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

KIND_ICAL_URL = "ical_url"
KIND_CALDAV = "caldav"

# Transport-level failures that are worth retrying (re-raised for autoretry).
_TRANSIENT = (httpx.HTTPError, socket.gaierror, ConnectionError, TimeoutError, OSError)


def _event_key(uid: str | None, starts_on: Any, ends_on: Any) -> tuple[str | None, Any, Any]:
    return (uid, starts_on, ends_on)


# The earliest civil date anywhere on Earth is UTC-12's. Used when no schedule
# is attached, so a calendar synced ahead of its first schedule still never
# deletes a day that is "today" somewhere.
_EARLIEST_UTC_OFFSET_HOURS = 12


def horizon_anchor(timezones: list[str], now: datetime) -> date:
    """First date the sync keeps: the earliest *local* today among the
    attached schedules' zones (never later than the UTC date).

    The gate judges the schedule's local date, so anchoring on the worker's
    UTC date deletes today's event for any schedule west of UTC for the hours
    between UTC midnight and local midnight. Computed per zone with zoneinfo,
    so DST offsets are honoured on the day they change.
    """
    now = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
    anchor = now.astimezone(UTC).date()
    if not timezones:
        return (now.astimezone(UTC) - timedelta(hours=_EARLIEST_UTC_OFFSET_HOURS)).date()
    for name in timezones:
        try:
            anchor = min(anchor, now.astimezone(ZoneInfo(name)).date())
        except (ValueError, KeyError, OSError):  # unknown zone: ignore, gate rejects it too
            continue
    return anchor


async def _load_events_for_calendar(
    calendar: WolCalendar,
    *,
    horizon_days: int,
    today: date,
) -> list[ParsedEvent]:
    """Fetch + parse the calendar's feed into flattened all-day spans.

    ``ical_url`` is fetched async over httpx; ``caldav`` runs the blocking
    client in a thread so the event loop is never blocked.
    """
    if calendar.kind == KIND_CALDAV:
        password = None
        if calendar.password_encrypted:
            try:
                password = decrypt_str(calendar.password_encrypted)
            except ValueError as exc:
                raise ValueError(f"stored CalDAV password could not be decrypted: {exc}") from exc
        return await asyncio.to_thread(
            fetch_caldav_events,
            calendar.url,
            calendar.username,
            password,
            horizon_days=horizon_days,
            today=today,
        )

    # Default / ical_url.
    text = await fetch_ical_url(calendar.url)
    return parse_ical(text, horizon_days=horizon_days, today=today)


async def sync_calendar(
    db: AsyncSession,
    calendar: WolCalendar,
    *,
    horizon_days: int = DEFAULT_HORIZON_DAYS,
    force: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Refresh one calendar's cached event spans. See module docstring for the
    transient/permanent error contract.

    ``force`` (only the manual REST ``sync-now`` path sets it) lets a
    *genuinely* cleared calendar empty its cache. When ``force`` is False (the
    beat-driven sweep) a successful-but-empty fetch against a non-empty cache is
    treated as suspect — the mass-delete is skipped and last-known-good is kept
    (see the zero-result guard below).

    Returns a summary dict (``status`` / ``added`` / ``removed`` / ``total``).
    """
    # Serialize per-calendar reconciles: the inline sync-now (API process) and
    # the beat sweep (worker process) can otherwise both read an empty
    # ``existing`` for a fresh span and each insert it, leaking a permanent
    # duplicate row (the natural key is non-unique because ``uid`` is nullable).
    # A row lock on the parent WolCalendar makes concurrent diffs mutually
    # exclusive.
    await db.execute(select(WolCalendar).where(WolCalendar.id == calendar.id).with_for_update())

    tz_names = list(
        (
            await db.execute(
                select(WolSchedule.timezone)
                .where(WolSchedule.calendar_id == calendar.id)
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    today = horizon_anchor(tz_names, now or datetime.now(UTC))

    try:
        parsed = await _load_events_for_calendar(calendar, horizon_days=horizon_days, today=today)
    except _TRANSIENT as exc:
        # Never surface the raw fetch exception — an httpx error echoes the
        # target URL/status and an SSRF'd body could leak through the
        # API-visible column. Keep the detail in server-side logs only.
        calendar.last_sync_status = "error"
        calendar.last_sync_error = "feed fetch failed"
        calendar.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning("wol_calendar_fetch_failed", calendar_id=str(calendar.id), error=str(exc))
        raise
    except Exception as exc:  # noqa: BLE001 — parse / shape / decrypt: don't retry
        # icalendar's ValueError echoes the offending feed line verbatim, so a
        # non-iCal body (e.g. an SSRF'd creds JSON) would leak through the
        # API-visible column. Store a generic message; keep detail server-side.
        calendar.last_sync_status = "error"
        calendar.last_sync_error = "feed is not valid iCalendar"
        calendar.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning("wol_calendar_parse_failed", calendar_id=str(calendar.id), error=str(exc))
        # Return the SAME generic message as the persisted column — the raw
        # exception (icalendar echoes the offending feed line, an SSRF'd body,
        # etc.) is logged server-side above and must never reach the caller via
        # the sync-now response either.
        return {
            "status": "error",
            "added": 0,
            "removed": 0,
            "total": 0,
            "error": "feed is not valid iCalendar",
        }

    # Dedupe parsed events by natural key (recurrence can repeat a UID; a feed
    # can list the same span twice).
    desired: dict[tuple[str | None, Any, Any], ParsedEvent] = {}
    for ev in parsed:
        desired[_event_key(ev.uid, ev.starts_on, ev.ends_on)] = ev

    existing_rows = (
        (
            await db.execute(
                select(WolCalendarEvent).where(WolCalendarEvent.calendar_id == calendar.id)
            )
        )
        .scalars()
        .all()
    )
    existing = {_event_key(r.uid, r.starts_on, r.ends_on): r for r in existing_rows}

    # Zero-result guard: a transient-empty fetch (CalDAV mid-reindex, temporarily
    # empty collection, VEVENT-less VCALENDAR) is indistinguishable from a
    # legitimately-cleared calendar on a 200. On the beat path (force=False),
    # refuse to delete a non-empty cache down to zero — keep last-known-good so
    # the holiday gate survives a blip. The manual REST path passes force=True,
    # so an operator who genuinely cleared the calendar can still empty it.
    if not desired and existing and not force:
        calendar.last_sync_status = "stale"
        calendar.last_sync_error = "feed returned no events — keeping last-known-good"
        calendar.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning(
            "wol_calendar_suspect_empty",
            calendar_id=str(calendar.id),
            kept=len(existing),
        )
        return {
            "status": "stale",
            "added": 0,
            "removed": 0,
            "total": len(existing),
        }

    to_add = set(desired) - set(existing)
    to_remove = set(existing) - set(desired)

    for key in to_add:
        ev = desired[key]
        db.add(
            WolCalendarEvent(
                calendar_id=calendar.id,
                starts_on=ev.starts_on,
                ends_on=ev.ends_on,
                summary=ev.summary,
                categories=list(ev.categories),
                uid=ev.uid,
            )
        )
    for key in to_remove:
        await db.delete(existing[key])

    calendar.event_count = len(desired)
    calendar.last_synced_at = datetime.now(UTC)
    calendar.last_sync_status = "success"
    calendar.last_sync_error = None
    await db.commit()

    logger.info(
        "wol_calendar_synced",
        calendar_id=str(calendar.id),
        added=len(to_add),
        removed=len(to_remove),
        total=len(desired),
    )
    return {
        "status": "success",
        "added": len(to_add),
        "removed": len(to_remove),
        "total": len(desired),
    }


__all__ = ["sync_calendar", "KIND_ICAL_URL", "KIND_CALDAV"]
