"""iCal / CalDAV calendar-gate tests for Scheduled Wake-on-LAN — Phase 2
(issue #586).

Covers the net-new Phase-2 surface:

* **iCal parsing** (:func:`app.services.wol_scheduler.calendar.parse_ical`) —
  all-day single-day and multi-day VEVENTs flatten to the correct *inclusive*
  ``[starts_on, ends_on]`` span (RFC 5545 exclusive-DTEND corrected), a timed
  event is ignored, and a weekly ``RRULE`` expands within the horizon and stays
  bounded (never infinite / oversized).
* **``sync_calendar`` set-reconcile** — new spans inserted, absent spans
  deleted, an unchanged span retained (same row id), ``last_sync_status`` /
  ``event_count`` stamped, and a fetch error persists ``last_sync_error`` +
  re-raises WITHOUT wiping the previously-cached events (last-known-good).
* **the calendar gate** (:func:`...gating.gate_verdict`) — ``skip_on_event`` /
  ``only_on_event`` polarity plus the optional ``calendar_match`` summary /
  category regex include/exclude filter.
* **password at rest** — a CalDAV subscription created with a password stores
  Fernet ciphertext; the read schema exposes only ``password_set=True`` and the
  secret is NEVER serialised back out.

All network is mocked (``httpx`` via the patched ``fetch_ical_url``; ``caldav``
via the patched ``fetch_caldav_events``) so the suite is fully offline.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, date, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str, encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.wol_schedule import WolCalendar, WolCalendarEvent, WolSchedule
from app.services.wol_scheduler import (
    SKIP_CALENDAR_EVENT,
    SKIP_NO_CALENDAR_EVENT,
    ParsedEvent,
    gate_verdict,
    parse_ical,
    sync_calendar,
)
from app.services.wol_scheduler.calendar import (
    _MAX_OCCURRENCES_PER_EVENT,
    _SSRF_GENERIC_MESSAGE,
    DEFAULT_HORIZON_DAYS,
    fetch_ical_url,
    normalise_ical_url,
)
from app.services.wol_scheduler.calendar_sync import horizon_anchor

_BASE = "/api/v1/wake-scheduler"


# ── iCal builders ─────────────────────────────────────────────────────


def _ics(*vevents: str) -> str:
    return (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//spatiumddi-test//EN\r\n"
        f"{''.join(vevents)}"
        "END:VCALENDAR\r\n"
    )


def _vevent(
    *,
    uid: str,
    dtstart: str,
    dtend: str | None = None,
    summary: str | None = None,
    categories: list[str] | None = None,
    rrule: str | None = None,
    all_day: bool = True,
) -> str:
    lines = ["BEGIN:VEVENT", f"UID:{uid}"]
    if all_day:
        lines.append(f"DTSTART;VALUE=DATE:{dtstart}")
        if dtend is not None:
            lines.append(f"DTEND;VALUE=DATE:{dtend}")
    else:
        # A timed (DATE-TIME) event — must be ignored by the all-day parser.
        lines.append(f"DTSTART:{dtstart}")
        if dtend is not None:
            lines.append(f"DTEND:{dtend}")
    if summary is not None:
        lines.append(f"SUMMARY:{summary}")
    if categories:
        lines.append("CATEGORIES:" + ",".join(categories))
    if rrule is not None:
        lines.append(f"RRULE:{rrule}")
    lines.append("END:VEVENT")
    return "\r\n".join(lines) + "\r\n"


def _ymd(d: date) -> str:
    return d.strftime("%Y%m%d")


# ══════════════════════════════════════════════════════════════════════
# 1. iCal parse — all-day flattening + DTEND-exclusive correction
# ══════════════════════════════════════════════════════════════════════


def test_parse_single_day_all_day_event() -> None:
    text = _ics(_vevent(uid="xmas@test", dtstart="20261225", summary="Christmas"))
    events = parse_ical(text, today=date(2026, 12, 1))
    assert len(events) == 1
    ev = events[0]
    # No DTEND / DURATION → a one-day event: starts_on == ends_on.
    assert ev.starts_on == date(2026, 12, 25)
    assert ev.ends_on == date(2026, 12, 25)
    assert ev.summary == "Christmas"
    assert ev.uid == "xmas@test"


def test_parse_multi_day_event_corrects_exclusive_dtend() -> None:
    # DTEND is EXCLUSIVE for all-day VEVENTs → a 24th→27th DTEND spans the
    # inclusive [24, 26] (three days), NOT [24, 27].
    text = _ics(
        _vevent(
            uid="break@test",
            dtstart="20261224",
            dtend="20261227",
            summary="Winter Break",
            categories=["holiday", "school-closed"],
        )
    )
    events = parse_ical(text, today=date(2026, 12, 1))
    assert len(events) == 1
    ev = events[0]
    assert ev.starts_on == date(2026, 12, 24)
    assert ev.ends_on == date(2026, 12, 26)  # exclusive 27th minus one day
    # CATEGORIES flatten to a plain str list.
    assert ev.categories == ["holiday", "school-closed"]


def test_parse_ignores_timed_event() -> None:
    # A DATE-TIME (timed) VEVENT is noise for a holiday/term calendar and must
    # be dropped — only all-day spans count.
    text = _ics(
        _vevent(uid="meeting@test", dtstart="20261225T090000Z", all_day=False, summary="Standup"),
        _vevent(uid="holiday@test", dtstart="20261225", summary="Holiday"),
    )
    events = parse_ical(text, today=date(2026, 12, 1))
    assert len(events) == 1
    assert events[0].uid == "holiday@test"


def test_parse_weekly_rrule_expands_within_horizon_and_is_bounded() -> None:
    anchor = date(2026, 1, 5)  # a Monday
    text = _ics(
        _vevent(uid="weekly@test", dtstart=_ymd(anchor), rrule="FREQ=WEEKLY", summary="Wake")
    )
    # A 30-day horizon from the DTSTART yields exactly the 5 Mondays in window
    # (0, +7, +14, +21, +28 days) — bounded, not infinite.
    events = parse_ical(text, today=anchor, horizon_days=30)
    starts = sorted(e.starts_on for e in events)
    assert starts == [
        anchor,
        anchor + timedelta(days=7),
        anchor + timedelta(days=14),
        anchor + timedelta(days=21),
        anchor + timedelta(days=28),
    ]
    # Every occurrence is a single-day span and inside the horizon window.
    horizon_end = anchor + timedelta(days=30)
    for e in events:
        assert e.starts_on == e.ends_on
        assert anchor <= e.starts_on <= horizon_end


def test_parse_unbounded_rrule_stays_bounded_over_default_horizon() -> None:
    # A COUNT/UNTIL-less FREQ=WEEKLY can't produce an unbounded set: the parser
    # clamps to [today, today + DEFAULT_HORIZON_DAYS] and the per-event ceiling.
    anchor = date(2026, 3, 2)
    text = _ics(_vevent(uid="w@test", dtstart=_ymd(anchor), rrule="FREQ=WEEKLY"))
    events = parse_ical(text, today=anchor)  # default 400-day horizon
    # ~57-58 weekly occurrences in 400 days — finite, small, well under the cap.
    assert DEFAULT_HORIZON_DAYS // 7 - 1 <= len(events) <= DEFAULT_HORIZON_DAYS // 7 + 1
    assert len(events) < _MAX_OCCURRENCES_PER_EVENT
    horizon_end = anchor + timedelta(days=DEFAULT_HORIZON_DAYS)
    assert all(anchor <= e.starts_on <= horizon_end for e in events)


def test_normalise_ical_url_rewrites_webcal() -> None:
    assert normalise_ical_url("webcal://cal.example/x.ics") == "https://cal.example/x.ics"
    assert normalise_ical_url("WEBCALS://cal.example/x.ics") == "https://cal.example/x.ics"
    assert normalise_ical_url("https://cal.example/x.ics") == "https://cal.example/x.ics"


# ══════════════════════════════════════════════════════════════════════
# 2. sync_calendar — set-reconcile + error contract
# ══════════════════════════════════════════════════════════════════════


async def _make_calendar(db: AsyncSession, *, kind: str = "ical_url", **kw: object) -> WolCalendar:
    cal = WolCalendar(
        name=f"cal-{uuid.uuid4().hex[:6]}",
        kind=kind,
        url="https://cal.example/feed.ics",
        **kw,
    )
    db.add(cal)
    await db.flush()
    return cal


async def _events_for(db: AsyncSession, calendar_id: uuid.UUID) -> list[WolCalendarEvent]:
    return list(
        (
            await db.execute(
                select(WolCalendarEvent).where(WolCalendarEvent.calendar_id == calendar_id)
            )
        )
        .scalars()
        .all()
    )


async def test_sync_inserts_new_events_and_stamps_status(db_session: AsyncSession) -> None:
    cal = await _make_calendar(db_session)
    base = date.today()
    a, b = base + timedelta(days=10), base + timedelta(days=20)
    ics = _ics(
        _vevent(uid="a@test", dtstart=_ymd(a), summary="A"),
        _vevent(uid="b@test", dtstart=_ymd(b), summary="B"),
    )

    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=ics),
    ):
        result = await sync_calendar(db_session, cal)

    assert result == {"status": "success", "added": 2, "removed": 0, "total": 2}
    rows = await _events_for(db_session, cal.id)
    assert {r.uid for r in rows} == {"a@test", "b@test"}
    assert cal.last_sync_status == "success"
    assert cal.last_sync_error is None
    assert cal.last_synced_at is not None
    assert cal.event_count == 2


async def test_sync_reconciles_add_delete_retain(db_session: AsyncSession) -> None:
    cal = await _make_calendar(db_session)
    base = date.today()
    a, b, c = (base + timedelta(days=d) for d in (10, 20, 30))

    ics1 = _ics(
        _vevent(uid="a@test", dtstart=_ymd(a), summary="A"),
        _vevent(uid="b@test", dtstart=_ymd(b), summary="B"),
    )
    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=ics1),
    ):
        await sync_calendar(db_session, cal)

    rows1 = {r.uid: r for r in await _events_for(db_session, cal.id)}
    a_id = rows1["a@test"].id  # capture to prove A is RETAINED (not re-created)

    # Second feed: A unchanged, B gone, C new.
    ics2 = _ics(
        _vevent(uid="a@test", dtstart=_ymd(a), summary="A"),
        _vevent(uid="c@test", dtstart=_ymd(c), summary="C"),
    )
    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=ics2),
    ):
        result = await sync_calendar(db_session, cal)

    assert result == {"status": "success", "added": 1, "removed": 1, "total": 2}
    rows2 = {r.uid: r for r in await _events_for(db_session, cal.id)}
    assert set(rows2) == {"a@test", "c@test"}  # B deleted, C inserted
    assert rows2["a@test"].id == a_id  # A retained in place, not churned
    assert cal.event_count == 2


async def test_sync_fetch_error_preserves_events_and_reraises(db_session: AsyncSession) -> None:
    cal = await _make_calendar(db_session)
    base = date.today()
    ics = _ics(_vevent(uid="a@test", dtstart=_ymd(base + timedelta(days=5)), summary="A"))

    # 1. Seed a good sync.
    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=ics),
    ):
        await sync_calendar(db_session, cal)
    assert len(await _events_for(db_session, cal.id)) == 1

    # 2. A transient fetch failure must persist the error state, KEEP the cached
    #    events (last-known-good, non-negotiable #5), and re-raise so the task's
    #    autoretry backs off.
    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(side_effect=httpx.HTTPError("upstream 503 https://internal.example/secret")),
    ):
        with pytest.raises(httpx.HTTPError):
            await sync_calendar(db_session, cal)

    assert cal.last_sync_status == "error"
    # The API-visible column carries a GENERIC message — the raw httpx exception
    # (which echoes the fetched URL / status) is kept in server-side logs only,
    # so the error store can't be turned into an SSRF disclosure oracle.
    assert cal.last_sync_error is not None
    assert "upstream 503" not in cal.last_sync_error
    assert "internal.example" not in cal.last_sync_error
    # Events NOT wiped — the previous good set survives the failed refresh.
    surviving = await _events_for(db_session, cal.id)
    assert len(surviving) == 1
    assert surviving[0].uid == "a@test"


async def test_sync_caldav_decrypts_password_and_reconciles(db_session: AsyncSession) -> None:
    # The CalDAV branch: the stored Fernet password is decrypted before the
    # blocking client runs, and the returned spans reconcile identically. The
    # network (caldav) is mocked at fetch_caldav_events.
    base = date.today()
    ev = ParsedEvent(
        starts_on=base + timedelta(days=3),
        ends_on=base + timedelta(days=3),
        summary="Holiday",
        categories=["holiday"],
        uid="cd-1@test",
    )
    cal = await _make_calendar(
        db_session,
        kind="caldav",
        username="svc",
        password_encrypted=encrypt_str("dav-pw"),
    )
    cal.url = "https://dav.example/cal/"

    fake = MagicMock(return_value=[ev])
    with patch("app.services.wol_scheduler.calendar_sync.fetch_caldav_events", fake):
        result = await sync_calendar(db_session, cal)

    assert result["status"] == "success"
    assert result["added"] == 1
    # The blocking client received url, username, and the DECRYPTED password.
    args, _kwargs = fake.call_args
    assert args[0] == "https://dav.example/cal/"
    assert args[1] == "svc"
    assert args[2] == "dav-pw"
    rows = await _events_for(db_session, cal.id)
    assert len(rows) == 1 and rows[0].uid == "cd-1@test"


# ── #2305: the horizon is anchored on the schedule's LOCAL date ────────


@pytest.mark.parametrize(
    ("tz", "now", "expected"),
    [
        # Just after UTC midnight: LA / Honolulu are still on the 20th.
        ("America/Los_Angeles", datetime(2026, 10, 21, 4, 0, tzinfo=UTC), date(2026, 10, 20)),
        ("Pacific/Honolulu", datetime(2026, 10, 21, 4, 0, tzinfo=UTC), date(2026, 10, 20)),
        # East of UTC is already on the 21st, so the UTC date bounds it.
        ("Pacific/Auckland", datetime(2026, 10, 21, 4, 0, tzinfo=UTC), date(2026, 10, 21)),
        # US fall-back day (2026-11-01): 23:30 PST on the 1st is 07:30Z on the 2nd.
        ("America/Los_Angeles", datetime(2026, 11, 2, 7, 30, tzinfo=UTC), date(2026, 11, 1)),
        # ...and 00:30 PDT on the 1st is 07:30Z on the 1st.
        ("America/Los_Angeles", datetime(2026, 11, 1, 7, 30, tzinfo=UTC), date(2026, 11, 1)),
        # US spring-forward (2026-03-08): 23:30 PDT on the 8th is 06:30Z on the 9th.
        ("America/Los_Angeles", datetime(2026, 3, 9, 6, 30, tzinfo=UTC), date(2026, 3, 8)),
        # Sydney spring-forward (2026-10-04): 02:00 AEST -> 03:00 AEDT at 16:00Z on the 3rd.
        ("Australia/Sydney", datetime(2026, 10, 3, 15, 30, tzinfo=UTC), date(2026, 10, 3)),
    ],
)
def test_horizon_anchor_is_the_schedules_local_date(tz: str, now: datetime, expected: date) -> None:
    anchor = horizon_anchor([tz], now)
    # Never later than the local date the gate will judge.
    assert anchor <= expected
    if tz in ("America/Los_Angeles", "Pacific/Honolulu"):
        assert anchor == expected


def test_horizon_anchor_takes_the_earliest_attached_zone_and_covers_no_schedules() -> None:
    now = datetime(2026, 10, 21, 4, 0, tzinfo=UTC)
    assert horizon_anchor(["Pacific/Auckland", "America/Los_Angeles"], now) == date(2026, 10, 20)
    # No schedule attached yet: UTC-12 is the earliest civil date on Earth.
    assert horizon_anchor([], now) == date(2026, 10, 20)
    assert horizon_anchor([], datetime(2026, 10, 21, 13, 0, tzinfo=UTC)) == date(2026, 10, 21)


async def _attach_schedule(db: AsyncSession, cal: WolCalendar, tz: str) -> None:
    sched = _cal_schedule("skip_on_event", tz=tz)
    sched.calendar_id = cal.id
    db.add(sched)
    await db.flush()


@pytest.mark.parametrize("tz", ["America/Los_Angeles", "Pacific/Honolulu", "Etc/GMT+12"])
async def test_sync_keeps_todays_local_event_across_utc_midnight(
    db_session: AsyncSession, tz: str
) -> None:
    cal = await _make_calendar(db_session)
    await _attach_schedule(db_session, cal, tz)
    holiday = date(2026, 10, 20)
    ics = _ics(
        _vevent(uid="hol@test", dtstart=_ymd(holiday), summary="Holiday"),
        _vevent(uid="later@test", dtstart=_ymd(date(2026, 11, 5)), summary="Later"),
    )
    fetch = AsyncMock(return_value=ics)
    # Before UTC midnight, then after it (still the 20th in every zone above).
    for now in (
        datetime(2026, 10, 20, 23, 0, tzinfo=UTC),
        datetime(2026, 10, 21, 4, 0, tzinfo=UTC),
    ):
        with patch("app.services.wol_scheduler.calendar_sync.fetch_ical_url", fetch):
            await sync_calendar(db_session, cal, now=now)
        rows = await _events_for(db_session, cal.id)
        assert holiday in {r.starts_on for r in rows}, now


async def test_sync_still_drops_a_span_that_is_over_everywhere(db_session: AsyncSession) -> None:
    cal = await _make_calendar(db_session)
    await _attach_schedule(db_session, cal, "America/Los_Angeles")
    ics = _ics(
        _vevent(uid="old@test", dtstart="20261019", summary="Yesterday"),
        _vevent(uid="later@test", dtstart="20261105", summary="Later"),
    )
    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=ics),
    ):
        await sync_calendar(db_session, cal, now=datetime(2026, 10, 21, 4, 0, tzinfo=UTC))
    assert {r.uid for r in await _events_for(db_session, cal.id)} == {"later@test"}


# ══════════════════════════════════════════════════════════════════════
# 3. Calendar gate — polarity + calendar_match filter
# ══════════════════════════════════════════════════════════════════════


def _cal_schedule(mode: str, *, match: str | None = None, tz: str = "UTC") -> WolSchedule:
    return WolSchedule(
        name="cal-sched",
        enabled=True,
        target_selector={"mode": "address_tags", "tags": ["wake:nightly"]},
        schedule_cron="0 7 * * *",
        timezone=tz,
        vantage={"kind": "server", "id": None},
        repeat_count=1,
        repeat_interval_ms=0,
        stagger_ms=0,
        port=9,
        calendar_id=uuid.uuid4(),
        calendar_mode=mode,
        calendar_match=match,
    )


def _cal_event(
    start: date,
    end: date,
    *,
    summary: str | None = None,
    categories: list[str] | None = None,
) -> WolCalendarEvent:
    return WolCalendarEvent(
        calendar_id=uuid.uuid4(),
        starts_on=start,
        ends_on=end,
        summary=summary,
        categories=categories or [],
    )


def test_gate_skip_on_event_hits_matching_event() -> None:
    sched = _cal_schedule("skip_on_event")
    ev = _cal_event(date(2026, 12, 25), date(2026, 12, 25), summary="Christmas")
    at = datetime(2026, 12, 25, 7, 0, tzinfo=UTC)
    assert gate_verdict(at, sched, calendar_events=[ev]) == SKIP_CALENDAR_EVENT


def test_gate_skip_on_event_calendar_match_excludes_event() -> None:
    # calendar_match narrows WHICH events count. The event is an exam (not a
    # holiday); a match of "holiday" excludes it → the day is NOT covered → the
    # skip_on_event gate does NOT suppress → the wake fires.
    sched = _cal_schedule("skip_on_event", match="holiday")
    ev = _cal_event(
        date(2026, 12, 25), date(2026, 12, 25), summary="Exam Week", categories=["exam"]
    )
    at = datetime(2026, 12, 25, 7, 0, tzinfo=UTC)
    assert gate_verdict(at, sched, calendar_events=[ev]) is None

    # The SAME event with a match that DOES hit its category is covered → skip.
    sched_hit = _cal_schedule("skip_on_event", match="exam")
    assert gate_verdict(at, sched_hit, calendar_events=[ev]) == SKIP_CALENDAR_EVENT


def test_gate_only_on_event_fires_on_match_skips_without() -> None:
    sched = _cal_schedule("only_on_event")
    ev = _cal_event(date(2026, 9, 1), date(2026, 9, 3), summary="Term")  # school days
    on = datetime(2026, 9, 2, 7, 0, tzinfo=UTC)  # inside the term span → fire
    off = datetime(2026, 9, 10, 7, 0, tzinfo=UTC)  # outside → no school day
    assert gate_verdict(on, sched, calendar_events=[ev]) is None
    assert gate_verdict(off, sched, calendar_events=[ev]) == SKIP_NO_CALENDAR_EVENT


def test_gate_only_on_event_match_filters_which_events_count() -> None:
    # only_on_event with a match: an event that DOESN'T match the filter doesn't
    # count as a school day → the day reads as off → skip.
    sched = _cal_schedule("only_on_event", match="school-day")
    ev = _cal_event(
        date(2026, 9, 1), date(2026, 9, 1), summary="Staff Training", categories=["closed"]
    )
    at = datetime(2026, 9, 1, 7, 0, tzinfo=UTC)
    assert gate_verdict(at, sched, calendar_events=[ev]) == SKIP_NO_CALENDAR_EVENT

    # A matching school-day event on that date flips it to fire.
    school = _cal_event(
        date(2026, 9, 1), date(2026, 9, 1), summary="Regular school-day", categories=["term"]
    )
    assert gate_verdict(at, sched, calendar_events=[school]) is None


# ══════════════════════════════════════════════════════════════════════
# 4. Password at rest — Fernet ciphertext, never returned
# ══════════════════════════════════════════════════════════════════════


async def _superadmin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_calendar_password_stored_encrypted_never_returned(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)

    r = await client.post(
        f"{_BASE}/calendars",
        json={
            "name": "school-caldav",
            "kind": "caldav",
            "url": "https://dav.example/cal/",
            "username": "svc",
            "password": "s3cret-pw",
            "refresh_interval_minutes": 360,
        },
        headers=_hdr(token),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    # The read schema exposes ONLY password_set — never the secret itself.
    assert body["password_set"] is True
    assert "password" not in body
    assert "password_encrypted" not in body
    cid = uuid.UUID(body["id"])

    # GET is the same shape — still no secret on the wire.
    r = await client.get(f"{_BASE}/calendars/{cid}", headers=_hdr(token))
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["password_set"] is True
    assert "password" not in got

    # At rest it's Fernet ciphertext (not the plaintext) that round-trips.
    row = await db_session.get(WolCalendar, cid)
    assert row is not None
    assert row.password_encrypted is not None
    assert row.password_encrypted != b"s3cret-pw"
    assert decrypt_str(row.password_encrypted) == "s3cret-pw"


async def test_calendar_without_password_sets_flag_false(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    r = await client.post(
        f"{_BASE}/calendars",
        json={
            "name": "public-ics",
            "kind": "ical_url",
            "url": "https://cal.example/basic.ics",
        },
        headers=_hdr(token),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["password_set"] is False
    row = await db_session.get(WolCalendar, uuid.UUID(body["id"]))
    assert row is not None and row.password_encrypted is None


# ══════════════════════════════════════════════════════════════════════
# 5. RRULE safety — sub-daily FREQ is a DoS vector and must NOT expand
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("freq", ["SECONDLY", "MINUTELY", "HOURLY"])
def test_parse_subdaily_rrule_is_rejected_not_expanded(freq: str) -> None:
    # A single crafted all-day VEVENT with a sub-daily FREQ would otherwise
    # expand to tens of millions of occurrences over the 400-day horizon
    # (multi-GB list build + minutes of CPU on one component — OOM/stall the
    # single-threaded API worker). The parser must skip it up front, cheaply.
    anchor = date(2026, 3, 2)
    text = _ics(_vevent(uid="evil@test", dtstart=_ymd(anchor), rrule=f"FREQ={freq}"))
    started = time.perf_counter()
    events = parse_ical(text, today=anchor)  # default 400-day horizon
    elapsed = time.perf_counter() - started
    # Skipped outright → zero spans, and it returned near-instantly (a real
    # expansion would take many seconds / minutes and blow memory).
    assert events == []
    assert elapsed < 2.0


def test_parse_weekly_rrule_expands_but_is_bounded_and_fast() -> None:
    # The safe counterpart: a normal FREQ=WEEKLY DOES expand, but the lazy
    # ``xafter(count=...)`` expansion is clamped to the horizon + the per-event
    # ceiling, so the result is small and the call is fast.
    anchor = date(2026, 3, 2)
    text = _ics(_vevent(uid="w@test", dtstart=_ymd(anchor), rrule="FREQ=WEEKLY"))
    started = time.perf_counter()
    events = parse_ical(text, today=anchor)  # default 400-day horizon
    elapsed = time.perf_counter() - started
    # ~57-58 weekly occurrences over 400 days — bounded, well under the cap.
    assert 0 < len(events) < _MAX_OCCURRENCES_PER_EVENT
    assert len(events) <= DEFAULT_HORIZON_DAYS // 7 + 1
    assert elapsed < 2.0


def test_parse_daily_rrule_is_capped_at_max_occurrences() -> None:
    # An all-day FREQ=DAILY over a horizon far larger than the per-event ceiling
    # is clamped to _MAX_OCCURRENCES_PER_EVENT — the count is bounded even when
    # the horizon window would otherwise admit more.
    anchor = date(2026, 1, 1)
    text = _ics(_vevent(uid="d@test", dtstart=_ymd(anchor), rrule="FREQ=DAILY"))
    # A 5000-day horizon admits ~5000 daily occurrences, but the cap holds.
    events = parse_ical(text, today=anchor, horizon_days=5000)
    assert len(events) == _MAX_OCCURRENCES_PER_EVENT


# ══════════════════════════════════════════════════════════════════════
# 6. SSRF — the operator-supplied feed URL is denylist-checked BEFORE any
#    network fetch, and the surfaced error is generic (no host/IP echoed)
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1/internal/feed.ics",
    ],
)
async def test_fetch_ical_url_rejects_blocked_target_before_network(url: str) -> None:
    # Both targets are bare IP literals → they classify (cloud_metadata /
    # loopback) with NO socket call, so the guard fires fully offline. httpx is
    # patched to blow up if it is ever constructed — proving the reject happens
    # BEFORE any request is dialled.
    boom = MagicMock(side_effect=AssertionError("network was dialled on a blocked target"))
    with patch("httpx.AsyncClient", boom):
        with pytest.raises(ValueError) as ei:  # noqa: PT011 — generic-message assert below
            await fetch_ical_url(url)

    msg = str(ei.value)
    # The message is the fixed generic string — no host, IP, or feed line.
    assert msg == _SSRF_GENERIC_MESSAGE
    assert "169.254" not in msg
    assert "127.0.0.1" not in msg
    boom.assert_not_called()


async def test_sync_blocked_target_stores_generic_error(db_session: AsyncSession) -> None:
    # End-to-end through the reconciler: a calendar whose URL resolves to the
    # metadata IP is rejected, and the API-visible ``last_sync_error`` carries a
    # generic message (no IP / status / feed body) so the error store can't be
    # turned into an internal-network discovery oracle.
    cal = await _make_calendar(db_session)
    cal.url = "http://169.254.169.254/latest/meta-data/"

    boom = MagicMock(side_effect=AssertionError("network was dialled on a blocked target"))
    with patch("httpx.AsyncClient", boom):
        result = await sync_calendar(db_session, cal)

    assert result["status"] == "error"
    assert cal.last_sync_status == "error"
    assert cal.last_sync_error is not None
    # Generic — the SSRF ValueError / metadata IP never reaches the operator.
    assert "169.254" not in cal.last_sync_error
    assert "meta-data" not in cal.last_sync_error
    boom.assert_not_called()


# ══════════════════════════════════════════════════════════════════════
# 7. Zero-result guard — an empty-but-successful fetch must not delete a
#    non-empty cache down to zero on the beat path (force=False)
# ══════════════════════════════════════════════════════════════════════


async def test_sync_empty_success_keeps_events_when_not_forced(
    db_session: AsyncSession,
) -> None:
    cal = await _make_calendar(db_session)
    base = date.today()
    ics = _ics(_vevent(uid="a@test", dtstart=_ymd(base + timedelta(days=5)), summary="A"))

    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=ics),
    ):
        await sync_calendar(db_session, cal)
    assert len(await _events_for(db_session, cal.id)) == 1

    # A successful-but-empty fetch (valid VEVENT-less VCALENDAR — no exception)
    # on the beat path (force defaults to False) is treated as suspect: the
    # mass-delete is skipped and last-known-good is kept.
    empty = _ics()  # VCALENDAR with zero VEVENTs → parse_ical returns []
    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=empty),
    ):
        result = await sync_calendar(db_session, cal)

    assert result["status"] == "stale"
    assert result["removed"] == 0
    assert result["total"] == 1  # the cached event still counts
    surviving = await _events_for(db_session, cal.id)
    assert len(surviving) == 1 and surviving[0].uid == "a@test"
    assert cal.last_sync_status == "stale"


async def test_sync_empty_success_empties_cache_when_forced(
    db_session: AsyncSession,
) -> None:
    cal = await _make_calendar(db_session)
    base = date.today()
    ics = _ics(_vevent(uid="a@test", dtstart=_ymd(base + timedelta(days=5)), summary="A"))

    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=ics),
    ):
        await sync_calendar(db_session, cal)
    assert len(await _events_for(db_session, cal.id)) == 1

    # The manual REST ``sync-now`` path passes force=True → a genuinely-cleared
    # calendar CAN empty its cache (transient-empty vs legit-empty are
    # indistinguishable from a 200, so the operator gets the explicit override).
    empty = _ics()
    with patch(
        "app.services.wol_scheduler.calendar_sync.fetch_ical_url",
        AsyncMock(return_value=empty),
    ):
        result = await sync_calendar(db_session, cal, force=True)

    assert result["status"] == "success"
    assert result["removed"] == 1
    assert result["total"] == 0
    assert await _events_for(db_session, cal.id) == []
    assert cal.event_count == 0
    assert cal.last_sync_status == "success"


# ══════════════════════════════════════════════════════════════════════
# 8. MCP preview reflects the calendar gate (parity with REST + runner)
# ══════════════════════════════════════════════════════════════════════


async def _persist_gated_schedule(
    db: AsyncSession,
    user: User,
    *,
    calendar_id: uuid.UUID,
    mode: str,
    next_run_at: datetime,
) -> WolSchedule:
    sched = WolSchedule(
        name=f"mcp-{uuid.uuid4().hex[:6]}",
        enabled=True,
        target_selector={"mode": "address_tags", "tags": ["wake:nightly"]},
        schedule_cron="0 7 * * *",
        timezone="UTC",
        vantage={"kind": "server", "id": None},
        repeat_count=1,
        repeat_interval_ms=0,
        stagger_ms=0,
        port=9,
        calendar_id=calendar_id,
        calendar_mode=mode,
        created_by_user_id=user.id,
        next_run_at=next_run_at,
    )
    db.add(sched)
    await db.flush()
    return sched


async def test_mcp_preview_reflects_calendar_skip(db_session: AsyncSession) -> None:
    # A skip_on_event schedule whose calendar covers the next fire date: the MCP
    # preview must load the events and report the skip — matching the REST
    # preview + the beat runner (the pre-fix bug never loaded events, so it
    # reported gate_verdict=null / would_fire=true, contradicting the runner).
    from app.services.ai.tools.wol_scheduler import (  # noqa: PLC0415
        PreviewWolScheduleTargetsArgs,
        preview_wol_schedule_targets,
    )

    user, _ = await _superadmin(db_session)
    cal = await _make_calendar(db_session)
    fire_day = date(2026, 12, 25)
    db_session.add(
        WolCalendarEvent(
            calendar_id=cal.id,
            starts_on=fire_day,
            ends_on=fire_day,
            summary="Christmas",
            categories=["holiday"],
        )
    )
    sched = await _persist_gated_schedule(
        db_session,
        user,
        calendar_id=cal.id,
        mode="skip_on_event",
        next_run_at=datetime(2026, 12, 25, 7, 0, tzinfo=UTC),
    )

    result = await preview_wol_schedule_targets(
        db_session, user, PreviewWolScheduleTargetsArgs(schedule_id=sched.id)
    )
    assert result["gate_verdict"] == SKIP_CALENDAR_EVENT
    assert result["would_fire"] is False


async def test_mcp_preview_would_fire_when_calendar_does_not_cover(
    db_session: AsyncSession,
) -> None:
    # Same skip_on_event gate, but the next fire date is NOT covered by any
    # event → the calendar step passes and the preview reports would_fire=true.
    # Proves the verdict is driven by the loaded events, not a constant.
    from app.services.ai.tools.wol_scheduler import (  # noqa: PLC0415
        PreviewWolScheduleTargetsArgs,
        preview_wol_schedule_targets,
    )

    user, _ = await _superadmin(db_session)
    cal = await _make_calendar(db_session)
    db_session.add(
        WolCalendarEvent(
            calendar_id=cal.id,
            starts_on=date(2026, 12, 25),
            ends_on=date(2026, 12, 25),
            summary="Christmas",
        )
    )
    sched = await _persist_gated_schedule(
        db_session,
        user,
        calendar_id=cal.id,
        mode="skip_on_event",
        next_run_at=datetime(2026, 12, 26, 7, 0, tzinfo=UTC),  # not a holiday
    )

    result = await preview_wol_schedule_targets(
        db_session, user, PreviewWolScheduleTargetsArgs(schedule_id=sched.id)
    )
    assert result["gate_verdict"] is None
    assert result["would_fire"] is True


# ══════════════════════════════════════════════════════════════════════
# 9. MCP create-schedule rejects a malformed calendar_match regex (parity
#    with the REST WakeScheduleCreate 422 — never silently store match-all)
# ══════════════════════════════════════════════════════════════════════


def test_mcp_create_schedule_rejects_invalid_calendar_match() -> None:
    from app.services.ai.operations import (  # noqa: PLC0415
        CreateWolScheduleArgs,
        WolSelectorArgs,
    )

    with pytest.raises(ValidationError):
        CreateWolScheduleArgs(
            name="cal-bad-regex",
            selector=WolSelectorArgs(mode="address_tags", tags=["wake:nightly"]),
            calendar_id=str(uuid.uuid4()),
            calendar_mode="skip_on_event",
            calendar_match="Holiday(2026",  # unbalanced paren → re.error
        )


def test_mcp_create_schedule_accepts_valid_calendar_match() -> None:
    # The valid-regex counterpart round-trips (the validator is not over-eager).
    from app.services.ai.operations import (  # noqa: PLC0415
        CreateWolScheduleArgs,
        WolSelectorArgs,
    )

    args = CreateWolScheduleArgs(
        name="cal-ok-regex",
        selector=WolSelectorArgs(mode="address_tags", tags=["wake:nightly"]),
        calendar_id=str(uuid.uuid4()),
        calendar_mode="skip_on_event",
        calendar_match="holiday|closed",
    )
    assert args.calendar_match == "holiday|closed"
