"""iCal / CalDAV parsing for the Scheduled Wake-on-LAN calendar gate —
Phase 2 (issue #586).

Turns a raw ``.ics`` payload (or an authenticated CalDAV collection) into a
list of flattened, recurrence-expanded, all-day :class:`ParsedEvent` date
spans that the gate compares the schedule-local fire date against.

The load-bearing all-day semantics (RFC 5545 §3.8.2.2):

* Only **all-day** VEVENTs count — ``DTSTART`` is a bare ``date`` (``VALUE=DATE``),
  not a ``datetime``. A timed event is ignored (a holiday / term calendar is
  all-day spans; a 09:00 meeting is noise).
* ``DTEND`` is **exclusive** for all-day VEVENTs → the inclusive ``ends_on`` is
  ``DTEND - 1 day``. No ``DTEND`` and no ``DURATION`` → a one-day event
  (``ends_on == starts_on``). ``DURATION`` is honoured (added to ``DTSTART``,
  then the same exclusive-end −1-day correction).
* Recurrence (``RRULE`` / ``RDATE``) is expanded via
  :func:`dateutil.rrule.rrulestr` over a **bounded forward horizon**
  (default 400 days) so a ``FREQ=YEARLY`` rule can't produce an unbounded set;
  ``EXDATE`` occurrences are dropped. Only occurrences whose start falls within
  ``[today, today + horizon]`` are emitted.
* All-day dates are **floating** — compared on the local calendar date with no
  timezone shift. ``ParsedEvent`` therefore carries plain :class:`date` spans.

``dateutil`` (python-dateutil) is a confirmed dependency; ``icalendar`` and
``caldav`` are pinned in ``pyproject.toml`` for this feature.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

import structlog

from app.core.safe_fetch import TARGET_REFUSED_MESSAGE, FetchRefusedError, safe_get_text
from app.core.ssrf import SSRFBlockedError, assert_safe_target

logger = structlog.get_logger(__name__)

# Default bounded forward horizon for recurrence expansion + persistence.
DEFAULT_HORIZON_DAYS = 400

# Hard cap on expanded occurrences per VEVENT — a pathological ``FREQ=DAILY``
# over the horizon is still bounded, but a malformed COUNT/UNTIL shouldn't be
# able to blow memory even within the horizon window.
_MAX_OCCURRENCES_PER_EVENT = 1000

# Sub-daily recurrence frequencies are rejected outright: an all-day holiday /
# term gate never needs them, and an ``FREQ=SECONDLY`` all-day VEVENT would
# otherwise expand to tens of millions of occurrences over the horizon
# (memory/CPU DoS). YEARLY / MONTHLY / WEEKLY / DAILY are the only useful ones.
_SUB_DAILY_FREQ = frozenset({"SECONDLY", "MINUTELY", "HOURLY"})

# Max HTTP redirect hops we will follow on an iCal feed fetch. Each hop's
# resolved target is re-checked against the SSRF denylist (an origin-only
# check is trivially bypassable with a 302 to an internal address).
_MAX_REDIRECTS = 5

# Generic, host/IP-free message surfaced to the operator when a feed target is
# denied by the SSRF guard — the resolved target is logged server-side only so
# the error store can't be turned into an internal-network discovery oracle.
_SSRF_GENERIC_MESSAGE = "calendar feed target is not permitted"


def _rrule_freq(rule_text: str) -> str | None:
    """Pull the ``FREQ=`` token (upper-cased) out of a canonical RRULE string."""
    for token in rule_text.replace("\n", ";").split(";"):
        key, sep, value = token.partition("=")
        if sep and key.strip().upper() == "FREQ":
            return value.strip().upper()
    return None


@dataclass(frozen=True)
class ParsedEvent:
    """One flattened all-day span (recurrence already expanded)."""

    starts_on: date
    ends_on: date  # inclusive
    summary: str | None = None
    categories: list[str] = field(default_factory=list)
    uid: str | None = None


def _as_all_day_date(value: object) -> date | None:
    """Return the bare ``date`` for an all-day DTSTART/DTEND, or ``None`` when
    the component is a timed ``datetime`` (which we deliberately ignore)."""
    # icalendar decodes DTSTART/DTEND to ``.dt`` — a ``date`` for VALUE=DATE,
    # a ``datetime`` for VALUE=DATE-TIME. ``datetime`` subclasses ``date`` so
    # the order of these checks matters.
    if isinstance(value, datetime):
        return None
    if isinstance(value, date):
        return value
    return None


def _extract_categories(comp: object) -> list[str]:
    """Flatten an icalendar CATEGORIES property (single or multi) to str list."""
    raw = comp.get("categories") if hasattr(comp, "get") else None  # type: ignore[attr-defined]
    if raw is None:
        return []
    out: list[str] = []
    # icalendar may hand back a single vCategory, a list of them, or a plain
    # string depending on how many CATEGORIES lines the VEVENT carried.
    candidates = raw if isinstance(raw, list) else [raw]
    for item in candidates:
        cats = getattr(item, "cats", None)
        if cats is not None:
            for c in cats:
                text = str(c).strip()
                if text:
                    out.append(text)
        else:
            text = str(item).strip()
            if text:
                out.append(text)
    return out


def _span_from_component(
    comp: object,
) -> tuple[date, date] | None:
    """Compute the base ``(starts_on, ends_on_inclusive)`` for a VEVENT, or
    ``None`` when it isn't an all-day event we can use."""
    dtstart_prop = comp.get("dtstart") if hasattr(comp, "get") else None  # type: ignore[attr-defined]
    if dtstart_prop is None:
        return None
    start = _as_all_day_date(getattr(dtstart_prop, "dt", None))
    if start is None:
        return None

    dtend_prop = comp.get("dtend") if hasattr(comp, "get") else None  # type: ignore[attr-defined]
    duration_prop = comp.get("duration") if hasattr(comp, "get") else None  # type: ignore[attr-defined]

    if dtend_prop is not None:
        end_excl = _as_all_day_date(getattr(dtend_prop, "dt", None))
        if end_excl is None:
            # DTEND present but timed — treat as single all-day.
            return (start, start)
        # Exclusive → inclusive. Guard against DTEND <= DTSTART.
        ends_on = end_excl - timedelta(days=1)
        if ends_on < start:
            ends_on = start
        return (start, ends_on)

    if duration_prop is not None:
        dur = getattr(duration_prop, "dt", None)
        if isinstance(dur, timedelta) and dur.days > 0:
            # DURATION spans an exclusive end too.
            return (start, start + timedelta(days=dur.days - 1))
        return (start, start)

    # No DTEND / DURATION → one-day all-day event.
    return (start, start)


def _expand_recurrence(
    comp: object,
    base_start: date,
    base_end_inclusive: date,
    *,
    horizon_start: date,
    horizon_end: date,
) -> list[tuple[date, date]]:
    """Expand RRULE / RDATE (minus EXDATE) into concrete inclusive spans within
    the horizon. Non-recurring events return the single base span."""
    has_rrule = hasattr(comp, "get") and comp.get("rrule") is not None  # type: ignore[attr-defined]
    has_rdate = hasattr(comp, "get") and comp.get("rdate") is not None  # type: ignore[attr-defined]
    if not has_rrule and not has_rdate:
        # Single occurrence — only keep it if it intersects the horizon.
        if base_end_inclusive < horizon_start or base_start > horizon_end:
            return []
        return [(base_start, base_end_inclusive)]

    duration_days = (base_end_inclusive - base_start).days

    # dateutil.rrule works in datetime space; anchor at midnight and stay in
    # the floating (naive) domain so no tz shift creeps in.
    from dateutil import rrule as _rrule  # noqa: PLC0415

    dt_start = datetime(base_start.year, base_start.month, base_start.day)
    win_start = datetime(horizon_start.year, horizon_start.month, horizon_start.day)
    win_end = datetime(horizon_end.year, horizon_end.month, horizon_end.day)

    starts: set[datetime] = set()

    if has_rrule:
        rrule_val = comp.get("rrule")  # type: ignore[attr-defined]
        # icalendar stores RRULE as a vRecur dict; ``.to_ical()`` renders the
        # canonical "FREQ=...;..." string rrulestr expects.
        rule_lines = rrule_val if isinstance(rrule_val, list) else [rrule_val]
        for rl in rule_lines:
            try:
                rule_text = rl.to_ical().decode() if hasattr(rl, "to_ical") else str(rl)
            except (ValueError, TypeError) as exc:
                logger.warning("wol_calendar_bad_rrule", error=str(exc))
                continue
            # Reject sub-daily frequencies up front — an all-day gate never
            # needs them, and expanding one is the DoS vector.
            freq = _rrule_freq(rule_text)
            if freq in _SUB_DAILY_FREQ:
                logger.warning("wol_calendar_subdaily_rrule_skipped", freq=freq)
                continue
            try:
                rule = _rrule.rrulestr(rule_text, dtstart=dt_start)
            except (ValueError, TypeError) as exc:
                logger.warning("wol_calendar_bad_rrule", error=str(exc))
                continue
            # Expand LAZILY with a hard count cap so an unbounded (COUNT/UNTIL-
            # less) rule can never materialise a huge list. ``xafter`` is a
            # generator that yields occurrences in ascending order; we stop at
            # the first one past the horizon end, or when the cap is hit.
            for occ in rule.xafter(win_start, count=_MAX_OCCURRENCES_PER_EVENT, inc=True):
                if occ > win_end:
                    break
                starts.add(occ)
                if len(starts) >= _MAX_OCCURRENCES_PER_EVENT:
                    break

    if has_rdate:
        rdate_val = comp.get("rdate")  # type: ignore[attr-defined]
        rdate_lines = rdate_val if isinstance(rdate_val, list) else [rdate_val]
        for rd in rdate_lines:
            for dt in getattr(rd, "dts", []) or []:
                d = _as_all_day_date(getattr(dt, "dt", None))
                if d is not None:
                    starts.add(datetime(d.year, d.month, d.day))

    # EXDATE removal.
    if hasattr(comp, "get") and comp.get("exdate") is not None:  # type: ignore[attr-defined]
        exdate_val = comp.get("exdate")  # type: ignore[attr-defined]
        ex_lines = exdate_val if isinstance(exdate_val, list) else [exdate_val]
        for ex in ex_lines:
            for dt in getattr(ex, "dts", []) or []:
                d = _as_all_day_date(getattr(dt, "dt", None))
                if d is not None:
                    starts.discard(datetime(d.year, d.month, d.day))

    spans: list[tuple[date, date]] = []
    for s in sorted(starts):
        sd = s.date()
        ed = sd + timedelta(days=duration_days)
        if ed < horizon_start or sd > horizon_end:
            continue
        spans.append((sd, ed))
    return spans


def parse_ical(
    text: str,
    *,
    horizon_days: int = DEFAULT_HORIZON_DAYS,
    today: date | None = None,
) -> list[ParsedEvent]:
    """Parse an ``.ics`` payload into flattened all-day :class:`ParsedEvent`
    spans, recurrence expanded over ``[today, today + horizon_days]``.

    Timed events are ignored; a malformed VEVENT is skipped (never fatal — a
    single bad component must not lose the whole feed).
    """
    from icalendar import Calendar  # noqa: PLC0415

    anchor = today or date.today()
    horizon_start = anchor
    horizon_end = anchor + timedelta(days=max(1, horizon_days))

    try:
        cal = Calendar.from_ical(text)
    except Exception as exc:  # noqa: BLE001 — icalendar raises a bare ValueError family
        raise ValueError(f"could not parse iCalendar payload: {exc}") from exc

    events: list[ParsedEvent] = []
    for comp in cal.walk("VEVENT"):
        try:
            base = _span_from_component(comp)
            if base is None:
                continue
            base_start, base_end = base
            summary_raw = comp.get("summary")
            summary = str(summary_raw).strip() if summary_raw is not None else None
            categories = _extract_categories(comp)
            uid_raw = comp.get("uid")
            uid = str(uid_raw).strip() if uid_raw is not None else None

            for span_start, span_end in _expand_recurrence(
                comp,
                base_start,
                base_end,
                horizon_start=horizon_start,
                horizon_end=horizon_end,
            ):
                events.append(
                    ParsedEvent(
                        starts_on=span_start,
                        ends_on=span_end,
                        summary=summary,
                        categories=list(categories),
                        uid=uid,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("wol_calendar_bad_vevent", error=str(exc))
            continue
    return events


def normalise_ical_url(url: str) -> str:
    """Rewrite a ``webcal://`` subscription URL to ``https://`` (webcal is a
    non-fetchable convenience scheme that means "subscribe over https")."""
    u = url.strip()
    if u.lower().startswith("webcal://"):
        return "https://" + u[len("webcal://") :]
    if u.lower().startswith("webcals://"):
        return "https://" + u[len("webcals://") :]
    return u


def _guard_target(target: str) -> None:
    """Raise a generic ``ValueError`` if ``target`` resolves to an SSRF pivot.

    Used by the CalDAV path, whose blocking client dials on its own. The full
    resolved target is logged server-side (via the ssrf guard's own
    structured warning) but never surfaced to the operator, so a blocked feed
    can't be used to fingerprint the internal network.
    """
    try:
        assert_safe_target(target, label="wol_calendar", block=True)
    except SSRFBlockedError as exc:
        logger.warning("wol_calendar_ssrf_blocked", detail=str(exc))
        raise ValueError(_SSRF_GENERIC_MESSAGE) from None


async def fetch_ical_url(url: str, *, timeout: float = 60.0) -> str:
    """Fetch a raw ``.ics`` payload over HTTP(S) (``webcal://`` normalised).

    Goes through :func:`app.core.safe_fetch.safe_get_text`: http/https only,
    the target checked against the loopback / link-local / cloud-metadata
    denylist before the request AND at connect time, and every redirect hop
    re-checked (an origin-only check is undone by a 302 to an internal
    address).

    Raises ``httpx.HTTPError`` on a transport / status failure so the caller's
    ``autoretry_for`` can back off (mirrors the DNS blocklist feed pull). A
    refused target / redirect-limit overflow raises a generic ``ValueError``
    (permanent — retrying won't help) with no host/IP in the message.
    """
    try:
        return await safe_get_text(
            normalise_ical_url(url),
            label="wol_calendar",
            timeout=timeout,
            max_redirects=_MAX_REDIRECTS,
        )
    except FetchRefusedError as exc:
        if str(exc) == TARGET_REFUSED_MESSAGE:
            raise ValueError(_SSRF_GENERIC_MESSAGE) from None
        raise ValueError(f"calendar {exc}") from None


def fetch_caldav_events(
    url: str,
    username: str | None,
    password: str | None,
    *,
    horizon_days: int = DEFAULT_HORIZON_DAYS,
    today: date | None = None,
) -> list[ParsedEvent]:
    """Pull all-day events from an authenticated CalDAV collection over the
    horizon and parse them via :func:`parse_ical`.

    Synchronous (the ``caldav`` client is blocking); the reconciler calls this
    through ``asyncio.to_thread`` so it never blocks the event loop. Network /
    auth failures raise so the caller's retry policy applies.
    """
    import caldav  # noqa: PLC0415

    # SSRF guard: resolve + check the operator-supplied CalDAV URL before the
    # blocking client dials it. A blocked target raises a generic ValueError
    # (permanent) with no host/IP leaked.
    _guard_target(url)

    anchor = today or date.today()
    win_start = datetime(anchor.year, anchor.month, anchor.day)
    win_end = win_start + timedelta(days=max(1, horizon_days))

    client = caldav.DAVClient(url=url, username=username or None, password=password or None)
    try:
        calendar = client.calendar(url=url)
        # ``expand=False`` — we run our own RRULE expansion in parse_ical so the
        # semantics are identical across ical_url + caldav (not every server
        # supports server-side expand).
        results = calendar.date_search(start=win_start, end=win_end, expand=False)
    finally:
        # DAVClient holds a requests.Session; close it so we don't leak sockets.
        try:
            client.close()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass

    events: list[ParsedEvent] = []
    for obj in results:
        data = getattr(obj, "data", None)
        if not data:
            continue
        events.extend(parse_ical(data, horizon_days=horizon_days, today=anchor))
    return events


__all__ = [
    "ParsedEvent",
    "parse_ical",
    "fetch_ical_url",
    "fetch_caldav_events",
    "normalise_ical_url",
    "DEFAULT_HORIZON_DAYS",
]
