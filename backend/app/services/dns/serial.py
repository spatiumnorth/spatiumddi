"""Zone serial bumping helper.

RFC 1912 recommends ``YYYYMMDDNN`` serials. We follow that convention when the
current serial is already in that range; otherwise we increment monotonically
so we never decrease a serial — RFC 1982 comparison treats decreasing serials
as wrap-around, which breaks AXFR/IXFR.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.dns import DNSZone


SERIAL_MODULUS = 2**32  # SOA serials are unsigned 32-bit, RFC 1982 arithmetic is mod 2^32


def compute_next_serial(current: int, *, now: datetime | None = None) -> int:
    """Return the next serial for a zone with ``current`` as the last value.

    Rules:
      * If ``current`` is a valid RFC 1912 ``YYYYMMDDNN`` serial for today,
        increment the NN component (capped at 99 — beyond that we fall back
        to ``current + 1`` to stay monotonic).
      * If ``current`` is a valid RFC 1912 serial from a past day, use
        ``YYYYMMDD00`` for today (if greater) or ``current + 1`` otherwise.
      * Otherwise (freshly seeded / garbage value) use today's
        ``YYYYMMDD00`` if that is greater than ``current``, else ``current + 1``.
    """
    nxt = _next_serial(current, now=now) % SERIAL_MODULUS
    # #1975 — the increment past 2^32 - 1 wraps (RFC 1982 §3.1), but to 1, not
    # 0: BIND's own ``increment`` update method skips 0 the same way, and 0 is
    # this codebase's "never seeded" value — the agents and the zone-file
    # writer render ``serial or 1``, so a stored 0 would be served as 1 and the
    # Zone Sync pill would compare the reported 1 against a target of 0.
    # 1 is still later than 2^32 - 1 in serial arithmetic (distance 2).
    return nxt or 1


def _next_serial(current: int, *, now: datetime | None) -> int:
    now = now or datetime.now(UTC)
    today_base = int(now.strftime("%Y%m%d")) * 100

    candidate_rfc = today_base
    if 1_000_000_000 <= current <= 9_999_999_999:  # 10 digits = YYYYMMDDNN range
        cur_date = current // 100
        cur_nn = current % 100
        if cur_date == today_base // 100:
            if cur_nn < 99:
                return current + 1
            return current + 1  # overflow safety — monotonic
        if today_base > current:
            return today_base
        return current + 1

    if candidate_rfc > current:
        return candidate_rfc
    return current + 1


def bump_zone_serial(zone: DNSZone, *, now: datetime | None = None) -> int:
    """Mutate ``zone.last_serial`` to the next serial and return it.

    Forward reference is used to keep this module import-cheap (no ORM
    models imported at module load — tests call this with either the real
    ORM object or a lightweight stand-in providing ``last_serial``).
    """
    current = int(getattr(zone, "last_serial", 0) or 0)
    nxt = compute_next_serial(current, now=now)
    zone.last_serial = nxt
    return nxt


__all__ = ["bump_zone_serial", "compute_next_serial"]
