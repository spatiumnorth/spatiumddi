"""Address-set write-delegation gate (issue #103).

A caller without subnet-wide ``write`` may still mutate an IP if it falls
inside an :class:`~app.models.address_set.AddressSet` they hold
``write``/``admin`` on. The control plane resolves the caller's writable
ranges on a subnet ONCE per request (:func:`load_writable_set_ranges`) and
then checks each candidate IP against them (:func:`user_can_write_ip`).

Both the interactive IPAM router and the import path consume these helpers;
they live here (not inside ``ipam.router``) so neither side reaches across
modules via a function-local import that would break only at runtime if a
helper were renamed (#12).

Representation (#10): contiguous sets become ``(start_int, end_int)`` interval
tuples (O(interval-count) membership), and explicit sets become a hash SET of
packed host ints (O(1) membership) so a large explicit set doesn't degrade to
an O(n) linear scan per candidate IP.
"""

from __future__ import annotations

import bisect
import ipaddress
import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import user_has_permission
from app.models.address_set import AddressSet
from app.services.feature_modules import is_module_enabled

logger = structlog.get_logger(__name__)

# Availability bound (#103, finding #7): cap the number of address-set rows we
# consider per subnet, and the total host ints an explicit-set load may
# accumulate, so a pathological subnet (thousands of delegated sets) can't turn
# the per-request gate build into an unbounded scan/allocation. Beyond the caps
# we stop loading and log a structured warning; correctness is unchanged for the
# normal (tens-of-sets) case. The interval list is additionally sorted + merged
# so membership is a binary search, not a linear scan over every interval.
ADDRESS_SETS_MODULE = "ipam.address_sets"
_MAX_SETS_PER_SUBNET: int = 4096
_MAX_EXPLICIT_HOSTS: int = 1_000_000


def _pack_ip(value: object) -> int | None:
    """Pack an IP (string / INET) into its integer form, or ``None`` if it
    can't be parsed. Shared by every IP→int conversion in this module so the
    packing rule lives in exactly one place (#12)."""
    try:
        return int(ipaddress.ip_address(str(value)))
    except (ValueError, TypeError):
        return None


@dataclass
class WritableSetRanges:
    """The caller's address-set-delegated writable space on one subnet.

    * ``intervals`` — contiguous ``(start_int, end_int)`` spans (inclusive),
      kept SORTED + non-overlapping after :meth:`finalize` so membership is an
      ``O(log n)`` binary search rather than an ``O(n)`` linear scan (#7).
    * ``hosts`` — packed ints for explicit-set members; ``O(1)`` membership.

    ``bool(ranges)`` is True iff the caller can write at least one address via
    delegation, so call sites can keep the prior ``if not set_ranges`` idiom.

    Build by appending raw intervals/hosts, then call :meth:`finalize` once;
    :func:`load_writable_set_ranges` does this before returning.
    """

    intervals: list[tuple[int, int]] = field(default_factory=list)
    hosts: set[int] = field(default_factory=set)
    # Lower bounds of the merged intervals, kept parallel to ``intervals`` so a
    # single ``bisect`` locates the only interval that could contain a query.
    _starts: list[int] = field(default_factory=list, repr=False)

    def __bool__(self) -> bool:
        return bool(self.intervals) or bool(self.hosts)

    def finalize(self) -> WritableSetRanges:
        """Sort + merge overlapping/adjacent intervals and cache their lower
        bounds for binary-search membership. Idempotent; returns ``self`` so it
        can be used inline."""
        if not self.intervals:
            self._starts = []
            return self
        ordered = sorted(self.intervals)
        merged: list[tuple[int, int]] = [ordered[0]]
        for s, e in ordered[1:]:
            ls, le = merged[-1]
            # Merge when the next span overlaps or is immediately adjacent
            # (``s <= le + 1``) — contiguous coverage collapses to one interval.
            if s <= le + 1:
                if e > le:
                    merged[-1] = (ls, e)
            else:
                merged.append((s, e))
        self.intervals = merged
        self._starts = [s for s, _ in merged]
        return self

    def contains(self, ip_int: int) -> bool:
        if ip_int in self.hosts:
            return True
        if not self.intervals:
            return False
        # Defensive: if intervals were appended without a ``finalize`` (e.g. a
        # direct construction outside ``load_writable_set_ranges``), the cached
        # ``_starts`` is stale — finalize once so the binary search is correct.
        if len(self._starts) != len(self.intervals):
            self.finalize()
        # Intervals are sorted + non-overlapping after ``finalize``: the only
        # candidate is the last interval whose start <= ip_int.
        idx = bisect.bisect_right(self._starts, ip_int) - 1
        if idx < 0:
            return False
        s, e = self.intervals[idx]
        return s <= ip_int <= e


async def load_writable_set_ranges(
    db: AsyncSession, user: Any, subnet_id: uuid.UUID, action: str = "write"
) -> WritableSetRanges:
    """Return the :class:`WritableSetRanges` the ``user`` can WRITE on this subnet.

    ``action`` names the grant a set must carry to count: ``"write"`` (the
    default) for a mutation, ``"delete"`` for removing addresses, so a delete
    grant scoped to one set reaches only the addresses inside that set.

    A set counts when the user holds ``write`` on its address_set id — ``admin``
    implies ``write`` via the permission matcher, so a SINGLE ``write`` check per
    set is sufficient (#9; the old code resolved ``write`` then ``admin``,
    doubling the role-tree walk). Empty when none — the caller still must hold
    subnet write for any IP outside these ranges.

    Always empty while the ``ipam.address_sets`` feature module is off (#3762):
    the sets are hidden and their API 404s, so a grant on one must not widen
    allocation write access the operator can no longer see or manage.
    """
    if not await is_module_enabled(db, ADDRESS_SETS_MODULE):
        return WritableSetRanges()
    # Bound the rows we pull per subnet (#7) — a pathological subnet with an
    # absurd number of delegated sets must not turn this per-request build into
    # an unbounded scan. ``+1`` so we can detect (and warn on) the overflow.
    rows = await db.execute(
        select(
            AddressSet.id,
            AddressSet.range_kind,
            AddressSet.start_address,
            AddressSet.end_address,
            AddressSet.explicit_addresses,
        )
        .where(AddressSet.subnet_id == subnet_id)
        .limit(_MAX_SETS_PER_SUBNET + 1)
    )
    fetched = rows.all()
    if len(fetched) > _MAX_SETS_PER_SUBNET:
        logger.warning(
            "address_set_gate_truncated",
            subnet_id=str(subnet_id),
            cap=_MAX_SETS_PER_SUBNET,
            reason="too_many_sets",
        )
        fetched = fetched[:_MAX_SETS_PER_SUBNET]

    ranges = WritableSetRanges()
    explicit_overflowed = False
    for set_id, range_kind, start_addr, end_addr, explicit in fetched:
        # ``admin`` implies ``write`` through ``_action_matches`` — one check.
        if not user_has_permission(user, action, "address_set", set_id):
            continue
        if range_kind == "contiguous" and start_addr is not None and end_addr is not None:
            s = _pack_ip(start_addr)
            e = _pack_ip(end_addr)
            if s is None or e is None:
                continue
            if s > e:
                # Guarded by a CHECK constraint + API validation, so this
                # should never fire; keep the defensive swap but flag it as a
                # data-integrity signal if it ever does (#13).
                logger.warning(
                    "address_set_inverted_bounds",
                    address_set_id=str(set_id),
                    subnet_id=str(subnet_id),
                    start_address=str(start_addr),
                    end_address=str(end_addr),
                )
                s, e = e, s
            ranges.intervals.append((s, e))
        else:
            for raw in explicit or []:
                # Bound the total explicit-host set so a heap of large explicit
                # sets can't balloon memory (#7). Correctness for normal sizes is
                # unchanged; over the cap we stop adding and warn once.
                if len(ranges.hosts) >= _MAX_EXPLICIT_HOSTS:
                    explicit_overflowed = True
                    break
                v = _pack_ip(raw)
                if v is not None:
                    ranges.hosts.add(v)
            if explicit_overflowed:
                break
    if explicit_overflowed:
        logger.warning(
            "address_set_gate_truncated",
            subnet_id=str(subnet_id),
            cap=_MAX_EXPLICIT_HOSTS,
            reason="too_many_explicit_hosts",
        )
    # Sort + merge the contiguous intervals once so membership is a binary search.
    return ranges.finalize()


def user_can_write_ip(
    user: Any,
    ip_int: int,
    subnet_writable: bool,
    set_ranges: WritableSetRanges,
) -> bool:
    """True if the caller may mutate this IP — either subnet-wide write, or the
    IP falls inside an address set they hold write/admin on (#103)."""
    return subnet_writable or set_ranges.contains(ip_int)
