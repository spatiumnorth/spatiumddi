"""Shared pagination envelope for list endpoints (#455).

A generic ``{items, total, page, page_size}`` response so list endpoints that
can grow unbounded (DNS zone records, DHCP leases, …) paginate server-side
instead of returning the whole table in one query + payload. New list
endpoints should adopt ``Page[T]`` for a consistent shape — the same shape the
nmap / network-device list endpoints already use ad-hoc.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy import func, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

# Default page size for paginated list endpoints. 100 keeps a 20k-record zone
# (the #455 trigger) to a 200-row poll instead of pulling the whole table.
DEFAULT_PAGE_SIZE = 100
# Upper bound a client may request. Bounded so "fetch all" can't sneak back in
# through an enormous page_size — bulk export has its own dedicated endpoint.
MAX_PAGE_SIZE = 1000
# Upper bound on the page NUMBER. ``page_size`` was bounded from the start and
# ``page`` was not, which left every list endpoint one query parameter away from
# an error: the offset is ``(page - 1) * page_size``, SQL ``OFFSET`` is a bigint,
# and a large enough ``page`` overflows it before Postgres ever sees a row.
# Measured on a live appliance at DEFAULT_PAGE_SIZE — page 92233720368547759
# gives offset 9223372036854775800 and returns 200; page 92233720368547760
# gives 9223372036854775900, past 2**63-1, and returned a 500 at the time
# (the global DBAPIError handler now answers 422, still not a useful reply).
#
# A million pages is past any real client (a million pages of MAX_PAGE_SIZE is
# a billion rows) while leaving the largest reachable offset — 10**9 — nine
# orders of magnitude below the bigint ceiling, so no page_size can climb back
# over it. Declared rather than clamped: the bound belongs in the OpenAPI
# document next to page_size's, and an out-of-range page is a client error that
# deserves the same 422 an out-of-range page_size already gets.
MAX_PAGE = 1_000_000


class Page[T](BaseModel):
    """A single page of ``items`` plus the counters the UI needs to render
    page controls (``total`` across all pages, current ``page``, ``page_size``).
    """

    items: list[T]
    total: int
    page: int
    page_size: int


def with_pk_tiebreak(base: Select[Any]) -> Select[Any]:
    """Return ``base`` with the first entity's primary key appended to its ORDER BY.

    Offset paging is only stable when the ordering is total. A sort on a
    non-unique column (``last_seen_at``, ``expired_at``, ``name``) leaves rows
    that share a value free to land on either side of a page boundary from one
    request to the next, so a client walking the pages skips or repeats rows
    (#4149: 41 of ~3,900 leases "missing" while a Kea server was ingesting).
    Ending the ordering in the primary key makes it total without changing the
    requested sort. A no-op when the select has no ORDER BY (the caller asked
    for no order) or already orders by every key column.
    """
    if not base._order_by_clauses:
        return base
    entity = base.column_descriptions[0].get("entity") if base.column_descriptions else None
    if entity is None:
        return base
    pk_cols = list(inspect(entity).primary_key)
    present = {getattr(c, "element", c) for c in base._order_by_clauses}
    missing = [c for c in pk_cols if c not in present]
    return base.order_by(*missing) if missing else base


async def paginate(
    db: AsyncSession, base: Select[Any], *, page: int, page_size: int
) -> tuple[list[Any], int]:
    """Return ``(page_rows, total)`` for ``base``, a ``select`` of ORM entities.

    ``base`` should already carry its ``WHERE`` + ``ORDER BY``. ``total`` is
    counted with the ordering stripped (it's irrelevant to a count and lets
    Postgres skip the sort); the returned slice keeps the order and applies
    ``LIMIT``/``OFFSET``. Callers map the scalar rows to their response model.

    The ORDER BY is made total with the entity's primary key (see
    :func:`with_pk_tiebreak`). Offset paging over a set that is being written
    can still move a row whose *sort key* changes between requests (a renewed
    lease's ``last_seen_at``); that is inherent to offset paging, see
    docs/API.md section 6.
    """
    total = (
        await db.execute(select(func.count()).select_from(base.order_by(None).subquery()))
    ).scalar_one()
    rows = (
        (await db.execute(with_pk_tiebreak(base).limit(page_size).offset((page - 1) * page_size)))
        .scalars()
        .all()
    )
    return list(rows), total
