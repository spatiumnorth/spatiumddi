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
from sqlalchemy import func, select
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


async def paginate(
    db: AsyncSession, base: Select[Any], *, page: int, page_size: int
) -> tuple[list[Any], int]:
    """Return ``(page_rows, total)`` for ``base``, a ``select`` of ORM entities.

    ``base`` should already carry its ``WHERE`` + ``ORDER BY``. ``total`` is
    counted with the ordering stripped (it's irrelevant to a count and lets
    Postgres skip the sort); the returned slice keeps the order and applies
    ``LIMIT``/``OFFSET``. Callers map the scalar rows to their response model.
    """
    total = (
        await db.execute(select(func.count()).select_from(base.order_by(None).subquery()))
    ).scalar_one()
    rows = (await db.execute(base.limit(page_size).offset((page - 1) * page_size))).scalars().all()
    return list(rows), total
