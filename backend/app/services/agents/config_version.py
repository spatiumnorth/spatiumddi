"""A cheap version key for an agent's config, so an idle long-poll tick skips the rebuild (#1109).

The DHCP and Looking Glass agent long-polls used to assemble the whole config
bundle from the database on every tick (every ``WAKE_TICK_SECONDS`` per parked
agent) and throw it away after an ETag comparison that said "unchanged". The
DNS long-poll no longer does: it compares the stored bundle's ETag (#1741).

This module is the change-detection half, independent of assembly: one small
statement that fingerprints every table the bundle reads. The key decides
whether to *rebuild*; the sha256 ETag still decides whether to *ship*, so a key
that moves without the content moving costs one wasted rebuild. A key that
fails to move when the content moves would freeze an agent's config while
every surface reports converged, so everything here errs towards moving:

* a table is fingerprinted by ``count(*)`` plus ``sum(xmin)``. ``xmin`` is the
  transaction that wrote the row version, so ANY write moves it -- no
  ``modified_at`` has to be maintained, and a column added tomorrow is covered
  without anyone remembering to list it. A delete moves the count; a
  delete-and-reinsert moves the sum;
* a table that is also written by the agents' own reports (a server's
  heartbeat, a peer's session state) is fingerprinted by its row as JSON minus
  the named volatile columns instead, so a heartbeat does not defeat the skip.
  A column NOT named there counts as config;
* the time-based contributors (a MAC block that expires) are probed on their
  own predicate, since no row changes when the clock passes them;
* a cached etag is trusted for at most ``SAFETY_REBUILD_SECONDS``: whatever
  neither of the above can see (a process-local cache, a rotated secret key)
  is corrected within that bound.

``tests/test_agent_config_version.py`` holds the guards: every table a bundle
reads is in the probe list, and a write to each moves the key.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.http_etag import etag_matches

#: An etag the key vouches for is trusted for at most this long. Idle agents
#: therefore still cost one rebuild per interval -- the backstop for anything
#: the key cannot see, not the primary mechanism.
SAFETY_REBUILD_SECONDS = 300.0

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_MAX_ENTRIES = 8192


@dataclass(frozen=True)
class Probe:
    """One scalar subquery of the version statement."""

    name: str
    sql: str  # a SELECT yielding one value; may use the shared bind params


def xmin_probe(table: str, where: str | None = None) -> Probe:
    """Fingerprint ``table`` (optionally filtered) by row count + sum of ``xmin``."""
    assert _IDENT.match(table), table
    clause = f" WHERE {where}" if where else ""
    return Probe(
        table,
        f"SELECT count(*)::text || ':' || coalesce(sum(xmin::text::bigint), 0)::text "
        f"FROM {table}{clause}",
    )


def row_probe(
    table: str, *, exclude: tuple[str, ...], where: str | None = None, order_by: str = "id"
) -> Probe:
    """Fingerprint ``table`` by its rows as JSON, minus the ``exclude`` columns."""
    assert _IDENT.match(table), table
    assert all(_IDENT.match(c) for c in exclude), exclude
    drop = "".join(f" - '{c}'" for c in exclude)
    clause = f" WHERE {where}" if where else ""
    return Probe(
        table,
        f"SELECT coalesce(md5(string_agg((to_jsonb(t){drop})::text, ',' "
        f"ORDER BY t.{order_by})), '') FROM {table} t{clause}",
    )


def raw_probe(name: str, sql: str) -> Probe:
    return Probe(name, sql)


async def config_version(db: AsyncSession, probes: list[Probe], **params: Any) -> str:
    """The version key: one round trip, no hydration, a pure function of the rows.

    Read it BEFORE building the bundle, never after: a change that commits in
    between then leaves the key behind the bundle, which costs one extra
    rebuild on the next tick, where the other order would pin a stale bundle
    to a newer key.
    """
    sql = "SELECT " + ", ".join(f"({p.sql}) AS p{i}" for i, p in enumerate(probes))
    row = (await db.execute(text(sql), params)).one()
    blob = "|".join(f"{p.name}={v}" for p, v in zip(probes, row, strict=True))
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class _Entry:
    key: str
    etag: str
    at: float
    meta: Any = None


@dataclass
class VersionCache:
    """Process-local ``server id -> (key, etag)``, valid for ``max_age`` seconds.

    Process-local on purpose: the key is a function of the database, so a
    replica that never saw the rebuild just misses once. It is shared across
    requests so a steady-state agent, whose poll reconnects every 30 s, costs
    nothing between safety rebuilds.
    """

    max_age: float = SAFETY_REBUILD_SECONDS
    _entries: dict[str, _Entry] = field(default_factory=dict)

    def hit(self, owner: str, key: str, if_none_match: str | None) -> _Entry | None:
        """The entry when ``key`` is what the cached etag was built at and the
        caller already holds that etag; otherwise None (rebuild)."""
        e = self._entries.get(owner)
        if e is None or e.key != key or time.monotonic() - e.at >= self.max_age:
            return None
        return e if etag_matches(if_none_match, e.etag) else None

    def store(self, owner: str, key: str, etag: str, meta: Any = None) -> None:
        if len(self._entries) >= _MAX_ENTRIES and owner not in self._entries:
            self._entries.clear()
        self._entries[owner] = _Entry(key, etag, time.monotonic(), meta)

    def forget(self, owner: str) -> None:
        self._entries.pop(owner, None)

    def clear(self) -> None:
        self._entries.clear()
