"""RPZ hit attribution — which clients keep reaching for blocked names (#699).

We serve curated blocklists as RPZ zones and, before this, discarded
every hit. That left the most operationally useful thing the blocklists
can tell you unanswerable: a blocked lookup is not a problem, but a
host generating thousands of them is an infected machine announcing
itself, and we were throwing that away.

Pure reporting — unlike the other three detections there is no scoring
here, because there is nothing to infer. A hit is ground truth: named
matched a policy and said so. The job is only to attribute hits to
clients and feeds and rank them.

**PASSTHRU is not a block.** It is an explicit allow — an exception
entry that let a name through *past* a blocklist. Counting it as a
block would inflate every client's number and, worse, would make a
correctly-configured allowlist look like an infection. Every function
here separates the two.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns_rpz_hit import DNSRPZHit
from app.services.logs.ip_filter import ip_filter_clause
from app.services.search.ranking import like_pattern

# An explicit allow, not a block. See the module docstring.
PASSTHRU = "PASSTHRU"

# A client has to be reaching for blocked names with some persistence
# before it is worth an operator's attention. One hit is an ad on a web
# page; hundreds in a day is a host with something running on it.
NOISY_CLIENT_HITS = 50


def _blocked(since: datetime) -> tuple[Any, ...]:
    """The predicate every "what was blocked" query shares.

    Defined once because it was restated six times across this module
    and a single missed ``policy != PASSTHRU`` silently turns an
    explicit ALLOW into a reported block.
    """
    return (DNSRPZHit.ts >= since, DNSRPZHit.policy != PASSTHRU)


async def top_offending_clients(
    db: AsyncSession,
    *,
    hours: int = 24,
    limit: int = 20,
    min_hits: int = 1,
) -> list[dict[str, Any]]:
    """Clients ranked by blocked-lookup count over the trailing window.

    Rows with no ``client_ip`` are excluded: a hit we could not attribute
    still counts toward the totals (it proves the blocklist fired) but
    cannot be pinned to a host, and listing it as an anonymous offender
    would be noise. :func:`summary` keeps it.
    """
    since = datetime.now(UTC) - timedelta(hours=hours)
    base = _blocked(since)

    # Per-client totals.
    totals = (
        select(
            DNSRPZHit.client_ip.label("client_ip"),
            func.count().label("hits"),
            func.count(func.distinct(DNSRPZHit.qname)).label("distinct_names"),
            func.count(func.distinct(DNSRPZHit.rpz_zone)).label("distinct_feeds"),
            func.max(DNSRPZHit.ts).label("last_seen"),
        )
        .where(*base, DNSRPZHit.client_ip.is_not(None))
        .group_by(DNSRPZHit.client_ip)
        .having(func.count() >= min_hits)
        .order_by(func.count().desc())
        .limit(limit)
        .subquery()
    )

    # Worst name per client, ranked in ONE pass. This was a per-client
    # SELECT inside the result loop — 1+N, so 201 serialised round trips
    # at the endpoint's limit=200 ceiling, on a 30-day-retention table,
    # and the cost scaled with how noisy the client was (i.e. worst for
    # exactly the host this feature exists to surface). Same
    # ``row_number() OVER (PARTITION BY ...)`` idiom the tunneling alert
    # matcher already uses for the same shape.
    per_name = (
        select(
            DNSRPZHit.client_ip.label("client_ip"),
            DNSRPZHit.qname.label("qname"),
            func.count().label("n"),
        )
        .where(*base, DNSRPZHit.client_ip.is_not(None), DNSRPZHit.qname.is_not(None))
        .group_by(DNSRPZHit.client_ip, DNSRPZHit.qname)
        .subquery()
    )
    ranked = select(
        per_name.c.client_ip,
        per_name.c.qname,
        per_name.c.n,
        func.row_number()
        .over(partition_by=per_name.c.client_ip, order_by=per_name.c.n.desc())
        .label("rn"),
    ).subquery()
    # Materialised ONCE — calling .subquery() per reference mints a
    # distinct alias each time, which Postgres rejects with "missing
    # FROM-clause entry".
    worst = (
        select(ranked.c.client_ip, ranked.c.qname, ranked.c.n).where(ranked.c.rn == 1).subquery()
    )

    stmt = select(
        totals.c.client_ip,
        totals.c.hits,
        totals.c.distinct_names,
        totals.c.distinct_feeds,
        totals.c.last_seen,
        worst.c.qname.label("top_qname"),
        worst.c.n.label("top_qname_hits"),
    ).select_from(totals.outerjoin(worst, totals.c.client_ip == worst.c.client_ip))
    rows = (await db.execute(stmt.order_by(totals.c.hits.desc()))).all()

    return [
        {
            "client_ip": str(r.client_ip),
            "hits": r.hits,
            "distinct_names": r.distinct_names,
            "distinct_feeds": r.distinct_feeds,
            "last_seen": r.last_seen,
            "top_qname": r.top_qname,
            "top_qname_hits": r.top_qname_hits or 0,
            "noisy": r.hits >= NOISY_CLIENT_HITS,
        }
        for r in rows
    ]


async def top_blocked_names(
    db: AsyncSession, *, hours: int = 24, limit: int = 20
) -> list[dict[str, Any]]:
    """The blocked names themselves, ranked by hit count."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = (
        await db.execute(
            select(
                DNSRPZHit.qname.label("qname"),
                func.count().label("hits"),
                func.count(func.distinct(DNSRPZHit.client_ip)).label("clients"),
                func.min(DNSRPZHit.rpz_zone).label("rpz_zone"),
            )
            .where(*_blocked(since), DNSRPZHit.qname.is_not(None))
            .group_by(DNSRPZHit.qname)
            .order_by(func.count().desc())
            .limit(limit)
        )
    ).all()
    return [
        {
            "qname": r.qname,
            "hits": r.hits,
            "clients": r.clients,
            "rpz_zone": r.rpz_zone,
        }
        for r in rows
    ]


async def feed_effectiveness(db: AsyncSession, *, hours: int = 24) -> list[dict[str, Any]]:
    """Hits per RPZ zone.

    **Resolution caveat.** ``dns/agent_config.py`` merges every enabled
    blocklist into ONE rendered RPZ zone per view
    (``spatium-blocklist[-<view>].rpz``), dropping the per-entry
    ``list_id``/``list_name`` that ``EffectiveEntry`` carries. So for
    SpatiumDDI-managed blocklists this returns one row per *view*, not
    one per subscribed feed — it cannot currently answer "which of my 14
    lists is firing". Splitting that apart needs either one rendered zone
    per list or a join from the blocked qname back to
    ``DNSBlockListEntry`` at report time; both are follow-up work,
    tracked on #699.

    It IS meaningful for operators running additional hand-rolled
    ``response-policy`` zones alongside ours, and for separating hits
    per view on a split-horizon install.
    """
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = (
        await db.execute(
            select(
                DNSRPZHit.rpz_zone.label("rpz_zone"),
                func.count().label("hits"),
                func.count(func.distinct(DNSRPZHit.client_ip)).label("clients"),
                func.count(func.distinct(DNSRPZHit.qname)).label("distinct_names"),
            )
            # ``rpz_zone IS NOT NULL`` keeps this consistent with
            # summary()'s ``count(distinct rpz_zone)``, which skips NULLs
            # by SQL semantics. Without it the card and the drilldown
            # disagreed on the feed count whenever a ``via`` clause
            # failed to parse.
            .where(*_blocked(since), DNSRPZHit.rpz_zone.is_not(None))
            .group_by(DNSRPZHit.rpz_zone)
            .order_by(func.count().desc())
            .limit(50)
        )
    ).all()
    return [
        {
            "rpz_zone": r.rpz_zone,
            "hits": r.hits,
            "clients": r.clients,
            "distinct_names": r.distinct_names,
        }
        for r in rows
    ]


async def summary(db: AsyncSession, *, hours: int = 24) -> dict[str, Any]:
    """Rollup for the dashboard card and the Operator Copilot.

    ``has_data`` distinguishes "nothing was blocked" from "this isn't
    running" — the same contract the threat summary carries, and for the
    same reason: an idle feature rendering as an all-clear is exactly
    the failure this whole area exists to avoid. Here it is sharper than
    usual, because zero hits is a *plausible* real answer on a quiet
    network, so the UI must not have to guess.
    """
    since = datetime.now(UTC) - timedelta(hours=hours)
    totals = (
        await db.execute(
            select(
                func.count().label("hits"),
                func.count(func.distinct(DNSRPZHit.client_ip)).label("clients"),
                func.count(func.distinct(DNSRPZHit.qname)).label("names"),
                func.count(func.distinct(DNSRPZHit.rpz_zone)).label("feeds"),
            ).where(*_blocked(since))
        )
    ).one()
    # Counted separately rather than filtered out entirely: an operator
    # tuning an allowlist wants to see it working.
    passthru = (
        await db.execute(
            select(func.count()).where(DNSRPZHit.ts >= since, DNSRPZHit.policy == PASSTHRU)
        )
    ).scalar_one()
    # Any hit at all — including PASSTHRU and unattributable rows — is
    # proof the pipeline is alive, which is what has_data must mean.
    any_row = (await db.execute(select(func.count()).where(DNSRPZHit.ts >= since))).scalar_one()
    top = await top_offending_clients(db, hours=hours, limit=1)
    return {
        "blocked_hits": totals.hits or 0,
        "clients_blocked": totals.clients or 0,
        "distinct_names": totals.names or 0,
        "feeds_firing": totals.feeds or 0,
        "passthru_hits": passthru or 0,
        "worst_client_ip": top[0]["client_ip"] if top else None,
        "worst_client_hits": top[0]["hits"] if top else None,
        "since": since,
        "has_data": (any_row or 0) > 0,
    }


async def recent_hits(
    db: AsyncSession,
    *,
    hours: int = 24,
    limit: int = 100,
    client_ip: str | None = None,
    qname_contains: str | None = None,
    include_passthru: bool = False,
) -> list[dict[str, Any]]:
    """The individual hits, newest first — not a rollup.

    Every other function here answers "how much"; this one answers "what,
    exactly". The rollups can say a client has 412 blocked lookups and a
    top name, which is enough to spot an infected host and not enough to
    close the other case out: a user reports a site is broken, and the
    operator needs the three lookups that machine made in the last ten
    minutes and what blocked them. That was unanswerable from the API
    even though the rows have been stored since #699 (issue #914).

    ``include_passthru`` is off by default for the reason the module
    docstring gives — a PASSTHRU is an explicit allow, and mixing it into
    a list captioned "blocked" misreads a working allowlist as an
    infection. It is available because "why did this name get through
    when the feed lists it?" is answered by exactly those rows.
    """
    since = datetime.now(UTC) - timedelta(hours=hours)
    stmt = select(DNSRPZHit).where(DNSRPZHit.ts >= since)
    if not include_passthru:
        stmt = stmt.where(DNSRPZHit.policy != PASSTHRU)
    if client_ip:
        stmt = stmt.where(ip_filter_clause(DNSRPZHit.client_ip, client_ip, field="client_ip"))
    if qname_contains:
        # Names are stored lower-cased and dot-stripped by the parser, so
        # the needle is normalised the same way rather than relying on
        # ILIKE to paper over a mismatch that would also defeat any index.
        needle = qname_contains.strip().rstrip(".").lower()
        # ``like_pattern`` neutralises LIKE metacharacters — searching for
        # ``50%`` must not match every row (the #879 finding).
        stmt = stmt.where(DNSRPZHit.qname.like(like_pattern(needle), escape="\\"))
    stmt = stmt.order_by(DNSRPZHit.ts.desc(), DNSRPZHit.id.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(h.id),
            "ts": h.ts,
            "server_id": str(h.server_id) if h.server_id else None,
            "client_ip": str(h.client_ip) if h.client_ip is not None else None,
            "qname": h.qname,
            "trigger": h.trigger,
            "policy": h.policy,
            "rpz_zone": h.rpz_zone,
            "raw": h.raw,
        }
        for h in rows
    ]
