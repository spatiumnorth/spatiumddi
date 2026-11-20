"""Reads over the agent-shipped DNS query log and DHCP activity log (#2120).

One home for the three questions every reader of these two tables asks, so
the REST routes under ``/logs`` and the copilot tools answer them the same
way:

* **Which servers?** :func:`resolve_dns_log_servers` /
  :func:`resolve_dhcp_log_servers` turn a ``server_id`` / ``group_id`` /
  neither filter into the set of servers to read. The filter is never
  trusted on its own: the result is always intersected with the servers the
  caller may read (:func:`can_read_log_server`), so a group or "all" query
  cannot return a server the caller has no grant on.
* **Which rows?** :func:`search_dns_queries` / :func:`search_dhcp_activity`
  apply the row filters over ``server_id IN (...)``, newest first, capped.
  Both tables carry ``(server_id, ts)`` and ``(ts)`` indexes; with a LIMIT
  the planner walks ``ix_*_ts`` backwards and stops at the cap, which is the
  right plan whether the set is one server or every server.
* **What did they look like?** :func:`dns_query_analytics` rolls the same
  set up into the top-N panels.

Permission model. The logs surface has always been gated on ``read`` on
``server``. A grant with no ``resource_id`` reads every server, as before.
A grant scoped to a ``resource_id`` reads either that one server (a server
id) or every server in that group (a DNS or DHCP server-group id). Server
and group ids are distinct UUIDs, so the two readings never collide.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.services.logs.ip_filter import InvalidLogFilter, ip_filter_clause, mac_filter_clause
from app.services.search.ranking import like_pattern

# Drivers backed by an in-container agent that ships its daemon's log lines
# to the control plane. Distinct from the agentless drivers (Windows over
# WinRM), whose logs are pulled on demand instead.
DNS_AGENT_DRIVERS: frozenset[str] = frozenset({"bind9", "powerdns"})
DHCP_AGENT_DRIVERS: frozenset[str] = frozenset({"kea"})

#: Sentinel for "the outcome was never recorded" (#914). Not a real RCODE,
#: and deliberately not spelled like one.
RCODE_UNKNOWN = "UNKNOWN"

#: Shown for a log row whose server was deleted before rows carried its name.
DELETED_SERVER_NAME = "deleted server"


class LogScopeError(Exception):
    """A filter that names something the caller cannot read, or that does
    not exist. Carries the HTTP status the REST layer answers with."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class LogServer:
    """One server a log read covers, with what a merged view shows for it."""

    id: uuid.UUID
    name: str
    host: str
    driver: str
    group_id: uuid.UUID | None
    group_name: str | None


def can_read_log_server(user: User, server_id: uuid.UUID, group_id: uuid.UUID | None) -> bool:
    """Whether ``user`` may read this server's agent-shipped logs.

    ``read`` on ``server`` either unscoped, scoped to this server's id, or
    scoped to its group's id. ``user_has_permission`` also applies any API
    token narrowing (#374), so a token bound to one server or group is held
    to it here.
    """
    from app.core.permissions import user_has_permission  # noqa: PLC0415

    if user_has_permission(user, "read", "server", server_id):
        return True
    return group_id is not None and user_has_permission(user, "read", "server", group_id)


async def _resolve(
    db: AsyncSession,
    user: User,
    *,
    server_model: Any,
    group_model: Any,
    group_column: Any,
    drivers: frozenset[str],
    kind: str,
    server_id: uuid.UUID | None,
    group_id: uuid.UUID | None,
) -> list[LogServer]:
    stmt = (
        select(server_model, group_model.name)
        .outerjoin(group_model, group_model.id == group_column)
        .order_by(func.lower(server_model.name))
    )
    if server_id is not None:
        row = (await db.execute(stmt.where(server_model.id == server_id))).first()
        if row is None:
            raise LogScopeError(404, f"{kind} server not found")
        server, group_name = row
        gid = getattr(server, group_column.key)
        if not can_read_log_server(user, server.id, gid):
            raise LogScopeError(403, f"Permission denied: cannot read this {kind} server's logs")
        if server.driver not in drivers:
            raise LogScopeError(
                400,
                f"Driver {server.driver!r} doesn't ship logs from an agent. "
                f"Use the Windows event log / audit log tabs for that server.",
            )
        if group_id is not None and gid != group_id:
            raise LogScopeError(422, f"That {kind} server is not in the requested group")
        return [LogServer(server.id, server.name, server.host, server.driver, gid, group_name)]

    stmt = stmt.where(server_model.driver.in_(drivers))
    if group_id is not None:
        if await db.get(group_model, group_id) is None:
            raise LogScopeError(404, f"{kind} server group not found")
        stmt = stmt.where(group_column == group_id)

    out: list[LogServer] = []
    denied = 0
    for server, group_name in (await db.execute(stmt)).all():
        gid = getattr(server, group_column.key)
        if not can_read_log_server(user, server.id, gid):
            denied += 1
            continue
        out.append(LogServer(server.id, server.name, server.host, server.driver, gid, group_name))
    # A named group the caller can read none of is a refusal, not an empty
    # answer — "no rows" would read as "nothing was logged". "All servers"
    # with nothing readable is simply empty.
    if group_id is not None and not out and denied:
        raise LogScopeError(403, f"Permission denied: cannot read this {kind} server group's logs")
    return out


async def resolve_dns_log_servers(
    db: AsyncSession,
    user: User,
    *,
    server_id: uuid.UUID | None = None,
    group_id: uuid.UUID | None = None,
) -> list[LogServer]:
    """Agent-backed DNS servers the filter selects AND the caller may read.

    ``server_id`` → that server; ``group_id`` → every agent server in that
    group; neither → every agent server. Raises :class:`LogScopeError`.
    """
    return await _resolve(
        db,
        user,
        server_model=DNSServer,
        group_model=DNSServerGroup,
        group_column=DNSServer.group_id,
        drivers=DNS_AGENT_DRIVERS,
        kind="DNS",
        server_id=server_id,
        group_id=group_id,
    )


async def resolve_dhcp_log_servers(
    db: AsyncSession,
    user: User,
    *,
    server_id: uuid.UUID | None = None,
    group_id: uuid.UUID | None = None,
) -> list[LogServer]:
    """DHCP twin of :func:`resolve_dns_log_servers`. A DHCP server may have
    no group; such a server is reachable by its id or through "all"."""
    return await _resolve(
        db,
        user,
        server_model=DHCPServer,
        group_model=DHCPServerGroup,
        group_column=DHCPServer.server_group_id,
        drivers=DHCP_AGENT_DRIVERS,
        kind="DHCP",
        server_id=server_id,
        group_id=group_id,
    )


def include_orphaned_logs(
    user: User, *, server_id: uuid.UUID | None, group_id: uuid.UUID | None
) -> bool:
    """Whether a read also covers rows whose server was deleted (#4173).

    Those rows have ``server_id`` NULL, so no server grant can name them.
    They are what the "all servers" read returns to a caller who holds an
    UNSCOPED ``read`` on ``server`` (the same caller who could have read them
    before the server went), never to a read narrowed to one server or group
    and never to a caller whose grants are scoped.
    """
    from app.core.permissions import user_has_permission  # noqa: PLC0415

    if server_id is not None or group_id is not None:
        return False
    return user_has_permission(user, "read", "server")


def _server_scope(column: Any, server_ids: Sequence[uuid.UUID], include_orphans: bool) -> Any:
    if include_orphans:
        return or_(column.in_(list(server_ids)), column.is_(None))
    return column.in_(list(server_ids))


def log_row_server_name(
    row_server_id: uuid.UUID | None, stored_name: str | None, names: dict[uuid.UUID, str]
) -> str:
    """The server name a merged log read shows for one row.

    The live name while the server exists, else the name stored at ingest,
    else a plain ``deleted server`` (rows older than the column).
    """
    if row_server_id is not None and row_server_id in names:
        return names[row_server_id]
    return stored_name or DELETED_SERVER_NAME


def _rcode_clause(rcode: str) -> Any:
    wanted = rcode.strip().upper()
    if wanted == RCODE_UNKNOWN:
        return DNSQueryLogEntry.rcode.is_(None)
    return DNSQueryLogEntry.rcode == wanted


def _dns_query_filters(
    *,
    since: datetime | None,
    until: datetime | None,
    q: str | None = None,
    qname_contains: str | None = None,
    qtype: str | None = None,
    client_ip: str | None = None,
    view: str | None = None,
    rcode: str | None = None,
) -> list[Any]:
    """WHERE clauses shared by the grid and the analytics rollups (#4072), so
    "analytics follow filters" can never disagree with the rows it summarises.

    ``q`` matches the qname or the raw line (the UI search box);
    ``qname_contains`` matches the qname only (the copilot's argument).
    Both are substring matches with LIKE metacharacters neutralised.
    """
    out: list[Any] = []
    if since is not None:
        out.append(DNSQueryLogEntry.ts >= since)
    if until is not None:
        out.append(DNSQueryLogEntry.ts <= until)
    if qtype:
        out.append(DNSQueryLogEntry.qtype == qtype.strip().upper())
    if client_ip:
        out.append(ip_filter_clause(DNSQueryLogEntry.client_ip, client_ip, field="client_ip"))
    if view:
        out.append(DNSQueryLogEntry.view == view)
    if rcode:
        out.append(_rcode_clause(rcode))
    if qname_contains:
        out.append(DNSQueryLogEntry.qname.ilike(like_pattern(qname_contains.strip()), escape="\\"))
    if q:
        like = like_pattern(q.strip())
        # qname is the common search; raw catches a fragment the operator
        # remembers from the daemon's own output that did not parse.
        out.append(
            DNSQueryLogEntry.qname.ilike(like, escape="\\")
            | DNSQueryLogEntry.raw.ilike(like, escape="\\")
        )
    return out


async def search_dns_queries(
    db: AsyncSession,
    server_ids: Sequence[uuid.UUID],
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = None,
    qname_contains: str | None = None,
    qtype: str | None = None,
    client_ip: str | None = None,
    view: str | None = None,
    rcode: str | None = None,
    limit: int = 200,
    include_orphans: bool = False,
) -> list[DNSQueryLogEntry]:
    """Query-log rows for ``server_ids``, newest first, at most ``limit``.

    Filters are those of :func:`_dns_query_filters`.
    """
    if not server_ids and not include_orphans:
        return []
    stmt = select(DNSQueryLogEntry).where(
        _server_scope(DNSQueryLogEntry.server_id, server_ids, include_orphans),
        *_dns_query_filters(
            since=since,
            until=until,
            q=q,
            qname_contains=qname_contains,
            qtype=qtype,
            client_ip=client_ip,
            view=view,
            rcode=rcode,
        ),
    )
    stmt = stmt.order_by(DNSQueryLogEntry.ts.desc(), DNSQueryLogEntry.id.desc()).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


@dataclass
class DNSQueryAnalytics:
    total_queries: int
    top_qnames: list[tuple[str, int]]
    top_clients: list[tuple[str, int]]
    qtype_distribution: list[tuple[str, int]]
    top_views: list[tuple[str, int]]
    rcode_distribution: list[tuple[str, int]]


async def dns_query_analytics(
    db: AsyncSession,
    server_ids: Sequence[uuid.UUID],
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = None,
    qtype: str | None = None,
    client_ip: str | None = None,
    view: str | None = None,
    rcode: str | None = None,
    limit: int = 10,
    include_orphans: bool = False,
) -> DNSQueryAnalytics:
    """Top-N rollups over every row the selected servers logged that also
    match the optional filters (#4072; none given = the whole window)."""
    if not server_ids and not include_orphans:
        return DNSQueryAnalytics(0, [], [], [], [], [])
    base_filter: list[Any] = [
        _server_scope(DNSQueryLogEntry.server_id, server_ids, include_orphans),
        *_dns_query_filters(
            since=since,
            until=until,
            q=q,
            qtype=qtype,
            client_ip=client_ip,
            view=view,
            rcode=rcode,
        ),
    ]

    total = (
        await db.execute(select(func.count()).select_from(DNSQueryLogEntry).where(*base_filter))
    ).scalar_one() or 0

    async def _topn(column: Any, n: int) -> list[tuple[str, int]]:
        # Aliased to ``n`` (not ``count``): ``Row.count`` is a method.
        stmt = (
            select(column.label("key"), func.count().label("n"))
            .where(*base_filter, column.is_not(None))
            .group_by(column)
            .order_by(func.count().desc())
            .limit(n)
        )
        return [(str(r.key), int(r.n)) for r in (await db.execute(stmt)).all()]

    rcode_distribution = await _topn(DNSQueryLogEntry.rcode, 25)
    # ``_topn`` skips NULLs, which is right for top talkers and wrong here:
    # the NULLs answer "is response logging on at all" (#914).
    unknown = (
        await db.execute(
            select(func.count())
            .select_from(DNSQueryLogEntry)
            .where(*base_filter, DNSQueryLogEntry.rcode.is_(None))
        )
    ).scalar_one() or 0
    if unknown:
        rcode_distribution.append((RCODE_UNKNOWN, int(unknown)))
        rcode_distribution.sort(key=lambda r: r[1], reverse=True)

    return DNSQueryAnalytics(
        total_queries=int(total),
        top_qnames=await _topn(DNSQueryLogEntry.qname, limit),
        top_clients=await _topn(DNSQueryLogEntry.client_ip, limit),
        # Every qtype / view seen, not just top-N: small cardinality, and
        # operators want the whole split.
        qtype_distribution=await _topn(DNSQueryLogEntry.qtype, 25),
        top_views=await _topn(DNSQueryLogEntry.view, 25),
        rcode_distribution=rcode_distribution,
    )


async def search_dhcp_activity(
    db: AsyncSession,
    server_ids: Sequence[uuid.UUID],
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = None,
    severity: str | None = None,
    code: str | None = None,
    mac_address: str | None = None,
    ip_address: str | None = None,
    limit: int = 200,
    include_orphans: bool = False,
) -> list[DHCPLogEntry]:
    """Kea activity rows for ``server_ids``, newest first, at most ``limit``."""
    if not server_ids and not include_orphans:
        return []
    stmt = select(DHCPLogEntry).where(
        _server_scope(DHCPLogEntry.server_id, server_ids, include_orphans)
    )
    if since is not None:
        stmt = stmt.where(DHCPLogEntry.ts >= since)
    if until is not None:
        stmt = stmt.where(DHCPLogEntry.ts <= until)
    if severity:
        stmt = stmt.where(DHCPLogEntry.severity == severity.strip().upper())
    if code:
        stmt = stmt.where(DHCPLogEntry.code == code.strip().upper())
    if mac_address:
        stmt = stmt.where(mac_filter_clause(DHCPLogEntry.mac_address, mac_address))
    if ip_address:
        stmt = stmt.where(ip_filter_clause(DHCPLogEntry.ip_address, ip_address, field="ip_address"))
    if q:
        stmt = stmt.where(DHCPLogEntry.raw.ilike(like_pattern(q.strip()), escape="\\"))
    stmt = stmt.order_by(DHCPLogEntry.ts.desc(), DHCPLogEntry.id.desc()).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


__all__ = [
    "DHCP_AGENT_DRIVERS",
    "DNS_AGENT_DRIVERS",
    "RCODE_UNKNOWN",
    "DNSQueryAnalytics",
    "InvalidLogFilter",
    "LogScopeError",
    "LogServer",
    "DELETED_SERVER_NAME",
    "can_read_log_server",
    "include_orphaned_logs",
    "log_row_server_name",
    "dns_query_analytics",
    "resolve_dhcp_log_servers",
    "resolve_dns_log_servers",
    "search_dhcp_activity",
    "search_dns_queries",
]
