"""Logs API — Windows Event Log reads over WinRM.

Two read endpoints + a source-discovery endpoint. No writes, no
retention (events live on the Windows side). This is the first slice
of a broader logging surface: future additions include agent logs,
audit-log streaming, and the SpatiumDDI service logs themselves.

Endpoints:
  ``GET  /logs/sources`` — lists every server that supports log pulls
  (Windows DNS + DHCP with WinRM credentials set) along with each
  driver's ``available_log_names`` for the source picker.

  ``POST /logs/query`` — runs ``Get-WinEvent -FilterHashtable`` on
  the named server and returns a neutral list of event rows.

Authorisation:
  ``read`` on ``server`` — aligns with the permission required to
  view DNS / DHCP server details. Superadmin bypass applies per the
  standard RBAC path.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import DB, CurrentUser
from app.api.token_binding import honours_token_binding
from app.core.permissions import require_permission, require_permission_or_scoped
from app.drivers.dhcp import AGENTLESS_DRIVERS as DHCP_AGENTLESS
from app.drivers.dhcp import get_driver as get_dhcp_driver
from app.drivers.dns import AGENTLESS_DRIVERS as DNS_AGENTLESS
from app.drivers.dns import get_driver as get_dns_driver
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer
from app.services.api_token_scopes import read_only_post
from app.services.feature_modules import get_enabled_modules, require_module
from app.services.logs.agent_logs import (
    InvalidLogFilter,
    LogScopeError,
    dns_query_analytics,
    resolve_dhcp_log_servers,
    resolve_dns_log_servers,
    search_dhcp_activity,
    search_dns_queries,
)

logger = structlog.get_logger(__name__)

# No router-level gate: the WinRM routes take ``read`` on ``server``
# unscoped, while the agent-log routes below also admit a scoped grant and
# narrow their own rows (#2120). Each route declares its own.
router = APIRouter()
_WINRM_READ = Depends(require_permission("read", "server"))


# ── Schemas ──────────────────────────────────────────────────────────────────


class LogNameOption(BaseModel):
    """One available event log on a given server."""

    name: str
    display: str


class LogSource(BaseModel):
    """A server that supports log pulls + its available log names."""

    server_id: uuid.UUID
    server_name: str
    server_kind: Literal["dns", "dhcp"]
    driver: str
    host: str
    logs: list[LogNameOption]


class LogEventRow(BaseModel):
    """One event row returned by ``Get-WinEvent``."""

    time: str
    id: int
    level: str
    provider: str
    machine: str
    message: str


class LogQueryRequest(BaseModel):
    """POST body for ``/logs/query``."""

    server_id: uuid.UUID
    server_kind: Literal["dns", "dhcp"]
    log_name: str
    max_events: int = Field(default=100, ge=1, le=500)
    level: int | None = Field(default=None, ge=1, le=5)
    since: datetime | None = None
    event_id: int | None = None


class LogQueryResponse(BaseModel):
    server_id: uuid.UUID
    server_kind: Literal["dns", "dhcp"]
    log_name: str
    events: list[LogEventRow]
    truncated: bool  # True when result count == max_events (more may exist)


# ── DHCP audit log ───────────────────────────────────────────────────────────


class DhcpAuditRow(BaseModel):
    """One row from a Windows DHCP server's ``DhcpSrvLog-<Day>.log``.

    Different schema from ``LogEventRow`` because the audit log is
    per-lease — so it's richer (IP / MAC / hostname are first-class
    columns, not buried in a Message blob).
    """

    time: str
    event_code: int
    event_label: str
    description: str
    ip_address: str
    hostname: str
    mac_address: str
    user_name: str
    transaction_id: str
    q_result: str


_WEEKDAYS: tuple[str, ...] = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")


class DhcpAuditRequest(BaseModel):
    server_id: uuid.UUID
    day: str | None = Field(
        default=None,
        description=(
            "Three-letter weekday (Mon / Tue / Wed / Thu / Fri / Sat / Sun). " "Null = today."
        ),
    )
    max_events: int = Field(default=500, ge=1, le=2000)


class DhcpAuditResponse(BaseModel):
    server_id: uuid.UUID
    day: str  # the day actually queried
    events: list[DhcpAuditRow]
    truncated: bool


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/sources", response_model=list[LogSource], dependencies=[_WINRM_READ])
async def list_sources(db: DB) -> list[LogSource]:
    """List every server we can pull logs from.

    Today that's any Windows DNS / DHCP server with WinRM credentials
    configured. Callers render this as a "pick a server" dropdown in
    the Logs UI. When new log sources land (agents, control-plane),
    they get a ``server_kind`` of their own.
    """
    out: list[LogSource] = []
    kinds = await _enabled_kinds(db)

    # DNS — iterate all servers using an agentless driver with creds.
    dns_rows = (
        (
            await db.execute(
                DNSServer.__table__.select().where(DNSServer.credentials_encrypted.is_not(None))
            )
        ).all()
        if "dns" in kinds
        else []
    )
    for row in dns_rows:
        s = row._mapping
        if s["driver"] not in DNS_AGENTLESS:
            continue
        try:
            driver = get_dns_driver(s["driver"])
        except ValueError:
            continue
        log_fn = getattr(driver, "available_log_names", None)
        if not callable(log_fn):
            continue
        logs = [LogNameOption(name=n, display=d) for n, d in log_fn()]
        out.append(
            LogSource(
                server_id=s["id"],
                server_name=s["name"],
                server_kind="dns",
                driver=s["driver"],
                host=s["host"],
                logs=logs,
            )
        )

    # DHCP — same pattern.
    dhcp_rows = (
        (
            await db.execute(
                DHCPServer.__table__.select().where(DHCPServer.credentials_encrypted.is_not(None))
            )
        ).all()
        if "dhcp" in kinds
        else []
    )
    for row in dhcp_rows:
        s = row._mapping
        if s["driver"] not in DHCP_AGENTLESS:
            continue
        try:
            driver = get_dhcp_driver(s["driver"])
        except ValueError:
            continue
        log_fn = getattr(driver, "available_log_names", None)
        if not callable(log_fn):
            continue
        logs = [LogNameOption(name=n, display=d) for n, d in log_fn()]
        out.append(
            LogSource(
                server_id=s["id"],
                server_name=s["name"],
                server_kind="dhcp",
                driver=s["driver"],
                host=s["host"],
                logs=logs,
            )
        )

    out.sort(key=lambda s: (s.server_kind, s.server_name.lower()))
    return out


_KIND_MODULE = {"dns": "core.dns", "dhcp": "core.dhcp"}


async def _enabled_kinds(db: DB) -> set[str]:
    """Server kinds whose core module is on (#2136).

    The shared ``/logs/*`` routes serve both DNS and DHCP, so they cannot
    take a router-level ``require_module``; instead they drop the half
    whose module is off, so the Logs page is never offered a server that
    every DNS- or DHCP-specific route would then 404 on.
    """
    enabled = await get_enabled_modules(db)
    return {kind for kind, module_id in _KIND_MODULE.items() if module_id in enabled}


async def _resolve_server(db: DB, server_kind: str, server_id: uuid.UUID) -> tuple[Any, str]:
    """Load the right server row for the requested kind, or 404.

    Returns ``(server, driver_name)``. A kind whose core module is off
    answers 404, the same as the module's own routes (#2136).
    """
    if server_kind not in await _enabled_kinds(db):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature '{_KIND_MODULE[server_kind]}' is disabled.",
        )
    server: Any
    allowed: frozenset[str]
    if server_kind == "dns":
        server = await db.get(DNSServer, server_id)
        allowed = DNS_AGENTLESS
    else:  # dhcp
        server = await db.get(DHCPServer, server_id)
        allowed = DHCP_AGENTLESS
    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{server_kind.upper()} server not found",
        )
    if server.driver not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Driver {server.driver!r} doesn't support log pulls; only "
                f"agentless drivers ({', '.join(sorted(allowed))}) do."
            ),
        )
    if not getattr(server, "credentials_encrypted", None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Server has no WinRM credentials configured — can't pull logs "
                "without them. Add credentials on the server edit form first."
            ),
        )
    return server, server.driver


@router.post("/query", response_model=LogQueryResponse, dependencies=[_WINRM_READ])
@read_only_post
async def query_logs(body: LogQueryRequest, db: DB) -> LogQueryResponse:
    """Run a filtered ``Get-WinEvent`` against the named server and return
    matching rows.

    The driver validates that the requested log actually exists for
    that server; on Windows server variants that don't have a given
    log enabled, ``Get-WinEvent`` returns an empty list rather than
    raising — so the UI sees "no events" instead of a 500.
    """
    server, driver_name = await _resolve_server(db, body.server_kind, body.server_id)

    if body.server_kind == "dns":
        driver = get_dns_driver(driver_name)
    else:
        driver = get_dhcp_driver(driver_name)

    get_events_fn = getattr(driver, "get_events", None)
    if not callable(get_events_fn):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Driver {driver_name!r} does not support log pulls.",
        )

    try:
        raw_events = await get_events_fn(
            server,
            log_name=body.log_name,
            max_events=body.max_events,
            level=body.level,
            since=body.since,
            event_id=body.event_id,
        )
    except ValueError as exc:
        # Driver surfaces credential / config errors as ValueError.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        # WinRM transport / PowerShell errors. 502 — upstream failed, not us.
        logger.warning(
            "logs_query_upstream_failed",
            server_id=str(body.server_id),
            kind=body.server_kind,
            log_name=body.log_name,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Log query failed on {server.host}: {exc}",
        )

    events = [LogEventRow(**e) for e in raw_events]
    return LogQueryResponse(
        server_id=body.server_id,
        server_kind=body.server_kind,
        log_name=body.log_name,
        events=events,
        truncated=len(events) >= body.max_events,
    )


@router.post(
    "/dhcp-audit",
    response_model=DhcpAuditResponse,
    dependencies=[_WINRM_READ, Depends(require_module("core.dhcp"))],
)
@read_only_post
async def query_dhcp_audit(body: DhcpAuditRequest, db: DB) -> DhcpAuditResponse:
    """Read + parse a Windows DHCP server's audit log for the given day.

    The DHCP audit log (``DhcpSrvLog-<Day>.log``) is Windows' per-lease
    trail — grants, renewals, releases, conflict detections, DNS
    update outcomes. Separate endpoint from ``/query`` because the
    shape is different (IP / MAC / hostname are columns, not buried
    inside a Message blob).

    ``day`` is the three-letter weekday (``Mon`` / ``Tue`` / … /
    ``Sun``). Null = today's log (server-local time, resolved by the
    driver's PowerShell).
    """
    server, driver_name = await _resolve_server(db, "dhcp", body.server_id)

    if body.day is not None and body.day not in _WEEKDAYS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"day must be one of {list(_WEEKDAYS)} (or null for today), " f"got {body.day!r}"
            ),
        )

    driver = get_dhcp_driver(driver_name)
    get_audit_fn = getattr(driver, "get_dhcp_audit_events", None)
    if not callable(get_audit_fn):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Driver {driver_name!r} does not expose a DHCP audit log "
                "reader. Only agentless Windows DHCP supports this today."
            ),
        )

    try:
        raw_events, raw_truncated = await get_audit_fn(
            server,
            day=body.day,
            max_events=body.max_events,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "dhcp_audit_query_upstream_failed",
            server_id=str(body.server_id),
            day=body.day,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"DHCP audit log query failed on {server.host}: {exc}",
        )

    # The driver returns today's weekday when ``day`` was null — we
    # don't have it in scope here, so recompute from the response's
    # perspective: if body.day was set, echo it; otherwise best-effort
    # from local time (close enough for UI display; the server side
    # used its own local time which may differ by a timezone, but the
    # weekday is stable within ±6 hours of midnight).
    from datetime import date as _date  # noqa: PLC0415

    resolved_day = body.day or _WEEKDAYS[(_date.today().weekday() + 1) % 7]

    events = [DhcpAuditRow(**e) for e in raw_events]
    return DhcpAuditResponse(
        server_id=body.server_id,
        day=resolved_day,
        events=events,
        # #426: trust the reader's raw-row-count truncation signal, not the
        # post-parse len() (which under-reports when a line failed to parse).
        truncated=raw_truncated,
    )


# ── Agent-shipped query / activity logs (BIND9 + Kea) ────────────────
#
# These reads cover one server, one server group, or every server, and
# return only what the caller may read (#2120). The gate admits a ``read``
# grant on ``server`` scoped to particular servers or groups;
# ``app.services.logs.agent_logs`` resolves the selected set and intersects
# it with the caller's grants, so the request's filter is never trusted on
# its own.

_AGENT_READ = Depends(require_permission_or_scoped("read", "server"))


def _scope_http_error(exc: LogScopeError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


class AgentLogSource(BaseModel):
    """One server that ships logs via its in-container agent.

    Different shape from ``LogSource`` — there's no log-name picker
    (each agent ships one stream), and we don't pre-fetch driver
    capability lists since the parser is universal. ``group_id`` /
    ``group_name`` drive the grouped picker (#2120); a DHCP server with no
    group carries ``None`` for both.
    """

    server_id: uuid.UUID
    server_name: str
    server_kind: Literal["dns", "dhcp"]
    driver: str
    host: str
    group_id: uuid.UUID | None = None
    group_name: str | None = None


@router.get(
    "/agent-sources",
    response_model=list[AgentLogSource],
    dependencies=[_AGENT_READ],
)
async def list_agent_sources(db: DB, current_user: CurrentUser) -> list[AgentLogSource]:
    """List every DNS / DHCP server backed by an agent driver that the
    caller may read.

    Drives the server-picker on the "DNS Queries" / "DHCP Activity"
    tabs. Servers whose agent has never reported in still appear —
    the tab UI reports "no entries yet" rather than hiding them, so
    operators can tell the difference between "I haven't enabled
    query logging yet" and "the server doesn't exist".
    """
    out: list[AgentLogSource] = []
    kinds = await _enabled_kinds(db)
    if "dns" in kinds:
        for s in await resolve_dns_log_servers(db, current_user):
            out.append(
                AgentLogSource(
                    server_id=s.id,
                    server_name=s.name,
                    server_kind="dns",
                    driver=s.driver,
                    host=s.host,
                    group_id=s.group_id,
                    group_name=s.group_name,
                )
            )
    if "dhcp" in kinds:
        for s in await resolve_dhcp_log_servers(db, current_user):
            out.append(
                AgentLogSource(
                    server_id=s.id,
                    server_name=s.name,
                    server_kind="dhcp",
                    driver=s.driver,
                    host=s.host,
                    group_id=s.group_id,
                    group_name=s.group_name,
                )
            )

    out.sort(key=lambda s: (s.server_kind, s.server_name.lower()))
    return out


class DNSQueryLogRow(BaseModel):
    id: int
    ts: datetime
    # Which server logged it (#2120) — a group or "all" read merges several.
    server_id: uuid.UUID
    server_name: str
    client_ip: str | None
    client_port: int | None
    qname: str | None
    qclass: str | None
    qtype: str | None
    flags: str | None
    view: str | None
    # What the client was actually told (issue #914). NULL means the
    # outcome was never recorded — response logging is off, or the driver
    # has no equivalent — and NOT that the query succeeded. The UI must
    # render the two differently or an unrecorded query reads as healthy.
    rcode: str | None = None
    answer_count: int | None = None
    raw: str


class DNSQueryLogRequest(BaseModel):
    # Scope (#2120): ``server_id`` → that server; ``group_id`` → every
    # agent server in the group; neither → every agent server the caller
    # may read. Both set → the server, which must be in the group.
    server_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    since: datetime | None = None
    until: datetime | None = None
    q: str | None = None
    qtype: str | None = None
    client_ip: str | None = None
    # Exact-match view filter (#371) — seeded by clicking a per-view
    # analytics card so split-horizon operators can drill into one view.
    view: str | None = None
    # Exact-match RCODE (#914), case-insensitive: "NXDOMAIN", "REFUSED",
    # "SERVFAIL". The literal ``UNKNOWN`` selects rows whose outcome was
    # never recorded, which is a question an operator genuinely asks
    # ("is response logging actually on?") and cannot express otherwise.
    rcode: str | None = None
    max_events: int = Field(default=200, ge=1, le=1000)


class DNSQueryLogResponse(BaseModel):
    # The requested server, when one was; ``None`` for a group / all read.
    server_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    # Every server the read covered — after the caller's grants narrowed it.
    server_ids: list[uuid.UUID]
    events: list[DNSQueryLogRow]
    truncated: bool


@router.post(
    "/dns-queries",
    response_model=DNSQueryLogResponse,
    dependencies=[_AGENT_READ, Depends(require_module("core.dns"))],
)
@honours_token_binding
@read_only_post
async def query_dns_queries(
    body: DNSQueryLogRequest, db: DB, current_user: CurrentUser
) -> DNSQueryLogResponse:
    """Read parsed BIND9 / PowerDNS query log entries for one server, one
    server group, or every server the caller may read.

    All filters are server-side so the firehose stays manageable —
    the typical caller asks for the most recent 200 entries with an
    optional substring on ``qname`` (e.g. operator typed "github.com"
    to debug a resolution problem). Newest first, merged across servers.
    """
    try:
        servers = await resolve_dns_log_servers(
            db, current_user, server_id=body.server_id, group_id=body.group_id
        )
    except LogScopeError as exc:
        raise _scope_http_error(exc) from exc
    names = {s.id: s.name for s in servers}
    try:
        rows = await search_dns_queries(
            db,
            list(names),
            since=body.since,
            until=body.until,
            q=body.q,
            qtype=body.qtype,
            client_ip=body.client_ip,
            view=body.view,
            rcode=body.rcode,
            limit=body.max_events,
        )
    except InvalidLogFilter as exc:
        raise HTTPException(status_code=422, detail=exc.detail) from exc
    events = [
        DNSQueryLogRow(
            id=r.id,
            ts=r.ts,
            server_id=r.server_id,
            server_name=names.get(r.server_id, str(r.server_id)),
            client_ip=str(r.client_ip) if r.client_ip is not None else None,
            client_port=r.client_port,
            qname=r.qname,
            qclass=r.qclass,
            qtype=r.qtype,
            flags=r.flags,
            view=r.view,
            rcode=r.rcode,
            answer_count=r.answer_count,
            raw=r.raw,
        )
        for r in rows
    ]
    return DNSQueryLogResponse(
        server_id=body.server_id,
        group_id=body.group_id,
        server_ids=list(names),
        events=events,
        truncated=len(events) >= body.max_events,
    )


# ── DNS query analytics ─────────────────────────────────────────────────────


class DNSQueryAnalyticsRow(BaseModel):
    key: str
    count: int


class DNSQueryAnalyticsRequest(BaseModel):
    # Same scope rules as ``DNSQueryLogRequest`` (#2120).
    server_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    # Defaults to "last hour" — the query log table is pruned at 24h, so
    # asking past that returns nothing useful anyway.
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=10, ge=1, le=100)


class DNSQueryAnalyticsResponse(BaseModel):
    server_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    server_ids: list[uuid.UUID]
    since: datetime | None
    until: datetime | None
    total_queries: int
    top_qnames: list[DNSQueryAnalyticsRow]
    top_clients: list[DNSQueryAnalyticsRow]
    qtype_distribution: list[DNSQueryAnalyticsRow]
    # Per-view query split (issue #371) — empty for single-view servers; useful
    # for split-horizon operators to see "which view is taking the load".
    top_views: list[DNSQueryAnalyticsRow]
    # Outcome split (issue #914). Rows with no recorded outcome are
    # reported under the ``UNKNOWN`` key rather than omitted, so a server
    # with response logging off shows one honest bar instead of an empty
    # panel that reads as "no failures".
    rcode_distribution: list[DNSQueryAnalyticsRow]


def _rows(pairs: list[tuple[str, int]]) -> list[DNSQueryAnalyticsRow]:
    return [DNSQueryAnalyticsRow(key=k, count=n) for k, n in pairs]


@router.post(
    "/dns-queries/analytics",
    response_model=DNSQueryAnalyticsResponse,
    dependencies=[_AGENT_READ, Depends(require_module("core.dns"))],
)
@read_only_post
async def query_dns_analytics(
    body: DNSQueryAnalyticsRequest, db: DB, current_user: CurrentUser
) -> DNSQueryAnalyticsResponse:
    """Top-N rollups over the parsed query log, across every server the
    scope selects.

    Computed on-demand against ``dns_query_log_entry`` (24 h retention).
    Every dimension in one round trip — operators land on the analytics
    panel and see all of them at once. Longer history belongs in Loki;
    this endpoint deliberately mirrors the query log's retention window.
    """
    try:
        servers = await resolve_dns_log_servers(
            db, current_user, server_id=body.server_id, group_id=body.group_id
        )
    except LogScopeError as exc:
        raise _scope_http_error(exc) from exc
    server_ids = [s.id for s in servers]
    a = await dns_query_analytics(
        db, server_ids, since=body.since, until=body.until, limit=body.limit
    )
    return DNSQueryAnalyticsResponse(
        server_id=body.server_id,
        group_id=body.group_id,
        server_ids=server_ids,
        since=body.since,
        until=body.until,
        total_queries=a.total_queries,
        top_qnames=_rows(a.top_qnames),
        top_clients=_rows(a.top_clients),
        qtype_distribution=_rows(a.qtype_distribution),
        top_views=_rows(a.top_views),
        rcode_distribution=_rows(a.rcode_distribution),
    )


class DHCPActivityLogRow(BaseModel):
    id: int
    ts: datetime
    # Which server logged it (#2120).
    server_id: uuid.UUID
    server_name: str
    severity: str | None
    code: str | None
    mac_address: str | None
    ip_address: str | None
    transaction_id: str | None
    raw: str


class DHCPActivityLogRequest(BaseModel):
    # Scope (#2120): ``server_id`` → that server; ``group_id`` → every Kea
    # server in that DHCP server group; neither → every Kea server the
    # caller may read.
    server_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    since: datetime | None = None
    until: datetime | None = None
    q: str | None = None
    severity: str | None = None
    code: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    max_events: int = Field(default=200, ge=1, le=1000)


class DHCPActivityLogResponse(BaseModel):
    server_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    server_ids: list[uuid.UUID]
    events: list[DHCPActivityLogRow]
    truncated: bool


@router.post(
    "/dhcp-activity",
    response_model=DHCPActivityLogResponse,
    dependencies=[_AGENT_READ, Depends(require_module("core.dhcp"))],
)
@honours_token_binding
@read_only_post
async def query_dhcp_activity(
    body: DHCPActivityLogRequest, db: DB, current_user: CurrentUser
) -> DHCPActivityLogResponse:
    """Read parsed Kea log entries for one server, one DHCP server group,
    or every server the caller may read. Newest first, merged."""
    try:
        servers = await resolve_dhcp_log_servers(
            db, current_user, server_id=body.server_id, group_id=body.group_id
        )
    except LogScopeError as exc:
        raise _scope_http_error(exc) from exc
    names = {s.id: s.name for s in servers}
    try:
        rows = await search_dhcp_activity(
            db,
            list(names),
            since=body.since,
            until=body.until,
            q=body.q,
            severity=body.severity,
            code=body.code,
            mac_address=body.mac_address,
            ip_address=body.ip_address,
            limit=body.max_events,
        )
    except InvalidLogFilter as exc:
        raise HTTPException(status_code=422, detail=exc.detail) from exc
    events = [
        DHCPActivityLogRow(
            id=r.id,
            ts=r.ts,
            server_id=r.server_id,
            server_name=names.get(r.server_id, str(r.server_id)),
            severity=r.severity,
            code=r.code,
            mac_address=str(r.mac_address) if r.mac_address is not None else None,
            ip_address=str(r.ip_address) if r.ip_address is not None else None,
            transaction_id=r.transaction_id,
            raw=r.raw,
        )
        for r in rows
    ]
    return DHCPActivityLogResponse(
        server_id=body.server_id,
        group_id=body.group_id,
        server_ids=list(names),
        events=events,
        truncated=len(events) >= body.max_events,
    )
