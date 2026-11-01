"""DNS threat analytics read surface (issue #699).

Read-mostly: the detections write themselves via the rollup task. The
one mutation is the per-client mute (operator triage), which carries a
``write`` permission gate of its own because suppressing a critical
security finding must not be something a read-only account can do.
Gated behind the default-off
``security.dns_threat`` feature module at the router include, so the
whole prefix 404s on installs that haven't opted in.

Gated on ``read:server`` at the router, matching the Logs surface it
summarises — anyone trusted to read raw queries is trusted to read a
rollup of them.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, or_, select

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_permission
from app.models.audit import AuditLog
from app.models.dns_threat import DNSClientWindow
from app.models.dns_threat_mute import DNSThreatMute
from app.services.dns_threat import rpz as rpz_service
from app.services.dns_threat.aggregate import INTERESTING_SCORE, compute_threat_summary
from app.services.logs.ip_filter import InvalidLogFilter

# Same gate the Logs router uses: this is a rollup of the DNS query
# log, so whoever may read raw queries may read a summary of them.
router = APIRouter(dependencies=[Depends(require_permission("read", "server"))])


class ClientWindowRow(BaseModel):
    id: str
    client_ip: str
    window_start: datetime
    window_end: datetime
    query_count: int
    distinct_qnames: int
    distinct_parents: int
    top_parent: str | None
    top_parent_subdomains: int
    max_label_length: int
    mean_label_entropy: float
    payload_qtype_count: int
    tunnel_score: float
    tunnel_signals: list[dict[str, Any]]
    beacon_score: float
    beacon_candidates: list[dict[str, Any]]
    beacon_detail: str
    dga_score: float
    dga_candidates: list[dict[str, Any]]
    dga_signals: list[dict[str, Any]]
    dga_detail: str
    allowlisted: bool
    server_count: int
    # Populated per row so the tab can dim a muted client and show who
    # cleared it, without a second request.
    muted: bool = False
    mute_reason: str | None = None
    mute_until: datetime | None = None


class ThreatSummary(BaseModel):
    """Rollup for the Security dashboard card."""

    windows_scored: int
    clients_seen: int
    suspicious_clients: int
    peak_score: float
    worst_client_ip: str | None
    worst_client_score: float | None
    worst_client_parent: str | None
    since: datetime
    # False when the rollup has produced nothing at all, which is the
    # difference between "no threats" and "not actually running" — the
    # UI needs to say which, or an idle card reads as an all-clear.
    has_data: bool


def _validated_ip(value: str) -> str:
    """Reject anything that isn't a bare IP before it reaches an INET
    comparison."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"client_ip must be a single IP address, got {value!r}",
        ) from exc


def _score_column(detection: str) -> Any:
    """Map the ``detection`` query param to the column it ranks by.

    One lookup rather than a chain of ternaries at each use site: the
    ordering and the threshold filter must agree on which score they
    mean, and keeping them keyed off the same table is what guarantees
    it. The caller's ``pattern=`` constraint means an unknown value
    never reaches here, but the fallback is tunneling — the default —
    rather than a raise, so a future detection added to the pattern and
    forgotten here degrades to the old behaviour instead of 500ing.
    """
    return {
        "tunnel": DNSClientWindow.tunnel_score,
        "beacon": DNSClientWindow.beacon_score,
        "dga": DNSClientWindow.dga_score,
    }.get(detection, DNSClientWindow.tunnel_score)


def _to_row(w: DNSClientWindow) -> ClientWindowRow:
    return ClientWindowRow(
        id=str(w.id),
        client_ip=str(w.client_ip),
        window_start=w.window_start,
        window_end=w.window_end,
        query_count=w.query_count,
        distinct_qnames=w.distinct_qnames,
        distinct_parents=w.distinct_parents,
        top_parent=w.top_parent,
        top_parent_subdomains=w.top_parent_subdomains,
        max_label_length=w.max_label_length,
        mean_label_entropy=w.mean_label_entropy,
        payload_qtype_count=w.payload_qtype_count,
        tunnel_score=w.tunnel_score,
        tunnel_signals=w.tunnel_signals or [],
        beacon_score=w.beacon_score,
        beacon_candidates=w.beacon_candidates or [],
        beacon_detail=w.beacon_detail,
        dga_score=w.dga_score,
        dga_candidates=w.dga_candidates or [],
        dga_signals=w.dga_signals or [],
        dga_detail=w.dga_detail,
        allowlisted=w.allowlisted,
        server_count=w.server_count,
    )


@router.get("/windows", response_model=list[ClientWindowRow])
async def list_windows(
    db: DB,
    current_user: CurrentUser,
    client_ip: str | None = Query(default=None),
    hours: int = Query(default=24, ge=1, le=24 * 30),
    min_score: float = Query(default=INTERESTING_SCORE, ge=0, le=100),
    # Which detection to rank and filter by. Kept explicit rather than
    # scoring on max(tunnel, beacon, dga): the three mean different
    # things and an operator hunting exfil should not have their list
    # reordered by a chatty monitoring agent.
    detection: str = Query(default="tunnel", pattern="^(tunnel|beacon|dga)$"),
    include_allowlisted: bool = Query(default=False),
    include_muted: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[ClientWindowRow]:
    """Scored client windows, worst first.

    Defaults to the interesting band rather than everything: on a busy
    resolver the vast majority of windows score ~0, and a list that
    opens on thousands of zeroes buries the handful that matter. Pass
    ``min_score=0`` to see the full picture.
    """
    since = datetime.now(UTC) - timedelta(hours=hours)
    stmt = (
        select(DNSClientWindow)
        .where(DNSClientWindow.window_start >= since)
        .order_by(
            desc(_score_column(detection)),
            desc(DNSClientWindow.window_start),
        )
        .limit(limit)
    )
    if client_ip:
        # The column is INET; an unvalidated string reaches Postgres as
        # `client_ip = 'web-01'` and raises `invalid input syntax for
        # type inet`, surfacing as a 500 rather than a 422.
        stmt = stmt.where(DNSClientWindow.client_ip == _validated_ip(client_ip))
        # A per-client drilldown wants the client's whole history, not
        # just its interesting hours.
        stmt = stmt.order_by(None).order_by(desc(DNSClientWindow.window_start))
    else:
        stmt = stmt.where(_score_column(detection) >= min_score)
    if not include_allowlisted:
        stmt = stmt.where(DNSClientWindow.allowlisted.is_(False))
    if not include_muted and not client_ip:
        # A muted client is one an operator reviewed and cleared, so it
        # drops out of the default view — that is what the mute dialog
        # promises. Still reachable via the toggle, and a per-client
        # lookup always shows everything so the drilldown stays honest.
        stmt = stmt.where(
            DNSClientWindow.client_ip.not_in(
                select(DNSThreatMute.client_ip).where(
                    or_(
                        DNSThreatMute.muted_until.is_(None),
                        DNSThreatMute.muted_until > datetime.now(UTC),
                    )
                )
            )
        )
    rows = (await db.execute(stmt)).scalars().all()
    # One lookup for the whole page rather than per row.
    now = datetime.now(UTC)
    mutes = {str(m.client_ip): m for m in (await db.execute(select(DNSThreatMute))).scalars().all()}
    out: list[ClientWindowRow] = []
    for w in rows:
        row = _to_row(w)
        mute = mutes.get(row.client_ip)
        if mute is not None and mute.is_active(now):
            row.muted = True
            row.mute_reason = mute.reason
            row.mute_until = mute.muted_until
        out.append(row)
    return out


@router.get("/summary", response_model=ThreatSummary)
async def threat_summary(
    db: DB,
    current_user: CurrentUser,
    hours: int = Query(default=24, ge=1, le=24 * 30),
    min_score: float = Query(default=INTERESTING_SCORE, ge=0, le=100),
) -> ThreatSummary:
    return ThreatSummary(**await compute_threat_summary(db, hours=hours, min_score=min_score))


class MuteBody(BaseModel):
    client_ip: str
    # Required, not optional: an unexplained mute is how a real incident
    # gets buried by someone tidying a dashboard.
    reason: str = Field(min_length=3, max_length=2000)
    # NULL = indefinite. The UI defaults to a dated mute so a snap
    # decision ages out and gets re-examined rather than silently
    # outliving the person who made it.
    muted_until: datetime | None = None


class MuteRow(BaseModel):
    id: str
    client_ip: str
    reason: str
    muted_until: datetime | None
    muted_by_display: str
    created_at: datetime
    active: bool


def _to_mute_row(m: DNSThreatMute, now: datetime) -> MuteRow:
    return MuteRow(
        id=str(m.id),
        client_ip=str(m.client_ip),
        reason=m.reason,
        muted_until=m.muted_until,
        muted_by_display=m.muted_by_display,
        created_at=m.created_at,
        active=m.is_active(now),
    )


@router.get("/mutes", response_model=list[MuteRow])
async def list_mutes(db: DB, current_user: CurrentUser) -> list[MuteRow]:
    """Every mute, expired ones included.

    Expired mutes are kept rather than deleted — "we muted this host for
    30 days in March" is part of the audit trail and explains why a
    client reappeared.
    """
    now = datetime.now(UTC)
    rows = (
        (await db.execute(select(DNSThreatMute).order_by(desc(DNSThreatMute.created_at))))
        .scalars()
        .all()
    )
    return [_to_mute_row(m, now) for m in rows]


@router.post(
    "/mutes",
    response_model=MuteRow,
    status_code=201,
    # The router-level gate is ``read`` because this surface is
    # read-mostly — but muting SUPPRESSES A CRITICAL SECURITY ALERT, so
    # it cannot inherit it. Without this a Viewer (read:*) could silence
    # an exfiltration finding. Non-negotiable #3.
    dependencies=[Depends(require_permission("write", "server"))],
)
async def create_mute(body: MuteBody, db: DB, current_user: CurrentUser) -> MuteRow:
    """Mute a client, or update the existing mute for it.

    Upsert rather than insert: re-muting an already-muted client should
    revise the decision (new expiry, better reason), not stack rows that
    disagree about when the mute ends.

    Audited — muting a finding is a security-relevant judgement call,
    and the audit row is what makes it reviewable later.
    """
    ip = _validated_ip(body.client_ip)
    existing = (
        await db.execute(select(DNSThreatMute).where(DNSThreatMute.client_ip == ip))
    ).scalar_one_or_none()
    action = "update" if existing is not None else "create"
    row = existing or DNSThreatMute(client_ip=ip)
    row.reason = body.reason
    row.muted_until = body.muted_until
    row.muted_by = current_user.id
    row.muted_by_display = current_user.username
    db.add(row)
    db.add(
        AuditLog(
            action=f"dns_threat_mute_{action}",
            resource_type="dns_client",
            resource_id=ip,
            resource_display=ip,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={
                "reason": body.reason,
                "muted_until": body.muted_until.isoformat() if body.muted_until else None,
            },
        )
    )
    await db.commit()
    await db.refresh(row)
    return _to_mute_row(row, datetime.now(UTC))


@router.delete(
    "/mutes/{client_ip}",
    status_code=204,
    dependencies=[Depends(require_permission("write", "server"))],
)
async def delete_mute(client_ip: str, db: DB, current_user: CurrentUser) -> None:
    """Un-mute a client so its findings surface again."""
    ip = _validated_ip(client_ip)
    row = (
        await db.execute(select(DNSThreatMute).where(DNSThreatMute.client_ip == ip))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="no mute for that client")
    await db.delete(row)
    db.add(
        AuditLog(
            action="dns_threat_mute_delete",
            resource_type="dns_client",
            resource_id=ip,
            resource_display=ip,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            old_value={"reason": row.reason},
        )
    )
    await db.commit()


# ── RPZ hit attribution (issue #699) ──────────────────────────────────
#
# Pure reporting, unlike the three scored detections above: a hit is
# ground truth (named matched a policy and logged it), so there is
# nothing to infer and nothing to threshold. These endpoints only
# attribute and rank.


class RPZOffender(BaseModel):
    client_ip: str
    hits: int
    distinct_names: int
    distinct_feeds: int
    last_seen: datetime
    top_qname: str | None
    top_qname_hits: int
    # True once the client is over the "worth chasing" bar. Carried from
    # the service so the UI and the copilot agree on what counts as
    # noisy rather than each inventing a threshold.
    noisy: bool


class RPZBlockedName(BaseModel):
    qname: str
    hits: int
    clients: int
    rpz_zone: str | None


class RPZFeedRow(BaseModel):
    rpz_zone: str | None
    hits: int
    clients: int
    distinct_names: int


class RPZSummary(BaseModel):
    blocked_hits: int
    clients_blocked: int
    distinct_names: int
    feeds_firing: int
    # PASSTHRU is an explicit allow, not a block — reported separately
    # so an operator tuning an allowlist can see it working, and so the
    # blocked count never silently includes it.
    passthru_hits: int
    worst_client_ip: str | None
    worst_client_hits: int | None
    since: datetime
    has_data: bool


@router.get("/rpz/summary", response_model=RPZSummary)
async def rpz_summary(
    db: DB,
    current_user: CurrentUser,
    hours: int = Query(default=24, ge=1, le=24 * 30),
) -> RPZSummary:
    """Blocklist activity rollup for the Security dashboard card."""
    return RPZSummary(**await rpz_service.summary(db, hours=hours))


@router.get("/rpz/clients", response_model=list[RPZOffender])
async def rpz_clients(
    db: DB,
    current_user: CurrentUser,
    hours: int = Query(default=24, ge=1, le=24 * 30),
    limit: int = Query(default=20, ge=1, le=200),
    min_hits: int = Query(default=1, ge=1),
) -> list[RPZOffender]:
    """Clients ranked by blocked-lookup count — "which machine is infected".

    This is the question the blocklists could always have answered and
    never did.
    """
    rows = await rpz_service.top_offending_clients(db, hours=hours, limit=limit, min_hits=min_hits)
    return [RPZOffender(**r) for r in rows]


@router.get("/rpz/names", response_model=list[RPZBlockedName])
async def rpz_names(
    db: DB,
    current_user: CurrentUser,
    hours: int = Query(default=24, ge=1, le=24 * 30),
    limit: int = Query(default=20, ge=1, le=200),
) -> list[RPZBlockedName]:
    """The blocked names themselves, ranked by hit count."""
    return [
        RPZBlockedName(**r)
        for r in await rpz_service.top_blocked_names(db, hours=hours, limit=limit)
    ]


class RPZHitRow(BaseModel):
    """One individual policy hit — the raw event, not a rollup."""

    id: str
    ts: datetime
    server_id: str | None
    client_ip: str | None
    qname: str | None
    trigger: str
    policy: str
    rpz_zone: str | None
    raw: str


@router.get("/rpz/hits", response_model=list[RPZHitRow])
async def rpz_hits(
    db: DB,
    current_user: CurrentUser,
    hours: int = Query(default=24, ge=1, le=24 * 30),
    limit: int = Query(default=100, ge=1, le=500),
    client_ip: str | None = Query(default=None),
    qname_contains: str | None = Query(default=None, max_length=255),
    include_passthru: bool = Query(default=False),
) -> list[RPZHitRow]:
    """The individual blocked lookups, newest first (issue #914).

    The four rollups above answer "how much"; this answers "what". The
    rows have been stored since #699 and were reachable from no endpoint,
    so "show me the three lookups this PC made in the last ten minutes
    that were blocked" — the question that actually closes out a user
    report — could not be asked.

    ``include_passthru`` is off by default: a PASSTHRU is an explicit
    ALLOW, and listing it among blocks makes a working allowlist look
    like an infection.
    """
    try:
        hits = await rpz_service.recent_hits(
            db,
            hours=hours,
            limit=limit,
            client_ip=client_ip,
            qname_contains=qname_contains,
            include_passthru=include_passthru,
        )
    except InvalidLogFilter as exc:
        raise HTTPException(status_code=422, detail=exc.detail) from exc
    return [RPZHitRow(**r) for r in hits]


@router.get("/rpz/feeds", response_model=list[RPZFeedRow])
async def rpz_feeds(
    db: DB,
    current_user: CurrentUser,
    hours: int = Query(default=24, ge=1, le=24 * 30),
) -> list[RPZFeedRow]:
    """Hits per blocklist feed — which subscriptions are earning their keep."""
    return [RPZFeedRow(**r) for r in await rpz_service.feed_effectiveness(db, hours=hours)]
