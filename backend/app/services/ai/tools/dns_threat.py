"""DNS threat analytics tools for the Operator Copilot (issue #699).

Four read-only tools over the per-client threat rollup — tunneling
(content) and beaconing (timing) score onto the same windows.

**No ``propose_mute_dns_client``** — an explicit decision, not an
oversight (non-negotiable #13). Muting suppresses a ``critical``
exfiltration alert and requires a written justification that outlives
the person who gave it; that belongs in a deliberate UI action with a
typed reason, not a chat turn, even an Apply-gated one. What the
copilot does need is to *see* mutes, so it stops re-reporting hosts an
operator already triaged — hence ``find_dns_threat_mutes``.

Not superadmin-gated, unlike the backup tools: this is a summary of the
DNS query log, and the permission model already decides who may read
that. It is tagged to the ``security.dns_threat`` module so the tools
disappear when the feature is off.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dns_threat import DNSClientWindow
from app.services.ai.tools.base import register_tool
from app.services.dns_threat.aggregate import INTERESTING_SCORE


class FindSuspiciousDNSClientsArgs(BaseModel):
    hours: int = Field(default=24, ge=1, le=24 * 30, description="Trailing window to consider.")
    min_score: float = Field(
        default=INTERESTING_SCORE,
        ge=0,
        le=100,
        description=(
            "Minimum tunneling score (0-100). 60+ is a strong signal; 20-60 is "
            "worth a look but is often busy-but-benign traffic."
        ),
    )
    client_ip: str | None = Field(
        default=None,
        description="Restrict to one client IP — use for 'why did 10.0.0.5 get flagged?'.",
    )
    limit: int = Field(default=25, ge=1, le=200)


@register_tool(
    name="find_suspicious_dns_clients",
    permission=("read", "server"),
    description=(
        "Find DNS clients whose query behaviour scores as tunneling / "
        "exfiltration (issue #699). DNS tunneling hides payload in the "
        "names a host looks up, under a domain the attacker controls — "
        "it is the exfil path firewalls do not inspect. Each row "
        "carries the client IP, the 0-100 score, the domain the traffic "
        "concentrated on, and the individual signals with their "
        "contributions (label length, label entropy, subdomain fan-out, "
        "payload-qtype ratio) so the answer explains itself. Use for "
        "'is anything tunnelling over DNS?', 'why was 10.0.0.5 "
        "flagged?', or 'what is the worst DNS client this week?'. "
        "Windows whose traffic was entirely to allowlisted domains "
        "(DNSBL / CDN / reverse-DNS, which look like tunnels by design) "
        "are excluded."
    ),
    args_model=FindSuspiciousDNSClientsArgs,
    category="dns",
    module="security.dns_threat",
    # Explicit per non-negotiable #13. Enabled: the surface exposes no
    # secrets and makes no off-prem call, and it is already behind a
    # default-off module that an operator had to turn on knowing it
    # reads query content — gating it twice would just hide the tool
    # from the person who opted in.
    default_enabled=True,
)
async def find_suspicious_dns_clients(
    db: AsyncSession, user: User, args: FindSuspiciousDNSClientsArgs
) -> list[dict[str, Any]]:
    since = datetime.now(UTC) - timedelta(hours=args.hours)
    stmt = (
        select(DNSClientWindow)
        .where(
            DNSClientWindow.window_start >= since,
            DNSClientWindow.allowlisted.is_(False),
        )
        .order_by(desc(DNSClientWindow.tunnel_score), desc(DNSClientWindow.window_start))
        .limit(args.limit)
    )
    if args.client_ip:
        # An LLM will cheerfully pass a hostname or a CIDR here; against
        # an INET column that is a 500 and an internal_error row rather
        # than an answer.
        try:
            ip = str(ipaddress.ip_address(args.client_ip.strip()))
        except ValueError:
            return [
                {
                    "error": (
                        f"client_ip must be a single IP address, got "
                        f"{args.client_ip!r}. Resolve the hostname first, or drop "
                        f"the filter to see the worst-scoring clients."
                    )
                }
            ]
        stmt = stmt.where(DNSClientWindow.client_ip == ip)
    else:
        stmt = stmt.where(DNSClientWindow.tunnel_score >= args.min_score)
    rows = (await db.execute(stmt)).scalars().all()
    if not rows:
        return [
            {
                "result": "no matching client windows",
                "note": (
                    "Either nothing is scoring above the threshold, or the rollup "
                    "has no data — the security.dns_threat module must be enabled "
                    "AND a DNS server group must have query logging turned on."
                ),
            }
        ]
    return [
        {
            "client_ip": str(w.client_ip),
            "tunnel_score": round(w.tunnel_score, 1),
            "window_start": w.window_start.isoformat(),
            "window_end": w.window_end.isoformat(),
            "query_count": w.query_count,
            "distinct_qnames": w.distinct_qnames,
            "top_parent": w.top_parent,
            "top_parent_subdomains": w.top_parent_subdomains,
            "max_label_length": w.max_label_length,
            "mean_label_entropy": round(w.mean_label_entropy, 2),
            "payload_qtype_count": w.payload_qtype_count,
            "signals": w.tunnel_signals or [],
        }
        for w in rows
    ]


class DNSThreatSummaryArgs(BaseModel):
    hours: int = Field(default=24, ge=1, le=24 * 30)


@register_tool(
    name="get_dns_threat_summary",
    permission=("read", "server"),
    description=(
        "One-shot rollup of DNS tunneling analytics over a trailing "
        "window (issue #699): how many client windows were scored, how "
        "many distinct clients, how many crossed the suspicious "
        "threshold, and the worst offender. Answers 'is anything "
        "exfiltrating over DNS right now?' without listing every "
        "client. Reports explicitly when the rollup has no data at all, "
        "so an idle result is never mistaken for an all-clear."
    ),
    args_model=DNSThreatSummaryArgs,
    category="dns",
    module="security.dns_threat",
    default_enabled=True,
)
async def get_dns_threat_summary(
    db: AsyncSession, user: User, args: DNSThreatSummaryArgs
) -> dict[str, Any]:
    # Shared with the REST endpoint and the dashboard card so the
    # copilot can't answer against a different "suspicious" threshold
    # than the UI is showing.
    from app.services.dns_threat.aggregate import compute_threat_summary  # noqa: PLC0415

    out = await compute_threat_summary(db, hours=args.hours)
    out["since"] = out["since"].isoformat()
    if not out["has_data"]:
        out["note"] = (
            "No client windows have been scored in this period. The rollup "
            "requires the security.dns_threat module enabled and query "
            "logging on at least one DNS server group — an empty result "
            "here is NOT an all-clear."
        )
    return out


class FindDNSThreatMutesArgs(BaseModel):
    include_expired: bool = Field(
        default=False,
        description=(
            "Include mutes that have lapsed. Expired mutes are kept for "
            "audit and explain why a client started appearing again."
        ),
    )


@register_tool(
    name="find_dns_threat_mutes",
    permission=("read", "server"),
    description=(
        "List DNS clients an operator has reviewed and muted, with the "
        "reason, who muted them and when it expires. Use before "
        "reporting a tunneling finding — a muted client has already "
        "been triaged and saying so ('10.0.0.5 is muted: Veeam backup "
        "agent') is more useful than re-reporting it as a threat. Also "
        "answers 'what have we cleared?' and 'why is this host not "
        "alerting?'."
    ),
    args_model=FindDNSThreatMutesArgs,
    category="dns",
    module="security.dns_threat",
    default_enabled=True,
)
async def find_dns_threat_mutes(
    db: AsyncSession, user: User, args: FindDNSThreatMutesArgs
) -> list[dict[str, Any]]:
    from app.models.dns_threat_mute import DNSThreatMute  # noqa: PLC0415

    now = datetime.now(UTC)
    rows = (
        (await db.execute(select(DNSThreatMute).order_by(desc(DNSThreatMute.created_at))))
        .scalars()
        .all()
    )
    out = []
    for m in rows:
        active = m.is_active(now)
        if not active and not args.include_expired:
            continue
        out.append(
            {
                "client_ip": str(m.client_ip),
                "reason": m.reason,
                "active": active,
                "muted_until": m.muted_until.isoformat() if m.muted_until else None,
                "muted_by": m.muted_by_display,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            }
        )
    if not out:
        return [{"result": "no muted clients"}]
    return out


class FindBeaconingClientsArgs(BaseModel):
    hours: int = Field(default=24, ge=1, le=24 * 30)
    min_score: float = Field(
        default=60.0,
        ge=0,
        le=100,
        description=(
            "Minimum beaconing score. Note that legitimate pollers "
            "(monitoring agents, health checks, update checkers) score "
            "as high as real callbacks — the query name is what "
            "distinguishes them, not the number."
        ),
    )
    limit: int = Field(default=25, ge=1, le=200)


@register_tool(
    name="find_beaconing_clients",
    permission=("read", "server"),
    description=(
        "Find DNS clients querying one name on a metronomic cadence — "
        "the rhythm of a C2 callback (issue #699). Each row carries the "
        "query name, the period in seconds, how many samples, and the "
        "variation, because **the name is what makes the finding "
        "actionable**: a monitoring agent and a beacon are "
        "indistinguishable by timing alone, and 'queries "
        "metrics.corp.example.com every 30s' is an instant dismissal "
        "where a bare score is not. ALWAYS report the name and period, "
        "never just the score, and say plainly that periodic lookups "
        "are frequently benign infrastructure. Distinct from "
        "find_suspicious_dns_clients, which scores name *content* for "
        "tunneling rather than timing."
    ),
    args_model=FindBeaconingClientsArgs,
    category="dns",
    module="security.dns_threat",
    default_enabled=True,
)
async def find_beaconing_clients(
    db: AsyncSession, user: User, args: FindBeaconingClientsArgs
) -> list[dict[str, Any]]:
    since = datetime.now(UTC) - timedelta(hours=args.hours)
    rows = (
        (
            await db.execute(
                select(DNSClientWindow)
                .where(
                    DNSClientWindow.window_start >= since,
                    DNSClientWindow.beacon_score >= args.min_score,
                )
                .order_by(desc(DNSClientWindow.beacon_score))
                .limit(args.limit)
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return [
            {
                "result": "no clients showing periodic callback behaviour",
                "note": (
                    "Either nothing is beaconing above the threshold, or the "
                    "rollup has no data — security.dns_threat must be enabled "
                    "AND a DNS group must have query logging on."
                ),
            }
        ]
    return [
        {
            "client_ip": str(w.client_ip),
            "beacon_score": round(w.beacon_score, 1),
            "window_start": w.window_start.isoformat(),
            "candidates": w.beacon_candidates or [],
            "detail": w.beacon_detail,
        }
        for w in rows
    ]


class FindDGAClientsArgs(BaseModel):
    hours: int = Field(default=24, ge=1, le=24 * 30)
    limit: int = Field(default=25, ge=1, le=200)
    min_score: float = Field(
        default=60.0,
        ge=0,
        le=100,
        description=(
            "Minimum DGA score. Scoring is on name plausibility alone — "
            "the BIND9 query log carries no rcode, so there is no "
            "NXDOMAIN prior — which makes this weaker evidence than the "
            "tunneling score and worth reporting with that caveat."
        ),
    )


@register_tool(
    name="find_dga_clients",
    permission=("read", "server"),
    description=(
        "Find DNS clients that queried a crop of algorithmically-"
        "generated domain names — how malware locates its "
        "command-and-control server (issue #699). Each row carries the "
        "implausible domains themselves, which is what makes the "
        "finding actionable: hashed-CDN buckets, shortlink services "
        "and odd brand names share the shape, so ALWAYS report the "
        "sample domains and say plainly that the score rests on name "
        "plausibility alone (no NXDOMAIN prior is available). Distinct "
        "from find_suspicious_dns_clients: a tunnel concentrates many "
        "subdomains under ONE parent, a DGA sprays across MANY parents."
    ),
    args_model=FindDGAClientsArgs,
    category="dns",
    module="security.dns_threat",
    default_enabled=True,
)
async def find_dga_clients(
    db: AsyncSession, user: User, args: FindDGAClientsArgs
) -> list[dict[str, Any]]:
    since = datetime.now(UTC) - timedelta(hours=args.hours)
    rows = (
        (
            await db.execute(
                select(DNSClientWindow)
                .where(
                    DNSClientWindow.window_start >= since,
                    DNSClientWindow.dga_score >= args.min_score,
                )
                .order_by(desc(DNSClientWindow.dga_score))
                .limit(args.limit)
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return [
            {
                "result": "no clients querying generated-looking domain crops",
                "note": (
                    "Either nothing scored above the threshold, or the rollup "
                    "has no data — security.dns_threat must be enabled AND a "
                    "DNS group must have query logging on."
                ),
            }
        ]
    return [
        {
            "client_ip": str(w.client_ip),
            "dga_score": round(w.dga_score, 1),
            "window_start": w.window_start.isoformat(),
            "distinct_parents": w.distinct_parents,
            "sample_domains": w.dga_candidates or [],
            "signals": w.dga_signals or [],
            "detail": w.dga_detail,
        }
        for w in rows
    ]


class FindRPZOffendersArgs(BaseModel):
    hours: int = Field(default=24, ge=1, le=24 * 30)
    limit: int = Field(default=20, ge=1, le=200)
    min_hits: int = Field(
        default=1,
        ge=1,
        description="Only clients with at least this many blocked lookups.",
    )


@register_tool(
    name="find_rpz_offenders",
    permission=("read", "server"),
    description=(
        "Find which clients keep reaching for domains the blocklists "
        "block (issue #699). This is ground truth, NOT a heuristic — "
        "named matched a response-policy rule and logged it — so it is "
        "much stronger evidence than the tunneling / beaconing / DGA "
        "scores. A single blocked lookup is an ad on a web page; "
        "hundreds from one host is a machine with something running on "
        "it. Rows carry the worst domain and the number of distinct "
        "feeds that fired. PASSTHRU (an explicit allow) is excluded "
        "from the counts by design."
    ),
    args_model=FindRPZOffendersArgs,
    category="dns",
    module="security.dns_threat",
    default_enabled=True,
)
async def find_rpz_offenders(
    db: AsyncSession, user: User, args: FindRPZOffendersArgs
) -> list[dict[str, Any]]:
    from app.services.dns_threat import rpz as rpz_service  # noqa: PLC0415

    rows = await rpz_service.top_offending_clients(
        db, hours=args.hours, limit=args.limit, min_hits=args.min_hits
    )
    if not rows:
        return [
            {
                "result": "no clients hit the blocklists in this window",
                "note": (
                    "This can legitimately mean nothing was blocked. It can "
                    "also mean the pipeline is not running: RPZ attribution "
                    "needs security.dns_threat enabled, query logging on for "
                    "a BIND9 group, and at least one blocklist assigned."
                ),
            }
        ]
    return [
        {
            **r,
            "last_seen": r["last_seen"].isoformat() if r.get("last_seen") else None,
        }
        for r in rows
    ]


@register_tool(
    name="get_rpz_block_summary",
    permission=("read", "server"),
    description=(
        "Blocklist activity rollup: how many lookups were blocked, how "
        "many distinct clients and names, which feeds fired, and the "
        "worst offending client (issue #699). Use to answer 'are the "
        "blocklists doing anything' and 'which feed is earning its "
        "keep'. Check has_data — zero blocks is a plausible real answer "
        "on a quiet network, so a zero WITHOUT has_data means the "
        "pipeline is not running rather than that nothing was blocked."
    ),
    args_model=DNSThreatSummaryArgs,
    category="dns",
    module="security.dns_threat",
    default_enabled=True,
)
async def get_rpz_block_summary(
    db: AsyncSession, user: User, args: DNSThreatSummaryArgs
) -> dict[str, Any]:
    from app.services.dns_threat import rpz as rpz_service  # noqa: PLC0415

    out = await rpz_service.summary(db, hours=args.hours)
    out["since"] = out["since"].isoformat()
    out["feeds"] = await rpz_service.feed_effectiveness(db, hours=args.hours)
    return out


# ── find_rpz_hits (issue #914) ────────────────────────────────────────


class FindRPZHitsArgs(BaseModel):
    hours: int = Field(default=24, ge=1, le=24 * 30, description="Trailing window in hours.")
    limit: int = Field(default=50, ge=1, le=500)
    client_ip: str | None = Field(
        default=None, description="Only hits from this client IP address."
    )
    qname_contains: str | None = Field(
        default=None, max_length=255, description="Substring match on the blocked domain."
    )
    include_passthru: bool = Field(
        default=False,
        description=(
            "Include PASSTHRU rows — explicit ALLOWs where an exception let a "
            "listed name through. Off by default: they are not blocks."
        ),
    )


@register_tool(
    name="find_rpz_hits",
    permission=("read", "server"),
    description=(
        "The INDIVIDUAL blocked lookups, newest first — not a rollup "
        "(issue #914). find_rpz_offenders says a client has N blocked "
        "lookups and its worst domain; this says exactly which names it "
        "asked for, when, and which feed blocked each one. Use it to "
        "close out 'the user says this site does not work': filter to "
        "their IP and read the last few minutes. Set include_passthru to "
        "answer the opposite question — why a listed name got through."
    ),
    args_model=FindRPZHitsArgs,
    category="dns",
    module="security.dns_threat",
    default_enabled=True,
)
async def find_rpz_hits(
    db: AsyncSession, user: User, args: FindRPZHitsArgs
) -> list[dict[str, Any]]:
    from app.services.dns_threat import rpz as rpz_service  # noqa: PLC0415

    client_ip: str | None = None
    if args.client_ip:
        # An INET comparison raises on a malformed literal, so the model's
        # own answer ("no such client") is returned instead of a 500 that
        # reads to the copilot as a broken tool.
        try:
            client_ip = str(ipaddress.ip_address(args.client_ip.strip()))
        except ValueError:
            return [{"result": f"{args.client_ip!r} is not an IP address"}]

    rows = await rpz_service.recent_hits(
        db,
        hours=args.hours,
        limit=args.limit,
        client_ip=client_ip,
        qname_contains=args.qname_contains,
        include_passthru=args.include_passthru,
    )
    return [{**r, "ts": r["ts"].isoformat() if r.get("ts") else None} for r in rows]
