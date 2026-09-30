"""Read-only DNS tools for the Operator Copilot (issue #90 Wave 2)."""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dns import (
    DNSBlockList,
    DNSPool,
    DNSPoolMember,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSTSIGKey,
    DNSView,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.services.ai.operations_writes import SetZoneUpdateAclArgs
from app.services.ai.tools.base import register_tool
from app.services.dns.name_scope import classify_zone_name
from app.services.dns.tld_registry import effective_registry

_ZONE_NAME_SCOPES = frozenset({"public", "reserved", "undelegated", "reverse"})


class ListZonesArgs(BaseModel):
    group_id: str | None = Field(default=None, description="Filter by DNS server group UUID.")
    kind: str | None = Field(
        default=None,
        description="Filter by zone kind: 'forward' or 'reverse'.",
    )
    search: str | None = Field(
        default=None,
        description="Substring match on the zone name (FQDN).",
    )
    name_scope: str | None = Field(
        default=None,
        description=(
            "Filter by TLD scope of the zone name: 'public' (a delegated "
            "IANA TLD), 'reserved' (a special-use namespace such as .local "
            "or .internal), 'undelegated' (a TLD nobody has delegated, e.g. "
            ".lan), or 'reverse' (in-addr.arpa / ip6.arpa)."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)

    @field_validator("name_scope")
    @classmethod
    def _v_name_scope(cls, v: str | None) -> str | None:
        """Reject an unknown scope rather than quietly matching nothing.

        A silent empty list here would read to the copilot — and to the
        operator reading its answer — as "there are no such zones", which
        is a confident wrong answer to a question that was never asked.
        """
        if v is None:
            return None
        norm = v.strip().lower()
        if not norm:
            return None
        if norm not in _ZONE_NAME_SCOPES:
            raise ValueError(f"name_scope must be one of {sorted(_ZONE_NAME_SCOPES)}")
        return norm


# Ceiling on the pre-filter scan when ``name_scope`` is set. The scope is
# derived from the name at read time rather than stored, so it cannot be a
# WHERE clause — the rows have to be classified in Python and the SQL LIMIT
# applied afterwards, or a "show me the undelegated zones" question would
# only ever search the alphabetically-first ``limit`` zones and confidently
# answer "none". This caps the cost of that scan; the tool says so in its
# reply when it bites, rather than silently under-reporting.
_ZONE_SCOPE_SCAN_CAP = 20_000


@register_tool(
    name="list_dns_zones",
    description=(
        "List DNS zones (authoritative / secondary / stub / forward). "
        "Each summary includes name, type, kind (forward / reverse), "
        "TTL, server group, view binding, and name_scope — whether the "
        "zone name sits on a delegated public TLD, a reserved special-use "
        "namespace, an undelegated TLD, or is a reverse zone."
    ),
    args_model=ListZonesArgs,
    category="dns",
    module="core.dns",
)
async def list_dns_zones(db: AsyncSession, user: User, args: ListZonesArgs) -> list[dict[str, Any]]:
    stmt = select(DNSZone).where(DNSZone.deleted_at.is_(None))
    if args.group_id:
        stmt = stmt.where(DNSZone.group_id == args.group_id)
    if args.kind:
        stmt = stmt.where(DNSZone.kind == args.kind)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(func.lower(DNSZone.name).like(like))
    stmt = stmt.order_by(DNSZone.name.asc())

    wanted = args.name_scope  # already normalised + validated
    stmt = stmt.limit(_ZONE_SCOPE_SCAN_CAP if wanted else args.limit)
    rows = list((await db.execute(stmt)).scalars().all())

    tlds = (await effective_registry(db)).tlds
    out: list[dict[str, Any]] = []
    for z in rows:
        scope = classify_zone_name(z.name, tlds=tlds)
        if wanted and scope.scope != wanted:
            continue
        out.append(
            {
                "id": str(z.id),
                "name": z.name,
                "zone_type": z.zone_type,
                "kind": z.kind,
                "group_id": str(z.group_id),
                "view_id": str(z.view_id) if z.view_id else None,
                "ttl": z.ttl,
                "name_scope": scope.scope,
                "name_scope_reason": scope.reason,
            }
        )
        if len(out) >= args.limit:
            break
    if wanted and len(rows) >= _ZONE_SCOPE_SCAN_CAP and len(out) < args.limit:
        out.append(
            {
                "note": (
                    f"scanned the first {_ZONE_SCOPE_SCAN_CAP} zones by name; "
                    "there may be further matches beyond that. Narrow with "
                    "group_id or search."
                )
            }
        )
    return out


class QueryRecordsArgs(BaseModel):
    zone_id: str | None = Field(default=None, description="Filter by zone UUID.")
    record_type: str | None = Field(
        default=None,
        description=(
            "Filter by record type — A, AAAA, CNAME, MX, TXT, NS, PTR, "
            "SRV, CAA, TLSA, SSHFP, NAPTR, LOC."
        ),
    )
    name: str | None = Field(
        default=None,
        description=(
            "Substring match on relative name OR full FQDN. Use this "
            "for questions like 'find all records for host1' or 'show "
            "me records under foo.example.com'."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="query_dns_records",
    description=(
        "Search DNS records across zones. Filters: zone, record type, "
        "and name / FQDN substring. Returns each record's relative "
        "name, FQDN, type, value, TTL, and zone."
    ),
    args_model=QueryRecordsArgs,
    category="dns",
    module="core.dns",
)
async def query_dns_records(
    db: AsyncSession, user: User, args: QueryRecordsArgs
) -> list[dict[str, Any]]:
    stmt = select(DNSRecord).where(DNSRecord.deleted_at.is_(None))
    if args.zone_id:
        stmt = stmt.where(DNSRecord.zone_id == args.zone_id)
    if args.record_type:
        stmt = stmt.where(DNSRecord.record_type == args.record_type.upper())
    if args.name:
        like = f"%{args.name.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(DNSRecord.name).like(like),
                func.lower(DNSRecord.fqdn).like(like),
            )
        )
    stmt = stmt.order_by(DNSRecord.fqdn.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "zone_id": str(r.zone_id),
            "name": r.name,
            "fqdn": r.fqdn,
            "record_type": r.record_type,
            "value": r.value,
            "ttl": r.ttl,
            "priority": r.priority,
            "weight": r.weight,
            "port": r.port,
        }
        for r in rows
    ]


class ListServerGroupsArgs(BaseModel):
    pass


@register_tool(
    name="list_dns_server_groups",
    description=(
        "List DNS server groups (logical groupings of authoritative "
        "DNS servers). Each summary includes name, group type, "
        "default view, and recursive flag."
    ),
    args_model=ListServerGroupsArgs,
    category="dns",
    module="core.dns",
)
async def list_dns_server_groups(
    db: AsyncSession, user: User, args: ListServerGroupsArgs
) -> list[dict[str, Any]]:
    rows = (
        (await db.execute(select(DNSServerGroup).order_by(DNSServerGroup.name.asc())))
        .scalars()
        .all()
    )
    return [
        {
            "id": str(g.id),
            "name": g.name,
            "group_type": g.group_type,
            "default_view": g.default_view,
            "is_recursive": g.is_recursive,
        }
        for g in rows
    ]


class FindDnsServersArgs(BaseModel):
    group_id: str | None = Field(
        default=None,
        description="Restrict to one server group (UUID). Omit for the whole fleet.",
    )
    search: str | None = Field(
        default=None,
        description="Case-insensitive substring match on server name or host.",
    )
    primary_only: bool = Field(
        default=False,
        description=(
            "Only the server each group applies DDNS / record writes at. "
            "Use when asked which server is primary, or to find a group "
            "that has none."
        ),
    )
    limit: int = Field(default=200, ge=1, le=1000)


@register_tool(
    name="find_dns_servers",
    description=(
        "List individual DNS servers with the group each belongs to, its "
        "driver, whether it is the group's primary, and its enabled / "
        "maintenance / config-apply state. Answers 'which group is this "
        "server in?', 'which server is primary for that group?' and "
        "'which groups have no primary?' — the last of which silently "
        "drops every record write to that group's zones. Read-only: "
        "moving a server between groups is done over the REST API or the "
        "DNS → Server Groups UI, not from here."
    ),
    args_model=FindDnsServersArgs,
    category="dns",
    module="core.dns",
)
async def find_dns_servers(
    db: AsyncSession, user: User, args: FindDnsServersArgs
) -> list[dict[str, Any]]:
    stmt = (
        select(DNSServer, DNSServerGroup.name)
        .join(DNSServerGroup, DNSServer.group_id == DNSServerGroup.id)
        .order_by(DNSServerGroup.name.asc(), DNSServer.name.asc())
        .limit(args.limit)
    )
    if args.group_id:
        try:
            stmt = stmt.where(DNSServer.group_id == uuid.UUID(args.group_id))
        except ValueError:
            return []
    if args.search:
        term = f"%{args.search.strip()}%"
        stmt = stmt.where(or_(DNSServer.name.ilike(term), DNSServer.host.ilike(term)))
    if args.primary_only:
        stmt = stmt.where(DNSServer.is_primary.is_(True))

    rows = (await db.execute(stmt)).all()
    return [
        {
            "id": str(s.id),
            "name": s.name,
            "group_id": str(s.group_id),
            "group_name": group_name,
            "driver": s.driver,
            "host": s.host,
            "port": s.port,
            "is_primary": s.is_primary,
            "is_enabled": s.is_enabled,
            "maintenance_mode": s.maintenance_mode,
            "status": s.status,
            # NULL means the agent has never reported a verdict (a pre-#882
            # agent, or an agentless driver with no apply loop). UNKNOWN,
            # never "ok" — a silently reverted config is exactly what would
            # hide behind that assumption.
            "config_apply_status": s.config_apply_status,
            "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
        }
        for s, group_name in rows
    ]


class PreviewZoneMoveArgs(BaseModel):
    zone_id: str = Field(..., description="UUID of the zone to move.")
    target_group_id: str = Field(..., description="UUID of the destination server group.")


@register_tool(
    name="preview_dns_zone_move",
    description=(
        "Report what moving a DNS zone to another server group would do, "
        "WITHOUT doing it. Answers 'can this zone move to that group, and "
        "what breaks?' — view scoping that would be lost or widened, "
        "dynamic-update grants whose TSIG keys don't exist in the target, "
        "whether the zone is DNSSEC-signed (a move re-signs it with new "
        "keys, so the DS at the registrar goes stale), name collisions, "
        "and ACME delegations whose NS records would still point at the "
        "old group. Read-only. The move itself is deliberately not "
        "available here — run it from the DNS UI or the REST API, where "
        "the operator confirms the zone name and acknowledges each "
        "consequence."
    ),
    args_model=PreviewZoneMoveArgs,
    category="dns",
    module="core.dns",
)
async def preview_dns_zone_move(
    db: AsyncSession, user: User, args: PreviewZoneMoveArgs
) -> dict[str, Any]:
    from app.services.dns.zone_move import ZoneMoveError, preview_move

    try:
        zone_uuid = uuid.UUID(args.zone_id)
        group_uuid = uuid.UUID(args.target_group_id)
    except ValueError as exc:
        return {"error": f"Invalid UUID: {exc}"}

    zone = await db.get(DNSZone, zone_uuid)
    if zone is None:
        return {"error": "Zone not found"}
    target = await db.get(DNSServerGroup, group_uuid)
    if target is None:
        return {"error": "Target server group not found"}

    try:
        plan = await preview_move(db, zone, target)
    except ZoneMoveError as exc:
        return {"error": exc.detail, "status": exc.status_code}

    return {
        "zone_name": plan.zone_name,
        "source_group": plan.source_group_name,
        "target_group": plan.target_group_name,
        "zone_view_action": plan.zone_view_action,
        "zone_view_from": plan.zone_view_from,
        "records_total": plan.records_total,
        "records_remapped": plan.records_remapped,
        # The dangerous one: an unscoped record answers in EVERY view, so
        # dropping a view reference widens exposure rather than removing it.
        "records_widened": plan.records_widened,
        "records_widened_by_view": plan.records_widened_by_view,
        "acl_rows_remapped": plan.acl_rows_remapped,
        "acl_keys_lost": plan.acl_keys_lost,
        "pools_repointed": plan.pools_repointed,
        "dnssec_signed": plan.dnssec_signed,
        "acme_accounts": plan.acme_accounts,
        "source_drivers": plan.source_drivers,
        "target_drivers": plan.target_drivers,
        "name_collision": plan.name_collision,
        # Hard refusals: none is waivable by acknowledgement, because none
        # leaves a state the operator could inspect and fix after.
        "dnssec_unsupported_drivers": plan.dnssec_unsupported_drivers,
        "acl_names_lost": plan.acl_names_lost,
        "key_names_lost": plan.key_names_lost,
        "warnings": plan.warnings,
        "required_acknowledgements": plan.required_acknowledgements,
    }


# ── Live DNS lookup tools ───────────────────────────────────────────
#
# ``forward_dns`` and ``reverse_dns`` wrap dnspython so the operator
# can ask "what does the resolver actually return for hostname X?"
# without leaving the chat. Configurable resolver lets operators
# point at a SpatiumDDI-managed BIND9 view they can't easily query
# from their workstation.


_DEFAULT_RESOLVE_TIMEOUT = 5.0


def _build_resolver(servers: list[str] | None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=not servers)
    if servers:
        resolver.nameservers = servers
    resolver.lifetime = _DEFAULT_RESOLVE_TIMEOUT
    return resolver


class ForwardDnsArgs(BaseModel):
    name: str = Field(
        ...,
        description="Hostname / FQDN to resolve. Trailing dots are tolerated.",
    )
    rdtype: str = Field(
        default="A",
        description=(
            "Record type — A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA. "
            "Pick A for v4 forward, AAAA for v6, ANY only when the "
            "operator explicitly wants every record at the name."
        ),
    )
    servers: list[str] | None = Field(
        default=None,
        description=(
            "Optional resolver IPs (e.g. ['10.0.0.53']). Defaults to "
            "the host's /etc/resolv.conf — useful when querying the "
            "platform's own BIND9 view from outside it."
        ),
    )

    @field_validator("rdtype")
    @classmethod
    def upper_rdtype(cls, v: str) -> str:
        v = v.strip().upper()
        if not v:
            raise ValueError("rdtype is required")
        return v


@register_tool(
    name="forward_dns",
    description=(
        "Live forward DNS lookup ('dig <name> <rdtype>'). Resolves "
        "against the host's resolver by default, or against operator-"
        "supplied nameserver IPs. Returns every answer record verbatim. "
        "Use this when the operator wants ground truth from the "
        "resolver — DB lookups via list_dns_records show the configured "
        "intent; this shows what the world actually sees."
    ),
    args_model=ForwardDnsArgs,
    category="dns",
    default_enabled=False,
    module="core.dns",
)
async def forward_dns(
    db: AsyncSession,  # noqa: ARG001
    user: User,  # noqa: ARG001
    args: ForwardDnsArgs,
) -> dict[str, Any]:
    target = args.name.strip().rstrip(".")
    resolver = _build_resolver(args.servers)
    try:
        answers = await asyncio.to_thread(resolver.resolve, target, args.rdtype)
    except dns.resolver.NXDOMAIN:
        return {
            "name": target,
            "rdtype": args.rdtype,
            "rcode": "NXDOMAIN",
            "answers": [],
        }
    except dns.resolver.NoAnswer:
        return {
            "name": target,
            "rdtype": args.rdtype,
            "rcode": "NOERROR",
            "answers": [],
        }
    except dns.resolver.NoNameservers as exc:
        return {
            "name": target,
            "rdtype": args.rdtype,
            "error": f"no nameservers: {exc}",
        }
    except dns.exception.Timeout:
        return {"name": target, "rdtype": args.rdtype, "error": "resolver timeout"}
    except dns.exception.DNSException as exc:
        return {
            "name": target,
            "rdtype": args.rdtype,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "name": target,
        "rdtype": args.rdtype,
        "rcode": "NOERROR",
        "ttl": int(answers.rrset.ttl) if answers.rrset is not None else None,
        "answers": [str(a) for a in answers],
    }


class ReverseDnsArgs(BaseModel):
    address: str = Field(
        ...,
        description="IPv4 or IPv6 address. Built into the appropriate ``in-addr.arpa`` / ``ip6.arpa`` query.",
    )
    servers: list[str] | None = Field(
        default=None,
        description="Optional resolver IPs (see ``forward_dns``).",
    )

    @field_validator("address")
    @classmethod
    def valid_addr(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc
        return v.strip()


@register_tool(
    name="reverse_dns",
    description=(
        "Live reverse-DNS lookup. Resolves the appropriate "
        "``<addr>.in-addr.arpa`` / ``<addr>.ip6.arpa`` PTR record. "
        "Returns every PTR answer; an empty list means no PTR exists. "
        "Useful when the operator wants to confirm reverse delegation "
        "is wired up correctly."
    ),
    args_model=ReverseDnsArgs,
    category="dns",
    default_enabled=False,
    module="core.dns",
)
async def reverse_dns(
    db: AsyncSession,  # noqa: ARG001
    user: User,  # noqa: ARG001
    args: ReverseDnsArgs,
) -> dict[str, Any]:
    arpa = dns.reversename.from_address(args.address).to_text(omit_final_dot=True)
    resolver = _build_resolver(args.servers)
    try:
        answers = await asyncio.to_thread(resolver.resolve, arpa, "PTR")
    except dns.resolver.NXDOMAIN:
        return {
            "address": args.address,
            "arpa": arpa,
            "rcode": "NXDOMAIN",
            "answers": [],
        }
    except dns.resolver.NoAnswer:
        return {
            "address": args.address,
            "arpa": arpa,
            "rcode": "NOERROR",
            "answers": [],
        }
    except dns.exception.Timeout:
        return {"address": args.address, "arpa": arpa, "error": "resolver timeout"}
    except dns.exception.DNSException as exc:
        return {
            "address": args.address,
            "arpa": arpa,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "address": args.address,
        "arpa": arpa,
        "rcode": "NOERROR",
        "answers": [str(a).rstrip(".") for a in answers],
    }


# ── Tier 3 DNS sub-resource depth (issue #101) ────────────────────────


# ── list_dns_records (cross-zone) ─────────────────────────────────────


class ListDNSRecordsArgs(BaseModel):
    name_contains: str | None = Field(
        default=None,
        description="Substring match on the relative record name (e.g. 'api' to find 'api.*').",
    )
    fqdn_contains: str | None = Field(
        default=None,
        description="Substring match on the full FQDN (e.g. 'foo.example.com').",
    )
    record_type: str | None = Field(
        default=None,
        description="Filter by type (A / AAAA / CNAME / MX / TXT / …). Case-insensitive.",
    )
    value_contains: str | None = Field(
        default=None,
        description="Substring match on the right-hand-side value (target IP / FQDN / TXT).",
    )
    zone_id: str | None = Field(default=None, description="Restrict to one zone by UUID.")
    group_id: str | None = Field(
        default=None,
        description="Restrict to zones under one DNS server group by UUID.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_dns_records",
    description=(
        "Cross-zone DNS record search. Filterable by relative name "
        "substring, FQDN substring, type, value substring, zone, or "
        "server group. Each row carries id, zone_id + zone name, "
        "name (relative), fqdn, record_type, value, ttl, priority, "
        "and the auto_generated flag (rows mirrored from IPAM / "
        "Kubernetes / Tailscale carry True). Use for 'where does "
        "*.api point?', 'find every CNAME pointing at "
        "old-host.example.com', or 'show me TXT records mentioning "
        "verification'. Distinct from query_dns_records, which is "
        "single-zone."
    ),
    args_model=ListDNSRecordsArgs,
    category="dns",
    module="core.dns",
)
async def list_dns_records(
    db: AsyncSession, user: User, args: ListDNSRecordsArgs
) -> list[dict[str, Any]]:
    stmt = (
        select(DNSRecord, DNSZone.name.label("zone_name"))
        .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
        .where(DNSRecord.deleted_at.is_(None))
        .where(DNSZone.deleted_at.is_(None))
    )
    if args.name_contains:
        stmt = stmt.where(func.lower(DNSRecord.name).like(f"%{args.name_contains.lower()}%"))
    if args.fqdn_contains:
        stmt = stmt.where(func.lower(DNSRecord.fqdn).like(f"%{args.fqdn_contains.lower()}%"))
    if args.record_type:
        stmt = stmt.where(DNSRecord.record_type == args.record_type.upper())
    if args.value_contains:
        stmt = stmt.where(func.lower(DNSRecord.value).like(f"%{args.value_contains.lower()}%"))
    if args.zone_id:
        stmt = stmt.where(DNSRecord.zone_id == args.zone_id)
    if args.group_id:
        stmt = stmt.where(DNSZone.group_id == args.group_id)
    stmt = stmt.order_by(DNSRecord.fqdn.asc(), DNSRecord.record_type.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).all()
    return [
        {
            "id": str(r.DNSRecord.id),
            "zone_id": str(r.DNSRecord.zone_id),
            "zone_name": r.zone_name,
            "name": r.DNSRecord.name,
            "fqdn": r.DNSRecord.fqdn,
            "record_type": r.DNSRecord.record_type,
            "value": r.DNSRecord.value,
            "ttl": r.DNSRecord.ttl,
            "priority": r.DNSRecord.priority,
            "auto_generated": r.DNSRecord.auto_generated,
        }
        for r in rows
    ]


# ── list_dns_blocklists ───────────────────────────────────────────────


class ListDNSBlockListsArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on blocklist name or description.",
    )
    category: str | None = Field(
        default=None,
        description="Filter by category: ads / malware / tracking / adult / custom / …",
    )
    enabled: bool | None = Field(
        default=None, description="Filter by ``enabled`` flag. None = both."
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_dns_blocklists",
    description=(
        "List DNS blocklists (RPZ rows). Each carries id, name, "
        "description, category, source_type (manual / url / "
        "file_upload), feed_url + feed_format when remote, "
        "block_mode (nxdomain / sinkhole / refused), "
        "feed_entries_are_wildcard (whether feed entries block "
        "subdomains too — off means a list naming tracker.example "
        "leaves cdn.tracker.example resolving), enabled, "
        "entry_count, last_synced_at + last_sync_status / error. "
        "Use for 'which blocklists are active?', 'is the malware "
        "feed up to date?', or 'when did the ads blocklist last "
        "sync?'."
    ),
    args_model=ListDNSBlockListsArgs,
    category="dns",
    module="core.dns",
)
async def list_dns_blocklists(
    db: AsyncSession, user: User, args: ListDNSBlockListsArgs
) -> list[dict[str, Any]]:
    stmt = select(DNSBlockList)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(DNSBlockList.name).like(like),
                func.lower(DNSBlockList.description).like(like),
            )
        )
    if args.category:
        stmt = stmt.where(DNSBlockList.category == args.category.lower())
    if args.enabled is not None:
        stmt = stmt.where(DNSBlockList.enabled.is_(args.enabled))
    stmt = stmt.order_by(DNSBlockList.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "category": r.category,
            "source_type": r.source_type,
            "feed_url": r.feed_url,
            "feed_format": r.feed_format,
            "update_interval_hours": r.update_interval_hours,
            "block_mode": r.block_mode,
            "feed_entries_are_wildcard": r.feed_entries_are_wildcard,
            "sinkhole_ip": r.sinkhole_ip,
            "enabled": r.enabled,
            "entry_count": r.entry_count,
            "last_synced_at": (r.last_synced_at.isoformat() if r.last_synced_at else None),
            "last_sync_status": r.last_sync_status,
            "last_sync_error": r.last_sync_error,
        }
        for r in rows
    ]


# ── list_dns_pools ────────────────────────────────────────────────────


class ListDNSPoolsArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on pool name or record_name.",
    )
    zone_id: str | None = Field(default=None, description="Restrict to one zone by UUID.")
    group_id: str | None = Field(
        default=None, description="Restrict to one DNS server group by UUID."
    )
    enabled: bool | None = Field(default=None, description="Filter by ``enabled`` flag.")
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_dns_pools",
    description=(
        "List GSLB pools (health-checked A/AAAA target sets sharing "
        "one DNS name). Each row carries id, name, description, "
        "zone_id, record_name + record_type, ttl, enabled, "
        "hc_type / interval / threshold settings, last_checked_at, "
        "and the per-member breakdown (address / weight / enabled / "
        "last_check_state / last_check_error, plus the geo-steering "
        "serving scope: serving_cidrs + site_id — empty/null means the "
        "member is a default target served to everyone). Use for 'is "
        "the www pool healthy?', 'which member of the api pool is "
        "down?', 'what's the TTL on the gslb pool?', or 'which datacenter "
        "does the eu client get for www?'."
    ),
    args_model=ListDNSPoolsArgs,
    category="dns",
    module="core.dns",
)
async def list_dns_pools(
    db: AsyncSession, user: User, args: ListDNSPoolsArgs
) -> list[dict[str, Any]]:
    # Eager-load members so each pool returns its full breakdown in
    # one trip — pools rarely exceed a handful of members.
    from sqlalchemy.orm import selectinload  # local import keeps the top imports lean

    stmt = select(DNSPool).options(selectinload(DNSPool.members))
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(DNSPool.name).like(like),
                func.lower(DNSPool.record_name).like(like),
            )
        )
    if args.zone_id:
        stmt = stmt.where(DNSPool.zone_id == args.zone_id)
    if args.group_id:
        stmt = stmt.where(DNSPool.group_id == args.group_id)
    if args.enabled is not None:
        stmt = stmt.where(DNSPool.enabled.is_(args.enabled))
    stmt = stmt.order_by(DNSPool.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().unique().all()
    return [
        {
            "id": str(p.id),
            "name": p.name,
            "description": p.description,
            "zone_id": str(p.zone_id),
            "group_id": str(p.group_id),
            "record_name": p.record_name,
            "record_type": p.record_type,
            "ttl": p.ttl,
            "enabled": p.enabled,
            "hc_type": p.hc_type,
            "hc_target_port": p.hc_target_port,
            "hc_interval_seconds": p.hc_interval_seconds,
            "hc_unhealthy_threshold": p.hc_unhealthy_threshold,
            "hc_healthy_threshold": p.hc_healthy_threshold,
            "last_checked_at": (p.last_checked_at.isoformat() if p.last_checked_at else None),
            "members": [
                {
                    "address": m.address,
                    "weight": m.weight,
                    "enabled": m.enabled,
                    "last_check_state": m.last_check_state,
                    "last_check_at": (m.last_check_at.isoformat() if m.last_check_at else None),
                    "last_check_error": m.last_check_error,
                    # Geo / topology-aware steering scope (issue #530).
                    "serving_cidrs": list(m.serving_cidrs or []),
                    "site_id": str(m.site_id) if m.site_id else None,
                }
                for m in p.members
            ],
        }
        for p in rows
    ]


# ── list_dns_views ────────────────────────────────────────────────────


class ListDNSViewsArgs(BaseModel):
    search: str | None = Field(default=None, description="Substring match on view name.")
    group_id: str | None = Field(
        default=None, description="Restrict to one DNS server group by UUID."
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_dns_views",
    description=(
        "List split-horizon DNS views — different clients see "
        "different zone data. Each row carries id, name, "
        "description, group_id, match_clients (CIDR/ACL list), "
        "match_destinations, recursion flag, evaluation order, and "
        "any per-view allow_query / allow_query_cache overrides. "
        "Use for 'which views does the corp group have?' or 'what "
        "clients does the internal view match?'."
    ),
    args_model=ListDNSViewsArgs,
    category="dns",
    module="core.dns",
)
async def list_dns_views(
    db: AsyncSession, user: User, args: ListDNSViewsArgs
) -> list[dict[str, Any]]:
    stmt = select(DNSView)
    if args.search:
        stmt = stmt.where(func.lower(DNSView.name).like(f"%{args.search.lower()}%"))
    if args.group_id:
        stmt = stmt.where(DNSView.group_id == args.group_id)
    stmt = stmt.order_by(DNSView.order.asc(), DNSView.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(v.id),
            "name": v.name,
            "description": v.description,
            "group_id": str(v.group_id),
            "match_clients": v.match_clients,
            "match_destinations": v.match_destinations,
            "recursion": v.recursion,
            "order": v.order,
            "allow_query": v.allow_query,
            "allow_query_cache": v.allow_query_cache,
        }
        for v in rows
    ]


class FindZoneDNSSECInfoArgs(BaseModel):
    zone_id: uuid.UUID = Field(
        description="UUID of the dns_zone row to inspect.",
    )


@register_tool(
    name="find_zone_dnssec_info",
    description=(
        "Return the DNSSEC posture of one DNS zone: ``dnssec_enabled`` "
        "flag, the list of DS records (key tag, algorithm, digest "
        "type, digest — formatted for parent-registrar paste), and "
        "the ``dnssec_synced_at`` timestamp the agent last reported. "
        "When enabled but ``dnssec_synced_at`` is null the zone is "
        "mid-signing or the agent hasn't reported back yet. Use this "
        "to answer 'is example.com signed?' or 'give me the DS "
        "records to paste into the registrar'. Read-only — the "
        "matching ``propose_sign_zone_dnssec`` write is deferred."
    ),
    args_model=FindZoneDNSSECInfoArgs,
    category="dns",
    module="core.dns",
)
async def find_zone_dnssec_info(
    db: AsyncSession, user: User, args: FindZoneDNSSECInfoArgs
) -> dict[str, Any]:
    from app.models.dns import DNSKey  # noqa: PLC0415

    zone = await db.get(DNSZone, args.zone_id)
    if zone is None:
        return {"error": "DNS zone not found", "zone_id": str(args.zone_id)}
    keys = (await db.execute(select(DNSKey).where(DNSKey.zone_id == zone.id))).scalars().all()
    return {
        "zone_id": str(zone.id),
        "name": zone.name,
        "dnssec_enabled": zone.dnssec_enabled,
        "dnssec_policy_id": (str(zone.dnssec_policy_id) if zone.dnssec_policy_id else None),
        "dnssec_ds_records": zone.dnssec_ds_records,
        "dnssec_synced_at": (zone.dnssec_synced_at.isoformat() if zone.dnssec_synced_at else None),
        "last_serial": zone.last_serial,
        "keys": [
            {
                "key_tag": k.key_tag,
                "key_type": k.key_type,
                "algorithm": k.algorithm,
                "state": k.state,
                "ds_records": k.ds_records or [],
            }
            for k in keys
        ],
    }


class FindDNSRateLimitSettingsArgs(BaseModel):
    group_id: uuid.UUID | None = Field(
        default=None,
        description="UUID of a dns_server_group to inspect. Omit for all groups.",
    )


@register_tool(
    name="find_dns_rate_limit_settings",
    description=(
        "Return the BIND9 Response Rate Limiting (RRL) + amplification "
        "defense posture for one DNS server group (or all groups when "
        "group_id is omitted): whether RRL is enabled, responses-per-second "
        "/ window / slip / qps-scale, the exempt-clients list, log-only "
        "(dry-run) mode, and the amplification knobs (minimal-responses, "
        "tcp-clients, clients-per-query, max-clients-per-query). Use this to "
        "answer 'is rate limiting on for the prod DNS group?' or 'what's the "
        "RRL responses-per-second?'. Read-only."
    ),
    args_model=FindDNSRateLimitSettingsArgs,
    category="dns",
    module="core.dns",
)
async def find_dns_rate_limit_settings(
    db: AsyncSession, user: User, args: FindDNSRateLimitSettingsArgs
) -> dict[str, Any]:
    # LEFT JOIN from the group: a DNSServerOptions row is created lazily (on
    # first GET/PUT of options), so an inner join would silently omit any
    # group that hasn't materialised one yet. Those groups report the model
    # defaults (RRL off) — which is their effective posture.
    stmt = select(DNSServerGroup, DNSServerOptions).outerjoin(
        DNSServerOptions, DNSServerOptions.group_id == DNSServerGroup.id
    )
    if args.group_id is not None:
        stmt = stmt.where(DNSServerGroup.id == args.group_id)
    rows = (await db.execute(stmt)).all()

    def _defaulted(g: DNSServerGroup, o: DNSServerOptions | None) -> dict[str, Any]:
        if o is None:
            return {
                "group_id": str(g.id),
                "group_name": g.name,
                "options_row_exists": False,
                "rrl_enabled": False,
                "rrl_responses_per_second": 15,
                "rrl_window": 15,
                "rrl_slip": 2,
                "rrl_qps_scale": None,
                "rrl_exempt_clients": [],
                "rrl_log_only": False,
                "minimal_responses": False,
                "tcp_clients": None,
                "clients_per_query": None,
                "max_clients_per_query": None,
                "dnsdist_enabled": False,
                "dnsdist_max_qps_per_client": None,
                "dnsdist_action": "truncate",
                "dnsdist_dynblock_qps": None,
                "dnsdist_dynblock_seconds": 60,
            }
        return {
            "group_id": str(g.id),
            "group_name": g.name,
            "options_row_exists": True,
            "rrl_enabled": o.rrl_enabled,
            "rrl_responses_per_second": o.rrl_responses_per_second,
            "rrl_window": o.rrl_window,
            "rrl_slip": o.rrl_slip,
            "rrl_qps_scale": o.rrl_qps_scale,
            "rrl_exempt_clients": o.rrl_exempt_clients or [],
            "rrl_log_only": o.rrl_log_only,
            "minimal_responses": o.minimal_responses,
            "tcp_clients": o.tcp_clients,
            "clients_per_query": o.clients_per_query,
            "max_clients_per_query": o.max_clients_per_query,
            "dnsdist_enabled": o.dnsdist_enabled,
            "dnsdist_max_qps_per_client": o.dnsdist_max_qps_per_client,
            "dnsdist_action": o.dnsdist_action,
            "dnsdist_dynblock_qps": o.dnsdist_dynblock_qps,
            "dnsdist_dynblock_seconds": o.dnsdist_dynblock_seconds,
        }

    groups = [_defaulted(g, o) for g, o in rows]
    return {"count": len(groups), "groups": groups}


class FindZoneDriftArgs(BaseModel):
    zone_id: uuid.UUID = Field(
        description="UUID of the dns_zone to check for per-server config drift.",
    )


@register_tool(
    name="find_dns_zone_drift",
    description=(
        "Per-server config-drift report for one DNS zone (#61): AXFRs / "
        "pulls the live zone from every server in the zone's group and "
        "diffs it against the SpatiumDDI DB source of truth. Returns, per "
        "server, how many records are 'extra on the server' (a manual "
        "change made directly on the host), 'missing on the server' (DB "
        "rows the server isn't serving), and in-sync — plus a sample of the "
        "drifting records. A value change shows as a missing+extra pair. "
        "Use to answer 'is example.com drifting?' or 'did someone edit "
        "records directly on the BIND9 host?'. Read-only."
    ),
    args_model=FindZoneDriftArgs,
    category="dns",
    module="core.dns",
)
async def find_dns_zone_drift(
    db: AsyncSession, user: User, args: FindZoneDriftArgs
) -> dict[str, Any]:
    from app.services.dns.drift import compute_zone_drift  # noqa: PLC0415

    zone = await db.get(DNSZone, args.zone_id)
    if zone is None:
        return {"error": "DNS zone not found", "zone_id": str(args.zone_id)}
    report = await compute_zone_drift(db, group_id=zone.group_id, zone=zone)
    return {
        "zone_id": report.zone_id,
        "name": report.zone_name,
        "db_record_count": report.db_record_count,
        "servers": [
            {
                "server_name": s.server_name,
                "driver": s.driver,
                "status": s.status,
                "error": s.error,
                "in_sync": s.in_sync,
                "drift_count": s.drift_count,
                "extra_on_server": [
                    f"{r.name} {r.record_type} {r.value}" for r in s.extra_on_server[:20]
                ],
                "missing_on_server": [
                    f"{r.name} {r.record_type} {r.value}" for r in s.missing_on_server[:20]
                ],
            }
            for s in report.servers
        ],
    }


class ListDNSSECPoliciesArgs(BaseModel):
    pass


@register_tool(
    name="list_dnssec_policies",
    description=(
        "List the DNSSEC signing policies operators can attach to BIND9 "
        "zones (issue #49): name, algorithm, NSEC3 settings, and KSK/ZSK "
        "lifetimes. The built-in 'default' policy always exists. Use this "
        "to answer 'what DNSSEC policies are available?' or 'what algorithm "
        "does policy X use?'. Read-only."
    ),
    args_model=ListDNSSECPoliciesArgs,
    category="dns",
    module="core.dns",
)
async def list_dnssec_policies(
    db: AsyncSession, user: User, args: ListDNSSECPoliciesArgs
) -> dict[str, Any]:
    from app.models.dns import DNSSECPolicy  # noqa: PLC0415

    rows = (await db.execute(select(DNSSECPolicy).order_by(DNSSECPolicy.name))).scalars().all()
    return {
        "policies": [
            {
                "id": str(p.id),
                "name": p.name,
                "is_builtin": p.is_builtin,
                "algorithm": p.algorithm,
                "ksk_lifetime_days": p.ksk_lifetime_days,
                "zsk_lifetime_days": p.zsk_lifetime_days,
                "nsec3": p.nsec3,
                "nsec3_iterations": p.nsec3_iterations,
                "nsec3_salt_length": p.nsec3_salt_length,
                "nsec3_optout": p.nsec3_optout,
            }
            for p in rows
        ]
    }


class FindDNSQueryStatsArgs(BaseModel):
    server_id: str | None = Field(
        default=None,
        description="Filter to one DNS server UUID. Omit for every server.",
    )
    window_minutes: int = Field(
        default=15,
        ge=1,
        le=1440,
        description="Trailing window to summarise (default 15 min, max 24 h).",
    )


@register_tool(
    name="find_dns_query_stats",
    description=(
        "Per-server DNS query stats over a trailing window from "
        "dns_metric_sample (the same rcode counters the NXDOMAIN-spike / "
        "query-rate-spike alerts use): total queries, NOERROR / NXDOMAIN / "
        "SERVFAIL counts, and the NXDOMAIN ratio %. Use to answer 'is any "
        "DNS server spiking?', 'what's the NXDOMAIN rate right now?', or to "
        "triage a query-anomaly alert. Read-only; empty for servers with no "
        "metric samples (non-agent / no traffic)."
    ),
    args_model=FindDNSQueryStatsArgs,
    category="dns",
    module="core.dns",
)
async def find_dns_query_stats(
    db: AsyncSession, user: User, args: FindDNSQueryStatsArgs
) -> list[dict[str, Any]]:
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from app.models.dns import DNSServer  # noqa: PLC0415
    from app.models.metrics import DNSMetricSample  # noqa: PLC0415

    since = datetime.now(UTC) - timedelta(minutes=args.window_minutes)
    stmt = (
        select(
            DNSMetricSample.server_id,
            func.sum(DNSMetricSample.queries_total).label("q"),
            func.sum(DNSMetricSample.noerror).label("ne"),
            func.sum(DNSMetricSample.nxdomain).label("nx"),
            func.sum(DNSMetricSample.servfail).label("sf"),
        )
        .where(DNSMetricSample.bucket_at >= since)
        .group_by(DNSMetricSample.server_id)
    )
    if args.server_id:
        stmt = stmt.where(DNSMetricSample.server_id == args.server_id)
    rows = (await db.execute(stmt)).all()
    if not rows:
        return []
    names = {
        sid: name
        for sid, name in (
            await db.execute(
                select(DNSServer.id, DNSServer.name).where(
                    DNSServer.id.in_([r.server_id for r in rows])
                )
            )
        ).all()
    }
    out: list[dict[str, Any]] = []
    for r in rows:
        q = int(r.q or 0)
        nx = int(r.nx or 0)
        out.append(
            {
                "server_id": str(r.server_id),
                "server_name": names.get(r.server_id),
                "window_minutes": args.window_minutes,
                "queries_total": q,
                "noerror": int(r.ne or 0),
                "nxdomain": nx,
                "servfail": int(r.sf or 0),
                "nxdomain_ratio_pct": round(nx / q * 100, 1) if q > 0 else 0.0,
            }
        )
    out.sort(key=lambda d: d["nxdomain_ratio_pct"], reverse=True)
    return out


# ── find_dns_queries (issue #914) ─────────────────────────────────────


class FindDNSQueriesArgs(BaseModel):
    client_ip: str | None = Field(
        default=None, description="Only queries from this client IP address."
    )
    qname_contains: str | None = Field(
        default=None, max_length=255, description="Substring match on the queried name."
    )
    qtype: str | None = Field(default=None, max_length=16, description="e.g. A, AAAA, MX, PTR.")
    rcode: str | None = Field(
        default=None,
        max_length=16,
        description=(
            "Exact outcome: NOERROR, NXDOMAIN, REFUSED, SERVFAIL. Pass "
            "UNKNOWN for queries whose outcome was never recorded."
        ),
    )
    server_id: str | None = Field(default=None, description="Filter to one DNS server UUID.")
    minutes: int = Field(
        default=60, ge=1, le=1440, description="Trailing window (the log is pruned at 24 h)."
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="find_dns_queries",
    description=(
        "Individual DNS queries a client made, newest first, WITH what it "
        "was told back (issue #914): rcode plus the answer count, so "
        "NXDOMAIN, REFUSED, SERVFAIL and an empty NOERROR (NODATA) are "
        "distinguishable. Use for 'this machine cannot reach X' — no row "
        "at all means the query never arrived (look at the resolver "
        "config, DHCP option 6 or a firewall), NOERROR means it is not "
        "DNS. rcode is null when the server group has response logging "
        "off; null means UNRECORDED, never success. Requires query "
        "logging on an agent-managed BIND9 / PowerDNS group; the log "
        "holds 24 h."
    ),
    args_model=FindDNSQueriesArgs,
    category="dns",
    module="core.dns",
)
async def find_dns_queries(
    db: AsyncSession, user: User, args: FindDNSQueriesArgs
) -> list[dict[str, Any]]:
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from app.models.logs import DNSQueryLogEntry  # noqa: PLC0415
    from app.services.search.ranking import like_pattern  # noqa: PLC0415

    since = datetime.now(UTC) - timedelta(minutes=args.minutes)
    stmt = select(DNSQueryLogEntry).where(DNSQueryLogEntry.ts >= since)
    if args.client_ip:
        try:
            client_ip = str(ipaddress.ip_address(args.client_ip.strip()))
        except ValueError:
            return [{"result": f"{args.client_ip!r} is not an IP address"}]
        stmt = stmt.where(DNSQueryLogEntry.client_ip == client_ip)
    if args.server_id:
        # A UUID column comparison raises a DBAPIError on anything that is
        # not one, and the likeliest wrong value here is a server NAME the
        # model read off another tool's output — so answer the question
        # instead of 500ing, exactly as the client_ip guard above does.
        try:
            server_id = str(uuid.UUID(args.server_id.strip()))
        except ValueError:
            return [{"result": f"{args.server_id!r} is not a server UUID"}]
        stmt = stmt.where(DNSQueryLogEntry.server_id == server_id)
    if args.qtype:
        stmt = stmt.where(DNSQueryLogEntry.qtype == args.qtype.strip().upper())
    if args.rcode:
        wanted = args.rcode.strip().upper()
        if wanted == "UNKNOWN":
            stmt = stmt.where(DNSQueryLogEntry.rcode.is_(None))
        else:
            stmt = stmt.where(DNSQueryLogEntry.rcode == wanted)
    if args.qname_contains:
        stmt = stmt.where(
            DNSQueryLogEntry.qname.ilike(like_pattern(args.qname_contains.strip()), escape="\\")
        )
    stmt = stmt.order_by(DNSQueryLogEntry.ts.desc(), DNSQueryLogEntry.id.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "ts": r.ts.isoformat(),
            "server_id": str(r.server_id),
            "client_ip": str(r.client_ip) if r.client_ip is not None else None,
            "qname": r.qname,
            "qtype": r.qtype,
            "view": r.view,
            # Spelled out rather than left null so a consumer cannot read
            # "no key" as "fine" — the one mistake this field exists to
            # stop (issue #914).
            "rcode": r.rcode or "UNKNOWN (response logging off for this group)",
            "answer_count": r.answer_count,
        }
        for r in rows
    ]


# Silence false-positive on lifted imports — Python pulls them in at
# module load, but the linters want at-least-one referent in module
# scope.
_ = (DNSPoolMember, DNSServerGroup)


class FindZoneUpdateAclsArgs(BaseModel):
    zone_id: uuid.UUID = Field(description="UUID of the DNS zone to inspect.")


@register_tool(
    name="find_zone_update_acls",
    description=(
        "Return a DNS zone's dynamic-update (RFC 2136) ACL (issue #641): "
        "whether ``dynamic_update_enabled`` is on, the ordered list of "
        "authorized writers (each identified by a TSIG key NAME or a "
        "source IP/CIDR — secrets are never returned), and what the "
        "zone's DNS backend can express (``caps``). Use this to answer "
        "'who can send dynamic updates to example.com?' or 'is the DC "
        "allowed to register records in this zone?'. Read-only — the "
        "matching ``propose_set_zone_update_acl`` write sets the ACL."
    ),
    args_model=FindZoneUpdateAclsArgs,
    category="dns",
    module="dns.dynamic_update_acl",
)
async def find_zone_update_acls(
    db: AsyncSession, user: User, args: FindZoneUpdateAclsArgs
) -> dict[str, Any]:
    from app.api.v1.dns.router import (  # noqa: PLC0415
        _effective_dynamic_update_caps,
        _group_driver_names,
    )

    zone = await db.get(DNSZone, args.zone_id)
    if zone is None:
        return {"error": "DNS zone not found", "zone_id": str(args.zone_id)}
    driver_names = await _group_driver_names(db, zone.group_id)
    caps = _effective_dynamic_update_caps(driver_names)
    rows = (
        await db.execute(
            select(DNSZoneUpdateAcl, DNSTSIGKey.name)
            .outerjoin(DNSTSIGKey, DNSZoneUpdateAcl.tsig_key_id == DNSTSIGKey.id)
            .where(DNSZoneUpdateAcl.zone_id == zone.id)
            .order_by(DNSZoneUpdateAcl.seq)
        )
    ).all()
    return {
        "zone_id": str(zone.id),
        "name": zone.name,
        "dynamic_update_enabled": zone.dynamic_update_enabled,
        "driver_names": driver_names,
        "caps": {
            "supports_ip_acl": caps.supports_ip_acl,
            "supports_tsig_acl": caps.supports_tsig_acl,
            "supports_name_scoping": caps.supports_name_scoping,
            "supports_per_type": caps.supports_per_type,
            "coarse_enum_only": caps.coarse_enum_only,
        },
        "entries": [
            {
                "seq": acl.seq,
                "action": acl.action,
                "match_kind": acl.match_kind,
                "ip_cidr": acl.ip_cidr,
                "tsig_key_name": key_name,
                "name_scope": acl.name_scope,
                "name_pattern": acl.name_pattern,
                "record_types": acl.record_types,
            }
            for acl, key_name in rows
        ],
    }


@register_tool(
    name="propose_set_zone_update_acl",
    description=(
        "Propose setting a DNS zone's dynamic-update (RFC 2136) ACL "
        "(issue #641) — a full ordered replace of who may send DDNS "
        "updates (by TSIG key id or source IP/CIDR), optionally flipping "
        "``dynamic_update_enabled``. Preview/apply: the model proposes, "
        "the operator clicks Apply. Security-sensitive (authorizes "
        "third-party writers to a zone), so this is disabled by default."
    ),
    args_model=SetZoneUpdateAclArgs,
    category="dns",
    writes=True,
    default_enabled=False,
    module="dns.dynamic_update_acl",
)
async def propose_set_zone_update_acl(
    db: AsyncSession, user: User, args: SetZoneUpdateAclArgs
) -> dict[str, Any]:
    from app.services.ai.tools.proposals import _propose_via  # noqa: PLC0415

    return await _propose_via(db=db, user=user, operation_name="set_zone_update_acl", args=args)


class FindDNSEncryptedTransportsArgs(BaseModel):
    group_id: str | None = Field(
        default=None,
        description="Filter to one DNS server group UUID. Omit for every group.",
    )


@register_tool(
    name="find_dns_encrypted_transports",
    description=(
        "Report which DNS server groups serve DNS-over-TLS (DoT) or "
        "DNS-over-HTTPS (DoH) to clients, and which forward to their "
        "upstream resolvers over TLS instead of plaintext port 53 "
        "(issue #50). Returns per group: the listener toggles + ports + "
        "DoH URL path, whether a usable TLS certificate is actually linked "
        "(a listener without one silently degrades to Do53), and the "
        "upstream transport with its verification hostname. Use this to "
        "answer 'is encrypted DNS on?', 'what port is DoH on?', 'are we "
        "still forwarding in cleartext?', or 'why isn't DoT working?'. "
        "Read-only; never returns certificate or key material."
    ),
    args_model=FindDNSEncryptedTransportsArgs,
    category="dns",
    module="core.dns",
)
async def find_dns_encrypted_transports(
    db: AsyncSession, user: User, args: FindDNSEncryptedTransportsArgs
) -> dict[str, Any]:
    from app.models.appliance import ApplianceCertificate  # noqa: PLC0415

    # Resolve the cert in the SAME query — one round-trip regardless of how
    # many groups exist, on the LLM's synchronous request path. Only the
    # name + a usability flag are selected: the row also carries an
    # encrypted private key, and an LLM surface has no business paging it.
    stmt = (
        select(
            DNSServerOptions,
            DNSServerGroup,
            ApplianceCertificate.name,
            ApplianceCertificate.cert_pem.isnot(None),
        )
        .join(DNSServerGroup, DNSServerGroup.id == DNSServerOptions.group_id)
        .outerjoin(
            ApplianceCertificate,
            ApplianceCertificate.id == DNSServerOptions.tls_certificate_id,
        )
    )
    if args.group_id:
        try:
            stmt = stmt.where(DNSServerOptions.group_id == uuid.UUID(args.group_id))
        except ValueError:
            return {"error": f"group_id is not a valid UUID: {args.group_id}"}

    groups: list[dict[str, Any]] = []
    for opts, group, cert_name, has_pem in (
        await db.execute(stmt.order_by(DNSServerGroup.name))
    ).all():
        cert_usable = bool(has_pem)
        listeners_effective = cert_usable and (opts.dot_enabled or opts.doh_enabled)
        groups.append(
            {
                "group_id": str(group.id),
                "group_name": group.name,
                "dot_enabled": opts.dot_enabled,
                "dot_port": opts.dot_port,
                "doh_enabled": opts.doh_enabled,
                "doh_port": opts.doh_port,
                "doh_path": opts.doh_path,
                "tls_certificate_name": cert_name,
                "tls_certificate_usable": cert_usable,
                # The honest answer to "is it actually serving?" — the agent
                # renderers skip a listener whose cert is missing rather than
                # emit a config the daemon would refuse to load.
                "listeners_effective": listeners_effective,
                "forward_transport": opts.forward_transport,
                "forward_tls_hostname": opts.forward_tls_hostname,
                "forward_tls_verify": opts.forward_tls_verify,
                "upstream_encrypted": opts.forward_transport == "tls",
            }
        )

    return {
        "groups": groups,
        "count": len(groups),
        "summary": {
            "groups_serving_encrypted": sum(1 for g in groups if g["listeners_effective"]),
            "groups_forwarding_encrypted": sum(1 for g in groups if g["upstream_encrypted"]),
            "groups_with_broken_listener": sum(
                1
                for g in groups
                if (g["dot_enabled"] or g["doh_enabled"]) and not g["tls_certificate_usable"]
            ),
        },
    }


class ListResolverPresetsArgs(BaseModel):
    """No arguments — the catalogue is small enough to return whole."""

    pass


@register_tool(
    name="list_resolver_presets",
    description=(
        "List the curated public upstream DNS resolvers SpatiumDDI ships "
        "presets for — Cloudflare, Google, Quad9 and friends — with each "
        "one's IPv4/IPv6 addresses, the DoT/DoH hostname its certificate "
        "presents, and what it filters by default. Use to answer 'what is "
        "Quad9's DoT hostname?', 'which upstream blocks malware?' or "
        "'what should I put in forward_tls_hostname for 1.1.1.1?'. The "
        "hostname matters: with DoT verification on, a wrong one fails "
        "closed and the group returns SERVFAIL for every query."
    ),
    args_model=ListResolverPresetsArgs,
    category="dns",
    # Read-only, and the contents are a static table of public addresses
    # shipped with the release — nothing install-specific, nothing secret.
    default_enabled=True,
    module="core.dns",
)
async def list_resolver_presets(
    db: AsyncSession, user: User, args: ListResolverPresetsArgs
) -> dict[str, Any]:
    from app.services.dns.resolver_presets import (  # noqa: PLC0415
        all_presets,
        catalog_version,
    )

    return {
        "version": catalog_version(),
        "presets": [
            {
                "id": p.id,
                "name": p.name,
                "provider": p.provider,
                "description": p.description,
                "ipv4": list(p.ipv4),
                "ipv6": list(p.ipv6),
                "tls_hostname": p.tls_hostname,
                "filtering": p.filtering,
                "homepage": p.homepage,
            }
            for p in all_presets()
        ],
        "note": (
            "One TLS hostname applies to a whole server group, so every "
            "forwarder in a group must present the same certificate name. "
            "A brand's filtering variants do NOT share one (1.1.1.1 is "
            "cloudflare-dns.com but 1.1.1.3 is family.cloudflare-dns.com), "
            "so mixing them needs one group per variant."
        ),
    }


# ── list_blocklist_templates ──────────────────────────────────────────


class ListBlocklistTemplatesArgs(BaseModel):
    """No arguments — the built-in set is small enough to return whole."""


@register_tool(
    name="list_blocklist_templates",
    description=(
        "List the built-in DNS blocklist templates and one-click "
        "profiles that ship with this release — the content-filtering "
        "presets (SafeSearch enforcement, Family filter). Templates "
        "carry per-provider groups showing which search engine each "
        "rewrites and to what; profiles name the feeds and templates "
        "they apply together. Use for 'how do I force SafeSearch?', "
        "'what does the family filter turn on?' or 'which engines "
        "does SafeSearch cover?'. Applying one is a separate action "
        "in the DNS > Blocklists screen."
    ),
    args_model=ListBlocklistTemplatesArgs,
    category="dns",
    # Read-only, and the payload is a static table shipped with the
    # release: rewrite targets published by each search provider, plus
    # the ids of catalog feeds. Nothing install-specific, nothing secret.
    default_enabled=True,
    module="core.dns",
)
async def list_blocklist_templates(
    db: AsyncSession, user: User, args: ListBlocklistTemplatesArgs
) -> dict[str, Any]:
    from app.services.dns.blocklist_templates import (  # noqa: PLC0415
        all_profiles,
        all_templates,
    )

    return {
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "groups": [
                    {
                        "id": g.id,
                        "name": g.name,
                        "target": g.target,
                        "domain_count": len(g.domains),
                        "enabled_by_default": g.default,
                        "note": g.note,
                    }
                    for g in t.groups
                ],
            }
            for t in all_templates()
        ],
        "profiles": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "source_ids": list(p.source_ids),
                "template_ids": list(p.template_ids),
                "note": p.note,
            }
            for p in all_profiles()
        ],
        "note": (
            "Applying a profile creates the blocklists but assigns them "
            "to nothing. Scope them to the views or server groups that "
            "serve the networks you want filtered — a list left "
            "unassigned filters nobody, and one assigned everywhere "
            "filters your servers too. RPZ rewrites are a BIND9 "
            "capability: Windows, PowerDNS and the cloud DNS drivers do "
            "not enforce them."
        ),
    }
