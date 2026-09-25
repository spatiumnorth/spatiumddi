"""Searchable resource types for global search (issue #879).

Each type is one :class:`SearchProvider`: a query function plus the
metadata the engine needs to decide whether the *calling user* may see it.

Two gates, both server-side, both mandatory (non-negotiable #3):

* ``resource_types`` — the caller needs ``read`` on at least one of them.
  v1 had no gate at all, so an IPAM-only operator searching ``example.com``
  got back DNS zones and records that ``GET /api/v1/dns/zones`` would have
  refused them. Search was the widest read surface in the product and the
  only one that checked nothing.
* ``module`` — the feature-module id, when the type has one. A disabled
  module removes the surface from the sidebar and 404s its router; leaving
  its rows searchable would put back exactly what the operator turned off.

Adding a type means adding one entry to :data:`PROVIDERS`. The engine, the
scope chips, the MCP tool and the response's ``searched_types`` all read
from that list, so there is no second place to update.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Select, Text, cast, literal_column, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import Appliance
from app.models.auth import Group, User
from app.models.circuit import Circuit
from app.models.dhcp import DHCPScope, DHCPServer, DHCPStaticAssignment
from app.models.dns import DNSBlockList, DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.models.ipam import CustomFieldDefinition, IPAddress, IPBlock, IPSpace, Subnet
from app.models.network import NetworkDevice
from app.models.ownership import Site
from app.models.vlans import VLAN
from app.services.search.ranking import (
    EXACT,
    escape_like,
    like_pattern,
    pick_match,
    sql_rank,
    total_score,
)
from app.services.search.schemas import QueryShape, SearchResult

__all__ = ["PROVIDERS", "SearchProvider", "provider_for"]

SearchFn = Callable[[AsyncSession, QueryShape, int], Awaitable[list[SearchResult]]]

# Query kinds a provider can usefully answer (see ``QueryShape.kind``).
ALL_SHAPES = frozenset({"text", "ip", "cidr", "mac"})
TEXT_ONLY = frozenset({"text"})
# Types with an address-bearing column (a host, a value, an ip_address) —
# their plain text predicate is meaningful when the operator pastes an IP.
TEXT_AND_IP = frozenset({"text", "ip"})


@dataclass(frozen=True)
class SearchProvider:
    type: str
    label: str
    # Scope chip this type belongs to in the UI.
    group: str
    # Caller needs ``read`` on ANY of these RBAC resource types.
    resource_types: tuple[str, ...]
    fn: SearchFn
    # Feature-module id gating the type, when it has one.
    module: str | None = None
    # Superadmin-only regardless of RBAC — for surfaces whose own routers
    # are superadmin-gated rather than permission-gated (users).
    superadmin_only: bool = False
    # Extra types whose results this provider can also emit. The IPAM
    # custom-field pass is one query returning blocks, subnets and
    # addresses, so requesting any of the three has to run it.
    also_emits: tuple[str, ...] = field(default_factory=tuple)
    # Query kinds worth running this provider for.
    shapes: frozenset[str] = ALL_SHAPES


# ── shared query helpers ──────────────────────────────────────────────────


def _ranked(
    stmt: Select,
    rank: Any,
    limit: int,
    *,
    tiebreak: Any = None,
) -> Select:
    """Order by relevance before the limit is applied.

    The ``ORDER BY`` is the entire reason ranking lives in SQL: without it
    the database is free to return any ``limit`` rows that satisfy the
    predicate, and on a table where thousands of rows contain the substring
    the exact match is usually not among them.

    A stable secondary key keeps paging and test assertions deterministic
    when several rows share a bucket.

    ``rank`` may be a plain int for the branches where every matching row
    is by definition an exact hit (an ``inet`` equality, a normalised MAC).
    Those are selected as a constant and deliberately NOT ordered by:
    ``ORDER BY 100`` means "order by the hundredth output column" in SQL,
    not "order by the number 100", so emitting it would be an error rather
    than a no-op.
    """
    order: list[Any] = []
    if isinstance(rank, int):
        rank_col: Any = literal_column(str(rank))
    else:
        rank_col = rank
        order.append(rank.desc())
    if tiebreak is not None:
        order.append(tiebreak.asc())
    return stmt.add_columns(rank_col.label("rank")).order_by(*order).limit(limit)


def _mac_normalized_sql(table: str) -> str:
    """SQL that strips a ``macaddr`` column down to bare hex.

    A MAC is written four different ways in the wild and stored
    canonically, so both sides of the comparison are normalised before
    matching — otherwise ``aa-bb-cc-dd-ee-ff`` finds nothing.

    On ``ip_address`` this expression is also the definition of the
    ``ix_trgm_ip_address_mac_normalized`` index (migration
    ``f4b91d38a70c``). PostgreSQL matches expression indexes by comparing
    the parsed expression, so any divergence between the two — a different
    cast spelling, a reordered REPLACE — silently costs the index rather
    than failing. That is exactly why it is generated from one function.

    No ``ESCAPE`` clause: backslash is PostgreSQL's default LIKE escape,
    which is what :func:`~app.services.search.ranking.escape_like` emits.
    Spelling it out in an f-string here would need the backslash doubled
    for Python and then again for the SQL literal, and getting that wrong
    is a runtime error rather than a lint failure.
    """
    return (
        f"REPLACE(REPLACE(REPLACE(CAST({table}.mac_address AS text), ':', ''),"
        " '-', ''), '.', '')"
    )


IP_MAC_NORMALIZED_SQL = _mac_normalized_sql("ip_address")


def _txt(col: Any) -> Any:
    """Cast a column to text so the pattern operators apply to it.

    Several columns that the ORM annotates ``Mapped[str]`` are ``inet`` or
    ``macaddr`` in PostgreSQL — ``DHCPStaticAssignment.ip_address`` and
    ``NetworkDevice.ip_address`` among them. ``ILIKE`` and ``lower()`` have
    no overload for those types, so matching one without this cast is not a
    silently-wrong result, it is a 500 on every search that touches the
    provider.
    """
    return cast(col, Text)


def _text_clauses(q: str, *columns: Any) -> Any:
    pattern = like_pattern(q)
    return or_(*[col.ilike(pattern, escape="\\") for col in columns])


def _annotate(result: SearchResult, quality: int, matched: str | None) -> SearchResult:
    result.matched_field = result.matched_field or matched
    result.score = total_score(quality, result.type)
    return result


async def _subnet_context(db: AsyncSession, subnet_ids: set) -> dict:
    """Load the subnet → space breadcrumb for a set of subnet ids.

    Deliberately a **second query** rather than a join on the search itself.
    Joining the parents in looks harmless — they are tiny tables — but the
    global soft-delete filter adds ``subnet.deleted_at IS NULL`` and
    ``ip_space.deleted_at IS NULL`` to the same statement, and the planner
    responds by driving the join from ``subnet`` (a couple of dozen rows)
    and re-running the ``ip_address`` bitmap scan once per subnet. Measured
    on 500k addresses: 9 ms as a standalone scan, 188 ms as a nested loop
    inside that join. Splitting it keeps both queries on their fast plan.

    Rows whose subnet is missing from the result are dropped by the
    callers. ``IPAddress`` carries no ``SoftDeleteMixin``, so an address
    under a soft-deleted subnet is only hidden by its parent being hidden —
    which the join used to do for us and this query still does, because the
    soft-delete filter applies here too.
    """
    if not subnet_ids:
        return {}
    rows = await db.execute(
        select(Subnet, IPSpace)
        .join(IPSpace, Subnet.space_id == IPSpace.id)
        .where(Subnet.id.in_(subnet_ids))
    )
    return {sn.id: (sn, sp) for sn, sp in rows.all()}


# ── IPAM ──────────────────────────────────────────────────────────────────


async def search_addresses(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    # Single-table match; the subnet/space breadcrumb is a second query.
    # See :func:`_subnet_context` for why joining it here is a 20x slowdown.
    stmt = select(IPAddress)

    if s.is_ip:
        stmt = stmt.where(text("CAST(ip_address.address AS inet) = CAST(:q AS inet)")).params(
            q=s.raw
        )
        rank: Any = EXACT
    elif s.is_mac:
        stmt = stmt.where(text(f"{IP_MAC_NORMALIZED_SQL} ILIKE :norm")).params(
            norm=f"%{escape_like(s.mac_normalized)}%"
        )
        rank = EXACT
    else:
        pattern = like_pattern(s.raw)
        stmt = stmt.where(
            or_(
                IPAddress.hostname.ilike(pattern, escape="\\"),
                IPAddress.description.ilike(pattern, escape="\\"),
                # Partial MACs — an OUI prefix, "aa:bb:cc" — don't parse as
                # a MAC, so they land here. Normalising both sides makes the
                # match separator-insensitive and, just as importantly, is
                # the one spelling the trigram index covers. The previous
                # raw ``CAST(mac_address AS text) ILIKE`` branch could use
                # no index, and because it sat in an OR beside the two
                # indexed predicates it forced the whole query to a
                # sequential scan: a single-hostname lookup over 500k rows
                # took 489 ms with hostname AND description both indexed,
                # because this third branch made them unusable.
                text(f"{IP_MAC_NORMALIZED_SQL} ILIKE :mac_norm").bindparams(
                    mac_norm=f"%{escape_like(s.mac_normalized)}%"
                ),
            )
        )
        rank = sql_rank(s.raw, IPAddress.hostname, IPAddress.description)

    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=IPAddress.address))).all()
    context = await _subnet_context(db, {ip.subnet_id for ip, _ in rows})

    out: list[SearchResult] = []
    for ip, row_rank in rows:
        parent = context.get(ip.subnet_id)
        if parent is None:
            # Subnet is soft-deleted (or vanished between the two queries).
            # The old single-statement join dropped these implicitly; do the
            # same rather than emit a result with no breadcrumb.
            continue
        subnet, space = parent
        quality, matched = pick_match(
            s.raw,
            [
                ("hostname", ip.hostname),
                ("mac_address", str(ip.mac_address) if ip.mac_address else None),
                ("description", ip.description),
            ],
        )
        if s.is_ip or s.is_mac:
            quality = int(row_rank)
            matched = "address" if s.is_ip else "mac_address"
        out.append(
            _annotate(
                SearchResult(
                    type="ip_address",
                    id=str(ip.id),
                    display=str(ip.address),
                    name=ip.hostname,
                    status=ip.status,
                    description=ip.description or None,
                    hostname=ip.hostname,
                    mac_address=str(ip.mac_address) if ip.mac_address else None,
                    subnet_id=str(ip.subnet_id),
                    subnet_network=str(subnet.network),
                    block_id=str(subnet.block_id) if subnet.block_id else None,
                    space_id=str(space.id),
                    space_name=space.name,
                ),
                quality,
                matched,
            )
        )
    return out


async def search_subnets(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = select(Subnet, IPSpace).join(IPSpace, Subnet.space_id == IPSpace.id)

    if s.is_cidr:
        stmt = stmt.where(text("CAST(subnet.network AS cidr) <<= CAST(:q AS cidr)").params(q=s.raw))
        rank: Any = EXACT
    elif s.is_ip:
        stmt = stmt.where(text("CAST(subnet.network AS cidr) >> CAST(:q AS inet)").params(q=s.raw))
        rank = EXACT
    else:
        stmt = stmt.where(_text_clauses(s.raw, Subnet.name, Subnet.description))
        rank = sql_rank(s.raw, Subnet.name, Subnet.description)

    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=Subnet.network))).all()

    out: list[SearchResult] = []
    for subnet, space, row_rank in rows:
        quality, matched = pick_match(
            s.raw, [("name", subnet.name), ("description", subnet.description)]
        )
        if s.is_address_like:
            quality, matched = int(row_rank), "network"
        out.append(
            _annotate(
                SearchResult(
                    type="subnet",
                    id=str(subnet.id),
                    display=str(subnet.network),
                    name=subnet.name or None,
                    status=subnet.status,
                    description=subnet.description or None,
                    subnet_id=str(subnet.id),
                    subnet_network=str(subnet.network),
                    block_id=str(subnet.block_id) if subnet.block_id else None,
                    space_id=str(space.id),
                    space_name=space.name,
                ),
                quality,
                matched,
            )
        )
    return out


async def search_blocks(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = select(IPBlock, IPSpace).join(IPSpace, IPBlock.space_id == IPSpace.id)

    if s.is_cidr:
        stmt = stmt.where(
            text("CAST(ip_block.network AS cidr) <<= CAST(:q AS cidr)").params(q=s.raw)
        )
        rank: Any = EXACT
    elif s.is_ip:
        stmt = stmt.where(
            text("CAST(ip_block.network AS cidr) >> CAST(:q AS inet)").params(q=s.raw)
        )
        rank = EXACT
    else:
        stmt = stmt.where(_text_clauses(s.raw, IPBlock.name, IPBlock.description))
        rank = sql_rank(s.raw, IPBlock.name, IPBlock.description)

    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=IPBlock.network))).all()

    out: list[SearchResult] = []
    for block, space, row_rank in rows:
        quality, matched = pick_match(
            s.raw, [("name", block.name), ("description", block.description)]
        )
        if s.is_address_like:
            quality, matched = int(row_rank), "network"
        out.append(
            _annotate(
                SearchResult(
                    type="block",
                    id=str(block.id),
                    display=str(block.network),
                    name=block.name or None,
                    description=block.description or None,
                    block_id=str(block.id),
                    space_id=str(space.id),
                    space_name=space.name,
                ),
                quality,
                matched,
            )
        )
    return out


async def search_spaces(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = select(IPSpace).where(_text_clauses(s.raw, IPSpace.name, IPSpace.description))
    rank = sql_rank(s.raw, IPSpace.name, IPSpace.description)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=IPSpace.name))).all()

    out: list[SearchResult] = []
    for space, _rank in rows:
        quality, matched = pick_match(
            s.raw, [("name", space.name), ("description", space.description)]
        )
        out.append(
            _annotate(
                SearchResult(
                    type="space",
                    id=str(space.id),
                    display=space.name,
                    name=space.name,
                    description=space.description or None,
                    space_id=str(space.id),
                    space_name=space.name,
                ),
                quality,
                matched,
            )
        )
    return out


# ── DNS ───────────────────────────────────────────────────────────────────


async def search_dns_groups(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = select(DNSServerGroup).where(
        _text_clauses(s.raw, DNSServerGroup.name, DNSServerGroup.description)
    )
    rank = sql_rank(s.raw, DNSServerGroup.name, DNSServerGroup.description)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=DNSServerGroup.name))).all()

    return [
        _annotate(
            SearchResult(
                type="dns_group",
                id=str(g.id),
                display=g.name,
                name=g.name,
                description=g.description or None,
                dns_group_id=str(g.id),
                dns_group_name=g.name,
            ),
            *pick_match(s.raw, [("name", g.name), ("description", g.description)]),
        )
        for g, _rank in rows
    ]


async def search_dns_zones(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = (
        select(DNSZone, DNSServerGroup)
        .join(DNSServerGroup, DNSZone.group_id == DNSServerGroup.id)
        .where(DNSZone.name.ilike(like_pattern(s.raw), escape="\\"))
    )
    rank = sql_rank(s.raw, DNSZone.name)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=DNSZone.name))).all()

    return [
        _annotate(
            SearchResult(
                type="dns_zone",
                id=str(z.id),
                display=z.name,
                name=z.name,
                status=z.zone_type,
                dns_group_id=str(g.id),
                dns_group_name=g.name,
                dns_zone_id=str(z.id),
                dns_zone_name=z.name,
            ),
            *pick_match(s.raw, [("name", z.name)]),
        )
        for z, g, _rank in rows
    ]


async def search_dns_records(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    # Single-table match, breadcrumb second — ``dns_record`` is the other
    # table that reaches millions of rows, and the same soft-delete-driven
    # nested loop that cost ``ip_address`` 20x applies to its zone join.
    stmt = select(DNSRecord).where(_text_clauses(s.raw, DNSRecord.fqdn, DNSRecord.value))
    rank = sql_rank(s.raw, DNSRecord.fqdn, DNSRecord.value)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=DNSRecord.fqdn))).all()
    if not rows:
        return []

    zone_rows = await db.execute(
        select(DNSZone, DNSServerGroup)
        .join(DNSServerGroup, DNSZone.group_id == DNSServerGroup.id)
        .where(DNSZone.id.in_({r.zone_id for r, _ in rows}))
    )
    zones = {z.id: (z, g) for z, g in zone_rows.all()}

    out: list[SearchResult] = []
    for r, _rank in rows:
        parent = zones.get(r.zone_id)
        if parent is None:
            continue
        z, g = parent
        out.append(
            _annotate(
                SearchResult(
                    type="dns_record",
                    id=str(r.id),
                    display=r.fqdn,
                    name=r.fqdn,
                    status=r.record_type,
                    dns_group_id=str(g.id),
                    dns_group_name=g.name,
                    dns_zone_id=str(z.id),
                    dns_zone_name=z.name,
                    dns_record_type=r.record_type,
                    dns_record_value=r.value,
                ),
                *pick_match(s.raw, [("fqdn", r.fqdn), ("value", r.value)]),
            )
        )
    return out


async def search_dns_servers(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = (
        select(DNSServer, DNSServerGroup)
        .join(DNSServerGroup, DNSServer.group_id == DNSServerGroup.id)
        .where(_text_clauses(s.raw, DNSServer.name, DNSServer.host, DNSServer.notes))
    )
    rank = sql_rank(s.raw, DNSServer.name, DNSServer.host, DNSServer.notes)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=DNSServer.name))).all()

    return [
        _annotate(
            SearchResult(
                type="dns_server",
                id=str(srv.id),
                display=srv.name,
                name=srv.name,
                status=srv.status,
                description=srv.notes or None,
                context=f"{g.name} · {srv.driver} · {srv.host}",
                dns_group_id=str(g.id),
                dns_group_name=g.name,
                route="/dns",
            ),
            *pick_match(s.raw, [("name", srv.name), ("host", srv.host), ("notes", srv.notes)]),
        )
        for srv, g, _rank in rows
    ]


async def search_dns_views(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = (
        select(DNSView, DNSServerGroup)
        .join(DNSServerGroup, DNSView.group_id == DNSServerGroup.id)
        .where(_text_clauses(s.raw, DNSView.name, DNSView.description))
    )
    rank = sql_rank(s.raw, DNSView.name, DNSView.description)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=DNSView.name))).all()

    return [
        _annotate(
            SearchResult(
                type="dns_view",
                id=str(v.id),
                display=v.name,
                name=v.name,
                description=v.description or None,
                context=f"View in {g.name}",
                dns_group_id=str(g.id),
                dns_group_name=g.name,
                route="/dns",
            ),
            *pick_match(s.raw, [("name", v.name), ("description", v.description)]),
        )
        for v, g, _rank in rows
    ]


async def search_dns_blocklists(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = select(DNSBlockList).where(
        _text_clauses(s.raw, DNSBlockList.name, DNSBlockList.description, DNSBlockList.category)
    )
    rank = sql_rank(s.raw, DNSBlockList.name, DNSBlockList.description, DNSBlockList.category)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=DNSBlockList.name))).all()

    return [
        _annotate(
            SearchResult(
                type="dns_blocklist",
                id=str(bl.id),
                display=bl.name,
                name=bl.name,
                status="enabled" if bl.enabled else "disabled",
                description=bl.description or None,
                context=f"{bl.category} · {bl.entry_count} entries",
                route="/admin/dns-blocklists",
            ),
            *pick_match(
                s.raw,
                [
                    ("name", bl.name),
                    ("category", bl.category),
                    ("description", bl.description),
                ],
            ),
        )
        for bl, _rank in rows
    ]


# ── DHCP ──────────────────────────────────────────────────────────────────


async def search_dhcp_scopes(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = (
        select(DHCPScope, Subnet)
        .join(Subnet, DHCPScope.subnet_id == Subnet.id)
        .where(_text_clauses(s.raw, DHCPScope.name, DHCPScope.description))
    )
    rank = sql_rank(s.raw, DHCPScope.name, DHCPScope.description)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=DHCPScope.name))).all()

    return [
        _annotate(
            SearchResult(
                type="dhcp_scope",
                id=str(sc.id),
                display=sc.name,
                name=sc.name,
                status="active" if sc.is_active else "inactive",
                description=sc.description or None,
                context=str(subnet.network),
                subnet_id=str(subnet.id),
                subnet_network=str(subnet.network),
                route=f"/dhcp?group={sc.group_id}",
            ),
            *pick_match(s.raw, [("name", sc.name), ("description", sc.description)]),
        )
        for sc, subnet, _rank in rows
    ]


async def search_dhcp_reservations(
    db: AsyncSession, s: QueryShape, limit: int
) -> list[SearchResult]:
    stmt = select(DHCPStaticAssignment, DHCPScope).join(
        DHCPScope, DHCPStaticAssignment.scope_id == DHCPScope.id
    )

    if s.is_mac:
        # ``macaddr`` renders canonically as ``aa:bb:cc:dd:ee:ff``, so the
        # separators are stripped from both sides and the query is matched
        # against the normalised form — a dashed or Cisco-dotted query finds
        # the same row.
        stmt = stmt.where(
            text(f"{_mac_normalized_sql('dhcp_static_assignment')} ILIKE :norm").params(
                norm=f"%{escape_like(s.mac_normalized)}%"
            )
        )
        rank: Any = EXACT
    else:
        cols = (
            DHCPStaticAssignment.hostname,
            _txt(DHCPStaticAssignment.ip_address),
            _txt(DHCPStaticAssignment.mac_address),
            DHCPStaticAssignment.description,
        )
        stmt = stmt.where(_text_clauses(s.raw, *cols))
        rank = sql_rank(s.raw, *cols)

    rows = (
        await db.execute(_ranked(stmt, rank, limit, tiebreak=DHCPStaticAssignment.ip_address))
    ).all()

    out: list[SearchResult] = []
    for res, scope, row_rank in rows:
        quality, matched = pick_match(
            s.raw,
            [
                ("hostname", res.hostname),
                ("ip_address", str(res.ip_address) if res.ip_address else None),
                ("mac_address", str(res.mac_address) if res.mac_address else None),
                ("description", res.description),
            ],
        )
        if s.is_mac:
            quality, matched = int(row_rank), "mac_address"
        out.append(
            _annotate(
                SearchResult(
                    type="dhcp_reservation",
                    id=str(res.id),
                    display=str(res.ip_address),
                    name=res.hostname or None,
                    description=res.description or None,
                    hostname=res.hostname or None,
                    mac_address=str(res.mac_address) if res.mac_address else None,
                    context=f"Reserved in {scope.name}",
                    route=f"/dhcp?group={scope.group_id}",
                ),
                quality,
                matched,
            )
        )
    return out


async def search_dhcp_servers(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    cols = (DHCPServer.name, DHCPServer.description, DHCPServer.host)
    stmt = select(DHCPServer).where(_text_clauses(s.raw, *cols))
    rank = sql_rank(s.raw, *cols)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=DHCPServer.name))).all()

    return [
        _annotate(
            SearchResult(
                type="dhcp_server",
                id=str(srv.id),
                display=srv.name,
                name=srv.name,
                status=srv.status,
                description=srv.description or None,
                context=f"{srv.driver} · {srv.host}",
                route=f"/dhcp?server={srv.id}",
            ),
            *pick_match(
                s.raw,
                [("name", srv.name), ("host", srv.host), ("description", srv.description)],
            ),
        )
        for srv, _rank in rows
    ]


# ── Network ───────────────────────────────────────────────────────────────


async def search_vlans(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    clauses: list[Any] = [
        VLAN.name.ilike(like_pattern(s.raw), escape="\\"),
        VLAN.description.ilike(like_pattern(s.raw), escape="\\"),
    ]
    # A bare number is almost always a VLAN id, not a name fragment.
    if s.raw.isdigit():
        try:
            clauses.append(VLAN.vlan_id == int(s.raw))
        except ValueError:
            # ``str.isdigit`` is True for characters ``int()`` rejects —
            # superscripts like "²", and other scripts' numerals. The query
            # simply isn't a VLAN id, so fall through to the name and
            # description clauses already in the list rather than failing
            # the whole search on an unusual keystroke.
            pass

    stmt = select(VLAN).where(or_(*clauses))
    # ``vlan_id`` has to be in the SQL rank, not only in the Python fix-up
    # below: the id match is an equality on an integer column, so without it
    # here the exact row scores 0 and ``ORDER BY rank DESC … LIMIT`` drops it
    # before any Python ever sees it — the precise failure this module's
    # SQL-side ranking exists to prevent.
    rank = sql_rank(s.raw, _txt(VLAN.vlan_id), VLAN.name, VLAN.description)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=VLAN.vlan_id))).all()

    out: list[SearchResult] = []
    for vlan, _rank in rows:
        quality, matched = pick_match(
            s.raw,
            [
                ("vlan_id", str(vlan.vlan_id)),
                ("name", vlan.name),
                ("description", vlan.description),
            ],
        )
        out.append(
            _annotate(
                SearchResult(
                    type="vlan",
                    id=str(vlan.id),
                    display=f"VLAN {vlan.vlan_id}",
                    name=vlan.name or None,
                    description=vlan.description or None,
                    route="/network/vlans",
                ),
                quality,
                matched,
            )
        )
    return out


async def search_devices(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    cols = (
        NetworkDevice.name,
        NetworkDevice.hostname,
        _txt(NetworkDevice.ip_address),
        NetworkDevice.vendor,
    )
    stmt = select(NetworkDevice).where(_text_clauses(s.raw, *cols))
    rank = sql_rank(s.raw, *cols)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=NetworkDevice.name))).all()

    return [
        _annotate(
            SearchResult(
                type="device",
                id=str(d.id),
                display=d.name or d.hostname or str(d.ip_address),
                name=d.name or None,
                status=d.device_type or None,
                hostname=d.hostname or None,
                context=" · ".join(x for x in (d.vendor, str(d.ip_address)) if x),
                route=f"/network/devices/{d.id}",
            ),
            *pick_match(
                s.raw,
                [
                    ("name", d.name),
                    ("hostname", d.hostname),
                    ("ip_address", str(d.ip_address) if d.ip_address else None),
                    ("vendor", d.vendor),
                ],
            ),
        )
        for d, _rank in rows
    ]


async def search_sites(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    cols = (Site.name, Site.code, Site.notes)
    stmt = select(Site).where(_text_clauses(s.raw, *cols))
    rank = sql_rank(s.raw, *cols)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=Site.name))).all()

    return [
        _annotate(
            SearchResult(
                type="site",
                id=str(site.id),
                display=site.name,
                name=site.name,
                status=site.kind or None,
                description=site.notes or None,
                context=" · ".join(x for x in (site.code, site.region) if x) or None,
                route="/network/sites",
            ),
            *pick_match(s.raw, [("name", site.name), ("code", site.code), ("notes", site.notes)]),
        )
        for site, _rank in rows
    ]


async def search_circuits(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    cols = (Circuit.name, Circuit.ckt_id, Circuit.notes)
    stmt = select(Circuit).where(_text_clauses(s.raw, *cols))
    rank = sql_rank(s.raw, *cols)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=Circuit.name))).all()

    return [
        _annotate(
            SearchResult(
                type="circuit",
                id=str(c.id),
                display=c.name,
                name=c.name,
                status=c.status or None,
                description=c.notes or None,
                context=" · ".join(x for x in (c.ckt_id, c.transport_class) if x) or None,
                route="/network/circuits",
            ),
            *pick_match(s.raw, [("name", c.name), ("ckt_id", c.ckt_id), ("notes", c.notes)]),
        )
        for c, _rank in rows
    ]


# ── Administration ────────────────────────────────────────────────────────


async def search_users(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    cols = (User.username, User.email, User.display_name)
    stmt = select(User).where(_text_clauses(s.raw, *cols))
    rank = sql_rank(s.raw, *cols)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=User.username))).all()

    return [
        _annotate(
            SearchResult(
                type="user",
                id=str(u.id),
                display=u.username,
                name=u.display_name or None,
                status="active" if u.is_active else "disabled",
                context=" · ".join(x for x in (u.email, u.auth_source) if x) or None,
                route="/admin/users",
            ),
            *pick_match(
                s.raw,
                [
                    ("username", u.username),
                    ("display_name", u.display_name),
                    ("email", u.email),
                ],
            ),
        )
        for u, _rank in rows
    ]


async def search_groups(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    cols = (Group.name, Group.description)
    stmt = select(Group).where(_text_clauses(s.raw, *cols))
    rank = sql_rank(s.raw, *cols)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=Group.name))).all()

    return [
        _annotate(
            SearchResult(
                type="group",
                id=str(g.id),
                display=g.name,
                name=g.name,
                description=g.description or None,
                context=g.auth_source or None,
                route="/admin/groups",
            ),
            *pick_match(s.raw, [("name", g.name), ("description", g.description)]),
        )
        for g, _rank in rows
    ]


async def search_appliances(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    stmt = select(Appliance).where(_text_clauses(s.raw, Appliance.hostname))
    rank = sql_rank(s.raw, Appliance.hostname)
    rows = (await db.execute(_ranked(stmt, rank, limit, tiebreak=Appliance.hostname))).all()

    return [
        _annotate(
            SearchResult(
                type="appliance",
                id=str(a.id),
                display=a.hostname,
                name=a.hostname,
                status=a.state,
                hostname=a.hostname,
                context=a.appliance_variant or None,
                route="/appliance",
            ),
            *pick_match(s.raw, [("hostname", a.hostname)]),
        )
        for a, _rank in rows
    ]


# ── IPAM custom fields ────────────────────────────────────────────────────


async def _searchable_field_names(db: AsyncSession, resource_type: str) -> list[str]:
    result = await db.execute(
        select(CustomFieldDefinition.name).where(
            CustomFieldDefinition.resource_type == resource_type,
            CustomFieldDefinition.is_searchable.is_(True),
        )
    )
    return [row[0] for row in result.all()]


def _custom_field_hit(q: str, values: dict | None, names: list[str]) -> tuple[int, str | None]:
    """Best (quality, ``custom_field:name=value``) over the searchable fields.

    Delegates the scoring to :func:`pick_match` rather than re-deriving the
    ladder. An earlier version inlined the bucket values, which meant
    retuning them in ``ranking.py`` silently desynced custom-field scores
    from every other kind of hit.
    """
    return pick_match(
        q,
        [
            (f"custom_field:{name}={values[name]}", str(values[name]))
            for name in names
            if (values or {}).get(name) is not None
        ],
    )


async def search_custom_fields(db: AsyncSession, s: QueryShape, limit: int) -> list[SearchResult]:
    """Substring-match searchable custom-field values on blocks/subnets/IPs.

    One provider rather than three because the ``custom_field_definition``
    lookup and the JSONB predicate shape are shared; the emitted rows still
    carry their own ``type`` and are filtered by the engine against what the
    caller asked for and may see.
    """
    out: list[SearchResult] = []

    def jsonb_cols(model: Any, names: list[str]) -> list[Any]:
        """``custom_fields ->> 'name'`` as real column expressions.

        Built through the ORM rather than as ``text()`` fragments so they
        can also feed :func:`sql_rank` — without an ``ORDER BY``, these
        three queries had the same "database returns any N matching rows"
        flaw this module exists to fix, and an exact custom-field hit among
        thousands of substring hits was routinely never fetched.
        """
        return [model.custom_fields[name].astext for name in names]

    block_fields = await _searchable_field_names(db, "ip_block")
    if block_fields:
        stmt = (
            select(IPBlock, IPSpace)
            .join(IPSpace, IPBlock.space_id == IPSpace.id)
            .where(
                or_(
                    *[
                        c.ilike(like_pattern(s.raw), escape="\\")
                        for c in jsonb_cols(IPBlock, block_fields)
                    ]
                )
            )
        )
        ranked = _ranked(
            stmt,
            sql_rank(s.raw, *jsonb_cols(IPBlock, block_fields)),
            limit,
            tiebreak=IPBlock.network,
        )
        for block, space, _rank in (await db.execute(ranked)).all():
            quality, label = _custom_field_hit(s.raw, block.custom_fields, block_fields)
            out.append(
                _annotate(
                    SearchResult(
                        type="block",
                        id=str(block.id),
                        display=str(block.network),
                        name=block.name or None,
                        description=block.description or None,
                        block_id=str(block.id),
                        space_id=str(space.id),
                        space_name=space.name,
                        matched_field=label or "custom_field",
                    ),
                    quality,
                    label,
                )
            )

    subnet_fields = await _searchable_field_names(db, "subnet")
    if subnet_fields:
        stmt = (
            select(Subnet, IPSpace)
            .join(IPSpace, Subnet.space_id == IPSpace.id)
            .where(
                or_(
                    *[
                        c.ilike(like_pattern(s.raw), escape="\\")
                        for c in jsonb_cols(Subnet, subnet_fields)
                    ]
                )
            )
        )
        ranked = _ranked(
            stmt,
            sql_rank(s.raw, *jsonb_cols(Subnet, subnet_fields)),
            limit,
            tiebreak=Subnet.network,
        )
        for subnet, space, _rank in (await db.execute(ranked)).all():
            quality, label = _custom_field_hit(s.raw, subnet.custom_fields, subnet_fields)
            out.append(
                _annotate(
                    SearchResult(
                        type="subnet",
                        id=str(subnet.id),
                        display=str(subnet.network),
                        name=subnet.name or None,
                        status=subnet.status,
                        description=subnet.description or None,
                        subnet_id=str(subnet.id),
                        subnet_network=str(subnet.network),
                        block_id=str(subnet.block_id) if subnet.block_id else None,
                        space_id=str(space.id),
                        space_name=space.name,
                        matched_field=label or "custom_field",
                    ),
                    quality,
                    label,
                )
            )

    addr_fields = await _searchable_field_names(db, "ip_address")
    if addr_fields:
        stmt = select(IPAddress).where(
            or_(
                *[
                    c.ilike(like_pattern(s.raw), escape="\\")
                    for c in jsonb_cols(IPAddress, addr_fields)
                ]
            )
        )
        stmt = _ranked(
            stmt,
            sql_rank(s.raw, *jsonb_cols(IPAddress, addr_fields)),
            limit,
            tiebreak=IPAddress.address,
        )
        addr_rows = [row[0] for row in (await db.execute(stmt)).all()]
        ctx = await _subnet_context(db, {ip.subnet_id for ip in addr_rows})
        for ip in addr_rows:
            parent = ctx.get(ip.subnet_id)
            if parent is None:
                continue
            subnet, space = parent
            quality, label = _custom_field_hit(s.raw, ip.custom_fields, addr_fields)
            out.append(
                _annotate(
                    SearchResult(
                        type="ip_address",
                        id=str(ip.id),
                        display=str(ip.address),
                        name=ip.hostname,
                        status=ip.status,
                        description=ip.description or None,
                        hostname=ip.hostname,
                        mac_address=str(ip.mac_address) if ip.mac_address else None,
                        subnet_id=str(ip.subnet_id),
                        subnet_network=str(subnet.network),
                        block_id=str(subnet.block_id) if subnet.block_id else None,
                        space_id=str(space.id),
                        space_name=space.name,
                        matched_field=label or "custom_field",
                    ),
                    quality,
                    label,
                )
            )

    return out


# ── registry ──────────────────────────────────────────────────────────────

PROVIDERS: tuple[SearchProvider, ...] = (
    # ── IPAM ──
    SearchProvider(
        type="ip_address",
        label="IP Address",
        group="ipam",
        resource_types=("ip_address",),
        fn=search_addresses,
        # Not "cidr": an address row can't equal a prefix, and the fallback
        # text branch would substring-match "10.0.0.0/24" against hostnames.
        shapes=frozenset({"text", "ip", "mac"}),
    ),
    SearchProvider(
        type="subnet",
        label="Subnet",
        group="ipam",
        resource_types=("subnet",),
        fn=search_subnets,
        shapes=frozenset({"text", "ip", "cidr"}),
    ),
    SearchProvider(
        type="block",
        label="Block",
        group="ipam",
        resource_types=("ip_block",),
        fn=search_blocks,
        shapes=frozenset({"text", "ip", "cidr"}),
    ),
    SearchProvider(
        type="space",
        label="Space",
        group="ipam",
        resource_types=("ip_space",),
        fn=search_spaces,
        shapes=TEXT_ONLY,
    ),
    SearchProvider(
        type="custom_field",
        label="Custom Field",
        group="ipam",
        resource_types=("ip_address", "subnet", "ip_block"),
        fn=search_custom_fields,
        also_emits=("ip_address", "subnet", "block"),
        # A custom field can legitimately hold an address ("gateway",
        # "management_ip"), so an IP query is worth running here.
        shapes=TEXT_AND_IP,
    ),
    # ── DNS ──
    SearchProvider(
        type="dns_group",
        label="DNS Group",
        group="dns",
        resource_types=("dns_group",),
        fn=search_dns_groups,
        shapes=TEXT_ONLY,
        module="core.dns",
    ),
    SearchProvider(
        type="dns_zone",
        label="DNS Zone",
        group="dns",
        resource_types=("dns_zone",),
        fn=search_dns_zones,
        # Reverse zones are named after addresses, but as ``…in-addr.arpa``
        # rather than dotted-quad, so an IP query never matches one.
        shapes=TEXT_ONLY,
        module="core.dns",
    ),
    SearchProvider(
        type="dns_record",
        label="DNS Record",
        group="dns",
        resource_types=("dns_record",),
        fn=search_dns_records,
        # An A record's value IS an address — "which name points here?" is
        # one of the most common lookups in the product.
        shapes=TEXT_AND_IP,
        module="core.dns",
    ),
    SearchProvider(
        type="dns_server",
        label="DNS Server",
        group="dns",
        resource_types=("dns_group",),
        fn=search_dns_servers,
        shapes=TEXT_AND_IP,
    ),
    SearchProvider(
        type="dns_view",
        label="DNS View",
        group="dns",
        resource_types=("dns_group",),
        fn=search_dns_views,
        shapes=TEXT_ONLY,
        module="core.dns",
    ),
    SearchProvider(
        type="dns_blocklist",
        label="Blocklist",
        group="dns",
        resource_types=("dns_blocklist",),
        fn=search_dns_blocklists,
        shapes=TEXT_ONLY,
        module="core.dns",
    ),
    # ── DHCP ──
    SearchProvider(
        type="dhcp_scope",
        label="DHCP Scope",
        group="dhcp",
        resource_types=("dhcp_scope",),
        fn=search_dhcp_scopes,
        shapes=TEXT_ONLY,
        module="core.dhcp",
    ),
    SearchProvider(
        type="dhcp_reservation",
        label="Reservation",
        group="dhcp",
        resource_types=("dhcp_static",),
        fn=search_dhcp_reservations,
        # The reservation table is where a MAC lookup usually lands.
        shapes=frozenset({"text", "ip", "mac"}),
        module="core.dhcp",
    ),
    SearchProvider(
        type="dhcp_server",
        label="DHCP Server",
        group="dhcp",
        resource_types=("dhcp_server",),
        fn=search_dhcp_servers,
        shapes=TEXT_AND_IP,
        module="core.dhcp",
    ),
    # ── Network ──
    SearchProvider(
        type="vlan",
        label="VLAN",
        group="network",
        resource_types=("vlan",),
        fn=search_vlans,
        module="network.vlan",
        shapes=TEXT_ONLY,
    ),
    SearchProvider(
        type="device",
        label="Device",
        group="network",
        resource_types=("manage_network_devices",),
        fn=search_devices,
        module="network.device",
        shapes=TEXT_AND_IP,
    ),
    SearchProvider(
        type="site",
        label="Site",
        group="network",
        resource_types=("site",),
        fn=search_sites,
        module="network.site",
        shapes=TEXT_ONLY,
    ),
    SearchProvider(
        type="circuit",
        label="Circuit",
        group="network",
        resource_types=("circuit",),
        fn=search_circuits,
        module="network.circuit",
        shapes=TEXT_ONLY,
    ),
    # ── Administration ──
    SearchProvider(
        type="user",
        label="User",
        group="admin",
        resource_types=("user",),
        fn=search_users,
        # /api/v1/users is superadmin-only, not permission-gated, so the
        # search view of it has to be too — otherwise search becomes a
        # username and email directory for anyone who can log in.
        superadmin_only=True,
        shapes=TEXT_ONLY,
    ),
    SearchProvider(
        type="group",
        label="Group",
        group="admin",
        resource_types=("group",),
        fn=search_groups,
        shapes=TEXT_ONLY,
    ),
    SearchProvider(
        type="appliance",
        label="Appliance",
        group="admin",
        resource_types=("appliance",),
        fn=search_appliances,
        shapes=TEXT_ONLY,
    ),
)

_BY_TYPE = {p.type: p for p in PROVIDERS}


def provider_for(type_name: str) -> SearchProvider | None:
    return _BY_TYPE.get(type_name)
