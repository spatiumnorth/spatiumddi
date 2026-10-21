"""Global search — every resource type the caller is allowed to see.

The matching, ranking and permission filtering live in
``app.services.search``; this module is the HTTP surface over it. The
service split exists because the ``global_search`` MCP tool used to carry
its own copy of the fan-out, and copies drift (issue #879).
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.api.deps import DB, CurrentUser
from app.api.token_binding import honours_token_binding
from app.services.search import execute, visible_providers
from app.services.search.schemas import SearchResponse, SearchResult, SearchTypeInfo

__all__ = ["SearchResponse", "SearchResult", "SearchTypeInfo", "router"]

router = APIRouter()


@router.get("/types", response_model=list[SearchTypeInfo])
@honours_token_binding
async def searchable_types(current_user: CurrentUser, db: DB) -> list[SearchTypeInfo]:
    """Types this caller may search, for building scope filters.

    Permission- and module-filtered, so the UI never offers a scope chip
    that can only ever come back empty.
    """
    return [
        SearchTypeInfo(type=p.type, label=p.label, group=p.group)
        for p in await visible_providers(db, current_user)
        if not p.also_emits
    ]


@router.get("", response_model=SearchResponse)
@honours_token_binding
async def global_search(
    current_user: CurrentUser,
    db: DB,
    q: str = Query(..., min_length=1, max_length=200, description="Search query"),
    types: str | None = Query(
        default=None,
        description=(
            "Comma-separated resource types to restrict the search to. "
            "See GET /search/types for the list this caller may use; "
            "unknown or forbidden entries are ignored."
        ),
    ),
    limit: int = Query(default=25, ge=1, le=100),
) -> SearchResponse:
    """Search across IPAM, DNS, DHCP, network and administration resources.

    Query interpretation:

    - Valid IP (``10.0.0.1``) → exact address match, the subnets and blocks
      containing it, DNS records pointing at it, reservations holding it.
    - CIDR (``10.0.0.0/24``) → subnets and blocks within that range.
    - MAC (any common separator style) → addresses and reservations.
    - Anything else → substring match over names, hostnames, FQDNs, record
      values, descriptions and searchable custom fields.

    Results are ranked by match quality (exact > prefix > substring) before
    the per-type limit is applied, then re-ranked across types, so an exact
    hit cannot be crowded out by weak matches from a type queried earlier.

    Every type is filtered against the caller's own ``read`` permission and
    the feature modules this install has enabled.
    """
    requested = {t.strip() for t in types.split(",") if t.strip()} if types else None
    return await execute(db, current_user, q, types=requested, limit=limit)
