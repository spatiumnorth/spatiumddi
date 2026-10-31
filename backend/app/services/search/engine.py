"""Global-search execution (issue #879).

One entry point, :func:`execute`, shared by the REST endpoint and the
``global_search`` MCP tool. They used to be two copies of the same fan-out —
which meant the Copilot's search silently missed every type added to the
HTTP one, and would have missed the permission filtering added here too.
"""

from __future__ import annotations

from collections import Counter

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import (
    _has_any_read_grant,
    is_effective_superadmin,
    token_scoped_resource_ids,
    user_has_permission,
)
from app.models.auth import User
from app.services.feature_modules import get_enabled_modules
from app.services.search.providers import PROVIDERS, SearchProvider
from app.services.search.schemas import (
    SearchResponse,
    SearchResult,
    SearchTypeInfo,
    shape_of,
)

logger = structlog.get_logger(__name__)

__all__ = ["execute", "visible_providers"]


# Result type -> the resource type whose grant scoped to ONE row reaches that
# row's own detail route: one subnet (#2438, #2569), and one space, block or
# site (#3039, #3134). Each such provider is admitted on any read grant for its
# type, scoped or not, that a resource-scoped API token (#374) does not narrow
# away (the coarse gate the type's own list route makes), and
# ``_narrow_to_grants`` cuts the rows to the granted ones. Every other provider
# (addresses, the custom-field pass, ...) keeps its type-level gate.
_INSTANCE_SCOPED_TYPES: dict[str, str] = {
    "subnet": "subnet",
    "block": "ip_block",
    "space": "ip_space",
    "site": "site",
}


def _may_read(user: User, provider: SearchProvider) -> bool:
    if provider.superadmin_only:
        return is_effective_superadmin(user)
    scoped_type = _INSTANCE_SCOPED_TYPES.get(provider.type)
    if scoped_type is not None and not provider.also_emits:
        return _has_any_read_grant(user, scoped_type)
    return any(user_has_permission(user, "read", rt) for rt in provider.resource_types)


async def visible_providers(db: AsyncSession, user: User) -> list[SearchProvider]:
    """Providers this user may run, after RBAC and feature-module gating."""
    enabled = await get_enabled_modules(db)
    return [
        p for p in PROVIDERS if (p.module is None or p.module in enabled) and _may_read(user, p)
    ]


# Result type -> (token resource type, the result field naming that resource).
# A resource-scoped API token (#374) passes the provider gate above on a type
# match alone, so each emitted row must also fall inside the token's bound
# instances, exactly as the REST list routes narrow (GHSA-wr8j-6r46-pj7g).
# Records are scoped by their zone and addresses by their subnet, matching
# how the zone / subnet routes enforce those tokens.
_TOKEN_SCOPE_FIELD: dict[str, tuple[str, str]] = {
    "dns_zone": ("dns_zone", "id"),
    "dns_record": ("dns_zone", "dns_zone_id"),
    "subnet": ("subnet", "id"),
    "ip_address": ("subnet", "subnet_id"),
    "block": ("ip_block", "id"),
    "space": ("ip_space", "id"),
}


def _narrow_to_token_scope(user: User, results: list[SearchResult]) -> list[SearchResult]:
    """Drop rows outside a resource-scoped token's bound instances.

    A no-op for sessions and unscoped tokens: ``token_scoped_resource_ids``
    returns ``None`` for them, and for a wildcard grant on the type.
    """
    bound: dict[str, set[str] | None] = {
        rtype: token_scoped_resource_ids(user, rtype)
        for rtype in {rt for rt, _field in _TOKEN_SCOPE_FIELD.values()}
    }
    if all(ids is None for ids in bound.values()):
        return results
    kept: list[SearchResult] = []
    for r in results:
        scope = _TOKEN_SCOPE_FIELD.get(r.type)
        if scope is not None:
            rtype, field = scope
            ids = bound[rtype]
            if ids is not None and str(getattr(r, field, None) or "") not in ids:
                continue
        kept.append(r)
    return kept


def _narrow_to_grants(user: User, results: list[SearchResult]) -> list[SearchResult]:
    """Keep only the subnet / space / block / site rows the caller may read
    when it holds no type-level read on that type (a grant scoped to
    individual rows, #2569, #3134).

    A no-op per type for anyone with a type-level (or wildcard) read on it."""
    narrowed = {
        rtype: scoped
        for rtype, scoped in _INSTANCE_SCOPED_TYPES.items()
        if not user_has_permission(user, "read", scoped)
    }
    if not narrowed:
        return results
    return [
        r
        for r in results
        if r.type not in narrowed or user_has_permission(user, "read", narrowed[r.type], r.id)
    ]


def _emitted_types(providers: list[SearchProvider]) -> set[str]:
    """Result ``type`` strings the caller is allowed to receive.

    Only single-type providers contribute. A multi-type provider — the IPAM
    custom-field pass, which is one query returning block, subnet and
    address rows — contributes nothing of its own, because its gate is
    "read on ANY of the three". Letting it widen this set would mean a
    caller with ``read`` on ``subnet`` but not ``ip_address`` receives
    address rows through the custom-field door, which is the whole reason
    the filtering happens on emitted rows rather than on providers.

    So a custom-field hit on an address survives only if the ``ip_address``
    provider itself passed its own gate.
    """
    return {p.type for p in providers if not p.also_emits}


# Rows fetched per type; the ceiling on ``total`` (``total_capped`` flags it).
FETCH_CAP = 100


async def execute(
    db: AsyncSession,
    user: User,
    q: str,
    *,
    types: set[str] | None = None,
    limit: int = 25,
) -> SearchResponse:
    q = q.strip()
    shape = shape_of(q)
    allowed = await visible_providers(db, user)
    allowed_types = _emitted_types(allowed)

    # A type the caller cannot see is dropped from the request rather than
    # rejected: a stale scope chip in an open tab should return nothing for
    # that scope, not fail the whole search.
    wanted = types & allowed_types if types else None

    to_run = [
        p
        for p in allowed
        if shape.kind in p.shapes
        and (wanted is None or bool(set(p.also_emits or (p.type,)) & wanted))
    ]

    # Fetch more per type than we will show. The engine reranks across types
    # afterwards, so a type whose rows all lose the rerank must not have
    # consumed the whole budget.
    # Independent of ``limit`` so that ``total`` does not move with it (#2987).
    per_type = FETCH_CAP
    capped = False

    results: list[SearchResult] = []
    for provider in to_run:
        try:
            # The SAVEPOINT is what makes the ``except`` mean what it says.
            # Catching the exception alone is not enough on PostgreSQL: a
            # failed statement leaves the session in "current transaction is
            # aborted", so every *later* provider dies with
            # PendingRollbackError and the caller gets an empty result set
            # with a 200. Since ``ip_address`` runs first, one bad query
            # there would blank the entire palette — the exact opposite of
            # the isolation this block is here to provide.
            async with db.begin_nested():
                got = await provider.fn(db, shape, per_type)
                # Per emitted type: the custom-field pass runs one LIMITed
                # query per type and returns them together, so its combined
                # length can reach the cap with no single type truncated.
                if any(n >= per_type for n in Counter(r.type for r in got).values()):
                    capped = True
                results.extend(got)
        except Exception:  # noqa: BLE001 — one broken type must not blank the palette
            logger.warning("search_provider_failed", type=provider.type, exc_info=True)

    # Post-filter: covers ``also_emits`` rows and any provider that returns a
    # type other than its own.
    results = [
        r for r in results if r.type in allowed_types and (wanted is None or r.type in wanted)
    ]
    results = _narrow_to_token_scope(user, results)
    results = _narrow_to_grants(user, results)

    # De-duplicate. The same row can arrive from a direct column match and
    # from the custom-field pass; keep the higher-scoring copy, preferring
    # the one that can explain itself when the scores tie.
    by_key: dict[str, SearchResult] = {}
    for r in results:
        key = f"{r.type}:{r.id}"
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = r
        elif r.score > existing.score:
            by_key[key] = r
        elif r.score == existing.score and existing.matched_field is None:
            by_key[key] = r

    # Relevance first; then a stable display-order tiebreak so equal-scoring
    # rows don't shuffle between identical requests.
    ranked = sorted(by_key.values(), key=lambda r: (-r.score, r.type, r.display))

    searched = [
        SearchTypeInfo(type=p.type, label=p.label, group=p.group)
        for p in allowed
        if not p.also_emits  # the custom-field pass is not a chip of its own
    ]

    logger.info(
        "search_executed",
        user=user.username,
        query=q,
        shape=shape.kind,
        providers_run=len(to_run),
        total=len(ranked),
    )

    return SearchResponse(
        query=q,
        total=len(ranked),
        total_capped=capped,
        results=ranked[:limit],
        searched_types=searched,
    )
