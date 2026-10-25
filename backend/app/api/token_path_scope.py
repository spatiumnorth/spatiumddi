"""Router-level per-instance gate for resource-scoped API tokens (GHSA-46mq-mpwf-xxwv).

A token restricted with ``resource_grants`` (#374) passes the router-level
permission gate on a resource TYPE match alone, whatever the instance. Every
handler keyed on a subnet, an address or a DNS zone then had to remember its
own ``token_scope_allows`` check. Dozens did not, and each one found became an
advisory (GHSA-wr8j-6r46-pj7g, then GHSA-46mq-mpwf-xxwv): reads that returned
another subnet's addresses or another zone's records, and writes that let a
token bound to one zone change another.

This dependency makes the check structural instead. Mounted on the IPAM and
DNS routers, it inspects the matched route's path parameters before any
handler runs:

* ``subnet_id``: the token must be bound to that subnet;
* ``address_id``: the token must be bound to the address's subnet;
* ``zone_id``: the token must be bound to that zone;
* ``block_id`` / ``space_id``: the block or space must contain a subnet the
  token is bound to (a block is checked through its parent chain), or be
  named by a grant of its own.

The same names are checked as **query** parameters too (``?subnet_id=…`` on
a report filters just as a path id selects), every occurrence of a repeated
parameter included. A block or space that contains one of the token's
subnets is admitted, not narrowed: handlers keyed on one that return data
about more than one subnet narrow their own rows with
``_token_subnet_scope_uuids`` (or refuse, where the answer is a fact about the
whole block and cannot be narrowed).

Ids carried in a form field or a JSON body are NOT seen here: the body is
the handler's to parse. A route that takes its subnet, block or space from
the body (the IPAM imports) checks the token itself, and a route whose answer
covers a whole block or space it was handed (an export) refuses a token bound
to subnets rather than relying on this admit.

Sessions and tokens without resource grants are untouched (one attribute
read, no query). A token with a wildcard ``subnet`` grant is not checked on
blocks and spaces. An id that does not parse, or an address that does not
exist, is left to the handler, which answers 422 / 404 as before. The
per-handler checks stay; this is the floor beneath them, and it covers routes
added later without anyone having to remember.

Mount a router with :func:`include_token_scoped`, never by adding the
dependency by hand: it also marks the router's routes as honouring the
binding, and a resource-bound token is refused on every unmarked route
(``app.api.token_binding``).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.api.token_binding import mark_router_token_scoped
from app.core.permissions import (
    _token_grants_for,
    token_scope_allows,
    token_scoped_resource_ids,
)
from app.models.ipam import IPAddress, IPBlock, Subnet

__all__ = ["enforce_path_token_scope", "include_token_scoped"]


def _uuid(value: object) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


def _deny(what: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"API token is not scoped to this {what}",
    )


def _ids(request: Request, name: str) -> list[uuid.UUID]:
    """Every id the request names under ``name``: the path parameter plus each
    occurrence of the query parameter. Values that do not parse are skipped
    (the handler's own validation answers for them)."""
    raw: list[object] = []
    if name in request.path_params:
        raw.append(request.path_params[name])
    raw.extend(request.query_params.getlist(name))
    out = []
    for value in raw:
        parsed = _uuid(value)
        if parsed is not None:
            out.append(parsed)
    return out


async def _granted_containers(
    db: AsyncSession, subnet_ids: set[uuid.UUID]
) -> tuple[set[uuid.UUID], set[uuid.UUID]]:
    """The spaces and blocks (with every ancestor block) that contain one of
    ``subnet_ids``."""
    if not subnet_ids:
        return set(), set()
    rows = (
        await db.execute(select(Subnet.space_id, Subnet.block_id).where(Subnet.id.in_(subnet_ids)))
    ).all()
    spaces = {r.space_id for r in rows if r.space_id is not None}
    blocks: set[uuid.UUID] = set()
    frontier = {r.block_id for r in rows if r.block_id is not None}
    while frontier:
        blocks |= frontier
        parents = (
            await db.execute(
                select(IPBlock.parent_block_id).where(
                    IPBlock.id.in_(frontier), IPBlock.parent_block_id.is_not(None)
                )
            )
        ).scalars()
        frontier = {p for p in parents if p is not None} - blocks
    return spaces, blocks


def _token_subnet_uuids(user: object) -> set[uuid.UUID] | None:
    scoped = token_scoped_resource_ids(user, "subnet")  # type: ignore[arg-type]
    if scoped is None:
        return None
    return {u for u in (_uuid(r) for r in scoped) if u is not None}


async def enforce_path_token_scope(request: Request, current_user: CurrentUser, db: DB) -> None:
    if not _token_grants_for(current_user):
        return  # session / unscoped token: nothing to narrow

    for subnet_id in _ids(request, "subnet_id"):
        if not token_scope_allows(current_user, "subnet", subnet_id):
            raise _deny("subnet")

    for address_id in _ids(request, "address_id"):
        address = await db.get(IPAddress, address_id)
        if address is not None and not token_scope_allows(
            current_user, "subnet", address.subnet_id
        ):
            raise _deny("subnet")

    for zone_id in _ids(request, "zone_id"):
        if not token_scope_allows(current_user, "dns_zone", zone_id):
            raise _deny("DNS zone")

    block_ids = _ids(request, "block_id")
    space_ids = _ids(request, "space_id")
    if block_ids or space_ids:
        granted = _token_subnet_uuids(current_user)
        if granted is None:
            return  # wildcard subnet grant: every block and space is in scope
        spaces, blocks = await _granted_containers(db, granted)
        # A grant naming the block or space itself also admits it, so this
        # floor stays in step with the per-handler checks if those types
        # ever become grantable.
        for block_id in block_ids:
            if block_id not in blocks and not token_scope_allows(
                current_user, "ip_block", block_id
            ):
                raise _deny("IP block")
        for space_id in space_ids:
            if space_id not in spaces and not token_scope_allows(
                current_user, "ip_space", space_id
            ):
                raise _deny("IP space")


def include_token_scoped(
    parent: APIRouter,
    router: APIRouter,
    *,
    dependencies: Sequence[Any] = (),
    **kwargs: Any,
) -> None:
    """Include ``router`` behind :func:`enforce_path_token_scope` and mark its
    routes as honouring a token's resource binding, in one step, so neither
    can be done without the other."""
    mark_router_token_scoped(router)
    parent.include_router(
        router,
        dependencies=[*dependencies, Depends(enforce_path_token_scope)],
        **kwargs,
    )
