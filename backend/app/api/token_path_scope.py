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
* ``zone_id``: the token must be bound to that zone.

Sessions and tokens without resource grants are untouched (one attribute
read, no query). A path id that does not parse, or an address that does not
exist, is left to the handler, which answers 422 / 404 as before. The
per-handler checks stay; this is the floor beneath them, and it covers routes
added later without anyone having to remember.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, Request, status

from app.api.deps import DB, CurrentUser
from app.core.permissions import _token_grants_for, token_scope_allows
from app.models.ipam import IPAddress

__all__ = ["enforce_path_token_scope"]


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


async def enforce_path_token_scope(request: Request, current_user: CurrentUser, db: DB) -> None:
    if not _token_grants_for(current_user):
        return  # session / unscoped token: nothing to narrow
    params = request.path_params

    subnet_id = _uuid(params.get("subnet_id"))
    if subnet_id is not None and not token_scope_allows(current_user, "subnet", subnet_id):
        raise _deny("subnet")

    address_id = _uuid(params.get("address_id"))
    if address_id is not None:
        address = await db.get(IPAddress, address_id)
        if address is not None and not token_scope_allows(
            current_user, "subnet", address.subnet_id
        ):
            raise _deny("subnet")

    zone_id = _uuid(params.get("zone_id"))
    if zone_id is not None and not token_scope_allows(current_user, "dns_zone", zone_id):
        raise _deny("DNS zone")
