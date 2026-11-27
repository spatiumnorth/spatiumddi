"""Which routes may serve a tenant user (#4263, multi-tenancy phase 1).

A tenant user is confined to the IP spaces of their tenant. The IPAM rows are
narrowed centrally, by an ORM-level filter on the request's session
(``app.services.tenancy``), so a route that only reads and writes those rows is
safe by construction. A route that reaches anything else (DNS zones, DHCP
scopes, audit history, settings, integrations, ...) would answer for the whole
install, so the default is closed: the auth dependency refuses a tenant user
on every route that has not declared it is tenant-aware, which is also what
makes a feature added later start closed for tenants until someone decides how
it behaves.

A route declares it in one of two ways:

* its router is mounted with :func:`include_tenant_aware`, which marks the
  routes of the router, nested routers included, minus an explicit
  ``exclude`` set of endpoint names the router must still refuse;
* its endpoint is decorated with :func:`tenant_aware`, for a route that
  narrows its own answer or returns nothing about the install (``/auth/me``).

Non-tenant users are never affected. This module imports nothing from the
app, so ``app.api.deps`` can use it.
"""

from __future__ import annotations

from collections.abc import Callable, Collection
from typing import Any

from starlette.requests import Request

_MARK = "_spatium_tenant_aware"


def tenant_aware[F: Callable[..., Any]](endpoint: F) -> F:
    """Declare that ``endpoint`` may serve a tenant user: every row it reads or
    writes is IPAM data narrowed by the session filter, or it returns nothing
    about the install. Apply it below the route decorator."""
    setattr(endpoint, _MARK, True)
    return endpoint


def mark_router_tenant_aware(router: Any, *, exclude: Collection[str] = ()) -> None:
    """Mark every route of ``router`` (nested routers included) except the
    endpoints whose function name is in ``exclude``.

    Older FastAPI copies an included router's routes into the parent; newer
    versions keep the included router nested under ``original_router``. Both
    shapes are walked; the mark sits on the endpoint function either way.
    """
    for route in getattr(router, "routes", ()):
        endpoint = getattr(route, "endpoint", None)
        if endpoint is not None and endpoint.__name__ not in exclude:
            tenant_aware(endpoint)
        nested = getattr(route, "original_router", None)
        if nested is not None:
            mark_router_tenant_aware(nested, exclude=exclude)


def endpoint_is_tenant_aware(endpoint: Any) -> bool:
    return bool(getattr(endpoint, _MARK, False))


def route_is_tenant_aware(request: Request) -> bool:
    """Whether the route this request matched has declared it serves tenant
    users. A request with no matched route answers ``False``."""
    endpoint = getattr(request.scope.get("route"), "endpoint", None)
    return endpoint_is_tenant_aware(endpoint)
