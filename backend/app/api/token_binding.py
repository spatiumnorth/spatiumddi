"""Which routes may serve an API token bound to specific subnets or zones.

A token restricted with ``resource_grants`` (#374) passes a coarse permission
gate on a resource TYPE match alone: a token bound to one subnet clears
``read`` on ``subnet`` for every subnet. Narrowing to the bound instances is
then the route's job. The IPAM and DNS routers do it structurally
(``app.api.token_path_scope``), but a route mounted anywhere else, such as a
report or a metrics series that aggregates over every subnet or server, had
nothing to narrow it, and answered for the whole estate.

So the default is inverted. The auth dependency refuses a resource-bound
token on every route that has not declared it honours the binding. A route
declares it in one of two ways:

* its router is mounted with ``include_token_scoped``, which adds
  ``enforce_path_token_scope`` and marks every route in it (nested routers
  included) in the same call, so the mark cannot exist without the check;
* its endpoint is decorated with :func:`honours_token_binding`, for a route
  that narrows its own answer to the bound subnets and zones, or that returns
  nothing about the estate at all.

Sessions and tokens without resource grants are unaffected.

This module imports nothing from the app, so ``app.api.deps`` can use it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from starlette.requests import Request

_MARK = "_spatium_honours_token_binding"


def honours_token_binding[F: Callable[..., Any]](endpoint: F) -> F:
    """Declare that ``endpoint`` may serve a token bound to specific subnets or
    DNS zones: it narrows what it returns to those instances itself, or it
    returns nothing about the estate. Apply it below the route decorator."""
    setattr(endpoint, _MARK, True)
    return endpoint


def mark_router_token_scoped(router: Any) -> None:
    """Mark every route of ``router``, nested routers included.

    Older FastAPI copies an included router's routes into the parent; newer
    versions keep the included router nested under ``original_router``. Both
    shapes are walked, and the mark sits on the endpoint function either way.
    """
    for route in getattr(router, "routes", ()):
        endpoint = getattr(route, "endpoint", None)
        if endpoint is not None:
            honours_token_binding(endpoint)
        nested = getattr(route, "original_router", None)
        if nested is not None:
            mark_router_token_scoped(nested)


def route_honours_token_binding(request: Request) -> bool:
    """Whether the route this request matched has declared it honours a
    token's resource binding. A request with no matched route (served by
    middleware, say) has declared nothing and answers ``False``."""
    endpoint = getattr(request.scope.get("route"), "endpoint", None)
    return bool(getattr(endpoint, _MARK, False))
