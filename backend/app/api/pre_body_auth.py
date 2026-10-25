"""Authorise a request from its headers before its body is read.

FastAPI reads a route's body (``await request.form()`` for a multipart
upload, ``await request.body()`` for JSON) before it resolves any
dependency, so a route whose only authorisation is a dependency has
already received the whole body by the time it answers 401 or 403. For a
multipart upload that means the parts are spooled to a temporary file on
the api pod's disk; for JSON it means the body is held in memory.

Under the ``/api/`` nginx location that is bounded by nginx's 1 MiB
default body limit and does not matter. The backup and upgrade-image
locations raise that limit to 2 GiB and 4 GiB with request buffering
off, so for their routes it does: the body has to wait until the caller
is known to be allowed to send it.

:class:`PreBodyAuthRoute` does that. For each route that takes a body it
finds the route's own authorisation dependencies (``require_superadmin``,
``get_current_user`` and the ``require_*permission`` family from
``app.core.permissions``) and runs them, in the order FastAPI would, from
the request headers alone, before the original handler reads anything.
The answers are the ones the dependencies give (the same 401 / 403
bodies, the same ``denied`` audit row), because they are the same
functions. The dependencies still run again in the normal way afterwards;
the early pass only decides whether the body is read at all.

A route that takes a body on a router using this class and declares none
of those dependencies is refused when the router is built: the class
exists to authorise first, and a body route with nothing to authorise
with would otherwise be served unchecked without anyone noticing.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

from fastapi import Request
from fastapi.routing import APIRoute
from starlette.responses import Response

from app.api.deps import _bearer, get_current_user, require_superadmin
from app.db import get_db

# The parameters an authorisation dependency may take. Every check in
# ``app.api.deps`` / ``app.core.permissions`` takes a subset of these.
_KNOWN_PARAMS = frozenset({"request", "current_user", "db"})

AuthCheck = Callable[..., Awaitable[Any]]


def _is_auth_check(call: Any) -> bool:
    return (
        call is get_current_user
        or call is require_superadmin
        or getattr(call, "spatium_requires", None) is not None
    )


def _auth_checks(route: APIRoute) -> list[AuthCheck]:
    """The route's top-level authorisation dependencies, in resolution order."""
    checks: list[AuthCheck] = []
    for dep in route.dependant.dependencies:
        call = dep.call
        if call is None or not _is_auth_check(call):
            continue
        params = set(inspect.signature(call).parameters)
        unknown = params - _KNOWN_PARAMS
        if unknown:
            raise RuntimeError(
                f"{route.path}: authorisation dependency {getattr(call, '__name__', call)!r} "
                f"takes {sorted(unknown)}, which cannot be supplied before the body is read"
            )
        checks.append(call)
    return checks


async def authorise_from_headers(request: Request, checks: list[AuthCheck]) -> None:
    """Run ``checks`` against ``request`` using only its headers.

    Raises the ``HTTPException`` the first failing check raises. The
    database session is taken from the same provider FastAPI would use
    (honouring ``dependency_overrides``) and closed before returning, so
    no connection is held while a large body is then received."""
    provider = request.app.dependency_overrides.get(get_db, get_db)
    sessions = provider()
    db = await sessions.__anext__()
    try:
        credentials = await _bearer(request)
        user = await get_current_user(request, db, credentials)
        values = {"request": request, "current_user": user, "db": db}
        for check in checks:
            if check is get_current_user:
                continue
            wanted = inspect.signature(check).parameters
            await check(**{name: values[name] for name in wanted})
    finally:
        await sessions.aclose()


class PreBodyAuthRoute(APIRoute):
    """Authorise a body-taking route from its headers before the body is
    read. Routes without a body are returned untouched.

    Subclasses can add further header-only checks by overriding
    :meth:`before_body`, which runs after authorisation succeeds."""

    async def before_body(self, request: Request) -> None:
        """Hook for a further check that needs no body. Default: none."""
        return None

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()
        if not self.dependant.body_params:
            return original
        checks = _auth_checks(self)
        if not checks:
            raise RuntimeError(
                f"{self.path}: takes a request body on a router that authorises "
                "before reading it, but declares no authorisation dependency"
            )

        async def authorised(request: Request) -> Response:
            await authorise_from_headers(request, checks)
            await self.before_body(request)
            return await original(request)

        return authorised
