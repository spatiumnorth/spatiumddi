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

The importers (DNS, DHCP, IPAM and NetBox) and the DNS agent router use
:class:`PreBodyAuthRoute` for every body route, JSON ones included: their
routes carry body allowances well above the app-wide cap
(``app.core.body_limit``), so the caller is checked before any of it is
read. The zone-spreadsheet import and the branding logo use
:class:`PreBodyAuthUploadRoute`, which does the same for a router's
multipart / form routes only: their routers also serve JSON routes that
stay under the app-wide body cap.

A dependency that authenticates something other than a user (the DNS
agent's bearer token, its bootstrap key) takes part by carrying a
``spatium_header_auth`` attribute: an async callable taking any of
``request`` / ``db`` that performs the same check from the headers alone
and raises the same ``HTTPException`` (:func:`header_auth`). A route
whose checks are all of that kind never resolves a user.

A route that takes a body on a router using this class and declares none
of those dependencies is refused when the router is built: the class
exists to authorise first, and a body route with nothing to authorise
with would otherwise be served unchecked without anyone noticing.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, TypeVar

import fastapi.routing as _fastapi_routing
from fastapi import Request
from fastapi import params as fastapi_params
from fastapi.routing import APIRoute
from starlette.responses import Response

from app.api.deps import _bearer, get_current_user, require_superadmin
from app.db import get_db

# The parameters an authorisation dependency may take. Every check in
# ``app.api.deps`` / ``app.core.permissions`` takes a subset of these.
_KNOWN_PARAMS = frozenset({"request", "current_user", "db"})

AuthCheck = Callable[..., Awaitable[Any]]
_Dep = TypeVar("_Dep", bound=Callable[..., Any])

# FastAPI serves a route included through ``include_router`` from an
# "effective" route that carries the router-level dependencies as well as
# the route's own, and names the one ``get_route_handler`` is building in
# this context variable (``APIRoute.get_route_handler`` reads it the same
# way). Used so a router-level permission gate (the IPAM router's) runs
# before the body too. It is private to FastAPI: without it the route's own
# dependencies are used, which still includes the login check, and
# ``tests/test_pre_body_auth.py`` fails loudly so the loss is noticed.
EFFECTIVE_CONTEXT_VAR = getattr(_fastapi_routing, "_effective_route_context_var", None)


def header_auth(check: AuthCheck) -> Callable[[_Dep], _Dep]:
    """Mark a dependency as an authorisation check :class:`PreBodyAuthRoute`
    can run before the body, by naming ``check``: an async callable taking
    any of ``request`` / ``db`` that gives the dependency's own answer from
    the request headers alone.

    When the dependency is replaced through ``app.dependency_overrides``
    (tests), ``check`` is skipped: the override is what the route then
    authorises with, and it runs in the normal way."""

    def mark(dependency: _Dep) -> _Dep:
        dependency.spatium_header_auth = check  # type: ignore[attr-defined]
        check.spatium_header_auth_for = dependency  # type: ignore[attr-defined]
        return dependency

    return mark


def _is_auth_check(call: Any) -> bool:
    return (
        call is get_current_user
        or call is require_superadmin
        or getattr(call, "spatium_requires", None) is not None
        or getattr(call, "spatium_header_auth", None) is not None
    )


def _route_dependant(route: APIRoute) -> Any:
    """The dependant FastAPI will serve ``route`` with: the effective one,
    router-level dependencies included, when one is being built."""
    if EFFECTIVE_CONTEXT_VAR is not None:
        context = EFFECTIVE_CONTEXT_VAR.get()
        if context is not None and getattr(context, "original_route", None) is route:
            dependant = getattr(context, "dependant", None)
            if dependant is not None:
                return dependant
    return route.dependant


def _auth_checks(route: APIRoute) -> list[AuthCheck]:
    """The route's top-level authorisation dependencies, router-level ones
    included, in resolution order."""
    checks: list[AuthCheck] = []
    for dep in _route_dependant(route).dependencies:
        call = dep.call
        if call is None or not _is_auth_check(call):
            continue
        if call is get_current_user:
            # Resolved by ``authorise_from_headers`` itself (a route that
            # declares ``CurrentUser`` directly lists it here).
            checks.append(call)
            continue
        header_check = getattr(call, "spatium_header_auth", None)
        if header_check is not None:
            call = header_check
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
    overrides = request.app.dependency_overrides
    checks = [
        check
        for check in checks
        if getattr(check, "spatium_header_auth_for", None) not in overrides
    ]
    if not checks:
        return
    provider = overrides.get(get_db, get_db)
    sessions = provider()
    db = await sessions.__anext__()
    try:
        values: dict[str, Any] = {"request": request, "db": db}
        if any(
            check is get_current_user or "current_user" in inspect.signature(check).parameters
            for check in checks
        ):
            credentials = await _bearer(request)
            values["current_user"] = await get_current_user(request, db, credentials)
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


def takes_upload(route: APIRoute) -> bool:
    """True when ``route`` takes a multipart / form body (a file upload)."""
    return any(
        isinstance(field.field_info, (fastapi_params.Form, fastapi_params.File))
        for field in route.dependant.body_params
    )


class PreBodyAuthUploadRoute(PreBodyAuthRoute):
    """:class:`PreBodyAuthRoute` for the upload routes of a router that also
    serves JSON routes: only a route taking a multipart / form body (a file
    upload) is checked before its body is read (#2780). Every other route on
    the router is served exactly as by ``APIRoute``; the app-wide body cap
    (``app.core.body_limit``) bounds those, so a router whose JSON routes
    carry a larger allowance uses :class:`PreBodyAuthRoute` instead."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        if not takes_upload(self):
            return APIRoute.get_route_handler(self)
        return super().get_route_handler()
