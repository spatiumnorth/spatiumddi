"""The built-in roles are held to the routes they are meant to open (#1862).

A role is a list of ``(action, resource_type)`` grants, and a route enforces
one or more of those pairs. Nothing tied the two together, so they drifted
without any test noticing: the Auditor was granted ``read`` on ``audit`` while
every audit-log route checks ``read`` on ``audit_log``, so the grant matched
nothing and the role's own description ("read on audit log") was false.

This walks every route the app serves, collects the ``(action, resource_type)``
pairs its dependencies require (the permission factories in
``app.core.permissions`` record them in ``spatium_requires``), and holds each
built-in role's grants against that inventory.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from app.api.deps import require_superadmin
from app.core.permissions import (
    _METHOD_TO_ACTION,
    _action_matches,
    _resource_type_matches,
)
from app.main import _BUILTIN_ROLES, app

# Resource types the routes do not enforce through a dependency, because the
# handler (or an operation it runs) checks them inline. The walker below cannot
# see those, so each is named here with where it is checked. A type that is in
# neither this table nor the route inventory is a grant that matches nothing.
CHECKED_INLINE: dict[str, str] = {
    "conformity": "conformity router, per handler (read / admin)",
    "change_request": "requests router, approve endpoint",
    "provisioning_request": "requests router, submit endpoint",
    "routing_policy": "overlays router, routing-policy mutations re-check it",
}


def _iter_routes(routes: Any) -> Iterator[Any]:
    """Every concrete route, across FastAPI versions.

    Newer FastAPI nests included routers (``effective_candidates``); older
    versions flatten them into ``app.routes``. Either way a concrete route has
    a ``dependant`` and ``methods``.
    """
    for r in routes:
        if hasattr(r, "effective_candidates"):
            yield from _iter_routes(r.effective_candidates())
        elif getattr(r, "dependant", None) is not None and hasattr(r, "methods"):
            yield r


def _dependency_calls(dependant: Any) -> Iterator[Any]:
    for d in dependant.dependencies:
        yield d.call
        yield from _dependency_calls(d)


def route_inventory() -> list[tuple[str, str, bool, set[tuple[str, str]]]]:
    """``(method, path, superadmin_only, {(action, resource_type), ...})``.

    The pairs are alternatives within one dependency (any-of) and conjunctions
    across dependencies; for this check what matters is which pairs a route
    names at all, so they are flattened.
    """
    out = []
    for r in _iter_routes(app.routes):
        calls = list(_dependency_calls(r.dependant))
        superadmin = any(c is require_superadmin for c in calls)
        for method in sorted(r.methods):
            if method in ("HEAD", "OPTIONS"):
                continue
            needs: set[tuple[str, str]] = set()
            for c in calls:
                req = getattr(c, "spatium_requires", None)
                if req is None:
                    continue
                kind, items = req
                if kind == "exact":
                    needs.update(items)
                else:
                    needs.update((_METHOD_TO_ACTION[method], t) for t in items)
            out.append((method, r.path, superadmin, needs))
    return out


def _grants() -> list[tuple[str, str, str]]:
    return [
        (role, p["action"], p["resource_type"])  # type: ignore[misc]
        for role, (_desc, perms) in _BUILTIN_ROLES.items()
        for p in perms
        if p["resource_type"] != "*"
    ]


def _routes_for(inventory, action: str, rtype: str):
    return [
        (m, path, sup)
        for m, path, sup, needs in inventory
        if any(_action_matches(action, na) and _resource_type_matches(rtype, nt) for na, nt in needs)
    ]


def test_inventory_finds_the_routes() -> None:
    # A walker that finds nothing makes every assertion below vacuous.
    assert len(route_inventory()) > 500


def test_every_builtin_grant_is_enforced_by_some_route() -> None:
    inv = route_inventory()
    dead = [
        f"{role}: {action} on {rtype}"
        for role, action, rtype in _grants()
        if rtype not in CHECKED_INLINE and not _routes_for(inv, action, rtype)
    ]
    assert not dead, (
        "built-in role grants that no route checks, so they open nothing "
        "(grant the resource_type the routes require, or add it to "
        "CHECKED_INLINE with where it is checked):\n" + "\n".join(dead)
    )


def test_the_audit_log_is_readable_by_the_roles_that_say_so() -> None:
    inv = route_inventory()
    audit_routes = [(m, p) for m, p, _s, needs in inv if ("read", "audit_log") in needs]
    assert audit_routes, "no route checks read on audit_log"
    for role in ("Auditor", "Compliance Editor"):
        _desc, perms = _BUILTIN_ROLES[role]
        assert any(
            _action_matches(p["action"], "read")  # type: ignore[arg-type]
            and _resource_type_matches(p["resource_type"], "audit_log")  # type: ignore[arg-type]
            for p in perms
        ), f"{role} cannot read the audit log"
