"""Structural guard: config-mutating routes publish an agent wake (#2040, #358).

A missed wake fails silently. The ETag compare stays authoritative, so the
change still converges — on the ``WAKE_TICK_SECONDS`` safety tick instead of at
once — and nothing anywhere reports it. That is how ``POST /new-devices/block``
shipped a ``collect_wake`` with no collector to publish it. These tests turn
each way of missing one into a failing test:

1. a handler that calls ``collect_wake`` must be mounted under the
   ``wake_publishing`` collector, or the call is a no-op;
2. every mutating route on the DHCP bundle surface (``/dhcp`` operator routes
   and ``/e911``, whose rows render options 99 / 123) must collect a wake
   itself, delegate to something that does, or be listed with the reason the
   bundle cannot be affected;
3. the two places that dispatch a copilot / approved operation outside any
   router collector must open one around ``op.apply``.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import textwrap
from typing import Any

from app.core.agent_wake import wake_publishing
from app.main import app
from tests.test_builtin_roles_match_routes import _dependency_calls, _iter_routes

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_WAKES = ("collect_wake(", "publish_wake(")

# The DHCP config bundle's REST surface. ``/dhcp/agents`` is the agent's own
# surface: the long-poll must never publish (it would wake itself).
_SURFACE_PREFIXES = ("/api/v1/dhcp/", "/api/v1/e911/")
_SURFACE_EXCLUDED = ("/api/v1/dhcp/agents/",)

# Routes whose handler hands the mutation to a function that collects the wake.
# The value is that function's dotted path; the guard reads ITS source, so a
# delegate that stops waking fails here too.
DELEGATES: dict[tuple[str, str], str] = {
    ("DELETE", "/api/v1/dhcp/scopes/{scope_id}"): (
        "app.services.ai.operations_risky._apply_delete_scope"
    ),
    **{
        ("POST", f"/api/v1/dhcp/import/{src}/commit"): "app.api.v1.dhcp_import.router._run_commit"
        for src in ("kea", "isc", "windows")
    },
}

_WINDOWS = "Windows failover relationship over WinRM; no agent renders it"
_READONLY = "reads or probes only; changes no bundle input"
# Routes that change nothing an agent bundle reads, each with the reason.
NO_WAKE: dict[tuple[str, str], str] = {
    ("POST", "/api/v1/dhcp/server-groups"): (
        "a new group has no members, so no agent is parked on its channel"
    ),
    ("DELETE", "/api/v1/dhcp/server-groups/{group_id}"): (
        "refused (409) while the group holds servers or scopes"
    ),
    ("POST", "/api/v1/dhcp/server-groups/{group_id}/failover/relationships"): _WINDOWS,
    ("PATCH", "/api/v1/dhcp/server-groups/{group_id}/failover/relationships/{name}"): _WINDOWS,
    ("DELETE", "/api/v1/dhcp/server-groups/{group_id}/failover/relationships/{name}"): _WINDOWS,
    ("POST", "/api/v1/dhcp/server-groups/{group_id}/failover/relationships/{name}/scopes"): (
        _WINDOWS
    ),
    (
        "DELETE",
        "/api/v1/dhcp/server-groups/{group_id}/failover/relationships/{name}/scopes/{scope_id}",
    ): _WINDOWS,
    ("POST", "/api/v1/dhcp/server-groups/{group_id}/failover/relationships/{name}/replicate"): (
        _WINDOWS
    ),
    ("POST", "/api/v1/dhcp/servers/test-windows-credentials"): _READONLY,
    ("POST", "/api/v1/dhcp/servers/test-fortigate-credentials"): _READONLY,
    ("POST", "/api/v1/dhcp/servers/{server_id}/pause"): (
        "pause only stops op shipping; it must NOT wake (resume does)"
    ),
    ("DELETE", "/api/v1/dhcp/servers/{server_id}/leases/{lease_id}"): (
        "drops the control plane's lease row; leases are not in the bundle"
    ),
    ("POST", "/api/v1/dhcp/server-groups/{group_id}/option-templates"): (
        "a template is a stamp; only applying it to a scope (which wakes) changes a bundle"
    ),
    ("PUT", "/api/v1/dhcp/option-templates/{template_id}"): (
        "a template is a stamp; only applying it to a scope (which wakes) changes a bundle"
    ),
    ("DELETE", "/api/v1/dhcp/option-templates/{template_id}"): (
        "a template is a stamp; only applying it to a scope (which wakes) changes a bundle"
    ),
    ("POST", "/api/v1/dhcp/groups/{group_id}/responders/{responder_id}/acknowledge"): (
        "rogue-responder bookkeeping; not a bundle input"
    ),
    ("POST", "/api/v1/dhcp/ra/groups/{group_id}/observed-routers/{router_id}/acknowledge"): (
        "rogue-RA bookkeeping; not a bundle input"
    ),
    ("POST", "/api/v1/dhcp/ra/groups/{group_id}/ra-allowlist"): (
        "rogue-RA detection allowlist; radvd.conf is rendered from scopes"
    ),
    ("DELETE", "/api/v1/dhcp/ra/groups/{group_id}/ra-allowlist/{entry_id}"): (
        "rogue-RA detection allowlist; radvd.conf is rendered from scopes"
    ),
    **{
        ("POST", f"/api/v1/dhcp/import/{src}/preview"): _READONLY
        for src in ("kea", "isc", "windows")
    },
    ("POST", "/api/v1/e911/erls"): "an ERL no binding points at is in no bundle",
    ("POST", "/api/v1/e911/erls/{erl_id}/validation"): (
        "the provider's verdict; options 99 / 123 do not read it"
    ),
}


def _routes() -> list[Any]:
    return list(_iter_routes(app.routes))


def _has_collector(route: Any) -> bool:
    return any(c is wake_publishing for c in _dependency_calls(route.dependant))


def _source(fn: Any) -> str:
    try:
        return inspect.getsource(inspect.unwrap(fn))
    except (OSError, TypeError):
        return ""


def _wakes(src: str) -> bool:
    return any(w in src for w in _WAKES)


def _resolve(dotted: str) -> Any:
    module, _, name = dotted.rpartition(".")
    return getattr(importlib.import_module(module), name)


def _surface() -> dict[tuple[str, str], Any]:
    out: dict[tuple[str, str], Any] = {}
    for r in _routes():
        if not r.path.startswith(_SURFACE_PREFIXES) or r.path.startswith(_SURFACE_EXCLUDED):
            continue
        for method in r.methods & _MUTATING:
            out[(method, r.path)] = r
    return out


# ── 1. a stashed wake needs a collector ──────────────────────────────────────


def test_the_walker_sees_routes() -> None:
    # A walker that finds nothing makes every test below vacuous.
    assert len(_routes()) > 500
    assert len(_surface()) > 50


def test_every_handler_that_collects_a_wake_is_under_a_collector() -> None:
    missing = sorted(
        f"{sorted(r.methods)} {r.path}"
        for r in _routes()
        if "collect_wake(" in _source(r.endpoint) and not _has_collector(r)
    )
    assert not missing, (
        "These handlers call collect_wake but are not mounted with the "
        "wake_publishing dependency, so the wake is silently dropped and agents "
        f"converge only on the safety tick. Add Depends(wake_publishing): {missing}"
    )


# ── 2. the DHCP bundle surface ───────────────────────────────────────────────


def test_every_dhcp_bundle_route_is_under_a_collector() -> None:
    missing = sorted(f"{m} {p}" for (m, p), r in _surface().items() if not _has_collector(r))
    assert not missing, f"mount these with Depends(wake_publishing): {missing}"


def test_every_dhcp_bundle_mutation_wakes_or_says_why_not() -> None:
    missing = sorted(
        f"{m} {p}"
        for (m, p), r in _surface().items()
        if (m, p) not in DELEGATES and (m, p) not in NO_WAKE and not _wakes(_source(r.endpoint))
    )
    assert not missing, (
        "These routes change DHCP / E911 state and publish no wake, so a parked "
        "agent long-poll misses the change until its safety tick. collect_wake the "
        "affected dhcp_group / dhcp_server channel, or list the route in DELEGATES "
        f"(with the function that wakes) or NO_WAKE (with the reason): {missing}"
    )


def test_delegates_really_wake() -> None:
    silent = sorted(d for d in DELEGATES.values() if not _wakes(_source(_resolve(d))))
    assert not silent, f"these delegates no longer publish a wake: {silent}"


def test_listed_routes_still_exist() -> None:
    surface = _surface()
    stale = sorted(
        f"{m} {p}" for (m, p) in (DELEGATES.keys() | NO_WAKE.keys()) if (m, p) not in surface
    )
    assert not stale, f"remove these from DELEGATES / NO_WAKE: {stale}"


def test_no_wake_entries_really_do_not_wake() -> None:
    surface = _surface()
    waking = sorted(
        f"{m} {p}"
        for (m, p) in NO_WAKE
        if (m, p) in surface and _wakes(_source(surface[(m, p)].endpoint))
    )
    assert not waking, f"these wake now; drop them from NO_WAKE: {waking}"


def test_every_listed_route_has_a_reason() -> None:
    assert all(reason.strip() for reason in NO_WAKE.values())


# ── 3. operation dispatch outside a router collector ─────────────────────────

_BACKEND = pathlib.Path(__file__).resolve().parents[1]
# The routers these live in mount no ``wake_publishing`` (/ai, /change-requests,
# /requests), so the dispatch site has to open the collector itself.
_DISPATCH_SITES = (
    "app/api/v1/ai/proposals.py",
    "app/services/approvals/service.py",
)


def _apply_calls_outside_a_collector(path: pathlib.Path) -> list[int]:
    tree = ast.parse(path.read_text())
    bad: list[int] = []

    def visit(node: ast.AST, inside: bool) -> None:
        if isinstance(node, ast.AsyncWith):
            opens = any(
                isinstance(item.context_expr, ast.Call)
                and getattr(item.context_expr.func, "id", None) == "collecting_wakes"
                for item in node.items
            )
            inside = inside or opens
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "apply"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "op"
            and not inside
        ):
            bad.append(node.lineno)
        for child in ast.iter_child_nodes(node):
            visit(child, inside)

    visit(tree, False)
    return bad


def test_operation_dispatch_sites_open_a_collector() -> None:
    found = 0
    problems: list[str] = []
    for rel in _DISPATCH_SITES:
        path = _BACKEND / rel
        src = path.read_text()
        found += textwrap.dedent(src).count("op.apply(")
        problems += [f"{rel}:{ln}" for ln in _apply_calls_outside_a_collector(path)]
    assert found >= 2, "the dispatch sites moved; update _DISPATCH_SITES"
    assert not problems, (
        "op.apply outside `async with collecting_wakes()`: an operation's own "
        f"collect_wake is a silent no-op there: {problems}"
    )
