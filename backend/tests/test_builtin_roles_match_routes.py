"""The built-in roles are held to the routes they are meant to open (#1861, #1862).

A role is a list of ``(action, resource_type)`` grants, and a route enforces
one or more of those pairs. Nothing tied the two together, so they drifted
without any test noticing:

* the Auditor was granted ``read`` on ``audit`` while every audit-log route
  checks ``read`` on ``audit_log``, so the grant matched nothing and the
  role's own description ("read on audit log") was false (#1862);
* the DHCP Editor and DNS Editor promised "Full CRUD" on their resources while
  134 of the 147 DNS / DHCP write routes also took ``SuperAdmin``, so the
  grants opened reads and nothing else (#1861).

This walks every route the app serves and records, per route, whether it
takes ``SuperAdmin`` and which ``(action, resource_type)`` alternatives each
of its permission dependencies accepts (the permission factories in
``app.core.permissions`` record them in ``spatium_requires``). Each built-in
role's grants are then evaluated against that table, the way the server
evaluates them, and held to:

* ``PROMISES`` — the routes each role's description says it can use. Every
  one must be reachable on the role's grants alone;
* the reverse — every write grant a role in ``PROMISES`` holds must be used by
  one of its promised routes, so a grant cannot outlive the promise it was for;
* ``OPEN_DNS_DHCP_WRITES`` — the complete list of DNS / DHCP write routes a
  non-superadmin may reach. Any other write route under ``/dns`` or ``/dhcp``
  must take ``SuperAdmin``, so a new route is classified on purpose rather
  than opened, or closed, by accident.

Inline handler checks (a superadmin-only zone field, ``?permanent=true``) are
not visible here; the behavioural API tests in
``test_dns_dhcp_editor_roles.py`` cover those. When you change a role, a route
gate or a role description, change this file with it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

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

_DNS = "/api/v1/dns"
_DHCP = "/api/v1/dhcp"
_TLS = "/api/v1/appliance/tls"
_ACME = "/api/v1/appliance/acme"

# What each role's description promises, as routes. Keep this next to the
# description in ``app.main._BUILTIN_ROLES``: the description is the prose,
# this is the claim the tests hold the server to.
PROMISES: dict[str, list[tuple[str, str]]] = {
    "DNS Editor": [
        # zones
        ("POST", f"{_DNS}/groups/{{group_id}}/zones"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/from-template"),
        ("PUT", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}"),
        ("DELETE", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/import/commit"),
        # #2139 — the spreadsheet import edits records the way the zone-file
        # import does, so it is the same promise.
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/import/spreadsheet/commit"),
        # records
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/records"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/records/bulk-create"),
        ("PUT", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/records/{{record_id}}"),
        ("DELETE", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/records/{{record_id}}"),
        # views + ACLs
        ("POST", f"{_DNS}/groups/{{group_id}}/views"),
        ("PUT", f"{_DNS}/groups/{{group_id}}/views/{{view_id}}"),
        ("DELETE", f"{_DNS}/groups/{{group_id}}/views/{{view_id}}"),
        ("POST", f"{_DNS}/groups/{{group_id}}/acls"),
        ("PUT", f"{_DNS}/groups/{{group_id}}/acls/{{acl_id}}"),
        ("DELETE", f"{_DNS}/groups/{{group_id}}/acls/{{acl_id}}"),
        # blocklist entries + exceptions
        ("POST", f"{_DNS}/blocklists/{{list_id}}/entries"),
        ("POST", f"{_DNS}/blocklists/{{list_id}}/entries/bulk"),
        ("PUT", f"{_DNS}/blocklists/{{list_id}}/entries/{{entry_id}}"),
        ("DELETE", f"{_DNS}/blocklists/{{list_id}}/entries/{{entry_id}}"),
        ("POST", f"{_DNS}/blocklists/{{list_id}}/exceptions"),
        ("PUT", f"{_DNS}/blocklists/{{list_id}}/exceptions/{{exception_id}}"),
        ("DELETE", f"{_DNS}/blocklists/{{list_id}}/exceptions/{{exception_id}}"),
        # reads
        ("GET", f"{_DNS}/groups"),
        ("GET", f"{_DNS}/blocklists"),
        ("GET", f"{_DNS}/pools/{{pool_id}}"),
        # #3067 — the TLS certificate store DoT / DoH / DoQ serve from
        ("GET", f"{_TLS}"),
        ("POST", f"{_TLS}/upload"),
        ("POST", f"{_TLS}/csr"),
        ("POST", f"{_TLS}/{{cert_id:uuid}}/import-cert"),
        ("DELETE", f"{_TLS}/{{cert_id:uuid}}"),
        ("PUT", f"{_ACME}/account"),
        ("POST", f"{_ACME}/issue"),
        ("GET", f"{_ACME}/orders"),
    ],
    "DHCP Editor": [
        # scopes
        ("POST", f"{_DHCP}/subnets/{{subnet_id}}/dhcp-scopes"),
        ("PUT", f"{_DHCP}/scopes/{{scope_id}}"),
        ("DELETE", f"{_DHCP}/scopes/{{scope_id}}"),
        # pools
        ("POST", f"{_DHCP}/scopes/{{scope_id}}/pools"),
        ("PUT", f"{_DHCP}/pools/{{pool_id}}"),
        ("DELETE", f"{_DHCP}/pools/{{pool_id}}"),
        # static assignments
        ("POST", f"{_DHCP}/scopes/{{scope_id}}/statics"),
        ("PUT", f"{_DHCP}/statics/{{static_id}}"),
        ("DELETE", f"{_DHCP}/statics/{{static_id}}"),
        # client classes + device policies
        ("POST", f"{_DHCP}/server-groups/{{group_id}}/client-classes"),
        ("PUT", f"{_DHCP}/client-classes/{{class_id}}"),
        ("DELETE", f"{_DHCP}/client-classes/{{class_id}}"),
        ("POST", f"{_DHCP}/server-groups/{{group_id}}/device-policies"),
        ("PUT", f"{_DHCP}/device-policies/{{policy_id}}"),
        ("DELETE", f"{_DHCP}/device-policies/{{policy_id}}"),
        # option templates
        ("POST", f"{_DHCP}/server-groups/{{group_id}}/option-templates"),
        ("PUT", f"{_DHCP}/option-templates/{{template_id}}"),
        ("DELETE", f"{_DHCP}/option-templates/{{template_id}}"),
        ("POST", f"{_DHCP}/scopes/{{scope_id}}/apply-option-template"),
        # phone + PXE profiles
        ("POST", f"{_DHCP}/server-groups/{{group_id}}/phone-profiles"),
        ("POST", f"{_DHCP}/server-groups/{{group_id}}/phone-profiles/seed-starter-pack"),
        ("PUT", f"{_DHCP}/phone-profiles/{{profile_id}}"),
        ("PUT", f"{_DHCP}/phone-profiles/{{profile_id}}/scopes"),
        ("DELETE", f"{_DHCP}/phone-profiles/{{profile_id}}"),
        ("POST", f"{_DHCP}/server-groups/{{group_id}}/pxe-profiles"),
        ("PUT", f"{_DHCP}/pxe-profiles/{{profile_id}}"),
        ("DELETE", f"{_DHCP}/pxe-profiles/{{profile_id}}"),
        # MAC blocks
        ("POST", f"{_DHCP}/server-groups/{{group_id}}/mac-blocks"),
        ("PUT", f"{_DHCP}/mac-blocks/{{block_id}}"),
        ("DELETE", f"{_DHCP}/mac-blocks/{{block_id}}"),
        # rogue-responder + router-advertisement findings
        ("POST", f"{_DHCP}/groups/{{group_id}}/responders/{{responder_id}}/acknowledge"),
        (
            "POST",
            f"{_DHCP}/ra/groups/{{group_id}}/observed-routers/{{router_id}}/acknowledge",
        ),
        ("POST", f"{_DHCP}/ra/groups/{{group_id}}/ra-allowlist"),
        ("DELETE", f"{_DHCP}/ra/groups/{{group_id}}/ra-allowlist/{{entry_id}}"),
        # reads
        ("GET", f"{_DHCP}/server-groups"),
        ("GET", f"{_DHCP}/servers"),
    ],
    "Auditor": [
        ("GET", "/api/v1/audit"),
        ("GET", "/api/v1/audit/integrity"),
    ],
    "Compliance Editor": [
        ("GET", "/api/v1/audit"),
        ("GET", "/api/v1/audit/integrity"),
    ],
}

# Every DNS / DHCP write route a non-superadmin may reach. The everyday data
# writes are the Editor roles' promises; the rest predate #1861 and are
# listed so the "everything else is superadmin" assertion below is exact.
OPEN_DNS_DHCP_WRITES: frozenset[tuple[str, str]] = frozenset(
    {
        (m, p)
        for role in ("DNS Editor", "DHCP Editor")
        for m, p in PROMISES[role]
        # The DNS Editor also promises the certificate store (#3067), which
        # lives under /appliance, not /dns.
        if m != "GET" and p.startswith((_DNS + "/", _DHCP + "/"))
    }
    | {
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/records/bulk-delete"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/delegate-from-parent"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/import/preview"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/import/spreadsheet/preview"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/sync-with-server"),
        ("POST", f"{_DNS}/tools/propagation-check"),
    }
)

# Infrastructure the Editor roles must NOT reach: a sample of each family the
# descriptions name as superadmin-only. The exhaustive version is
# ``test_every_other_dns_dhcp_write_is_superadmin_only``; this one says it in
# terms of the roles.
INFRASTRUCTURE: dict[str, list[tuple[str, str]]] = {
    "DNS Editor": [
        ("POST", f"{_DNS}/groups"),
        ("DELETE", f"{_DNS}/groups/{{group_id}}"),
        ("POST", f"{_DNS}/groups/{{group_id}}/servers"),
        ("PUT", f"{_DNS}/groups/{{group_id}}/options"),
        ("POST", f"{_DNS}/groups/{{group_id}}/tsig-keys"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/dnssec/sign"),
        ("POST", f"{_DNS}/dnssec-policies"),
        ("PUT", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/update-acl"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/move/commit"),
        ("POST", f"{_DNS}/blocklists"),
        ("POST", f"{_DNS}/blocklists/from-catalog"),
        ("PUT", f"{_DNS}/blocklists/{{list_id}}/assignments"),
        ("POST", f"{_DNS}/blocklists/{{list_id}}/refresh"),
        ("POST", f"{_DNS}/groups/{{group_id}}/zones/{{zone_id}}/pools"),
        ("POST", f"{_DNS}/import/bind9/commit"),
        # #3067 — the store, yes; making a cert the Web UI cert, no.
        ("POST", f"{_TLS}/{{cert_id:uuid}}/activate"),
    ],
    "DHCP Editor": [
        ("POST", f"{_DHCP}/server-groups"),
        ("DELETE", f"{_DHCP}/server-groups/{{group_id}}"),
        ("POST", f"{_DHCP}/servers"),
        ("PUT", f"{_DHCP}/servers/{{server_id}}"),
        ("POST", f"{_DHCP}/servers/{{server_id}}/sync"),
        ("POST", f"{_DHCP}/servers/test-windows-credentials"),
        ("POST", f"{_DHCP}/server-groups/{{group_id}}/failover/relationships"),
        ("DELETE", f"{_DHCP}/servers/{{server_id}}/leases/{{lease_id}}"),
        ("POST", f"{_DHCP}/import/kea/commit"),
    ],
}


# ── route table ────────────────────────────────────────────────────────────


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


Gate = tuple[bool, list[list[tuple[str, str]]]]


def route_table() -> dict[tuple[str, str], Gate]:
    """``{(method, path): (superadmin_only, [alternatives, ...])}``.

    Each entry of the list is one permission dependency, given as the
    ``(action, resource_type)`` pairs it accepts (any one passes). A request
    passes the route when it passes every dependency.
    """
    table: dict[tuple[str, str], Gate] = {}
    for r in _iter_routes(app.routes):
        calls = list(_dependency_calls(r.dependant))
        superadmin = any(c is require_superadmin for c in calls)
        for method in sorted(r.methods):
            if method in ("HEAD", "OPTIONS"):
                continue
            deps: list[list[tuple[str, str]]] = []
            for c in calls:
                req = getattr(c, "spatium_requires", None)
                if req is None:
                    continue
                # A per-route gate (the IPAM router, #3058) requires EVERY
                # type it maps the route to: one dependency per type. An
                # unclassified route admits no type-level grant at all.
                per_route = getattr(c, "spatium_route_requires", None)
                if per_route is not None:
                    needs = per_route(method, r.path)
                    action = _METHOD_TO_ACTION[method]
                    deps.extend([[(action, t)] for t in needs] if needs else [[]])
                    continue
                kind, items = req
                if kind == "exact":
                    deps.append(list(items))
                else:
                    deps.append([(_METHOD_TO_ACTION[method], t) for t in items])
            table[(method, r.path)] = (superadmin, deps)
    return table


def route_inventory() -> list[tuple[str, str, bool, set[tuple[str, str]]]]:
    """Flattened table: ``(method, path, superadmin_only, {pairs named})``."""
    return [
        (m, p, sup, {pair for dep in deps for pair in dep})
        for (m, p), (sup, deps) in route_table().items()
    ]


def _perms(role: str) -> list[dict[str, Any]]:
    return list(_BUILTIN_ROLES[role][1])


def _grants_pair(perms: list[dict[str, Any]], action: str, rtype: str) -> bool:
    return any(
        _action_matches(p["action"], action) and _resource_type_matches(p["resource_type"], rtype)
        for p in perms
    )


def role_can(table: dict[tuple[str, str], Gate], role: str, method: str, path: str) -> bool:
    """Whether a holder of only ``role`` passes the route's dependency gates."""
    sup, deps = table[(method, path)]
    perms = _perms(role)
    if any(p["action"] == "*" and p["resource_type"] == "*" for p in perms):
        return True
    if sup:
        return False
    return all(any(_grants_pair(perms, a, t) for a, t in dep) for dep in deps)


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
        if any(
            _action_matches(action, na) and _resource_type_matches(rtype, nt) for na, nt in needs
        )
    ]


@pytest.fixture(scope="module")
def table() -> dict[tuple[str, str], Gate]:
    return route_table()


# ── tests ──────────────────────────────────────────────────────────────────


def test_inventory_finds_the_routes(table) -> None:
    # A walker that finds nothing makes every assertion below vacuous.
    assert len(table) > 500
    for routes in (*PROMISES.values(), *INFRASTRUCTURE.values(), OPEN_DNS_DHCP_WRITES):
        missing = [r for r in routes if r not in table]
        assert not missing, f"routes named here that the app does not serve: {missing}"


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


@pytest.mark.parametrize("role", sorted(PROMISES))
def test_each_role_can_do_what_its_description_promises(table, role: str) -> None:
    refused = [f"{m} {p}" for m, p in PROMISES[role] if not role_can(table, role, m, p)]
    assert not refused, (
        f"the built-in {role} is refused routes its description promises "
        "(a superadmin-only handler, or a grant the route does not accept):\n" + "\n".join(refused)
    )


@pytest.mark.parametrize("role", sorted(PROMISES))
def test_each_write_grant_backs_a_promise(table, role: str) -> None:
    # The reverse direction: a write grant no promised route uses is a grant
    # the description does not account for, which is how "Full CRUD" outlived
    # the routes behind it.
    unused = []
    for p in _perms(role):
        if p["resource_type"] == "*" or p["resource_type"] in CHECKED_INLINE:
            continue
        if not any(_action_matches(p["action"], a) for a in ("write", "delete")):
            continue
        used = any(
            m != "GET"
            and any(
                _action_matches(p["action"], a) and _resource_type_matches(p["resource_type"], t)
                for dep in table[(m, path)][1]
                for a, t in dep
            )
            for m, path in PROMISES[role]
        )
        if not used:
            unused.append(f"{p['action']} on {p['resource_type']}")
    assert not unused, (
        f"the built-in {role} holds write grants none of its promised routes "
        "use; narrow the grant, or promise (and open) the route:\n" + "\n".join(unused)
    )


@pytest.mark.parametrize("role", sorted(INFRASTRUCTURE))
def test_editors_are_refused_infrastructure(table, role: str) -> None:
    reached = [f"{m} {p}" for m, p in INFRASTRUCTURE[role] if role_can(table, role, m, p)]
    assert not reached, f"the built-in {role} reaches infrastructure routes:\n" + "\n".join(reached)


def test_every_other_dns_dhcp_write_is_superadmin_only(table) -> None:
    unclassified = []
    for (m, p), (sup, _deps) in sorted(table.items()):
        if m == "GET" or not (p.startswith(_DNS + "/") or p.startswith(_DHCP + "/")):
            continue
        # Agent-facing routes authenticate the agent, not a user.
        if "/agents/" in p:
            continue
        if sup or (m, p) in OPEN_DNS_DHCP_WRITES:
            continue
        unclassified.append(f"{m} {p}")
    assert not unclassified, (
        "DNS / DHCP write routes a non-superadmin can reach that are not in "
        "OPEN_DNS_DHCP_WRITES; decide which they are:\n" + "\n".join(unclassified)
    )
    closed = [f"{m} {p}" for m, p in sorted(OPEN_DNS_DHCP_WRITES) if table[(m, p)][0]]
    assert not closed, "routes listed as open that take SuperAdmin:\n" + "\n".join(closed)


def test_opened_deletes_ask_for_delete(table) -> None:
    # A DELETE route open to the Editor roles must check ``delete``, not
    # ``write``: a role (or clone) granted write without delete must not be
    # able to remove what it can edit.
    wrong = []
    for m, p in sorted(OPEN_DNS_DHCP_WRITES):
        if m != "DELETE":
            continue
        for dep in table[(m, p)][1]:
            if any(a != "delete" for a, _t in dep):
                wrong.append(f"{m} {p}: {dep}")
    assert not wrong, "DELETE routes gated on something other than delete:\n" + "\n".join(wrong)


def test_the_audit_log_is_readable_by_the_roles_that_say_so() -> None:
    inv = route_inventory()
    audit_routes = [(m, p) for m, p, _s, needs in inv if ("read", "audit_log") in needs]
    assert audit_routes, "no route checks read on audit_log"
    for role in ("Auditor", "Compliance Editor"):
        assert _grants_pair(_perms(role), "read", "audit_log"), f"{role} cannot read the audit log"
