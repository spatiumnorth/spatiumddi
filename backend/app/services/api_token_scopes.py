"""API token scopes — coarse-grained access vocabulary (issue #74).

Five well-known scopes that compose by union:

* ``read`` — restricts the token to safe-method requests only
  (``GET`` / ``HEAD`` / ``OPTIONS``), plus the POST routes that carry
  the :func:`read_only_post` marker (a filter / preview body, no mutation),
  plus the Operator Copilot MCP endpoint. Any other mutation is refused.
  A ``read`` token never makes SpatiumDDI send traffic outward (#3302):
  a GET carrying :func:`token_outbound` (a probe, a live pull from a
  managed server, an off-prem lookup) is refused to it. Over MCP, which
  only ``read`` admits, an ``outbound=True`` tool is hidden from every
  scoped token except one holding the write scope that covers the tool's
  REST equivalent (see :func:`scopes_allow_outbound_tool`).
* ``ipam:write`` — allows mutations under ``/api/v1/ipam``,
  ``/api/v1/vlans``, ``/api/v1/vrfs``, ``/api/v1/network-devices``.
  Read traffic anywhere is also allowed by ``read`` if combined.
* ``dns:write`` — allows mutations under ``/api/v1/dns`` (zones, records,
  server groups, views, RPZ blocklists and DNS pools all mount there).
  It does NOT cover the sibling mounts ``/api/v1/dnsbl`` (IP reputation
  lists) or ``/api/v1/dns-threat`` (threat analytics): those are separate
  products that merely share the ``dns`` spelling.
* ``dhcp:write`` — allows mutations under ``/api/v1/dhcp``.

Each write scope also covers the plainly-domain routes mounted elsewhere
(``_IPAM_PREFIXES`` and ``_ROUTE_RULES``), and the approve-and-provision
routes, which then check the stored operation's family at apply time
(:func:`enforce_operation_token_scope`, #3302).

Every prefix is matched on a whole path segment: ``/api/v1/dns`` covers
``/api/v1/dns`` and ``/api/v1/dns/...`` but not ``/api/v1/dnsbl/...``. A
scope grants only the surface it names, including for routers mounted later
whose prefix happens to start with the same letters.

There is no scope for the agent push surface (``/api/v1/dns/agents/*``,
``/api/v1/dhcp/agents/*``). Those routes authenticate with the agent's own
JWT or PSK and never reach the API-token resolver, so an ``sddi_*`` token
gets 401 there whatever it carries (#3302). An ``agent`` scope used to be
accepted at create time and reached nothing; it is retired (create / update
refuse it, see :data:`RETIRED_SCOPES`). A token that already stores it
cannot be made unrestricted by that: a non-empty scope list with no
matching scope is refused everywhere, so ``["agent"]`` stays a token that
can do nothing, and no migration rewrites it (stripping its only scope
would leave ``[]``, which means no restriction).

Empty ``scopes`` = no scope restriction (the existing RBAC path
is the only gate). Non-empty = enforced BEFORE RBAC at the auth
layer; a request that doesn't match any of the token's scopes
is refused 403 with ``token scope insufficient`` (the credential is valid,
so 401 — which tells a client to re-authenticate — would be wrong, #3223). Multiple scopes form a
union (any single match passes).

Why a closed vocabulary? Storing free-form strings would let an
operator scope a token to ``/api/v1/typo`` and silently lock
themselves out — the failure mode is delayed, surfaces as 401,
and gives no hint about the typo. The closed enum lets the create
endpoint reject the typo with 422 at issuance time.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

_READ_ONLY_POST_ATTR = "__token_read_only_post__"
_OUTBOUND_ATTR = "__token_outbound__"


def read_only_post[F: Callable[..., Any]](fn: F) -> F:
    """Mark a POST handler as read-only for the coarse token-scope gate.

    A ``read``-scoped token may call a marked route. Use it ONLY for a POST
    whose body is a filter / preview / dry-run input and which cannot change
    state: no row written (an audit row for the read excepted), no queued op,
    no outbound traffic or probe (a WinRM / API pull from a managed server
    counts as outbound). RBAC on the route is unchanged — this only
    stops the scope gate reading every POST as a write (#3223). Apply under
    the ``@router.post(...)`` decorator.
    """
    setattr(fn, _READ_ONLY_POST_ATTR, True)
    return fn


def is_read_only_post(endpoint: object) -> bool:
    return bool(getattr(endpoint, _READ_ONLY_POST_ATTR, False))


def token_outbound[F: Callable[..., Any]](fn: F) -> F:
    """Mark a safe-method handler as making SpatiumDDI send traffic outward.

    The counterpart of :func:`read_only_post` for the other direction: a
    ``read``-scoped token never makes SpatiumDDI contact another host
    (#3302), so the scope gate stops ``read`` covering a marked route even
    though it is a GET. Use it for a handler that probes a host, pulls live
    state from a managed server (AXFR, WinRM, a vendor or cloud API, a
    backup destination, an appliance's kubeapi through the supervisor) or
    looks something up off-prem (RIPEstat, PeeringDB, crt.sh). A write
    scope whose prefix covers the path still admits it, as does an
    unrestricted token; RBAC on the route is unchanged. Apply under the
    ``@router.get(...)`` decorator.
    """
    setattr(fn, _OUTBOUND_ATTR, True)
    return fn


def is_token_outbound(endpoint: object) -> bool:
    return bool(getattr(endpoint, _OUTBOUND_ATTR, False))


# Vocabulary — values stored verbatim in ``api_token.scopes``. Any
# new entry needs a matching branch in ``scope_matches_request``.
TOKEN_SCOPE_VOCABULARY: frozenset[str] = frozenset(
    {
        "read",
        "ipam:write",
        "dns:write",
        "dhcp:write",
    }
)

# Scopes that were once accepted and are now refused at create / update
# with an explanation. Stored rows may still carry them; the gate treats
# them as matching nothing (never as "no restriction").
RETIRED_SCOPES: dict[str, str] = {
    "agent": (
        "the 'agent' scope was retired: the agent push surface "
        "(/api/v1/dns/agents, /api/v1/dhcp/agents) authenticates with the "
        "agent's own JWT or pre-shared key, never an API token, so the scope "
        "reached nothing"
    ),
}

_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# The scopes that grant mutations (and the values ``Tool.outbound_scope``
# may name).
WRITE_SCOPES: frozenset[str] = frozenset({"ipam:write", "dns:write", "dhcp:write"})

# Path-prefix vocabulary per scope. Prefixes are matched on a whole path
# segment (see ``_path_under``) against the request path *with* the
# ``/api/v1`` mount, so the leading ``/api/v1`` is included.
_IPAM_PREFIXES: tuple[str, ...] = (
    "/api/v1/ipam",
    "/api/v1/vlans",
    "/api/v1/vrfs",
    "/api/v1/network-devices",
    # Plainly-IPAM surfaces mounted outside /api/v1/ipam (#3302).
    "/api/v1/address-sets",
    "/api/v1/multicast",
    "/api/v1/av/flows",
    "/api/v1/av/reserved-ranges",
    # Custom-field definitions are for ip_space / ip_block / subnet /
    # ip_address only, so they are IPAM's.
    "/api/v1/custom-fields",
)
# Single routes (method + path) that belong to a write scope without their
# whole router being covered (#3302). A prefix would widen the scope onto the
# siblings that share it: ``/nmap`` scan creation is an active probe, and
# ``/acme/update`` is the acme-dns client's own credential, not an operator.
# Each entry is ``(scope, method, path regex)``, matched whole (``fullmatch``).
_ROUTE_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("ipam:write", "POST", re.compile(r"/api/v1/nmap/scans/[^/]+/stamp-discovered")),
    ("dns:write", "POST", re.compile(r"/api/v1/acme/register")),
    ("dns:write", "DELETE", re.compile(r"/api/v1/acme/accounts/[^/]+")),
    # Registered-domain (RDAP / expiry) inventory, except the synchronous
    # RDAP refresh: an off-prem lookup needs an unrestricted token, as
    # ``lookup_whois_domain`` does over MCP.
    ("dns:write", "*", re.compile(r"/api/v1/domains(?:/(?![^/]+/refresh-whois\Z).*)?")),
    # Blocks a MAC across DHCP groups; also needs ``write dhcp_mac_block`` RBAC.
    ("dhcp:write", "POST", re.compile(r"/api/v1/new-devices/block")),
)

# Approve-and-provision routes. A scoped token may enter any of them holding
# ANY write scope; the handler then checks the scope of the OPERATION's own
# family (:func:`enforce_operation_token_scope`). The route gate cannot, since
# the family is in the stored request, not the path.
_APPLY_TIME_ROUTES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("POST", re.compile(r"/api/v1/requests")),
    ("POST", re.compile(r"/api/v1/requests/[^/]+/(approve|reject|cancel)")),
    ("POST", re.compile(r"/api/v1/change-requests/[^/]+/(approve|reject|cancel)")),
    ("POST", re.compile(r"/api/v1/ai/proposals/[^/]+/apply")),
)

# Registered operation -> the write scope covering its REST twin. Keyed by
# name, not by ``Operation.category``: ``allowlist_mac`` is category ``ipam``
# but its REST route (/new-devices) is in no scope. An operation absent here
# needs an unrestricted token.
OPERATION_WRITE_SCOPE: dict[str, str] = {
    **dict.fromkeys(
        (
            "allocate_subnet",
            "create_ip_address",
            "create_address_set",
            "delete_subnet",
            "delete_block",
            "delete_space",
            "commit_netbox_import",
            "create_multicast_group",
            "allocate_multicast_groups",
            "create_multicast_domain",
            "update_multicast_domain",
            "delete_multicast_domain",
        ),
        "ipam:write",
    ),
    **dict.fromkeys(
        (
            "create_dns_record",
            "create_dns_zone",
            "delete_zone",
            "sign_zone_dnssec",
            "unsign_zone_dnssec",
            "set_zone_update_acl",
            "commit_dns_import",
        ),
        "dns:write",
    ),
    **dict.fromkeys(
        (
            "create_dhcp_static",
            "delete_scope",
            "delete_group",
            "commit_dhcp_import",
            "allowlist_ra_router",
            "block_mac",
        ),
        "dhcp:write",
    ),
}

# DNS pools are served under ``/api/v1/dns/pools``; nothing is mounted at
# ``/api/v1/dns-pools``, so it is not listed.
_DNS_PREFIXES: tuple[str, ...] = ("/api/v1/dns",)
_DHCP_PREFIXES: tuple[str, ...] = ("/api/v1/dhcp",)
# Agent routes are nested under the dns / dhcp prefixes but authenticate
# without an API token; the write scopes must not be read as covering them.
_AGENT_PREFIXES: tuple[str, ...] = (
    "/api/v1/dns/agents",
    "/api/v1/dhcp/agents",
)
# Operator Copilot — MCP endpoint accepts POST under JSON-RPC, so it
# doesn't fit the generic GET = read mapping. Tokens with ``read`` scope
# may POST here because the MCP transport never dispatches a write or
# ``propose_*`` tool, and for a scoped token it also hides the tools
# registered ``outbound=True`` (``app.api.v1.ai.mcp._mcp_tool_names``).
_MCP_PREFIXES: tuple[str, ...] = ("/api/v1/ai/mcp",)


def _path_under(path: str, prefixes: tuple[str, ...]) -> bool:
    """True when ``path`` is one of ``prefixes`` or lies beneath one of
    them by whole path segment. ``/api/v1/dns`` matches ``/api/v1/dns`` and
    ``/api/v1/dns/zones`` but not ``/api/v1/dnsbl`` or ``/api/v1/dns-threat``.
    """
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def _route_rule_matches(scope: str, method: str, path: str) -> bool:
    return any(
        s == scope and m in ("*", method) and rx.fullmatch(path) for s, m, rx in _ROUTE_RULES
    )


def _apply_time_route(method: str, path: str) -> bool:
    return any(m == method and rx.fullmatch(path) for m, rx in _APPLY_TIME_ROUTES)


def enforce_operation_token_scope(request: object, operation_name: str) -> None:
    """Apply-time scope check for the approve-and-provision routes (#3302).

    The route gate admits a write-scoped token to ``/requests``,
    ``/change-requests/*/{approve,reject,cancel}`` and
    ``/ai/proposals/*/apply`` without knowing which domain the stored
    operation touches. This closes that: a scoped token must hold the write
    scope of the operation's own family, else 403 naming it. An operation
    with no family scope (``OPERATION_WRITE_SCOPE``) needs an unrestricted
    token. No-op for a session or an unrestricted token (``request.state``
    carries no scopes, or an empty list). RBAC is separate and unchanged.
    Reject and cancel are held to the same family rule: they change no
    domain, but they decide a request for that family, and a token that
    could not have made or applied it has no business ending it.
    """
    state = getattr(request, "state", None)
    scopes: list[str] = list(getattr(state, "api_token_scopes", None) or [])
    if not scopes:
        return
    needed = OPERATION_WRITE_SCOPE.get(operation_name)
    if needed is not None and needed in scopes:
        return
    from fastapi import HTTPException, status  # noqa: PLC0415

    what = (
        f"the {needed} scope"
        if needed
        else "an unrestricted token (no write scope covers this operation)"
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Token scope insufficient: operation '{operation_name}' needs {what}",
    )


def scopes_allow_outbound_tool(scopes: list[str], outbound_scope: str | None) -> bool:
    """Whether a token with these ``scopes`` may run an ``outbound=True``
    MCP tool whose ``Tool.outbound_scope`` is ``outbound_scope`` (#3302).

    Unrestricted (empty ``scopes``): yes. A scoped token reaches MCP only
    through ``read``, and a ``read`` token never makes SpatiumDDI send
    traffic outward, so it gets the tool only when it also holds the write
    scope covering the tool's REST equivalent — the same token the REST
    route admits (``find_dns_zone_drift`` with ``dns:write``, as
    ``GET /dns/.../drift``). A tool with no such scope (a probe, whose REST
    route is ``/tools/*``; an off-prem lookup) needs an unrestricted token,
    as its REST route does. A session (no token at all) is not subject to
    this.
    """
    return not scopes or (outbound_scope is not None and outbound_scope in scopes)


def scope_matches_request(
    scopes: list[str],
    method: str,
    path: str,
    *,
    read_only_route: bool = False,
    outbound_route: bool = False,
) -> bool:
    """Decide whether a token with these ``scopes`` can serve the
    request. Empty ``scopes`` always passes (no restriction).

    ``read_only_route`` is True when the matched handler carries
    :func:`read_only_post`; ``read`` then covers it like a safe method, for
    a POST only. The marker is a statement about one POST handler, so it
    never lets ``read`` reach a PUT / PATCH / DELETE, even if the same
    function were ever registered for one.

    ``outbound_route`` is True when the matched handler carries
    :func:`token_outbound`; ``read`` then does NOT cover it, whatever the
    method. A write scope whose prefix covers the path still does.

    Returns True on first match — scopes union, not intersect.
    """
    if not scopes:
        return True
    method = method.upper()
    is_safe = method in _SAFE_METHODS
    read_only_post_request = read_only_route and method == "POST"
    for scope in scopes:
        if scope == "read" and outbound_route:
            continue
        if scope == "read" and (is_safe or read_only_post_request):
            return True
        # The MCP transport dispatches no write / propose tool, and hides
        # outbound tools from a read-only token — so a JSON-RPC POST to
        # ``/api/v1/ai/mcp`` is fine under ``read``.
        if scope == "read" and _path_under(path, _MCP_PREFIXES):
            return True
        if scope in WRITE_SCOPES and _route_rule_matches(scope, method, path):
            return True
        if scope in WRITE_SCOPES and _apply_time_route(method, path):
            return True
        if scope == "ipam:write" and _path_under(path, _IPAM_PREFIXES):
            return True
        if scope == "dns:write" and _path_under(path, _DNS_PREFIXES):
            # Agent paths are nested under /api/v1/dns/* — no token scope
            # covers them (they take the agent's own credential).
            if _path_under(path, _AGENT_PREFIXES):
                continue
            return True
        if scope == "dhcp:write" and _path_under(path, _DHCP_PREFIXES):
            if _path_under(path, _AGENT_PREFIXES):
                continue
            return True
        # Any other value (a retired ``agent`` left in a stored row) matches
        # nothing: the list is non-empty, so the token is not unrestricted.
    return False


def validate_scopes(scopes: list[str]) -> list[str]:
    """Return the de-duplicated list if every entry is in the
    vocabulary; raise ``ValueError`` otherwise. Used by the
    create / update endpoints + by Pydantic field_validator.
    """
    retired = [s for s in scopes if s in RETIRED_SCOPES]
    if retired:
        raise ValueError("; ".join(RETIRED_SCOPES[s] for s in dict.fromkeys(retired)))
    invalid = [s for s in scopes if s not in TOKEN_SCOPE_VOCABULARY]
    if invalid:
        raise ValueError(
            f"Unknown scope(s): {', '.join(invalid)}. "
            f"Allowed: {', '.join(sorted(TOKEN_SCOPE_VOCABULARY))}"
        )
    # Preserve order but dedupe.
    seen: set[str] = set()
    out: list[str] = []
    for s in scopes:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


# Per-token resource-grant vocabulary (issue #374). Only the resource types
# whose handlers actually enforce token binding are accepted — minting a
# block-scoped token that isn't enforced would give a false sense of security.
TOKEN_GRANT_RESOURCE_TYPES: frozenset[str] = frozenset({"subnet", "dns_zone"})
TOKEN_GRANT_ACTIONS: frozenset[str] = frozenset({"read", "write", "delete", "admin", "*"})


def validate_resource_grant_shape(grants: list[dict]) -> list[dict]:
    """Shape-validate per-token resource grants (issue #374).

    Pure validation — no DB. Each entry must be
    ``{action, resource_type, resource_id}`` with a known action + an
    enforced resource_type + a non-empty resource_id. The create handler does
    the DB-existence + "issuing user must hold this grant" checks on top.
    """
    out: list[dict] = []
    for g in grants:
        if not isinstance(g, dict):
            raise ValueError("each resource grant must be an object")
        action = g.get("action")
        rtype = g.get("resource_type")
        rid = g.get("resource_id")
        if action not in TOKEN_GRANT_ACTIONS:
            raise ValueError(
                f"grant action {action!r} invalid; allowed: "
                f"{', '.join(sorted(TOKEN_GRANT_ACTIONS))}"
            )
        if rtype not in TOKEN_GRANT_RESOURCE_TYPES:
            raise ValueError(
                f"grant resource_type {rtype!r} invalid; allowed: "
                f"{', '.join(sorted(TOKEN_GRANT_RESOURCE_TYPES))}"
            )
        if not rid or not str(rid).strip():
            raise ValueError("grant resource_id is required (token must bind to an instance)")
        out.append({"action": action, "resource_type": rtype, "resource_id": str(rid)})
    return out


__all__ = [
    "OPERATION_WRITE_SCOPE",
    "TOKEN_GRANT_ACTIONS",
    "TOKEN_GRANT_RESOURCE_TYPES",
    "TOKEN_SCOPE_VOCABULARY",
    "is_read_only_post",
    "is_token_outbound",
    "read_only_post",
    "enforce_operation_token_scope",
    "scope_matches_request",
    "scopes_allow_outbound_tool",
    "token_outbound",
    "validate_resource_grant_shape",
    "validate_scopes",
]
