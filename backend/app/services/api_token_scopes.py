"""API token scopes — coarse-grained access vocabulary (issue #74).

Five well-known scopes that compose by union:

* ``read`` — restricts the token to safe-method requests only
  (``GET`` / ``HEAD`` / ``OPTIONS``). Any mutation 401s.
* ``ipam:write`` — allows mutations under ``/api/v1/ipam``,
  ``/api/v1/vlans``, ``/api/v1/vrfs``, ``/api/v1/network-devices``.
  Read traffic anywhere is also allowed by ``read`` if combined.
* ``dns:write`` — allows mutations under ``/api/v1/dns`` (zones, records,
  server groups, views, RPZ blocklists and DNS pools all mount there).
  It does NOT cover the sibling mounts ``/api/v1/dnsbl`` (IP reputation
  lists) or ``/api/v1/dns-threat`` (threat analytics): those are separate
  products that merely share the ``dns`` spelling.
* ``dhcp:write`` — allows mutations under ``/api/v1/dhcp``.

Every prefix is matched on a whole path segment: ``/api/v1/dns`` covers
``/api/v1/dns`` and ``/api/v1/dns/...`` but not ``/api/v1/dnsbl/...``. A
scope grants only the surface it names, including for routers mounted later
whose prefix happens to start with the same letters.
* ``agent`` — allows the agent push surface
  (``/api/v1/dns/agents/*``, ``/api/v1/dhcp/agents/*``) only.
  Used by the BIND9 / Kea sidecar agents that bootstrap with
  PSK + JWT but can also be issued plain API tokens for ops
  testing.

Empty ``scopes`` = no scope restriction (the existing RBAC path
is the only gate). Non-empty = enforced BEFORE RBAC at the auth
layer; a request that doesn't match any of the token's scopes
401s with ``token scope insufficient``. Multiple scopes form a
union (any single match passes).

Why a closed vocabulary? Storing free-form strings would let an
operator scope a token to ``/api/v1/typo`` and silently lock
themselves out — the failure mode is delayed, surfaces as 401,
and gives no hint about the typo. The closed enum lets the create
endpoint reject the typo with 422 at issuance time.
"""

from __future__ import annotations

# Vocabulary — values stored verbatim in ``api_token.scopes``. Any
# new entry needs a matching branch in ``scope_matches_request``.
TOKEN_SCOPE_VOCABULARY: frozenset[str] = frozenset(
    {
        "read",
        "ipam:write",
        "dns:write",
        "dhcp:write",
        "agent",
    }
)

_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# Path-prefix vocabulary per scope. Prefixes are matched on a whole path
# segment (see ``_path_under``) against the request path *with* the
# ``/api/v1`` mount, so the leading ``/api/v1`` is included.
_IPAM_PREFIXES: tuple[str, ...] = (
    "/api/v1/ipam",
    "/api/v1/vlans",
    "/api/v1/vrfs",
    "/api/v1/network-devices",
)
# DNS pools are served under ``/api/v1/dns/pools``; nothing is mounted at
# ``/api/v1/dns-pools``, so it is not listed.
_DNS_PREFIXES: tuple[str, ...] = ("/api/v1/dns",)
_DHCP_PREFIXES: tuple[str, ...] = ("/api/v1/dhcp",)
_AGENT_PREFIXES: tuple[str, ...] = (
    "/api/v1/dns/agents",
    "/api/v1/dhcp/agents",
)
# Operator Copilot — MCP endpoint accepts POST under JSON-RPC, so it
# doesn't fit the generic GET = read mapping. Tokens with ``read`` scope
# may POST here because every Wave 2 tool is read-only. Phase 3 adds an
# ``mcp:write`` scope to gate write-tool calls.
_MCP_PREFIXES: tuple[str, ...] = ("/api/v1/ai/mcp",)


def _path_under(path: str, prefixes: tuple[str, ...]) -> bool:
    """True when ``path`` is one of ``prefixes`` or lies beneath one of
    them by whole path segment. ``/api/v1/dns`` matches ``/api/v1/dns`` and
    ``/api/v1/dns/zones`` but not ``/api/v1/dnsbl`` or ``/api/v1/dns-threat``.
    """
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def scope_matches_request(scopes: list[str], method: str, path: str) -> bool:
    """Decide whether a token with these ``scopes`` can serve the
    request. Empty ``scopes`` always passes (no restriction).

    Returns True on first match — scopes union, not intersect.
    """
    if not scopes:
        return True
    method = method.upper()
    is_safe = method in _SAFE_METHODS
    for scope in scopes:
        if scope == "read" and is_safe:
            return True
        # MCP tools are read-only in Wave 2 — any safe method or a
        # JSON-RPC POST to ``/api/v1/ai/mcp`` is fine under ``read``.
        if scope == "read" and _path_under(path, _MCP_PREFIXES):
            return True
        if scope == "ipam:write" and _path_under(path, _IPAM_PREFIXES):
            return True
        if scope == "dns:write" and _path_under(path, _DNS_PREFIXES):
            # Agent paths are nested under /api/v1/dns/* — explicitly
            # require the ``agent`` scope for those rather than
            # letting ``dns:write`` cover them too.
            if _path_under(path, _AGENT_PREFIXES):
                continue
            return True
        if scope == "dhcp:write" and _path_under(path, _DHCP_PREFIXES):
            if _path_under(path, _AGENT_PREFIXES):
                continue
            return True
        if scope == "agent" and _path_under(path, _AGENT_PREFIXES):
            return True
    return False


def validate_scopes(scopes: list[str]) -> list[str]:
    """Return the de-duplicated list if every entry is in the
    vocabulary; raise ``ValueError`` otherwise. Used by the
    create / update endpoints + by Pydantic field_validator.
    """
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
    "TOKEN_GRANT_ACTIONS",
    "TOKEN_GRANT_RESOURCE_TYPES",
    "TOKEN_SCOPE_VOCABULARY",
    "scope_matches_request",
    "validate_resource_grant_shape",
    "validate_scopes",
]
