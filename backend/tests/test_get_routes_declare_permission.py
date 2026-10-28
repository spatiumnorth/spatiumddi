"""Every GET route declares the permission it reads under, or says why not.

A read route that takes only ``CurrentUser`` answers every signed-in account,
whatever its role grants. This walks the route table the app serves and
fails for any GET route that carries no permission dependency — a
``require_*permission`` factory from ``app.core.permissions`` (they record
what they enforce in ``spatium_requires``) or ``SuperAdmin`` — unless the
route is listed in ``NO_PERMISSION_DEPENDENCY`` below with the reason.

Valid reasons are narrow: the route is reachable before sign-in by design;
it is authenticated by something other than a user session (an agent JWT, a
signed URL, a feed token); it returns only the caller's own rows; it returns
static reference data or settings every signed-in screen needs; or the
handler performs the check itself. When the reason is the last one, say
where. A new read route over install data belongs behind a dependency, not
in this list.
"""

from __future__ import annotations

from app.api.deps import require_superadmin
from app.main import app
from tests.test_builtin_roles_match_routes import _dependency_calls, _iter_routes

_AGENT = "agent endpoint, authenticated by the agent's own JWT and mounted outside the user gates"
_PUBLIC = "reachable before sign-in by design"
_SELF = "returns only the caller's own rows"

NO_PERMISSION_DEPENDENCY: dict[str, str] = {
    # ── public / pre-sign-in ────────────────────────────────────────────
    "/.well-known/acme-challenge/{token}": "ACME HTTP-01 challenge the CA fetches",
    "/api/docs": "OpenAPI viewer shell, no install data; fetches the spec signed in (#2935)",
    "/api/redoc": "OpenAPI viewer shell, no install data; fetches the spec signed in (#2935)",
    "/api/openapi.json": "the API schema, any signed-in caller (#2935); no install data",
    "/api/v1/auth/password-policy": f"{_PUBLIC}: the change-password screen renders the policy",
    "/api/v1/auth/providers": f"{_PUBLIC}: the login page lists sign-in buttons",
    "/api/v1/auth/{provider_id}/authorize": f"{_PUBLIC}: OIDC / SAML redirect",
    "/api/v1/auth/{provider_id}/callback": f"{_PUBLIC}: OIDC callback",
    "/api/v1/auth/{provider_id}/metadata": f"{_PUBLIC}: SAML SP metadata",
    "/api/v1/settings/public": f"{_PUBLIC}: login banner + branding",
    "/api/v1/settings/public/logo": f"{_PUBLIC}: login page logo",
    "/api/v1/version": "version handshake; the version itself only when signed in (#2935)",
    "/health/live": "liveness probe",
    "/health/platform": "platform health probe; components only when signed in (#2935)",
    "/health/ready": "readiness probe",
    "/health/startup": "startup probe",
    # ── authenticated by something other than a user session ────────────
    "/api/v1/dns/agents/config": _AGENT,
    "/api/v1/dns/agents/record-ops": _AGENT,
    "/api/v1/dhcp/agents/config": _AGENT,
    "/api/v1/looking-glass/agents/config": _AGENT,
    "/api/v1/appliance/supervisor/tls-pins": "supervisor re-pin; signed by the CA, nothing secret",
    "/api/v1/appliance/upgrade-images/{image_id}/raw.xz": "signed ?t= download token",
    "/api/v1/appliance/slot-images": "redirect shim to /upgrade-images, gated there",
    "/api/v1/appliance/slot-images/{image_id}": "redirect shim to /upgrade-images, gated there",
    "/api/v1/appliance/slot-images/{image_id}/raw.xz": "redirect shim to the signed download",
    "/api/v1/firewall-feeds/feeds/{feed_id}/blocklist.txt": "authenticated by the feed's own token",
    "/api/v1/nmap/scans/{scan_id}/stream": (
        "SSE stream; resolves the user from its stream token and checks "
        "read on manage_nmap_scans in the handler"
    ),
    # ── the caller's own rows ───────────────────────────────────────────
    "/api/v1/ai/prompts": f"{_SELF} plus prompts marked shared",
    "/api/v1/ai/prompts/{prompt_id}": f"{_SELF} plus prompts marked shared",
    "/api/v1/ai/proposals": _SELF,
    "/api/v1/ai/proposals/{proposal_id}": _SELF,
    "/api/v1/ai/sessions": _SELF,
    "/api/v1/ai/sessions/{session_id}": _SELF,
    "/api/v1/ai/usage/me": _SELF,
    "/api/v1/api-tokens": f"{_SELF}; superadmin sees all (checked in the handler)",
    "/api/v1/api-tokens/{token_id}": f"{_SELF} (_require_owned)",
    "/api/v1/auth/me": _SELF,
    "/api/v1/auth/me/permissions": _SELF,
    "/api/v1/auth/mfa/status": _SELF,
    "/api/v1/change-requests": "own requests unless an approver (checked in the handler)",
    "/api/v1/change-requests/{cr_id}": "own request unless an approver (checked in the handler)",
    "/api/v1/requests": "own requests unless provisioning_request read (_require_read)",
    "/api/v1/requests/{req_id}": "checked in the handler (_require_read)",
    "/api/v1/requests/catalog": "checked in the handler (_require_submit)",
    "/api/v1/requests/resource-options": "checked in the handler (_require_submit + per-type read)",
    "/api/v1/saved-views": _SELF,
    "/api/v1/sessions/me": _SELF,
    # ── shell / static reference data every signed-in screen needs ──────
    "/api/v1/admin/feature-modules": "the sidebar reads which modules are on",
    "/api/v1/ai/available": "whether the copilot is configured, no install data",
    "/api/v1/ai/mcp": "MCP server info + the count of tools this caller may call",
    "/api/v1/api-tokens/enrolment-context": "the served TLS fingerprint, public on the wire",
    "/api/v1/dhcp/option-codes": "static RFC option-code catalogue, no install data",
    "/api/v1/dhcp/voip-options": "static VoIP vendor option catalogue, no install data",
    "/api/v1/webhooks/event-types": "static event-type catalogue",
    "/api/v1/search/types": "the searchable type list; filtered to the caller's grants",
    # ── platform-wide reads open to every signed-in user by design ──────
    "/api/v1/settings": "platform settings the UI shell reads on every screen",
    "/api/v1/settings/defaults": "column defaults for the settings form",
    "/api/v1/settings/resolver": "slice of GET /settings",
    "/api/v1/settings/oui/status": "OUI database status, no install data",
    "/api/v1/settings/oui/refresh/{task_id}": "status of an OUI refresh task",
    "/api/v1/groups": "group pickers (auth providers, groups page); writes need admin on group",
    "/api/v1/groups/{group_id}": "as /groups",
    "/api/v1/roles": "role picker on the groups page; writes need admin on role",
    "/api/v1/roles/{role_id}": "as /roles",
    "/api/v1/bgp/asn/{asn}/announced-prefixes": "public RIPEstat / PeeringDB data, no install data",
    "/api/v1/bgp/asn/{asn}/ixps": "public RIPEstat / PeeringDB data, no install data",
    "/api/v1/bgp/asn/{asn}/network": "public RIPEstat / PeeringDB data, no install data",
    "/api/v1/bgp/asn/{asn}/overview": "public RIPEstat / PeeringDB data, no install data",
    "/api/v1/bgp/prefix/origin": "public RIPEstat / PeeringDB data, no install data",
    "/api/v1/bgp/prefix/routing-history": "public RIPEstat / PeeringDB data, no install data",
    # ── checked in the handler ──────────────────────────────────────────
    "/api/v1/tags/keys": "unions only the tagged tables the caller may read (_readable_tables)",
    "/api/v1/tags/values": "unions only the tagged tables the caller may read (_readable_tables)",
    "/api/v1/search": "the search engine filters every result type by the caller's read grant",
    "/api/v1/dashboards/security/summary": "per-panel user_has_permission in the handler",
    "/api/v1/sessions": "superadmin sees all, others their own (checked in the handler)",
    "/api/v1/conformity/checks": "checked in the handler (_require_read)",
    "/api/v1/conformity/export.pdf": "checked in the handler (_require_read)",
    "/api/v1/conformity/policies": "checked in the handler (_require_read)",
    "/api/v1/conformity/policies/{policy_id}": "checked in the handler (_require_read)",
    "/api/v1/conformity/results": "checked in the handler (_require_read)",
    "/api/v1/conformity/summary": "checked in the handler (_require_read)",
    "/api/v1/appliance/firewall/aliases": "checked in the handler (_require_read)",
    "/api/v1/appliance/firewall/appliances/{appliance_id}/effective": (
        "checked in the handler (_require_read)"
    ),
    "/api/v1/appliance/firewall/enforcement": "checked in the handler (_require_read)",
    "/api/v1/appliance/firewall/policies": "checked in the handler (_require_read)",
    "/api/v1/appliance/firewall/policies/{policy_id}": "checked in the handler (_require_read)",
    "/api/v1/appliance/firewall/web-ui-access": "checked in the handler (_require_read)",
}


def _ungated_get_paths() -> set[str]:
    out: set[str] = set()
    for route in _iter_routes(app.routes):
        if "GET" not in route.methods:
            continue
        calls = list(_dependency_calls(route.dependant))
        if any(c is require_superadmin for c in calls):
            continue
        if any(getattr(c, "spatium_requires", None) is not None for c in calls):
            continue
        out.add(route.path)
    return out


def _all_get_paths() -> set[str]:
    return {r.path for r in _iter_routes(app.routes) if "GET" in r.methods}


def test_walker_sees_the_read_routes() -> None:
    # A walker that finds nothing makes the next test vacuous.
    paths = _all_get_paths()
    assert len(paths) > 400
    assert "/api/v1/dns/groups" in paths
    assert "/api/v1/dhcp/servers" in paths


def test_every_get_route_declares_a_permission_or_is_listed() -> None:
    missing = sorted(_ungated_get_paths() - NO_PERMISSION_DEPENDENCY.keys())
    assert not missing, (
        "GET routes with no permission dependency. Add require_permission / "
        "require_resource_permission (or SuperAdmin) for the resource they read, "
        f"or list them in NO_PERMISSION_DEPENDENCY with the reason: {missing}"
    )


def test_listed_routes_still_exist_and_are_still_ungated() -> None:
    # An entry for a route that has since gained a dependency, or gone, is
    # dead weight that would let a future route of that path through unread.
    stale = sorted(NO_PERMISSION_DEPENDENCY.keys() - _ungated_get_paths())
    assert not stale, f"remove these from NO_PERMISSION_DEPENDENCY: {stale}"


def test_every_listed_route_has_a_reason() -> None:
    assert all(reason.strip() for reason in NO_PERMISSION_DEPENDENCY.values())


def test_dns_dhcp_and_capture_reads_are_all_gated() -> None:
    # The operator-facing DNS, DHCP, packet-capture and scan surfaces: every
    # read carries a dependency except the agent routes and two static
    # catalogues, which are listed above with their reasons.
    prefixes = ("/api/v1/dns", "/api/v1/dhcp", "/api/v1/pcap", "/api/v1/nmap", "/api/v1/metrics")
    ungated = {p for p in _ungated_get_paths() if p.startswith(prefixes)}
    allowed = {
        "/api/v1/dns/agents/config",
        "/api/v1/dns/agents/record-ops",
        "/api/v1/dhcp/agents/config",
        "/api/v1/dhcp/option-codes",
        "/api/v1/dhcp/voip-options",
        "/api/v1/nmap/scans/{scan_id}/stream",
    }
    assert ungated <= allowed, sorted(ungated - allowed)
