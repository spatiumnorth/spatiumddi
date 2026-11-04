"""Every POST / PUT / PATCH / DELETE route declares the permission it needs (#3476).

The write-side twin of ``test_get_routes_declare_permission.py``, built on the
same walk and the same notion of "gated" (``route_is_gated``): the route, or
the router it is mounted on, carries ``SuperAdmin`` or a ``require_*permission``
dependency from ``app.core.permissions``. A ``require_module`` gate is a feature
switch, not a permission, and does not count.

A route with no such dependency must be listed in ``NO_PERMISSION_DEPENDENCY``
with a narrow reason, or in ``KNOWN_UNGATED`` when it is a defect waiting for
its own fix. Keys are ``"METHOD /path"``. Valid reasons: reachable before
sign-in by design; authenticated by something other than a user session (an
agent / supervisor credential); acts only on the caller's own rows; or the
handler or the service it calls performs the check, in which case the entry
says where. The route tests in ``test_read_only_post_rbac_3302.py`` and
``test_operation_permission_declared.py`` cover the read-only-POST scope and the
Copilot operation registry; neither walks the route table.

``declared_gate`` reports what each gated route requires, so a later check can
compare it with what the frontend gates on.
"""

from __future__ import annotations

from typing import Any

from app.api.deps import require_superadmin
from app.core.permissions import _METHOD_TO_ACTION
from app.main import app
from tests.test_builtin_roles_match_routes import _dependency_calls, _iter_routes
from tests.test_get_routes_declare_permission import route_is_gated

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

_PUBLIC = "reachable before sign-in by design"
_SELF = "acts only on the caller's own rows"
_AGENT_PSK = "agent registration, authenticated by the bootstrap PSK (_require_bootstrap_key)"
_AGENT_JWT = "agent endpoint, authenticated by the agent's own JWT (_auth_agent)"
_SUP_CERT = "supervisor endpoint, authenticated by its mTLS client cert (_require_cert_auth)"
_SUP_SESSION = "supervisor endpoint, authenticated by its pairing session token"
_SETTINGS = "checked inline: user_has_permission(user, 'write', 'settings') in the handler"
_SESSION = f"{_SELF}; the handler admits any signed-in caller"

NO_PERMISSION_DEPENDENCY: dict[str, str] = {
    # ── public / pre-sign-in ────────────────────────────────────────────
    "POST /api/v1/auth/login": _PUBLIC,
    "POST /api/v1/auth/login/mfa": f"{_PUBLIC}: second step, proven by the MFA flow token",
    "POST /api/v1/auth/refresh": f"{_PUBLIC}: authenticated by the refresh cookie",
    "POST /api/v1/auth/{provider_id}/callback": f"{_PUBLIC}: SAML ACS, signed assertion",
    "POST /api/v1/acme/update": "acme-dns API, authenticated by the per-account credentials (_auth_acme)",
    "DELETE /api/v1/acme/update": "acme-dns API, authenticated by the per-account credentials (_auth_acme)",
    "POST /held/self": (
        "HELD self-query: off unless E911_SELF_QUERY_ENABLED, answers by TCP "
        "source address only, rate-limited fail-closed (held_router.py)"
    ),
    # ── authenticated by something other than a user session ────────────
    "POST /api/v1/dns/agents/register": _AGENT_PSK,
    "POST /api/v1/dhcp/agents/register": _AGENT_PSK,
    "POST /api/v1/looking-glass/agents/register": _AGENT_PSK,
    "POST /api/v1/dns/agents/heartbeat": _AGENT_JWT,
    "POST /api/v1/dns/agents/ops/{op_id}/ack": _AGENT_JWT,
    "POST /api/v1/dns/agents/zone-state": _AGENT_JWT,
    "POST /api/v1/dns/agents/ingested-records": _AGENT_JWT,
    "POST /api/v1/dns/agents/dnssec-state": _AGENT_JWT,
    "POST /api/v1/dns/agents/metrics": _AGENT_JWT,
    "POST /api/v1/dns/agents/query-log-entries": _AGENT_JWT,
    "POST /api/v1/dns/agents/admin/rendered-config": _AGENT_JWT,
    "POST /api/v1/dns/agents/admin/rndc-status": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/heartbeat": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/lease-events": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/mac-sightings": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/ha-status": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/metrics": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/ops/{op_id}/ack": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/log-entries": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/dhcp-fingerprints": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/dhcp-offers": _AGENT_JWT,
    "POST /api/v1/dhcp/agents/ra-observations": _AGENT_JWT,
    "POST /api/v1/looking-glass/agents/heartbeat": _AGENT_JWT,
    "POST /api/v1/looking-glass/agents/routes": _AGENT_JWT,
    "POST /api/v1/appliance/supervisor/register": "unauthenticated; the pairing code is the credential",
    "POST /api/v1/appliance/supervisor/poll": _SUP_SESSION,
    "POST /api/v1/appliance/supervisor/heartbeat": "supervisor endpoint; session token or mTLS cert checked in _supervisor_heartbeat",
    "POST /api/v1/appliance/self-register-bootstrap": (
        "proves the caller is the local supervisor by the host-only "
        "self-bootstrap.token file, checked before any DB write"
    ),
    "POST /api/v1/appliance/supervisor/k8s-proxy/poll": _SUP_CERT,
    "POST /api/v1/appliance/supervisor/k8s-proxy/reply/{request_id}": _SUP_CERT,
    "POST /api/v1/appliance/supervisor/nettool/poll": _SUP_CERT,
    "POST /api/v1/appliance/supervisor/nettool/reply/{request_id}": _SUP_CERT,
    "POST /api/v1/appliance/supervisor/storage/poll": _SUP_CERT,
    "POST /api/v1/appliance/supervisor/storage/reply/{request_id}": _SUP_CERT,
    "POST /api/v1/appliance/supervisor/pcap/poll": _SUP_CERT,
    "POST /api/v1/appliance/supervisor/pcap/progress/{capture_id}": _SUP_CERT,
    "POST /api/v1/appliance/supervisor/pcap/upload/{capture_id}": _SUP_CERT,
    "POST /api/v1/appliance/slot-images": "308 redirect shim to /upgrade-images, gated there",
    "DELETE /api/v1/appliance/slot-images/{image_id}": "308 redirect shim to /upgrade-images, gated there",
    # ── the caller's own rows / own credentials ─────────────────────────
    "POST /api/v1/auth/logout": _SELF,
    "POST /api/v1/auth/change-password": f"{_SELF}; re-verifies the current password",
    "POST /api/v1/auth/mfa/enroll/begin": f"{_SELF}; step-up verified (verify_enrol_stepup)",
    "POST /api/v1/auth/mfa/enroll/reauth": _SELF,
    "POST /api/v1/auth/mfa/enroll/verify": f"{_SELF}; TOTP verified",
    "POST /api/v1/auth/mfa/disable": f"{_SELF}; password + TOTP verified",
    "POST /api/v1/auth/mfa/recovery-codes/regenerate": f"{_SELF}; password + TOTP verified",
    "DELETE /api/v1/sessions/{session_id}": f"{_SELF}; revoking another user's needs superadmin (checked in the handler)",
    "POST /api/v1/api-tokens": f"{_SELF}; a token never exceeds its owner's grants; step-up for sensitive scopes",
    "PATCH /api/v1/api-tokens/{token_id}": f"{_SELF} (_require_owned)",
    "DELETE /api/v1/api-tokens/{token_id}": f"{_SELF} (_require_owned)",
    "POST /api/v1/saved-views": _SELF,
    "PATCH /api/v1/saved-views/{view_id}": f"{_SELF} (_owned)",
    "DELETE /api/v1/saved-views/{view_id}": f"{_SELF} (_owned)",
    "POST /api/v1/ai/prompts": f"{_SELF}; a shared prompt needs superadmin (checked in the handler)",
    "PUT /api/v1/ai/prompts/{prompt_id}": f"{_SELF}; shared prompts need superadmin (checked in the handler)",
    "DELETE /api/v1/ai/prompts/{prompt_id}": f"{_SELF}; shared prompts need superadmin (checked in the handler)",
    "PUT /api/v1/ai/sessions/{session_id}": _SELF,
    "DELETE /api/v1/ai/sessions/{session_id}": _SELF,
    "POST /api/v1/ai/proposals/{proposal_id}/discard": f"{_SELF} (proposal user_id match)",
    # ── Copilot: the tool / operation carries the permission ────────────
    "POST /api/v1/ai/chat": "every tool call re-checks the tool's own permission against the caller",
    "POST /api/v1/ai/mcp": "ToolRegistry.call re-checks each tool's declared permission (ai/mcp.py)",
    "POST /api/v1/ai/proposals/{proposal_id}/apply": (
        "enforce_operation_permission(user, op) before dispatch (ai/proposals.py:156)"
    ),
    # ── checked inline in the handler ───────────────────────────────────
    "PUT /api/v1/settings": f"{_SETTINGS} (settings/router.py)",
    "PUT /api/v1/settings/resolver": f"{_SETTINGS}, then superadmin",
    "POST /api/v1/settings/reverse-dns/run": _SETTINGS,
    "POST /api/v1/settings/apt/validate": _SETTINGS,
    "POST /api/v1/settings/oui/refresh": _SETTINGS,
    "POST /api/v1/settings/snmp/reveal-community": (
        "superadmin + password step-up, checked in the handler (settings/router.py)"
    ),
    "POST /api/v1/admin/agent-keys/reveal": (
        "is_effective_superadmin + password step-up, checked in the handler (admin/agent_keys.py)"
    ),
    "POST /api/v1/nmap/scans/{scan_id}/stamp-discovered": (
        "user_has_permission(user, 'write', 'ip_address') in the handler (nmap/router.py)"
    ),
    "POST /api/v1/conformity/policies": "_require_admin in the handler (conformity/router.py)",
    "PATCH /api/v1/conformity/policies/{policy_id}": "_require_admin in the handler",
    "DELETE /api/v1/conformity/policies/{policy_id}": "_require_admin in the handler",
    "POST /api/v1/conformity/policies/{policy_id}/evaluate": "_require_admin in the handler",
    "POST /api/v1/appliance/firewall/policies": "_require_admin in the handler (appliance/firewall.py)",
    "PATCH /api/v1/appliance/firewall/policies/{policy_id}": "_require_admin in the handler",
    "DELETE /api/v1/appliance/firewall/policies/{policy_id}": "_require_admin in the handler",
    "PUT /api/v1/appliance/firewall/policies/{policy_id}/rules": "_require_admin in the handler",
    "POST /api/v1/appliance/firewall/policies/{policy_id}/rules": "_require_admin in the handler",
    "PATCH /api/v1/appliance/firewall/policies/{policy_id}/rules/{rule_id}": "_require_admin in the handler",
    "DELETE /api/v1/appliance/firewall/policies/{policy_id}/rules/{rule_id}": "_require_admin in the handler",
    "POST /api/v1/appliance/firewall/aliases": "_require_admin in the handler",
    "PATCH /api/v1/appliance/firewall/aliases/{alias_id}": "_require_admin in the handler",
    "DELETE /api/v1/appliance/firewall/aliases/{alias_id}": "_require_admin in the handler",
    "PUT /api/v1/appliance/firewall/enforcement": "_require_admin in the handler",
    "PUT /api/v1/appliance/firewall/logging": "_require_admin in the handler",
    "POST /api/v1/appliance/firewall/posture": "_require_admin in the handler",
    "PUT /api/v1/appliance/firewall/web-ui-access": "_require_admin in the handler",
    "POST /api/v1/appliance/firewall/preview": "dry-run render, _require_read in the handler",
    "POST /api/v1/requests": "_require_submit in the handler (requests/router.py:473)",
    "POST /api/v1/requests/{req_id}/approve": (
        "approve_change_request: approver must hold the operation's own permission "
        "(services/approvals/service.py)"
    ),
    "POST /api/v1/requests/{req_id}/reject": "reject_change_request in the shared approvals spine",
    "POST /api/v1/requests/{req_id}/cancel": "_require_read + owner check in the handler",
    "POST /api/v1/change-requests/{cr_id}/approve": (
        "approve_change_request: approver must hold the operation's own permission "
        "(services/approvals/service.py)"
    ),
    "POST /api/v1/change-requests/{cr_id}/reject": "reject_change_request in the shared approvals spine",
    "POST /api/v1/change-requests/{cr_id}/cancel": "requester-only cancel, checked in the handler",
}

# Genuinely ungated write routes: defects, each waiting for its own issue.
# Nothing is listed today; a route found without a check goes here (with a
# TODO naming the issue) rather than into NO_PERMISSION_DEPENDENCY, so the
# two kinds of exception stay distinguishable.
KNOWN_UNGATED: dict[str, str] = {}


def _write_routes() -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for route in _iter_routes(app.routes):
        for method in sorted(set(route.methods) & set(WRITE_METHODS)):
            out.append((f"{method} {route.path}", route))
    return out


def ungated_write_keys() -> set[str]:
    return {key for key, route in _write_routes() if not route_is_gated(route)}


def declared_gate(route: Any, method: str) -> str:
    """What the route requires, e.g. ``superadmin`` or ``write:subnet|ip_address``.

    A route with several permission dependencies reports them joined with
    ``&`` (every one must pass)."""
    calls = list(_dependency_calls(route.dependant))
    parts: list[str] = []
    if any(c is require_superadmin for c in calls):
        parts.append("superadmin")
    for c in calls:
        req = getattr(c, "spatium_requires", None)
        if req is None:
            continue
        per_route = getattr(c, "spatium_route_requires", None)
        if per_route is not None:
            parts.append(
                "&".join(f"{_METHOD_TO_ACTION[method]}:{t}" for t in per_route(method, route.path))
                or "unclassified"
            )
            continue
        kind, items = req
        if kind == "exact":
            parts.append("|".join(f"{a}:{t}" for a, t in items))
        else:
            parts.append("|".join(f"{_METHOD_TO_ACTION[method]}:{t}" for t in items))
    return "&".join(parts) or "none"


def test_walker_sees_the_write_routes() -> None:
    keys = {k for k, _ in _write_routes()}
    assert len(keys) > 600
    assert "POST /api/v1/dns/groups" in keys
    assert "DELETE /api/v1/dhcp/scopes/{scope_id}" in keys


def test_every_write_route_declares_a_permission_or_is_listed() -> None:
    missing = sorted(ungated_write_keys() - NO_PERMISSION_DEPENDENCY.keys() - KNOWN_UNGATED.keys())
    assert not missing, (
        "Write routes with no permission dependency. Add require_permission / "
        "require_resource_permission (or SuperAdmin) for the resource they change, "
        "or list them in NO_PERMISSION_DEPENDENCY with the reason: "
        f"{missing}"
    )


def test_listed_routes_still_exist_and_are_still_ungated() -> None:
    # An entry for a route that gained a dependency, or went away, would let a
    # future route of that path through unread.
    live = ungated_write_keys()
    stale = sorted((NO_PERMISSION_DEPENDENCY.keys() | KNOWN_UNGATED.keys()) - live)
    assert not stale, f"remove these from the allowlists: {stale}"


def test_a_route_is_in_one_list_only() -> None:
    assert not NO_PERMISSION_DEPENDENCY.keys() & KNOWN_UNGATED.keys()


def test_every_listed_route_has_a_reason() -> None:
    assert all(r.strip() for r in NO_PERMISSION_DEPENDENCY.values())
    assert all(r.strip() for r in KNOWN_UNGATED.values())


def test_declared_gate_reports_action_and_resource() -> None:
    gates = {key: declared_gate(route, key.split(" ", 1)[0]) for key, route in _write_routes()}
    assert gates["POST /api/v1/dns/groups"] != "none"
    assert gates["POST /api/v1/auth/login"] == "none"
    assert any(g == "superadmin" or g.startswith("superadmin&") for g in gates.values())
    assert any(":" in g for g in gates.values())
