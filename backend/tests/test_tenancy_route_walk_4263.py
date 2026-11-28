"""Guard: every route is either tenant-aware or refused to a tenant user, and
no tenant-aware GET route answers with another tenant's rows (#4263)."""

from __future__ import annotations

import re
import uuid
from typing import Any

from httpx import AsyncClient

from app.api.deps import get_current_user
from app.api.tenant_binding import endpoint_is_tenant_aware
from app.main import app
from tests._tenancy_helpers import Side, bearer, get, make_side, make_user, reset_scope
from tests.test_builtin_roles_match_routes import _dependency_calls, _iter_routes

_PARAM = re.compile(r"{([^}:]+)(?::[^}]*)?}")


def _api_routes() -> list[Any]:
    return [r for r in _iter_routes(app.routes) if r.path.startswith("/api/v1/")]


# The reviewed set of tenant-aware GET routes outside /ipam. Adding a route here
# is the decision "this reads only IPAM rows the session filter narrows, or
# nothing about the install"; the walk below then has to pass for it.
NON_IPAM_TENANT_AWARE_GET = {
    "/api/v1/auth/me",
    "/api/v1/auth/me/permissions",
    "/api/v1/auth/password-policy",
    "/api/v1/auth/mfa/status",
    "/api/v1/auth/providers",
    # sign-in flows: no signed-in user, nothing about the estate
    "/api/v1/auth/{provider_id}/authorize",
    "/api/v1/auth/{provider_id}/callback",
    "/api/v1/auth/{provider_id}/metadata",
    "/api/v1/admin/feature-modules",
    "/api/v1/settings",
    "/api/v1/search",
    "/api/v1/search/types",
    "/api/v1/ai/mcp",
}


def test_tenant_aware_get_routes_outside_ipam_are_the_reviewed_set() -> None:
    aware = {
        r.path
        for r in _api_routes()
        if "GET" in (r.methods or set())
        and endpoint_is_tenant_aware(r.endpoint)
        and not r.path.startswith("/api/v1/ipam")
    }
    unexpected = aware - NON_IPAM_TENANT_AWARE_GET
    assert not unexpected, (
        "tenant-aware routes outside IPAM that the reviewed list does not name: "
        f"{sorted(unexpected)}"
    )


def test_every_refused_ipam_endpoint_name_exists() -> None:
    from app.api.v1.ipam.tenant_policy import TENANT_REFUSED_IPAM_ENDPOINTS

    names = {r.endpoint.__name__ for r in _api_routes() if r.path.startswith("/api/v1/ipam")}
    assert not (TENANT_REFUSED_IPAM_ENDPOINTS - names), (
        "TENANT_REFUSED_IPAM_ENDPOINTS names endpoints that no longer exist: "
        f"{sorted(TENANT_REFUSED_IPAM_ENDPOINTS - names)}"
    )


def test_refused_ipam_endpoints_are_not_marked_aware() -> None:
    from app.api.v1.ipam.tenant_policy import TENANT_REFUSED_IPAM_ENDPOINTS

    leaked = [
        r.path
        for r in _api_routes()
        if r.endpoint.__name__ in TENANT_REFUSED_IPAM_ENDPOINTS
        and endpoint_is_tenant_aware(r.endpoint)
    ]
    assert not leaked, leaked


def _fill(path: str, other: Side) -> str:
    ids = {
        "space_id": other.space.id,
        "block_id": other.block.id,
        "subnet_id": other.subnet.id,
        "address_id": other.address.id,
        "tenant_id": other.tenant.id,
    }

    def one(m: re.Match[str]) -> str:
        name = m.group(1)
        return str(ids.get(name, uuid.uuid4()))

    return _PARAM.sub(one, path)


async def test_walk_get_routes_as_a_tenant_user(client: AsyncClient, db_session) -> None:
    """Hit every GET route as tenant A with tenant B's ids. A route is fine when
    it refuses (403), reports not found / invalid input, or answers without a
    single trace of B; it fails when B's rows come back."""
    a = await make_side(db_session, "Acme")
    b = await make_side(db_session, "Beta")
    reset_scope(db_session)
    markers = [
        str(b.space.id),
        str(b.block.id),
        str(b.subnet.id),
        str(b.address.id),
        str(b.tenant.id),
        "Beta-block",
        "Beta-subnet",
        "beta-host",
        "Beta space",
    ]
    failures: list[str] = []
    seen_aware = 0
    for route in _api_routes():
        if "GET" not in (route.methods or set()):
            continue
        path = _fill(route.path, b)
        r = await get(client, db_session, path, a.headers)
        aware = endpoint_is_tenant_aware(route.endpoint)
        if aware:
            seen_aware += 1
        body = r.text
        hit = [m for m in markers if m in body]
        # B's own ids appear in the URL, so only a 2xx can be a leak
        if r.status_code < 300 and hit:
            failures.append(f"{route.path}: {r.status_code} leaks {hit}")
        if aware and r.status_code >= 500:
            failures.append(f"{route.path}: {r.status_code}")
    assert seen_aware > 20
    assert not failures, "\n".join(failures)


async def test_walk_unaware_routes_refuse_tenant_users(client: AsyncClient, db_session) -> None:
    """A route that is not tenant-aware and needs a signed-in user answers 403."""
    a = await make_side(db_session, "Acme")
    reset_scope(db_session)
    admin = await make_user(db_session, superadmin=True)
    await db_session.commit()
    checked = 0
    for route in _api_routes():
        if "GET" not in (route.methods or set()) or endpoint_is_tenant_aware(route.endpoint):
            continue
        path = _fill(route.path, a)
        # a route that does not take the signed-in user (public, agent-JWT) is skipped
        if get_current_user not in set(_dependency_calls(route.dependant)):
            continue
        reset_scope(db_session)
        r = await get(client, db_session, path, a.headers)
        # superadmin passes auth, so a 403 here is the tenant gate's alone
        assert r.status_code == 403, (route.path, r.status_code)
        assert "not available to tenant users" in r.text, (route.path, r.text)
        checked += 1
    assert checked > 100
    _ = admin, bearer
