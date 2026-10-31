"""A ``read``-scoped API token may call the POST routes that only read (#3223).

The coarse scope gate used to treat every POST as a write, so a monitoring
integration holding a read-only token could not query the DNS query log
(whose filter travels in a POST body). Routes now declare ``@read_only_post``;
the scope gate consults that marker instead of the method. "Scope
insufficient" is a 403 (the credential is fine), while a bad / revoked /
expired token stays 401.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.services.api_token_scopes import is_read_only_post, scope_matches_request

# Every POST route that declares itself read-only. Pinned so that adding the
# marker to a route is a reviewed decision, not a drive-by.
EXPECTED_READ_ONLY_POSTS: frozenset[str] = frozenset(
    {
        "/api/v1/av/allocation-preview",
        "/api/v1/dhcp/import/isc/preview",
        "/api/v1/dhcp/import/kea/preview",
        "/api/v1/dicom/aes/import/preview",
        "/api/v1/dns/groups/{group_id}/zones/{zone_id}/import/preview",
        "/api/v1/dns/groups/{group_id}/zones/{zone_id}/import/spreadsheet/preview",
        "/api/v1/dns/groups/{group_id}/zones/{zone_id}/move/preview",
        "/api/v1/dns/import/bind9/preview",
        "/api/v1/ipam/blocks/{block_id}/move/preview",
        "/api/v1/ipam/blocks/{block_id}/plan-allocation",
        "/api/v1/ipam/blocks/{block_id}/resize/preview",
        "/api/v1/ipam/import/addresses/preview",
        "/api/v1/ipam/import/preview",
        "/api/v1/ipam/import/preview-json",
        "/api/v1/ipam/plans/validate-tree",
        "/api/v1/ipam/plans/{plan_id}/validate",
        "/api/v1/ipam/spaces/{space_id}/find-free",
        "/api/v1/ipam/subnets/{subnet_id}/bulk-allocate/preview",
        "/api/v1/ipam/subnets/{subnet_id}/merge/preview",
        "/api/v1/ipam/subnets/{subnet_id}/resize/preview",
        "/api/v1/ipam/subnets/{subnet_id}/split/preview",
        "/api/v1/logs/dhcp-activity",
        "/api/v1/logs/dns-queries",
        "/api/v1/logs/dns-queries/analytics",
        "/api/v1/multicast/groups/bulk-allocate/preview",
        "/api/v1/ot/devices/import/preview",
        "/api/v1/tools/mac-vendor",
    }
)

# POST routes whose name says query / preview / validate but which are
# deliberately still writes for the scope gate, with the reason.
DELIBERATELY_WRITE: dict[str, str] = {
    "/api/v1/appliance/firewall/preview": "dispatches a render to the supervisor",
    "/api/v1/appliance/acme/preview": "resolves DNS-01 solvers, reaches cloud DNS APIs",
    "/api/v1/backup/manifest-preview": "accepts an uploaded archive and reads it server-side",
    "/api/v1/block-sync/blocks/preview": "asks the integration target (outbound)",
    "/api/v1/dns/agents/query-log-entries": "agent ingest — writes rows",
    "/api/v1/dhcp/import/windows/preview": "live WinRM pull from a Windows server",
    "/api/v1/dns/import/cloud/preview": "live pull from a cloud DNS provider",
    "/api/v1/dns/import/powerdns/preview": "live pull from a PowerDNS API",
    "/api/v1/dns/import/technitium/preview": "live pull from a Technitium API",
    "/api/v1/dns/import/windows-dns/preview": "live WinRM pull from a Windows server",
    "/api/v1/dns/tools/propagation-check": "sends queries to public resolvers",
    "/api/v1/logs/query": "runs Get-WinEvent over WinRM on a Windows server (outbound, stored creds)",
    "/api/v1/logs/dhcp-audit": "reads the audit log over WinRM on a Windows server (outbound)",
    "/api/v1/ipam/import/netbox/preview": "live pull from NetBox (outbound)",
    "/api/v1/overlays/{overlay_id}/simulate": "not reviewed as side-effect free",
    "/api/v1/settings/apt/validate": "not reviewed as side-effect free",
    "/api/v1/system/factory-reset/preview": "destructive-operation workflow step",
    "/api/v1/system/support-bundle/preview": "writes an audit row + commits",
    "/api/v1/tools/firewall-logs": "queues a command row for the appliance",
    "/api/v1/tools/dig": "sends DNS traffic",
    "/api/v1/tools/dns-propagation": "sends DNS traffic to public resolvers",
    "/api/v1/tools/mtr": "sends probe traffic",
    "/api/v1/tools/ping": "sends probe traffic",
    "/api/v1/tools/port-test": "sends probe traffic",
    "/api/v1/tools/tls-cert": "opens a connection to the target",
    "/api/v1/tools/traceroute": "sends probe traffic",
    "/api/v1/tools/whois": "outbound query",
    "/api/v1/tools/wol": "sends a magic packet and writes an audit row",
    "/api/v1/upgrades/plan": "writes a planned upgrade run",
    "/api/v1/wake-scheduler/preview-targets": "not reviewed",
    "/api/v1/wake-scheduler/schedules/{schedule_id}/preview-targets": "not reviewed",
    "/api/v1/migration/cutover/plans/{plan_id}/items/{item_id}/lease-handover/preview": (
        "cutover workflow step against live servers"
    ),
    "/api/v1/migration/cutover/plans/{plan_id}/items/{item_id}/ttl-preflight/preview": (
        "cutover workflow step against live servers"
    ),
}

_QUERYISH = re.compile(
    r"(preview|query|dns-queries|dhcp-audit|dhcp-activity|analytics|search|validate"
    r"|find-free|plan-allocation|allocation-preview|simulate)"
)


def _post_routes() -> dict[str, object]:
    from app.main import app  # noqa: PLC0415

    found: dict[str, object] = {}

    def rec(routes, prefix: str = "") -> None:  # type: ignore[no-untyped-def]
        for r in routes:
            if hasattr(r, "original_router"):
                rec(r.original_router.routes, prefix + r.include_context.prefix)
            elif hasattr(r, "endpoint") and "POST" in getattr(r, "methods", ()):
                found[re.sub(r":\w+}", "}", prefix + r.path)] = r.endpoint

    rec(app.routes)
    return found


def test_the_marked_routes_are_exactly_the_reviewed_set() -> None:
    marked = {p for p, ep in _post_routes().items() if is_read_only_post(ep)}
    assert marked == set(EXPECTED_READ_ONLY_POSTS)


def test_query_shaped_post_routes_are_marked_or_justified() -> None:
    """Heuristic guard (it keys on the route path, so a read-only POST with an
    unusual name will not be caught): a POST whose path looks like a query /
    preview / validation must either carry ``@read_only_post`` or be listed
    in ``DELIBERATELY_WRITE`` with a reason."""
    missing = []
    for path, ep in sorted(_post_routes().items()):
        if not path.startswith("/api/v1/") or not _QUERYISH.search(path):
            continue
        if is_read_only_post(ep):
            continue
        if path in DELIBERATELY_WRITE:
            continue
        missing.append(path)
    assert not missing, (
        "POST route(s) look read-only but are neither @read_only_post nor in "
        "DELIBERATELY_WRITE:\n" + "\n".join(missing)
    )


def test_read_scope_covers_a_marked_route_but_not_other_posts() -> None:
    assert scope_matches_request(["read"], "POST", "/api/v1/logs/dns-queries") is False
    assert (
        scope_matches_request(["read"], "POST", "/api/v1/logs/dns-queries", read_only_route=True)
        is True
    )
    # The marker never widens a write scope's reach or other methods.
    assert (
        scope_matches_request(["dns:write"], "POST", "/api/v1/logs/x", read_only_route=True)
        is False
    )
    for method in ("PUT", "PATCH", "DELETE"):
        assert (
            scope_matches_request(["read"], method, "/api/v1/logs/x", read_only_route=True) is False
        ), method


# ── HTTP ─────────────────────────────────────────────────────────────────


async def _token(db: AsyncSession, scopes: list[str], **kw) -> str:  # type: ignore[no-untyped-def]
    owner = User(
        username=f"tok-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Token Owner",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(owner)
    await db.flush()
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=scopes,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=kw.get("is_active", True),
            expires_at=kw.get("expires_at"),
        )
    )
    await db.flush()
    await db.commit()
    return raw


def _h(raw: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {raw}"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/logs/dns-queries", {}),
        ("/api/v1/logs/dns-queries/analytics", {}),
        ("/api/v1/logs/dhcp-activity", {}),
        ("/api/v1/tools/mac-vendor", {"macs": ["00:11:22:33:44:55"]}),
    ],
)
async def test_read_token_reaches_read_only_posts(
    client: AsyncClient, db_session: AsyncSession, path: str, body: dict
) -> None:
    raw = await _token(db_session, ["read"])
    r = await client.post(path, json=body, headers=_h(raw))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_read_token_is_refused_403_on_a_real_write_post(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    raw = await _token(db_session, ["read"])
    r = await client.post("/api/v1/dns/groups", json={"name": "nope"}, headers=_h(raw))
    assert r.status_code == 403, r.text
    assert "scope" in r.text.lower()
    r = await client.post("/api/v1/tools/ping", json={"host": "192.0.2.1"}, headers=_h(raw))
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_unrestricted_token_is_unaffected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    raw = await _token(db_session, [])
    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(raw))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_revoked_and_expired_tokens_stay_401(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    revoked = await _token(db_session, ["read"], is_active=False)
    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(revoked))
    assert r.status_code == 401, r.text
    expired = await _token(db_session, ["read"], expires_at=datetime.now(UTC) - timedelta(hours=1))
    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(expired))
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "body"),
    [
        (
            "/api/v1/logs/query",
            {"server_id": str(uuid.uuid4()), "server_kind": "dns", "log_name": "DNS Server"},
        ),
        ("/api/v1/logs/dhcp-audit", {"server_id": str(uuid.uuid4())}),
    ],
)
async def test_read_token_is_refused_on_the_winrm_log_pulls(
    client: AsyncClient, db_session: AsyncSession, path: str, body: dict
) -> None:
    """These run PowerShell over WinRM on a managed Windows server with its
    stored credentials. That reaches out, so it is not ``read``."""
    raw = await _token(db_session, ["read"])
    r = await client.post(path, json=body, headers=_h(raw))
    assert r.status_code == 403, r.text
    assert "scope" in r.text.lower()


@pytest.mark.asyncio
async def test_a_write_scope_is_not_widened_by_the_marker(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    raw = await _token(db_session, ["dns:write"])
    r = await client.post("/api/v1/logs/dns-queries", json={}, headers=_h(raw))
    assert r.status_code == 403, r.text
