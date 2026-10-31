"""Dashboard rollups and metric series read with the caller's own grants.

The DNS / DHCP traffic series, the Network / Integrations dashboard tabs and
the tag autocomplete summarise rows that each have their own router and their own ``read`` grant.
These routes now ask for the same grants: a caller who could not read the
underlying rows through their own routes gets 403 (or an empty panel), and
the built-in Viewer, which holds ``read *``, still sees everything.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.asn import ASN
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.ipam import IPSpace

pytestmark = pytest.mark.asyncio


async def _headers(
    db: AsyncSession,
    *,
    role: str | None = None,
    permissions: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"ro-{tag}",
        email=f"{tag}@example.test",
        display_name="Reader",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    perms = list(_BUILTIN_ROLES[role][1]) if role is not None else list(permissions or [])
    r = Role(name=f"r-{tag}", description="", permissions=perms)
    g = Group(name=f"g-{tag}", description="")
    g.roles = [r]
    g.users = [user]
    db.add_all([r, g, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _grant(action: str, resource_type: str) -> list[dict[str, Any]]:
    return [{"action": action, "resource_type": resource_type}]


# A grant unrelated to every surface under test, so the caller is a real
# signed-in user with a role, just not one covering these reads.
_UNRELATED = _grant("read", "custom_field")


# ── DNS / DHCP traffic series ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "path", ["/api/v1/metrics/dns/timeseries", "/api/v1/metrics/dhcp/timeseries"]
)
async def test_traffic_series_refused_without_a_dns_or_dhcp_grant(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    headers = await _headers(db_session, permissions=_UNRELATED)
    resp = await client.get(path, headers=headers)
    assert resp.status_code == 403, resp.text


async def test_dns_series_needs_dns_read_not_dhcp_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    dhcp_reader = await _headers(db_session, permissions=_grant("read", "dhcp_server"))
    assert (
        await client.get("/api/v1/metrics/dns/timeseries", headers=dhcp_reader)
    ).status_code == 403
    assert (
        await client.get("/api/v1/metrics/dhcp/timeseries", headers=dhcp_reader)
    ).status_code == 200

    # Server traffic is a server-group read, as the /dns server routes are (#3073).
    dns_reader = await _headers(db_session, permissions=_grant("read", "dns_group"))
    assert (
        await client.get("/api/v1/metrics/dns/timeseries", headers=dns_reader)
    ).status_code == 200
    assert (
        await client.get("/api/v1/metrics/dhcp/timeseries", headers=dns_reader)
    ).status_code == 403


@pytest.mark.parametrize(
    "path", ["/api/v1/metrics/dns/timeseries", "/api/v1/metrics/dhcp/timeseries"]
)
async def test_viewer_still_reads_traffic_series(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    headers = await _headers(db_session, role="Viewer")
    resp = await client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text


# ── Network dashboard ──────────────────────────────────────────────────────


async def _drifted_asn(db: AsyncSession) -> ASN:
    asn = ASN(number=64512 + int(uuid.uuid4().int % 1000), name="drifted", whois_state="drift")
    db.add(asn)
    await db.flush()
    return asn


async def test_network_summary_refused_without_any_network_grant(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session, permissions=_UNRELATED)
    resp = await client.get("/api/v1/dashboards/network/summary", headers=headers)
    assert resp.status_code == 403, resp.text


async def test_network_summary_only_fills_panels_the_caller_can_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    asn = await _drifted_asn(db_session)

    circuit_reader = await _headers(db_session, permissions=_grant("read", "circuit"))
    resp = await client.get("/api/v1/dashboards/network/summary", headers=circuit_reader)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["asn_drift_count"] == 0
    assert body["asn_drift"] == []

    viewer = await _headers(db_session, role="Viewer")
    resp = await client.get("/api/v1/dashboards/network/summary", headers=viewer)
    assert resp.status_code == 200, resp.text
    assert asn.number in [row["number"] for row in resp.json()["asn_drift"]]


# ── Integrations dashboard ─────────────────────────────────────────────────


async def test_integrations_summary_refused_without_any_integration_grant(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session, permissions=_UNRELATED)
    resp = await client.get("/api/v1/dashboards/integrations/summary", headers=headers)
    assert resp.status_code == 403, resp.text


async def test_integrations_summary_only_shows_readable_integrations(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db_session.add(
        AuditLog(
            user_display_name="system",
            action="sync",
            resource_type="docker_host",
            resource_id=str(uuid.uuid4()),
            resource_display="docker-reconcile-target",
            result="error",
            error_detail="docker reconcile failed",
        )
    )
    await db_session.flush()

    k8s_reader = await _headers(db_session, permissions=_grant("read", "kubernetes_cluster"))
    resp = await client.get("/api/v1/dashboards/integrations/summary", headers=k8s_reader)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [p["kind"] for p in body["panels"]] == ["kubernetes"]
    assert body["recent_errors"] == []

    viewer = await _headers(db_session, role="Viewer")
    resp = await client.get("/api/v1/dashboards/integrations/summary", headers=viewer)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["panels"]) == 11
    assert "docker-reconcile-target" in [e["target_display"] for e in body["recent_errors"]]


# ── Tag autocomplete ───────────────────────────────────────────────────────


async def test_tag_autocomplete_offers_only_tags_on_readable_tables(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    key = f"k{uuid.uuid4().hex[:8]}"
    db_session.add(
        IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="", tags={key: "space-value"})
    )
    await db_session.flush()

    dhcp_reader = await _headers(db_session, permissions=_grant("read", "dhcp_server"))
    resp = await client.get("/api/v1/tags/keys", params={"prefix": key}, headers=dhcp_reader)
    assert resp.status_code == 200, resp.text
    assert resp.json()["keys"] == []
    resp = await client.get("/api/v1/tags/values", params={"key": key}, headers=dhcp_reader)
    assert resp.status_code == 200, resp.text
    assert resp.json()["values"] == []

    # Any IPAM read opens the IPAM router, so it opens the IPAM tags too.
    for headers in (
        await _headers(db_session, permissions=_grant("read", "subnet")),
        await _headers(db_session, role="Viewer"),
    ):
        resp = await client.get("/api/v1/tags/keys", params={"prefix": key}, headers=headers)
        assert resp.json()["keys"] == [key]
        resp = await client.get("/api/v1/tags/values", params={"key": key}, headers=headers)
        assert resp.json()["values"] == ["space-value"]
