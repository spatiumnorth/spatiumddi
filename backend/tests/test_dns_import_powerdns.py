"""Tests for the PowerDNS REST live-pull importer (issue #128 Phase 3).

httpx is monkeypatched at ``httpx.AsyncClient`` so the tests never
hit a real PowerDNS server. The synthetic responses match the
shapes documented in the PowerDNS Authoritative v1 REST API docs
so we exercise the same parsing paths the production importer
hits.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone

# ── Helpers ──────────────────────────────────────────────────────────


async def _make_admin(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username="pdns-admin",
        email="pdns-admin@example.com",
        display_name="pdns-admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    token = create_access_token(str(user.id))
    return user, token


async def _make_group(db: AsyncSession, name: str = "pdns-grp") -> DNSServerGroup:
    g = DNSServerGroup(name=name)
    db.add(g)
    await db.flush()
    return g


# ── PowerDNS REST shapes ─────────────────────────────────────────────


_ZONES_SUMMARY = [
    {
        "id": "example.com.",
        "name": "example.com.",
        "kind": "Native",
        "url": "/api/v1/servers/localhost/zones/example.com.",
        "serial": 2026050901,
    },
    {
        "id": "10.in-addr.arpa.",
        "name": "10.in-addr.arpa.",
        "kind": "Master",
        "url": "/api/v1/servers/localhost/zones/10.in-addr.arpa.",
        "serial": 2026050901,
    },
]


def _zone_full(zone_id: str) -> dict[str, Any]:
    if zone_id == "example.com.":
        return {
            "id": "example.com.",
            "name": "example.com.",
            "kind": "Native",
            "serial": 2026050901,
            "rrsets": [
                {
                    "name": "example.com.",
                    "type": "SOA",
                    "ttl": 3600,
                    "records": [
                        {
                            "content": (
                                "ns1.example.com. admin.example.com. "
                                "2026050901 3600 1800 1209600 3600"
                            ),
                            "disabled": False,
                        }
                    ],
                },
                {
                    "name": "example.com.",
                    "type": "NS",
                    "ttl": 3600,
                    "records": [
                        {"content": "ns1.example.com.", "disabled": False},
                        {"content": "ns2.example.com.", "disabled": False},
                    ],
                },
                {
                    "name": "www.example.com.",
                    "type": "A",
                    "ttl": 3600,
                    "records": [{"content": "192.0.2.10", "disabled": False}],
                },
                {
                    "name": "mail.example.com.",
                    "type": "MX",
                    "ttl": 3600,
                    "records": [{"content": "10 mail.example.com.", "disabled": False}],
                },
                # SRV with priority/weight/port
                {
                    "name": "_sip._tcp.example.com.",
                    "type": "SRV",
                    "ttl": 3600,
                    "records": [
                        {"content": "10 60 5060 sipserver.example.com.", "disabled": False}
                    ],
                },
                # disabled record — should be skipped with a warning
                {
                    "name": "deleted.example.com.",
                    "type": "A",
                    "ttl": 3600,
                    "records": [{"content": "192.0.2.99", "disabled": True}],
                },
                # DNSSEC record — should be stripped with a warning
                {
                    "name": "example.com.",
                    "type": "DNSKEY",
                    "ttl": 3600,
                    "records": [{"content": "256 3 8 fakekey", "disabled": False}],
                },
                # PowerDNS-specific LUA record — unsupported, dropped
                {
                    "name": "lb.example.com.",
                    "type": "LUA",
                    "ttl": 60,
                    "records": [
                        {"content": "A \"ifportup(443, {'10.0.0.1'})\"", "disabled": False}
                    ],
                },
            ],
        }
    if zone_id == "10.in-addr.arpa.":
        return {
            "id": "10.in-addr.arpa.",
            "name": "10.in-addr.arpa.",
            "kind": "Master",
            "serial": 2026050901,
            "rrsets": [
                {
                    "name": "10.in-addr.arpa.",
                    "type": "SOA",
                    "ttl": 3600,
                    "records": [
                        {
                            "content": (
                                "ns1.example.com. admin.example.com. "
                                "2026050901 3600 1800 1209600 3600"
                            ),
                            "disabled": False,
                        }
                    ],
                },
                {
                    "name": "1.0.0.10.in-addr.arpa.",
                    "type": "PTR",
                    "ttl": 3600,
                    "records": [{"content": "www.example.com.", "disabled": False}],
                },
            ],
        }
    return {"id": zone_id, "name": zone_id, "kind": "Native", "serial": 1, "rrsets": []}


def _make_transport(
    *,
    zones_status: int = 200,
    info_status: int = 200,
) -> httpx.MockTransport:
    """Build a mock transport that replies to the three API URLs the
    importer hits: server-info, zones list, per-zone full payload."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/servers/localhost") and not path.endswith("zones"):
            if info_status != 200:
                return httpx.Response(info_status, text="error")
            return httpx.Response(
                200,
                json={
                    "type": "Server",
                    "id": "localhost",
                    "daemon_type": "authoritative",
                    "version": "4.9.0",
                    "url": "/api/v1/servers/localhost",
                },
            )
        if path.endswith("/servers/localhost/zones"):
            if zones_status != 200:
                return httpx.Response(zones_status, text="error")
            return httpx.Response(200, json=_ZONES_SUMMARY)
        if "/zones/" in path:
            zone_id = path.split("/zones/", 1)[1]
            return httpx.Response(200, json=_zone_full(zone_id))
        return httpx.Response(404, text=f"unexpected path {path}")

    return httpx.MockTransport(handler)


@pytest.fixture
def patched_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ``httpx.AsyncClient`` so every importer call goes
    through the mock transport. Keyword args other than ``transport``
    pass through unchanged."""

    real_async_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.setdefault("transport", _make_transport())
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


# ── Service-layer ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_parse_powerdns_canonical_shape(patched_httpx: None) -> None:
    from app.services.dns_import import parse_powerdns_server

    preview = await parse_powerdns_server(
        api_url="http://pdns.example.com:8081",
        api_key="secret",
    )
    assert preview.source == "powerdns"
    assert len(preview.zones) == 2

    by_name = {z.name: z for z in preview.zones}
    assert "example.com." in by_name
    assert "10.in-addr.arpa." in by_name

    fwd = by_name["example.com."]
    assert fwd.kind == "forward"
    assert fwd.zone_type == "primary"  # Native → primary
    # SOA hoisted from the rrset content
    assert fwd.soa is not None
    assert fwd.soa.serial == 2026050901
    assert fwd.soa.primary_ns == "ns1.example.com."
    assert fwd.soa.refresh == 3600

    types = {r.record_type for r in fwd.records}
    assert "NS" in types and "A" in types and "MX" in types and "SRV" in types
    # Apex name relativised to "@"
    apex_ns = [r for r in fwd.records if r.record_type == "NS" and r.name == "@"]
    assert len(apex_ns) == 2
    # MX priority + value split
    mx = next(r for r in fwd.records if r.record_type == "MX")
    assert mx.priority == 10
    assert mx.value == "mail.example.com."
    # SRV priority/weight/port split
    srv = next(r for r in fwd.records if r.record_type == "SRV")
    assert srv.priority == 10
    assert srv.weight == 60
    assert srv.port == 5060
    assert srv.value == "sipserver.example.com."

    # disabled / DNSSEC / unsupported all get dropped
    record_names = {r.name for r in fwd.records}
    assert "deleted" not in record_names

    # Warnings cover all three drop paths
    warnings_text = " ".join(fwd.parse_warnings)
    assert "disabled" in warnings_text.lower()
    assert "DNSSEC" in warnings_text or "DNSKEY" in warnings_text
    assert "unsupported" in warnings_text.lower() or "LUA" in warnings_text

    # Reverse zone classification
    rev = by_name["10.in-addr.arpa."]
    assert rev.kind == "reverse"
    assert rev.zone_type == "primary"  # Master → primary


@pytest.mark.asyncio
async def test_test_connection_returns_daemon_info(patched_httpx: None) -> None:
    from app.services.dns_import import test_powerdns_connection

    info = await test_powerdns_connection(
        api_url="http://pdns.example.com:8081",
        api_key="secret",
    )
    assert info["daemon_type"] == "authoritative"
    assert info["version"] == "4.9.0"
    assert info["id"] == "localhost"


@pytest.mark.asyncio
async def test_parse_rejects_401(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.dns_import import PowerDNSImportError, parse_powerdns_server

    real_async_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.setdefault(
            "transport",
            httpx.MockTransport(lambda req: httpx.Response(401, text="bad key")),
        )
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    with pytest.raises(PowerDNSImportError, match="API key"):
        await parse_powerdns_server(
            api_url="http://pdns.example.com:8081",
            api_key="wrong",
        )


@pytest.mark.asyncio
async def test_parse_handles_url_with_api_v1_suffix(patched_httpx: None) -> None:
    """``http://host/api/v1`` and ``http://host`` both work — the
    suffix is stripped if the operator pasted it in."""

    from app.services.dns_import import parse_powerdns_server

    preview = await parse_powerdns_server(
        api_url="http://pdns.example.com:8081/api/v1",
        api_key="secret",
    )
    assert len(preview.zones) == 2


# ── HTTP integration ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_test_connection_endpoint(
    db_session: AsyncSession, client: AsyncClient, patched_httpx: None
) -> None:
    _, token = await _make_admin(db_session)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/dns/import/powerdns/test-connection",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "api_url": "http://pdns.example.com:8081",
            "api_key": "secret",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["daemon_type"] == "authoritative"


@pytest.mark.asyncio
async def test_test_connection_endpoint_502_on_unreachable(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, token = await _make_admin(db_session)
    await db_session.commit()

    real_async_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.setdefault(
            "transport",
            httpx.MockTransport(lambda req: httpx.Response(401, text="bad key")),
        )
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)

    resp = await client.post(
        "/api/v1/dns/import/powerdns/test-connection",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "api_url": "http://pdns.example.com:8081",
            "api_key": "wrong",
        },
    )
    assert resp.status_code == 502
    assert "API key" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_preview_returns_canonical_shape(
    db_session: AsyncSession, client: AsyncClient, patched_httpx: None
) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/dns/import/powerdns/preview",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "api_url": "http://pdns.example.com:8081",
            "api_key": "secret",
            "target_group_id": str(group.id),
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source"] == "powerdns"
    assert len(body["zones"]) == 2
    assert body["conflicts"] == []


@pytest.mark.asyncio
async def test_commit_creates_zones_with_provenance(
    db_session: AsyncSession, client: AsyncClient, patched_httpx: None
) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    await db_session.commit()

    preview_resp = await client.post(
        "/api/v1/dns/import/powerdns/preview",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "api_url": "http://pdns.example.com:8081",
            "api_key": "secret",
            "target_group_id": str(group.id),
        },
    )
    plan = preview_resp.json()

    commit_resp = await client.post(
        "/api/v1/dns/import/powerdns/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "plan": plan,
            "conflict_actions": {},
        },
    )
    assert commit_resp.status_code == 200, commit_resp.text
    body = commit_resp.json()
    assert body["total_zones_created"] == 2

    zones = (
        (await db_session.execute(select(DNSZone).where(DNSZone.import_source == "powerdns")))
        .scalars()
        .all()
    )
    assert {z.name for z in zones} == {"example.com.", "10.in-addr.arpa."}
    assert all(z.imported_at is not None for z in zones)
    # SOA serial seeded from the parsed SOA
    fwd = next(z for z in zones if z.name == "example.com.")
    assert fwd.last_serial == 2026050901
    assert fwd.primary_ns == "ns1.example.com"  # trailing dot stripped

    records = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.zone_id == fwd.id)))
        .scalars()
        .all()
    )
    # NS×2 + A + MX + SRV (the disabled / DNSSEC / LUA records were stripped)
    assert len(records) == 5
    assert all(r.import_source == "powerdns" for r in records)

    # Audit row tagged with the right source
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dns_zone",
                AuditLog.resource_display == "example.com.",
            )
        )
    ).scalar_one()
    assert audit.new_value is not None
    assert audit.new_value.get("import_source") == "powerdns"


@pytest.mark.asyncio
async def test_commit_plan_source_mismatch_returns_400(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/dns/import/powerdns/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "plan": {
                "source": "bind9",
                "zones": [],
                "conflicts": [],
                "warnings": [],
                "total_records": 0,
                "record_type_histogram": {},
            },
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 400
    assert "source mismatch" in resp.json()["detail"]


def test_secondary_keeps_masters_and_no_records_4259() -> None:
    from app.services.dns_import.canonical import settle_replica_zones
    from app.services.dns_import.powerdns import _build_imported_zone

    full = {
        "name": "sec.example.com.",
        "kind": "Slave",
        "masters": ["192.0.2.1", "192.0.2.2:5300", "[2001:db8::1]:53", "junk"],
        "rrsets": [
            {
                "name": "www.sec.example.com.",
                "type": "A",
                "ttl": 60,
                "records": [{"content": "192.0.2.9", "disabled": False}],
            },
        ],
    }
    z = _build_imported_zone({"name": "sec.example.com.", "kind": "Slave"}, full)
    assert z.masters == ["192.0.2.1", "192.0.2.2@5300", "2001:db8::1"]
    warnings: list[str] = []
    assert settle_replica_zones([z], warnings) == [z]
    assert z.records == []
    bare = _build_imported_zone(
        {"name": "b.example.com.", "kind": "Slave"}, {"name": "b.example.com.", "kind": "Slave"}
    )
    out: list[str] = []
    assert settle_replica_zones([bare], out) == [] and "no primary server" in out[0]
