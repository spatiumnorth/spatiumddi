"""Technitium importer: internal zones, RNAME form, URL/TLS, provenance (#1777)."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest

from app.api.v1.dns_import.router import _assert_source_server
from app.services.dns_import import technitium as tech
from app.services.dns_import.soa_mailbox import importable_admin_email
from app.services.dns_import.technitium import (
    TechnitiumImportError,
    _build_imported_zone,
    parse_technitium_server,
)

_SOA = {
    "name": "example.com",
    "type": "SOA",
    "ttl": 3600,
    "rData": {
        "primaryNameServer": "ns1.example.com",
        "responsiblePerson": "hostmaster@example.com",
        "serial": 1,
    },
}


def _fake(monkeypatch: pytest.MonkeyPatch, zones_pages: list[list[dict[str, Any]]], seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/zones/list":
            page = int(request.url.params.get("pageNumber", "1"))
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "response": {
                        "pageNumber": page,
                        "totalPages": len(zones_pages),
                        "zones": zones_pages[page - 1],
                    },
                },
            )
        return httpx.Response(200, json={"status": "ok", "response": {"records": [_SOA]}})

    real = httpx.AsyncClient

    def factory(*a: Any, **kw: Any) -> httpx.AsyncClient:
        kw["transport"] = httpx.MockTransport(handler)
        seen_kw.append(kw.get("verify"))
        return real(*a, **kw)

    seen_kw: list[Any] = []
    monkeypatch.setattr(tech.httpx, "AsyncClient", factory)
    return seen_kw


def _z(name: str, **kw: Any) -> dict[str, Any]:
    return {"name": name, "type": "Primary", "disabled": False, **kw}


@pytest.mark.asyncio
async def test_internal_zones_are_not_offered(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        [_z("localhost", internal=True), _z("127.in-addr.arpa", internal=True), _z("example.com")]
    ]
    _fake(monkeypatch, pages, [])
    preview = await parse_technitium_server(api_url="http://t:5380", api_token="x")
    assert [z.name for z in preview.zones] == ["example.com."]
    info = await tech.test_technitium_connection(api_url="http://t:5380", api_token="x")
    assert info["importable_zone_count"] == 1


@pytest.mark.asyncio
async def test_pagination_followed_url_normalised_and_tls_toggle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []
    kw = _fake(monkeypatch, [[_z("a.example")], [_z("b.example")]], seen)
    preview = await parse_technitium_server(
        api_url="https://t:53443/api/", api_token="x", verify_tls=False
    )
    assert [z.name for z in preview.zones] == ["a.example.", "b.example."]
    assert all("/api/api" not in str(r.url) for r in seen)
    assert set(kw) == {False}


@pytest.mark.asyncio
async def test_schemeless_url_refused() -> None:
    with pytest.raises(TechnitiumImportError):
        await parse_technitium_server(api_url="tdns.internal:5380", api_token="x")


def test_rname_email_form_becomes_soa_form_and_is_kept() -> None:
    zone = _build_imported_zone("example.com", [_SOA])
    assert zone.soa is not None
    assert zone.soa.admin_email == "hostmaster.example.com."
    assert importable_admin_email(zone.soa.admin_email) == ("hostmaster.example.com", None)


def test_rname_with_dotted_local_part_is_escaped_not_split() -> None:
    soa = {**_SOA, "rData": {**_SOA["rData"], "responsiblePerson": "john.doe@example.com"}}
    zone = _build_imported_zone("example.com", [soa])
    assert zone.soa is not None and zone.soa.admin_email == "john\\.doe.example.com."


@pytest.mark.asyncio
async def test_technitium_plan_may_name_a_technitium_api_server(db_session: Any) -> None:
    from fastapi import HTTPException

    from app.models.dns import DNSServer, DNSServerGroup

    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(g)
    await db_session.flush()
    srv = DNSServer(group_id=g.id, name="t1", host="t1", driver="technitium_api")
    bind = DNSServer(group_id=g.id, name="b1", host="b1", driver="bind9")
    db_session.add_all([srv, bind])
    await db_session.flush()
    await _assert_source_server(db_session, srv.id, "technitium")
    with pytest.raises(HTTPException):
        await _assert_source_server(db_session, bind.id, "technitium")
