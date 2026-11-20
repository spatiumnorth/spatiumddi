"""PowerDNS importer record types follow the target group's driver (#4604 B8)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer
from app.services.dns_import.powerdns import _build_imported_zone
from tests.test_dns_import_powerdns import _make_admin, _make_group, _make_transport


@pytest.fixture
def pdns_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    real = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.setdefault("transport", _make_transport())
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


_FULL: dict[str, Any] = {
    "name": "example.com.",
    "kind": "Native",
    "rrsets": [
        {"name": "example.com.", "type": "A", "ttl": 60, "records": [{"content": "192.0.2.1"}]},
        {
            "name": "svc.example.com.",
            "type": "SVCB",
            "ttl": 60,
            "records": [{"content": '1 . alpn="h2"'}],
        },
        {
            "name": "web.example.com.",
            "type": "HTTPS",
            "ttl": 60,
            "records": [{"content": '1 . alpn="h3"'}],
        },
        {
            "name": "sub.example.com.",
            "type": "DNAME",
            "ttl": 60,
            "records": [{"content": "other.example.net."}],
        },
        {
            "name": "alias.example.com.",
            "type": "ALIAS",
            "ttl": 60,
            "records": [{"content": "target.example.net."}],
        },
        {
            "name": "lb.example.com.",
            "type": "LUA",
            "ttl": 60,
            "records": [{"content": "A \"ifportup(443, {'10.0.0.1'})\""}],
        },
    ],
}


def _types(drivers: frozenset[str] | None) -> set[str]:
    return {r.record_type for r in _build_imported_zone({}, _FULL, drivers).records}


def test_svcb_https_dname_import_whatever_the_target() -> None:
    for drivers in (None, frozenset({"bind9"}), frozenset({"powerdns"})):
        assert {"SVCB", "HTTPS", "DNAME"} <= _types(drivers)


def test_alias_and_lua_import_into_a_powerdns_group() -> None:
    assert {"ALIAS", "LUA"} <= _types(frozenset({"powerdns"}))


def test_alias_and_lua_dropped_elsewhere_with_the_target_driver_named() -> None:
    for drivers in (frozenset({"bind9"}), frozenset({"powerdns", "bind9"})):
        zone = _build_imported_zone({}, _FULL, drivers)
        assert not {"ALIAS", "LUA"} & {r.record_type for r in zone.records}
        warning = next(w for w in zone.parse_warnings if "ALIAS=1" in w)
        assert "LUA=1" in warning
        assert "bind9" in warning


async def test_preview_endpoint_reads_the_target_groups_drivers(
    db_session: AsyncSession, client: AsyncClient, pdns_mock: None
) -> None:
    """The route passes the group's drivers: a PowerDNS-only group keeps the
    zone's LUA record, a BIND9 group drops it with a warning."""
    _, token = await _make_admin(db_session)
    results: dict[str, Any] = {}
    for driver in ("powerdns", "bind9"):
        group = await _make_group(db_session, f"g-{driver}")
        db_session.add(
            DNSServer(group_id=group.id, name=f"s-{driver}", driver=driver, host="h", port=53)
        )
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
        results[driver] = resp.json()

    def lua_records(body: dict[str, Any]) -> list[Any]:
        return [r for z in body["zones"] for r in z["records"] if r["record_type"] == "LUA"]

    assert lua_records(results["powerdns"])
    assert not lua_records(results["bind9"])
    assert any(
        "LUA=1" in w and "bind9" in w
        for z in results["bind9"]["zones"]
        for w in z["parse_warnings"]
    )
