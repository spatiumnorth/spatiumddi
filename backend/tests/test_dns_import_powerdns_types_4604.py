"""PowerDNS importer record types follow the target group's driver (#4604 B8)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServer, DNSServerOptions, DNSZone
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


# ── ALIAS needs the group's Do53 forwarders (#4604) ──────────────────


@pytest.fixture
def pdns_full_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the route's live pull return ``_FULL``, built the way the real
    parser builds it, so the route's own kwargs decide what survives."""
    import importlib

    import_router = importlib.import_module("app.api.v1.dns_import.router")
    from app.services.dns_import.canonical import ImportPreview

    async def fake_parse(**kw: Any) -> ImportPreview:
        zone = _build_imported_zone(
            {}, _FULL, kw.get("target_drivers"), kw.get("alias_resolvable", True)
        )
        return ImportPreview(
            source="powerdns",
            zones=[zone],
            conflicts=[],
            warnings=[],
            total_records=len(zone.records),
            record_type_histogram={},
        )

    monkeypatch.setattr(import_router, "parse_powerdns_server", fake_parse)


async def _pdns_group(
    db: AsyncSession, name: str, forwarders: list[str], transport: str = "do53"
) -> Any:
    group = await _make_group(db, name)
    db.add(DNSServer(group_id=group.id, name=f"s-{name}", driver="powerdns", host="h", port=53))
    db.add(DNSServerOptions(group_id=group.id, forwarders=forwarders, forward_transport=transport))
    await db.commit()
    return group


async def _preview(client: AsyncClient, token: str, group: Any) -> dict[str, Any]:
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
    return resp.json()


def _types_of(plan: dict[str, Any]) -> list[str]:
    return [r["record_type"] for z in plan["zones"] for r in z["records"]]


async def test_preview_drops_alias_without_do53_forwarders(
    db_session: AsyncSession, client: AsyncClient, pdns_full_zone: None
) -> None:
    _, token = await _make_admin(db_session)
    bare = await _pdns_group(db_session, "bare", [])
    tls_only = await _pdns_group(db_session, "tls", ["10.0.0.53"], "dot")
    for group in (bare, tls_only):
        plan = await _preview(client, token, group)
        types = _types_of(plan)
        assert "ALIAS" not in types
        assert {"A", "SVCB", "LUA"} <= set(types)
        warnings = [w for z in plan["zones"] for w in z["parse_warnings"]]
        assert any(w.startswith("Dropped 1 ALIAS record(s)") and "Do53" in w for w in warnings)


async def test_preview_keeps_alias_with_a_do53_forwarder(
    db_session: AsyncSession, client: AsyncClient, pdns_full_zone: None
) -> None:
    _, token = await _make_admin(db_session)
    group = await _pdns_group(db_session, "fwd", ["10.0.0.53"])
    plan = await _preview(client, token, group)
    assert "ALIAS" in _types_of(plan)
    assert not any("ALIAS record(s)" in w for z in plan["zones"] for w in z["parse_warnings"])


async def test_commit_drops_alias_without_do53_forwarders(
    db_session: AsyncSession, client: AsyncClient, pdns_full_zone: None
) -> None:
    """The plan is client-supplied: a commit into a group with no forwarders
    drops the ALIAS even when the plan was previewed against another group."""
    _, token = await _make_admin(db_session)
    fwd = await _pdns_group(db_session, "fwd2", ["10.0.0.53"])
    bare = await _pdns_group(db_session, "bare2", [])
    plan = await _preview(client, token, fwd)
    assert "ALIAS" in _types_of(plan)

    resp = await client.post(
        "/api/v1/dns/import/powerdns/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_group_id": str(bare.id), "plan": plan, "conflict_actions": {}},
    )
    assert resp.status_code == 200, resp.text
    assert any("Dropped 1 ALIAS record(s)" in w for w in resp.json()["warnings"])
    stored = (
        (
            await db_session.execute(
                select(DNSRecord.record_type)
                .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
                .where(DNSZone.group_id == bare.id)
            )
        )
        .scalars()
        .all()
    )
    assert "ALIAS" not in stored
    assert {"A", "LUA"} <= set(stored)


async def test_commit_keeps_alias_with_a_do53_forwarder(
    db_session: AsyncSession, client: AsyncClient, pdns_full_zone: None
) -> None:
    _, token = await _make_admin(db_session)
    fwd = await _pdns_group(db_session, "fwd3", ["10.0.0.53"])
    plan = await _preview(client, token, fwd)
    resp = await client.post(
        "/api/v1/dns/import/powerdns/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={"target_group_id": str(fwd.id), "plan": plan, "conflict_actions": {}},
    )
    assert resp.status_code == 200, resp.text
    stored = (
        (
            await db_session.execute(
                select(DNSRecord.record_type)
                .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
                .where(DNSZone.group_id == fwd.id)
            )
        )
        .scalars()
        .all()
    )
    assert "ALIAS" in stored
