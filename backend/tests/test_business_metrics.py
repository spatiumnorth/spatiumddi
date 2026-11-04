"""IPAM / DHCP business series on /metrics (#2146)."""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from app import metrics as metrics_mod
from app.config import settings
from app.metrics import metrics_endpoint
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import business_metrics
from app.services.business_metrics import business_metrics_text

TOKEN = "scrape-token-2146"


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    business_metrics.clear_cache()


async def _estate(db: AsyncSession) -> tuple[Subnet, DHCPScope]:
    space = IPSpace(name="lab", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.70.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.70.0.0/24",
        name="s",
        total_ips=254,
        allocated_ips=25,
    )
    db.add(subnet)
    await db.flush()
    group = DHCPServerGroup(name="edge")
    db.add(group)
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="ha-scope")
    servers = [
        DHCPServer(
            name=f"kea-{i}-{uuid.uuid4().hex[:4]}",
            host=f"10.0.0.{i}",
            driver="kea",
            server_group_id=group.id,
        )
        for i in (1, 2)
    ]
    db.add_all([scope, *servers])
    await db.flush()
    for server in servers:  # an HA pair mirrors the same lease
        db.add(
            DHCPLease(
                server_id=server.id,
                scope_id=scope.id,
                ip_address="10.70.0.10",
                mac_address="aa:bb:cc:00:00:01",
                state="active",
            )
        )
    db.add(
        DHCPLease(
            server_id=servers[0].id,
            scope_id=scope.id,
            ip_address="10.70.0.11",
            mac_address="aa:bb:cc:00:00:02",
            state="active",
        )
    )
    await db.flush()
    return subnet, scope


@pytest.mark.asyncio
async def test_series_carry_the_seeded_values(db_session: AsyncSession) -> None:
    subnet, scope = await _estate(db_session)
    text = await business_metrics_text(db_session)
    sl = f'subnet_id="{subnet.id}",subnet="10.70.0.0/24",space="lab"'
    assert f"spatiumddi_subnet_allocated_ips{{{sl}}} 25" in text
    assert f"spatiumddi_subnet_total_ips{{{sl}}} 254" in text
    pct = round(25 / 254 * 100, 4)
    assert f"spatiumddi_subnet_utilization_percent{{{sl}}} {pct}" in text
    cl = f'scope_id="{scope.id}",scope="ha-scope",group="edge",subnet="10.70.0.0/24"'
    # HA pair: 3 lease rows, 2 distinct addresses
    assert f"spatiumddi_dhcp_scope_active_leases{{{cl}}} 2" in text
    assert f"spatiumddi_dhcp_scope_active{{{cl}}} 1" in text
    assert "spatiumddi_business_metrics_truncated 0" in text


@pytest.mark.asyncio
async def test_no_per_address_or_client_labels(db_session: AsyncSession) -> None:
    await _estate(db_session)
    text = await business_metrics_text(db_session)
    for forbidden in ("10.70.0.10", "10.70.0.11", "aa:bb:cc", "mac=", "ip="):
        assert forbidden not in text
    labels = {
        part.split("=")[0]
        for line in text.splitlines()
        if "{" in line and not line.startswith("#")
        for part in line[line.index("{") + 1 : line.index("}")].split(",")
    }
    assert labels <= {"subnet_id", "subnet", "space", "scope_id", "scope", "group"}


@pytest.mark.asyncio
async def test_series_are_capped(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
    await _estate(db_session)
    monkeypatch.setattr(business_metrics, "MAX_SERIES_PER_FAMILY", 0)
    text = await _render_uncached(db_session)
    assert "spatiumddi_business_metrics_truncated 1" in text


async def _render_uncached(db: AsyncSession) -> str:
    business_metrics.clear_cache()
    return await business_metrics_text(db)


@pytest.mark.asyncio
async def test_a_scrape_is_three_queries_and_cached(db_session: AsyncSession) -> None:
    await _estate(db_session)
    count = 0
    seen: list[str] = []

    def _count(conn: object, cursor: object, statement: str, *_a: object) -> None:
        nonlocal count
        seen.append(statement)
        if "FROM" in statement:  # not driver type-introspection / SAVEPOINTs
            count += 1

    sync_engine = db_session.get_bind()
    event.listen(sync_engine, "before_cursor_execute", _count)
    try:
        await business_metrics_text(db_session)
        first = count
        await business_metrics_text(db_session)
    finally:
        event.remove(sync_engine, "before_cursor_execute", _count)
    assert first <= 6, seen  # constant: ORM eager loads, not per-row
    assert count == first, "the second scrape inside the TTL must not query"


def _app() -> FastAPI:
    app = FastAPI()
    app.add_route("/metrics", metrics_endpoint)
    return app


@pytest.fixture
def stub_block(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _block() -> bytes:
        return b'spatiumddi_subnet_total_ips{subnet="x"} 1\n'

    monkeypatch.setattr(metrics_mod, "_business_block", _block)


def test_authenticated_scrape_includes_the_series(
    monkeypatch: pytest.MonkeyPatch, stub_block: None
) -> None:
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", True)
    monkeypatch.setattr(settings, "prometheus_metrics_token", TOKEN)
    r = TestClient(_app()).get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200
    assert b"spatiumddi_subnet_total_ips" in r.content


def test_unauthenticated_scrape_is_still_refused_and_leaks_nothing(
    monkeypatch: pytest.MonkeyPatch, stub_block: None
) -> None:
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", True)
    monkeypatch.setattr(settings, "prometheus_metrics_token", TOKEN)
    r = TestClient(_app()).get("/metrics")
    assert r.status_code == 401
    assert b"spatiumddi_" not in r.content


def test_anonymous_mode_omits_business_series(
    monkeypatch: pytest.MonkeyPatch, stub_block: None
) -> None:
    """Names and CIDRs must not reach an endpoint anyone can scrape."""
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", False)
    r = TestClient(_app()).get("/metrics")
    assert r.status_code == 200
    assert b"spatiumddi_subnet_total_ips" not in r.content


def test_business_series_can_be_switched_off(
    monkeypatch: pytest.MonkeyPatch, stub_block: None
) -> None:
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", True)
    monkeypatch.setattr(settings, "prometheus_metrics_token", TOKEN)
    monkeypatch.setattr(settings, "prometheus_business_metrics_enabled", False)
    r = TestClient(_app()).get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200
    assert b"spatiumddi_subnet_total_ips" not in r.content
