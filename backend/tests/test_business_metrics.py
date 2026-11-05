"""IPAM / DHCP business series on /metrics (#2146)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import metrics as metrics_mod
from app.config import settings
from app.core.security import generate_api_token, hash_password
from app.main import _BUILTIN_ROLES
from app.metrics import metrics_endpoint
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import APIToken, Group, Role, User
from app.models.dhcp import DHCPLease, DHCPPool, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.metrics import DHCPMetricSample, DNSMetricSample
from app.services import business_metrics
from app.services.business_metrics import business_metrics_text
from app.services.influxdb.collect import (
    collect_dhcp_scope_lease_points,
    collect_subnet_utilization_points,
)

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
    assert labels <= {
        "subnet_id",
        "subnet",
        "space",
        "scope_id",
        "scope",
        "group",
        "pool_id",
        "pool",
        "server_id",
        "server",
        "rcode",
        "severity",
    }


@pytest.mark.asyncio
async def test_series_are_capped(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
    await _estate(db_session)
    monkeypatch.setattr(business_metrics, "MAX_SERIES_PER_FAMILY", 0)
    text = await _render_uncached(db_session)
    assert "spatiumddi_business_metrics_truncated 1" in text


async def _render_uncached(db: AsyncSession) -> str:
    business_metrics.clear_cache()
    return await business_metrics_text(db)


async def _count_queries(db: AsyncSession) -> int:
    count = 0

    def _count(conn: object, cursor: object, statement: str, *_a: object) -> None:
        nonlocal count
        if "FROM" in statement:  # not driver type-introspection / SAVEPOINTs
            count += 1

    sync_engine = db.get_bind()
    event.listen(sync_engine, "before_cursor_execute", _count)
    try:
        await _render_uncached(db)
    finally:
        event.remove(sync_engine, "before_cursor_execute", _count)
    return count


@pytest.mark.asyncio
async def test_a_scrape_costs_the_same_queries_however_large_the_estate(
    db_session: AsyncSession,
) -> None:
    await _estate(db_session)
    small = await _count_queries(db_session)
    space = (await db_session.execute(select(IPSpace))).scalars().first()
    assert space is not None
    block = IPBlock(space_id=space.id, network="10.80.0.0/16", name="big")
    db_session.add(block)
    await db_session.flush()
    for i in range(30):
        db_session.add(
            Subnet(
                space_id=space.id,
                block_id=block.id,
                network=f"10.80.{i}.0/24",
                name=f"n{i}",
                total_ips=254,
            )
        )
    await db_session.flush()
    assert await _count_queries(db_session) == small, "no per-subnet queries"


@pytest.mark.asyncio
async def test_a_second_scrape_inside_the_ttl_does_not_query(db_session: AsyncSession) -> None:
    await _estate(db_session)
    await _render_uncached(db_session)
    count = 0

    def _count(*_a: object) -> None:
        nonlocal count
        count += 1

    sync_engine = db_session.get_bind()
    event.listen(sync_engine, "before_cursor_execute", _count)
    try:
        await business_metrics_text(db_session)
    finally:
        event.remove(sync_engine, "before_cursor_execute", _count)
    assert count == 0


def _app() -> FastAPI:
    app = FastAPI()
    app.add_route("/metrics", metrics_endpoint)
    return app


@pytest.fixture
def stub_block(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _block(sections: frozenset[str]) -> bytes:
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


# ── Values of the server, pool, traffic and alert families ─────────────────


async def _servers_and_traffic(db: AsyncSession) -> dict[str, str]:
    """A DNS group with one healthy and one reverted server, traffic, RPZ hits,
    a Kea server with socket drops and one without the measurement, a
    dynamic pool and open alerts. Returns the ids the assertions need."""
    now = datetime.now(UTC)
    _, scope = await _estate(db)
    dg = DNSServerGroup(name="core-dns")
    db.add(dg)
    await db.flush()
    up = DNSServer(group_id=dg.id, name="ns1", host="10.1.0.1", status="active")
    down = DNSServer(
        group_id=dg.id,
        name="ns2",
        host="10.1.0.2",
        status="unreachable",
        config_apply_status="reverted",
    )
    db.add_all([up, down])
    await db.flush()
    db.add(
        DNSMetricSample(
            server_id=up.id,
            bucket_at=now - timedelta(minutes=1),
            queries_total=600,
            noerror=540,
            nxdomain=30,
            servfail=30,
        )
    )
    # Outside the 5-minute window: not counted.
    db.add(
        DNSMetricSample(server_id=up.id, bucket_at=now - timedelta(minutes=30), queries_total=99999)
    )
    for policy in ("NXDOMAIN", "CNAME", "PASSTHRU"):
        db.add(DNSRPZHit(server_id=up.id, ts=now, trigger="QNAME", policy=policy))
    kea = (await db.execute(select(DHCPServer).order_by(DHCPServer.name))).scalars().first()
    assert kea is not None
    kea.config_apply_status = "ok"
    db.add(DHCPMetricSample(server_id=kea.id, bucket_at=now, socket_drop=7))
    pool = DHCPPool(
        scope_id=scope.id,
        name="dyn",
        start_ip="10.70.0.10",
        end_ip="10.70.0.19",
        pool_type="dynamic",
    )
    db.add_all(
        [
            pool,
            DHCPPool(
                scope_id=scope.id,
                name="excl",
                start_ip="10.70.0.100",
                end_ip="10.70.0.110",
                pool_type="excluded",
            ),
        ]
    )
    rule = AlertRule(name="r", rule_type="subnet_utilization", severity="critical")
    db.add(rule)
    await db.flush()
    for sev, resolved in (("critical", False), ("warning", False), ("warning", True)):
        db.add(
            AlertEvent(
                rule_id=rule.id,
                subject_type="subnet",
                subject_id=uuid.uuid4().hex,
                subject_display="x",
                severity=sev,
                message="m",
                fired_at=now,
                resolved_at=now if resolved else None,
            )
        )
    await db.flush()
    return {
        "up": str(up.id),
        "down": str(down.id),
        "kea": str(kea.id),
        "kea_name": kea.name,
        "pool": str(pool.id),
        "scope": str(scope.id),
    }


def _samples(text: str) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    """Parse the exposition the way Prometheus does; fails on malformed text."""
    out: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    for fam in text_string_to_metric_families(text):
        for s in fam.samples:
            out[(s.name, tuple(sorted(s.labels.items())))] = s.value
    return out


def _get_value(samples: dict, name: str, **labels: str) -> float | None:
    for (n, lbl), v in samples.items():
        if n == name and all(dict(lbl).get(k) == want for k, want in labels.items()):
            return v
    return None


@pytest.mark.asyncio
async def test_server_pool_traffic_and_alert_families(db_session: AsyncSession) -> None:
    ids = await _servers_and_traffic(db_session)
    samples = _samples(await _render_uncached(db_session))

    assert _get_value(samples, "spatiumddi_dns_server_up", server_id=ids["up"]) == 1
    assert _get_value(samples, "spatiumddi_dns_server_up", server_id=ids["down"]) == 0
    assert _get_value(samples, "spatiumddi_dns_server_config_apply_ok", server_id=ids["down"]) == 0
    # NULL config_apply_status is unknown: no series, never a 1.
    assert _get_value(samples, "spatiumddi_dns_server_config_apply_ok", server_id=ids["up"]) is None
    assert _get_value(samples, "spatiumddi_dhcp_server_config_apply_ok", server_id=ids["kea"]) == 1

    qps = "spatiumddi_dns_queries_per_second"
    assert _get_value(samples, qps, server_id=ids["up"], rcode="all") == 2.0  # 600 / 300 s
    assert _get_value(samples, qps, server_id=ids["up"], rcode="nxdomain") == 0.1
    assert _get_value(samples, "spatiumddi_dns_rpz_blocked_24h", group="core-dns") == 2

    assert _get_value(samples, "spatiumddi_dhcp_packets_dropped_5m", server_id=ids["kea"]) == 7
    # The second Kea server never measured socket drops: no series, not a 0.
    dropped = [k for k in samples if k[0] == "spatiumddi_dhcp_packets_dropped_5m"]
    assert len(dropped) == 1

    # 10.70.0.10 is leased (by both HA partners), 10.70.0.11 too: 2 of 10.
    ratio = "spatiumddi_dhcp_pool_occupancy_ratio"
    assert _get_value(samples, ratio, pool_id=ids["pool"]) == 0.2
    assert len([k for k in samples if k[0] == ratio]) == 1, "only dynamic pools"

    assert _get_value(samples, "spatiumddi_alerts_open", severity="critical") == 1
    assert _get_value(samples, "spatiumddi_alerts_open", severity="warning") == 1
    assert _get_value(samples, "spatiumddi_alerts_open", severity="info") == 0


@pytest.mark.asyncio
async def test_the_numbers_match_the_influxdb_collectors(db_session: AsyncSession) -> None:
    """Both exporters read the same functions, so they report the same values."""
    await _servers_and_traffic(db_session)
    samples = _samples(await _render_uncached(db_session))
    now = datetime.now(UTC)
    subnets = await collect_subnet_utilization_points(db_session, now)
    scopes = await collect_dhcp_scope_lease_points(db_session, now)
    assert subnets and scopes
    for p in subnets:
        sid = p.tags["subnet_id"]
        for name, field in (
            ("spatiumddi_subnet_allocated_ips", "allocated"),
            ("spatiumddi_subnet_total_ips", "total"),
            ("spatiumddi_subnet_utilization_percent", "percent"),
        ):
            assert _get_value(samples, name, subnet_id=sid) == float(p.fields[field])
    for p in scopes:
        assert _get_value(
            samples, "spatiumddi_dhcp_scope_active_leases", scope_id=p.tags["scope_id"]
        ) == float(p.fields["active_leases"])


# ── Trash ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trashed_subnets_scopes_and_pools_are_not_reported(
    db_session: AsyncSession,
) -> None:
    ids = await _servers_and_traffic(db_session)
    subnet = (await db_session.execute(select(Subnet))).scalars().one()
    scope = await db_session.get(DHCPScope, uuid.UUID(ids["scope"]))
    pool = await db_session.get(DHCPPool, uuid.UUID(ids["pool"]))
    assert scope is not None and pool is not None
    now = datetime.now(UTC)
    subnet.deleted_at = now
    scope.deleted_at = now
    await db_session.flush()
    text = await _render_uncached(db_session)
    assert str(subnet.id) not in text
    assert ids["scope"] not in text
    assert ids["pool"] not in text, "a pool under a trashed scope is gone too"

    # The pool alone in the Trash, its subnet and scope live.
    subnet.deleted_at = None
    scope.deleted_at = None
    pool.deleted_at = now
    await db_session.flush()
    text = await _render_uncached(db_session)
    assert ids["scope"] in text
    assert ids["pool"] not in text


# ── Exposition format ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_label_values_are_escaped(db_session: AsyncSession) -> None:
    """A name with a quote, a backslash or a newline must not break the
    exposition: Prometheus rejects the whole scrape on one bad line."""
    nasty = 'lab "east"\\dc\nfloor 2'
    await _estate(db_session)
    space = (await db_session.execute(select(IPSpace))).scalars().one()
    space.name = nasty
    scope = (await db_session.execute(select(DHCPScope))).scalars().one()
    scope.name = nasty
    await db_session.flush()
    text = await _render_uncached(db_session)
    samples = _samples(text)  # raises on malformed exposition
    assert _get_value(samples, "spatiumddi_subnet_total_ips", space=nasty) == 254
    assert _get_value(samples, "spatiumddi_dhcp_scope_active", scope=nasty) == 1
    for line in text.splitlines():
        assert line.startswith(("#", "spatiumddi_")), line


# ── Who may read which section ──────────────────────────────────────────────


async def _owner(db: AsyncSession, role: str | None, *, superadmin: bool = False) -> User:
    u = User(
        username=f"bm-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="scraper",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
        is_active=True,
    )
    u.groups = []
    if role is not None:
        description, perms = _BUILTIN_ROLES[role]
        r = Role(name=f"{role}-{uuid.uuid4().hex[:6]}", description=description, permissions=perms)
        g = Group(name=f"g-{uuid.uuid4().hex[:6]}")
        g.roles = [r]
        u.groups = [g]
        db.add_all([r, g])
    db.add(u)
    await db.flush()
    return u


async def _raw_token(
    db: AsyncSession,
    owner: User,
    *,
    scopes: list[str] | None = None,
    grants: list[dict[str, Any]] | None = None,
) -> str:
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=scopes or [],
            resource_grants=grants,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.commit()
    return raw


async def _scrape(authorization: str) -> tuple[int, str]:
    transport = ASGITransport(app=_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/metrics", headers={"Authorization": authorization})
    return r.status_code, r.text


_IPAM = "spatiumddi_subnet_total_ips"
_SCOPE = "spatiumddi_dhcp_scope_active_leases"
_POOL = "spatiumddi_dhcp_pool_occupancy_ratio"
_DHCP_SRV = "spatiumddi_dhcp_server_up"
_DNS_SRV = "spatiumddi_dns_server_up"
_RPZ = "spatiumddi_dns_rpz_blocked_24h"
_ALERTS = "spatiumddi_alerts_open"
_ALL = {_IPAM, _SCOPE, _POOL, _DHCP_SRV, _DNS_SRV, _RPZ, _ALERTS}


def _families_in(text: str) -> set[str]:
    return {f for f in _ALL if f"\n{f}{{" in text}


@pytest.fixture
def api_tokens_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", True)
    monkeypatch.setattr(settings, "prometheus_metrics_token", TOKEN)
    monkeypatch.setattr(settings, "prometheus_business_metrics_enabled", True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "superadmin", "scopes", "expected"),
    [
        (None, True, None, _ALL),
        ("Viewer", False, None, _ALL),
        ("Viewer", False, ["read"], _ALL),
        ("DNS Editor", False, None, {_DNS_SRV, _ALERTS}),
        ("DHCP Editor", False, None, {_SCOPE, _POOL, _DHCP_SRV, _ALERTS}),
        ("IPAM Editor", False, None, {_IPAM, _ALERTS}),
        (None, False, None, set()),
    ],
    ids=[
        "superadmin",
        "viewer",
        "viewer read-scoped",
        "dns editor",
        "dhcp editor",
        "ipam editor",
        "no grants",
    ],
)
async def test_an_api_token_reads_only_the_sections_its_owner_may_list(
    db_session: AsyncSession,
    api_tokens_only: None,
    role: str | None,
    superadmin: bool,
    scopes: list[str] | None,
    expected: set[str],
) -> None:
    await _servers_and_traffic(db_session)
    owner = await _owner(db_session, role, superadmin=superadmin)
    raw = await _raw_token(db_session, owner, scopes=scopes)
    status, text = await _scrape(f"Bearer {raw}")
    assert status == 200
    assert "spatiumddi_api_requests_total" in text, "process metrics stay readable"
    assert _families_in(text) == expected
    if not expected:
        assert "10.70.0.0/24" not in text and "core-dns" not in text
        assert "spatiumddi_business_metrics_truncated" not in text


@pytest.mark.asyncio
async def test_the_scrape_token_reads_every_section(
    db_session: AsyncSession, api_tokens_only: None
) -> None:
    await _servers_and_traffic(db_session)
    await db_session.commit()
    status, text = await _scrape(f"Bearer {TOKEN}")
    assert status == 200
    assert _families_in(text) == _ALL
    _samples(text)  # the combined scrape parses


@pytest.mark.asyncio
async def test_a_role_scoped_to_one_subnet_reads_no_estate_wide_series(
    db_session: AsyncSession, api_tokens_only: None
) -> None:
    await _servers_and_traffic(db_session)
    subnet = (await db_session.execute(select(Subnet))).scalars().one()
    owner = await _owner(db_session, None)
    r = Role(
        name=f"one-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[
            {"action": "read", "resource_type": "ip_space"},
            {"action": "read", "resource_type": "subnet", "resource_id": str(subnet.id)},
        ],
    )
    g = Group(name=f"g-{uuid.uuid4().hex[:6]}")
    g.roles = [r]
    owner.groups = [g]
    db_session.add_all([r, g])
    raw = await _raw_token(db_session, owner)
    status, text = await _scrape(f"Bearer {raw}")
    assert status == 200
    assert _families_in(text) == set()


@pytest.mark.asyncio
async def test_a_resource_bound_token_is_refused(
    db_session: AsyncSession, api_tokens_only: None
) -> None:
    await _servers_and_traffic(db_session)
    subnet = (await db_session.execute(select(Subnet))).scalars().one()
    owner = await _owner(db_session, None, superadmin=True)
    raw = await _raw_token(
        db_session,
        owner,
        grants=[{"action": "read", "resource_type": "subnet", "resource_id": str(subnet.id)}],
    )
    status, text = await _scrape(f"Bearer {raw}")
    assert status == 401
    assert "10.70.0.0/24" not in text


@pytest.mark.asyncio
async def test_the_cache_never_serves_a_broad_scrape_to_a_narrow_one(
    db_session: AsyncSession, api_tokens_only: None
) -> None:
    await _servers_and_traffic(db_session)
    admin = await _owner(db_session, None, superadmin=True)
    dns = await _owner(db_session, "DNS Editor")
    admin_raw = await _raw_token(db_session, admin)
    dns_raw = await _raw_token(db_session, dns)
    _, admin_text = await _scrape(f"Bearer {admin_raw}")
    assert _families_in(admin_text) == _ALL
    _, dns_text = await _scrape(f"Bearer {dns_raw}")  # inside the TTL
    assert _families_in(dns_text) == {_DNS_SRV, _ALERTS}
    assert "10.70.0.0/24" not in dns_text
