"""Web exposure detection (#3651): classification, windowing, verdict, the
alert, the API, the MCP tools and every opt-in mitigation.

Redis-backed cases run against the suite's real Redis under a per-test key
prefix, so parallel runs cannot see each other's counters.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.db as app_db
from app.config import settings
from app.core.redis_client import make_async_redis
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services import feature_modules as fm
from app.services.web_exposure import config as cfg_mod
from app.services.web_exposure import mitigations, store
from app.services.web_exposure.classify import bucket_of, classify, parse_networks
from app.services.web_exposure.config import WebExposureConfig
from app.services.web_exposure.verdict import build_verdict

pytestmark = pytest.mark.asyncio

_PW = "Exposure-test-pw-1!"


# ── Fixtures ────────────────────────────────────────────────────────


@pytest_asyncio.fixture(autouse=True)
async def _isolated_redis(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> AsyncGenerator[str, None]:
    prefix = f"webexp-test-{uuid.uuid4().hex[:8]}:"
    monkeypatch.setattr(store, "KEY_PREFIX", prefix)
    # The request hook and the login path read config through the app's own
    # session factory; point it at the test database.
    monkeypatch.setattr(
        app_db,
        "AsyncSessionLocal",
        async_sessionmaker(db_session.bind, class_=AsyncSession, expire_on_commit=False),
    )
    cfg_mod.invalidate_cache()
    store.reset_buffer()
    yield prefix
    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    try:
        keys = [k async for k in r.scan_iter(match=f"{prefix}*")]
        if keys:
            await r.delete(*keys)
    finally:
        await r.aclose()
    cfg_mod.invalidate_cache()
    store.reset_buffer()


def _from(ip: str, **kw: Any) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app, client=(ip, 41234)),
        base_url="http://test",
        **kw,
    )


async def _user(
    db: AsyncSession, *, superadmin: bool = False, totp: bool = False
) -> tuple[User, dict[str, str]]:
    name = f"wx-{uuid.uuid4().hex[:8]}"
    u = User(
        username=name,
        email=f"{name}@example.com",
        display_name=name,
        hashed_password=hash_password(_PW),
        auth_source="local",
        is_superadmin=superadmin,
        totp_enabled=totp,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    if totp:
        u.totp_secret_encrypted = b"x"
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _set_config(db: AsyncSession, **values: Any) -> WebExposureConfig:
    row = await db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
        await db.flush()
    cfg = WebExposureConfig.model_validate({**(row.web_exposure or {}), **values})
    row.web_exposure = cfg.model_dump()
    await db.commit()
    cfg_mod.invalidate_cache()
    return cfg


async def _drain() -> None:
    await store.flush()


# ── Classification ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip",
    [
        "10.1.2.3",
        "172.16.9.9",
        "192.168.0.5",
        "100.64.0.1",  # CGNAT
        "100.127.255.254",
        "fd12:3456::1",  # ULA
        "127.0.0.1",
        "::1",
        "169.254.1.1",  # link-local
        "fe80::1",
        "::ffff:10.0.0.7",  # v4-mapped private
    ],
)
async def test_private_space_is_internal(ip: str) -> None:
    assert classify(ip) == "internal"


@pytest.mark.parametrize(
    "ip", ["203.0.113.7", "8.8.8.8", "100.128.0.1", "2001:db8::1", "2606:4700::1", "::ffff:8.8.8.8"]
)
async def test_everything_else_is_external(ip: str) -> None:
    assert classify(ip) == "external"


async def test_documentation_and_reserved_ranges_are_not_internal() -> None:
    # ``ipaddress.is_private`` calls these private; for this feature they are not.
    for ip in ("192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "0.0.0.1"):
        assert classify(ip) == "external", ip


async def test_trusted_list_is_the_only_escape_for_public_ranges() -> None:
    trusted = parse_networks(["203.0.113.0/24", "2001:db8:aaaa::/48"])
    assert classify("203.0.113.200", trusted) == "trusted"
    assert classify("2001:db8:aaaa::5", trusted) == "trusted"
    assert classify("203.0.114.1", trusted) == "external"
    # a v4 entry never matches a v6 address and vice versa
    assert classify("2001:db8:bbbb::1", trusted) == "external"
    assert classify(None) is None
    assert classify("not-an-ip") is None


async def test_buckets_are_coarse() -> None:
    assert bucket_of("203.0.113.77") == "203.0.113.0/24"
    assert bucket_of("2001:db8:1:2:3:4:5:6") == "2001:db8:1::/48"
    assert bucket_of("::ffff:203.0.113.77") == "203.0.113.0/24"


# ── Module default ──────────────────────────────────────────────────


async def test_module_ships_off_and_requires_nothing() -> None:
    spec = fm.MODULES_BY_ID["security.web_exposure"]
    assert spec.group == "Security"
    assert not spec.requires


# ── Windowing and bounds ────────────────────────────────────────────


async def test_window_counts_only_recent_hours() -> None:
    now = time.time()
    store.record("198.51.100.0/24", "198.51.100.4", store.SIGNAL_LOGIN_PAGE, now=now)
    store.record("192.0.2.0/24", "192.0.2.4", store.SIGNAL_LOGIN_PAGE, now=now - 30 * 3600)
    await _drain()
    one_day = await store.read_window(24, now=now)
    assert one_day is not None
    assert [b.bucket for b in one_day.buckets] == ["198.51.100.0/24"]
    two_days = await store.read_window(48, now=now)
    assert two_days is not None
    assert {b.bucket for b in two_days.buckets} == {"198.51.100.0/24", "192.0.2.0/24"}


async def test_evidence_is_kept_and_capped() -> None:
    now = time.time()
    for i in range(20):
        store.record(
            "198.51.100.0/24",
            f"198.51.100.{i}",
            store.SIGNAL_UNAUTH,
            path=f"/api/v1/thing{i}/{'x' * 200}",
            now=now + i,
        )
    await _drain()
    data = await store.read_window(24, now=now + 30)
    assert data is not None
    (b,) = data.buckets
    assert b.counts[store.SIGNAL_UNAUTH] == 20
    assert len(b.addresses) == store.SAMPLE_ADDRESSES
    assert len(b.paths) <= store.SAMPLE_PATHS
    assert all(len(p) <= 80 for p in b.paths)
    assert b.first_seen == int(now) and b.last_seen == int(now + 19)


async def test_storage_is_bounded_however_many_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "MAX_BUFFER_ENTRIES", 5)
    now = time.time()
    for i in range(50):
        store.record(f"198.51.{i}.0/24", f"198.51.{i}.1", store.SIGNAL_LOGIN_PAGE, now=now)
    assert len(store._buffer) == 5
    assert store.dropped == 45
    await _drain()
    monkeypatch.setattr(store, "MAX_FIELDS_PER_HOUR", 48)
    for round_ in range(4):
        for i in range(30):
            store.record(f"203.{round_}.{i}.0/24", f"203.{round_}.{i}.1", "login_page", now=now)
        await _drain()
    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    try:
        assert int(await r.hlen(store.hour_key(store.hour_of(now)))) <= 48 + 12
    finally:
        await r.aclose()


async def test_usernames_are_counted_not_stored() -> None:
    now = time.time()
    for n in ("alice", "bob", "carol", "Alice"):
        store.record("198.51.100.0/24", "198.51.100.9", store.SIGNAL_LOGIN_FAILURE, username=n)
    await _drain()
    data = await store.read_window(24, now=now + 5)
    assert data is not None and data.distinct_usernames == 3
    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    try:
        blob = json.dumps(
            {
                (k.decode() if isinstance(k, bytes) else k): (
                    v.decode() if isinstance(v, bytes) else v
                )
                for k, v in (await r.hgetall(store.hour_key(store.hour_of(time.time())))).items()
            }
        )
    finally:
        await r.aclose()
    assert "alice" not in blob.lower()


# ── Verdict ─────────────────────────────────────────────────────────


def _ev(bucket: str, **counts: int) -> store.BucketEvidence:
    return store.BucketEvidence(
        bucket, counts, 1_700_000_000, 1_700_000_100, ["203.0.113.4"], ["/x"]
    )


def _win(*buckets: store.BucketEvidence, users: int = 0, proxy: int = 0) -> store.WindowData:
    return store.WindowData(list(buckets), users, proxy)


async def test_verdict_not_observed_is_honest() -> None:
    v = build_verdict(_win(), WebExposureConfig(), include_addresses=True)
    assert v.verdict == "not_observed" and v.severity is None
    assert "not proof" in v.summary


async def test_verdict_below_threshold_is_reached_from_outside_without_an_alert() -> None:
    w = _win(_ev("203.0.113.0/24", login_page=4), _ev("198.51.100.0/24", unauth_api=2))
    v = build_verdict(w, WebExposureConfig(), include_addresses=True)
    assert v.verdict == "reached_from_outside" and v.severity is None


async def test_version_polling_alone_never_reaches_the_threshold() -> None:
    w = _win(*[_ev(f"198.51.{i}.0/24", version=50) for i in range(10)])
    v = build_verdict(w, WebExposureConfig(), include_addresses=True)
    assert v.verdict == "reached_from_outside"


async def test_verdict_exposed_at_threshold_carries_evidence() -> None:
    w = _win(*[_ev(f"198.51.{i}.0/24", login_page=1) for i in range(3)])
    v = build_verdict(w, WebExposureConfig(), include_addresses=True)
    assert v.verdict == "exposed" and v.severity == "warning"
    assert v.distinct_external_buckets == 3 and v.totals["login_page"] == 3
    assert (
        v.since and v.buckets[0].addresses == ["203.0.113.4"] and v.buckets[0].endpoints == ["/x"]
    )
    assert v.fix_hint and v.deployment_shape in {"appliance", "compose", "kubernetes", "unknown"}
    # addresses are withheld unless asked for
    v2 = build_verdict(w, WebExposureConfig(), include_addresses=False)
    assert all(b.addresses is None for b in v2.buckets)


async def test_any_failed_login_or_host_refusal_from_outside_is_exposed_and_critical_for_logins() -> (
    None
):
    one = _win(_ev("203.0.113.0/24", login_failure=1))
    v = build_verdict(one, WebExposureConfig(), include_addresses=False)
    assert v.verdict == "exposed" and v.severity == "critical" and v.attack_evidence
    host = _win(_ev("203.0.113.0/24", host_refused=1))
    v = build_verdict(host, WebExposureConfig(), include_addresses=False)
    assert v.verdict == "exposed" and v.severity == "warning"


async def test_username_spray_escalates_to_critical() -> None:
    w = _win(*[_ev(f"198.51.{i}.0/24", login_page=1) for i in range(3)], users=9)
    v = build_verdict(w, WebExposureConfig(), include_addresses=False)
    assert v.severity == "critical"


async def test_intentional_demotes_reachability_but_not_attack_evidence() -> None:
    cfg = WebExposureConfig(intentional=True)
    reach = _win(*[_ev(f"198.51.{i}.0/24", login_page=1) for i in range(3)])
    assert build_verdict(reach, cfg, include_addresses=False).severity == "info"
    attack = _win(_ev("203.0.113.0/24", login_failure=2))
    assert build_verdict(attack, cfg, include_addresses=False).severity == "critical"


async def test_unreadable_counters_are_unknown_never_not_observed() -> None:
    v = build_verdict(None, WebExposureConfig(), include_addresses=False)
    assert v.verdict == "unknown"


async def test_proxy_without_real_ip_is_an_attribution_warning_not_a_source() -> None:
    w = _win(_ev("10.0.0.0/24", proxy_no_real_ip=40), proxy=40)
    v = build_verdict(w, WebExposureConfig(), include_addresses=False)
    assert v.attribution_warning and v.verdict == "not_observed"


# ── The request hook ────────────────────────────────────────────────


async def test_external_requests_are_counted_with_endpoints(client: AsyncClient) -> None:
    async with _from("203.0.113.9") as ext:
        r = await ext.get("/api/v1/settings/public")
        assert r.status_code == 200
        assert (await ext.get("/api/v1/ipam/spaces")).status_code in (401, 403)
        await ext.get("/api/v1/version")
        await ext.get("/health/live")
    await _drain()
    data = await store.read_window(24)
    assert data is not None and [b.bucket for b in data.buckets] == ["203.0.113.0/24"]
    c = data.buckets[0].counts
    assert c.get("login_page") == 1 and c.get("unauth_api") == 1 and c.get("version") == 1
    assert "/api/v1/settings/public" in data.buckets[0].paths
    assert not any("health" in p for p in data.buckets[0].paths)


async def test_internal_trusted_and_module_off_record_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    for ip in ("10.0.0.5", "100.64.3.3", "fd00::9", "127.0.0.1"):
        async with _from(ip) as c:
            await c.get("/api/v1/settings/public")
    await _set_config(db_session, trusted_networks=["203.0.113.0/24"])
    async with _from("203.0.113.50") as c:
        await c.get("/api/v1/settings/public")
    await _drain()
    data = await store.read_window(24)
    assert data is not None and data.buckets == []

    # module off: an external source is not counted either
    from app.models.feature_module import FeatureModule

    db_session.add(FeatureModule(id="security.web_exposure", enabled=False))
    await db_session.commit()
    fm.invalidate_cache()
    async with _from("198.51.100.9") as c:
        await c.get("/api/v1/settings/public")
    await _drain()
    data = await store.read_window(24)
    assert data is not None and data.buckets == []


async def test_agent_and_supervisor_surfaces_never_count(client: AsyncClient) -> None:
    async with _from("203.0.113.9") as ext:
        await ext.post("/api/v1/dns/agents/register", json={})
        await ext.post("/api/v1/appliance/supervisor/heartbeat", json={})
        await ext.get("/api/v1/dhcp/agents/config")
    await _drain()
    data = await store.read_window(24)
    assert data is not None and data.buckets == []


async def test_x_real_ip_is_believed_only_from_a_trusted_proxy(client: AsyncClient) -> None:
    # A trusted (loopback) proxy peer forwarding an external client: counted.
    async with _from("127.0.0.1") as proxy:
        await proxy.get("/api/v1/settings/public", headers={"X-Real-IP": "203.0.113.20"})
    # An external peer claiming to be internal: NOT believed, still external.
    async with _from("198.51.100.30") as spoof:
        await spoof.get("/api/v1/settings/public", headers={"X-Real-IP": "10.0.0.1"})
    await _drain()
    data = await store.read_window(24)
    assert data is not None
    assert {b.bucket for b in data.buckets} == {"203.0.113.0/24", "198.51.100.0/24"}


async def test_proxy_sending_xff_without_x_real_ip_is_flagged(client: AsyncClient) -> None:
    async with _from("10.9.9.9") as proxy:
        await proxy.get("/api/v1/settings/public", headers={"X-Forwarded-For": "203.0.113.5"})
    await _drain()
    data = await store.read_window(24)
    assert data is not None and data.proxy_no_real_ip == 1


async def test_failed_login_from_outside_is_counted_with_username_hash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    async with _from("203.0.113.9") as ext:
        r = await ext.post(
            "/api/v1/auth/login",
            json={"username": f"ghost-{uuid.uuid4().hex[:8]}", "password": "x"},
        )
        assert r.status_code == 401
    await _drain()
    data = await store.read_window(24)
    assert data is not None and data.buckets[0].counts["login_failure"] == 1
    assert data.distinct_usernames == 1
    # an internal failure is not an exposure signal
    async with _from("10.0.0.4") as inside:
        await inside.post(
            "/api/v1/auth/login",
            json={"username": f"ghost-{uuid.uuid4().hex[:8]}", "password": "x"},
        )
    await _drain()
    data = await store.read_window(24)
    assert data is not None and len(data.buckets) == 1


# ── The alert ───────────────────────────────────────────────────────


async def test_alert_matcher_opens_one_event_with_evidence(db_session: AsyncSession) -> None:
    from app.models.alerts import AlertRule
    from app.services import alerts as a
    from app.services.alert_rule_catalogue import rule_type_names

    assert a.RULE_TYPE_WEB_UI_EXPOSED in a.RULE_TYPES
    assert a.RULE_TYPE_WEB_UI_EXPOSED in rule_type_names()
    assert a.rule_type_module(a.RULE_TYPE_WEB_UI_EXPOSED) == "security.web_exposure"

    rule = AlertRule(
        name="x", rule_type=a.RULE_TYPE_WEB_UI_EXPOSED, severity="warning", enabled=True
    )
    assert await a._matching_web_ui_exposed_subjects(db_session, rule) == []

    now = time.time()
    for i in range(3):
        store.record(
            f"198.51.{i}.0/24",
            f"198.51.{i}.4",
            "login_page",
            path="/api/v1/settings/public",
            now=now,
        )
    await _drain()
    (m,) = await a._matching_web_ui_exposed_subjects(db_session, rule)
    subject, _display, message, severity = m
    assert subject == "install" and severity == "warning"
    assert "198.51.0.0/24" in message and "/api/v1/settings/public" in message
    assert "198.51.0.4" not in message  # exact addresses never leave in an alert payload

    store.record("198.51.0.0/24", "198.51.0.4", "login_failure", username="u", now=now)
    await _drain()
    (m,) = await a._matching_web_ui_exposed_subjects(db_session, rule)
    assert m[3] == "critical"

    rule.threshold_percent = 50  # operator raised the network threshold
    store.reset_buffer()


async def test_seed_is_idempotent_and_enabled(db_session: AsyncSession) -> None:
    from app.models.alerts import AlertRule
    from app.services import alerts as a

    await a.seed_web_ui_exposed_alert_rule()
    await a.seed_web_ui_exposed_alert_rule()
    rows = (
        (
            await db_session.execute(
                select(AlertRule).where(AlertRule.rule_type == a.RULE_TYPE_WEB_UI_EXPOSED)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1 and rows[0].enabled


# ── API ─────────────────────────────────────────────────────────────


async def test_verdict_privilege_split(client: AsyncClient, db_session: AsyncSession) -> None:
    now = time.time()
    for i in range(3):
        store.record(f"198.51.{i}.0/24", f"198.51.{i}.4", "login_page", now=now)
    await _drain()
    _, plain = await _user(db_session)
    _, root = await _user(db_session, superadmin=True)
    r = await client.get("/api/v1/web-exposure/verdict", headers=plain)
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "exposed" and body["distinct_external_buckets"] == 3
    assert body["buckets"] == []
    r = await client.get("/api/v1/web-exposure/verdict", headers=root)
    body = r.json()
    assert len(body["buckets"]) == 3 and body["buckets"][0]["addresses"]


async def test_config_is_superadmin_only_audited_and_validated(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, plain = await _user(db_session)
    _, root = await _user(db_session, superadmin=True)
    assert (await client.get("/api/v1/web-exposure/config", headers=plain)).status_code == 403
    assert (
        await client.put("/api/v1/web-exposure/config", headers=plain, json={})
    ).status_code == 403

    got = (await client.get("/api/v1/web-exposure/config", headers=root)).json()
    assert got["config"]["trusted_networks"] == []
    assert not any(
        got["config"][k]
        for k in ("external_throttle_enabled", "ban_enabled", "require_mfa_external")
    )
    assert got["caller_class"] == "internal"

    bad = await client.put(
        "/api/v1/web-exposure/config", headers=root, json={"trusted_networks": ["nope"]}
    )
    assert bad.status_code == 422

    ok = await client.put(
        "/api/v1/web-exposure/config",
        headers=root,
        json={"trusted_networks": ["203.0.113.5/24"], "intentional": True, "threshold": 5},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["config"]["trusted_networks"] == ["203.0.113.0/24"]
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "web_exposure", AuditLog.action == "update"
            )
        )
    ).scalar_one()
    assert set(row.changed_fields or []) == {"trusted_networks", "intentional", "threshold"}

    added = await client.post(
        "/api/v1/web-exposure/trusted-networks", headers=root, json={"cidr": "198.51.100.0/24"}
    )
    assert added.json()["config"]["trusted_networks"] == ["203.0.113.0/24", "198.51.100.0/24"]
    assert (
        await client.post(
            "/api/v1/web-exposure/trusted-networks", headers=root, json={"cidr": "zzz"}
        )
    ).status_code == 422


async def test_routes_404_when_the_module_is_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.feature_module import FeatureModule

    _, root = await _user(db_session, superadmin=True)
    db_session.add(FeatureModule(id="security.web_exposure", enabled=False))
    await db_session.commit()
    fm.invalidate_cache()
    assert (await client.get("/api/v1/web-exposure/verdict", headers=root)).status_code == 404


# ── MCP ─────────────────────────────────────────────────────────────


async def test_mcp_tools_are_read_only_superadmin_and_default_enabled() -> None:
    from app.services.ai.tools import REGISTRY

    all_names = [t.name for t in REGISTRY.all()]
    names = [n for n in all_names if "web_exposure" in n or "web_access" in n]
    assert sorted(names) == ["find_web_access_sources", "get_web_exposure_verdict"]
    for n in names:
        t = REGISTRY.get(n)
        assert t is not None
        assert t.module == "security.web_exposure"
        assert t.permission == "superadmin"
        assert not t.writes and t.default_enabled
    assert not [n for n in all_names if n.startswith("propose_") and "exposure" in n]


# ── Mitigations: tier 1a ────────────────────────────────────────────


async def _login(ip: str, username: str | None = None, password: str = "x") -> Any:
    # A fresh name per call: the existing per-username failed-password budget
    # lives in the suite's shared Redis and would otherwise answer 429 for us.
    username = username or f"ghost-{uuid.uuid4().hex[:10]}"
    async with _from(ip) as c:
        return await c.post("/api/v1/auth/login", json={"username": username, "password": password})


async def test_everything_defaults_off(client: AsyncClient, db_session: AsyncSession) -> None:
    c = WebExposureConfig()
    assert not c.any_mitigation()
    for _ in range(12):
        assert (await _login("203.0.113.9")).status_code == 401  # never throttled / banned


async def test_tier_1a_throttles_external_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _set_config(
        db_session,
        external_throttle_enabled=True,
        external_throttle_attempts=3,
        trusted_networks=["198.51.100.0/24"],
    )
    codes = [(await _login(f"203.0.113.{i + 1}")).status_code for i in range(6)]
    # one /24 bucket shares the budget even across addresses
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429, 429]
    r = await _login("203.0.113.99")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    # never-lock-out: internal, trusted and loopback sources are untouched
    for ip in ("10.0.0.8", "100.64.1.1", "198.51.100.7", "127.0.0.1", "fd00::5"):
        for _ in range(6):
            assert (await _login(ip)).status_code == 401, ip
    # another outside network has its own budget
    assert (await _login("192.0.2.5")).status_code == 401


async def test_break_glass_env_disables_every_tier(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _set_config(db_session, external_throttle_enabled=True, external_throttle_attempts=1)
    monkeypatch.setattr(settings, "web_exposure_mitigations", "off")
    for _ in range(5):
        assert (await _login("203.0.113.9")).status_code == 401


async def test_throttle_fails_open_without_redis(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _set_config(db_session, external_throttle_enabled=True, external_throttle_attempts=1)

    def boom() -> Any:
        raise ConnectionError("redis down")

    monkeypatch.setattr(mitigations, "_redis", boom)
    for _ in range(4):
        assert (await _login("203.0.113.9")).status_code == 401


# ── Mitigations: tier 1b ────────────────────────────────────────────


async def test_tier_1b_bans_an_external_bucket_with_backoff_and_audit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _set_config(db_session, ban_enabled=True, ban_failures=3, ban_base_minutes=15)
    for _ in range(3):
        assert (await _login("203.0.113.9")).status_code == 401
    r = await _login("203.0.113.77")  # same /24
    assert r.status_code == 429
    assert 0 < int(r.headers["Retry-After"]) <= 15 * 60
    bans = await mitigations.list_bans()
    assert bans and bans[0]["bucket"] == "203.0.113.0/24" and bans[0]["level"] == 1
    audit = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "web_exposure.ban"))
    ).scalar_one()
    assert audit.resource_id == "203.0.113.0/24"
    # other networks and every internal source are unaffected
    assert (await _login("192.0.2.5")).status_code == 401
    for _ in range(8):
        assert (await _login("10.1.1.1")).status_code == 401
    assert (
        await mitigations.list_bans() is not None and len(await mitigations.list_bans() or []) == 1
    )


async def test_ban_doubles_up_to_the_cap_and_is_bounded(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _set_config(
        db_session, ban_enabled=True, ban_failures=3, ban_base_minutes=15, ban_max_hours=1
    )
    levels = []
    for _ in range(4):
        for _ in range(3):
            await mitigations.register_failure("203.0.113.9")
        (ban,) = await mitigations.list_bans() or []
        levels.append(ban["minutes"])
        # let the next ban start fresh without waiting out the TTL
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            await r.hdel(f"{store.KEY_PREFIX}bans", "203.0.113.0/24")
        finally:
            await r.aclose()
    assert levels == [15, 30, 60, 60]  # doubled, capped at ban_max_hours

    monkeypatch.setattr(mitigations, "MAX_BANS", 3)
    await _set_config(db_session, ban_failures=3)
    for i in range(6):
        for _ in range(3):
            await mitigations.register_failure(f"198.51.{i}.9")
    assert len(await mitigations.list_bans() or []) == 3


async def test_bans_can_be_listed_and_cleared_from_settings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _set_config(db_session, ban_enabled=True, ban_failures=3)
    for _ in range(3):
        await _login("203.0.113.9")
    assert (await _login("203.0.113.9")).status_code == 429
    _, plain = await _user(db_session)
    _, root = await _user(db_session, superadmin=True)
    assert (await client.get("/api/v1/web-exposure/bans", headers=plain)).status_code == 403
    assert (await client.delete("/api/v1/web-exposure/bans", headers=plain)).status_code == 403
    listed = (await client.get("/api/v1/web-exposure/bans", headers=root)).json()
    assert [b["bucket"] for b in listed["bans"]] == ["203.0.113.0/24"]
    r = await client.delete(
        "/api/v1/web-exposure/bans", headers=root, params={"bucket": "203.0.113.0/24"}
    )
    assert r.json() == {"cleared": 1}
    assert (await _login("203.0.113.9")).status_code == 401
    cleared = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "web_exposure.ban_cleared")
        )
    ).scalar_one()
    assert cleared.new_value["cleared"] == 1


# ── Mitigations: tier 2 ─────────────────────────────────────────────


async def test_tier_2_refuses_local_accounts_without_totp_from_outside_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ip = f"203.0.113.{uuid.uuid4().int % 200 + 20}"  # per-IP login budget is shared Redis
    plain_user, _ = await _user(db_session)
    totp_user, _ = await _user(db_session, totp=True)
    await _set_config(db_session, require_mfa_external=True)

    # outside, no second factor: refused AFTER the password was verified
    r = await _login(ip, plain_user.username, _PW)
    assert r.status_code == 403 and "second factor" in r.json()["detail"]
    assert "access_token" not in r.json()
    # a wrong password still looks exactly like it always did
    assert (await _login(ip, plain_user.username, "wrong")).status_code == 401
    # outside, TOTP enrolled: proceeds to the MFA challenge
    ok = await _login(ip, totp_user.username, _PW)
    assert ok.status_code == 200 and ok.json()["mfa_required"] is True
    # inside (internal, loopback, trusted): unaffected
    for ip in ("10.0.0.3", "127.0.0.1", "100.64.0.9"):
        assert (await _login(ip, plain_user.username, _PW)).status_code == 200, ip
    await _set_config(db_session, trusted_networks=["203.0.113.0/24"])
    assert (await _login(ip, plain_user.username, _PW)).status_code == 200


async def test_tier_2_preflight_refuses_a_lockout_and_names_who_is_stranded(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin, _ = await _user(db_session, superadmin=True)
    stranded, _ = await _user(db_session, superadmin=True)
    enrolled, enrolled_headers = await _user(db_session, superadmin=True, totp=True)
    # The enabling superadmin signs in from outside with no TOTP: refused, 422
    # lists every local superadmin without TOTP.
    async with _from("203.0.113.9") as ext:
        r = await ext.put(
            "/api/v1/web-exposure/config",
            headers={"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
            json={"require_mfa_external": True},
        )
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert admin.username in detail and stranded.username in detail
    assert enrolled.username not in detail
    # An admin who HAS TOTP may enable it even from outside
    async with _from("203.0.113.9") as ext:
        r = await ext.put(
            "/api/v1/web-exposure/config",
            headers=enrolled_headers,
            json={"require_mfa_external": True},
        )
    assert r.status_code == 200
    # ...and any superadmin sitting inside may enable it
    await _set_config(db_session, require_mfa_external=False)
    r = await client.put(
        "/api/v1/web-exposure/config",
        headers={"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
        json={"require_mfa_external": True},
    )
    assert r.status_code == 200


async def test_tier_1_enable_from_an_external_address_warns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, root = await _user(db_session, superadmin=True)
    async with _from("203.0.113.9") as ext:
        r = await ext.put("/api/v1/web-exposure/config", headers=root, json={"ban_enabled": True})
    assert r.status_code == 200 and r.json()["warnings"]


# ── Tier 3a: appliance Web UI source restriction ────────────────────


async def test_tier_3a_is_appliance_only(client: AsyncClient, db_session: AsyncSession) -> None:
    _, root = await _user(db_session, superadmin=True)
    r = await client.post("/api/v1/web-exposure/apply-web-ui-allow-list", headers=root, json={})
    assert r.status_code == 409


async def test_tier_3a_bridges_to_the_existing_guarded_endpoint(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "appliance_mode", True)
    _, root = await _user(db_session, superadmin=True)
    await _set_config(db_session, trusted_networks=["203.0.113.0/24"])
    r = await client.post("/api/v1/web-exposure/apply-web-ui-allow-list", headers=root, json={})
    assert r.status_code == 200, r.text
    cidrs = r.json()["allowed_cidrs"]
    assert "203.0.113.0/24" in cidrs and "10.0.0.0/8" in cidrs and "100.64.0.0/10" in cidrs
    assert "fc00::/7" in cidrs and "127.0.0.0/8" in cidrs
    row = await db_session.get(PlatformSettings, 1)
    await db_session.refresh(row)
    assert "203.0.113.0/24" in row.web_ui_allowed_cidrs
    acts = (
        (
            await db_session.execute(
                select(AuditLog.action).where(
                    AuditLog.resource_type.in_(["web_exposure", "platform_settings"])
                )
            )
        )
        .scalars()
        .all()
    )
    assert "web_exposure.apply_web_ui_allow_list" in acts

    # The #1013 guard still applies: an operator signing in from an address
    # the list does not cover is refused rather than stranded.
    await db_session.execute(PlatformSettings.__table__.update().values(web_ui_allowed_cidrs=[]))
    await db_session.commit()
    async with _from("198.51.100.4") as ext:
        r = await ext.post("/api/v1/web-exposure/apply-web-ui-allow-list", headers=root, json={})
    assert r.status_code == 422
