"""Pool member health staleness: shown, alerted on, and serving stays fail-open (#2312)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.auth import User
from app.models.dns import (
    DNSPool,
    DNSPoolMember,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSZone,
)
from app.services import alerts
from app.services.alert_rule_catalogue import build_catalogue
from app.services.dns.pool_apply import apply_pool_state

_RULE = SimpleNamespace(severity="warning")


async def _zone(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(DNSServer(group_id=grp.id, name="ns1", driver="bind9", host="10.0.0.1", is_primary=True))
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.flush()
    return grp, zone


async def _pool(
    db: AsyncSession,
    grp: DNSServerGroup,
    zone: DNSZone,
    name: str,
    *,
    interval: int = 60,
    enabled: bool = True,
    members: list[tuple[str, float | None, str, bool]],
) -> DNSPool:
    """members: (address, last_check age in seconds | None, state, enabled)."""
    pool = DNSPool(
        group_id=grp.id,
        zone_id=zone.id,
        name=name,
        record_name=name,
        record_type="A",
        ttl=30,
        enabled=enabled,
        hc_interval_seconds=interval,
    )
    db.add(pool)
    await db.flush()
    now = datetime.now(UTC)
    for addr, age, state, m_enabled in members:
        db.add(
            DNSPoolMember(
                pool_id=pool.id,
                address=addr,
                enabled=m_enabled,
                last_check_state=state,
                last_check_at=None if age is None else now - timedelta(seconds=age),
            )
        )
    await db.flush()
    await db.refresh(pool, ["members"])
    return pool


async def _fired(db: AsyncSession) -> dict[str, str]:
    out = await alerts._matching_dns_pool_health_stale_subjects(db, _RULE)
    return {display: message for _sid, display, message, _sev in out}


@pytest.mark.asyncio
async def test_alert_fires_past_three_intervals_only(db_session: AsyncSession) -> None:
    grp, zone = await _zone(db_session)
    # interval 60 -> stale after 180 s
    await _pool(db_session, grp, zone, "dead", members=[("192.0.2.1", 3600, "healthy", True)])
    await _pool(db_session, grp, zone, "fresh", members=[("192.0.2.2", 170, "healthy", True)])
    fired = await _fired(db_session)
    assert set(fired) == {"dead"}
    assert "still being served" in fired["dead"]
    assert "1 of 1" in fired["dead"]


@pytest.mark.asyncio
async def test_alert_age_is_minutes_under_an_hour_and_hours_above(
    db_session: AsyncSession,
) -> None:
    grp, zone = await _zone(db_session)
    await _pool(db_session, grp, zone, "mins", members=[("192.0.2.1", 420, "healthy", True)])
    await _pool(
        db_session, grp, zone, "hours", members=[("192.0.2.2", 3 * 3600 + 120, "healthy", True)]
    )
    fired = await _fired(db_session)
    assert "oldest 7 min ago" in fired["mins"]
    assert "0 h" not in fired["mins"]
    assert "oldest 3 h ago" in fired["hours"]


@pytest.mark.asyncio
async def test_interval_floor_is_the_tasks_own_30_seconds(db_session: AsyncSession) -> None:
    grp, zone = await _zone(db_session)
    # A 10 s interval is still checked every 30 s: 80 s old is fine, 100 s is stale.
    await _pool(
        db_session, grp, zone, "ok80", interval=10, members=[("192.0.2.1", 80, "healthy", True)]
    )
    await _pool(
        db_session, grp, zone, "bad100", interval=10, members=[("192.0.2.2", 100, "healthy", True)]
    )
    assert set(await _fired(db_session)) == {"bad100"}


@pytest.mark.asyncio
async def test_disabled_pools_members_and_unchecked_members_never_count(
    db_session: AsyncSession,
) -> None:
    grp, zone = await _zone(db_session)
    await _pool(
        db_session, grp, zone, "off", enabled=False, members=[("192.0.2.1", 9999, "healthy", True)]
    )
    await _pool(db_session, grp, zone, "m-off", members=[("192.0.2.2", 9999, "healthy", False)])
    await _pool(db_session, grp, zone, "never", members=[("192.0.2.3", None, "unknown", True)])
    assert await _fired(db_session) == {}


@pytest.mark.asyncio
async def test_one_event_per_pool_and_stale_unhealthy_alone_omits_served_claim(
    db_session: AsyncSession,
) -> None:
    grp, zone = await _zone(db_session)
    await _pool(
        db_session,
        grp,
        zone,
        "multi",
        members=[
            ("192.0.2.1", 9999, "healthy", True),
            ("192.0.2.2", 9999, "healthy", True),
            ("192.0.2.3", 5, "healthy", True),
        ],
    )
    await _pool(db_session, grp, zone, "down", members=[("192.0.2.9", 9999, "unhealthy", True)])
    out = await alerts._matching_dns_pool_health_stale_subjects(db_session, _RULE)
    assert len(out) == 2
    fired = {d: m for _s, d, m, _v in out}
    assert "2 of 3" in fired["multi"]
    assert "still being served" not in fired["down"]


@pytest.mark.asyncio
async def test_serving_stays_fail_open_for_a_stale_healthy_member(
    db_session: AsyncSession,
) -> None:
    grp, zone = await _zone(db_session)
    pool = await _pool(
        db_session, grp, zone, "www", members=[("192.0.2.1", 99999, "healthy", True)]
    )
    await apply_pool_state(db_session, pool)
    await db_session.flush()
    recs = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id)))
        .scalars()
        .all()
    )
    assert [r.value for r in recs] == ["192.0.2.1"]


@pytest.mark.asyncio
async def test_api_reports_stale_and_age(client: AsyncClient, db_session: AsyncSession) -> None:
    user = User(
        username="pool-stale-admin",
        email="pool-stale-admin@example.test",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    grp, zone = await _zone(db_session)
    await _pool(
        db_session,
        grp,
        zone,
        "api",
        members=[
            ("192.0.2.1", 7200, "healthy", True),
            ("192.0.2.2", 10, "healthy", True),
            ("192.0.2.3", None, "unknown", True),
        ],
    )
    await db_session.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    r = await client.get(f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/pools", headers=h)
    assert r.status_code == 200, r.text
    members = {m["address"]: m for m in r.json()[0]["members"]}
    assert members["192.0.2.1"]["check_stale"] is True
    assert 7190 <= members["192.0.2.1"]["check_age_seconds"] <= 7300
    assert members["192.0.2.2"]["check_stale"] is False
    assert members["192.0.2.3"]["check_stale"] is False
    assert members["192.0.2.3"]["check_age_seconds"] is None


@pytest.mark.asyncio
async def test_rule_is_registered_gated_and_seeded_enabled(db_session: AsyncSession) -> None:
    assert alerts.RULE_TYPE_DNS_POOL_HEALTH_STALE in alerts.RULE_TYPES
    assert alerts.rule_type_module(alerts.RULE_TYPE_DNS_POOL_HEALTH_STALE) == "core.dns"
    assert alerts.RULE_TYPE_DNS_POOL_HEALTH_STALE in {c.rule_type for c in build_catalogue()}
    await alerts.seed_dns_pool_health_stale_alert_rule()
    await alerts.seed_dns_pool_health_stale_alert_rule()
    rows = (
        (
            await db_session.execute(
                select(AlertRule).where(
                    AlertRule.rule_type == alerts.RULE_TYPE_DNS_POOL_HEALTH_STALE
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1 and rows[0].enabled is True
