"""Capacity forecasting (#43): regression math, API, alert rule, MCP tool."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace, Subnet, SubnetUtilizationHistory
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import REGISTRY
from app.services.alerts import _matching_subnet_capacity_forecast_subjects, evaluate_all
from app.services.ipam.capacity_forecast import compute_capacity_forecasts, project_days_to_full

TOTAL = 1000


def test_projection_math() -> None:
    assert project_days_to_full(50.0, 1.0) == 50
    assert project_days_to_full(50.0, 0.3) == 167  # ceil(166.67)
    assert project_days_to_full(50.0, 0.0) is None  # flat
    assert project_days_to_full(50.0, -2.0) is None  # shrinking
    assert project_days_to_full(100.0, 0.5) == 0  # already full, still growing
    assert project_days_to_full(10.0, 1e-9) is None  # beyond ten years


async def _subnet(db: AsyncSession, network: str, *, allocated: int = 0) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    s = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=network,
        name="s",
        total_ips=TOTAL,
        allocated_ips=allocated,
    )
    db.add(s)
    await db.flush()
    return s


async def _history(db: AsyncSession, s: Subnet, counts: list[int]) -> None:
    """One snapshot per day, ending today: counts[-1] is today's."""
    now = datetime.now(UTC)
    for i, c in enumerate(counts):
        db.add(
            SubnetUtilizationHistory(
                subnet_id=s.id,
                sampled_at=now - timedelta(days=len(counts) - 1 - i, minutes=1),
                allocated_ips=c,
                total_ips=TOTAL,
            )
        )
    await db.flush()


async def _growing(db: AsyncSession, network: str, per_day: int = 10) -> Subnet:
    # 20 days, +10 addresses (1 point) a day, ending at 500/1000 = 50%.
    counts = [500 - per_day * (19 - i) for i in range(20)]
    s = await _subnet(db, network, allocated=counts[-1])
    await _history(db, s, counts)
    return s


async def test_forecast_growing_flat_shrinking_short_full(db_session: AsyncSession) -> None:
    grow = await _growing(db_session, "10.1.0.0/24")
    flat = await _subnet(db_session, "10.2.0.0/24", allocated=300)
    await _history(db_session, flat, [300] * 20)
    shrink = await _subnet(db_session, "10.3.0.0/24", allocated=300)
    await _history(db_session, shrink, [300 + 5 * (19 - i) for i in range(20)])
    short = await _subnet(db_session, "10.4.0.0/24", allocated=500)
    await _history(db_session, short, [400 + 10 * i for i in range(13)])  # < 14 points
    full = await _subnet(db_session, "10.5.0.0/24", allocated=1000)
    await _history(db_session, full, [800 + 10 * i for i in range(20)])
    await db_session.commit()

    got = {str(f.subnet_id): f for f in await compute_capacity_forecasts(db_session)}
    assert set(got) == {str(grow.id), str(full.id)}
    g = got[str(grow.id)]
    assert g.sample_count == 20
    assert g.slope_percent_per_day == pytest.approx(1.0, abs=0.01)
    assert 49 <= g.days_to_full <= 51  # 50 points left at 1 point/day
    assert g.forecast_full_date == (datetime.now(UTC) + timedelta(days=g.days_to_full)).date()
    assert got[str(full.id)].days_to_full == 0


async def test_excluded_prefix_has_no_forecast(db_session: AsyncSession) -> None:
    # /31 is past the default utilization_max_prefix_ipv4 (30).
    if (await db_session.execute(select(PlatformSettings))).first() is None:
        db_session.add(PlatformSettings(id=1))
    s = await _growing(db_session, "10.6.0.0/31")
    await db_session.commit()
    ids = {f.subnet_id for f in await compute_capacity_forecasts(db_session)}
    assert s.id not in ids


async def _admin(db: AsyncSession) -> str:
    u = User(
        username=f"cf-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="CF",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return create_access_token(str(u.id))


async def test_api_endpoint(client: AsyncClient, db_session: AsyncSession) -> None:
    grow = await _growing(db_session, "10.7.0.0/24")
    token = await _admin(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    r = await client.get("/api/v1/ipam/subnets/capacity-forecast", headers=h)
    assert r.status_code == 200, r.text
    row = next(x for x in r.json() if x["subnet_id"] == str(grow.id))
    assert 49 <= row["days_to_full"] <= 51
    assert row["forecast_full_date"]

    r = await client.get(
        "/api/v1/ipam/subnets/capacity-forecast", params={"max_days": 5}, headers=h
    )
    assert all(x["subnet_id"] != str(grow.id) for x in r.json())


async def test_alert_rule_fires_within_threshold(db_session: AsyncSession) -> None:
    grow = await _growing(db_session, "10.8.0.0/24")  # ~50 days out
    rule_hit = AlertRule(
        name="fc-90",
        rule_type="subnet_capacity_forecast",
        severity="warning",
        threshold_days=90,
        enabled=True,
    )
    rule_miss = AlertRule(
        name="fc-10",
        rule_type="subnet_capacity_forecast",
        severity="warning",
        threshold_days=10,
        enabled=True,
    )
    db_session.add_all([rule_hit, rule_miss])
    await db_session.commit()

    hit = await _matching_subnet_capacity_forecast_subjects(db_session, rule_hit)
    assert [sid for sid, _d, _m in hit] == [str(grow.id)]
    assert "projected to be full" in hit[0][2]
    assert await _matching_subnet_capacity_forecast_subjects(db_session, rule_miss) == []

    await evaluate_all(db_session)
    events = (
        (await db_session.execute(select(AlertEvent).where(AlertEvent.rule_id == rule_hit.id)))
        .scalars()
        .all()
    )
    assert len(events) == 1 and events[0].subject_type == "subnet"


async def test_mcp_tool(db_session: AsyncSession) -> None:
    grow = await _growing(db_session, "10.9.0.0/24")
    user = User(
        username=f"mcp-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="m",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.commit()
    tool = REGISTRY.get("find_subnet_forecasts")
    assert tool is not None and tool.default_enabled and not tool.writes
    rows = await REGISTRY.call(
        "find_subnet_forecasts", {"within_days": 120}, db=db_session, user=user
    )
    row = next(r for r in rows if r["id"] == str(grow.id))
    assert 49 <= row["days_to_full"] <= 51
    assert (
        await REGISTRY.call("find_subnet_forecasts", {"within_days": 5}, db=db_session, user=user)
        == []
    )


async def _plain_user(db: AsyncSession, permissions: list[dict]) -> str:
    from app.models.auth import Group, Role

    u = User(
        username=f"cfs-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="CFS",
        hashed_password=hash_password("x"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    u.groups = [group]
    db.add_all([role, group, u])
    await db.flush()
    return create_access_token(str(u.id))


async def test_api_scoped_grant_is_refused_not_leaked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A grant scoped to one subnet does not open the all-subnet forecast."""
    mine = await _growing(db_session, "10.11.0.0/24")
    await _growing(db_session, "10.12.0.0/24")
    tok = await _plain_user(
        db_session, [{"action": "read", "resource_type": "subnet", "resource_id": str(mine.id)}]
    )
    await db_session.commit()
    r = await client.get(
        "/api/v1/ipam/subnets/capacity-forecast", headers={"Authorization": f"Bearer {tok}"}
    )
    assert r.status_code == 403


async def test_api_without_subnet_read_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _growing(db_session, "10.13.0.0/24")
    tok = await _plain_user(db_session, [{"action": "read", "resource_type": "dns_zone"}])
    await db_session.commit()
    r = await client.get(
        "/api/v1/ipam/subnets/capacity-forecast", headers={"Authorization": f"Bearer {tok}"}
    )
    assert r.status_code == 403


async def test_resized_subnet_uses_percent_at_each_sample(db_session: AsyncSession) -> None:
    """A subnet resized mid-window must not show a phantom jump: 100/1000 then
    200/2000 is a flat 10 %, not growth."""
    s = await _subnet(db_session, "10.14.0.0/24", allocated=200)
    now = datetime.now(UTC)
    for i in range(20):
        big = i >= 10
        db_session.add(
            SubnetUtilizationHistory(
                subnet_id=s.id,
                sampled_at=now - timedelta(days=19 - i, minutes=1),
                allocated_ips=200 if big else 100,
                total_ips=2000 if big else 1000,
            )
        )
    await db_session.commit()
    assert s.id not in {f.subnet_id for f in await compute_capacity_forecasts(db_session)}


async def test_alert_evaluation_is_idempotent(db_session: AsyncSession) -> None:
    await _growing(db_session, "10.15.0.0/24")
    rule = AlertRule(
        name="fc-idem",
        rule_type="subnet_capacity_forecast",
        severity="warning",
        threshold_days=90,
        enabled=True,
    )
    db_session.add(rule)
    await db_session.commit()
    await evaluate_all(db_session)
    await evaluate_all(db_session)
    events = (
        (await db_session.execute(select(AlertEvent).where(AlertEvent.rule_id == rule.id)))
        .scalars()
        .all()
    )
    assert len(events) == 1
