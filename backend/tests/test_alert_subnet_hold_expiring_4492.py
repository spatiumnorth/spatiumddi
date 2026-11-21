"""``subnet_hold_expiring`` alert rule (#4492)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertRule
from app.models.ipam import IPBlock, IPSpace
from app.models.subnet_hold import SubnetHold
from app.services import alert_rule_catalogue, alerts
from app.services.alerts import _matching_subnet_hold_expiring_subjects


async def test_matches_active_holds_inside_window_only(db_session: AsyncSession) -> None:
    now = datetime.now(UTC)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()

    def mk(net: str, days: float | None, status: str = "active") -> SubnetHold:
        h = SubnetHold(
            space_id=space.id,
            block_id=block.id,
            network=net,
            reason="falcon",
            status=status,
            expires_at=None if days is None else now + timedelta(days=days),
        )
        db_session.add(h)
        return h

    near = mk("10.0.1.0/24", 10)
    overdue = mk("10.0.2.0/24", -3)
    far = mk("10.0.3.0/24", 365)
    never = mk("10.0.4.0/24", None)
    released = mk("10.0.5.0/24", 5, status="released")
    rule = AlertRule(
        name="Hold expiry",
        rule_type="subnet_hold_expiring",
        severity="info",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)
    await db_session.commit()

    got = {
        sid: (msg, sev)
        for sid, _d, msg, sev in await _matching_subnet_hold_expiring_subjects(
            db_session, rule, now
        )
    }
    assert str(near.id) in got and str(overdue.id) in got
    for h in (far, never, released):
        assert str(h.id) not in got
    assert got[str(overdue.id)][1] == "critical"
    assert "expired" in got[str(overdue.id)][0]
    assert "10.0.1.0/24" in got[str(near.id)][0]


def test_rule_type_registered_and_in_catalogue() -> None:
    assert alerts.RULE_TYPE_SUBNET_HOLD_EXPIRING in alerts.RULE_TYPES
    assert alerts.RULE_TYPE_SUBNET_HOLD_EXPIRING in alert_rule_catalogue.rule_type_names()
