"""#3074 — Copilot tool gates agree with the REST surfaces they mirror.

``current_state`` rolls up alerts, subnet utilisation and failed logins; each
section needs the grant its own REST surface needs, and is omitted otherwise.
``propose_create_ip_address`` needs the grant the REST address write needs
(``write subnet`` since #3058), not the old ``write ip_address``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.ai.operations import CreateIPAddressArgs
from app.services.ai.tools import REGISTRY
from app.services.ai.tools.base import ToolPermissionDenied


async def _user(db: AsyncSession, perms: list[tuple[str, str]], superadmin: bool = False) -> User:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="t",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    u.groups = []
    if perms:
        role = Role(
            name=f"r-{uuid.uuid4().hex[:8]}",
            permissions=[{"action": a, "resource_type": t} for a, t in perms],
        )
        group = Group(name=f"g-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        u.groups = [group]
        db.add_all([role, group])
    db.add(u)
    await db.commit()
    return u


async def _seed(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.0.5.0/24",
        name="hot",
        utilization_percent=95,
    )
    db.add(subnet)
    rule = AlertRule(name="r", rule_type="subnet_utilization", severity="critical")
    db.add(rule)
    await db.flush()
    db.add(
        AlertEvent(
            rule_id=rule.id,
            subject_type="subnet",
            subject_id=str(subnet.id),
            subject_display="hot",
            severity="critical",
            message="m",
            fired_at=datetime.now(UTC),
        )
    )
    db.add(
        AuditLog(
            user_display_name="x",
            action="login",
            resource_type="user",
            resource_id="x",
            resource_display="x",
            result="failure",
            timestamp=datetime.now(UTC),
        )
    )
    await db.commit()
    return subnet


async def _state(db: AsyncSession, user: User) -> dict:
    return await REGISTRY.call("current_state", {}, db=db, user=user, effective={"current_state"})


@pytest.mark.asyncio
async def test_subnet_only_role_sees_subnets_not_alerts_or_logins(db_session: AsyncSession) -> None:
    await _seed(db_session)
    out = await _state(db_session, await _user(db_session, [("read", "subnet")]))
    assert [s["name"] for s in out["high_utilisation_subnets"]] == ["hot"]
    for key in ("open_alerts_total", "open_alerts_by_severity", "recent_critical_or_warning"):
        assert key not in out
    assert "failed_logins_last_hour" not in out
    assert out["sections_omitted"] == ["alerts", "failed_logins"]


@pytest.mark.asyncio
async def test_alerts_only_role_sees_alerts_only(db_session: AsyncSession) -> None:
    await _seed(db_session)
    out = await _state(db_session, await _user(db_session, [("read", "alert")]))
    assert out["open_alerts_total"] == 1
    assert len(out["recent_critical_or_warning"]) == 1
    assert "high_utilisation_subnets" not in out
    assert "failed_logins_last_hour" not in out
    assert out["sections_omitted"] == ["subnets", "failed_logins"]


@pytest.mark.asyncio
async def test_audit_only_role_sees_logins_only(db_session: AsyncSession) -> None:
    await _seed(db_session)
    out = await _state(db_session, await _user(db_session, [("read", "audit_log")]))
    assert out["failed_logins_last_hour"] == 1
    assert "open_alerts_total" not in out
    assert "high_utilisation_subnets" not in out


@pytest.mark.asyncio
async def test_superadmin_sees_everything(db_session: AsyncSession) -> None:
    await _seed(db_session)
    out = await _state(db_session, await _user(db_session, [], superadmin=True))
    assert out["open_alerts_total"] == 1
    assert len(out["high_utilisation_subnets"]) == 1
    assert out["failed_logins_last_hour"] == 1
    assert out["sections_omitted"] == []


@pytest.mark.asyncio
async def test_current_state_refused_without_any_section_grant(db_session: AsyncSession) -> None:
    # An address-only reader used to pass the old IPAM-wide gate.
    user = await _user(db_session, [("read", "ip_address")])
    with pytest.raises(ToolPermissionDenied):
        await _state(db_session, user)


@pytest.mark.asyncio
async def test_propose_create_ip_address_needs_write_subnet(db_session: AsyncSession) -> None:
    subnet = await _seed(db_session)
    args = CreateIPAddressArgs(subnet_id=str(subnet.id), address="10.0.5.10").model_dump()
    name = "propose_create_ip_address"
    eff = {name}

    old = await _user(db_session, [("write", "ip_address")])
    with pytest.raises(ToolPermissionDenied):
        await REGISTRY.call(name, args, db=db_session, user=old, effective=eff)

    new = await _user(db_session, [("write", "subnet")])
    out = await REGISTRY.call(name, args, db=db_session, user=new, effective=eff)
    assert out["kind"] == "proposal"
