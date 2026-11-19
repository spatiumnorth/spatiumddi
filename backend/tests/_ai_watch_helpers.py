"""Shared fixtures for the Copilot Watch tests (issue #4405)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.ai import AIProvider
from app.models.ai_watch import AIFinding, AIWatchConfig, AIWatchRun
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.services.ai.watch import runner
from app.services.ai.watch.principal import ensure_watch_principal

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


async def viewer_role(db: AsyncSession) -> Role:
    """The built-in Viewer role, which app startup seeds and the test
    schema does not."""
    role = await db.scalar(select(Role).where(Role.name == "Viewer"))
    if role is None:
        role = Role(
            name="Viewer",
            description="Read-only access to every resource.",
            is_builtin=True,
            permissions=[{"action": "read", "resource_type": "*"}],
        )
        db.add(role)
        await db.flush()
    return role


async def make_user(
    db: AsyncSession, *, superadmin: bool = False, permissions: list[dict] | None = None
) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"watch-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Watch Tester",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
        is_active=True,
    )
    u.groups = []
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        u.groups = [group]
        db.add_all([role, group])
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def make_provider(
    db: AsyncSession,
    name: str = "local",
    *,
    on_prem: bool = True,
    priority: int = 100,
    enabled: bool = True,
    model: str | None = None,
) -> AIProvider:
    p = AIProvider(
        name=name,
        kind="openai_compat",
        base_url=f"http://{name}.example.test/v1",
        default_model=model or f"{name}-model",
        is_enabled=enabled,
        is_on_prem=on_prem,
        priority=priority,
        options={},
    )
    db.add(p)
    await db.commit()
    return p


async def arm(db: AsyncSession, **overrides: Any) -> AIWatchConfig:
    """Turn Watch on with the sweep already done, so a test's tick runs
    only for the trigger the test sets up."""
    await viewer_role(db)
    config = await runner.get_config(db)
    config.enabled = True
    config.last_sweep_at = NOW
    config.alert_cursor = {}
    for key, value in overrides.items():
        setattr(config, key, value)
    await ensure_watch_principal(db)
    await db.commit()
    return config


async def request_run(db: AsyncSession) -> None:
    config = await runner.get_config(db)
    config.run_requested_at = NOW
    await db.commit()


async def make_alert(
    db: AsyncSession,
    *,
    subject_id: str | None = None,
    subject_type: str = "server",
    display: str = "ns1",
    severity: str = "critical",
    rule: AlertRule | None = None,
    message: str = "server is unreachable",
) -> AlertEvent:
    if rule is None:
        rule = AlertRule(
            name=f"rule-{uuid.uuid4().hex[:6]}",
            rule_type="server_unreachable",
            severity=severity,
        )
        db.add(rule)
        await db.flush()
    event = AlertEvent(
        rule_id=rule.id,
        subject_type=subject_type,
        subject_id=subject_id or str(uuid.uuid4()),
        subject_display=display,
        severity=severity,
        message=message,
        fired_at=NOW,
    )
    db.add(event)
    await db.commit()
    return event


def findings_reply(*findings: dict[str, Any]) -> str:
    return json.dumps({"findings": list(findings)})


def draft(*refs: str, title: str = "ns1 is down", **extra: Any) -> dict[str, Any]:
    return {
        "kind": "outage",
        "severity": "critical",
        "title": title,
        "explanation": "The health check cannot reach it.",
        "evidence": list(refs),
        "recommendations": ["Check the agent container on the host."],
        "confidence": "high",
        **extra,
    }


async def runs(db: AsyncSession) -> list[AIWatchRun]:
    stmt = select(AIWatchRun).order_by(AIWatchRun.started_at, AIWatchRun.id)
    return list((await db.execute(stmt.execution_options(populate_existing=True))).scalars().all())


async def findings(db: AsyncSession) -> list[AIFinding]:
    stmt = select(AIFinding).order_by(AIFinding.first_seen_at, AIFinding.id)
    return list((await db.execute(stmt.execution_options(populate_existing=True))).scalars().all())


async def audit_rows(
    db: AsyncSession, resource_type: str, action: str | None = None
) -> list[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.resource_type == resource_type)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    return list((await db.execute(stmt.order_by(AuditLog.seq))).scalars().all())
