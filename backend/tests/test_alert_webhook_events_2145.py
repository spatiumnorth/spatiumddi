"""``alert.fired`` / ``alert.resolved`` typed webhook events (#2145).

Nothing in the publish path is stubbed: a real ``AlertEvent`` is inserted and
resolved through the ORM, the real after-commit dispatch writes
``event_outbox``, and the delivery is signed by the real ``_deliver_one``
against an in-process transport.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime

import httpx
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.alerts import AlertEvent, AlertRule
from app.models.event_subscription import EventOutbox, EventSubscription
from app.models.settings import PlatformSettings
from app.services import after_commit_dispatch, event_delivery

SECRET = "s3cret-for-2145"


async def _drain() -> None:
    pending = [t for t in after_commit_dispatch._tasks if not t.done()]  # noqa: SLF001
    if pending:
        await asyncio.wait(pending, timeout=10)


async def _outbox(db: AsyncSession) -> list[EventOutbox]:
    await _drain()
    rows = (
        await db.execute(
            select(EventOutbox)
            .order_by(EventOutbox.created_at)
            .execution_options(populate_existing=True)
        )
    ).scalars()
    return list(rows.all())


async def _sub(db: AsyncSession, event_types: list[str] | None) -> EventSubscription:
    sub = EventSubscription(
        name=f"s-{uuid.uuid4().hex[:6]}",
        url="https://receiver.invalid/hook",
        enabled=True,
        event_types=event_types,
        secret_encrypted=encrypt_str(SECRET),
    )
    db.add(sub)
    await db.commit()
    return sub


async def _rule(db: AsyncSession) -> AlertRule:
    rule = AlertRule(
        name="Subnet high util",
        rule_type="subnet_utilization",
        severity="warning",
        enabled=True,
    )
    db.add(rule)
    await db.commit()
    return rule


async def _fire(db: AsyncSession, rule: AlertRule) -> AlertEvent:
    ev = AlertEvent(
        rule_id=rule.id,
        subject_type="subnet",
        subject_id=str(uuid.uuid4()),
        subject_display="10.0.0.0/24 — lab",
        severity="warning",
        message="92% used",
        fired_at=datetime.now(UTC),
    )
    db.add(ev)
    await db.commit()
    await db.refresh(ev)
    return ev


async def test_fired_then_resolved_each_emitted_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db_session.add(PlatformSettings(id=1, app_base_url="https://ddi.example.net/"))
    await db_session.commit()
    await _sub(db_session, ["alert.fired", "alert.resolved"])
    rule = await _rule(db_session)

    ev = await _fire(db_session, rule)
    rows = await _outbox(db_session)
    assert [r.event_type for r in rows] == ["alert.fired"]
    p = rows[0].payload
    assert p["schema_version"] == 1
    assert p["event_id"] == str(ev.id)
    assert p["rule_id"] == str(rule.id)
    assert p["rule_name"] == "Subnet high util"
    assert p["rule_type"] == "subnet_utilization"
    assert p["severity"] == "warning"
    assert p["subject_type"] == "subnet"
    assert p["subject_display"] == "10.0.0.0/24 — lab"
    assert p["message"] == "92% used"
    assert p["resolved_at"] is None
    assert p["fired_at"] == ev.fired_at.isoformat()
    assert p["url"] == "https://ddi.example.net/admin/alerts"

    # A touch that does not resolve (severity escalation, receipts) is silent.
    ev.severity = "critical"
    ev.delivered_webhook = True
    await db_session.commit()
    await db_session.refresh(ev)
    assert [r.event_type for r in await _outbox(db_session)] == ["alert.fired"]

    ev.resolved_at = datetime.now(UTC)
    await db_session.commit()
    await db_session.refresh(ev)
    rows = await _outbox(db_session)
    assert sorted(r.event_type for r in rows) == ["alert.fired", "alert.resolved"]
    resolved = next(r for r in rows if r.event_type == "alert.resolved")
    assert resolved.payload["event_id"] == str(ev.id)
    assert resolved.payload["resolved_at"] == ev.resolved_at.isoformat()
    assert resolved.payload["occurred_at"] == ev.resolved_at.isoformat()
    assert resolved.payload["severity"] == "critical"
    assert resolved.created_at >= next(r for r in rows if r.event_type == "alert.fired").created_at

    # Re-saving an already resolved event does not publish again.
    ev.message = "edited"
    await db_session.commit()
    assert len(await _outbox(db_session)) == 2


async def test_no_event_when_subscription_omits_the_type(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _sub(db_session, ["subnet.created"])
    only_resolved = await _sub(db_session, ["alert.resolved"])
    rule = await _rule(db_session)
    ev = await _fire(db_session, rule)
    assert await _outbox(db_session) == []  # nobody asked for alert.fired
    ev.resolved_at = datetime.now(UTC)
    await db_session.commit()
    rows = await _outbox(db_session)
    assert [(r.event_type, r.subscription_id) for r in rows] == [
        ("alert.resolved", only_resolved.id)
    ]


async def test_signature_verifies_and_carries_timestamp(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    sub = await _sub(db_session, ["alert.fired"])
    rule = await _rule(db_session)
    await _fire(db_session, rule)
    (row,) = await _outbox(db_session)

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        code, err = await event_delivery._deliver_one(c, sub, row, SECRET, "test")  # noqa: SLF001
    assert (code, err) == (204, None)
    req = seen[0]
    assert req.headers["X-SpatiumDDI-Event"] == "alert.fired"
    ts = req.headers["X-SpatiumDDI-Timestamp"]
    expected = hmac.new(SECRET.encode(), ts.encode() + b"." + req.content, hashlib.sha256)
    assert req.headers["X-SpatiumDDI-Signature"] == f"sha256={expected.hexdigest()}"
    body = json.loads(req.content)
    assert body["rule_name"] == "Subnet high util"
    assert body["event_type"] == "alert.fired"
    assert body["event_id"] == row.payload["event_id"]


async def test_catalog_lists_alert_events(client: AsyncClient, db_session: AsyncSession) -> None:
    from app.api.v1.webhooks.router import list_event_types

    types = (await list_event_types(None))["event_types"]  # type: ignore[arg-type]
    assert "alert.fired" in types and "alert.resolved" in types
