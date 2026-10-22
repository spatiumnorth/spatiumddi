"""#2260 — a circuit / service term's end date is INCLUSIVE.

On ``term_end_date == today`` the term is still running: the alert must say
"expires today" rather than "has expired", and the Network dashboard must not
count the circuit as past its term.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.auth import User
from app.models.circuit import Circuit
from app.models.ownership import Provider
from app.services.alerts import _matching_circuit_term_expiring_subjects


async def _circuit(db: AsyncSession, provider: Provider, days: int) -> Circuit:
    c = Circuit(
        name=f"ckt-{uuid.uuid4().hex[:6]}",
        provider_id=provider.id,
        term_end_date=(datetime.now(UTC) + timedelta(days=days)).date(),
    )
    db.add(c)
    await db.flush()
    return c


async def _provider(db: AsyncSession) -> Provider:
    p = Provider(name=f"p2260-{uuid.uuid4().hex[:6]}")
    db.add(p)
    await db.flush()
    return p


async def test_alert_says_expires_today_on_the_last_day(db_session: AsyncSession) -> None:
    p = await _provider(db_session)
    last_day = await _circuit(db_session, p, 0)
    yesterday = await _circuit(db_session, p, -1)
    rule = AlertRule(
        name="ckt term", rule_type="circuit_term_expiring", severity="info", threshold_days=30
    )
    db_session.add(rule)
    await db_session.commit()

    subjects = await _matching_circuit_term_expiring_subjects(db_session, rule, datetime.now(UTC))
    msgs = {sid: msg for sid, _d, msg, _s in subjects}
    assert "expires today" in msgs[str(last_day.id)]
    assert "has expired" not in msgs[str(last_day.id)]
    assert "has expired" in msgs[str(yesterday.id)]


async def test_dashboard_does_not_count_a_circuit_on_its_last_day(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = User(
        username=f"su-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="su",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    p = await _provider(db_session)
    await _circuit(db_session, p, 0)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    base = (await client.get("/api/v1/dashboards/network/summary", headers=headers)).json()[
        "circuit_term_expiring_count"
    ]
    assert base == 0

    await _circuit(db_session, p, -1)
    await db_session.commit()
    resp = await client.get("/api/v1/dashboards/network/summary", headers=headers)
    assert resp.json()["circuit_term_expiring_count"] == 1
