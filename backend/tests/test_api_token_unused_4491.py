"""#4491 slice 2: the ``api_token_unused`` alert rule and the Security
dashboard's idle-token count share one definition of "idle": active,
unexpired, no call in N days, never-used counted from creation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.auth import APIToken, User
from app.services.alert_rule_catalogue import build_catalogue
from app.services.alerts import RULE_TYPES, _matching_api_token_unused_subjects

NOW = datetime.now(UTC)


async def _seed(db: AsyncSession) -> dict[str, APIToken]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()

    def tok(name: str, **kw: object) -> APIToken:
        base: dict[str, object] = {
            "name": name,
            "token_hash": uuid.uuid4().hex,
            "prefix": "abc123",
            "created_by_user_id": user.id,
            "user_id": user.id,
            "scope": "user",
            "is_active": True,
            "created_at": NOW - timedelta(days=200),
        }
        base.update(kw)
        return APIToken(**base)

    toks = {
        "stale": tok("stale", last_used_at=NOW - timedelta(days=120)),
        "fresh": tok("fresh", last_used_at=NOW - timedelta(days=2)),
        "never_old": tok("never_old"),
        "never_new": tok("never_new", created_at=NOW - timedelta(days=5)),
        "revoked": tok("revoked", is_active=False, last_used_at=NOW - timedelta(days=300)),
        "expired": tok(
            "expired", expires_at=NOW - timedelta(days=1), last_used_at=NOW - timedelta(days=300)
        ),
    }
    db.add_all(toks.values())
    await db.commit()
    return toks


@pytest.mark.asyncio
async def test_rule_flags_idle_and_never_used_but_not_revoked_expired_or_fresh(
    db_session: AsyncSession,
) -> None:
    toks = await _seed(db_session)
    rule = AlertRule(
        name="idle", rule_type="api_token_unused", severity="warning", threshold_days=90
    )
    subjects = await _matching_api_token_unused_subjects(db_session, rule, NOW)
    ids = {sid for sid, _d, _m in subjects}
    assert ids == {f"api_token:{toks['stale'].id}", f"api_token:{toks['never_old'].id}"}
    msgs = " ".join(m for _s, _d, m in subjects)
    assert "never used" in msgs
    # A hash or full token must never appear; only the stored prefix does.
    assert toks["stale"].token_hash not in msgs


@pytest.mark.asyncio
async def test_rule_default_window_is_90_days_when_unset(db_session: AsyncSession) -> None:
    toks = await _seed(db_session)
    rule = AlertRule(name="idle", rule_type="api_token_unused", severity="warning")
    ids = {s for s, _d, _m in await _matching_api_token_unused_subjects(db_session, rule, NOW)}
    assert f"api_token:{toks['stale'].id}" in ids
    rule.threshold_days = 400
    assert await _matching_api_token_unused_subjects(db_session, rule, NOW) == []


def test_rule_type_is_creatable_and_catalogued() -> None:
    assert "api_token_unused" in RULE_TYPES
    spec = next(s for s in build_catalogue() if s.rule_type == "api_token_unused")
    assert [p.name for p in spec.params] == ["threshold_days"]


@pytest.mark.asyncio
async def test_dashboard_counts_idle_tokens(db_session: AsyncSession, client: AsyncClient) -> None:
    await _seed(db_session)
    admin = (await db_session.execute(User.__table__.select().limit(1))).first()
    assert admin is not None
    headers = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    r = await client.get("/api/v1/dashboards/security/summary", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api_tokens_idle_count"] == 2
    assert body["api_tokens_idle_days"] == 90


@pytest.mark.asyncio
async def test_evaluate_all_opens_then_resolves_when_token_is_used(
    db_session: AsyncSession,
) -> None:
    from sqlalchemy import select

    from app.models.alerts import AlertEvent
    from app.services.alerts import evaluate_all

    toks = await _seed(db_session)
    rule = AlertRule(
        name="idle", rule_type="api_token_unused", severity="info", threshold_days=90, enabled=True
    )
    db_session.add(rule)
    await db_session.commit()

    async def open_events() -> list[AlertEvent]:
        return list(
            (
                await db_session.execute(
                    select(AlertEvent).where(
                        AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None)
                    )
                )
            )
            .scalars()
            .all()
        )

    await evaluate_all(db_session)
    events = await open_events()
    assert {e.subject_id for e in events} == {
        f"api_token:{toks['stale'].id}",
        f"api_token:{toks['never_old'].id}",
    }
    assert {e.subject_type for e in events} == {"api_token"}

    toks["stale"].last_used_at = datetime.now(UTC)
    await db_session.commit()
    await evaluate_all(db_session)
    assert {e.subject_id for e in await open_events()} == {f"api_token:{toks['never_old'].id}"}
