"""Blocklist feed sync state is visible, and a stale feed raises an alert (#2313)."""

from __future__ import annotations

import contextlib
import importlib.util
import pathlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.auth import User
from app.models.dns import DNSBlockList
from app.services import alerts
from app.services.alert_rule_catalogue import build_catalogue
from app.services.dns.blocklist_feed_health import feed_sync_state
from app.tasks import dns as dns_tasks

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
_RULE = SimpleNamespace(severity="warning")
URL = "https://feeds.example.test/list.txt"


async def _list(
    db: AsyncSession,
    name: str,
    *,
    success_hours_ago: float | None,
    interval: int = 24,
    created_hours_ago: float = 1000,
    status: str | None = None,
    enabled: bool = True,
    feed_url: str | None = URL,
) -> DNSBlockList:
    bl = DNSBlockList(
        name=name,
        source_type="url" if feed_url else "manual",
        feed_url=feed_url,
        update_interval_hours=interval,
        enabled=enabled,
        last_sync_status=status,
        last_success_at=(
            None if success_hours_ago is None else NOW - timedelta(hours=success_hours_ago)
        ),
        created_at=NOW - timedelta(hours=created_hours_ago),
    )
    db.add(bl)
    await db.flush()
    return bl


async def _fired(db: AsyncSession) -> dict[str, tuple[str, str]]:
    out = await alerts._matching_dns_blocklist_feed_stale_subjects(db, _RULE, NOW)
    return {display: (message, sev) for _sid, display, message, sev in out}


@pytest.mark.asyncio
async def test_alert_uses_three_intervals_from_the_last_success(db_session: AsyncSession) -> None:
    await _list(db_session, "past-3x", success_hours_ago=73)  # > 3 x 24
    await _list(db_session, "inside-3x", success_hours_ago=71)
    await _list(db_session, "hourly-past", success_hours_ago=4, interval=1)
    fired = await _fired(db_session)
    assert set(fired) == {"past-3x", "hourly-past"}
    message, severity = fired["past-3x"]
    assert severity == "warning"
    assert "73 h ago" in message


@pytest.mark.asyncio
async def test_a_recent_failure_alone_does_not_fire_but_a_long_one_does(
    db_session: AsyncSession,
) -> None:
    # One failed attempt after a recent success: the chip is red, no alert.
    await _list(db_session, "blip", success_hours_ago=25, status="error")
    # last_synced_at is stamped on failure, so it must not reset the clock.
    bl = await _list(db_session, "long-failing", success_hours_ago=200, status="error")
    bl.last_synced_at = NOW - timedelta(minutes=5)
    bl.last_sync_error = "Fetch failed: 404"
    await db_session.flush()
    fired = await _fired(db_session)
    assert set(fired) == {"long-failing"}
    assert "Fetch failed: 404" in fired["long-failing"][0]


@pytest.mark.asyncio
async def test_never_succeeded_is_measured_from_creation(db_session: AsyncSession) -> None:
    await _list(db_session, "old-never", success_hours_ago=None, created_hours_ago=100)
    await _list(db_session, "new-never", success_hours_ago=None, created_hours_ago=2)
    fired = await _fired(db_session)
    assert set(fired) == {"old-never"}
    assert "never refreshed successfully" in fired["old-never"][0]


@pytest.mark.asyncio
async def test_manual_disabled_and_featureless_lists_never_fire(db_session: AsyncSession) -> None:
    await _list(db_session, "manual-refresh", success_hours_ago=9999, interval=0)
    await _list(db_session, "disabled", success_hours_ago=9999, enabled=False)
    await _list(db_session, "hand-made", success_hours_ago=9999, feed_url=None)
    assert await _fired(db_session) == {}


def test_state_classification() -> None:
    def bl(**kw: object) -> SimpleNamespace:
        base = dict(
            feed_url=URL,
            update_interval_hours=24,
            last_sync_status="success",
            last_success_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )
        base.update(kw)
        return SimpleNamespace(**base)

    assert feed_sync_state(bl()) == "ok"  # type: ignore[arg-type]
    assert feed_sync_state(bl(feed_url=None)) is None  # type: ignore[arg-type]
    assert feed_sync_state(bl(last_sync_status="error")) == "error"  # type: ignore[arg-type]
    assert feed_sync_state(bl(last_success_at=None, last_sync_status=None)) == "never"  # type: ignore[arg-type]
    old = datetime.now(UTC) - timedelta(days=4)
    assert feed_sync_state(bl(last_success_at=old)) == "stale"  # type: ignore[arg-type]
    assert feed_sync_state(bl(last_success_at=old, update_interval_hours=0)) == "ok"  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_api_exposes_state_and_last_success(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = User(
        username="bl-stale-admin",
        email="bl-stale-admin@example.test",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    now = datetime.now(UTC)
    for name, kw in {
        "api-stale": dict(last_success_at=now - timedelta(days=10)),
        "api-error": dict(last_success_at=now, last_sync_status="error"),
        "api-never": dict(last_success_at=None),
        "api-manual": dict(feed_url=None, source_type="manual"),
    }.items():
        db_session.add(
            DNSBlockList(
                **{"name": name, "source_type": "url", "feed_url": URL, **kw},  # type: ignore[arg-type]
            )
        )
    await db_session.flush()
    resp = await client.get("/api/v1/dns/blocklists", headers=headers)
    assert resp.status_code == 200, resp.text
    by = {r["name"]: r for r in resp.json()}
    assert by["api-stale"]["feed_sync_state"] == "stale"
    assert by["api-error"]["feed_sync_state"] == "error"
    assert by["api-never"]["feed_sync_state"] == "never"
    assert by["api-manual"]["feed_sync_state"] is None
    assert by["api-stale"]["last_success_at"] is not None


class _NullEngine:
    async def dispose(self) -> None:
        return None


async def _noop_publish(_channel: str) -> None:
    return None


def _wire(monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, *, fail: bool) -> None:
    class _Resp:
        text = "a.example\n"

        def raise_for_status(self) -> None:
            return None

    class _Client:
        def __init__(self, *a: object, **kw: object) -> None:
            pass

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: object) -> None:
            return None

        async def get(self, _url: str) -> _Resp:
            if fail:
                raise httpx.ConnectError("boom")
            return _Resp()

    monkeypatch.setattr(dns_tasks.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)


@pytest.mark.asyncio
async def test_refresh_moves_last_success_only_on_success(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    bl = await _list(db_session, "refresh", success_hours_ago=None)
    await db_session.commit()
    bl_id = bl.id

    _wire(monkeypatch, db_session, fail=True)
    with pytest.raises(httpx.ConnectError):
        await dns_tasks._refresh_blocklist_feed_async(str(bl_id))
    row = (
        await db_session.execute(select(DNSBlockList).where(DNSBlockList.id == bl_id))
    ).scalar_one()
    await db_session.refresh(row)
    assert row.last_sync_status == "error"
    assert row.last_synced_at is not None  # the attempt is stamped...
    assert row.last_success_at is None  # ...but it is not a success

    _wire(monkeypatch, db_session, fail=False)
    out = await dns_tasks._refresh_blocklist_feed_async(str(bl_id))
    assert out["status"] == "success"
    await db_session.refresh(row)
    assert row.last_success_at is not None
    assert row.last_success_at == row.last_synced_at


@pytest.mark.asyncio
async def test_migration_backfill_only_trusts_successful_rows(db_session: AsyncSession) -> None:
    path = next(
        pathlib.Path(__file__).resolve().parent.parent.glob("alembic/versions/c4a8e2f7b913_*.py")
    )
    spec = importlib.util.spec_from_file_location("mig_c4a8e2f7b913", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    synced = NOW - timedelta(days=2)
    ok = await _list(db_session, "bf-ok", success_hours_ago=None, status="success")
    bad = await _list(db_session, "bf-bad", success_hours_ago=None, status="error")
    none = await _list(db_session, "bf-none", success_hours_ago=None, status=None)
    for r in (ok, bad, none):
        r.last_synced_at = synced
    await db_session.flush()
    await db_session.execute(text(mod.BACKFILL_SQL))
    for r in (ok, bad, none):
        await db_session.refresh(r)
    assert ok.last_success_at == synced
    assert bad.last_success_at is None  # nothing recorded when it last worked
    assert none.last_success_at is None


@pytest.mark.asyncio
async def test_rule_is_seeded_enabled_and_registered(db_session: AsyncSession) -> None:
    assert alerts.RULE_TYPE_DNS_BLOCKLIST_FEED_STALE in alerts.RULE_TYPES
    assert alerts.rule_type_module(alerts.RULE_TYPE_DNS_BLOCKLIST_FEED_STALE) == "core.dns"
    assert alerts.RULE_TYPE_DNS_BLOCKLIST_FEED_STALE in {c.rule_type for c in build_catalogue()}
    await alerts.seed_dns_blocklist_feed_stale_alert_rule()
    await alerts.seed_dns_blocklist_feed_stale_alert_rule()  # idempotent
    rows = (
        (
            await db_session.execute(
                select(AlertRule).where(
                    AlertRule.rule_type == alerts.RULE_TYPE_DNS_BLOCKLIST_FEED_STALE
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1 and rows[0].enabled is True
