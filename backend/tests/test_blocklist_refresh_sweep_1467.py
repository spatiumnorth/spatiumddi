"""Periodic blocklist feed refresh (#1467).

``update_interval_hours`` used to be stored and never read: a feed list was
fetched on create and on a manual Refresh only. The hourly sweep now queues a
refresh for every enabled URL list whose interval has passed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSBlockList
from app.tasks import blocklist_refresh_sweep as sweep

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


async def _list(
    db: AsyncSession,
    name: str,
    *,
    synced_hours_ago: float | None,
    interval: int = 24,
    source_type: str = "url",
    enabled: bool = True,
    feed_url: str | None = "https://feeds.example.test/list.txt",
) -> DNSBlockList:
    bl = DNSBlockList(
        name=name,
        source_type=source_type,
        feed_url=feed_url,
        update_interval_hours=interval,
        enabled=enabled,
        last_synced_at=(
            None if synced_hours_ago is None else NOW - timedelta(hours=synced_hours_ago)
        ),
    )
    db.add(bl)
    await db.flush()
    return bl


@pytest.mark.asyncio
async def test_only_due_url_lists_are_picked(db_session: AsyncSession) -> None:
    overdue = await _list(db_session, "overdue", synced_hours_ago=25)
    exactly = await _list(db_session, "exactly-due", synced_hours_ago=24)
    never = await _list(db_session, "never-synced", synced_hours_ago=None)
    await _list(db_session, "fresh", synced_hours_ago=1)
    await _list(db_session, "manual-only", synced_hours_ago=500, interval=0)
    await _list(db_session, "disabled", synced_hours_ago=500, enabled=False)
    await _list(db_session, "manual-source", synced_hours_ago=500, source_type="manual")
    await _list(db_session, "no-url", synced_hours_ago=500, feed_url=None)
    await _list(db_session, "empty-url", synced_hours_ago=500, feed_url="")

    ids = await sweep.due_blocklist_ids(db_session, NOW)

    # Never-synced first, then the longest overdue.
    assert ids == [str(never.id), str(overdue.id), str(exactly.id)]


@pytest.mark.asyncio
async def test_a_shorter_interval_makes_a_list_due(db_session: AsyncSession) -> None:
    bl = await _list(db_session, "hourly", synced_hours_ago=2, interval=24)
    assert await sweep.due_blocklist_ids(db_session, NOW) == []

    bl.update_interval_hours = 1
    await db_session.flush()
    assert await sweep.due_blocklist_ids(db_session, NOW) == [str(bl.id)]


@pytest.mark.asyncio
async def test_the_sweep_queues_each_due_list_staggered() -> None:
    calls: list[tuple[list[str], int]] = []

    def fake_apply_async(*, args: list[str], countdown: int) -> None:
        calls.append((args, countdown))

    async def fake_due(_db: object, _now: datetime) -> list[str]:
        return ["a", "b", "c"]

    async def enabled(_db: object, _key: str) -> bool:
        return True

    with (
        patch.object(sweep, "due_blocklist_ids", fake_due),
        patch.object(sweep, "is_module_enabled", enabled),
        patch("app.tasks.dns.refresh_blocklist_feed.apply_async", side_effect=fake_apply_async),
    ):
        queued = await sweep._dispatch_due_async()  # noqa: SLF001

    assert queued == 3
    step = sweep.STAGGER_SECONDS
    assert calls == [(["a"], 0), (["b"], step), (["c"], 2 * step)]


@pytest.mark.asyncio
async def test_a_tick_queues_no_more_than_fit_before_the_next_one() -> None:
    """A list still on its countdown at the next tick would be queued twice."""
    calls: list[tuple[list[str], int]] = []

    def fake_apply_async(*, args: list[str], countdown: int) -> None:
        calls.append((args, countdown))

    ids = [f"l{i}" for i in range(sweep.MAX_PER_TICK + 15)]

    async def fake_due(_db: object, _now: datetime) -> list[str]:
        return ids

    async def enabled(_db: object, _key: str) -> bool:
        return True

    with (
        patch.object(sweep, "due_blocklist_ids", fake_due),
        patch.object(sweep, "is_module_enabled", enabled),
        patch("app.tasks.dns.refresh_blocklist_feed.apply_async", side_effect=fake_apply_async),
    ):
        queued = await sweep._dispatch_due_async()  # noqa: SLF001

    assert queued == sweep.MAX_PER_TICK
    # Longest-overdue first: the ones left over are the most recently synced.
    assert [c[0][0] for c in calls] == ids[: sweep.MAX_PER_TICK]
    # The last one starts with time to finish before the next tick.
    assert max(c[1] for c in calls) + 300 <= sweep.SWEEP_PERIOD_SECONDS


def test_the_tick_cap_matches_the_beat_period() -> None:
    from app.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["dns-blocklist-refresh"]
    assert entry["schedule"].run_every.total_seconds() == sweep.SWEEP_PERIOD_SECONDS


@pytest.mark.asyncio
async def test_the_sweep_does_nothing_with_dns_switched_off() -> None:
    async def disabled(_db: object, _key: str) -> bool:
        return False

    with (
        patch.object(sweep, "is_module_enabled", disabled),
        patch("app.tasks.dns.refresh_blocklist_feed.apply_async") as apply_async,
    ):
        assert await sweep._dispatch_due_async() == 0  # noqa: SLF001
    apply_async.assert_not_called()


def test_the_sweep_is_scheduled_on_the_dns_queue() -> None:
    entry = celery_app.conf.beat_schedule["dns-blocklist-refresh"]
    assert entry["task"] == "app.tasks.blocklist_refresh_sweep.dispatch_due_blocklists"
    assert entry["schedule"].run_every.total_seconds() == 3600
    assert "app.tasks.blocklist_refresh_sweep" in celery_app.conf.include
    assert celery_app.conf.task_routes["app.tasks.blocklist_refresh_sweep.*"] == {"queue": "dns"}


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="bl-interval-admin",
        email="bl-interval-admin@example.test",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("hours", [-1, 8761])
async def test_an_out_of_range_interval_is_refused(
    client: AsyncClient, db_session: AsyncSession, hours: int
) -> None:
    headers = await _admin_headers(db_session)
    resp = await client.post(
        "/api/v1/dns/blocklists",
        headers=headers,
        json={"name": f"bad-{hours}", "update_interval_hours": hours},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_zero_and_the_cap_are_accepted(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin_headers(db_session)
    for hours in (0, 8760):
        resp = await client.post(
            "/api/v1/dns/blocklists",
            headers=headers,
            json={"name": f"ok-{hours}", "update_interval_hours": hours},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["update_interval_hours"] == hours
