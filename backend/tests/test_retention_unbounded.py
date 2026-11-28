"""#2274 — retention for the tables that grew forever, and the batched delete.

Each prune must remove only OLD + TERMINAL rows, keep everything else, treat
a window of 0 as keep-forever, and be idempotent.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai import AIChatMessage, AIChatSession
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import User, UserSession
from app.models.change_request import ChangeRequest
from app.models.conformity import ConformityPolicy, ConformityResult
from app.models.event_subscription import EventOutbox, EventSubscription
from app.models.ipam import IPAddress, IPBlock, IpMacHistory, IPSpace, Subnet
from app.models.nmap import NmapScan
from app.models.settings import PlatformSettings
from app.models.wol_schedule import WolRun
from app.services.retention import batched_delete, prune_unbounded_tables

NOW = datetime.now(UTC)


def old(days: int = 4000) -> datetime:
    return NOW - timedelta(days=days)


async def count(db: AsyncSession, model: Any) -> int:
    db.expire_all()
    return (await db.execute(select(func.count()).select_from(model))).scalar_one()


async def settings_row(db: AsyncSession, **kw: int) -> PlatformSettings:
    row = await db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
    for k, v in kw.items():
        setattr(row, k, v)
    await db.commit()
    return row


async def make_user(db: AsyncSession) -> User:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="u",
        hashed_password="x",
        auth_source="local",
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return u


# ── batched_delete ────────────────────────────────────────────────────


async def test_batched_delete_removes_all_in_several_batches(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    for _ in range(7):
        db_session.add(
            UserSession(
                user_id=user.id,
                refresh_token_hash=uuid.uuid4().hex,
                created_at=old(),
                expires_at=old(),
            )
        )
    keep = UserSession(
        user_id=user.id,
        refresh_token_hash=uuid.uuid4().hex,
        created_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )
    db_session.add(keep)
    await db_session.commit()

    n = await batched_delete(UserSession, UserSession.expires_at < NOW, batch_size=3)
    assert n == 7
    assert await count(db_session, UserSession) == 1
    assert await batched_delete(UserSession, UserSession.expires_at < NOW, batch_size=3) == 0


async def test_batched_delete_commits_each_batch(db_session: AsyncSession) -> None:
    """A failure mid-way leaves the earlier batches committed (resumable)."""
    user = await make_user(db_session)
    for _ in range(5):
        db_session.add(
            UserSession(
                user_id=user.id,
                refresh_token_hash=uuid.uuid4().hex,
                created_at=old(),
                expires_at=old(),
            )
        )
    await db_session.commit()

    from app.db import task_sessionmaker

    calls = 0
    async with task_sessionmaker() as real:

        def flaky() -> Any:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeError("boom")
            return real()

        with pytest.raises(RuntimeError):
            await batched_delete(
                UserSession, UserSession.expires_at < NOW, batch_size=2, session_factory=flaky
            )
    assert await count(db_session, UserSession) == 1  # two batches of 2 survived the failure


async def test_batched_delete_rejects_bad_batch_size() -> None:
    with pytest.raises(ValueError):
        await batched_delete(UserSession, UserSession.expires_at < NOW, batch_size=0)


# ── per-table prunes ──────────────────────────────────────────────────


async def test_alert_events_only_resolved_and_old(db_session: AsyncSession) -> None:
    rule = AlertRule(name="r", rule_type="subnet_utilization", severity="info")
    db_session.add(rule)
    await db_session.flush()

    shared = str(uuid.uuid4())

    def ev(fired: datetime, resolved: datetime | None, subject: str | None = None) -> AlertEvent:
        return AlertEvent(
            rule_id=rule.id,
            subject_type="subnet",
            subject_id=subject or str(uuid.uuid4()),
            fired_at=fired,
            resolved_at=resolved,
        )

    db_session.add_all(
        [
            ev(old(), old(3999), shared),  # resolved long ago, superseded: pruned
            ev(old(3000), old(2999), shared),  # newest for its subject: kept
            ev(old(), None),  # still open, however old: kept
            ev(old(), NOW - timedelta(days=10)),  # resolved recently: kept
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["alert_event"] == 1
    assert await count(db_session, AlertEvent) == 3
    assert (await prune_unbounded_tables())["alert_event"] == 0


async def test_alert_events_keep_state_the_evaluators_read(db_session: AsyncSession) -> None:
    """The newest event per (rule, subject) is a baseline (transition-once
    rules, conformity) and a manual resolve still suppresses its subject
    (#2498): neither may be pruned, only the older history behind them."""
    rule = AlertRule(name="r2", rule_type="tls_cert_changed", severity="info")
    db_session.add(rule)
    await db_session.flush()

    def ev(subject: str, age: int, **kw: Any) -> AlertEvent:
        return AlertEvent(
            rule_id=rule.id,
            subject_type="tls_cert",
            subject_id=subject,
            fired_at=old(age),
            resolved_at=old(age - 1),
            **kw,
        )

    manual = ev("manual", 4000, last_observed_value={"resolved_by": "manual"})
    cleared = ev(
        "manual", 3999, last_observed_value={"resolved_by": "manual", "manual_cleared": True}
    )
    db_session.add_all(
        [
            ev("base", 4000),  # older history behind a newer event: pruned
            ev("base", 3999, last_observed_value={"to": "fp"}),  # newest: the baseline, kept
            manual,  # still suppressing: kept although a newer event exists
            cleared,  # newest of its subject: kept
            ev("pending", 4000, delivery_pending_since=old(4000)),  # undelivered: kept
            ev("pending", 3999),  # newest: kept
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["alert_event"] == 1
    assert await count(db_session, AlertEvent) == 5


async def test_user_sessions_expired_or_old_revoked(db_session: AsyncSession) -> None:
    user = await make_user(db_session)

    def sess(**kw: Any) -> UserSession:
        base: dict[str, Any] = dict(
            user_id=user.id,
            refresh_token_hash=uuid.uuid4().hex,
            created_at=old(),
            expires_at=NOW + timedelta(days=5),
        )
        base.update(kw)
        return UserSession(**base)

    db_session.add_all(
        [
            sess(expires_at=old(100)),  # expired long ago: pruned
            sess(expires_at=NOW - timedelta(days=1)),  # expired yesterday: kept
            sess(revoked=True),  # revoked, idle for ages: pruned
            sess(revoked=True, created_at=NOW, last_seen_at=NOW),  # revoked just now: kept
            sess(created_at=NOW),  # live: kept
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["user_session"] == 2
    assert await count(db_session, UserSession) == 3


async def test_change_requests_only_terminal(db_session: AsyncSession) -> None:
    def cr(state: str, age: int) -> ChangeRequest:
        return ChangeRequest(
            operation="delete_subnet",
            resource_type="subnet",
            resource_display="x",
            args={},
            preview_text="p",
            risk_reason="r",
            state=state,
            requested_by_display="u",
            expires_at=NOW,
            created_at=old(),
            modified_at=NOW - timedelta(days=age),
        )

    db_session.add_all(
        [cr("executed", 4000), cr("rejected", 4000), cr("pending", 4000), cr("executed", 1)]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["change_request"] == 2
    states = sorted(
        (await db_session.execute(select(ChangeRequest.state))).scalars().all(),
    )
    assert states == ["executed", "pending"]


async def test_event_outbox_only_old_delivered(db_session: AsyncSession) -> None:
    sub = EventSubscription(name="s", url="https://example.test/h", event_types=[])
    db_session.add(sub)
    await db_session.flush()

    def ob(state: str, delivered: datetime | None) -> EventOutbox:
        return EventOutbox(
            subscription_id=sub.id, event_type="x", payload={}, state=state, delivered_at=delivered
        )

    db_session.add_all(
        [
            ob("delivered", NOW - timedelta(days=30)),  # pruned
            ob("delivered", NOW - timedelta(days=1)),  # recent: kept
            ob("pending", None),  # kept
            ob("dead", NOW - timedelta(days=30)),  # kept: operator may want to inspect it
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["event_outbox"] == 1
    assert await count(db_session, EventOutbox) == 3


async def test_nmap_only_finished_and_old(db_session: AsyncSession) -> None:
    def scan(status: str, finished: datetime | None) -> NmapScan:
        return NmapScan(target_ip="10.0.0.1", status=status, finished_at=finished)

    db_session.add_all(
        [
            scan("completed", NOW - timedelta(days=200)),  # pruned
            scan("completed", NOW - timedelta(days=5)),  # kept
            scan("running", None),  # kept
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["nmap_scan"] == 1
    assert await count(db_session, NmapScan) == 2


async def test_wol_run_only_finished_and_old(db_session: AsyncSession) -> None:
    def run(status: str, started: datetime) -> WolRun:
        return WolRun(trigger="manual", status=status, started_at=started, finished_at=started)

    db_session.add_all(
        [
            run("ok", old()),  # pruned
            run("in_progress", old()),  # kept
            run("ok", NOW),  # kept
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["wol_run"] == 1
    assert await count(db_session, WolRun) == 2


async def test_ai_chats_only_idle(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    idle = AIChatSession(user_id=user.id, modified_at=old())
    active = AIChatSession(user_id=user.id, modified_at=old())
    fresh = AIChatSession(user_id=user.id)
    db_session.add_all([idle, active, fresh])
    await db_session.flush()
    db_session.add_all(
        [
            AIChatMessage(session_id=idle.id, role="user", content="a", created_at=old()),
            AIChatMessage(session_id=active.id, role="user", content="b", created_at=NOW),
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["ai_chat_session"] == 1
    assert await count(db_session, AIChatSession) == 2
    assert await count(db_session, AIChatMessage) == 1  # idle chat's message cascaded


async def test_ip_mac_history_keeps_operator_decisions(db_session: AsyncSession) -> None:
    space = IPSpace(name="s")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.1.0.0/24", name="n")
    db_session.add(subnet)
    await db_session.flush()
    ips = []
    for i in range(1, 5):
        ip = IPAddress(subnet_id=subnet.id, address=f"10.1.0.{i}", status="allocated")
        db_session.add(ip)
        ips.append(ip)
    await db_session.flush()
    db_session.add_all(
        [
            IpMacHistory(ip_address_id=ips[0].id, mac_address="aa:bb:cc:00:00:01", last_seen=old()),
            IpMacHistory(
                ip_address_id=ips[1].id,
                mac_address="aa:bb:cc:00:00:02",
                last_seen=old(),
                classification="acknowledged",
            ),
            IpMacHistory(
                ip_address_id=ips[2].id,
                mac_address="aa:bb:cc:00:00:03",
                last_seen=old(),
                classification="known",
            ),
            IpMacHistory(ip_address_id=ips[3].id, mac_address="aa:bb:cc:00:00:04", last_seen=NOW),
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["ip_mac_history"] == 1
    assert await count(db_session, IpMacHistory) == 3


async def test_conformity_keeps_newest_result_per_target(db_session: AsyncSession) -> None:
    pol = ConformityPolicy(
        name="p",
        framework="custom",
        check_kind="subnet_has_vlan",
        target_kind="subnet",
        target_filter={},
        severity="info",
    )
    db_session.add(pol)
    await db_session.flush()

    def res(rid: str, at: datetime) -> ConformityResult:
        return ConformityResult(
            policy_id=pol.id,
            resource_kind="subnet",
            resource_id=rid,
            evaluated_at=at,
            status="pass",
        )

    db_session.add_all(
        [
            res("a", old(900)),  # superseded and old: pruned
            res("a", old(800)),  # newest for "a", though old: kept
            res("b", old(900)),  # only one for "b": kept
            res("c", old(900)),  # superseded...
            res("c", NOW),  # ...by a fresh one: pruned
        ]
    )
    await db_session.commit()
    assert (await prune_unbounded_tables())["conformity_result"] == 2
    assert await count(db_session, ConformityResult) == 3


async def test_zero_window_keeps_forever(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    db_session.add(
        UserSession(
            user_id=user.id, refresh_token_hash=uuid.uuid4().hex, created_at=old(), expires_at=old()
        )
    )
    await db_session.commit()
    await settings_row(db_session, user_session_retention_days=0)
    out = await prune_unbounded_tables()
    assert "user_session" not in out
    assert await count(db_session, UserSession) == 1


async def test_window_comes_from_the_setting(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    db_session.add(
        UserSession(
            user_id=user.id,
            refresh_token_hash=uuid.uuid4().hex,
            created_at=old(),
            expires_at=NOW - timedelta(days=10),
        )
    )
    await db_session.commit()
    await settings_row(db_session, user_session_retention_days=30)
    assert (await prune_unbounded_tables())["user_session"] == 0
    await settings_row(db_session, user_session_retention_days=5)
    assert (await prune_unbounded_tables())["user_session"] == 1
