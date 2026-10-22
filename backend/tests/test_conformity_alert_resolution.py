"""Conformity alert events resolve themselves — issue #2277.

#1578 took ``subject_type="conformity"`` events away from the generic
alert evaluator, which used to close them (wrongly, within a tick). The
engine never picked up the job, so an event stayed open forever: a fixed
subnet, a deleted subnet or a disabled policy left the alert red, and
because the event was still open a later re-failure never paged.

These run real policies through ``evaluate_policy`` against real subnets
with a check whose verdict the test controls, and assert on the stored
``AlertEvent`` rows and on what was handed to delivery.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import User
from app.models.conformity import ConformityPolicy
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import alerts as alert_service
from app.services.conformity import engine
from app.services.conformity.checks import CheckOutcome

_CHECK = "test_2277_controlled"


class _Harness:
    """A check whose verdict per subnet the test sets, plus a record of
    every event handed to delivery (one entry = one page)."""

    def __init__(self) -> None:
        self.verdicts: dict[uuid.UUID, str] = {}
        self.crash: set[uuid.UUID] = set()
        self.paged: list[str] = []

    async def check(self, db: AsyncSession, *, target: Any, **_: Any) -> CheckOutcome:
        if target.id in self.crash:
            raise RuntimeError("boom")
        status = self.verdicts.get(target.id, "pass")
        return CheckOutcome(status, f"verdict {status}", {})

    async def deliver(
        self, rule: AlertRule, event: AlertEvent, targets: list[dict[str, Any]]
    ) -> tuple[bool, bool, bool]:
        self.paged.append(event.subject_id)
        return False, False, False


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession) -> _Harness:
    # The tests commit between passes the way the beat task does; keep
    # the fixtures' rows readable across those commits.
    db_session.sync_session.expire_on_commit = False
    h = _Harness()
    monkeypatch.setitem(engine.CHECK_REGISTRY, _CHECK, h.check)
    # The engine binds ``_deliver`` at import; patch both names so the
    # count holds whichever one the delivery path resolves.
    monkeypatch.setattr(engine, "_deliver", h.deliver, raising=False)
    monkeypatch.setattr(alert_service, "_deliver", h.deliver)
    return h


async def _subnet(db: AsyncSession, *, pci: bool = True) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, name="b", network="10.0.0.0/16")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        name=f"s-{uuid.uuid4().hex[:6]}",
        network="10.0.1.0/24",
        pci_scope=pci,
    )
    db.add(subnet)
    await db.flush()
    return subnet


async def _policy(db: AsyncSession) -> ConformityPolicy:
    rule = AlertRule(
        name=f"conf-{uuid.uuid4().hex[:8]}",
        description="",
        rule_type="compliance_change",
        classification="pci_scope",
        severity="critical",
        enabled=True,
    )
    db.add(rule)
    await db.flush()
    policy = ConformityPolicy(
        name=f"pol-{uuid.uuid4().hex[:8]}",
        framework="custom",
        target_kind="subnet",
        target_filter={"classification": "pci_scope"},
        check_kind=_CHECK,
        check_args={},
        fail_alert_rule_id=rule.id,
    )
    db.add(policy)
    await db.flush()
    return policy


async def _events(db: AsyncSession, policy: ConformityPolicy) -> list[AlertEvent]:
    return list(
        (
            await db.execute(
                select(AlertEvent)
                .where(
                    AlertEvent.subject_type == "conformity",
                    AlertEvent.subject_id.startswith(f"{policy.id}:"),
                )
                .order_by(AlertEvent.fired_at)
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


async def _evaluate(db: AsyncSession, policy: ConformityPolicy) -> None:
    await engine.evaluate_policy(db, policy)
    await db.commit()


def _open(events: list[AlertEvent]) -> list[AlertEvent]:
    return [e for e in events if e.resolved_at is None]


def _resolution(event: AlertEvent) -> str | None:
    return (event.last_observed_value or {}).get("resolution")


@pytest.mark.asyncio
async def test_fail_then_pass_resolves_on_that_pass(
    db_session: AsyncSession, harness: _Harness
) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)

    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)
    events = await _events(db_session, policy)
    assert len(_open(events)) == 1
    assert len(harness.paged) == 1

    harness.verdicts[subnet.id] = "pass"
    await _evaluate(db_session, policy)
    events = await _events(db_session, policy)
    assert _open(events) == []
    assert _resolution(events[0]) == "passed"
    # Resolution is not a page.
    assert len(harness.paged) == 1


@pytest.mark.asyncio
async def test_not_applicable_resolves(db_session: AsyncSession, harness: _Harness) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)

    harness.verdicts[subnet.id] = "not_applicable"
    await _evaluate(db_session, policy)
    events = await _events(db_session, policy)
    assert _open(events) == []
    assert _resolution(events[0]) == "not_applicable"


@pytest.mark.asyncio
async def test_refail_after_pass_opens_a_new_event_and_pages(
    db_session: AsyncSession, harness: _Harness
) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)

    for verdict in ("fail", "pass", "fail"):
        harness.verdicts[subnet.id] = verdict
        await _evaluate(db_session, policy)

    events = await _events(db_session, policy)
    assert len(events) == 2
    assert events[0].resolved_at is not None
    assert events[1].resolved_at is None
    assert len(harness.paged) == 2


@pytest.mark.asyncio
async def test_still_failing_does_not_repage_or_resolve(
    db_session: AsyncSession, harness: _Harness
) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    for _ in range(3):
        await _evaluate(db_session, policy)

    events = await _events(db_session, policy)
    assert len(events) == 1 and events[0].resolved_at is None
    assert len(harness.paged) == 1


@pytest.mark.asyncio
async def test_warn_and_crashed_check_hold_the_event_open(
    db_session: AsyncSession, harness: _Harness
) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)

    harness.verdicts[subnet.id] = "warn"
    await _evaluate(db_session, policy)
    assert len(_open(await _events(db_session, policy))) == 1

    # A crash is an unknown, not evidence the failure went away.
    harness.crash.add(subnet.id)
    await _evaluate(db_session, policy)
    assert len(_open(await _events(db_session, policy))) == 1


@pytest.mark.asyncio
async def test_deleted_target_resolves(db_session: AsyncSession, harness: _Harness) -> None:
    subnet = await _subnet(db_session)
    other = await _subnet(db_session)
    policy = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    harness.verdicts[other.id] = "fail"
    await _evaluate(db_session, policy)
    assert len(_open(await _events(db_session, policy))) == 2

    await db_session.delete(subnet)
    await db_session.commit()
    await _evaluate(db_session, policy)

    events = await _events(db_session, policy)
    by_target = {e.subject_id.rsplit(":", 1)[1]: e for e in events}
    assert by_target[str(subnet.id)].resolved_at is not None
    assert _resolution(by_target[str(subnet.id)]) == "out_of_scope"
    # The other subnet still fails; its event stays open.
    assert by_target[str(other.id)].resolved_at is None


@pytest.mark.asyncio
async def test_out_of_scope_resolves_and_returning_still_failing_pages(
    db_session: AsyncSession, harness: _Harness
) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)

    subnet.pci_scope = False
    await db_session.commit()
    await _evaluate(db_session, policy)
    events = await _events(db_session, policy)
    assert _open(events) == []
    assert _resolution(events[0]) == "out_of_scope"

    # Back in scope and still failing. The last stored result is "fail"
    # (no result is written while out of scope), but the engine closed
    # the event, so this is a new incident.
    subnet.pci_scope = True
    await db_session.commit()
    await _evaluate(db_session, policy)
    events = await _events(db_session, policy)
    assert len(_open(events)) == 1
    assert len(harness.paged) == 2


@pytest.mark.asyncio
async def test_manual_resolve_while_failing_does_not_repage(
    db_session: AsyncSession, harness: _Harness
) -> None:
    """Unchanged behaviour: an operator who resolves a still-failing
    event by hand is not paged again on every pass."""
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)
    await db_session.execute(
        update(AlertEvent)
        .where(AlertEvent.subject_id.startswith(f"{policy.id}:"))
        .values(resolved_at=datetime.now(UTC))
    )
    await db_session.commit()

    await _evaluate(db_session, policy)
    assert _open(await _events(db_session, policy)) == []
    assert len(harness.paged) == 1


@pytest.mark.asyncio
async def test_resolution_is_idempotent(db_session: AsyncSession, harness: _Harness) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)
    harness.verdicts[subnet.id] = "pass"
    await _evaluate(db_session, policy)
    first = (await _events(db_session, policy))[0].resolved_at

    await _evaluate(db_session, policy)
    assert await engine.resolve_orphaned_policy_alerts(db_session) == 0
    events = await _events(db_session, policy)
    assert len(events) == 1
    assert events[0].resolved_at == first


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("pw"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_disabling_a_policy_resolves_its_events_and_reenabling_repages(
    client: AsyncClient, db_session: AsyncSession, harness: _Harness
) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    headers = await _admin_headers(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)

    r = await client.patch(
        f"/api/v1/conformity/policies/{policy.id}", headers=headers, json={"enabled": False}
    )
    assert r.status_code == 200, r.text
    events = await _events(db_session, policy)
    assert _open(events) == []
    assert _resolution(events[0]) == "policy_disabled"

    r = await client.patch(
        f"/api/v1/conformity/policies/{policy.id}", headers=headers, json={"enabled": True}
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(policy)
    await _evaluate(db_session, policy)
    assert len(_open(await _events(db_session, policy))) == 1
    assert len(harness.paged) == 2


@pytest.mark.asyncio
async def test_deleting_a_policy_resolves_its_events(
    client: AsyncClient, db_session: AsyncSession, harness: _Harness
) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    headers = await _admin_headers(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)

    r = await client.delete(f"/api/v1/conformity/policies/{policy.id}", headers=headers)
    assert r.status_code == 204, r.text
    events = await _events(db_session, policy)
    assert _open(events) == []
    assert _resolution(events[0]) == "policy_deleted"


@pytest.mark.asyncio
async def test_beat_sweep_resolves_events_of_a_policy_disabled_out_of_band(
    db_session: AsyncSession, harness: _Harness
) -> None:
    """A path that flips ``enabled`` without the hook (a restore, direct
    SQL) is caught by the sweep the beat task runs every minute."""
    subnet = await _subnet(db_session)
    disabled = await _policy(db_session)
    live = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, disabled)
    await _evaluate(db_session, live)

    await db_session.execute(
        update(ConformityPolicy).where(ConformityPolicy.id == disabled.id).values(enabled=False)
    )
    await db_session.commit()
    assert await engine.resolve_orphaned_policy_alerts(db_session) == 1
    await db_session.commit()

    gone = await _events(db_session, disabled)
    assert _open(gone) == [] and _resolution(gone[0]) == "policy_disabled"
    assert len(_open(await _events(db_session, live))) == 1


@pytest.mark.asyncio
async def test_beat_pass_pages_after_commit_and_resolves(
    db_session: AsyncSession, harness: _Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the beat entry point, which defers delivery (#2261): the
    page goes out for an event another connection can already see, and
    the next due pass resolves it once the resource passes."""
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    await db_session.commit()

    committed_when_paged: list[int] = []

    async def deliver(rule: AlertRule, event: AlertEvent, targets: Any) -> Any:
        async with db_session.bind.connect() as conn:
            committed_when_paged.append(
                (
                    await conn.execute(
                        select(func.count())
                        .select_from(AlertEvent)
                        .where(AlertEvent.id == event.id)
                    )
                ).scalar_one()
            )
        return await harness.deliver(rule, event, targets)

    monkeypatch.setattr(alert_service, "_deliver", deliver)

    harness.verdicts[subnet.id] = "fail"
    await engine.evaluate_due_policies(db_session)
    assert len(_open(await _events(db_session, policy))) == 1
    assert committed_when_paged == [1]

    harness.verdicts[subnet.id] = "pass"
    policy.last_evaluated_at = None  # due again
    await db_session.commit()
    await engine.evaluate_due_policies(db_session)
    events = await _events(db_session, policy)
    assert _open(events) == [] and _resolution(events[0]) == "passed"
    assert len(harness.paged) == 1


async def _rule(db: AsyncSession) -> AlertRule:
    rule = AlertRule(
        name=f"conf-{uuid.uuid4().hex[:8]}",
        description="",
        rule_type="compliance_change",
        classification="pci_scope",
        severity="critical",
        enabled=True,
    )
    db.add(rule)
    await db.flush()
    return rule


@pytest.mark.asyncio
async def test_switching_the_alert_rule_moves_the_failure_to_the_new_rule(
    db_session: AsyncSession, harness: _Harness
) -> None:
    """Re-wiring ``fail_alert_rule_id`` while a resource fails closes the
    old rule's event and pages the ongoing failure once on the new rule."""
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    old_rule_id = policy.fail_alert_rule_id
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)

    new_rule = await _rule(db_session)
    policy.fail_alert_rule_id = new_rule.id
    await db_session.commit()
    await _evaluate(db_session, policy)
    await _evaluate(db_session, policy)

    events = await _events(db_session, policy)
    assert len(events) == 2
    old, new = events
    assert old.rule_id == old_rule_id and old.resolved_at is not None
    assert _resolution(old) == "alert_rule_changed"
    assert new.rule_id == new_rule.id and new.resolved_at is None
    assert len(harness.paged) == 2


@pytest.mark.asyncio
async def test_clearing_the_alert_rule_resolves_and_does_not_page(
    db_session: AsyncSession, harness: _Harness
) -> None:
    subnet = await _subnet(db_session)
    policy = await _policy(db_session)
    harness.verdicts[subnet.id] = "fail"
    await _evaluate(db_session, policy)

    policy.fail_alert_rule_id = None
    await db_session.commit()
    await _evaluate(db_session, policy)

    events = await _events(db_session, policy)
    assert _open(events) == [] and _resolution(events[0]) == "alert_rule_changed"
    assert len(harness.paged) == 1
