"""``appliance_disk_usage`` alert rule (#2240).

Every node's supervisor reports its ``/var`` data partition as used and total
bytes inside ``cluster_health`` (#402, ``host_disk_partitions``), and nothing
alarmed on it. A seven-node cluster loaded towards a million devices filled
``/var`` (23 GiB of a 40 GiB disk) to 88-91% on every node with every alert
quiet. The kubelet starts evicting pods, the control plane's included, once
less than 5% of ``/var`` is available to it.

The rule warns at the operator's threshold and is critical at the kubelet's
eviction line, per appliance, and follows the ``appliance_storage_degraded``
(#999) conventions: a reading that does not exist is not a match, and a
reading that disappears or goes stale holds an open event instead of
announcing a recovery that nobody observed.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.services import alerts as alerts_svc

GIB = 1024**3


def _parts(var: tuple[int, int] | None, *, root_pct: int = 40, esp_pct: int = 5) -> list[dict]:
    """``host_disk_partitions`` the way ``read_host_disk_partitions`` ships it."""
    parts: list[dict[str, Any]] = [
        {
            "mount": "/",
            "label": "OS (root slot)",
            "total_bytes": 8 * GIB,
            "used_bytes": 8 * GIB * root_pct // 100,
        },
        {
            "mount": "/boot/efi",
            "label": "ESP",
            "total_bytes": 512 * 1024**2,
            "used_bytes": 512 * 1024**2 * esp_pct // 100,
        },
    ]
    if var is not None:
        used, total = var
        parts.insert(
            1, {"mount": "/var", "label": "Data", "total_bytes": total, "used_bytes": used}
        )
    return parts


def _pct_of(total: int, pct: float) -> tuple[int, int]:
    return int(total * pct / 100), total


async def _node(
    db: AsyncSession,
    *,
    var: tuple[int, int] | None = None,
    cluster_health: dict | None = None,
    last_seen: datetime | None | str = "now",
    state: str = APPLIANCE_STATE_APPROVED,
    revoked: bool = False,
    hostname: str | None = None,
) -> Appliance:
    der = os.urandom(32)
    if cluster_health is None:
        cluster_health = {"kubeapi_ready": True, "host_disk_partitions": _parts(var)}
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname or f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=state,
        deployment_kind="appliance",
        appliance_variant="control-plane",
        session_token_hash=hashlib.sha256(der).hexdigest(),
        cluster_health=cluster_health,
        last_seen_at=datetime.now(UTC) if last_seen == "now" else last_seen,
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    db.add(row)
    await db.flush()
    return row


def _rule(threshold: int | None = None) -> AlertRule:
    return AlertRule(
        name="Appliance data partition filling (test)",
        rule_type=alerts_svc.RULE_TYPE_APPLIANCE_DISK_USAGE,
        severity="warning",
        enabled=True,
        threshold_percent=threshold,
    )


async def _match(
    db: AsyncSession, rule: AlertRule | None = None
) -> dict[str, tuple[str, str, str]]:
    """``{subject_id: (display, message, severity)}`` for one matcher pass."""
    matches = await alerts_svc._matching_appliance_disk_usage_subjects(  # noqa: SLF001
        db, rule if rule is not None else _rule(), datetime.now(UTC)
    )
    return {sid: (disp, msg, sev) for sid, disp, msg, sev in matches}


async def _open_events(db: AsyncSession, rule: AlertRule) -> list[AlertEvent]:
    return list(
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )


async def _no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]
    return (False, False, False)


# ── registration ───────────────────────────────────────────────────────────


def test_rule_type_is_registered_and_catalogued() -> None:
    """Registered, so ``POST /alerts/rules`` accepts it and an operator who
    deletes the seeded rule can recreate it; catalogued, so the editor shows
    its threshold with the evaluator's default."""
    from app.services.alert_rule_catalogue import build_catalogue

    assert alerts_svc.RULE_TYPE_APPLIANCE_DISK_USAGE == "appliance_disk_usage"
    assert alerts_svc.RULE_TYPE_APPLIANCE_DISK_USAGE in alerts_svc.RULE_TYPES
    spec = next(s for s in build_catalogue() if s.rule_type == "appliance_disk_usage")
    assert spec.group == "Infrastructure"
    assert [p.name for p in spec.params] == ["threshold_percent"]
    assert spec.params[0].default == 80
    assert spec.params[0].unit == "%"


# ── the matcher ────────────────────────────────────────────────────────────


async def test_var_at_or_over_the_threshold_warns_and_below_is_silent(
    db_session: AsyncSession,
) -> None:
    quiet = await _node(db_session, var=_pct_of(40 * GIB, 79.9), hostname="ddi-quiet")
    at = await _node(db_session, var=_pct_of(40 * GIB, 80), hostname="ddi-at")
    over = await _node(db_session, var=_pct_of(40 * GIB, 86), hostname="ddi-over")

    got = await _match(db_session)

    assert set(got) == {str(at.id), str(over.id)}
    assert str(quiet.id) not in got
    display, message, severity = got[str(over.id)]
    assert display == "ddi-over"
    assert severity == "warning"
    assert "/var" in message and "ddi-over" in message
    assert "86%" in message
    assert "34.4 GiB of 40.0 GiB" in message


async def test_the_kubelet_eviction_line_is_critical_whatever_the_threshold(
    db_session: AsyncSession,
) -> None:
    """At 90% used by the supervisor's count, the 5% ext4 keeps for root
    leaves the kubelet its last 5%: ``nodefs.available<5%`` starts evicting.
    That is not a tuning question, so a threshold set above it does not
    silence it, the same way ``node_pressure``'s fixed full-stall floor is
    critical whatever its threshold says."""
    line = await _node(db_session, var=_pct_of(40 * GIB, 90))
    past = await _node(db_session, var=_pct_of(64 * GIB, 97))
    under = await _node(db_session, var=_pct_of(40 * GIB, 89.9))

    got = await _match(db_session)
    assert got[str(line.id)][2] == "critical"
    assert got[str(past.id)][2] == "critical"
    assert got[str(under.id)][2] == "warning"
    assert "evict" in got[str(past.id)][1]

    # A threshold above the line still leaves the line critical.
    got = await _match(db_session, _rule(threshold=95))
    assert got[str(line.id)][2] == "critical"
    assert got[str(past.id)][2] == "critical"
    assert str(under.id) not in got


async def test_the_threshold_is_operator_tunable(db_session: AsyncSession) -> None:
    half = await _node(db_session, var=_pct_of(40 * GIB, 60))
    tenth = await _node(db_session, var=_pct_of(40 * GIB, 10))

    assert await _match(db_session) == {}
    assert set(await _match(db_session, _rule(threshold=50))) == {str(half.id)}
    # 0 means what it says: every node that reports /var at all.
    assert set(await _match(db_session, _rule(threshold=0))) == {str(half.id), str(tenth.id)}


async def test_a_null_threshold_uses_the_default(db_session: AsyncSession) -> None:
    node = await _node(db_session, var=_pct_of(40 * GIB, 81))
    assert set(await _match(db_session, _rule(threshold=None))) == {str(node.id)}
    assert await _match(db_session, _rule(threshold=82)) == {}


async def test_no_reading_is_never_a_match(db_session: AsyncSession) -> None:
    """A supervisor that reports no ``/var`` is UNKNOWN: firing would be a
    guess, and treating it as fine would be a lie. Neither is a match."""
    await _node(db_session, cluster_health={"kubeapi_ready": True})
    await _node(db_session, cluster_health={})
    await _node(db_session, var=None)  # partitions reported, /var not among them
    for bad in (
        {"mount": "/var", "total_bytes": 0, "used_bytes": 0},
        {"mount": "/var", "total_bytes": True, "used_bytes": True},
        {"mount": "/var", "total_bytes": "40", "used_bytes": "39"},
        {"mount": "/var", "total_bytes": 40 * GIB, "used_bytes": -1},
        {"mount": "/var"},
    ):
        await _node(
            db_session,
            cluster_health={"kubeapi_ready": True, "host_disk_partitions": [bad]},
        )
    await _node(db_session, cluster_health={"host_disk_partitions": "not a list"})

    assert await _match(db_session, _rule(threshold=0)) == {}


async def test_only_var_is_judged(db_session: AsyncSession) -> None:
    """The root slot is a read-only image and the ESP a fixed boot partition;
    neither fills the way ``/var`` (Postgres, images, logs) does."""
    await _node(
        db_session,
        cluster_health={
            "host_disk_partitions": _parts(_pct_of(40 * GIB, 10), root_pct=99, esp_pct=99)
        },
    )
    assert await _match(db_session) == {}


async def test_revoked_and_unapproved_nodes_are_skipped(db_session: AsyncSession) -> None:
    await _node(db_session, var=_pct_of(40 * GIB, 95), revoked=True)
    await _node(db_session, var=_pct_of(40 * GIB, 95), state="pending_approval")
    assert await _match(db_session) == {}


async def test_a_reading_that_disappears_holds_its_open_event(
    db_session: AsyncSession,
) -> None:
    """``evaluate_all`` resolves every open event whose subject is absent from
    a pass. A supervisor rolled back to a slot that does not report ``/var``
    would otherwise announce that a full disk recovered."""
    rolled_back = await _node(db_session, cluster_health={"kubeapi_ready": True})
    await _node(db_session, cluster_health={"kubeapi_ready": True})  # never reported
    rule = _rule()
    db_session.add(rule)
    await db_session.flush()
    db_session.add(
        AlertEvent(
            rule_id=rule.id,
            subject_type="appliance",
            subject_id=str(rolled_back.id),
            subject_display=rolled_back.hostname,
            severity="critical",
            message="/var on it is 93% full.",
            fired_at=datetime.now(UTC),
        )
    )
    await db_session.flush()

    got = await _match(db_session, rule)
    assert set(got) == {str(rolled_back.id)}
    _display, message, severity = got[str(rolled_back.id)]
    assert severity == "critical"  # held at its existing severity: a no-op for the caller
    assert "can no longer be read" in message


async def test_a_stale_reading_opens_nothing_and_holds_what_is_open(
    db_session: AsyncSession,
) -> None:
    """A node that stopped heartbeating keeps its last ``cluster_health``.
    That old number says nothing about now (``appliance_heartbeat_stale``
    covers the silence), so it opens no event, and an event already open is
    held rather than resolved."""
    now = datetime.now(UTC)
    await _node(db_session, var=_pct_of(40 * GIB, 95), last_seen=now - timedelta(minutes=30))
    held = await _node(db_session, var=_pct_of(40 * GIB, 50), last_seen=now - timedelta(hours=2))
    await _node(db_session, var=_pct_of(40 * GIB, 95), last_seen=None)
    rule = _rule()
    db_session.add(rule)
    await db_session.flush()
    db_session.add(
        AlertEvent(
            rule_id=rule.id,
            subject_type="appliance",
            subject_id=str(held.id),
            subject_display=held.hostname,
            severity="warning",
            message="/var on it is 84% full.",
            fired_at=now - timedelta(hours=3),
        )
    )
    await db_session.flush()

    got = await _match(db_session, rule)
    assert set(got) == {str(held.id)}
    assert got[str(held.id)][2] == "warning"
    assert "not reported" in got[str(held.id)][1]


async def test_evaluate_all_opens_escalates_and_resolves(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule()
    db_session.add(rule)
    node = await _node(db_session, var=_pct_of(40 * GIB, 82))
    await _node(db_session, var=_pct_of(40 * GIB, 30))
    await db_session.commit()

    await alerts_svc.evaluate_all(db_session)
    events = await _open_events(db_session, rule)
    assert [(e.subject_type, e.subject_id, e.severity) for e in events] == [
        ("appliance", str(node.id), "warning")
    ]

    node.cluster_health = {"host_disk_partitions": _parts(_pct_of(40 * GIB, 92))}
    node.last_seen_at = datetime.now(UTC)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    events = await _open_events(db_session, rule)
    assert len(events) == 1 and events[0].severity == "critical"

    node.cluster_health = {"host_disk_partitions": _parts(_pct_of(40 * GIB, 40))}
    node.last_seen_at = datetime.now(UTC)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert await _open_events(db_session, rule) == []


async def test_seed_creates_one_enabled_rule_and_never_overrides_the_operator(
    db_session: AsyncSession,
) -> None:
    await alerts_svc.seed_appliance_disk_usage_alert_rule()
    await alerts_svc.seed_appliance_disk_usage_alert_rule()  # idempotent
    rules = (
        (
            await db_session.execute(
                select(AlertRule).where(AlertRule.rule_type == "appliance_disk_usage")
            )
        )
        .scalars()
        .all()
    )
    assert len(rules) == 1
    assert rules[0].enabled is True
    assert rules[0].threshold_percent == 80

    rules[0].enabled = False
    await db_session.commit()
    await alerts_svc.seed_appliance_disk_usage_alert_rule()
    await db_session.refresh(rules[0])
    assert rules[0].enabled is False
