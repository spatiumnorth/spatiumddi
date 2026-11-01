"""#3232 / #3233 — what an open alert and its rule say about thresholds."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.services import alerts as alerts_svc

from .test_alert_appliance_disk_usage import GIB, _node, _pct_of
from .test_alert_resolve_hysteresis_2778 import _no_delivery, _subnet

pytestmark = pytest.mark.asyncio


async def _event(db: AsyncSession) -> AlertEvent:
    db.expire_all()
    return (
        await db.execute(select(AlertEvent).where(AlertEvent.resolved_at.is_(None)))
    ).scalar_one()


async def test_subnet_threshold_edit_is_not_shown_as_the_current_reading(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = AlertRule(
        name="u",
        rule_type=alerts_svc.RULE_TYPE_SUBNET_UTILIZATION,
        severity="warning",
        enabled=True,
        threshold_percent=68,
    )
    db_session.add(rule)
    subnet = await _subnet(db_session)
    subnet.utilization_percent = 71.4
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert "(threshold 68%)" in (await _event(db_session)).message

    for new in (73, 63):
        rule.threshold_percent = new
        await db_session.commit()
        await alerts_svc.evaluate_all(db_session)
        msg = (await _event(db_session)).message
        assert f"(threshold {new}%)" in msg and "71.4%" in msg
        assert "[now:" not in msg

    # A real reading change afterwards still shows only the reading.
    subnet.utilization_percent = 64.3
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    msg = (await _event(db_session)).message
    assert "[now: 64.3%" in msg and "(threshold 63%)" in msg
    assert "[now: 63" not in msg


async def test_var_threshold_edit_is_not_shown_as_the_current_reading(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = AlertRule(
        name="v",
        rule_type=alerts_svc.RULE_TYPE_APPLIANCE_DISK_USAGE,
        severity="warning",
        enabled=True,
        threshold_percent=0,
    )
    db_session.add(rule)
    await _node(db_session, var=_pct_of(40 * GIB, 27))
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    rule.threshold_percent = 26
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    msg = (await _event(db_session)).message
    assert "26% threshold" in msg and "[now:" not in msg


async def test_seeded_var_description_states_the_resolve_margin(
    db_session: AsyncSession,
) -> None:
    await alerts_svc.seed_appliance_disk_usage_alert_rule()
    rule = (
        await db_session.execute(
            select(AlertRule).where(AlertRule.rule_type == "appliance_disk_usage")
        )
    ).scalar_one()
    assert "5 points below the threshold" in rule.description
    assert "drops below" not in rule.description

    # A row still carrying the old seeded text is refreshed; an edited one is not.
    rule.description = alerts_svc._appliance_disk_description(legacy=True)
    await db_session.commit()
    await alerts_svc.seed_appliance_disk_usage_alert_rule()
    await db_session.refresh(rule)
    assert "5 points below" in rule.description
    rule.description = "mine"
    await db_session.commit()
    await alerts_svc.seed_appliance_disk_usage_alert_rule()
    await db_session.refresh(rule)
    assert rule.description == "mine"


# ── #3233 across the other templates that print their own threshold ─────────


async def _edit_and_eval(db: AsyncSession, rule: AlertRule, **knobs: int) -> str:
    for k, v in knobs.items():
        setattr(rule, k, v)
    await db.commit()
    await alerts_svc.evaluate_all(db)
    return (await _event(db)).message


def _rule(rule_type: str, **knobs: int) -> AlertRule:
    return AlertRule(name=rule_type, rule_type=rule_type, severity="warning", enabled=True, **knobs)


async def test_dhcp_pool_percent_and_floor_edits_are_restated(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .test_alert_resolve_hysteresis_2778 import _occupancy, _pool

    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    _occupancy(monkeypatch, {"assigned": 95})  # 95% used, 5 free
    rule = _rule(alerts_svc.RULE_TYPE_DHCP_POOL_EXHAUSTION, threshold_percent=90)
    rule.min_free_addresses = 10
    db_session.add(rule)
    await _pool(db_session)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert "(threshold 90%)" in (await _event(db_session)).message

    msg = await _edit_and_eval(db_session, rule, threshold_percent=93)
    assert "(threshold 93%)" in msg and "[now:" not in msg
    # min_free_addresses is printed as the floor: an edit to it is a threshold edit.
    msg = await _edit_and_eval(db_session, rule, min_free_addresses=20)
    assert "(floor 20)" in msg and "[now:" not in msg
    # Both knobs once held 10 → moving them apart still restates each.
    msg = await _edit_and_eval(db_session, rule, threshold_percent=91, min_free_addresses=30)
    assert "(threshold 91%)" in msg and "(floor 30)" in msg and "[now:" not in msg


async def test_voice_lease_count_threshold_edit_is_restated(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule(alerts_svc.RULE_TYPE_VOICE_LEASE_COUNT_BELOW, threshold_percent=5)
    db_session.add(rule)
    subnet = await _subnet(db_session)
    subnet.subnet_role = "voice"
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert "(threshold 5)" in (await _event(db_session)).message
    msg = await _edit_and_eval(db_session, rule, threshold_percent=7)
    assert "(threshold 7)" in msg and "[now:" not in msg


async def test_stale_ip_count_and_days_edits_are_restated(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.ipam import stale_ips

    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule(alerts_svc.RULE_TYPE_STALE_IP_COUNT, threshold_percent=3, threshold_days=30)
    db_session.add(rule)
    subnet = await _subnet(db_session)
    await db_session.commit()

    async def fake(db, *, stale_days, include_never_seen):  # type: ignore[no-untyped-def]
        return {subnet.id: 8}

    monkeypatch.setattr(stale_ips, "count_stale_per_subnet", fake)
    await alerts_svc.evaluate_all(db_session)
    msg = await _edit_and_eval(db_session, rule, threshold_percent=4, threshold_days=45)
    assert "has 8 stale" in msg and "45+ days (threshold 4)" in msg and "[now:" not in msg


async def test_nxdomain_ratio_and_floor_edits_are_restated(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .test_alert_dns_query_anomaly import _make_dns_server, _sample

    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    server = await _make_dns_server(db_session)
    await _sample(db_session, server.id, minutes_ago=1, queries=100, nxdomain=60)
    rule = _rule(alerts_svc.RULE_TYPE_DNS_NXDOMAIN_SPIKE, threshold_percent=30)
    rule.min_free_addresses = 10
    db_session.add(rule)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    msg = await _edit_and_eval(db_session, rule, threshold_percent=40, min_free_addresses=20)
    assert "(threshold 40% / floor 20)" in msg and "[now:" not in msg


async def test_decom_threshold_days_edit_is_restated(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .test_alert_decom_expiring import _make_subnet

    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule(alerts_svc.RULE_TYPE_DECOM_EXPIRING, threshold_days=30)
    db_session.add(rule)
    await _make_subnet(db_session, network="10.7.0.0/24", decom_days=20)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert "threshold 30 d)" in (await _event(db_session)).message
    msg = await _edit_and_eval(db_session, rule, threshold_days=40)
    assert "threshold 40 d)" in msg and "[now:" not in msg


async def test_node_pressure_threshold_edit_is_restated(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.config import settings

    from .test_node_pressure_alert import _psi, _snap

    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    monkeypatch.setattr(settings, "appliance_mode", True, raising=False)
    snap = _snap(psi_cpu=_psi(some=60.0))
    monkeypatch.setattr("app.services.appliance.cluster_health.get_cluster_health", lambda: snap)
    rule = _rule(alerts_svc.RULE_TYPE_NODE_PRESSURE, threshold_percent=50)
    db_session.add(rule)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    msg = await _edit_and_eval(db_session, rule, threshold_percent=55)
    assert "60.0% of the last 5 min (threshold 55%)" in msg and "[now:" not in msg


async def test_edit_twice_and_an_escalation_in_between(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .test_alert_decom_expiring import _make_subnet

    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule(alerts_svc.RULE_TYPE_DECOM_EXPIRING, threshold_days=30)
    rule.severity = "info"
    db_session.add(rule)
    await _make_subnet(db_session, network="10.7.0.0/24", decom_days=20)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert (await _event(db_session)).severity == "info"
    # 20 d is under 120/4 = 30: the edit escalates, the peak is replaced.
    msg = await _edit_and_eval(db_session, rule, threshold_days=120)
    ev = await _event(db_session)
    assert ev.severity == "warning" and "threshold 120 d)" in msg and "[now:" not in msg
    # Two edits between evaluations are restated from the stored threshold.
    rule.threshold_days = 150
    await db_session.commit()
    msg = await _edit_and_eval(db_session, rule, threshold_days=160)
    assert "threshold 160 d)" in msg and "[now:" not in msg


async def test_event_opened_before_the_change_still_composes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An open event with no ``peak_message`` (written before #3233)."""
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule(alerts_svc.RULE_TYPE_SUBNET_UTILIZATION, threshold_percent=68)
    db_session.add(rule)
    subnet = await _subnet(db_session)
    subnet.utilization_percent = 71.4
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    ev = await _event(db_session)
    ev.last_observed_value = None
    await db_session.commit()
    subnet.utilization_percent = 72.0
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    ev = await _event(db_session)
    assert ev.message.endswith("[now: 72.0% / 10/14]") or "[now: 72.0%" in ev.message
    assert "71.4% (threshold 68%)" in ev.last_observed_value["peak_message"]
    # From here on a threshold edit is restated.
    msg = await _edit_and_eval(db_session, rule, threshold_percent=70)
    assert "(threshold 70%)" in msg and "[now: 70" not in msg


async def test_a_reading_equal_to_the_old_threshold_is_not_rewritten() -> None:
    restate = alerts_svc._restate_edited_thresholds
    unmark = alerts_svc._unmark_thresholds
    token = alerts_svc._MARK_THRESHOLDS.set(True)
    try:
        thr = alerts_svc._thr
        peak = "Subnet x utilisation 68.0% (threshold 68%) — 10/14 IPs allocated"
        # Reading unchanged at 68.0 while the threshold moves 68 → 70: only the
        # threshold position changes.
        cur, idx = unmark(
            f"Subnet x utilisation 68.0% (threshold {thr(70)}%) — 10/14 IPs allocated"
        )
        assert restate(peak, cur, idx) == cur
        # A count reading equal to the old threshold stays where the reading did not move.
        peak = "Voice subnet x has 5 active lease(s) (threshold 5) — y"
        cur, idx = unmark(f"Voice subnet x has 5 active lease(s) (threshold {thr(7)}) — y")
        assert restate(peak, cur, idx) == cur
        # Different templates (a skeleton change) are left to the composer.
        other, idx = unmark(f"other {thr(7)}")
        assert restate(peak, other, idx) == peak
    finally:
        alerts_svc._MARK_THRESHOLDS.reset(token)
    # Outside an evaluation pass a matcher's text carries no marks.
    assert alerts_svc._thr(70) == "70"


async def test_a_reading_that_moves_with_its_threshold_is_kept(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review thread 1: count and threshold both 3 → 4; the reading is not restated."""
    from app.services.ipam import stale_ips

    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule(alerts_svc.RULE_TYPE_STALE_IP_COUNT, threshold_percent=3, threshold_days=30)
    db_session.add(rule)
    subnet = await _subnet(db_session)
    await db_session.commit()
    network = str(subnet.network)
    count = {"n": 3}

    async def fake(db, *, stale_days, include_never_seen):  # type: ignore[no-untyped-def]
        return {subnet.id: count["n"]}

    monkeypatch.setattr(stale_ips, "count_stale_per_subnet", fake)
    await alerts_svc.evaluate_all(db_session)
    count["n"] = 4
    msg = await _edit_and_eval(db_session, rule, threshold_percent=4)
    assert msg.startswith(f"Subnet {network}") and "has 3 stale" in msg
    assert "(threshold 4)" in msg and msg.endswith("[now: 4]")
    assert "\ue000" not in msg and "\ue001" not in msg


async def test_var_threshold_edit_across_the_resolve_margin(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review thread 2: 27% at threshold 0%, edited to 29% (margin template),
    then to 26% — the peak ends on 26% with no ``[now: 26%]``."""
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = _rule(alerts_svc.RULE_TYPE_APPLIANCE_DISK_USAGE, threshold_percent=0)
    db_session.add(rule)
    await _node(db_session, var=_pct_of(40 * GIB, 27))
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    msg = await _edit_and_eval(db_session, rule, threshold_percent=29)
    assert "the rule's 0% threshold" in msg and "[now:" in msg  # different template
    msg = await _edit_and_eval(db_session, rule, threshold_percent=26)
    assert "the rule's 26% threshold" in msg and "[now:" not in msg
    # And it stays that way on the next pass.
    await alerts_svc.evaluate_all(db_session)
    assert "[now:" not in (await _event(db_session)).message


async def test_legacy_var_description_is_the_text_main_seeded() -> None:
    """The refresh only fires on an exact match, so the legacy text must be it."""
    assert alerts_svc._appliance_disk_description(legacy=True) == (
        "Fires when an appliance's /var data partition (Postgres, "
        "container images, logs) fills. Warning at the threshold "
        "(80% by default); critical at "
        "87% used whatever the threshold, a "
        "few points before the kubelet's eviction line: from about 90% "
        "used the kubelet is down to its last 5% of free space (ext4 "
        "keeps another 5% for root) and evicts pods, the control "
        "plane's among them. Silent on supervisors that do not report "
        "/var; a reading that stops arriving holds an open alert rather "
        "than resolving it. Auto-resolves when usage drops below the "
        "threshold."
    )
