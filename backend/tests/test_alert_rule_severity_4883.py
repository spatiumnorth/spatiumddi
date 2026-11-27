"""The rule's Severity is the floor of every rule type's events (#4883).

Twelve matchers hand back a severity of their own with each match, and
``evaluate_all`` used to open and escalate at ``override or rule.severity``,
so the matcher's level always won: a rule set to Critical opened a warning.
"""

from __future__ import annotations

import inspect
import re

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.services import alerts as alerts_svc

# rule type -> (matcher attribute, evaluate_all subject_type is irrelevant here)
_MATCHER_RULE_TYPES = {
    "appliance_disk_usage": "_matching_appliance_disk_usage_subjects",
    "node_pressure": "_matching_node_pressure_subjects",
    "cluster_dns_degraded": "_matching_cluster_dns_subjects",
    "agent_spool_trimmed": "_matching_agent_spool_trimmed_subjects",
    "dns_memory_pressure": "_matching_dns_memory_pressure_subjects",
    "dnssec_multi_signer": "_matching_dnssec_multi_signer_subjects",
    "dhcp_scope_uncoordinated": "_matching_dhcp_scope_uncoordinated_subjects",
    "dns_blocklist_feed_stale": "_matching_dns_blocklist_feed_stale_subjects",
    "dns_pool_health_stale": "_matching_dns_pool_health_stale_subjects",
    "agent_bundle_render_failed": "_matching_agent_bundle_render_failed_subjects",
    "appliance_heartbeat_stale": "_matching_appliance_heartbeat_stale_subjects",
    "postgres_instance_unhealthy": "_matching_postgres_instance_subjects",
}


def test_every_matcher_type_is_a_registered_rule_type() -> None:
    assert set(_MATCHER_RULE_TYPES) <= alerts_svc.RULE_TYPES


@pytest.mark.parametrize(
    ("rule_sev", "override", "expected"),
    [
        ("critical", "warning", "critical"),
        ("critical", "info", "critical"),
        ("info", "warning", "warning"),
        ("warning", "critical", "critical"),
        ("info", None, "info"),
        ("critical", None, "critical"),
    ],
)
def test_event_severity_floor(rule_sev: str, override: str | None, expected: str) -> None:
    assert alerts_svc._event_severity(rule_sev, override) == expected  # noqa: SLF001


def test_evaluate_all_never_picks_the_event_severity_by_hand() -> None:
    """A new type that goes around ``_event_severity`` fails here."""
    src = inspect.getsource(alerts_svc.evaluate_all)
    assert not re.search(r"\bor rule\.severity\b", src)
    assert src.count("_event_severity(") >= 2


@pytest.mark.parametrize("rule_type", sorted(_MATCHER_RULE_TYPES))
async def test_rule_severity_is_the_floor_for_matcher_levelled_types(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, rule_type: str
) -> None:
    async def fake(*_a, **_k):  # type: ignore[no-untyped-def]
        return [("subj-1", "Subject", "something is wrong", "warning")]

    monkeypatch.setattr(alerts_svc, _MATCHER_RULE_TYPES[rule_type], fake)
    monkeypatch.setattr(alerts_svc, "_RULE_TYPE_MODULE", {})

    async def no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]
        return (False, False, False)

    monkeypatch.setattr(alerts_svc, "_deliver_or_defer", no_delivery)

    rule = AlertRule(
        name=f"sev {rule_type}", rule_type=rule_type, severity="critical", enabled=True
    )
    db_session.add(rule)
    await db_session.commit()

    await alerts_svc.evaluate_all(db_session)
    events = (
        (await db_session.execute(select(AlertEvent).where(AlertEvent.rule_id == rule.id)))
        .scalars()
        .all()
    )
    assert [e.severity for e in events] == ["critical"]
