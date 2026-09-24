"""Every alert rule type the evaluator knows is one the API accepts.

``RULE_TYPES`` is the allow-list behind the ``POST /alerts/rules`` validator
and the conformity ``alert_rule_enabled`` check. A ``RULE_TYPE_*`` constant
left out of it is still seeded and still evaluated, so nothing looks wrong —
until an operator who deleted the seeded rule tries to recreate it and gets a
422, or a conformity policy naming it reports "not applicable".
``dhcp_packets_dropped`` (#980) and ``agent_daemon_degraded`` (#1067) were
both missing; this keeps the next one from joining them.
"""

from __future__ import annotations

from app.services import alerts


def test_every_rule_type_constant_is_registered() -> None:
    declared = {
        value
        for name, value in vars(alerts).items()
        if name.startswith("RULE_TYPE_") and isinstance(value, str)
    }
    assert declared, "no RULE_TYPE_* constants found — did the module move?"
    assert sorted(declared - alerts.RULE_TYPES) == []
