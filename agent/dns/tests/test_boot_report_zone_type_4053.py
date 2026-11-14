"""The startup zone-state report keeps each zone's type and the views (#4053).

``Bind9Driver.served_zone_serials`` reads a zone back from named only when it
is a primary of a group without views, or a secondary / stub zone (#3940);
forward zones and every primary of a group with views report the bundle's
serial. The startup
report stored only name + serial, so every zone looked like a primary of a
group without views and a transferred secondary was reported at the serial
named serves (which the control plane reads as drift against its own 0).
"""

from __future__ import annotations

from typing import Any

from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.sync import SyncLoop

SERVED = 2026111301


def _driver(agent_cfg: AgentConfig) -> Bind9Driver:
    drv = object.__new__(Bind9Driver)
    drv._served_soa = lambda zone: (None, 0, SERVED, False)  # type: ignore[method-assign]
    return drv


def _loop(agent_cfg: AgentConfig) -> SyncLoop:
    loop = object.__new__(SyncLoop)
    loop.driver = _driver(agent_cfg)
    loop._boot_report_attempts = 0
    return loop


def _report(loop: SyncLoop) -> dict[str, int]:
    assert loop._boot_report_bundle is not None
    return loop.driver.served_zone_serials(loop._boot_report_bundle)  # type: ignore[attr-defined]


def test_boot_report_keeps_each_zone_type(agent_cfg: AgentConfig) -> None:
    """A forward zone reports the bundle's serial; a secondary is read back
    from named (#3940), like a primary; a zone with no type is a primary."""
    loop = _loop(agent_cfg)
    bundle: dict[str, Any] = {
        "zones": [
            {"name": "p.example.", "serial": 5, "type": "primary"},
            {"name": "s.example.", "serial": 0, "type": "secondary"},
            {"name": "f.example.", "serial": 3, "type": "forward"},
            {"name": "legacy.example.", "serial": 7},  # no type: a primary
        ]
    }
    loop._arm_boot_report(bundle)
    out = _report(loop)
    assert out == {
        "p.example": SERVED,
        "s.example": SERVED,
        "f.example": 3,
        "legacy.example": SERVED,
    }


def test_boot_report_keeps_views(agent_cfg: AgentConfig) -> None:
    loop = _loop(agent_cfg)
    loop._arm_boot_report(
        {
            "views": [{"name": "internal", "match_clients": ["any"]}],
            "zones": [{"name": "p.example.", "serial": 5, "type": "primary"}],
        }
    )
    assert _report(loop) == {"p.example": 5}
