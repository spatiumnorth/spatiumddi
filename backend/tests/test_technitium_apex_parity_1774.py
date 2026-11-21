"""The agentless apex translation answers as the agent's does (#1774).

``app/services/technitium/apex.py`` is ``zone_apex`` from
``agent/dns/spatium_dns_agent/drivers/technitium.py``, which cannot be shared
because the agent ships as its own package. The same zone must give the same
NS set and SOA on both, or a zone moved between the two drivers is rewritten.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from app.services.technitium.apex import zone_apex

_AGENT = Path(__file__).parents[2] / "agent/dns/spatium_dns_agent/drivers/technitium.py"


def _agent_zone_apex() -> Any:
    spec = importlib.util.spec_from_file_location("_agent_technitium_apex_parity", _AGENT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ImportError as exc:  # the agent's own dependencies are not installed here
        pytest.skip(f"agent module not importable: {exc}")
    return module._zone_apex


_ZONES = [
    {},
    {"ttl": 3600, "refresh": 7200},
    {"primary_ns": "ns1.example.com.", "admin_email": "hostmaster.example.com."},
    {
        "primary_ns": "ns1",
        "admin_email": "ops@example.com",
        "refresh": 1,
        "minimum": 60,
        "ttl": 300,
    },
    {
        "primary_ns": "ns1.example.com",
        "ttl": 3600,
        "records": [
            {"type": "NS", "name": "@", "value": "ns2.example.com.", "ttl": 600},
            {"type": "NS", "name": "example.com.", "value": "ns3", "ttl": None},
            {"type": "NS", "name": "kid", "value": "ns.kid.example.com."},
            {"type": "A", "name": "@", "value": "10.0.0.1"},
        ],
    },
    {"records": [{"type": "NS", "name": "@", "value": "@"}], "admin_email": "a\\.b.example.com."},
]


@pytest.mark.skipif(not _AGENT.exists(), reason="agent package not in this checkout")
@pytest.mark.parametrize("zone", _ZONES)
def test_the_same_zone_gives_the_same_apex(zone: dict[str, Any]) -> None:
    assert zone_apex("example.com", zone) == _agent_zone_apex()("example.com", zone)
