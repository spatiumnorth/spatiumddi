"""Serving pods must stay within their memory request (#1828).

The kubelet's memory-eviction ranking looks at "is usage over the memory
REQUEST" BEFORE priority, so a ``spatium-service`` pod running above its
request is evicted ahead of every pod within its own request, whatever the
PriorityClasses say.  The chart carried 64Mi on pods whose idle working set
is 66-85 Mi, which inverted the documented order (DNS/DHCP last).

HOW TO RUN: python3 -m pytest appliance/tests/test_chart_serving_memory_requests.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

VALUES = Path(__file__).resolve().parent.parent.parent / "charts" / "spatiumddi-appliance" / "values.yaml"

# Highest measured idle working set of any serving pod (BIND 85 Mi, #1828) is
# the floor a request must clear; 128Mi is the smallest round value above it.
MIN_MI = 128


def _mi(q: str) -> float:
    for suffix, mult in (("Gi", 1024), ("Mi", 1), ("Ki", 1 / 1024)):
        if q.endswith(suffix):
            return float(q[: -len(suffix)]) * mult
    raise AssertionError(f"unhandled quantity {q!r}")


def _serving_roles() -> dict[str, dict]:
    values = yaml.safe_load(VALUES.read_text(encoding="utf-8"))
    return {
        k: v
        for k, v in values.items()
        if isinstance(v, dict) and v.get("priorityClassName") == "spatium-service"
    }


def test_the_serving_roles_were_found() -> None:
    # Negative control: a filter that matches nothing would pass every case
    # below vacuously.
    assert set(_serving_roles()) >= {
        "dnsBind9",
        "dnsPowerdns",
        "dnsTechnitium",
        "dhcpKea",
        "lookingGlass",
    }


@pytest.mark.parametrize("role", sorted(_serving_roles()))
def test_serving_memory_request_clears_the_idle_working_set(role: str) -> None:
    cfg = _serving_roles()[role]
    # #2223: a role whose memory the supervisor sizes per node keeps its
    # floor under ``memory.request``; the template layers it under any
    # explicit ``resources.requests.memory``, so the effective request is
    # the explicit one when present, else that floor.
    req = (cfg.get("resources", {}).get("requests", {}) or {}).get("memory") or (
        cfg.get("memory", {}) or {}
    ).get("request")
    assert req, f"{role} has no memory request in resources or memory (#1828)"
    assert _mi(req) >= MIN_MI, (
        f"{role} requests {req}: a spatium-service pod over its memory request is "
        "evicted ahead of the control plane (#1828)"
    )
