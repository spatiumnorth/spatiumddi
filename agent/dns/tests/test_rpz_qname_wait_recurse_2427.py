"""A blocked name must not wait for its own recursion (#2427).

BIND's ``qname-wait-recurse`` defaults to yes: the qname is resolved first
and a failed lookup is not rewritten, so a blocked name whose upstream is
dead answered SERVFAIL after ~10 s. Assert on the rendered named.conf, for
the global and the per-view ``response-policy`` forms, and (when a bind9
toolchain is present) that named-checkconf accepts it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver

_BL = {
    "rpz_zone_name": "spatium-blocklist.rpz.",
    "entries": [
        {"domain": "ads.example.test", "action": "block", "block_mode": "nxdomain"}
    ],
    "exceptions": [],
    "view_name": None,
}


def _render(tmp_path: Path, views: list[dict]) -> str:
    bundle = {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "views": views,
        "zones": [],
        "tsig_keys": [],
        "blocklists": [dict(_BL)],
    }
    Bind9Driver(state_dir=tmp_path).render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


_VIEW = {
    "id": "v1",
    "name": "internal",
    "match_clients": ["any"],
    "match_destinations": [],
    "recursion": True,
    "order": 0,
}


def _policies(conf: str) -> list[str]:
    return re.findall(r"response-policy \{[^}]*\}[^;]*;", conf)


def test_global_response_policy_does_not_wait_for_recursion(tmp_path: Path) -> None:
    conf = _render(tmp_path, [])
    pols = _policies(conf)
    assert len(pols) == 1
    assert "break-dnssec yes" in pols[0]
    assert "qname-wait-recurse no" in pols[0]


def test_per_view_response_policy_does_not_wait_for_recursion(tmp_path: Path) -> None:
    conf = _render(tmp_path, [_VIEW])
    pols = _policies(conf)
    assert len(pols) == 1
    assert "break-dnssec yes" in pols[0]
    assert "qname-wait-recurse no" in pols[0]


@pytest.mark.skipif(
    shutil.which("named-checkconf") is None, reason="no bind9 toolchain"
)
@pytest.mark.parametrize("views", [[], [_VIEW]])
def test_named_checkconf_accepts_it(tmp_path: Path, views: list[dict]) -> None:
    _render(tmp_path, views)
    r = subprocess.run(
        ["named-checkconf", str(tmp_path / "rendered.new" / "named.conf")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("views", [[], [_VIEW]])
def test_response_policy_servfails_until_zones_loaded_4064(
    tmp_path: Path, views: list[dict]
) -> None:
    """A big policy zone loads while named already answers, so a blocked name
    resolved for seconds after every start (#4064)."""
    pols = _policies(_render(tmp_path, views))
    assert len(pols) == 1
    assert "servfail-until-ready yes" in pols[0]


def test_no_blocklists_renders_no_response_policy_4064(tmp_path: Path) -> None:
    bundle = {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "views": [],
        "zones": [],
        "tsig_keys": [],
        "blocklists": [],
    }
    Bind9Driver(state_dir=tmp_path).render(bundle)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "response-policy" not in conf
    assert "servfail-until-ready" not in conf
