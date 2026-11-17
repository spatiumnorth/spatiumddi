"""A blocklist must not override the group's DNSSEC validation (#3563).

The renderer used to force ``dnssec-validation no`` whenever the bundle
carried any blocklist, so attaching one silently turned validation off for
every name the group resolves while Settings still showed it on.
``break-dnssec yes`` on the response-policy is what lets RPZ rewrite signed
names; tests/live_rpz_dnssec_check.py proves that against a real named.
Assert on the rendered named.conf, for the global and per-view forms.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver

_BL = {
    "rpz_zone_name": "spatium-blocklist.rpz.",
    "entries": [{"domain": "ads.example.com", "action": "block", "block_mode": "nxdomain"}],
    "exceptions": [],
    "view_name": None,
}

_VIEW = {
    "id": "v1",
    "name": "internal",
    "match_clients": ["any"],
    "match_destinations": [],
    "recursion": True,
    "order": 0,
}


def _render(tmp_path: Path, validation: str, views: list[dict], blocklists: bool) -> str:
    bundle = {
        "options": {
            "recursion_enabled": True,
            "allow_query": ["any"],
            "dnssec_validation": validation,
        },
        "views": views,
        "zones": [],
        "tsig_keys": [],
        "blocklists": [dict(_BL)] if blocklists else [],
    }
    Bind9Driver(state_dir=tmp_path).render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


@pytest.mark.parametrize("validation", ["auto", "yes", "no"])
@pytest.mark.parametrize("views", [[], [_VIEW]], ids=["global", "per-view"])
def test_blocklist_keeps_configured_dnssec_validation(
    tmp_path: Path, validation: str, views: list[dict]
) -> None:
    conf = _render(tmp_path, validation, views, blocklists=True)
    # The blocklist really is applied, so this is the case that used to flip.
    assert "break-dnssec yes" in conf
    assert re.findall(r"dnssec-validation (\w+);", conf) == [validation]


def test_blocklist_render_matches_unfiltered_validation(tmp_path: Path) -> None:
    with_bl = _render(tmp_path / "a", "auto", [], blocklists=True)
    without = _render(tmp_path / "b", "auto", [], blocklists=False)
    pick = re.compile(r"dnssec-validation \w+;")
    assert pick.findall(with_bl) == pick.findall(without) == ["dnssec-validation auto;"]
