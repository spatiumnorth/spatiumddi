"""#2263 — two client access controls that were stored and enforced nothing.

* A zone's own ``allow_query`` was shipped in the bundle and ignored by the
  Technitium agent, which applied only the group's list: a zone restricted
  to internal clients stayed open on a Technitium group.
* The group ``blackhole`` list was accepted and validated but never shipped
  or rendered, so a blackholed client kept getting answers from BIND9.

Asserted on what reaches the daemon — the ``zones/options/set`` calls and
the rendered ``named.conf`` — per the #899 lesson.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.drivers.technitium import TechnitiumDriver

from .test_technitium_render import _install_fake_request, _seed_token

# ── Technitium: the zone's own allow_query ──────────────────────────────


def _tzone(name: str, ztype: str = "primary", **over: Any) -> dict[str, Any]:
    z: dict[str, Any] = {"name": name, "type": ztype, "records": []}
    if ztype in ("secondary", "stub"):
        z["masters"] = ["192.0.2.1"]
    if ztype == "forward":
        z["forwarders"] = ["192.0.2.53"]
    z.update(over)
    return z


def _apply(tmp_path: Path, bundle: dict[str, Any]) -> tuple[TechnitiumDriver, list[Any]]:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    d.daemon_running = lambda: True  # type: ignore[method-assign]
    d._wait_for_api_up = lambda **_: None  # type: ignore[method-assign]
    calls = _install_fake_request(d, lambda *_: {"status": "ok", "response": {"records": []}})
    d.render(bundle)
    d.validate()
    d.swap_and_reload()
    return d, calls


def _final_query_access(calls: list[Any]) -> dict[str, tuple[str, str]]:
    """The last ``queryAccess`` each zone was given (a created Primary is
    held at ``Deny`` first, #1758; the release is what stays)."""
    out: dict[str, tuple[str, str]] = {}
    for c in calls:
        if c[2] == "zones/options/set" and "queryAccess" in c[3]:
            out[c[3]["zone"]] = (c[3]["queryAccess"], c[3].get("queryAccessNetworkACL") or "")
    return out


@pytest.mark.parametrize("ztype", ["primary", "secondary", "stub"])
def test_zone_allow_query_overrides_the_group_list(tmp_path: Path, ztype: str) -> None:
    _, calls = _apply(
        tmp_path,
        {
            "zones": [
                _tzone("internal.test", ztype, allow_query=["10.0.0.0/8", "!10.9.0.0/16"]),
                _tzone("open.test", ztype),
            ],
            "options": {"allow_query": ["any"]},
        },
    )
    sent = _final_query_access(calls)
    assert sent["internal.test"] == ("UseSpecifiedNetworkACL", "10.0.0.0/8,!10.9.0.0/16")
    # A zone with no override keeps the group's list.
    assert sent["open.test"] == ("Allow", "")


def test_zone_allow_query_narrows_a_restricted_group(tmp_path: Path) -> None:
    _, calls = _apply(
        tmp_path,
        {
            "zones": [_tzone("a.test", allow_query=["none"])],
            "options": {"allow_query": ["10.0.0.0/8"]},
        },
    )
    assert _final_query_access(calls)["a.test"] == ("Deny", "")


@pytest.mark.parametrize("own", [None, [], [" "]])
def test_unset_or_empty_zone_allow_query_inherits_the_group(tmp_path: Path, own: Any) -> None:
    """``[]`` renders no zone clause in BIND, so the zone inherits; reading
    it as ``Allow`` would open a zone the group restricts."""
    _, calls = _apply(
        tmp_path,
        {
            "zones": [_tzone("a.test", allow_query=own)],
            "options": {"allow_query": ["10.0.0.0/8"]},
        },
    )
    assert _final_query_access(calls)["a.test"] == ("UseSpecifiedNetworkACL", "10.0.0.0/8")


def test_forward_zone_keeps_the_group_list(tmp_path: Path) -> None:
    """BIND has no zone-level allow-query on a forward zone, and the BIND9
    agent renders none there, so the two drivers agree on the group's."""
    _, calls = _apply(
        tmp_path,
        {
            "zones": [_tzone("fwd.test", "forward", allow_query=["192.0.2.0/24"])],
            "options": {"allow_query": ["10.0.0.0/8"]},
        },
    )
    assert _final_query_access(calls)["fwd.test"] == ("UseSpecifiedNetworkACL", "10.0.0.0/8")


def test_untranslatable_zone_allow_query_never_falls_back_to_the_group(
    tmp_path: Path,
) -> None:
    """A zone list Technitium cannot express leaves the zone alone and says
    so. Applying the group's (wider) list instead would silently widen it."""
    d, calls = _apply(
        tmp_path,
        {
            "zones": [_tzone("a.test", "secondary", allow_query=["localnets"])],
            "options": {"allow_query": ["any"]},
        },
    )
    assert "a.test" not in _final_query_access(calls)
    refused = [r for r in d._refused_zones if "zone's own list" in r]
    assert len(refused) == 1, d._refused_zones
    assert "1 zone(s)" in refused[0]


def test_new_primary_with_untranslatable_zone_list_is_released_to_the_group_list(
    tmp_path: Path,
) -> None:
    """A Primary this pass creates is held at ``Deny`` and then released
    (#1758). With its own list inexpressible, the release must not fall back
    to ``Allow`` — wider than the group's list, which the zone would have
    got without the override (a zone moved in, or a row stored before the
    gate)."""
    d, calls = _apply(
        tmp_path,
        {
            "zones": [_tzone("a.test", allow_query=["localnets"])],
            "options": {"allow_query": ["10.0.0.0/8"]},
        },
    )
    assert _final_query_access(calls)["a.test"] == ("UseSpecifiedNetworkACL", "10.0.0.0/8")
    assert not any(
        c[2] == "zones/options/set" and "_release_query_access" in c[3] for c in calls
    )
    assert [r for r in d._refused_zones if "zone's own list" in r]


# ── BIND9: the group blackhole ──────────────────────────────────────────


def _bundle(**opts: Any) -> dict[str, Any]:
    return {
        "options": {
            "forwarders": [],
            "recursion_enabled": False,
            "allow_query": ["any"],
            "dnssec_validation": "auto",
            "allow_transfer": ["none"],
            **opts,
        },
        "tsig_keys": [],
        "zones": [],
    }


def _named_conf(tmp_path: Path, bundle: dict[str, Any]) -> str:
    Bind9Driver(state_dir=tmp_path).render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def test_blackhole_renders_in_the_options_block(tmp_path: Path) -> None:
    conf = _named_conf(
        tmp_path, _bundle(blackhole=["198.51.100.0/24", "!192.0.2.7", "2001:db8::/32"])
    )
    options = conf.split("options {", 1)[1].split("\n};", 1)[0]
    assert "    blackhole { 198.51.100.0/24; !192.0.2.7; 2001:db8::/32; };\n" in options


@pytest.mark.parametrize("value", [None, [], [" "]])
def test_no_blackhole_keeps_named_conf_byte_identical(tmp_path: Path, value: Any) -> None:
    """A group that does not use it renders exactly what it did before."""
    without = _named_conf(tmp_path / "a", _bundle())
    with_empty = _named_conf(tmp_path / "b", _bundle(blackhole=value))
    assert with_empty.replace(str(tmp_path / "b"), "X") == without.replace(str(tmp_path / "a"), "X")
    assert "blackhole" not in with_empty


def test_blackhole_drops_an_entry_that_would_break_the_statement(tmp_path: Path) -> None:
    conf = _named_conf(tmp_path, _bundle(blackhole=["192.0.2.1; }; controls { };", "203.0.113.9"]))
    assert "    blackhole { 203.0.113.9; };\n" in conf
    assert "controls { };" not in conf.split("options {", 1)[1].split("\n};", 1)[0]
