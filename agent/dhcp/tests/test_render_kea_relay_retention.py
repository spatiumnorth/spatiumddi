"""#54 — Kea keeps each client's relay agent information when a class needs it.

A unicast renewal (every client's renewal at T1) goes straight to the server,
not through the relay, so it carries no option 82. A client that leased from
a pool restricted to an option-82 class then no longer matches that class.
Measured on kea-dhcp4 3.0.3 (rig: a relayed DORA with option 82, then a
unicast DHCPREQUEST without it):

    stash-agent-options  store-extended-info  unicast renewal
    off                  off                  DHCPNAK
    on                   off                  DHCPNAK
    off                  on                   DHCPNAK
    on                   on                   DHCPACK

So the control plane sends ``relay_info_retention`` in the ``server`` block
when the group has such a class, and the agent turns on both keys, in Dhcp4
only.

The golden config below is also what CI's ``kea-dhcp4 -t`` step loads into
the built Kea image (``build-dhcp-images.yml``, ``make kea-config-check``),
so a render change that Kea would reject fails a PR rather than an agent's
reload. Regenerate it after an intended render change with
``SPATIUM_UPDATE_GOLDEN=1 python -m pytest tests/test_render_kea_relay_retention.py``.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

from spatium_dhcp_agent.render_kea import render

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN_BUNDLE = FIXTURES / "kea_golden_bundle.json"
GOLDEN_DHCP4 = FIXTURES / "kea_golden_dhcp4.json"

KEYS = ("stash-agent-options", "store-extended-info")


def _bundle(**server: object) -> dict:
    bundle = json.loads(GOLDEN_BUNDLE.read_text())
    bundle.pop("failover")
    bundle["server"] = {"dhcp_socket_type": "udp", **server}
    return bundle


def _with_v6_scope(bundle: dict) -> dict:
    bundle = copy.deepcopy(bundle)
    bundle["scopes"].append(
        {
            "subnet_cidr": "2001:db8:54::/64",
            "address_family": "ipv6",
            "is_active": True,
            "lease_time": 3600,
            "options": {},
            "pools": [
                {"start_ip": "2001:db8:54::10", "end_ip": "2001:db8:54::20", "pool_type": "dynamic"}
            ],
            "statics": [],
        }
    )
    return bundle


def test_both_keys_render_in_dhcp4_when_the_bundle_asks() -> None:
    out = render(_bundle(relay_info_retention=True))
    assert {k: out["Dhcp4"].get(k) for k in KEYS} == dict.fromkeys(KEYS, True)


def test_neither_key_renders_without_the_flag() -> None:
    """Absent, not ``false``: both default to false in Kea, and a group with
    no option-82 class must render exactly as it did before #54."""
    for server in ({}, {"relay_info_retention": False}):
        out = render(_bundle(**server))
        assert not set(KEYS) & set(out["Dhcp4"]), server


def test_never_in_dhcp6() -> None:
    """``stash-agent-options`` is a Dhcp4 key; kea-dhcp6 rejects an unknown
    top-level key, which would revert the bundle for both daemons."""
    out = render(_with_v6_scope(_bundle(relay_info_retention=True)))
    assert out["Dhcp6"]["subnet6"], "the v6 scope should have rendered"
    assert not set(KEYS) & set(out["Dhcp6"])


def _golden_render() -> dict:
    """The Dhcp4 document the agent writes to ``kea-dhcp4.conf`` (sync.py
    splits the two daemons into separate files)."""
    return {"Dhcp4": render(json.loads(GOLDEN_BUNDLE.read_text()))["Dhcp4"]}


def test_golden_config_matches_the_renderer() -> None:
    """The checked-in golden is what the renderer produces today, so the
    ``kea-dhcp4 -t`` CI step is checking the current render, not a stale one."""
    rendered = _golden_render()
    if os.environ.get("SPATIUM_UPDATE_GOLDEN"):
        GOLDEN_DHCP4.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n")
    assert rendered == json.loads(GOLDEN_DHCP4.read_text()), (
        "render_kea output changed; if intended, regenerate the golden with "
        "SPATIUM_UPDATE_GOLDEN=1 (see this module's docstring)"
    )


def test_golden_config_exercises_retention_and_ha() -> None:
    """The golden is only worth loading into Kea if it carries the keys this
    issue added, a pool restricted to a relay4 class and the HA hook."""
    dhcp4 = json.loads(GOLDEN_DHCP4.read_text())["Dhcp4"]
    assert {k: dhcp4.get(k) for k in KEYS} == dict.fromkeys(KEYS, True)
    assert any("relay4[" in c.get("test", "") for c in dhcp4["client-classes"])
    restricted = [p for s in dhcp4["subnet4"] for p in s["pools"] if p.get("client-class")]
    assert restricted
    assert any(h["library"].endswith("libdhcp_ha.so") for h in dhcp4["hooks-libraries"])
