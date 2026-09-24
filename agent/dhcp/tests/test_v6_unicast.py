"""kea-dhcp6 unicast sockets on the host's global IPv6 addresses (#1140).

``"*"`` binds link-local and ff02::1:2 only, so a relay's Relay-Forward to
the server's global address found no socket. The agent now adds an
``"<iface>/<address>"`` entry per bindable global address it finds on the
host — detected live, because kea-dhcp6 refuses the WHOLE config when an
entry names an address the interface does not hold (measured on 3.0.3).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from spatium_dhcp_agent import sync as sync_mod
from spatium_dhcp_agent.cache import save_config
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.render_kea import render
from spatium_dhcp_agent.sync import SyncLoop
from spatium_dhcp_agent.v6_unicast import global_ipv6_addresses, parse_if_inet6

# Real ``/proc/net/if_inet6`` rows: address, ifindex, prefix len, scope,
# flags, name. Flags: 0x80 permanent, 0x01 temporary, 0x20 deprecated,
# 0x40 tentative, 0x08 dad-failed. Scope: 0x00 global, 0x20 link, 0x10 host.
_IF_INET6 = """\
00000000000000000000000000000001 01 80 10 80       lo
20010db8008700000000000000000040 02 40 00 80    ens18
fe80000000000000be2411fffe41b745 02 40 20 80    ens18
20010db8008700000000000000000099 02 40 00 01    ens18
20010db8008700000000000000000098 02 40 00 20    ens18
20010db8008700000000000000000097 02 40 00 40    ens18
20010db8008700000000000000000096 02 40 00 08    ens18
fd00000000000000000000000000000a 05 40 00 00     eth1
not-a-row
"""


def test_parse_keeps_only_stable_global_addresses_sorted() -> None:
    assert parse_if_inet6(_IF_INET6) == [
        ("ens18", "2001:db8:87::40"),
        ("eth1", "fd00::a"),
    ]


def test_a_missing_proc_file_means_no_addresses(tmp_path: Path) -> None:
    """IPv6 disabled in the kernel: fall back to the wildcard alone."""
    assert global_ipv6_addresses(tmp_path / "absent") == []


def _v6_bundle(**server: Any) -> dict[str, Any]:
    return {
        "server": {"interfaces": ["*"], **server},
        "scopes": [
            {
                "subnet_cidr": "2001:db8:83::/64",
                "lease_time": 3600,
                "address_family": "ipv6",
                "v6_address_mode": "stateful",
                "pools": [
                    {
                        "start_ip": "2001:db8:83::100",
                        "end_ip": "2001:db8:83::1ff",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
            }
        ],
    }


_UNICAST = [("ens18", "2001:db8:87::40")]


def test_v6_scopes_add_a_unicast_entry_beside_the_wildcard() -> None:
    out = render(_v6_bundle(), v6_unicast=_UNICAST)
    assert out["Dhcp6"]["interfaces-config"]["interfaces"] == [
        "*",
        "ens18/2001:db8:87::40",
    ]
    # Dhcp4 never sees a v6 entry — kea-dhcp4 would reject it.
    assert out["Dhcp4"]["interfaces-config"]["interfaces"] == ["*"]


def test_no_v6_scopes_binds_nothing_whatever_the_host_has() -> None:
    out = render({"server": {"interfaces": ["*"]}, "scopes": []}, v6_unicast=_UNICAST)
    assert out["Dhcp6"]["interfaces-config"]["interfaces"] == []


def test_an_explicit_interface_list_only_gains_its_own_addresses() -> None:
    """Adding ``eth1/…`` to a list that names only ``ens18`` would widen
    what Kea serves."""
    unicast = [("ens18", "2001:db8:87::40"), ("eth1", "fd00::a")]
    out = render(_v6_bundle(interfaces=["ens18"]), v6_unicast=unicast)
    assert out["Dhcp6"]["interfaces-config"]["interfaces"] == [
        "ens18",
        "ens18/2001:db8:87::40",
    ]


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []


def _v6_interfaces_written(cfg: AgentConfig) -> list[str]:
    doc = json.loads(Path(cfg.kea_config_path_v6).read_text())
    return doc["Dhcp6"]["interfaces-config"]["interfaces"]


def test_apply_renders_the_detected_addresses(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sync_mod, "global_ipv6_addresses", lambda: list(_UNICAST))
    loop = SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())
    loop._apply_bundle(_v6_bundle(), reload_kea=False)
    assert _v6_interfaces_written(agent_cfg) == ["*", "ens18/2001:db8:87::40"]


def test_an_address_change_re_renders_the_current_bundle(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bundle ETag cannot see host addresses, so nothing else would
    re-render — and a gone address fails kea-dhcp6's next config load."""
    addrs = list(_UNICAST)
    monkeypatch.setattr(sync_mod, "global_ipv6_addresses", lambda: list(addrs))
    loop = SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())
    applied: list[str] = []

    def _apply(bundle: dict[str, Any], etag: str) -> bool:
        applied.append(etag)
        loop._apply_bundle(bundle, reload_kea=False)
        return True

    monkeypatch.setattr(loop, "_apply_with_revert", _apply)
    bundle = _v6_bundle()
    save_config(agent_cfg.state_dir, bundle, "sha256:v6")
    loop._current_etag = "sha256:v6"
    loop._apply_bundle(bundle, reload_kea=False)

    loop._recheck_v6_unicast()
    assert applied == [], "unchanged addresses: no re-render"

    addrs[:] = [("ens18", "2001:db8:87::41")]
    loop._recheck_v6_unicast()
    assert applied == ["sha256:v6"]
    assert _v6_interfaces_written(agent_cfg) == ["*", "ens18/2001:db8:87::41"]

    addrs[:] = []
    loop._recheck_v6_unicast()
    assert applied == ["sha256:v6", "sha256:v6"], "an address going away re-renders too"
    assert _v6_interfaces_written(agent_cfg) == ["*"]


def test_without_v6_scopes_address_changes_are_ignored(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    addrs = list(_UNICAST)
    monkeypatch.setattr(sync_mod, "global_ipv6_addresses", lambda: list(addrs))
    loop = SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())
    monkeypatch.setattr(
        loop, "_apply_with_revert", lambda *_a: pytest.fail("must not re-render")
    )
    bundle: dict[str, Any] = {"server": {"interfaces": ["*"]}, "scopes": []}
    save_config(agent_cfg.state_dir, bundle, "sha256:v4only")
    loop._current_etag = "sha256:v4only"
    loop._apply_bundle(bundle, reload_kea=False)

    addrs[:] = []
    loop._recheck_v6_unicast()
