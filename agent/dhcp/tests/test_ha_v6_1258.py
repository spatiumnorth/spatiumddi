"""DHCPv6 high availability (#1258).

kea-dhcp4 and kea-dhcp6 are separate processes, each with its own HA hook, its
own HTTP listener and its own state machine. These tests assert on the
rendered Dhcp6 document and on what the status poller reports upstream.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from spatium_dhcp_agent import ha_status
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.ha_status import HAStatusPoller
from spatium_dhcp_agent.ha_tls import AGENT_CAPABILITIES
from spatium_dhcp_agent.kea_ctrl import KeaCtrlError
from spatium_dhcp_agent.render_kea import render

V6_SCOPE = {
    "address_family": "ipv6",
    "subnet_cidr": "2001:db8:1::/64",
    "v6_address_mode": "stateful",
    "pools": [
        {"pool_type": "dynamic", "start_ip": "2001:db8:1::100", "end_ip": "2001:db8:1::1ff"}
    ],
}
V4_SCOPE = {
    "address_family": "ipv4",
    "subnet_cidr": "10.0.0.0/24",
    "pools": [{"pool_type": "dynamic", "start_ip": "10.0.0.100", "end_ip": "10.0.0.200"}],
}


def _bundle(*, scopes: list[dict[str, Any]], v6_urls: bool = True, tls: bool = False) -> dict:
    peers = [
        {"name": "a", "url": "http://10.0.0.1:8000/", "role": "primary"},
        {"name": "b", "url": "http://10.0.0.2:8000/", "role": "standby"},
    ]
    if v6_urls:
        peers[0]["url_v6"] = "http://10.0.0.1:8001/"
        peers[1]["url_v6"] = "http://10.0.0.2:8001/"
    failover: dict[str, Any] = {
        "channel_id": "g",
        "channel_name": "g",
        "this_server_name": "a",
        "mode": "hot-standby",
        "peers": peers,
    }
    if tls:
        failover["tls"] = {"ca_pem": "ca", "cert_pem": "cert", "key_pem": "key"}
    return {
        "server": {"name": "a", "interfaces": ["eth0"]},
        "global_options": {},
        "scopes": scopes,
        "failover": failover,
    }


def _ha_hooks(daemon: dict[str, Any]) -> list[dict[str, Any]]:
    return [h for h in daemon["hooks-libraries"] if h["library"].endswith("libdhcp_ha.so")]


def _libs(daemon: dict[str, Any]) -> list[str]:
    return [h["library"].rsplit("/", 1)[-1] for h in daemon["hooks-libraries"]]


def test_dhcp6_gets_the_ha_hook_on_its_own_listener_port():
    out = render(_bundle(scopes=[V4_SCOPE, V6_SCOPE]))
    (hook4,) = _ha_hooks(out["Dhcp4"])
    (hook6,) = _ha_hooks(out["Dhcp6"])
    rel4 = hook4["parameters"]["high-availability"][0]
    rel6 = hook6["parameters"]["high-availability"][0]
    assert [p["url"] for p in rel4["peers"]] == ["http://10.0.0.1:8000/", "http://10.0.0.2:8000/"]
    assert [p["url"] for p in rel6["peers"]] == ["http://10.0.0.1:8001/", "http://10.0.0.2:8001/"]
    # One relationship, two daemons: same identity, mode and roles.
    for key in ("this-server-name", "mode", "heartbeat-delay"):
        assert rel6[key] == rel4[key]
    assert [p["role"] for p in rel6["peers"]] == ["primary", "standby"]
    # Kea rejects the HA hook without lease_cmds loaded before it.
    assert _libs(out["Dhcp6"]) == ["libdhcp_lease_cmds.so", "libdhcp_ha.so"]


def test_no_v6_ha_without_v6_scopes():
    out = render(_bundle(scopes=[V4_SCOPE]))
    assert len(_ha_hooks(out["Dhcp4"])) == 1
    assert _ha_hooks(out["Dhcp6"]) == []
    assert _libs(out["Dhcp6"]) == ["libdhcp_lease_cmds.so"]


def test_no_v6_ha_when_the_control_plane_sent_no_v6_urls():
    """An older control plane, or a member whose agent predates this."""
    out = render(_bundle(scopes=[V4_SCOPE, V6_SCOPE], v6_urls=False))
    assert len(_ha_hooks(out["Dhcp4"])) == 1
    assert _ha_hooks(out["Dhcp6"]) == []


def test_one_peer_without_a_v6_url_keeps_v6_ha_off():
    b = _bundle(scopes=[V6_SCOPE])
    del b["failover"]["peers"][1]["url_v6"]
    assert _ha_hooks(render(b)["Dhcp6"]) == []


def test_standalone_renders_no_ha_in_either_daemon():
    b = _bundle(scopes=[V4_SCOPE, V6_SCOPE])
    b["failover"] = None
    out = render(b)
    assert _ha_hooks(out["Dhcp4"]) == [] and _ha_hooks(out["Dhcp6"]) == []


def test_v6_listener_follows_the_group_credential():
    out = render(_bundle(scopes=[V6_SCOPE], tls=True), ha_tls_dir="/state/ha-tls")
    rel = _ha_hooks(out["Dhcp6"])[0]["parameters"]["high-availability"][0]
    assert rel["require-client-certs"] is True
    assert rel["trust-anchor"] == "/state/ha-tls/ca.pem"
    assert [p["url"] for p in rel["peers"]] == ["https://10.0.0.1:8001/", "https://10.0.0.2:8001/"]


def test_agent_advertises_the_capability():
    assert "ha_v6" in AGENT_CAPABILITIES


# ── status poller ────────────────────────────────────────────────────────────


def _status(state: str) -> dict[str, Any]:
    return {
        "arguments": {
            "high-availability": [{"ha-servers": {"local": {"role": "primary", "state": state}}}]
        }
    }


@pytest.fixture
def poller(agent_cfg: AgentConfig) -> HAStatusPoller:
    return HAStatusPoller(agent_cfg, ["tok"])


def test_poller_reads_each_daemons_own_socket(
    poller: HAStatusPoller, agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
):
    asked: list[Path] = []
    answers = {
        agent_cfg.kea_control_socket: _status("hot-standby"),
        agent_cfg.kea_control_socket_v6: _status("partner-down"),
    }

    def fake_send(sock: Path, command: str, *a: Any, **k: Any) -> dict[str, Any]:
        asked.append(sock)
        return answers[sock]

    monkeypatch.setattr(ha_status, "send_command", fake_send)
    assert poller._poll_kea()[0] == "hot-standby"
    assert poller._poll_kea(agent_cfg.kea_control_socket_v6)[0] == "partner-down"
    assert asked == [agent_cfg.kea_control_socket, agent_cfg.kea_control_socket_v6]


def _run_once(poller: HAStatusPoller, monkeypatch: pytest.MonkeyPatch, polls: dict) -> list[dict]:
    posted: list[dict[str, Any]] = []
    monkeypatch.setattr(
        poller,
        "_poll_kea",
        lambda sock=None: polls["v6" if sock is not None else "v4"],
    )
    monkeypatch.setattr(poller, "_report", lambda *a: posted.append(a))
    poller.set_enabled(True)
    # run() loops until stopped: stop it from inside the first wait.
    monkeypatch.setattr(poller._stop, "wait", lambda timeout=None: poller.stop())
    poller.run()
    return posted


def test_poller_reports_v4_and_v6_state_separately(
    poller: HAStatusPoller, monkeypatch: pytest.MonkeyPatch
):
    posted = _run_once(
        poller,
        monkeypatch,
        {"v4": ("hot-standby", {"a": 1}), "v6": ("partner-down", {"b": 2})},
    )
    assert posted == [("hot-standby", {"a": 1}, "partner-down", {"b": 2})]


def test_a_dhcp6_without_the_hook_reports_no_v6_state(
    poller: HAStatusPoller, monkeypatch: pytest.MonkeyPatch
):
    posted = _run_once(poller, monkeypatch, {"v4": ("normal", {}), "v6": (None, None)})
    assert posted == [("normal", {}, None, None)]


def test_report_body_omits_v6_keys_when_there_is_no_v6_state(
    poller: HAStatusPoller, monkeypatch: pytest.MonkeyPatch
):
    """A control plane that predates DHCPv6 HA must see the old payload."""
    bodies: list[dict[str, Any]] = []

    class _Resp:
        status_code = 200

    class _Client:
        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

        def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> _Resp:
            bodies.append(json)
            return _Resp()

    monkeypatch.setattr(poller, "_client", lambda: _Client())
    poller._report("normal", {"x": 1})
    poller._report("normal", {"x": 1}, "waiting", {"y": 2})
    assert bodies[0] == {"state": "normal", "raw": {"x": 1}}
    assert bodies[1] == {
        "state": "normal",
        "raw": {"x": 1},
        "state_v6": "waiting",
        "raw_v6": {"y": 2},
    }


def test_a_missing_v6_socket_is_not_an_error(
    poller: HAStatusPoller, agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
):
    def boom(*a: Any, **k: Any) -> dict[str, Any]:
        raise FileNotFoundError

    monkeypatch.setattr(ha_status, "send_command", boom)
    assert poller._poll_kea(agent_cfg.kea_control_socket_v6) == (None, None)

    def err(*a: Any, **k: Any) -> dict[str, Any]:
        raise KeaCtrlError("no HA hook")

    monkeypatch.setattr(ha_status, "send_command", err)
    assert poller._poll_kea(agent_cfg.kea_control_socket_v6) == (None, None)
