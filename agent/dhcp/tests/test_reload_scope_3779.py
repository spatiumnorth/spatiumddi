"""Per-daemon reload scope (#3779).

A Kea ``config-reload`` restarts the HA hook's state machine, so the agent
reloads only a daemon whose rendered document (or HA TLS files) changed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dhcp_agent import sync as sync_mod
from spatium_dhcp_agent.cache import ensure_layout
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.config_apply import ApplyStatus
from spatium_dhcp_agent.render_kea import render
from spatium_dhcp_agent.sync import SyncLoop


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.config_apply = ApplyStatus()


def _scope(cidr: str, family: str) -> dict[str, Any]:
    d: dict[str, Any] = {
        "subnet_cidr": cidr,
        "lease_time": 3600,
        "address_family": family,
        "pools": [],
        "statics": [],
    }
    if family == "ipv6":
        d["v6_address_mode"] = "stateful"
    return d


def _bundle(v4: str = "192.0.2.0/24", v6: str = "2001:db8::/64") -> dict[str, Any]:
    return {"etag": "x", "scopes": [_scope(v4, "ipv4"), _scope(v6, "ipv6")]}


class _Kea:
    """Both daemons: records reloads and answers config-hash-get."""

    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg
        self.reloads: list[str] = []
        self.checks: list[str] = []
        self.hashes = {"dhcp4": "h4-0", "dhcp6": "h6-0"}
        self.hash_works = True

    def _daemon(self, sock: Path) -> str:
        return "dhcp4" if sock == self.cfg.kea_control_socket else "dhcp6"

    def reload(self, sock: Path) -> None:
        d = self._daemon(sock)
        self.reloads.append(d)
        self.hashes[d] = f"h-{d}-{len(self.reloads)}"

    def hash_get(self, sock: Path) -> str | None:
        return self.hashes[self._daemon(sock)] if self.hash_works else None


@pytest.fixture
def env(agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch) -> tuple[SyncLoop, _Kea]:
    kea = _Kea(agent_cfg)
    monkeypatch.setattr(sync_mod, "config_check", lambda d, p: kea.checks.append(d))
    monkeypatch.setattr(sync_mod, "config_reload", kea.reload)
    monkeypatch.setattr(sync_mod, "config_hash_get", kea.hash_get)
    ensure_layout(agent_cfg.state_dir)
    return SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat()), kea


def test_first_apply_reloads_both(env: tuple[SyncLoop, _Kea]) -> None:
    loop, kea = env
    loop._apply_bundle(_bundle(), reload_kea=True)
    assert sorted(kea.reloads) == ["dhcp4", "dhcp6"]


def test_unchanged_document_is_skipped(env: tuple[SyncLoop, _Kea]) -> None:
    loop, kea = env
    loop._apply_bundle(_bundle(), reload_kea=True)
    kea.reloads.clear()
    kea.checks.clear()
    loop._apply_bundle(_bundle(), reload_kea=True)
    assert kea.reloads == []
    assert kea.checks == []
    # A skip is an OK apply for the etag.
    assert loop._last_reload_results == {"dhcp4": "ok", "dhcp6": "ok"}
    assert loop._reload_confirmed is True


def test_v6_only_change_does_not_reload_dhcp4(env: tuple[SyncLoop, _Kea]) -> None:
    loop, kea = env
    loop._apply_bundle(_bundle(), reload_kea=True)
    kea.reloads.clear()
    loop._apply_bundle(_bundle(v6="2001:db8:1::/64"), reload_kea=True)
    assert kea.reloads == ["dhcp6"]


def test_v4_only_change_does_not_reload_dhcp6(env: tuple[SyncLoop, _Kea]) -> None:
    loop, kea = env
    loop._apply_bundle(_bundle(), reload_kea=True)
    kea.reloads.clear()
    loop._apply_bundle(_bundle(v4="198.51.100.0/24"), reload_kea=True)
    assert kea.reloads == ["dhcp4"]


def test_restarted_daemon_is_reloaded(env: tuple[SyncLoop, _Kea]) -> None:
    loop, kea = env
    loop._apply_bundle(_bundle(), reload_kea=True)
    kea.reloads.clear()
    kea.hashes["dhcp4"] = "restarted-with-baked-config"
    loop._apply_bundle(_bundle(), reload_kea=True)
    assert kea.reloads == ["dhcp4"]


def test_no_hash_means_no_skip(env: tuple[SyncLoop, _Kea]) -> None:
    loop, kea = env
    kea.hash_works = False
    loop._apply_bundle(_bundle(), reload_kea=True)
    kea.reloads.clear()
    loop._apply_bundle(_bundle(), reload_kea=True)
    assert sorted(kea.reloads) == ["dhcp4", "dhcp6"]


def _ha_bundle(key: str) -> dict[str, Any]:
    b = _bundle()
    b["failover"] = {
        "channel_id": "g",
        "channel_name": "g",
        "mode": "hot-standby",
        "this_server_name": "a",
        "peers": [
            {"name": "a", "url": "http://10.0.0.1:8000/", "role": "primary"},
            {"name": "b", "url": "http://10.0.0.2:8000/", "role": "standby"},
        ],
        "tls": {"ca_pem": "ca", "cert_pem": "cert", "key_pem": key},
    }
    return b


def test_tls_credential_change_reloads_dhcp4_only(env: tuple[SyncLoop, _Kea]) -> None:
    loop, kea = env
    loop._apply_bundle(_ha_bundle("k1"), reload_kea=True)
    kea.reloads.clear()
    loop._apply_bundle(_ha_bundle("k1"), reload_kea=True)
    assert kea.reloads == []
    loop._apply_bundle(_ha_bundle("k2"), reload_kea=True)
    assert kea.reloads == ["dhcp4"]


def test_failed_reload_clears_baseline(
    env: tuple[SyncLoop, _Kea], monkeypatch: pytest.MonkeyPatch
) -> None:
    loop, kea = env
    loop._apply_bundle(_bundle(), reload_kea=True)
    monkeypatch.setattr(
        sync_mod, "config_reload", lambda s: (_ for _ in ()).throw(OSError("down"))
    )
    loop._apply_bundle(_bundle(v4="198.51.100.0/24"), reload_kea=True)
    assert "dhcp4" not in loop._applied
    monkeypatch.setattr(sync_mod, "config_reload", kea.reload)
    kea.reloads.clear()
    loop._apply_bundle(_bundle(v4="198.51.100.0/24"), reload_kea=True)
    assert "dhcp4" in kea.reloads


def test_ha_heartbeat_default_is_2s() -> None:
    failover = {
        "channel_id": "g",
        "channel_name": "g",
        "mode": "hot-standby",
        "this_server_name": "a",
        "peers": [
            {"name": "a", "url": "http://10.0.0.1:8000/", "role": "primary"},
            {"name": "b", "url": "http://10.0.0.2:8000/", "role": "standby"},
        ],
    }
    out = render(
        {"server": {"name": "a", "interfaces": ["eth0"]}, "scopes": [], "failover": failover}
    )
    hook = next(
        h for h in out["Dhcp4"]["hooks-libraries"] if h["library"].endswith("libdhcp_ha.so")
    )
    rel = hook["parameters"]["high-availability"][0]
    assert rel["heartbeat-delay"] == 2000
    assert rel["max-response-delay"] >= 5 * rel["heartbeat-delay"]
