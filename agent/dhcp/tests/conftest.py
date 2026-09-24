"""Shared pytest fixtures for the DHCP agent tests."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from spatium_dhcp_agent.config import AgentConfig


@pytest.fixture
def tmp_state(tmp_path: Path) -> Iterator[Path]:
    yield tmp_path


@pytest.fixture
def agent_cfg(tmp_state: Path) -> AgentConfig:
    return AgentConfig(
        control_plane_url="http://localhost:8000",
        agent_key="test-key",
        server_name="dhcp-test",
        state_dir=tmp_state,
        kea_config_path=tmp_state / "kea-dhcp4.conf",
        kea_control_socket=tmp_state / "kea4-ctrl-socket",
        kea_lease_file=tmp_state / "kea-leases4.csv",
        kea_config_path_v6=tmp_state / "kea-dhcp6.conf",
        kea_control_socket_v6=tmp_state / "kea6-ctrl-socket",
        group_name="default",
        roles=["primary"],
        tls_ca_path=None,
        insecure_skip_tls_verify=True,
    )


@pytest.fixture(autouse=True)
def _no_host_ipv6_unicast(monkeypatch: pytest.MonkeyPatch) -> None:
    """#1140 — ``_apply_bundle`` reads the live host's global IPv6 addresses
    for kea-dhcp6's unicast sockets. Pin that to "none" so a sync test's
    rendered document does not depend on the machine running it; tests of
    the unicast path patch ``sync.global_ipv6_addresses`` themselves."""
    monkeypatch.setattr("spatium_dhcp_agent.sync.global_ipv6_addresses", lambda: [])
