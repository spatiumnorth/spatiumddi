"""The agent verifies the control plane, and a CA bundle beats the skip flag (#1220).

The remote-agent compose files defaulted SPATIUM_INSECURE_SKIP_TLS_VERIFY to
1, and the skip was checked before TLS_CA_PATH in every client this agent
builds (seven copies of the same four lines). So an operator who followed
the docs and mounted the control plane's CA still verified nothing, and
anyone on the network path could read the agent key.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

from spatium_dns_agent.config import AgentConfig

PACKAGE = Path(__file__).resolve().parent.parent / "spatium_dns_agent"
REPO = Path(__file__).resolve().parents[3]


def _cfg(agent_cfg: AgentConfig, url: str, ca: str | None, skip: bool) -> AgentConfig:
    return dataclasses.replace(
        agent_cfg, control_plane_url=url, tls_ca_path=ca, insecure_skip_tls_verify=skip
    )


@pytest.mark.parametrize(
    ("ca", "skip", "expected"),
    [
        (None, False, True),
        ("/etc/ssl/spatium-ca.crt", False, "/etc/ssl/spatium-ca.crt"),
        (None, True, False),
        # The #1220 case: the CA the operator mounted is used.
        ("/etc/ssl/spatium-ca.crt", True, "/etc/ssl/spatium-ca.crt"),
    ],
)
def test_verify_resolution(agent_cfg: AgentConfig, ca: str | None, skip: bool, expected) -> None:
    assert _cfg(agent_cfg, "https://cp", ca, skip).httpx_verify() == expected


def test_skipping_is_warned_about(agent_cfg: AgentConfig) -> None:
    warning = _cfg(agent_cfg, "https://cp", None, True).tls_warning()
    assert warning is not None and "OFF" in warning


def test_an_ignored_skip_is_reported(agent_cfg: AgentConfig) -> None:
    warning = _cfg(agent_cfg, "https://cp", "/ca.crt", True).tls_warning()
    assert warning is not None and "ignored" in warning


@pytest.mark.parametrize("skip", [False, True])
def test_no_warning_for_plain_http(agent_cfg: AgentConfig, skip: bool) -> None:
    """The in-stack agents talk to http://api:8000: nothing to verify."""
    assert _cfg(agent_cfg, "http://api:8000", None, skip).tls_warning() is None


def test_no_warning_when_verifying(agent_cfg: AgentConfig) -> None:
    assert _cfg(agent_cfg, "https://cp", None, False).tls_warning() is None


def test_every_client_uses_the_one_resolution() -> None:
    """Seven hand-copied decisions are how the precedence went wrong in all
    of them at once. Only config.py may read the raw fields."""
    offenders = [
        path.name
        for path in PACKAGE.rglob("*.py")
        if path.name != "config.py"
        and re.search(r"\.(insecure_skip_tls_verify|tls_ca_path)\b", path.read_text())
    ]
    assert offenders == []


@pytest.mark.skipif(
    not (REPO / "docker-compose.agent-dns-bind9.yml").exists(),
    reason="compose files not present in this checkout",
)
def test_remote_agent_compose_files_verify_by_default() -> None:
    files = sorted(REPO.glob("docker-compose.agent-*.yml"))
    assert len(files) >= 5
    for path in files:
        text = path.read_text()
        defaults = re.findall(r"SPATIUM_INSECURE_SKIP_TLS_VERIFY:-(\d)", text)
        assert defaults, path.name
        assert set(defaults) == {"0"}, path.name
        # Every service that sets the flag also passes TLS_CA_PATH through.
        assert text.count('TLS_CA_PATH: "${TLS_CA_PATH:-}"') == len(defaults), path.name
