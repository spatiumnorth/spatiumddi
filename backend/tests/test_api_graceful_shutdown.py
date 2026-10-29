"""#2944 — uvicorn's graceful-shutdown timeout must sit below every grace
period that stops the api image, or the kill lands before lifespan shutdown."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    not (REPO / "k8s" / "base" / "api.yaml").exists(),
    reason="repo-root files are not in the container image",
)

HEADROOM_S = 5


def _flag() -> int:
    text = (REPO / "backend" / "Dockerfile").read_text()
    cmd = re.search(r"^CMD \[(.*uvicorn.*)\]$", text, re.M)
    assert cmd, "runtime CMD not found"
    m = re.search(r'"--timeout-graceful-shutdown",\s*"(\d+)"', cmd.group(1))
    assert m, "api CMD must pass --timeout-graceful-shutdown"
    return int(m.group(1))


def test_flag_present() -> None:
    assert _flag() > 0


@pytest.mark.parametrize("path", ["k8s/base/api.yaml", "charts/spatiumddi/templates/api.yaml"])
def test_pod_grace_exceeds_flag(path: str) -> None:
    m = re.search(
        r"^\s*terminationGracePeriodSeconds:\s*(\d+)\s*$",
        (REPO / path).read_text(),
        re.M,
    )
    assert m, f"{path}: terminationGracePeriodSeconds not a literal"
    assert int(m.group(1)) >= _flag() + HEADROOM_S


@pytest.mark.parametrize("path", ["docker-compose.yml", "docker-compose.dev.yml"])
def test_compose_stop_grace_exceeds_flag(path: str) -> None:
    text = (REPO / path).read_text()
    api = re.search(r"^  api:\n(.*?)(?=^  \S)", text, re.M | re.S)
    assert api, f"{path}: api service not found"
    m = re.search(r"^    stop_grace_period:\s*(\d+)s\s*$", api.group(1), re.M)
    assert m, f"{path}: api needs stop_grace_period (Docker default is 10 s)"
    assert int(m.group(1)) >= _flag() + HEADROOM_S


# ── #3015 — the long-polls that outlive the cut must end on shutdown ─────────
#
# Holds of 30 s exceed the 20 s cut, so a stop that lands mid-hold would be
# cancelled into a 500. The primary fix is not to lower the holds (agents rely
# on 30 s to keep idle polling cheap) but to end every hold the moment SIGTERM
# lands (``app.core.shutdown``). This pins both halves: any hold that is not
# shorter than the cut MUST race the shutdown flag, and the cut stays below
# the pod's grace period (tests above).

_LONGPOLL_FILES = {
    "backend/app/api/v1/dns/agents.py": "wake.wait(",
    "backend/app/api/v1/dhcp/agents.py": "wake.wait(",
    "backend/app/api/v1/looking_glass/agents.py": "wake.wait(",
    "backend/app/api/v1/appliance/supervisor.py": "WakeResult.SHUTDOWN",
    "backend/app/services/appliance/agent_cmd.py": "get_or_shutdown(",
    "backend/app/services/appliance/k8s_proxy.py": "get_or_shutdown(",
}


@pytest.mark.parametrize("path", sorted(_LONGPOLL_FILES))
def test_long_poll_waits_race_the_shutdown_flag(path: str) -> None:
    text = (REPO / path).read_text()
    assert _LONGPOLL_FILES[path] in text
    if "wake.wait(" in text:
        assert "WakeResult.SHUTDOWN" in text, f"{path}: wake.wait result must handle SHUTDOWN"


def test_wake_subscription_wait_honours_shutdown() -> None:
    text = (REPO / "backend/app/core/agent_wake.py").read_text()
    assert "shutdown_requested()" in text and "WakeResult.SHUTDOWN" in text


def test_a_hold_longer_than_the_cut_is_covered_by_the_flag() -> None:
    holds = []
    for path in ("dns", "dhcp"):
        t = (REPO / f"backend/app/api/v1/{path}/agents.py").read_text()
        m = re.search(r'LONGPOLL_TIMEOUT"?, "(\d+)"', t)
        assert m
        holds.append(int(m.group(1)))
    if max(holds) >= _flag():
        assert "install_signal_hook()" in (REPO / "backend/app/main.py").read_text()
