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
