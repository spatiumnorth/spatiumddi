"""The version the agent reports is the image's build stamp (#1182).

It was a literal date string that nothing rewrote, so every agent reported
the day its package was first written, whatever release it shipped in.
"""

from __future__ import annotations

import importlib

import pytest

import spatium_dns_agent


def _version_with(monkeypatch: pytest.MonkeyPatch, stamp: str | None) -> str:
    if stamp is None:
        monkeypatch.delenv("SPATIUM_AGENT_VERSION", raising=False)
    else:
        monkeypatch.setenv("SPATIUM_AGENT_VERSION", stamp)
    try:
        return importlib.reload(spatium_dns_agent).__version__
    finally:
        monkeypatch.undo()
        importlib.reload(spatium_dns_agent)


@pytest.mark.parametrize("stamp", ["2026.11.03-1", "1.0.0", "1.0.0-rc.1"])
def test_the_version_is_the_build_stamp(monkeypatch: pytest.MonkeyPatch, stamp: str) -> None:
    assert _version_with(monkeypatch, stamp) == stamp


@pytest.mark.parametrize("stamp", [None, "", "   "])
def test_an_unstamped_build_reports_dev(monkeypatch: pytest.MonkeyPatch, stamp: str | None) -> None:
    assert _version_with(monkeypatch, stamp) == "dev"


def test_the_version_fits_what_the_control_plane_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Register and heartbeat take at most 64 characters; a longer stamp
    would be refused on every call."""
    assert _version_with(monkeypatch, "1.0.0-" + "x" * 100) == ("1.0.0-" + "x" * 100)[:64]
