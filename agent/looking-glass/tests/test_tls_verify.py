"""A CA bundle beats the skip flag, and skipping is warned about (#1220).

The skip used to be checked before TLS_CA_PATH, so an operator who mounted
the control plane's CA while the compose default still said 1 verified
nothing, and anyone on the network path could read the agent key.
"""

from __future__ import annotations

import pytest

from spatium_lg_agent.config import AgentConfig


def _cfg(monkeypatch: pytest.MonkeyPatch, url: str, ca: str | None, skip: bool) -> AgentConfig:
    monkeypatch.setenv("CONTROL_PLANE_URL", url)
    monkeypatch.setenv("LG_AGENT_KEY", "k")
    if ca is None:
        monkeypatch.delenv("TLS_CA_PATH", raising=False)
    else:
        monkeypatch.setenv("TLS_CA_PATH", ca)
    monkeypatch.setenv("SPATIUM_INSECURE_SKIP_TLS_VERIFY", "1" if skip else "0")
    monkeypatch.delenv("TLS_PINNED_CERTS_PATH", raising=False)
    return AgentConfig.from_env()


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
def test_verify_resolution(
    monkeypatch: pytest.MonkeyPatch, ca: str | None, skip: bool, expected: bool | str
) -> None:
    assert _cfg(monkeypatch, "https://cp", ca, skip).httpx_verify() == expected


def test_skipping_is_warned_about(monkeypatch: pytest.MonkeyPatch) -> None:
    warning = _cfg(monkeypatch, "https://cp", None, True).tls_warning()
    assert warning is not None and "OFF" in warning


def test_an_ignored_skip_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    warning = _cfg(monkeypatch, "https://cp", "/ca.crt", True).tls_warning()
    assert warning is not None and "ignored" in warning


@pytest.mark.parametrize("skip", [False, True])
def test_no_warning_for_plain_http(monkeypatch: pytest.MonkeyPatch, skip: bool) -> None:
    assert _cfg(monkeypatch, "http://api:8000", None, skip).tls_warning() is None
