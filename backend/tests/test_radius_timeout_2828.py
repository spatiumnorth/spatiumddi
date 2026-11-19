"""RADIUS: a silent server is a timeout, not a protocol error (#2828)."""

from __future__ import annotations

from typing import Any

import pytest
from pyrad.client import Timeout as PyradTimeout
from structlog.testing import capture_logs

from app.core.auth import radius
from app.core.auth.radius import RADIUSConfig, RADIUSServiceError, authenticate_radius


class _Provider:
    id = "p1"
    secrets_encrypted = None
    config = {"server": "192.0.2.1", "port": 1812, "timeout": 1, "retries": 2}


class _Pkt(dict):  # type: ignore[type-arg]
    def PwCrypt(self, pw: str) -> str:  # noqa: N802
        return pw


def _patch(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    class _Client:
        timeout = 0
        retries = 0

        def CreateAuthPacket(self, **_: Any) -> _Pkt:  # noqa: N802
            return _Pkt()

        def SendPacket(self, _req: Any) -> Any:  # noqa: N802
            raise exc

    def _from_provider(_p: Any) -> RADIUSConfig:
        return RADIUSConfig(
            server="192.0.2.1",
            port=1812,
            backup_servers=["192.0.2.2"],
            secret=b"s",
            timeout=1,
            retries=2,
            nas_identifier="x",
            attr_groups="Filter-Id",
        )

    monkeypatch.setattr(RADIUSConfig, "from_provider", staticmethod(_from_provider))
    monkeypatch.setattr(radius, "_client", lambda *_a, **_k: _Client())


def test_pyrad_timeout_is_unreachable_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, PyradTimeout())
    with capture_logs() as logs, pytest.raises(RADIUSServiceError):
        authenticate_radius(_Provider(), "u", "p")  # type: ignore[arg-type]
    events = [e["event"] for e in logs]
    assert events == ["radius_target_unreachable"] * 2
    assert "radius_target_protocol_error" not in events


def test_all_silent_says_no_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, PyradTimeout())
    with pytest.raises(RADIUSServiceError) as ei:
        authenticate_radius(_Provider(), "u", "p")  # type: ignore[arg-type]
    assert "no reply from 192.0.2.2:1812" in str(ei.value)


def test_empty_str_exception_names_its_type(monkeypatch: pytest.MonkeyPatch) -> None:
    class Weird(Exception):
        pass

    _patch(monkeypatch, Weird())
    with pytest.raises(RADIUSServiceError) as ei:
        authenticate_radius(_Provider(), "u", "p")  # type: ignore[arg-type]
    assert "protocol error" in str(ei.value)
    assert str(ei.value).rstrip().endswith("Weird")
