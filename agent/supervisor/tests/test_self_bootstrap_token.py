"""The control-plane supervisor proves it is local when it self-bootstraps.

``_self_bootstrap_or_skip`` writes a one-time token to the host release-state
directory, presents it to ``/self-register-bootstrap``, and removes it again.
The api compares the presented value with the file, which nothing on the
network can read.
"""

from __future__ import annotations

import dataclasses
import json
import stat
from pathlib import Path

import httpx
import pytest
import structlog

from spatium_supervisor import __main__ as main_mod
from spatium_supervisor import self_bootstrap_token
from spatium_supervisor.config import SupervisorConfig

_REAL_CLIENT = httpx.Client


@pytest.fixture
def token_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "release-state" / "self-bootstrap.token"
    path.parent.mkdir()
    monkeypatch.setattr(self_bootstrap_token, "TOKEN_PATH", path)
    return path


def _cfg(tmp_path: Path) -> SupervisorConfig:
    cfg = SupervisorConfig.from_env()
    return dataclasses.replace(
        cfg,
        state_dir=tmp_path / "state",
        control_plane_url="",
        bootstrap_pairing_code="",
    )


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    def factory(*_a, **_k) -> httpx.Client:
        return _REAL_CLIENT(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(main_mod.httpx, "Client", factory)


def test_write_creates_a_private_token_and_remove_deletes_it(token_path: Path) -> None:
    token = self_bootstrap_token.write()
    assert token is not None
    assert len(token) == 64
    assert token_path.read_text() == token
    # Not readable by "other": the api reads it through the directory's group.
    assert stat.S_IMODE(token_path.stat().st_mode) == 0o640
    assert token_path.stat().st_gid == token_path.parent.stat().st_gid
    assert not token_path.with_name(token_path.name + ".tmp").exists()

    second = self_bootstrap_token.write()
    assert second is not None and second != token
    assert token_path.read_text() == second

    self_bootstrap_token.remove()
    assert not token_path.exists()
    self_bootstrap_token.remove()  # already gone: no error


def test_write_failure_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "no-such-dir" / "self-bootstrap.token"
    monkeypatch.setattr(self_bootstrap_token, "TOKEN_PATH", missing)
    assert self_bootstrap_token.write() is None


def test_self_bootstrap_presents_the_token_on_disk_then_removes_it(
    tmp_path: Path, token_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.read())
        seen["body"] = body
        # The file holds exactly the presented value while the api reads it.
        seen["on_disk"] = token_path.read_text() if token_path.exists() else None
        return httpx.Response(
            200,
            json={
                "code": "12345678",
                "control_plane_url": "http://api.example:8000",
                "expires_in_seconds": 600,
            },
        )

    _patch_client(monkeypatch, handler)
    cfg = main_mod._self_bootstrap_or_skip(
        _cfg(tmp_path), "control-plane", structlog.get_logger()
    )

    assert seen["body"]["appliance_variant"] == "control-plane"
    token = seen["body"]["bootstrap_token"]
    assert token and len(token) >= 32
    assert seen["on_disk"] == token
    assert not token_path.exists()
    assert cfg.bootstrap_pairing_code == "12345678"
    assert cfg.control_plane_url == "http://api.example:8000"


def test_token_removed_after_a_transport_error(
    tmp_path: Path, token_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    _patch_client(monkeypatch, handler)
    cfg = main_mod._self_bootstrap_or_skip(
        _cfg(tmp_path), "control-plane", structlog.get_logger()
    )
    assert cfg.bootstrap_pairing_code == ""
    assert not token_path.exists()


def test_no_request_without_a_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        self_bootstrap_token,
        "TOKEN_PATH",
        tmp_path / "missing" / "self-bootstrap.token",
    )
    calls: list = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(500)

    _patch_client(monkeypatch, handler)
    cfg = main_mod._self_bootstrap_or_skip(
        _cfg(tmp_path), "control-plane", structlog.get_logger()
    )
    assert calls == []
    assert cfg.bootstrap_pairing_code == ""
