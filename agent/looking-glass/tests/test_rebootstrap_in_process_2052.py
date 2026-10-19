"""A 401/404 re-registers in process; it never ends a thread (#2052)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from spatium_lg_agent import bootstrap as bootstrap_mod
from spatium_lg_agent.cache import load_token, save_token
from spatium_lg_agent.config import AgentConfig
from spatium_lg_agent.heartbeat import HeartbeatClient


class _Resp:
    status_code = 404
    headers: dict[str, str] = {}
    text = ""

    def json(self) -> dict[str, Any]:
        return {}


class _Client:
    def __enter__(self) -> _Client:  # noqa: PYI034
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, *a: Any, **k: Any) -> _Resp:
        return _Resp()


@pytest.fixture(autouse=True)
def _reset_reauth_state() -> Iterator[None]:
    bootstrap_mod._reset_reauth_state()
    yield
    bootstrap_mod._reset_reauth_state()


def _cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AgentConfig:
    monkeypatch.setenv("CONTROL_PLANE_URL", "http://localhost:8000")
    monkeypatch.setenv("LG_AGENT_KEY", "k")
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))
    cfg = AgentConfig.from_env()
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    return cfg


def test_heartbeat_404_re_registers_without_stopping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _cfg(tmp_path, monkeypatch)
    calls: list[int] = []

    def fake_register(c: AgentConfig):  # type: ignore[no-untyped-def]
        calls.append(1)
        save_token(c.state_dir, "new-token")
        return "agent", "new-token", {}

    monkeypatch.setattr(bootstrap_mod, "register", fake_register)
    token_ref = ["old-token"]
    hb = HeartbeatClient(cfg, token_ref)
    monkeypatch.setattr(hb, "_client", _Client)
    hb.send_once()
    assert calls == [1]
    assert token_ref[0] == "new-token"
    assert load_token(cfg.state_dir) == "new-token"
    assert not hb._stop.is_set()
    # a second thread holding the same stale token does not register again
    bootstrap_mod.reauthenticate(cfg, token_ref, "old-token")
    assert calls == [1]


def test_repeated_reauthentication_is_paced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _cfg(tmp_path, monkeypatch)
    minted = iter(f"token-{i}" for i in range(10))
    monkeypatch.setattr(bootstrap_mod, "register", lambda c: ("a", next(minted), {}))
    sleeps: list[float] = []
    monkeypatch.setattr(bootstrap_mod.time, "sleep", sleeps.append)
    token_ref = ["old"]
    bootstrap_mod.reauthenticate(cfg, token_ref, "old")
    bootstrap_mod.reauthenticate(cfg, token_ref, token_ref[0])
    assert len(sleeps) == 1 and sleeps[0] >= 5.0
    assert bootstrap_mod.reauth_generation() == 2
