"""A refused registration proof keeps the pairing code (#4433).

Clock skew or a bad signature says nothing about the code, so the supervisor
keeps it, backs off and registers by itself once the clock is right. A genuinely
dead code is still cleared.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
import structlog
from structlog.testing import capture_logs

from spatium_supervisor import __main__ as main_mod
from spatium_supervisor import appliance_state, cp_tls
from spatium_supervisor.config import SupervisorConfig
from spatium_supervisor.identity import load_appliance_id
from spatium_supervisor.register import (
    RegisterCodeRejected,
    RegisterProofRefused,
    RegisterResult,
)
from spatium_supervisor.state import ensure_layout


def _cfg(tmp_path: Path) -> SupervisorConfig:
    monkey_env = {
        "STATE_DIR": str(tmp_path),
        "CONTROL_PLANE_URL": "https://cp.example.com",
        "BOOTSTRAP_PAIRING_CODE": "12345678",
    }
    import os

    old = {k: os.environ.get(k) for k in monkey_env}
    os.environ.update(monkey_env)
    try:
        cfg = SupervisorConfig.from_env()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    ensure_layout(cfg.state_dir)
    assert cfg.bootstrap_pairing_code == "12345678"
    return cfg


def _setup(monkeypatch: pytest.MonkeyPatch, outcomes: list[Any]) -> list[str]:
    calls: list[str] = []

    class _Client:
        def __enter__(self) -> None:
            return None

        def __exit__(self, *_a: Any) -> None:
            return None

    monkeypatch.setattr(cp_tls, "client", lambda *_a, **_k: _Client())
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: None)

    def fake_register(**kw: Any) -> RegisterResult:
        calls.append(kw["pairing_code"])
        out = outcomes.pop(0)
        if isinstance(out, Exception):
            raise out
        return out

    monkeypatch.setattr(main_mod, "register", fake_register)
    return calls


def test_clock_skew_keeps_the_code_and_backs_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ok = RegisterResult(str(uuid.uuid4()), "pending_approval", "fp", "tok")
    calls = _setup(
        monkeypatch,
        [
            RegisterProofRefused("clock_skew", "skewed"),
            RegisterProofRefused("clock_skew", "skewed"),
            ok,
        ],
    )
    cfg = _cfg(tmp_path)
    now = [0.0]
    retry = main_mod.RevokedReregisterRetry(clock=lambda: now[0])
    log = structlog.get_logger()

    with capture_logs() as logs:
        out = main_mod._maybe_register(cfg, log, proof_retry=retry)
    assert out.bootstrap_pairing_code == "12345678"
    assert out.control_plane_url == "https://cp.example.com"
    assert not retry.due()  # backing off
    event = next(e for e in logs if e["event"] == "supervisor.register.proof_refused")
    assert event["reason"] == "clock_skew"
    assert "clock" in event["hint"]

    now[0] += 61
    assert retry.due()
    out = main_mod._maybe_register(out, log, proof_retry=retry)
    assert out.bootstrap_pairing_code == "12345678"
    now[0] += 121  # the wait doubled
    assert retry.due()

    # The clock is fixed: the same code registers, and the backoff resets.
    out = main_mod._maybe_register(out, log, proof_retry=retry)
    assert calls == ["12345678"] * 3
    assert load_appliance_id(cfg.state_dir) is not None
    assert retry.due()


def test_a_dead_code_is_still_cleared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup(monkeypatch, [RegisterCodeRejected("invalid / expired")])
    cfg = _cfg(tmp_path)
    out = main_mod._maybe_register(
        cfg, structlog.get_logger(), proof_retry=main_mod.RevokedReregisterRetry()
    )
    assert out.bootstrap_pairing_code == ""
