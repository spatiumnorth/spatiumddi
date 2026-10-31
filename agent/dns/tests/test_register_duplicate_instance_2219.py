"""Registration names the process and backs off on a duplicate refusal (#2219).

Two agent processes on one server identity share the server's one token hash.
A token minted for the refused half of the pair (#2044) stales the owner's,
the owner re-registers and stales it back, and the pair trade
re-registrations forever. The control plane now refuses that registration with
the same 409 the poll gets; the agent has to send its instance id for it to
know, and must wait on the refusal at a steady pace rather than spin or treat
it as an ordinary failure.
"""

from __future__ import annotations

from typing import Any

import pytest

from spatium_dns_agent import bootstrap as bootstrap_mod
from spatium_dns_agent.cache import ensure_layout, load_token
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.instance import (
    AGENT_INSTANCE,
    AGENT_INSTANCE_HEADER,
    DUPLICATE_INSTANCE_BACKOFF,
    DUPLICATE_INSTANCE_HEADER,
)


class _Resp:
    def __init__(
        self, status: int, headers: dict[str, str] | None = None, body: Any = None
    ):
        self.status_code = status
        self.headers = headers or {}
        self._body = body or {}
        self.text = ""

    def json(self) -> Any:
        return self._body


class _Client:
    def __init__(self, answers: list[_Resp], sent: list[dict[str, str]]):
        self._answers = answers
        self._sent = sent

    def __enter__(self) -> _Client:  # noqa: PYI034
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(
        self, path: str, json: Any = None, headers: dict[str, str] | None = None
    ) -> _Resp:
        self._sent.append(dict(headers or {}))
        return self._answers.pop(0)


def _ok() -> _Resp:
    return _Resp(
        200, body={"server_id": "s", "agent_token": "minted", "pending_approval": False}
    )


def _duplicate() -> _Resp:
    return _Resp(409, headers={DUPLICATE_INSTANCE_HEADER: "1"})


def test_register_sends_the_instance_id(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    ensure_layout(agent_cfg.state_dir)
    sent: list[dict[str, str]] = []
    answers = [_ok()]
    monkeypatch.setattr(bootstrap_mod, "_client", lambda cfg: _Client(answers, sent))
    _agent_id, token, _ = bootstrap_mod.register(agent_cfg)
    assert token == "minted"
    assert sent[0][AGENT_INSTANCE_HEADER] == AGENT_INSTANCE


def test_duplicate_refusal_waits_steadily_then_registers(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three refusals, then the owner stops and the registration goes through.
    Each wait is the steady duplicate back-off, not the doubling failure one,
    and nothing is saved as a token while refused."""
    ensure_layout(agent_cfg.state_dir)
    sent: list[dict[str, str]] = []
    answers = [_duplicate(), _duplicate(), _duplicate(), _ok()]
    sleeps: list[float] = []

    def fake_sleep(s: float) -> None:
        sleeps.append(s)
        assert load_token(agent_cfg.state_dir) in (None, "")

    monkeypatch.setattr(bootstrap_mod.time, "sleep", fake_sleep)
    monkeypatch.setattr(bootstrap_mod, "_client", lambda cfg: _Client(answers, sent))
    _agent_id, token, _ = bootstrap_mod.register(agent_cfg)
    assert token == "minted"
    assert len(sleeps) == 3
    assert all(
        DUPLICATE_INSTANCE_BACKOFF <= s <= DUPLICATE_INSTANCE_BACKOFF + 2
        for s in sleeps
    )


def test_a_plain_409_is_still_an_ordinary_failure(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the duplicate header a 409 takes the doubling back-off as before."""
    ensure_layout(agent_cfg.state_dir)
    sent: list[dict[str, str]] = []
    answers = [_Resp(409), _Resp(409), _ok()]
    sleeps: list[float] = []
    monkeypatch.setattr(bootstrap_mod.time, "sleep", sleeps.append)
    monkeypatch.setattr(bootstrap_mod, "_client", lambda cfg: _Client(answers, sent))
    bootstrap_mod.register(agent_cfg)
    assert sleeps[0] < DUPLICATE_INSTANCE_BACKOFF and sleeps[1] > sleeps[0] - 2
