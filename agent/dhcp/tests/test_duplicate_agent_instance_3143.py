"""The DHCP agent names its process and backs off on a duplicate refusal (#3143).

Two DHCP agent processes on one server identity (a cloned Kea VM, two
containers on one state dir) shared the server's one token hash: each
registration or rotation staled the other's token and the pair traded 401s
and re-registrations forever. The control plane now keeps one owner per
server (the DNS #2044 / #2219 rules) and refuses the other's polls and
registrations with 409 + ``X-Spatium-Duplicate-Agent-Instance``. For that the
agent has to send its instance id on poll, heartbeat and register, and on the
refusal it must wait at a steady pace, keep its token and keep Kea on the
config it has — not re-register (which would not change who owns the row)
and not treat the control plane as unreachable.
"""

from __future__ import annotations

from typing import Any

import pytest

from spatium_dhcp_agent import bootstrap as bootstrap_mod
from spatium_dhcp_agent.cache import ensure_layout, load_token, save_token
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.config_apply import ApplyStatus
from spatium_dhcp_agent.heartbeat import HeartbeatClient
from spatium_dhcp_agent.instance import (
    AGENT_INSTANCE,
    AGENT_INSTANCE_HEADER,
    DUPLICATE_INSTANCE_BACKOFF,
    DUPLICATE_INSTANCE_HEADER,
)
from spatium_dhcp_agent.sync import SyncLoop


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

    def get(self, path: str, headers: dict[str, str] | None = None, **k: Any) -> _Resp:
        self._sent.append(dict(headers or {}))
        return self._answers.pop(0)

    def post(
        self,
        path: str,
        json: Any = None,
        headers: dict[str, str] | None = None,
        **k: Any,
    ) -> _Resp:
        self._sent.append(dict(headers or {}))
        return self._answers.pop(0)


class _Heartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.config_apply = ApplyStatus()


def _ok() -> _Resp:
    return _Resp(
        200, body={"server_id": "s", "agent_token": "minted", "pending_approval": False}
    )


def _duplicate() -> _Resp:
    return _Resp(
        409,
        headers={DUPLICATE_INSTANCE_HEADER: "1"},
        body={"detail": "Another agent process is polling as DHCP server 'x'."},
    )


# ── registration ───────────────────────────────────────────────────────────


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
    assert sent[0]["X-DHCP-Agent-Key"] == "test-key"


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
    assert len(sleeps) == 2
    assert sleeps[0] < DUPLICATE_INSTANCE_BACKOFF


# ── the config poll ────────────────────────────────────────────────────────


def test_poll_sends_the_instance_id(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    ensure_layout(agent_cfg.state_dir)
    sent: list[dict[str, str]] = []
    loop = SyncLoop(agent_cfg, ["tok"], heartbeat=_Heartbeat())
    monkeypatch.setattr(loop, "_client", lambda: _Client([_Resp(304)], sent))
    loop._poll_once()
    assert sent[0][AGENT_INSTANCE_HEADER] == AGENT_INSTANCE


def test_a_duplicate_refusal_keeps_the_token_and_the_config(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused: no re-registration (a new token would not change who owns the
    row, and would stale the owner's), no apply, the token and etag kept, the
    control plane not marked unreachable, and a ~30 s wait before asking
    again."""
    ensure_layout(agent_cfg.state_dir)
    save_token(agent_cfg.state_dir, "tok")
    token_ref = ["tok"]
    loop = SyncLoop(agent_cfg, token_ref, heartbeat=_Heartbeat())
    loop._current_etag = "e1"
    sent: list[dict[str, str]] = []
    answers = [_duplicate() for _ in range(5)]
    monkeypatch.setattr(loop, "_client", lambda: _Client(answers, sent))

    def no_register(cfg: AgentConfig):  # type: ignore[no-untyped-def]
        raise AssertionError("a duplicate refusal must not re-register")

    def no_apply(*a: Any, **k: Any) -> bool:
        raise AssertionError("a duplicate refusal must not touch Kea")

    monkeypatch.setattr(bootstrap_mod, "register", no_register)
    monkeypatch.setattr(loop, "_apply_with_revert", no_apply)
    waits: list[float | None] = []
    monkeypatch.setattr(loop._stop, "wait", lambda t=None: waits.append(t) or False)

    for _ in range(5):
        loop._poll_once()

    assert waits == [DUPLICATE_INSTANCE_BACKOFF] * 5
    assert token_ref[0] == "tok"
    assert load_token(agent_cfg.state_dir) == "tok"
    assert loop._current_etag == "e1"
    assert not loop._offline
    assert not loop._stop.is_set()


# ── the heartbeat ──────────────────────────────────────────────────────────


def test_heartbeat_sends_the_instance_id(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    ensure_layout(agent_cfg.state_dir)
    sent: list[dict[str, str]] = []
    hb = HeartbeatClient(agent_cfg, ["tok"])
    monkeypatch.setattr(
        hb, "_client", lambda: _Client([_Resp(200, body={"status": "active"})], sent)
    )
    hb.send_once()
    assert sent and sent[0][AGENT_INSTANCE_HEADER] == AGENT_INSTANCE
    assert sent[0]["Authorization"] == "Bearer tok"
