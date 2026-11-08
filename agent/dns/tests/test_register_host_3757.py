"""SERVER_HOST is sent as ``host`` at registration, and only when set (#3757)."""

from __future__ import annotations

import dataclasses

import pytest
from spatium_dns_agent import bootstrap as bootstrap_mod
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.cache import ensure_layout


class _Resp:
    status_code = 200
    headers: dict = {}

    def json(self) -> dict:
        return {"server_id": "s1", "agent_token": "t"}


class _Client:
    def __init__(self, sent: list[dict]) -> None:
        self.sent = sent

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, path, json=None, headers=None):
        self.sent.append(json)
        return _Resp()


def _register(cfg, monkeypatch) -> dict:
    ensure_layout(cfg.state_dir)
    sent: list[dict] = []
    monkeypatch.setattr(bootstrap_mod, "_client", lambda c: _Client(sent))
    bootstrap_mod.register(cfg)
    return sent[0]


def test_host_sent_when_configured(agent_cfg, monkeypatch) -> None:
    body = _register(dataclasses.replace(agent_cfg, server_host="p-0.h.ns.svc.cluster.local"), monkeypatch)
    assert body["host"] == "p-0.h.ns.svc.cluster.local"
    assert body["hostname"] == agent_cfg.server_name


def test_host_omitted_when_unset(agent_cfg, monkeypatch) -> None:
    assert "host" not in _register(agent_cfg, monkeypatch)


def test_from_env_reads_server_host(monkeypatch) -> None:
    monkeypatch.setenv("CONTROL_PLANE_URL", "http://api:8000")
    monkeypatch.setenv("DNS_AGENT_KEY", "k" * 32)
    monkeypatch.setenv("SERVER_HOST", " p-0.h.ns.svc.cluster.local ")
    assert AgentConfig.from_env().server_host == "p-0.h.ns.svc.cluster.local"
    monkeypatch.delenv("SERVER_HOST")
    assert AgentConfig.from_env().server_host is None
