"""SERVER_HOST is sent as ``host`` at registration, and only when set (#3757)."""

from __future__ import annotations

import dataclasses

import pytest

from spatium_dns_agent import bootstrap as bootstrap_mod
from spatium_dns_agent.cache import ensure_layout
from spatium_dns_agent.config import AgentConfig


class _Resp:
    status_code = 200
    headers: dict = {}  # noqa: RUF012 — read-only stub

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
    body = _register(
        dataclasses.replace(agent_cfg, server_host="p-0.h.ns.svc.cluster.local"), monkeypatch
    )
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


# ── An already-registered agent carries a new SERVER_HOST (#3757) ─────────────
# A cached token means /register never runs on restart, so a chart upgrade that
# adds SERVER_HOST never reached the server row. ensure_token registers once
# when SERVER_HOST differs from the host it last registered.

_FQDN = "p-0.h.ns.svc.cluster.local"


class _FailResp:
    status_code = 503
    headers: dict = {}  # noqa: RUF012 — read-only stub
    text = "unavailable"


def _seed(cfg, *, token: str = "cached", recorded: str | None = None) -> None:
    # Written as files, not through the new helpers, so the tests fail on an
    # assertion (not an ImportError) against a build without the fix.
    ensure_layout(cfg.state_dir)
    (cfg.state_dir / "agent_token.jwt").write_text(token)
    if recorded is not None:
        (cfg.state_dir / "registered_host").write_text(recorded)


def _recorded(cfg) -> str | None:
    path = cfg.state_dir / "registered_host"
    return path.read_text().strip() if path.exists() else None


def _token(cfg) -> str:
    return (cfg.state_dir / "agent_token.jwt").read_text().strip()


class _EchoResp(_Resp):
    """A control plane with #3757: the response carries the row's host."""

    def __init__(self, host: str | None = None) -> None:
        self.host = host

    def json(self) -> dict:
        return {"server_id": "s1", "agent_token": "t", "host": self.host}


def _capture(monkeypatch, resp=None) -> list[dict]:
    sent: list[dict] = []

    class _C(_Client):
        def post(self, path, json=None, headers=None):
            self.sent.append(json)
            if resp is not None:
                return resp
            return _EchoResp(json.get("host"))

    monkeypatch.setattr(bootstrap_mod, "_client", lambda c: _C(sent))
    monkeypatch.setattr(bootstrap_mod.time, "sleep", lambda s: pytest.fail("must not wait"))
    return sent


def test_cached_token_registers_once_for_an_unregistered_host(agent_cfg, monkeypatch) -> None:
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg)  # an agent older than #3757: token cached, no host recorded
    sent = _capture(monkeypatch)
    _aid, token = bootstrap_mod.ensure_token(cfg)
    assert [b["host"] for b in sent] == [_FQDN]
    assert token == "t" and _token(cfg) == "t"
    assert _recorded(cfg) == _FQDN
    # The next start has nothing to carry.
    sent.clear()
    bootstrap_mod.ensure_token(cfg)
    assert sent == []


def test_cached_token_registers_when_the_host_changed(agent_cfg, monkeypatch) -> None:
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg, recorded="old.h.ns.svc.cluster.local")
    sent = _capture(monkeypatch)
    bootstrap_mod.ensure_token(cfg)
    assert [b["host"] for b in sent] == [_FQDN]


def test_cached_token_and_same_host_does_not_register(agent_cfg, monkeypatch) -> None:
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg, recorded=_FQDN)
    sent = _capture(monkeypatch)
    assert bootstrap_mod.ensure_token(cfg)[1] == "cached"
    assert sent == []


def test_cached_token_without_server_host_does_not_register(agent_cfg, monkeypatch) -> None:
    # The appliance sets no SERVER_HOST: nothing to carry, so no registration.
    _seed(agent_cfg)
    sent = _capture(monkeypatch)
    assert bootstrap_mod.ensure_token(agent_cfg)[1] == "cached"
    assert sent == []


def test_failed_host_register_keeps_the_cached_token(agent_cfg, monkeypatch) -> None:
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg)
    sent = _capture(monkeypatch, resp=_FailResp())
    # One attempt, no wait: the daemon starts on its cached config.
    assert bootstrap_mod.ensure_token(cfg)[1] == "cached"
    assert len(sent) == 1
    assert _token(cfg) == "cached"
    assert _recorded(cfg) is None  # the next start retries


def test_unreachable_control_plane_keeps_the_cached_token(agent_cfg, monkeypatch) -> None:
    import httpx

    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg)

    class _Down(_Client):
        def post(self, path, json=None, headers=None):
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(bootstrap_mod, "_client", lambda c: _Down([]))
    monkeypatch.setattr(bootstrap_mod.time, "sleep", lambda s: pytest.fail("must not wait"))
    assert bootstrap_mod.ensure_token(cfg)[1] == "cached"


def test_register_records_the_host_it_sent(agent_cfg, monkeypatch) -> None:
    ensure_layout(agent_cfg.state_dir)
    _capture(monkeypatch)
    bootstrap_mod.register(dataclasses.replace(agent_cfg, server_host=_FQDN))
    assert _recorded(agent_cfg) == _FQDN
    bootstrap_mod.register(agent_cfg)
    assert _recorded(agent_cfg) == ""


# ── Only a control plane that read the host counts (#3757) ────────────────────
# `helm upgrade` restarts the agent and the api together, so the agent can
# register against the OLD api, which ignores `host` and still answers 200. The
# response's echoed `host` is what says the field was read.


class _Clock:
    def __init__(self, monkeypatch) -> None:
        self.now = 1000.0
        monkeypatch.setattr(bootstrap_mod.time, "monotonic", lambda: self.now)


def test_no_echo_is_not_recorded_and_arms_a_retry(agent_cfg, monkeypatch) -> None:
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg)
    clock = _Clock(monkeypatch)
    sent = _capture(monkeypatch, resp=_Resp())  # an old api: 200, no host
    assert bootstrap_mod.ensure_token(cfg)[1] == "t"
    assert _recorded(cfg) is None
    token_ref = ["t"]
    # Not due yet: the heartbeat hook does not register on every beat.
    clock.now += 60
    bootstrap_mod.retry_host_register(cfg, token_ref)
    assert len(sent) == 1
    # Due, and the api is new now: registers once, records, stops.
    clock.now += bootstrap_mod.HOST_RETRY_INTERVAL_SECONDS
    sent2 = _capture(monkeypatch)
    bootstrap_mod.retry_host_register(cfg, token_ref)
    assert [b["host"] for b in sent2] == [_FQDN]
    assert _recorded(cfg) == _FQDN and token_ref == ["t"]
    clock.now += 10 * bootstrap_mod.HOST_RETRY_INTERVAL_SECONDS
    bootstrap_mod.retry_host_register(cfg, token_ref)
    assert len(sent2) == 1


def test_echoed_host_is_recorded(agent_cfg, monkeypatch) -> None:
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg)
    _capture(monkeypatch, resp=_EchoResp(_FQDN))
    bootstrap_mod.ensure_token(cfg)
    assert _recorded(cfg) == _FQDN


def test_a_different_echoed_host_is_still_recorded(agent_cfg, monkeypatch) -> None:
    # The server read the field and kept its own value (an operator edit or the
    # vetting rule): that is a decision, so nothing is retried.
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg)
    clock = _Clock(monkeypatch)
    sent = _capture(monkeypatch, resp=_EchoResp("192.0.2.10"))
    bootstrap_mod.ensure_token(cfg)
    assert _recorded(cfg) == _FQDN
    clock.now += bootstrap_mod.HOST_RETRY_INTERVAL_SECONDS + 1
    bootstrap_mod.retry_host_register(cfg, ["t"])
    assert len(sent) == 1


def test_a_failed_start_register_is_retried_in_process(agent_cfg, monkeypatch) -> None:
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg)
    clock = _Clock(monkeypatch)
    _capture(monkeypatch, resp=_FailResp())
    assert bootstrap_mod.ensure_token(cfg)[1] == "cached"
    clock.now += bootstrap_mod.HOST_RETRY_INTERVAL_SECONDS
    sent = _capture(monkeypatch)
    token_ref = ["cached"]
    bootstrap_mod.retry_host_register(cfg, token_ref)
    assert [b["host"] for b in sent] == [_FQDN]
    assert token_ref == ["t"] and _recorded(cfg) == _FQDN


def test_the_retry_gives_up_after_its_window(agent_cfg, monkeypatch) -> None:
    cfg = dataclasses.replace(agent_cfg, server_host=_FQDN)
    _seed(cfg)
    clock = _Clock(monkeypatch)
    sent = _capture(monkeypatch, resp=_Resp())
    bootstrap_mod.ensure_token(cfg)
    token_ref = ["t"]
    while clock.now < 1000.0 + 2 * bootstrap_mod.HOST_RETRY_WINDOW_SECONDS:
        clock.now += bootstrap_mod.HOST_RETRY_INTERVAL_SECONDS
        bootstrap_mod.retry_host_register(cfg, token_ref)
    attempts = len(sent) - 1
    expected = bootstrap_mod.HOST_RETRY_WINDOW_SECONDS / bootstrap_mod.HOST_RETRY_INTERVAL_SECONDS
    assert 0 < attempts < expected
    assert _recorded(cfg) is None


def test_no_server_host_never_arms_a_retry(agent_cfg, monkeypatch) -> None:
    # The appliance: nothing sent, nothing to confirm.
    _seed(agent_cfg)
    clock = _Clock(monkeypatch)
    sent = _capture(monkeypatch, resp=_Resp())
    (agent_cfg.state_dir / "agent_token.jwt").write_text("")
    bootstrap_mod.ensure_token(agent_cfg)
    clock.now += bootstrap_mod.HOST_RETRY_INTERVAL_SECONDS + 1
    bootstrap_mod.retry_host_register(agent_cfg, ["t"])
    assert len(sent) == 1
