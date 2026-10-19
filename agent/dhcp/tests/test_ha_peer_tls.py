"""Kea HA peers authenticate to each other with the group's credential.

The control plane ships the group's CA / peer certificate / key in
``failover.tls``. The agent writes them to ``<state_dir>/ha-tls`` (0600) and
renders the HA relationship with ``trust-anchor`` / ``cert-file`` /
``key-file`` + ``require-client-certs``, which is what makes Kea's dedicated
HA listener refuse a client that does not hold a certificate from the group's
CA. These tests assert on the rendered document, the files on disk, the logs
and the heartbeat body.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any, Self

import pytest
import structlog
from spatium_dhcp_agent import heartbeat as heartbeat_mod
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.heartbeat import HeartbeatClient
from spatium_dhcp_agent.render_kea import render
from spatium_dhcp_agent.sync import SyncLoop

KEY_MARKER = "MHcCAQEEIKEYBODYMARKERthatmustnevershowupanywhere"
CRED = {
    "ca_pem": "-----BEGIN CERTIFICATE-----\nQ0EtTUFSS0VS\n-----END CERTIFICATE-----\n",
    "cert_pem": "-----BEGIN CERTIFICATE-----\nTEVBRi1NQVJLRVI=\n-----END CERTIFICATE-----\n",
    "key_pem": f"-----BEGIN PRIVATE KEY-----\n{KEY_MARKER}\n-----END PRIVATE KEY-----\n",
}


def _bundle(tls: dict[str, str] | None) -> dict[str, Any]:
    failover: dict[str, Any] = {
        "channel_id": "g",
        "channel_name": "g",
        "this_server_name": "a",
        "mode": "hot-standby",
        "peers": [
            {"name": "a", "url": "http://10.0.0.1:8000/", "role": "primary"},
            {"name": "b", "url": "http://10.0.0.2:8000/", "role": "standby"},
        ],
    }
    if tls is not None:
        failover["tls"] = tls
    return {
        "server": {"name": "a", "interfaces": ["eth0"]},
        "global_options": {},
        "scopes": [],
        "failover": failover,
    }


def _relationship(dhcp4: dict[str, Any]) -> dict[str, Any]:
    hook = next(
        h for h in dhcp4["hooks-libraries"] if h["library"].endswith("libdhcp_ha.so")
    )
    return hook["parameters"]["high-availability"][0]


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []


# ── rendering ────────────────────────────────────────────────────────────────


def test_credential_renders_tls_with_client_certificates_required():
    rel = _relationship(render(_bundle(CRED), ha_tls_dir="/state/ha-tls")["Dhcp4"])
    assert rel["trust-anchor"] == "/state/ha-tls/ca.pem"
    assert rel["cert-file"] == "/state/ha-tls/cert.pem"
    assert rel["key-file"] == "/state/ha-tls/key.pem"
    # The entry for this server builds Kea's SERVER context with
    # cert_required = require-client-certs: the listener refuses a client
    # with no certificate from the group's CA.
    assert rel["require-client-certs"] is True
    assert rel["restrict-commands"] is True
    # Both peers, including this server's own entry (which is where the
    # listener's address and scheme come from), speak https.
    assert [p["url"] for p in rel["peers"]] == [
        "https://10.0.0.1:8000/",
        "https://10.0.0.2:8000/",
    ]


def test_credential_material_is_referenced_by_path_never_inlined():
    doc = json.dumps(render(_bundle(CRED), ha_tls_dir="/state/ha-tls"))
    assert KEY_MARKER not in doc
    assert "BEGIN" not in doc


def test_without_a_credential_the_ha_config_stays_plaintext():
    """A bundle from a control plane that has not opened the gate (an older
    peer in the group) renders exactly the plaintext relationship the
    partner's older agent also renders, so the pair keeps talking. The same
    group with the credential renders TLS."""
    plain = _relationship(render(_bundle(None))["Dhcp4"])
    for key in ("trust-anchor", "cert-file", "key-file", "require-client-certs"):
        assert key not in plain
    assert [p["url"] for p in plain["peers"]] == [
        "http://10.0.0.1:8000/",
        "http://10.0.0.2:8000/",
    ]
    tls = _relationship(render(_bundle(CRED))["Dhcp4"])
    assert tls["require-client-certs"] is True
    # Apart from the TLS keys and the URL scheme, the two are identical.
    assert {
        k: v
        for k, v in tls.items()
        if k
        not in (
            "trust-anchor",
            "cert-file",
            "key-file",
            "require-client-certs",
            "peers",
        )
    } == {k: v for k, v in plain.items() if k != "peers"}


@pytest.mark.parametrize("missing", ["ca_pem", "cert_pem", "key_pem"])
def test_only_a_complete_credential_renders_tls(missing):
    """Kea refuses a relationship with only some of the three TLS paths, so a
    partial credential must not produce one; the complete one must."""
    partial = {k: v for k, v in CRED.items() if k != missing}
    assert "trust-anchor" not in _relationship(render(_bundle(partial))["Dhcp4"])
    assert "trust-anchor" in _relationship(render(_bundle(CRED))["Dhcp4"])


# ── applying: files on disk, config on disk, logs ────────────────────────────


def test_apply_writes_private_credential_files_the_config_points_at(
    agent_cfg: AgentConfig,
):
    loop = SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())
    loop._apply_bundle({"bundle": _bundle(CRED)}, reload_kea=False)

    tls_dir = agent_cfg.state_dir / "ha-tls"
    written = json.loads(agent_cfg.kea_config_path.read_text())
    rel = _relationship(written["Dhcp4"])
    assert rel["require-client-certs"] is True
    for key, name, field in (
        ("trust-anchor", "ca.pem", "ca_pem"),
        ("cert-file", "cert.pem", "cert_pem"),
        ("key-file", "key.pem", "key_pem"),
    ):
        path = Path(rel[key])
        assert path == tls_dir / name
        assert path.read_text() == CRED[field]
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert KEY_MARKER not in agent_cfg.kea_config_path.read_text()
    for f in (agent_cfg.state_dir / "rendered").glob("*"):
        assert KEY_MARKER not in f.read_text()


def test_dropping_the_credential_removes_the_files(agent_cfg: AgentConfig):
    loop = SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())
    loop._apply_bundle({"bundle": _bundle(CRED)}, reload_kea=False)
    tls_dir = agent_cfg.state_dir / "ha-tls"
    assert (tls_dir / "key.pem").exists()
    loop._apply_bundle({"bundle": _bundle(None)}, reload_kea=False)
    assert not any(tls_dir.glob("*.pem"))
    rel = _relationship(json.loads(agent_cfg.kea_config_path.read_text())["Dhcp4"])
    assert "key-file" not in rel


def test_the_key_never_reaches_the_logs(agent_cfg: AgentConfig):
    loop = SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())
    with structlog.testing.capture_logs() as logs:
        loop._apply_bundle({"bundle": _bundle(CRED)}, reload_kea=False)
    assert logs, "expected the apply to log something"
    # The key really was handled on this apply (it is on disk) ...
    assert KEY_MARKER in (agent_cfg.state_dir / "ha-tls" / "key.pem").read_text()
    # ... and no log event carries it.
    assert KEY_MARKER not in repr(logs)


# ── advertising the capability ───────────────────────────────────────────────


class _Resp:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text

    def json(self) -> dict[str, Any]:
        return {}


class _Client:
    def __init__(self, sent: list[dict[str, Any]], refuse_field: str | None) -> None:
        self.sent = sent
        self.refuse_field = refuse_field

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> _Resp:
        self.sent.append(dict(json))
        if self.refuse_field and self.refuse_field in json:
            return _Resp(
                422, f'{{"detail":[{{"loc":["body","{self.refuse_field}"]}}]}}'
            )
        return _Resp(200)


def _heartbeat(agent_cfg: AgentConfig, monkeypatch, refuse_field: str | None):
    sent: list[dict[str, Any]] = []
    hb = HeartbeatClient(agent_cfg, token_ref=["t"])
    monkeypatch.setattr(hb, "_client", lambda: _Client(sent, refuse_field))
    monkeypatch.setattr(heartbeat_mod.kea_ctrl, "version_get", lambda _sock: "3.0.3")
    return hb, sent


def test_heartbeat_advertises_the_ha_peer_tls_capability(agent_cfg, monkeypatch):
    hb, sent = _heartbeat(agent_cfg, monkeypatch, refuse_field=None)
    hb.send_once()
    assert sent[-1]["capabilities"] == ["ha_peer_tls"]


def test_heartbeat_drops_the_field_for_a_control_plane_that_refuses_it(
    agent_cfg, monkeypatch
):
    """A control plane that predates the field answers 422 (its heartbeat
    model forbids unknown keys); the agent keeps its liveness signal."""
    hb, sent = _heartbeat(agent_cfg, monkeypatch, refuse_field="capabilities")
    hb.send_once()
    assert "capabilities" in sent[0]
    assert "capabilities" not in sent[-1]
    hb.send_once()
    assert "capabilities" not in sent[-1]


def test_heartbeat_offers_the_field_again_once_the_control_plane_is_upgraded(
    agent_cfg, monkeypatch
):
    """An agent that came up against an older api pod mid-upgrade must not
    keep the HA peer-credential gate shut until it is restarted."""
    now = [1000.0]
    monkeypatch.setattr(heartbeat_mod.time, "monotonic", lambda: now[0])
    hb, sent = _heartbeat(agent_cfg, monkeypatch, refuse_field="capabilities")
    hb.send_once()
    assert "capabilities" not in sent[-1]

    # The control plane is upgraded; the agent keeps its token, so it never
    # re-registers. Its next heartbeats still leave the field out for a while…
    monkeypatch.setattr(hb, "_client", lambda: _Client(sent, None))
    now[0] += heartbeat_mod.CAPABILITIES_RETRY_SECONDS / 2
    hb.send_once()
    assert "capabilities" not in sent[-1]
    # …and then offer it again, which the upgraded control plane accepts.
    now[0] += heartbeat_mod.CAPABILITIES_RETRY_SECONDS
    hb.send_once()
    assert sent[-1]["capabilities"] == ["ha_peer_tls"]
    hb.send_once()
    assert sent[-1]["capabilities"] == ["ha_peer_tls"]


def test_a_url_without_a_port_keeps_its_port_under_https():
    """``http://h/`` meant port 80; Kea reads ``https://h/`` as 443. The
    firewall rule is computed from the stored URL, so the port must not move."""
    b = _bundle(CRED)
    b["failover"]["peers"][0]["url"] = "http://10.0.0.1/"
    b["failover"]["peers"][1]["url"] = "http://[2001:db8::2]/"
    rel = _relationship(render(b)["Dhcp4"])
    assert [p["url"] for p in rel["peers"]] == [
        "https://10.0.0.1:80/",
        "https://[2001:db8::2]:80/",
    ]
