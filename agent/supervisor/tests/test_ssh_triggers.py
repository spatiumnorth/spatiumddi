"""Supervisor SSH config-reload trigger writer + key-count reader (#157).

Covers the appliance-only gate, the payload shape (6 header lines + the two
concatenated bodies), hash-based idempotency, the host-side lockout-safety
refusal, and the ``read_ssh_key_count`` sidecar parser. The actual sshd
reload is the host-side runner (spatiumddi-ssh-reload).
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state


@pytest.fixture
def ssh_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(
        appliance_state, "_SSH_TRIGGER_FILE", tmp_path / "ssh-config-pending"
    )
    monkeypatch.setattr(
        appliance_state, "_SSH_HASH_SIDECAR", tmp_path / "ssh-config-hash"
    )
    monkeypatch.setattr(
        appliance_state, "_SSH_KEY_COUNT_SIDECAR", tmp_path / "ssh-key-count"
    )
    return tmp_path


_AUTH_KEYS = "# Managed by SpatiumDDI\nssh-ed25519 AAAA op@host\n"
_SSHD_CONF = "Port 2222\nPasswordAuthentication yes\nPermitRootLogin no\n"
_BLOCK = {
    "enabled": True,
    "config_hash": "abc123",
    "authorized_keys": _AUTH_KEYS,
    "sshd_conf": _SSHD_CONF,
    "ssh_port": 2222,
    "allowed_source_networks": ["10.0.0.0/24"],
    "password_auth": True,
    "key_count": 1,
}


def test_enabled_writes_payload(ssh_paths: Path) -> None:
    assert appliance_state.maybe_fire_ssh_reload(_BLOCK) is True
    body = (ssh_paths / "ssh-config-pending").read_text()
    lines = body.split("\n")
    assert lines[0] == "enabled"
    assert lines[1] == "abc123"
    assert lines[2] == "2222"
    assert json.loads(lines[3]) == ["10.0.0.0/24"]
    assert lines[4] == "1"  # password auth on
    ak_len = int(lines[5])
    # The header is 6 lines; the rest is authorized_keys ++ sshd_conf.
    rest = body.split("\n", 6)[6]
    assert rest.encode("utf-8")[:ak_len].decode("utf-8") == _AUTH_KEYS
    assert rest.encode("utf-8")[ak_len:].decode("utf-8") == _SSHD_CONF


def test_trigger_is_owner_only(ssh_paths: Path) -> None:
    # _fire_host_config writes secret-bearing payloads (here the sshd
    # config; for the APT/SNMP planes, mirror passwords + the SNMP
    # community) into the shared release-state dir, so the trigger
    # file must land 0o600 with no world-readable window (sec scanning #82).
    assert appliance_state.maybe_fire_ssh_reload(_BLOCK) is True
    mode = stat.S_IMODE((ssh_paths / "ssh-config-pending").stat().st_mode)
    assert mode == 0o600


def test_idempotent_until_consumed(ssh_paths: Path) -> None:
    assert appliance_state.maybe_fire_ssh_reload(_BLOCK) is True
    assert appliance_state.maybe_fire_ssh_reload(_BLOCK) is False


def test_hash_unchanged_does_not_fire(ssh_paths: Path) -> None:
    (ssh_paths / "ssh-config-hash").write_text("abc123\n")
    assert appliance_state.maybe_fire_ssh_reload(_BLOCK) is False
    assert not (ssh_paths / "ssh-config-pending").exists()


def test_lockout_payload_refused(ssh_paths: Path) -> None:
    # Password auth off + zero keys → host-side guard refuses to write.
    unsafe = {
        **_BLOCK,
        "config_hash": "deadbeef",
        "password_auth": False,
        "key_count": 0,
    }
    assert appliance_state.maybe_fire_ssh_reload(unsafe) is False
    assert not (ssh_paths / "ssh-config-pending").exists()


def test_disabled_block_fires_when_previously_applied(ssh_paths: Path) -> None:
    (ssh_paths / "ssh-config-hash").write_text("abc123\n")
    disabled = {
        "enabled": False,
        "config_hash": "",
        "authorized_keys": "",
        "sshd_conf": "",
        "ssh_port": 22,
        "allowed_source_networks": [],
        "password_auth": True,
        "key_count": 0,
    }
    assert appliance_state.maybe_fire_ssh_reload(disabled) is True
    body = (ssh_paths / "ssh-config-pending").read_text()
    assert body.split("\n")[0] == "disabled"


def test_non_appliance_no_op(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(
        appliance_state, "_SSH_TRIGGER_FILE", tmp_path / "ssh-config-pending"
    )
    assert appliance_state.maybe_fire_ssh_reload(_BLOCK) is False
    assert not (tmp_path / "ssh-config-pending").exists()


def test_read_ssh_key_count_parses_sidecar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sidecar = tmp_path / "ssh-key-count"
    monkeypatch.setattr(appliance_state, "_SSH_KEY_COUNT_SIDECAR", sidecar)
    # Missing sidecar → None (backend leaves the column alone).
    assert appliance_state.read_ssh_key_count() is None
    sidecar.write_text("3\n")
    assert appliance_state.read_ssh_key_count() == 3
    sidecar.write_text("0\n")
    assert appliance_state.read_ssh_key_count() == 0
    # Garbage → None.
    sidecar.write_text("nope\n")
    assert appliance_state.read_ssh_key_count() is None
