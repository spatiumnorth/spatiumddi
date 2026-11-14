"""An existing Technitium ``webservice.config`` is rewritten to loopback before the daemon starts."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

import pytest

from spatium_dns_agent.drivers import technitium as mod


def _addr(a: str) -> bytes:
    ip = ipaddress.ip_address(a)
    return bytes([1 if ip.version == 4 else 2]) + ip.packed


def _config(addrs: list[str], version: int = 4) -> bytes:
    head = b"WC" + bytes([version]) + struct.pack("<ii", 5380, 53443)
    return head + bytes([len(addrs)]) + b"".join(_addr(a) for a in addrs) + b"\x00TAIL-BYTES"


def test_wide_bind_becomes_loopback(tmp_path: Path) -> None:
    f = tmp_path / "webservice.config"
    f.write_bytes(_config(["0.0.0.0", "::"]))
    assert mod.pin_stored_web_service_bind(tmp_path) is True
    assert f.read_bytes() == _config(["127.0.0.1"])
    assert (tmp_path / "webservice.config.spatium-bak").read_bytes() == _config(["0.0.0.0", "::"])
    assert not (tmp_path / "webservice.config.spatium-tmp").exists()


def test_empty_address_list_becomes_loopback(tmp_path: Path) -> None:
    f = tmp_path / "webservice.config"
    f.write_bytes(_config([], version=3))
    assert mod.pin_stored_web_service_bind(tmp_path) is True
    assert f.read_bytes() == _config(["127.0.0.1"], version=3)


def test_already_loopback_is_untouched(tmp_path: Path) -> None:
    f = tmp_path / "webservice.config"
    f.write_bytes(_config(["127.0.0.1"]))
    assert mod.pin_stored_web_service_bind(tmp_path) is False
    assert not (tmp_path / "webservice.config.spatium-bak").exists()


def test_unknown_format_is_left_alone(tmp_path: Path) -> None:
    f = tmp_path / "webservice.config"
    for blob in (
        b"",
        b"XX\x04" + b"\x00" * 20,
        _config(["0.0.0.0"], version=9),
        _config(["::"])[:14],
    ):
        f.write_bytes(blob)
        assert mod.pin_stored_web_service_bind(tmp_path) is False
        assert f.read_bytes() == blob


def test_missing_file_is_fine(tmp_path: Path) -> None:
    assert mod.pin_stored_web_service_bind(tmp_path) is False


def test_daemon_is_not_spawned_until_the_stored_bind_is_loopback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "etc-dns"
    cfg.mkdir()
    (cfg / "webservice.config").write_bytes(_config(["0.0.0.0", "::"]))
    seen: list[bytes] = []

    class _P:
        pid = 4242

    def popen(*_a: object, **_k: object) -> _P:
        seen.append((cfg / "webservice.config").read_bytes())
        return _P()

    monkeypatch.setattr(mod, "_CONFIG_DIR", cfg)
    monkeypatch.setattr(mod.shutil, "which", lambda _n: "/usr/bin/dotnet")
    monkeypatch.setattr(mod, "find_running_daemon", lambda _n: None)
    monkeypatch.setattr(mod.subprocess, "Popen", popen)
    d = mod.TechnitiumDriver(state_dir=tmp_path)
    monkeypatch.setattr(d, "admin_bootstrap_password", lambda: "x")
    d.start_daemon()
    assert seen == [_config(["127.0.0.1"])]
