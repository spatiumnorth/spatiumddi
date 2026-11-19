"""radvd apply/stop lifecycle on the DHCP agent (issue #524).

Covers the "disable RA actually stops radvd" fix: an empty ``radvd_conf`` is an
intentional disable (last RA scope turned off, or the ``ipv6.router_advertisements``
feature module toggled off), so ``apply_radvd`` must SIGTERM radvd and blank the
managed config rather than leaving stale RAs advertised.
"""

from __future__ import annotations

import signal

import spatium_dhcp_agent.radvd_apply as ra


def _env(monkeypatch, tmp_path, *, managed: bool = True) -> tuple:
    cfg = tmp_path / "radvd.conf"
    pidfile = tmp_path / "radvd.pid"
    monkeypatch.setenv("RADVD_MANAGED", "1" if managed else "0")
    monkeypatch.setenv("RADVD_CONFIG_PATH", str(cfg))
    monkeypatch.setenv("RADVD_PIDFILE", str(pidfile))
    return cfg, pidfile


def test_empty_config_stops_radvd(monkeypatch, tmp_path) -> None:
    cfg, pidfile = _env(monkeypatch, tmp_path)
    cfg.write_text("interface eth0 { ... };\n")  # last-good config still on disk
    pidfile.write_text("4242\n")

    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(ra.os, "kill", lambda pid, sig: killed.append((pid, sig)))

    ra.apply_radvd("")  # empty → intentional disable

    assert killed == [(4242, signal.SIGTERM)]
    # Managed config blanked so the disable is durable across restarts.
    assert cfg.read_text() == ""


def test_whitespace_config_stops_radvd(monkeypatch, tmp_path) -> None:
    _cfg, pidfile = _env(monkeypatch, tmp_path)
    pidfile.write_text("77\n")
    killed: list[int] = []
    monkeypatch.setattr(ra.os, "kill", lambda pid, sig: killed.append(pid))
    ra.apply_radvd("   \n  ")
    assert killed == [77]


def test_empty_config_no_pidfile_is_noop(monkeypatch, tmp_path) -> None:
    _env(monkeypatch, tmp_path)  # no pidfile written → radvd not running
    called: list = []
    monkeypatch.setattr(ra.os, "kill", lambda *a: called.append(a))
    ra.apply_radvd("")  # must not raise, must not kill
    assert called == []


def test_not_managed_is_noop(monkeypatch, tmp_path) -> None:
    cfg, pidfile = _env(monkeypatch, tmp_path, managed=False)
    pidfile.write_text("9\n")
    called: list = []
    monkeypatch.setattr(ra.os, "kill", lambda *a: called.append(a))
    ra.apply_radvd("")
    ra.apply_radvd("interface eth0 {};")
    assert called == []
    assert not cfg.exists()


def test_stop_already_gone_pid_blanks_config(monkeypatch, tmp_path) -> None:
    cfg, pidfile = _env(monkeypatch, tmp_path)
    cfg.write_text("stale\n")
    pidfile.write_text("123\n")

    def _raise(pid, sig):
        raise ProcessLookupError()

    monkeypatch.setattr(ra.os, "kill", _raise)
    ra.apply_radvd("")  # process already dead → treated as stopped
    assert cfg.read_text() == ""


def test_failed_validation_leaves_live_file_untouched(monkeypatch, tmp_path) -> None:
    """GHSA-6235-5gh6-4hr2: a rejected config must never replace a working one."""
    cfg, pidfile = _env(monkeypatch, tmp_path)
    cfg.write_text("interface eth0 { AdvSendAdvert on; };\n")
    pidfile.write_text("5\n")
    killed: list = []
    monkeypatch.setattr(ra.os, "kill", lambda *a: killed.append(a))
    monkeypatch.setattr(ra, "_validate", lambda path: False)

    ra.apply_radvd("interface eth0 { BOGUS; };\n")

    assert cfg.read_text() == "interface eth0 { AdvSendAdvert on; };\n"
    assert killed == []
    assert [p.name for p in tmp_path.iterdir() if p.name != "radvd.pid"] == [
        "radvd.conf"
    ]


def test_valid_config_is_swapped_in_and_reloaded(monkeypatch, tmp_path) -> None:
    cfg, pidfile = _env(monkeypatch, tmp_path)
    cfg.write_text("old\n")
    pidfile.write_text("5\n")
    seen: list[str] = []

    def fake_validate(path) -> bool:
        seen.append(path.read_text())
        assert path != cfg  # validated while still staged
        return True

    killed: list = []
    monkeypatch.setattr(ra, "_validate", fake_validate)
    monkeypatch.setattr(ra.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    ra.apply_radvd("new\n")
    assert seen == ["new\n"]
    assert cfg.read_text() == "new\n"
    assert killed == [(5, signal.SIGHUP)]
