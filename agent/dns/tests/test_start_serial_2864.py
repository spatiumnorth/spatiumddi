"""A zone's served serial never steps back across an agent start (#2864).

At a start named is not running, so nothing freezes the zone or moves the
render past the serial named served (``_freeze_and_wait`` does that on a
running named). The render carries the control plane's ``last_serial``; if
named had served a later one (an RFC 2136 update moved it, or an earlier
apply moved it past), the zone went backwards, and a secondary holding the
later serial stopped transferring it. Now the serial named last served is
read from the previous live copy, and the render is served at it when the
data is the same, one past it when not.

Scripted ``subprocess.run``, as in ``test_dynamic_records_carry_2850``; the
live half is in ``live_dynamic_restart_check.py``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _soa_serial

ZONE = "st.test"


def _canonical(serial: int, www: str = "192.0.2.1") -> str:
    """A render of ``_bundle`` as ``named-compilezone -s full`` prints it."""
    return (
        f"st.test.\t3600 IN SOA\tns1.st.test. admin.st.test. {serial} 3600 600 86400 300\n"
        "st.test.\t3600 IN NS\tns1.st.test.\n"
        "ns1.st.test.\t3600 IN A\t127.0.0.1\n"
        f"www.st.test.\t300 IN A\t{www}\n"
    )


def _bundle(
    serial: int = 5, www: str = "192.0.2.1", view: str | None = None
) -> dict[str, Any]:
    zone: dict[str, Any] = {
        "name": ZONE + ".",
        "type": "primary",
        "ttl": 3600,
        "serial": serial,
        "dynamic_update_enabled": False,
        "update_acl": [],
        "records": [{"name": "www", "type": "A", "value": www, "ttl": 300}],
    }
    bundle: dict[str, Any] = {
        "options": {"forwarders": [], "recursion_enabled": False},
        "tsig_keys": [],
        "zones": [zone],
    }
    if view:
        zone["view_name"] = view
        bundle["views"] = [{"name": view, "match_clients": ["any"]}]
    return bundle


class Checker:
    """``named-compilezone`` answering per file: the live copy (with its
    journal) reads as ``live``, the signed copy as ``signed``, a staged file
    as ``staged``. ``None`` fails the read."""

    def __init__(self, live: str | None, staged: str, signed: str | None = None):
        self.live, self.staged, self.signed = live, staged, signed
        self.calls: list[list[str]] = []

    def __call__(
        self, cmd: list[str], *a: Any, **kw: Any
    ) -> subprocess.CompletedProcess:
        cmd = list(cmd)
        self.calls.append(cmd)
        if Path(cmd[0]).name != "named-compilezone":
            return subprocess.CompletedProcess(cmd, 0, "", "")
        source = cmd[-1]
        if "raw" in cmd:
            text = self.signed
        elif "rendered.new" in source:
            text = self.staged
        else:
            text = self.live
        if text is None:
            return subprocess.CompletedProcess(cmd, 1, "", "failed")
        Path(cmd[cmd.index("-o") + 1]).write_text(text)
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture
def driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bind9Driver:
    monkeypatch.setattr(bind9.shutil, "which", lambda name: f"/usr/sbin/{name}")
    drv = Bind9Driver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "daemon_running", lambda: False)
    monkeypatch.setattr(drv, "start_daemon", lambda: None)
    monkeypatch.setattr(drv, "_await_named_started", lambda: False)
    return drv


def _named_was_at(drv: Bind9Driver, view: str | None = None) -> Path:
    """The last start's tree; named took an update since (a journal)."""
    drv.render(_bundle(view=view))
    live = drv.state_dir / "rendered"
    (drv.state_dir / "rendered.new").rename(live)
    zone_file = live / "zones" / (f"{view}/" if view else "") / f"{ZONE}.db"
    zone_file.with_name(zone_file.name + ".jnl").write_bytes(b"journal")
    return zone_file


def _start(drv: Bind9Driver, bundle: dict[str, Any]) -> None:
    drv.render(bundle)
    drv.swap_and_reload()


def test_a_start_keeps_named_serial_for_the_same_data(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone_file = _named_was_at(driver)
    monkeypatch.setattr(bind9.subprocess, "run", Checker(_canonical(9), _canonical(5)))
    _start(driver, _bundle())
    assert _soa_serial(zone_file) == 9


def test_a_start_with_new_data_serves_one_past_named(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone_file = _named_was_at(driver)
    monkeypatch.setattr(
        bind9.subprocess, "run", Checker(_canonical(9), _canonical(5, www="192.0.2.2"))
    )
    _start(driver, _bundle(www="192.0.2.2"))
    assert _soa_serial(zone_file) == 10


def test_a_render_already_later_keeps_its_own_serial(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone_file = _named_was_at(driver)
    monkeypatch.setattr(bind9.subprocess, "run", Checker(_canonical(9), _canonical(20)))
    _start(driver, _bundle(serial=20))
    assert _soa_serial(zone_file) == 20


def test_named_dump_without_a_journal_is_read_directly(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """named wrote the zone out (serial 9) and dropped the journal: the file
    itself says what it served."""
    zone_file = _named_was_at(driver)
    zone_file.with_name(zone_file.name + ".jnl").unlink()
    zone_file.write_text(_canonical(9))
    monkeypatch.setattr(bind9.subprocess, "run", Checker(_canonical(9), _canonical(5)))
    _start(driver, _bundle())
    assert _soa_serial(zone_file) == 9


def test_a_view_zone_does_not_go_back(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone_file = _named_was_at(driver, view="v1")
    monkeypatch.setattr(bind9.subprocess, "run", Checker(_canonical(9), _canonical(5)))
    _start(driver, _bundle(view="v1"))
    assert _soa_serial(zone_file) == 9


def test_an_inline_signed_zone_does_not_go_back_below_its_signed_serial(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-signing moves the signed serial on its own; that is what a
    secondary holds, and the swap sets the signed copy aside."""
    zone_file = _named_was_at(driver)
    zone_file.with_name(zone_file.name + ".signed").write_bytes(b"raw")
    monkeypatch.setattr(
        bind9.subprocess,
        "run",
        Checker(_canonical(9), _canonical(5), signed=_canonical(15)),
    )
    _start(driver, _bundle())
    assert _soa_serial(zone_file) == 15


def test_an_unreadable_previous_copy_keeps_the_render(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No serial to compare with is no reason to hold the zone back."""
    zone_file = _named_was_at(driver)
    monkeypatch.setattr(bind9.subprocess, "run", Checker(None, _canonical(5)))
    _start(driver, _bundle())
    assert _soa_serial(zone_file) == 5
    assert driver.held_back == ()


def test_a_running_named_is_left_to_the_freeze(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a running named the freeze decides; nothing is read back here."""
    _named_was_at(driver)
    checker = Checker(_canonical(9), _canonical(5))
    monkeypatch.setattr(bind9.subprocess, "run", checker)
    monkeypatch.setattr(driver, "daemon_running", lambda: True)
    monkeypatch.setattr(driver, "_freeze_before_swap", lambda *a, **kw: {})
    monkeypatch.setattr(driver, "_signal_reload", lambda *a, **kw: None)
    _start(driver, _bundle())
    assert [c for c in checker.calls if Path(c[0]).name == "named-compilezone"] == []
