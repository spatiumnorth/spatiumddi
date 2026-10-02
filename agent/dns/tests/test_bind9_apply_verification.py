"""A BIND9 apply is OK only if named is actually serving it (#1224, #1239).

Before this, an apply was reported OK, and committed as last-known-good,
whenever the commands to install it had been sent:

* ``validate()`` ran ``named-checkconf``, which never reads zone files, and
  returned success outright when the checker was missing;
* ``rndc reload <zone>`` only QUEUES the load and exits 0 even for a file
  named cannot parse (verified against BIND 9.20), so a broken zone kept
  serving its old copy, or SERVFAILed if it was new;
* a ``reconfig`` named refused (a cert it could not read) fell back to
  SIGHUP, which named refuses the same way, and the SIGHUP was never checked;
* a named that died on startup read back as started, because a zombie still
  reads ``named`` in ``/proc/<pid>/comm``.

These drive the driver with a scripted ``subprocess.run`` so every one of
those answers can be produced on a machine without BIND. The live half, with
a real ``named-checkzone``, skips where BIND is not installed.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

import pytest

from spatium_dns_agent.config_apply import ConfigApplyError
from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import (
    Bind9Driver,
    _serial_at_least,
    _soa_serial,
    _zonestatus_serial,
)

# A zone named will load: its in-zone NS has an address, without which named
# refuses the zone even under ``check-integrity no`` (verified, BIND 9.20).
SOA = (
    "$TTL 300\n@ IN SOA ns1.{z}. host.{z}. ( {serial} 3600 600 86400 300 )\n"
    "@ IN NS ns1.{z}.\nns1 IN A 192.0.2.53\n"
)


def _zone(
    root: Path, zname: str, serial: int, view: str | None = None, extra: str = ""
) -> Path:
    path = root / "zones" / (view or "") / f"{zname}.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SOA.format(z=zname, serial=serial) + extra)
    return path


class Script:
    """A ``subprocess.run`` stand-in answering by command, recording calls."""

    def __init__(self, answer: Callable[[list[str]], tuple[int, str, str]]):
        self.answer = answer
        self.calls: list[list[str]] = []

    def __call__(
        self, cmd: list[str], *a: Any, **kw: Any
    ) -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        rc, out, err = self.answer(list(cmd))
        return subprocess.CompletedProcess(cmd, rc, out, err)

    def verbs(self, tool: str) -> list[list[str]]:
        return [c for c in self.calls if Path(c[0]).name == tool]


@pytest.fixture
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    """No real waiting: one poll, then the verdict."""
    monkeypatch.setattr(bind9, "_ZONE_LOAD_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9, "_NAMED_START_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9, "_SIGHUP_SETTLE_S", 0.0)
    monkeypatch.setattr(bind9.time, "sleep", lambda _s: None)


def _all_tools(monkeypatch: pytest.MonkeyPatch, *missing: str) -> None:
    monkeypatch.setattr(
        bind9.shutil,
        "which",
        lambda name: None if name in missing else f"/usr/sbin/{name}",
    )


def _stage(tmp_path: Path) -> Path:
    new = tmp_path / "rendered.new"
    new.mkdir(parents=True)
    (new / "named.conf").write_text("options {};\n")
    return new


# ── the helpers the verdict rests on ──────────────────────────────────────────


def test_soa_serial_reads_our_render(tmp_path: Path) -> None:
    assert _soa_serial(_zone(tmp_path, "a.test", 2026092901)) == 2026092901


def test_soa_serial_reads_the_file_named_writes_back_on_freeze(tmp_path: Path) -> None:
    """``freeze`` rewrites a journal-dirty zone in named's own layout."""
    path = tmp_path / "f.db"
    path.write_text(
        "a.test.\t\t\t300 IN SOA\tns1.a.test. host.a.test. (\n"
        "\t\t\t\t77         ; serial\n\t\t\t\t3600       ; refresh (1 hour)\n"
        "\t\t\t\t600 86400 300 )\n"
    )
    assert _soa_serial(path) == 77


def test_soa_serial_is_none_without_an_soa(tmp_path: Path) -> None:
    path = tmp_path / "x.db"
    path.write_text("; nothing here\n")
    assert _soa_serial(path) is None


def test_zonestatus_serial_takes_the_raw_serial_of_a_signed_zone() -> None:
    """Inline-signed zones print the raw serial first, then the signed one;
    the render is the raw zone. Output shape verified against BIND 9.20."""
    out = "name: s.test\ntype: primary\nserial: 2\nsigned serial: 4\nnodes: 3\n"
    assert _zonestatus_serial(out) == 2


def test_serial_comparison_is_rfc1982() -> None:
    assert _serial_at_least(5, 5)
    assert _serial_at_least(6, 5)
    assert not _serial_at_least(4, 5)
    assert _serial_at_least(3, 2**32 - 2), "wraps past 2^32"


# ── #1224: validate reads the zone files ──────────────────────────────────────


def test_validate_fails_closed_without_named_checkconf(
    tmp_path: Path, monkeypatch
) -> None:
    _stage(tmp_path)
    _all_tools(monkeypatch, "named-checkconf")
    with pytest.raises(RuntimeError, match="named-checkconf is not installed"):
        Bind9Driver(tmp_path).validate()


def test_validate_checks_each_changed_zone_with_named_checkzone(
    tmp_path: Path, monkeypatch
) -> None:
    new = _stage(tmp_path)
    live = tmp_path / "rendered"
    _zone(new, "same.test", 1)
    _zone(live, "same.test", 1)
    _zone(new, "edited.test", 2)
    _zone(live, "edited.test", 1)
    _zone(new, "added.test", 1, view="internal")
    _all_tools(monkeypatch)
    run = Script(lambda cmd: (0, "", ""))
    monkeypatch.setattr(subprocess, "run", run)

    Bind9Driver(tmp_path).validate()

    checked = {
        (c[-2], Path(c[-1]).relative_to(new).as_posix())
        for c in run.verbs("named-checkzone")
    }
    assert checked == {
        ("edited.test", "zones/edited.test.db"),
        ("added.test", "zones/internal/added.test.db"),
    }, "an unchanged zone is what named already loaded; only changes are checked"
    for call in run.verbs("named-checkzone"):
        # Must match named's own settings here, or the checker refuses zones
        # named loads: check-integrity is off in the rendered options.
        assert call[1:5] == ["-i", "none", "-k", "fail"]


def test_validate_checks_every_zone_on_a_first_render(
    tmp_path: Path, monkeypatch
) -> None:
    new = _stage(tmp_path)
    _zone(new, "a.test", 1)
    _zone(new, "b.test", 1)
    _all_tools(monkeypatch)
    run = Script(lambda cmd: (0, "", ""))
    monkeypatch.setattr(subprocess, "run", run)

    Bind9Driver(tmp_path).validate()

    assert sorted(c[-2] for c in run.verbs("named-checkzone")) == ["a.test", "b.test"]


def test_a_zone_named_cannot_load_fails_validation(tmp_path: Path, monkeypatch) -> None:
    new = _stage(tmp_path)
    _zone(new, "bad.test", 2)
    _all_tools(monkeypatch)

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if Path(cmd[0]).name == "named-checkzone":
            return (
                1,
                f"dns_rdata_fromtext: {new}/zones/bad.test.db:6: near '999.1.1.1': bad dotted quad\n"
                "zone bad.test/IN: not loaded due to errors.\n",
                "",
            )
        return (0, "", "")

    monkeypatch.setattr(subprocess, "run", Script(answer))
    with pytest.raises(RuntimeError) as exc:
        Bind9Driver(tmp_path).validate()
    message = str(exc.value)
    assert "bad.test" in message and "bad dotted quad" in message
    assert str(new) not in message, "the staging path is noise in an operator message"


def test_validate_fails_closed_without_named_checkzone(
    tmp_path: Path, monkeypatch
) -> None:
    new = _stage(tmp_path)
    _zone(new, "a.test", 1)
    _all_tools(monkeypatch, "named-checkzone")
    monkeypatch.setattr(subprocess, "run", Script(lambda cmd: (0, "", "")))
    with pytest.raises(RuntimeError, match="named-checkzone is not installed"):
        Bind9Driver(tmp_path).validate()


def test_a_bad_zone_is_a_validate_phase_failure(tmp_path: Path, monkeypatch) -> None:
    """Validate, not reload: the daemon was never touched, so the #882 revert
    leaves it alone instead of re-rendering the previous bundle."""
    drv = Bind9Driver(tmp_path)
    monkeypatch.setattr(drv, "render", lambda bundle: None)
    monkeypatch.setattr(
        drv, "validate", lambda: (_ for _ in ()).throw(RuntimeError("bad zone"))
    )
    with pytest.raises(ConfigApplyError) as exc:
        drv.apply_config({})
    assert exc.value.phase == "validate"
    assert exc.value.daemon_disturbed is False


# ── #1224 / #1239: after the swap, named must be serving it ───────────────────


def _running(tmp_path: Path, monkeypatch, zones: dict[str, int]) -> Bind9Driver:
    """A live daemon, and a staged tree holding ``zones`` at those serials."""
    new = _stage(tmp_path)
    for zname, serial in zones.items():
        _zone(new, zname, serial)
    drv = Bind9Driver(tmp_path)
    drv.daemon_pid = 4242
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    return drv


def test_a_reload_that_left_the_old_serial_fails_the_apply(
    tmp_path: Path, monkeypatch, fast
) -> None:
    """The #1224 symptom: reload "succeeded", named still on the old copy."""
    drv = _running(tmp_path, monkeypatch, {"a.test": 2})
    _all_tools(monkeypatch)
    run = Script(
        lambda cmd: (
            (0, "name: a.test\nserial: 1\n", "") if "zonestatus" in cmd else (0, "", "")
        )
    )
    monkeypatch.setattr(subprocess, "run", run)

    with pytest.raises(RuntimeError, match=r"a\.test: serving serial 1, file has 2"):
        drv.swap_and_reload()


def test_a_new_zone_named_did_not_load_fails_the_apply(
    tmp_path: Path, monkeypatch, fast
) -> None:
    drv = _running(tmp_path, monkeypatch, {"new.test": 1})
    _all_tools(monkeypatch)

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if "zonestatus" in cmd:
            return (1, "", "rndc: 'zonestatus' failed: zone not loaded\n")
        return (0, "", "")

    monkeypatch.setattr(subprocess, "run", Script(answer))
    with pytest.raises(RuntimeError, match="zone not loaded"):
        drv.swap_and_reload()


def test_a_loaded_zone_passes(tmp_path: Path, monkeypatch, fast) -> None:
    drv = _running(tmp_path, monkeypatch, {"a.test": 2})
    _all_tools(monkeypatch)
    run = Script(
        lambda cmd: (0, "serial: 2\n", "") if "zonestatus" in cmd else (0, "", "")
    )
    monkeypatch.setattr(subprocess, "run", run)

    drv.swap_and_reload()

    zonestatus = [c for c in run.calls if "zonestatus" in c]
    assert zonestatus and zonestatus[0][-1] == "a.test"


def test_a_later_serial_passes(tmp_path: Path, monkeypatch, fast) -> None:
    """An RFC 2136 update between the reload and the check moves the serial on."""
    drv = _running(tmp_path, monkeypatch, {"a.test": 2})
    _all_tools(monkeypatch)
    serials = iter(["serial: 1\n", "serial: 3\n"])  # before the reload, then after
    monkeypatch.setattr(
        subprocess,
        "run",
        Script(lambda cmd: (0, next(serials), "") if "zonestatus" in cmd else (0, "", "")),
    )
    drv.swap_and_reload()


def test_a_serial_that_was_already_ahead_and_did_not_move_fails(
    tmp_path: Path, monkeypatch, fast
) -> None:
    """RFC 2136 updates had taken named to 108 and the render is 105. Still
    serving 108 afterwards is named on the OLD zone, not a later update, so
    "at least the file's serial" alone would have passed a failed load."""
    drv = _running(tmp_path, monkeypatch, {"a.test": 105})
    _all_tools(monkeypatch)
    monkeypatch.setattr(
        subprocess,
        "run",
        Script(lambda cmd: (0, "serial: 108\n", "") if "zonestatus" in cmd else (0, "", "")),
    )
    with pytest.raises(RuntimeError, match="serving serial 108, file has 105"):
        drv.swap_and_reload()


def test_verification_waits_for_a_queued_load(tmp_path: Path, monkeypatch) -> None:
    """The load is asynchronous: the first answer can still be the old serial."""
    monkeypatch.setattr(bind9.time, "sleep", lambda _s: None)
    drv = _running(tmp_path, monkeypatch, {"a.test": 2})
    _all_tools(monkeypatch)
    answers = iter(["serial: 1\n", "serial: 1\n", "serial: 2\n"])

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        return (0, next(answers), "") if "zonestatus" in cmd else (0, "", "")

    monkeypatch.setattr(subprocess, "run", Script(answer))
    drv.swap_and_reload()


def test_only_changed_zones_are_verified(tmp_path: Path, monkeypatch, fast) -> None:
    drv = _running(tmp_path, monkeypatch, {"same.test": 1, "edited.test": 2})
    prev_live = tmp_path / "rendered"
    _zone(prev_live, "same.test", 1)
    _zone(prev_live, "edited.test", 1)
    _all_tools(monkeypatch)
    serving = {"edited.test": 1}

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if "reload" in cmd:
            serving[cmd[-1]] = 2
        if "zonestatus" in cmd:
            return (0, f"serial: {serving[cmd[-1]]}\n", "")
        return (0, "", "")

    run = Script(answer)
    monkeypatch.setattr(subprocess, "run", run)

    drv.swap_and_reload()

    # Once frozen before the swap (#1407), once after the reload: only the zone
    # that changed.
    assert [c[-1] for c in run.calls if "zonestatus" in c] == ["edited.test", "edited.test"]


def test_a_config_named_refuses_fails_the_apply_instead_of_sighup(
    tmp_path: Path, monkeypatch, fast
) -> None:
    """``reconfig`` exiting 1 with "'reconfig' failed:" is named answering and
    refusing (verified: a TLS cert it cannot read). SIGHUP would be refused
    the same way, so it is not tried."""
    drv = _running(tmp_path, monkeypatch, {})
    _all_tools(monkeypatch)
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(bind9.os, "kill", lambda pid, sig: killed.append((pid, sig)))

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if "reconfig" in cmd:
            return (1, "", "rndc: 'reconfig' failed: TLS error\n")
        return (0, "", "")

    monkeypatch.setattr(subprocess, "run", Script(answer))
    with pytest.raises(
        RuntimeError, match="named rejected the new config: .*TLS error"
    ):
        drv.swap_and_reload()
    assert killed == []


def test_an_unreachable_control_channel_still_falls_back_to_sighup(
    tmp_path: Path, monkeypatch, fast
) -> None:
    drv = _running(tmp_path, monkeypatch, {})
    _all_tools(monkeypatch)
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(bind9.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(
        subprocess,
        "run",
        Script(
            lambda cmd: (
                1,
                "",
                "rndc: connect failed: 127.0.0.1#953: connection refused\n",
            )
        ),
    )

    drv.swap_and_reload()

    assert killed == [(4242, bind9.signal.SIGHUP)]


def test_a_sighup_that_cannot_be_delivered_fails_the_apply(
    tmp_path: Path, monkeypatch, fast
) -> None:
    """``os.kill`` raising means named is gone; it used to be logged and the
    apply reported OK."""
    drv = _running(tmp_path, monkeypatch, {})
    _all_tools(monkeypatch, "rndc")

    def boom(pid: int, sig: int) -> None:
        raise ProcessLookupError(3, "No such process")

    monkeypatch.setattr(bind9.os, "kill", boom)
    with pytest.raises(RuntimeError, match="could not signal named"):
        drv.swap_and_reload()


def test_named_dying_after_sighup_fails_the_apply(
    tmp_path: Path, monkeypatch, fast
) -> None:
    drv = _running(tmp_path, monkeypatch, {})
    _all_tools(monkeypatch, "rndc")
    monkeypatch.setattr(bind9.os, "kill", lambda pid, sig: None)
    alive = iter([True, False])
    monkeypatch.setattr(drv, "daemon_running", lambda: next(alive))
    with pytest.raises(RuntimeError, match="named exited after being told to reload"):
        drv.swap_and_reload()


def test_named_dying_on_first_start_fails_the_apply(
    tmp_path: Path, monkeypatch, fast
) -> None:
    """The deferred first start: named refusing its first config exits, and
    that used to be the end of it."""
    _stage(tmp_path)
    drv = Bind9Driver(tmp_path)
    _all_tools(monkeypatch)
    monkeypatch.setattr(drv, "daemon_running", lambda: False)
    monkeypatch.setattr(drv, "start_daemon", lambda: None)
    monkeypatch.setattr(subprocess, "run", Script(lambda cmd: (0, "", "")))
    with pytest.raises(RuntimeError, match="named exited during startup"):
        drv.swap_and_reload()


def test_a_first_start_that_answers_is_verified(
    tmp_path: Path, monkeypatch, fast
) -> None:
    new = _stage(tmp_path)
    _zone(new, "a.test", 5)
    drv = Bind9Driver(tmp_path)
    _all_tools(monkeypatch)
    monkeypatch.setattr(drv, "start_daemon", lambda: None)
    states = iter([False, True, True])
    monkeypatch.setattr(drv, "daemon_running", lambda: next(states))
    run = Script(
        lambda cmd: (0, "serial: 5\n", "") if "zonestatus" in cmd else (0, "", "")
    )
    monkeypatch.setattr(subprocess, "run", run)

    drv.swap_and_reload()

    verbs = [c[1] if c[1] != "-c" else c[3] for c in run.calls]
    assert verbs == ["status", "zonestatus"], "confirmed up, then its zones checked"


def test_a_reload_failure_is_a_reload_phase_failure(
    tmp_path: Path, monkeypatch
) -> None:
    """Reload phase: the live tree was replaced, so the #882 revert re-renders
    the previous bundle rather than trusting the daemon's state."""
    drv = Bind9Driver(tmp_path)
    monkeypatch.setattr(drv, "render", lambda bundle: None)
    monkeypatch.setattr(drv, "validate", lambda: None)
    monkeypatch.setattr(
        drv,
        "swap_and_reload",
        lambda: (_ for _ in ()).throw(RuntimeError("did not load")),
    )
    with pytest.raises(ConfigApplyError) as exc:
        drv.apply_config({})
    assert exc.value.phase == "reload"
    assert exc.value.daemon_disturbed is True


# ── the real checker ──────────────────────────────────────────────────────────


@pytest.mark.skipif(
    shutil.which("named-checkzone") is None, reason="needs BIND's named-checkzone"
)
def test_the_real_named_checkzone_refuses_a_broken_zone(tmp_path: Path) -> None:
    new = _stage(tmp_path)
    _zone(new, "bad.test", 2, extra="www IN A 999.1.1.1\n")
    _zone(new, "good.test", 1, extra="www IN A 192.0.2.1\nns1 IN A 192.0.2.53\n")
    with pytest.raises(RuntimeError, match="bad.test.*bad dotted quad"):
        Bind9Driver(tmp_path)._check_zone_files(new)


@pytest.mark.skipif(
    shutil.which("named-checkzone") is None, reason="needs BIND's named-checkzone"
)
def test_the_real_named_checkzone_passes_a_zone_named_loads(tmp_path: Path) -> None:
    """An MX and an SRV pointing at in-zone names with no address: named
    loads this (verified), and the checker must too, or it refuses zones
    that serve fine."""
    new = _stage(tmp_path)
    _zone(
        new,
        "ok.test",
        1,
        extra="www IN A 192.0.2.1\n@ IN MX 10 nohost.ok.test.\n"
        "_sip._tcp IN SRV 0 0 5060 nosip.ok.test.\n",
    )
    Bind9Driver(tmp_path)._check_zone_files(new)


@pytest.mark.skipif(
    shutil.which("named-checkzone") is None, reason="needs BIND's named-checkzone"
)
def test_the_real_named_checkzone_refuses_an_ns_without_an_address(
    tmp_path: Path,
) -> None:
    """named will not load this even with ``check-integrity no``, so the
    checker refusing it before the swap is agreeing with named."""
    new = _stage(tmp_path)
    path = new / "zones" / "nons.test.db"
    path.parent.mkdir(parents=True)
    path.write_text(
        "$TTL 300\n@ IN SOA ns1.nons.test. h.nons.test. ( 1 3600 600 86400 300 )\n"
        "@ IN NS ns1.nons.test.\n"
    )
    with pytest.raises(RuntimeError, match="has no address records"):
        Bind9Driver(tmp_path)._check_zone_files(new)
