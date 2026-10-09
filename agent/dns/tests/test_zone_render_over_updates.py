"""A zone re-render lands over the RFC 2136 updates named holds (#1407).

named keeps an RFC 2136 update in memory and in the zone's journal, and writes
it into the zone's file up to 15 minutes later. ``rndc freeze`` makes it write
the zone out at once, but asynchronously: the command answers when the write is
queued. ``swap_and_reload`` used to swap the new render in first and freeze the
zone after, so a zone holding updates had named's own copy written over the
render, and the thaw loaded that copy: a zone-level change (TTL, SOA timers,
apex) was dropped, and the served serial went backwards (seen live on
nightly-2026.09.30, f838ab85). Each changed zone named serves is now frozen
before the swap, and the swap waits until the write has landed on the file
being replaced.

These drive the driver against a scripted named that models exactly that: a
zone's serving serial, whether it holds an update its file lacks, a write that
lands only once the agent waits (``time.sleep``), at whatever path the zone's
file has then, and a load that reads the file.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _soa_serial

ZONE = "lab.test"


def _render_text(serial: int, ttl: int = 3600, extra: str = "") -> str:
    """A zone file in the shape ``_write_zone_file`` writes."""
    return (
        f"$TTL {ttl}\n@ IN SOA ns1.{ZONE}. host.{ZONE}. ( {serial} 3600 600 86400 300 )\n"
        f"@ IN NS ns1.{ZONE}.\nns1 IN A 192.0.2.53\n{extra}"
    )


def _dump_text(serial: int, ttl: int = 3600) -> str:
    """The shape named writes a zone back in (owner and TTL spelled out, the
    serial on a line of its own)."""
    return (
        f"$TTL {ttl}\t; 1 hour\n{ZONE}.\t\tIN SOA\tns1.{ZONE}. host.{ZONE}. (\n"
        f"\t\t\t\t{serial} ; serial\n\t\t\t\t3600 600 86400 300 )\n"
        f"\t\t\tNS\tns1.{ZONE}.\nfrom-rfc2136.{ZONE}. A 192.0.2.99\n"
    )


class _Named:
    """``subprocess.run`` for rndc, answering as one zone's named would."""

    def __init__(self, tmp: Path, *, serving: int, held: bool, writes: bool = True,
                 freeze_rc: int = 0, reconfig: tuple[int, str] = (0, "")):
        self.tmp = tmp
        self.serving = serving          # the serial named serves
        self.held = held                # it holds an update its file lacks
        self.writes = writes            # a queued write ever lands
        self.freeze_rc = freeze_rc
        self.reconfig = reconfig
        self.frozen = False
        self.queued = False             # a write was queued by a freeze
        self.calls: list[list[str]] = []
        self.landed_after: list[str] | None = None   # the rndc verbs sent before it

    def file(self) -> Path:
        return self.tmp / "rendered" / "zones" / f"{ZONE}.db"

    def tick(self, _s: float = 0.0) -> None:
        """Time passes: a queued write lands, on the zone's file AS IT IS NOW."""
        if self.queued and self.writes:
            self.file().write_text(_dump_text(self.serving))
            self.landed_after = self.verbs()
            self.queued = False
            self.held = False

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls]

    def __call__(self, cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        verb = cmd[1]
        if verb == "reconfig":
            rc, err = self.reconfig
            return subprocess.CompletedProcess(cmd, rc, "", err)
        if verb == "freeze":
            if self.freeze_rc:
                return subprocess.CompletedProcess(cmd, self.freeze_rc, "", "not dynamic")
            self.frozen = True
            if self.held:
                self.queued = True
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if verb == "reload":
            serial = _soa_serial(self.file())
            if serial is not None:
                self.serving = serial
            return subprocess.CompletedProcess(cmd, 0, "zone reload queued", "")
        if verb == "thaw":
            self.frozen = False
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if verb == "zonestatus":
            return subprocess.CompletedProcess(cmd, 0, f"name: {ZONE}\nserial: {self.serving}\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bind9, "_ZONE_LOAD_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9.shutil, "which", lambda name: f"/usr/sbin/{name}")


def _driver(tmp: Path, monkeypatch, named: _Named, *, live: int | None, staged: int,
            ttl: int = 1800) -> Bind9Driver:
    """A live tree holding the zone at serial ``live`` (None: no file of it), and
    a staged render of it at ``staged`` with the zone TTL edited."""
    (tmp / "rendered" / "zones").mkdir(parents=True)
    if live is not None:
        named.file().write_text(_render_text(live))
    new = tmp / "rendered.new" / "zones"
    new.mkdir(parents=True)
    (new / f"{ZONE}.db").write_text(_render_text(staged, ttl=ttl))
    drv = Bind9Driver(tmp)
    drv.daemon_pid = 4242
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    monkeypatch.setattr(subprocess, "run", named)
    monkeypatch.setattr(bind9.time, "sleep", named.tick)
    return drv


def test_a_zone_holding_updates_is_written_out_before_the_render_goes_in(
    tmp_path: Path, monkeypatch, quick
) -> None:
    named = _Named(tmp_path, serving=8, held=True)
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=9)
    # The dump lands only once the agent waits; give it the one wait it needs.
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 5.0)

    drv.swap_and_reload()

    assert named.verbs() == ["freeze", "zonestatus", "reconfig", "reload", "thaw", "zonestatus"]
    # named's own copy landed before the swap, on the file being replaced ...
    assert named.landed_after == ["freeze", "zonestatus"]
    assert "from-rfc2136" in (tmp_path / "rendered.prev" / "zones" / f"{ZONE}.db").read_text()
    # ... the render is what is live, and what named loaded and serves.
    live = (tmp_path / "rendered" / "zones" / f"{ZONE}.db").read_text()
    assert live == _render_text(9, ttl=1800)
    assert (named.serving, named.frozen) == (9, False)


def test_the_old_order_is_what_dropped_the_render(tmp_path: Path, monkeypatch, quick) -> None:
    """The scripted named reproduces the defect when frozen after the swap: its
    queued write lands on the render, and a load reads named's copy back."""
    named = _Named(tmp_path, serving=8, held=True)
    _driver(tmp_path, monkeypatch, named, live=7, staged=9)
    (tmp_path / "rendered").rename(tmp_path / "rendered.prev")
    (tmp_path / "rendered.new").rename(tmp_path / "rendered")
    named(["rndc", "freeze", ZONE])
    named.tick()
    named(["rndc", "reload", ZONE])
    assert named.serving == 8, "named's copy, not the render's 9"
    assert "$TTL 1800" not in named.file().read_text()


def test_a_render_not_ahead_of_named_is_moved_past_it(tmp_path: Path, monkeypatch, quick) -> None:
    """named runs ahead of the database when something else wrote the zone (a
    third party, #641). The render goes out under named's serial plus one, or a
    secondary holding named's serial never sees it, and a lower one goes
    backwards."""
    named = _Named(tmp_path, serving=9, held=True)
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=8)
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 5.0)

    drv.swap_and_reload()

    live = (tmp_path / "rendered" / "zones" / f"{ZONE}.db").read_text()
    assert live == _render_text(10, ttl=1800), "only the serial moved"
    assert named.serving == 10


def test_an_equal_serial_is_moved_past_too(tmp_path: Path, monkeypatch, quick) -> None:
    named = _Named(tmp_path, serving=8, held=True)
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=8)
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 5.0)

    drv.swap_and_reload()

    assert _soa_serial(tmp_path / "rendered" / "zones" / f"{ZONE}.db") == 9
    assert named.serving == 9


def test_a_render_ahead_of_named_keeps_its_serial(tmp_path: Path, monkeypatch, quick) -> None:
    named = _Named(tmp_path, serving=7, held=False)
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=8)

    drv.swap_and_reload()

    assert (tmp_path / "rendered" / "zones" / f"{ZONE}.db").read_text() == _render_text(
        8, ttl=1800
    )
    assert named.verbs() == ["freeze", "zonestatus", "reconfig", "reload", "thaw", "zonestatus"]


@pytest.mark.parametrize(
    ("staged", "served"),
    [(5, 5), (2**32 - 1, 1)],
    ids=["5-is-already-later", "the-next-after-2**32-1-is-1-not-0"],
)
def test_the_serial_wraps(tmp_path: Path, monkeypatch, quick, staged: int, served: int) -> None:
    """RFC 1982 arithmetic past 2**32 - 1. 0 would be next, but the render reads
    a 0 serial as none at all, so 1 it is."""
    named = _Named(tmp_path, serving=2**32 - 1, held=False)
    drv = _driver(tmp_path, monkeypatch, named, live=2**32 - 1, staged=staged)

    drv.swap_and_reload()

    assert _soa_serial(tmp_path / "rendered" / "zones" / f"{ZONE}.db") == served
    assert named.serving == served


def test_a_write_that_never_lands_is_waited_for_then_the_swap_goes_on(
    tmp_path: Path, monkeypatch, quick
) -> None:
    """named can serve a serial its file does not carry with nothing to write
    (an edit made outside the agent; a zone the old order left with named's
    copy on disk). Waiting on it forever would wedge every later apply, so the
    wait is bounded and the swap goes on; the verification then holds the
    apply to the render."""
    named = _Named(tmp_path, serving=8, held=True, writes=False)
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=9)
    seen: list[float] = []
    real_tick = named.tick

    def tick(s: float = 0.0) -> None:
        seen.append(s)
        real_tick(s)

    monkeypatch.setattr(bind9.time, "sleep", tick)
    clock = iter(range(1000))
    monkeypatch.setattr(bind9.time, "monotonic", lambda: float(next(clock)))
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 3.0)

    drv.swap_and_reload()

    assert seen and seen[0] == bind9._ZONE_DUMP_POLL_S, "it waited"
    assert named.verbs() == ["freeze", "zonestatus", "reconfig", "reload", "thaw", "zonestatus"]
    assert (named.serving, named.frozen) == (9, False)


def test_a_failure_after_the_freeze_thaws_the_zone(tmp_path: Path, monkeypatch, quick) -> None:
    named = _Named(tmp_path, serving=7, held=False,
                   reconfig=(1, "rndc: 'reconfig' failed: TLS error"))
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=8)

    with pytest.raises(RuntimeError, match="named rejected the new config"):
        drv.swap_and_reload()

    assert named.verbs() == ["freeze", "zonestatus", "reconfig", "thaw"]
    assert named.frozen is False


def test_the_sighup_fallback_thaws_first(tmp_path: Path, monkeypatch, quick) -> None:
    named = _Named(tmp_path, serving=7, held=False,
                   reconfig=(1, "rndc: connect failed: 127.0.0.1#953: connection refused"))
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=8)
    sent: list[int] = []
    monkeypatch.setattr(bind9.os, "kill", lambda pid, sig: sent.append(sig))

    drv.swap_and_reload()

    assert named.verbs() == ["freeze", "zonestatus", "reconfig", "thaw"]
    assert sent, "SIGHUP still sent"


def test_a_zone_the_freeze_refuses_keeps_the_old_sequence(
    tmp_path: Path, monkeypatch, quick
) -> None:
    """Not dynamic (no allow-update), or frozen by an operator: nothing to wait
    for before the swap, and the freeze/reload/thaw after it as before."""
    named = _Named(tmp_path, serving=7, held=False, freeze_rc=1)
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=8)

    drv.swap_and_reload()

    assert named.verbs() == [
        "freeze", "reconfig", "zonestatus", "freeze", "reload", "thaw", "zonestatus"
    ]
    assert named.serving == 8


def test_a_zone_new_to_named_is_not_frozen_before_the_swap(
    tmp_path: Path, monkeypatch, quick
) -> None:
    named = _Named(tmp_path, serving=0, held=False)
    drv = _driver(tmp_path, monkeypatch, named, live=None, staged=1)

    drv.swap_and_reload()

    assert named.verbs() == ["reconfig", "zonestatus", "freeze", "reload", "thaw", "zonestatus"]


def test_verification_holds_the_apply_to_the_render(tmp_path: Path, monkeypatch, quick) -> None:
    """If named's own copy ends up live anyway (a write that lands after the
    reload, as before the fix), the apply fails: the expected serial is the
    render's, read before the swap, not whatever the live file says after."""
    named = _Named(tmp_path, serving=7, held=False)
    drv = _driver(tmp_path, monkeypatch, named, live=7, staged=8)
    real = named.__call__

    def late_write(cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        res = real(cmd, *a, **kw)
        if cmd[1] == "thaw":            # the old race: named's copy lands and loads
            named.file().write_text(_dump_text(7))
            named.serving = 7
        return res

    monkeypatch.setattr(subprocess, "run", late_write)

    with pytest.raises(RuntimeError, match=r"lab\.test: serving serial 7, file has 8"):
        drv.swap_and_reload()

    assert named.verbs().count("thaw") == 1, "thawed once, by the reload; not again on the way out"
