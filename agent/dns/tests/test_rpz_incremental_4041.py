"""A changed blocklist is applied to named as updates, not reloaded (#4041).

Every blocklist refresh used to rewrite the RPZ zone file and ``rndc reload``
it, so named held the old and the new zone together (~977 MB peak on a ~940k
line list). With the agent's own key allowed to update the zone, a change is
the adds and deletes between what named holds and the new render.

A scripted named stands in for the daemon: it keeps the zone as a set of
lines, applies RFC 2136 messages the driver sends over ``dns.query.tcp``, and
answers ``rndc zonestatus`` with its own serial. The assertions are on what
named was told (no reload, no freeze, one small update) and on what it holds
afterwards, not on log lines.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import dns.rdataclass
import dns.rdatatype
import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver

RPZ = "spatium-blocklist.rpz."
RPZ_FILE = "zones/spatium-blocklist.rpz.db"
KEYS = [{"name": "spatium-loop.", "secret": "c2VjcmV0c2VjcmV0", "algorithm": "hmac-sha256"}]


def _entries(n: int, skip: set[int] | None = None) -> list[dict[str, Any]]:
    return [
        {
            "domain": f"ads{i:05d}.example.test",
            "action": "block",
            "block_mode": "nxdomain",
            "target": None,
            "is_wildcard": i % 2 == 0,
        }
        for i in range(n)
        if i not in (skip or set())
    ]


def _bundle(entries: list[dict[str, Any]], digest: str, keys: Any = KEYS) -> dict[str, Any]:
    return {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "zones": [],
        "tsig_keys": keys,
        "blocklists": [
            {
                "rpz_zone_name": RPZ,
                "entries": entries,
                "exceptions": [],
                "view_name": None,
                "rpz_sha256": digest,
            }
        ],
    }


class FakeNamed:
    """The zone as named holds it, and the commands that reach it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.records: set[str] = set()
        self.serial: int | None = None
        self.rndc: list[list[str]] = []
        self.messages: list[int] = []  # ops per RFC 2136 message
        self.refuse_updates = False

    def load(self) -> None:
        text = (self.root / "rendered" / RPZ_FILE).read_text().splitlines()
        self.serial = bind9._soa_serial(self.root / "rendered" / RPZ_FILE)
        self.records = {ln for ln in text[3:] if ln}

    def run(self, cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess[str]:
        self.rndc.append(list(cmd))
        out = ""
        if "zonestatus" in cmd:
            if self.serial is None:
                return subprocess.CompletedProcess(cmd, 1, "", "zone not loaded")
            out = f"serial: {self.serial}\n"
        if "reload" in cmd and cmd[-1] == "spatium-blocklist.rpz":
            self.load()
        return subprocess.CompletedProcess(cmd, 0, out, "")

    def tcp(self, upd: Any, where: str, timeout: float = 0) -> Any:
        self.messages.append(len(upd.update))

        class Resp:
            def __init__(self, rc: int) -> None:
                self._rc = rc

            def rcode(self) -> int:
                return self._rc

        if self.refuse_updates:
            return Resp(5)
        for rrset in upd.update:
            owner = rrset.name.to_text().rstrip(".")
            for rd in rrset:
                line = f"{owner} {dns.rdatatype.to_text(rrset.rdtype)} {rd.to_text()}"
                if rrset.deleting is not None or rrset.rdclass == dns.rdataclass.NONE:
                    self.records.discard(line)
                else:
                    self.records.add(line)
        assert self.serial is not None
        self.serial += 1
        return Resp(0)


@pytest.fixture
def named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeNamed:
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9, "_ZONE_LOAD_TIMEOUT_S", 0.0)
    fake = FakeNamed(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake.run)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/sbin/rndc")
    monkeypatch.setattr(bind9.dns.query, "tcp", fake.tcp)
    return fake


def _driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bind9Driver:
    drv = Bind9Driver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    return drv


def _apply(drv: Bind9Driver, bundle: dict[str, Any]) -> None:
    drv.render(bundle)
    drv.swap_and_reload()


def _zone_calls(fake: FakeNamed, *verbs: str) -> list[list[str]]:
    return [c for c in fake.rndc if any(v in c for v in verbs) and "spatium-blocklist.rpz" in c]


def _first_load(drv: Bind9Driver, named: FakeNamed, n: int = 2000) -> None:
    """The initial apply: no baseline yet, so the full render and a reload."""
    _apply(drv, _bundle(_entries(n), "sha256:" + "a" * 64))
    named.load()  # named's first load of the file (it started on the tree)


def test_a_small_change_to_a_large_list_sends_updates_and_reloads_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: FakeNamed
) -> None:
    drv = _driver(tmp_path, monkeypatch)
    _first_load(drv, named)
    assert named.serial is not None and len(named.records) > 2000
    named.rndc.clear()
    written: list[str] = []
    real = Bind9Driver._write_rpz_zone_file

    def spy(self: Bind9Driver, path: Path, bl: dict[str, Any]) -> None:
        written.append(path.name)
        real(self, path, bl)

    monkeypatch.setattr(Bind9Driver, "_write_rpz_zone_file", spy)

    # One domain removed (it is a wildcard, so two lines), one added.
    changed = _entries(2000, skip={10}) + [
        {"domain": "new.example.test", "action": "block", "block_mode": "nxdomain"}
    ]
    _apply(drv, _bundle(changed, "sha256:" + "b" * 64))

    # The measure: no reload, no freeze, no thaw, no re-verification of the zone.
    assert not _zone_calls(named, "reload", "freeze", "thaw"), named.rndc
    # One message, of exactly the diff: 2 deletes (ads00010 + its wildcard) and 1 add.
    assert named.messages == [3]
    assert "ads00010.example.test CNAME ." not in named.records
    assert "*.ads00010.example.test CNAME ." not in named.records
    assert "new.example.test CNAME ." in named.records
    # What named holds is the render, serial and all, and a restart loads the same.
    live = tmp_path / "rendered" / RPZ_FILE
    assert bind9._soa_serial(live) == named.serial
    assert {ln for ln in live.read_text().splitlines()[3:] if ln} == named.records


def test_the_next_change_diffs_against_what_the_last_one_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: FakeNamed
) -> None:
    drv = _driver(tmp_path, monkeypatch)
    _first_load(drv, named)
    _apply(drv, _bundle(_entries(2000, skip={10}), "sha256:" + "b" * 64))
    named.rndc.clear()
    named.messages.clear()

    _apply(drv, _bundle(_entries(2000, skip={10, 11}), "sha256:" + "c" * 64))

    assert not _zone_calls(named, "reload", "freeze", "thaw")
    assert named.messages == [1]
    live = tmp_path / "rendered" / RPZ_FILE
    assert {ln for ln in live.read_text().splitlines()[3:] if ln} == named.records


def test_an_unrelated_apply_after_an_update_does_not_reload_the_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: FakeNamed
) -> None:
    """named dumps its own copy over the live file after an update; the next
    apply (the list unchanged) must not read that as a changed list."""
    drv = _driver(tmp_path, monkeypatch)
    _first_load(drv, named)
    _apply(drv, _bundle(_entries(2000, skip={10}), "sha256:" + "b" * 64))
    live = tmp_path / "rendered" / RPZ_FILE
    # named's dump: a different spelling of the same zone.
    dumped = live.with_name("dump.tmp")
    dumped.write_text("$ORIGIN .\nspatium-blocklist.rpz 60 IN SOA localhost. root.localhost. (\n")
    dumped.replace(live)
    named.rndc.clear()
    named.messages.clear()

    _apply(drv, _bundle(_entries(2000, skip={10}), "sha256:" + "b" * 64))

    assert not _zone_calls(named, "reload", "freeze", "thaw")
    assert named.messages == []


def test_a_change_too_large_to_be_an_edit_is_reloaded_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: FakeNamed
) -> None:
    monkeypatch.setattr(bind9, "_RPZ_INCREMENTAL_MAX_CHANGES", 10)
    drv = _driver(tmp_path, monkeypatch)
    _first_load(drv, named, 200)
    named.rndc.clear()

    _apply(drv, _bundle(_entries(200, skip=set(range(100))), "sha256:" + "b" * 64))

    assert named.messages == []
    assert _zone_calls(named, "reload")
    live = tmp_path / "rendered" / RPZ_FILE
    assert {ln for ln in live.read_text().splitlines()[3:] if ln} == named.records


def test_a_refused_update_falls_back_to_the_full_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: FakeNamed
) -> None:
    drv = _driver(tmp_path, monkeypatch)
    _first_load(drv, named, 200)
    named.refuse_updates = True
    named.rndc.clear()

    _apply(drv, _bundle(_entries(200, skip={3}), "sha256:" + "b" * 64))

    assert _zone_calls(named, "reload")
    live = tmp_path / "rendered" / RPZ_FILE
    assert {ln for ln in live.read_text().splitlines()[3:] if ln} == named.records


def test_a_zone_named_serves_under_another_serial_is_not_patched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: FakeNamed
) -> None:
    """The baseline records the serial it was taken at; named serving another
    means the diff would be against something it does not hold."""
    drv = _driver(tmp_path, monkeypatch)
    _first_load(drv, named, 200)
    assert named.serial is not None
    named.serial += 7
    named.rndc.clear()

    _apply(drv, _bundle(_entries(200, skip={3}), "sha256:" + "b" * 64))

    assert named.messages == []
    assert _zone_calls(named, "reload")


def test_no_group_key_means_no_update_grant_and_the_full_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: FakeNamed
) -> None:
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, _bundle(_entries(50), "sha256:" + "a" * 64, keys=[]))
    named.load()
    assert (
        "allow-update"
        not in (tmp_path / "rendered" / "named.conf")
        .read_text()
        .split('zone "spatium-blocklist.rpz"')[1]
    )
    named.rndc.clear()

    _apply(drv, _bundle(_entries(50, skip={1}), "sha256:" + "b" * 64, keys=[]))

    assert named.messages == []
    assert _zone_calls(named, "reload")


def test_the_rpz_zone_takes_the_agents_own_key_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: FakeNamed
) -> None:
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, _bundle(_entries(5), "sha256:" + "a" * 64))
    conf = (tmp_path / "rendered" / "named.conf").read_text()
    stanza = next(
        ln for ln in conf.splitlines() if 'zone "spatium-blocklist.rpz."' in ln and "file" in ln
    )
    assert 'allow-update { key "spatium-loop."; };' in stanza
    assert "0.0.0.0" not in stanza  # the grant is the key alone, no address
