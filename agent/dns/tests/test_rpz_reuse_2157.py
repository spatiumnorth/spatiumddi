"""An RPZ zone whose content did not change is not rewritten (#2157).

Every structural apply used to re-serialise every RPZ zone from scratch: a
catalog feed is ~186k entries and an ~11 MB file, written again on every
agent (and again on every replica of its volume) for an edit that touched no
blocklist, with the previous ~11 MB deleted from ``rendered.prev`` at the same
time. The control plane now ships a content hash per RPZ zone
(``rpz_sha256``); the render hard-links a file whose hash matches instead of
writing it.

These assert on what reaches the disk (inodes, mtimes, link counts) and on
which ``rndc`` commands are issued, not on log lines: the failure this guards
against is invisible in every other way.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver

RPZ = "spatium-blocklist.rpz."
RPZ_FILE = "zones/spatium-blocklist.rpz.db"


def _entries(prefix: str, n: int = 50) -> list[dict[str, Any]]:
    return [
        {
            "domain": f"{prefix}{i:03d}.example.test",
            "action": "block",
            "block_mode": "sinkhole" if i % 7 == 0 else "nxdomain",
            "target": None,
            "is_wildcard": i % 3 == 0,
        }
        for i in range(n)
    ]


def _bl(
    zone: str = RPZ,
    view: str | None = None,
    *,
    prefix: str = "ads",
    digest: str | None = "sha256:" + "a" * 64,
) -> dict[str, Any]:
    bl: dict[str, Any] = {
        "rpz_zone_name": zone,
        "entries": _entries(prefix),
        "exceptions": ["allowed.example.test"],
        "view_name": view,
    }
    if digest is not None:
        bl["rpz_sha256"] = digest
    return bl


def _zone(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 2026101801,
        "primary_ns": f"ns1.{name}",
        "admin_email": f"hostmaster.{name}",
        "records": [{"name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300}],
    }


def _forward(name: str) -> dict[str, Any]:
    return {"name": name, "type": "forward", "forwarders": ["192.0.2.53"]}


def _flat(blocklists: list[dict[str, Any]], *, with_forward: bool = True) -> dict[str, Any]:
    zones = [_zone("example.test.")]
    if with_forward:
        zones.append(_forward("corp.test."))
    return {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "zones": zones,
        "tsig_keys": [],
        "blocklists": blocklists,
    }


def _views(blocklists: list[dict[str, Any]], *, recursion: bool = True) -> dict[str, Any]:
    return {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "views": [
            {
                "id": "v1",
                "name": "internal",
                "match_clients": ["10.0.0.0/8"],
                "match_destinations": [],
                "recursion": recursion,
                "order": 0,
            },
            {
                "id": "v2",
                "name": "external",
                "match_clients": ["any"],
                "match_destinations": [],
                "recursion": True,
                "order": 1,
            },
        ],
        "zones": [],
        "tsig_keys": [],
        "blocklists": blocklists,
    }


#: The state dir the fake named reads its "loaded" serials from.
_NAMED_ROOT: dict[str, Path] = {}


@pytest.fixture
def rndc(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Every subprocess ``swap_and_reload`` runs, answered as a named that
    loads what it is told to: ``zonestatus`` reports the live file's serial."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        out = ""
        if "zonestatus" in cmd:
            i = cmd.index("zonestatus")
            zname = cmd[i + 1]
            view = cmd[i + 3] if len(cmd) > i + 3 else None
            live = _NAMED_ROOT["root"] / "rendered" / bind9._zone_rel(zname, view)
            serial = bind9._soa_serial(live)
            out = f"serial: {serial}\n" if serial is not None else ""
        if ("freeze" in cmd or "thaw" in cmd) and ".rpz" in cmd[-1]:
            # An RPZ zone has no allow-update, so it is not dynamic, and
            # named refuses to freeze or thaw it.
            return subprocess.CompletedProcess(cmd, 1, "", "rndc: 'freeze' failed: not dynamic")
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/sbin/rndc")
    return calls


def _driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bind9Driver:
    drv = Bind9Driver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    _NAMED_ROOT["root"] = tmp_path
    return drv


def _apply(drv: Bind9Driver, bundle: dict[str, Any]) -> None:
    drv.render(bundle)
    drv.swap_and_reload()


def _rpz_writes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Each zone ``_write_rpz_zone_file`` serialises, in order."""
    written: list[str] = []
    real = Bind9Driver._write_rpz_zone_file

    def spy(self: Bind9Driver, path: Path, bl: dict[str, Any]) -> None:
        written.append(bl["rpz_zone_name"])
        real(self, path, bl)

    monkeypatch.setattr(Bind9Driver, "_write_rpz_zone_file", spy)
    return written


def _rndc_zones(calls: list[list[str]], verb: str) -> list[str]:
    return [c[c.index(verb) + 1] for c in calls if verb in c]


# ── The issue's tests ─────────────────────────────────────────────────────────


def test_a_structural_only_change_writes_no_rpz_bytes_and_reloads_no_rpz(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rndc: list[list[str]]
) -> None:
    """The reported case: removing a forward zone rewrote the 11 MB RPZ file.

    Negative control: on main before #2157 the render ignores ``rpz_sha256``
    and writes a new file, so the inode assertion fails."""
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, _flat([_bl()]))
    live = tmp_path / "rendered" / RPZ_FILE
    before = live.stat()
    written = _rpz_writes(monkeypatch)
    rndc.clear()

    _apply(drv, _flat([_bl()], with_forward=False))  # the unrelated edit

    after = live.stat()
    assert written == [], "the unchanged RPZ zone was re-serialised"
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert "corp.test" not in (tmp_path / "rendered" / "named.conf").read_text()
    # Not one rndc command names the RPZ zone: not freeze, reload, thaw, nor
    # the zonestatus that would mean it was being verified as reloaded.
    assert not [c for c in rndc if "spatium-blocklist.rpz" in c], rndc
    assert ["reconfig"] in [c[-1:] for c in rndc]
    # The backup is the same inode, so rendered.prev costs no extra blocks.
    prev = (tmp_path / "rendered.prev" / RPZ_FILE).stat()
    assert prev.st_ino == after.st_ino
    assert after.st_nlink == 2


def test_a_list_change_rewrites_and_reloads_only_that_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rndc: list[list[str]]
) -> None:
    drv = _driver(tmp_path, monkeypatch)
    internal = "spatium-blocklist-internal.rpz."
    external = "spatium-blocklist-external.rpz."
    _apply(
        drv,
        _views([_bl(internal, "internal"), _bl(external, "external", digest="sha256:" + "e" * 64)]),
    )
    live = tmp_path / "rendered" / "zones"
    int_before = (live / "internal" / "spatium-blocklist-internal.rpz.db").stat()
    ext_before = (live / "external" / "spatium-blocklist-external.rpz.db").stat()
    written = _rpz_writes(monkeypatch)
    rndc.clear()

    _apply(
        drv,
        _views(
            [
                _bl(internal, "internal", prefix="tracker", digest="sha256:" + "b" * 64),
                _bl(external, "external", digest="sha256:" + "e" * 64),
            ]
        ),
    )

    assert written == [internal]
    int_after = (live / "internal" / "spatium-blocklist-internal.rpz.db").stat()
    ext_after = (live / "external" / "spatium-blocklist-external.rpz.db").stat()
    assert int_after.st_ino != int_before.st_ino
    assert (ext_after.st_ino, ext_after.st_mtime_ns) == (ext_before.st_ino, ext_before.st_mtime_ns)
    assert _rndc_zones(rndc, "reload") == ["spatium-blocklist-internal.rpz"]
    assert "spatium-blocklist-external.rpz" not in {z for c in rndc for z in c}
    # The changed zone is verified loaded, on a serial that moved with it.
    assert "spatium-blocklist-internal.rpz" in _rndc_zones(rndc, "zonestatus")


def test_revert_after_a_failed_apply_restores_the_previous_rpz(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rndc: list[list[str]]
) -> None:
    """#882: the failed bundle is live, and the revert re-renders the previous
    one. Its RPZ zone comes back from ``rendered.prev`` (linked, not
    re-serialised), with a fresh mtime — named skips ``rndc reload`` of a
    primary zone whose file is older than its last load — and is reloaded."""
    drv = _driver(tmp_path, monkeypatch)
    good = _bl()
    _apply(drv, _flat([good]))
    good_bytes = (tmp_path / "rendered" / RPZ_FILE).read_bytes()
    good_ino = (tmp_path / "rendered" / RPZ_FILE).stat().st_ino

    bad = _bl(prefix="tracker", digest="sha256:" + "c" * 64)
    _apply(drv, _flat([bad]))  # the apply that "fails" once it is live
    failed_mtime = (tmp_path / "rendered" / RPZ_FILE).stat().st_mtime_ns
    assert (tmp_path / "rendered" / RPZ_FILE).read_bytes() != good_bytes
    written = _rpz_writes(monkeypatch)
    rndc.clear()

    _apply(drv, _flat([good]))  # the revert

    live = tmp_path / "rendered" / RPZ_FILE
    assert written == [], "the revert re-serialised a zone its backup holds"
    assert live.read_bytes() == good_bytes
    assert live.stat().st_ino == good_ino, "restored by link from rendered.prev"
    assert live.stat().st_mtime_ns >= failed_mtime
    assert _rndc_zones(rndc, "reload") == ["spatium-blocklist.rpz"]


def test_the_revert_restores_a_changed_rpz_even_without_a_backup_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rndc: list[list[str]]
) -> None:
    """No tree holds the previous bundle's file (its backup was rotated
    away): the render falls back to serialising it, as before #2157."""
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, _flat([_bl()]))
    good_bytes = (tmp_path / "rendered" / RPZ_FILE).read_bytes()
    _apply(drv, _flat([_bl(prefix="x", digest="sha256:" + "1" * 64)]))
    _apply(drv, _flat([_bl(prefix="y", digest="sha256:" + "2" * 64)]))
    written = _rpz_writes(monkeypatch)

    _apply(drv, _flat([_bl()]))

    assert written == [RPZ]
    assert (tmp_path / "rendered" / RPZ_FILE).read_bytes() == good_bytes


# ── The backup stays the backup ───────────────────────────────────────────────


def test_a_changed_list_never_writes_through_a_link_into_the_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rndc: list[list[str]]
) -> None:
    """After a structural-only apply the live and backup RPZ files are one
    inode. The next list change must replace the live NAME, not write into
    that inode, or the backup the #882 revert restores from changes too."""
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, _flat([_bl()]))
    original = (tmp_path / "rendered" / RPZ_FILE).read_bytes()
    _apply(drv, _flat([_bl()], with_forward=False))  # live + prev share it now

    _apply(drv, _flat([_bl(prefix="tracker", digest="sha256:" + "d" * 64)], with_forward=False))

    prev = tmp_path / "rendered.prev" / RPZ_FILE
    assert prev.read_bytes() == original
    assert (tmp_path / "rendered" / RPZ_FILE).read_bytes() != original
    assert prev.stat().st_ino != (tmp_path / "rendered" / RPZ_FILE).stat().st_ino


def test_holding_back_a_zone_linked_from_the_backup_leaves_the_backup_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one place a rendered file used to be written through its name: a
    zone ``named-checkzone`` refuses gets the live copy put back over it. A
    zone reused from ``rendered.prev`` is a link to the backup's inode, so a
    write through it (``shutil.copyfile``) put the LIVE bytes into the backup.

    Reached on a retry of a reverted bundle: the live tree is the last good
    one, the backup is the failed bundle's, and the retry's RPZ zone is
    linked from the backup."""
    good, bad = _bl(), _bl(prefix="tracker", digest="sha256:" + "f" * 64)
    drv = Bind9Driver(state_dir=tmp_path)
    for bundle in (_flat([bad]), _flat([good])):  # bad's tree is now the backup
        drv.render(bundle)
        drv._swap_in(tmp_path / "rendered.new", tmp_path / "rendered", tmp_path / "rendered.prev")
    backup_file = tmp_path / "rendered.prev" / RPZ_FILE
    backup_bytes = backup_file.read_bytes()

    drv.render(_flat([bad]))  # the retry: linked from the backup
    staged = tmp_path / "rendered.new" / RPZ_FILE
    assert staged.stat().st_ino == backup_file.stat().st_ino

    def checker(cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess[str]:
        if Path(cmd[0]).name == "named-checkzone" and cmd[-2] == RPZ.rstrip("."):
            return subprocess.CompletedProcess(cmd, 1, "zone refused: bad record", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", checker)
    monkeypatch.setattr("shutil.which", lambda n: f"/usr/bin/{n}")
    drv._check_zone_files(tmp_path / "rendered.new")

    assert [h.zone for h in drv.held_back] == [RPZ.rstrip(".")]
    assert backup_file.read_bytes() == backup_bytes, "the hold-back wrote into the backup"
    assert staged.read_bytes() == (tmp_path / "rendered" / RPZ_FILE).read_bytes()
    # The staged sidecar now describes the live copy, not the refused render,
    # so the next apply cannot "reuse" the held copy as the refused bundle's.
    assert (
        bind9._rpz_sidecar(staged).read_text()
        == bind9._rpz_sidecar(tmp_path / "rendered" / RPZ_FILE).read_text()
    )


# ── Determinism ───────────────────────────────────────────────────────────────


def test_the_same_bundle_renders_the_same_bytes(tmp_path: Path) -> None:
    trees = []
    for name in ("one", "two"):
        state = tmp_path / name
        Bind9Driver(state_dir=state).render(_flat([_bl()]))
        trees.append(state / "rendered.new")
    one, two = trees
    files = sorted(p.relative_to(one) for p in one.rglob("*") if p.is_file())
    assert Path(RPZ_FILE) in files
    for rel in files:
        if rel.name == "named.conf":
            # Absolute state-dir paths differ between the two trees, by design.
            assert (one / rel).read_text().replace(str(tmp_path / "one"), "") == (
                two / rel
            ).read_text().replace(str(tmp_path / "two"), "")
        else:
            assert (one / rel).read_bytes() == (two / rel).read_bytes(), rel


def test_the_rpz_serial_moves_with_the_content_and_only_with_it() -> None:
    a, a_again = _bl(), _bl()
    b = _bl(digest="sha256:" + "b" * 64)
    assert bind9._rpz_serial(a) == bind9._rpz_serial(a_again)
    assert bind9._rpz_serial(a) != bind9._rpz_serial(b)
    assert 0 < bind9._rpz_serial(a) < 2**32
    assert bind9._rpz_serial(_bl(digest=None)) == 1, "no hash: the old constant"


def test_the_rpz_serial_is_not_the_render_time(tmp_path: Path, monkeypatch) -> None:
    lines = []
    for when in (1_000_000_000, 2_000_000_000):
        monkeypatch.setattr("time.time", lambda w=when: float(w))
        out = tmp_path / f"{when}.db"
        Bind9Driver(state_dir=tmp_path)._write_rpz_zone_file(out, _bl())
        lines.append(out.read_text().splitlines()[1])
    assert lines[0] == lines[1]


# ── Wire compatibility ────────────────────────────────────────────────────────


def test_a_bundle_without_hashes_renders_every_time_as_before(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An older control plane ships no ``rpz_sha256``. Nothing can say the
    file is current, so it is rendered on every apply, its bytes are the
    pre-#2157 bytes (serial 1), and no sidecar is written to be trusted
    later."""
    drv = Bind9Driver(state_dir=tmp_path)
    written = _rpz_writes(monkeypatch)
    inodes = []
    for _ in range(2):
        drv.render(_flat([_bl(digest=None)]))
        drv._swap_in(tmp_path / "rendered.new", tmp_path / "rendered", tmp_path / "rendered.prev")
        inodes.append((tmp_path / "rendered" / RPZ_FILE).stat().st_ino)
    assert written == [RPZ, RPZ]
    assert inodes[0] != inodes[1]
    live = tmp_path / "rendered" / RPZ_FILE
    assert not bind9._rpz_sidecar(live).exists()
    assert live.read_text().splitlines()[1] == (
        "@ IN SOA localhost. root.localhost. ( 1 3600 600 86400 60 )"
    )


def test_a_hash_arriving_later_takes_over_without_a_stale_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Old control plane, then new: the first hashed bundle renders (no
    sidecar to match) and the second reuses."""
    drv = Bind9Driver(state_dir=tmp_path)
    written = _rpz_writes(monkeypatch)
    for bl in (_bl(digest=None), _bl(), _bl()):
        drv.render(_flat([bl]))
        drv._swap_in(tmp_path / "rendered.new", tmp_path / "rendered", tmp_path / "rendered.prev")
    assert written == [RPZ, RPZ]


# ── When a sidecar must not be trusted ───────────────────────────────────────


def _two_renders(tmp_path: Path, tamper: Any, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_flat([_bl()]))
    drv._swap_in(tmp_path / "rendered.new", tmp_path / "rendered", tmp_path / "rendered.prev")
    tamper(tmp_path / "rendered" / RPZ_FILE)
    written = _rpz_writes(monkeypatch)
    drv.render(_flat([_bl()]))
    return written


def test_a_truncated_file_is_rendered_again(tmp_path: Path, monkeypatch) -> None:
    def truncate(p: Path) -> None:
        os.truncate(p, 10)

    assert _two_renders(tmp_path, truncate, monkeypatch) == [RPZ]


def test_another_renderer_revisions_file_is_rendered_again(tmp_path: Path, monkeypatch) -> None:
    def older(p: Path) -> None:
        side = bind9._rpz_sidecar(p)
        rev = bind9._RPZ_RENDER_REVISION
        side.write_text(side.read_text().replace(f"r{rev}:", f"r{rev - 1}:", 1))

    assert _two_renders(tmp_path, older, monkeypatch) == [RPZ]


def test_a_missing_sidecar_is_rendered_again(tmp_path: Path, monkeypatch) -> None:
    def drop(p: Path) -> None:
        bind9._rpz_sidecar(p).unlink()

    assert _two_renders(tmp_path, drop, monkeypatch) == [RPZ]


def test_a_corrupt_sidecar_is_rendered_again(tmp_path: Path, monkeypatch) -> None:
    def garble(p: Path) -> None:
        bind9._rpz_sidecar(p).write_bytes(b"\xff\xfe not a sidecar")

    assert _two_renders(tmp_path, garble, monkeypatch) == [RPZ]


def test_the_rpz_file_is_durable_before_its_sidecar_vouches_for_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once a sidecar exists the file is linked forward and never checked
    again, so its bytes must reach the disk before the sidecar is written."""
    events: list[str] = []
    real_fsync = os.fsync
    real_write = bind9._write_new_inode

    def fsync(fd: int) -> None:
        events.append("fsync")
        real_fsync(fd)

    def write_new_inode(path: Path, data: bytes) -> None:
        if path.name.endswith(".sha256"):
            events.append("sidecar")
        real_write(path, data)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(bind9, "_write_new_inode", write_new_inode)
    Bind9Driver(state_dir=tmp_path).render(_flat([_bl()]))
    assert "sidecar" in events
    assert "fsync" in events[: events.index("sidecar")]


def test_the_rendered_config_push_skips_the_sidecars(tmp_path: Path) -> None:
    from spatium_dns_agent.admin_pusher import _walk_rendered

    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_flat([_bl()]))
    drv._swap_in(tmp_path / "rendered.new", tmp_path / "rendered", tmp_path / "rendered.prev")
    assert bind9._rpz_sidecar(tmp_path / "rendered" / RPZ_FILE).is_file()
    pushed = dict(_walk_rendered(tmp_path / "rendered"))
    assert RPZ_FILE in pushed
    assert not [p for p in pushed if p.endswith((".sha256", ".tmp"))]


def test_no_hard_links_falls_back_to_a_copy_not_a_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A volume that refuses links (or a cross-device tree) still skips the
    serialisation; it copies the bytes instead."""

    def no_link(*_a: Any, **_k: Any) -> None:
        raise OSError(18, "Invalid cross-device link")

    monkeypatch.setattr(os, "link", no_link)
    written = _two_renders(tmp_path, lambda _p: None, monkeypatch)
    assert written == []
    staged = tmp_path / "rendered.new" / RPZ_FILE
    live = tmp_path / "rendered" / RPZ_FILE
    assert staged.read_bytes() == live.read_bytes()
    assert staged.stat().st_ino != live.stat().st_ino


def test_zone_comparison_does_not_read_a_linked_file(tmp_path: Path, monkeypatch) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_flat([_bl()]))
    drv._swap_in(tmp_path / "rendered.new", tmp_path / "rendered", tmp_path / "rendered.prev")
    drv.render(_flat([_bl()]))
    read: list[str] = []
    real = Path.read_bytes

    def spy(self: Path) -> bytes:
        read.append(self.name)
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", spy)
    changed = bind9._zones_differing(tmp_path / "rendered.new", tmp_path / "rendered")
    assert changed == set()
    assert "spatium-blocklist.rpz.db" not in read


@pytest.mark.skipif(shutil.which("named-checkzone") is None, reason="needs BIND's named-checkzone")
def test_the_real_checker_loads_a_rendered_rpz_zone_with_its_derived_serial(
    tmp_path: Path,
) -> None:
    out = tmp_path / "rpz.db"
    Bind9Driver(state_dir=tmp_path)._write_rpz_zone_file(out, _bl())
    res = subprocess.run(
        ["named-checkzone", "-i", "none", "-k", "fail", RPZ, str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr
    assert f"loaded serial {bind9._rpz_serial(_bl())}" in res.stdout
