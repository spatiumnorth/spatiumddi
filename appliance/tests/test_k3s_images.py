"""k3s's import of the slot's baked images: stale ingests cleared, misses re-imported (#1630).

A slot upgrade's first boot failed to import seven of its image tarballs, the
DNS and DHCP agents' among them:

    failed to ingest "index.json": failed commit on ref "tar-index.json":
    commit failed: unexpected commit size 3071, expected 374: failed precondition

k3s imports every tarball's ``index.json`` under the one containerd ref
``tar-index.json``. An uncommitted write left under that ref (an "ingest") makes
containerd fail every shorter ``index.json`` after it: it restarts the write
but never truncates the old data file. k3s records only what imported
(``.cache.json``) and does not retry a failed tarball until the file changes.
The agents' pods sat in ``ErrImageNeverPull`` for good.

``spatium-k3s-images`` closes both halves:

  * ``clear-ingests``, an ExecStartPre of k3s.service, removes unfinished
    writes before k3s starts;
  * ``verify --repair``, run by firstboot, checks k3s's record and containerd
    once the start-up import is over. It clears idle ingests and has k3s
    re-import what it missed.

These tests drive the real script. ``FakeK3s`` plays k3s's watcher and
containerd. It imports a tarball only when the file's mtime moves, as the
watcher does on an inotify event, and only when no ingest longer than the
tarball's ``index.json`` is on disk, as containerd's writer does. It then
records the import in ``.cache.json`` in k3s's own format.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_k3s_images.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

APPLIANCE = Path(__file__).parent.parent
SCRIPT = APPLIANCE / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-k3s-images"
UNIT = APPLIANCE / "mkosi.extra" / "etc" / "systemd" / "system" / "k3s.service"
FIRSTBOOT = APPLIANCE / "mkosi.extra" / "usr" / "local" / "bin" / "spatiumddi-firstboot"
SHELL = shutil.which("dash") or "sh"

TAG = "2026.10.06-1"
# name -> (images it carries, size of its index.json); sizes as on the 10-03 walk
TARBALLS = {
    "dhcp-kea.tar.zst": ([f"ghcr.io/spatiumnorth/dhcp-kea:{TAG}"], 374),
    "dns-bind9.tar.zst": ([f"ghcr.io/spatiumnorth/dns-bind9:{TAG}"], 375),
    "k3s-airgap-images-amd64.tar.zst": (
        ["docker.io/rancher/mirrored-pause:3.10.2", "docker.io/rancher/mirrored-coredns-coredns:1.14.6"],
        3071,
    ),
}
OLD = 1_760_000_000  # every tarball's mtime at the start-up import


def _rfc3339(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load(monkeypatch):
    loader = SourceFileLoader("spatium_k3s_images", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve the defining module through sys.modules
    monkeypatch.setitem(sys.modules, loader.name, module)
    loader.exec_module(module)
    return module


class FakeK3s:
    """k3s's watcher and containerd, on a fake clock.

    The watcher queues a tarball whose mtime moved and imports the queue one
    file at a time. An import takes ``slow[name]`` seconds of the fake clock
    (0: done within the tick), and for that long the tarball is open: a
    ``<proc>/<pid>/fd/<n>`` symlink names it, which is what k3s's open file
    looks like in /proc (#2109). The cache entry records the file as it was
    when its import began, so a tarball touched mid-import is imported again
    once this import ends, as k3s does."""

    PID = "4242"

    def __init__(self, mod, root: Path) -> None:
        self.mod = mod
        self.images_dir = root / "images"
        self.content = root / "content"
        self.proc = root / "proc"
        self.images_dir.mkdir()
        (self.content / "ingest").mkdir(parents=True)
        (self.content / "blobs" / "sha256").mkdir(parents=True)
        (self.content / "blobs" / "sha256" / ("ab" * 32)).write_bytes(b"a committed blob")
        (self.proc / self.PID / "fd").mkdir(parents=True)
        (self.proc / "self").mkdir()  # not a pid: skipped
        self.store: set[str] = set()
        self.down = False
        self.broken: set[str] = set()
        self.attempts: list[str] = []
        self.cache: dict[str, dict] = {}
        self.slow: dict[str, float] = {}
        self.clock = 0.0
        self.kubelet_at: float | None = 0.0  # when the kubelet answers; None: never
        self.queue: list[str] = []
        self.current: list | None = None  # [name, seconds left, mtime it started on]
        self.done_at: dict[str, float] = {}
        self._seen: dict[str, float] = {}
        for name, (_, index) in TARBALLS.items():
            p = self.images_dir / name
            p.write_bytes(name.encode() * 100)
            os.utime(p, (OLD, OLD))
        self.write_cache()

    # the start-up import, as k3s ran it before the test begins
    def booted(self, *, failed: tuple[str, ...] = ()) -> None:
        for name in TARBALLS:
            p = self.images_dir / name
            self._seen[name] = p.stat().st_mtime
            if name in failed:
                self.cache.pop(str(p), None)
            else:
                self._record(p, p.stat().st_mtime)
        self.write_cache()

    # the start-up import, still running when the check begins: the slot
    # upgrade copied every tarball across, so k3s has all of them queued
    def booting(self, **seconds: float) -> None:
        for name in TARBALLS:
            p = self.images_dir / name
            os.utime(p, (OLD + 100, OLD + 100))
            self.slow[name] = seconds.get(name.split(".")[0].replace("-", "_"), 0)
        self.kubelet_at = None
        self.tick(0)

    def _record(self, p: Path, mtime: float) -> None:
        imgs = TARBALLS[p.name][0]
        self.cache[str(p)] = {"size": p.stat().st_size, "modTime": _rfc3339(mtime), "images": imgs}
        self.store.update(imgs)

    def write_cache(self) -> None:
        (self.images_dir / ".cache.json").write_text(json.dumps(self.cache))

    def plant(self, data: int, *, ref: str = "k8s.io-12-tar-index.json", age: float = 3600) -> Path:
        d = self.content / "ingest" / f"{abs(hash(ref)):064x}"[:64]
        d.mkdir()
        (d / "ref").write_text(ref)
        (d / "data").write_bytes(b"\0" * data)
        (d / "total").write_text("449")
        for f in ("startedat", "updatedat"):
            (d / f).write_text("x")
        stamp = time.time() - age
        for f in d.iterdir():
            os.utime(f, (stamp, stamp))
        os.utime(d, (stamp, stamp))
        return d

    def _poisoned(self, index: int) -> bool:
        for d in (self.content / "ingest").iterdir():
            data = d / "data"
            if data.exists() and data.stat().st_size > index:
                return True
        return False

    def _fd(self) -> Path:
        return self.proc / self.PID / "fd" / "171"

    # the watcher, over ``seconds`` of the fake clock
    def tick(self, seconds: float = 0) -> None:
        for name in TARBALLS:
            mtime = (self.images_dir / name).stat().st_mtime
            if self._seen.get(name) != mtime:
                self._seen[name] = mtime
                if name not in self.queue:
                    self.queue.append(name)
        budget = seconds
        while True:
            if self.current is None:
                if not self.queue:
                    break
                name = self.queue.pop(0)
                p = self.images_dir / name
                self.attempts.append(name)
                self.current = [name, self.slow.get(name, 0), p.stat().st_mtime]
                self._fd().symlink_to(os.path.realpath(p))
                if not self.queue and self.kubelet_at is None:
                    # k3s starts the kubelet once its queue is EMPTY, which is
                    # when the last tarball is taken off it, not imported
                    self.kubelet_at = self.clock
            name, left, mtime = self.current
            step = min(left, budget)
            self.clock += step
            budget -= step
            if left > step:
                self.current[1] = left - step
                break
            self._fd().unlink()
            self.current = None
            self.done_at[name] = self.clock
            if not (name in self.broken or self._poisoned(TARBALLS[name][1])):
                self._record(self.images_dir / name, mtime)
        self.clock += budget
        self.write_cache()

    def kubelet(self) -> bool:
        return self.kubelet_at is not None and self.clock >= self.kubelet_at

    def present(self):
        return None if self.down else set(self.store)


@pytest.fixture()
def k3s(tmp_path, monkeypatch) -> FakeK3s:
    mod = _load(monkeypatch)
    fake = FakeK3s(mod, tmp_path)
    monkeypatch.setattr(mod, "IMAGES_DIR", fake.images_dir)
    monkeypatch.setattr(mod, "CONTENT_DIR", fake.content)
    monkeypatch.setattr(mod, "PROC_DIR", fake.proc, raising=False)
    monkeypatch.setattr(mod, "present_images", fake.present)
    monkeypatch.setattr(mod, "kubelet_up", fake.kubelet)
    monkeypatch.setattr(mod, "_sleep", fake.tick)
    monkeypatch.setattr(mod, "time", SimpleNamespace(monotonic=lambda: fake.clock, time=time.time))
    return fake


def _verify(k3s: FakeK3s, *args: str) -> int:
    return k3s.mod.main(["verify", "--repair-wait", "0", *args])


# ── clear-ingests ────────────────────────────────────────────────────────────


def test_clear_ingests_removes_every_unfinished_write_and_no_content(k3s: FakeK3s, capsys) -> None:
    stale = k3s.plant(3071)
    other = k3s.plant(12, ref="k8s.io-13-tar-blobs/sha256/0f", age=5)

    assert k3s.mod.main(["clear-ingests"]) == 0

    assert not stale.exists() and not other.exists(), "an unfinished containerd write survived the clear"
    assert (k3s.content / "blobs" / "sha256").exists() and any((k3s.content / "blobs" / "sha256").iterdir())
    out = capsys.readouterr().out
    assert "cleared stale containerd ingest k8s.io-12-tar-index.json (3071 bytes)" in out
    assert "cleared stale containerd ingest k8s.io-13-tar-blobs/sha256/0f (12 bytes)" in out


def test_clear_ingests_with_min_idle_spares_a_write_in_flight(k3s: FakeK3s) -> None:
    stale = k3s.plant(3071, age=3600)
    live = k3s.plant(40, ref="k8s.io-14-tar-index.json", age=1)

    assert k3s.mod.main(["clear-ingests", "--min-idle", "60"]) == 0

    assert not stale.exists()
    assert live.exists(), "an ingest written a second ago is an import in flight; it must be left alone"


def test_clear_ingests_is_quiet_and_fine_with_no_content_store(k3s: FakeK3s, capsys) -> None:
    shutil.rmtree(k3s.content)
    assert k3s.mod.main(["clear-ingests"]) == 0
    assert capsys.readouterr().out == ""


def test_k3s_clears_ingests_before_it_starts() -> None:
    lines = [ln.strip() for ln in UNIT.read_text().splitlines()]
    clear = "ExecStartPre=-/usr/local/bin/spatium-k3s-images clear-ingests"
    assert clear in lines, (
        "k3s.service does not clear containerd's stale ingests before k3s starts: one "
        "left under tar-index.json fails every shorter index.json on every boot (#1630)"
    )
    assert lines.index(clear) < lines.index("ExecStart=/usr/local/bin/k3s server")


def test_the_helper_is_executable_in_the_built_image() -> None:
    postinst = (APPLIANCE / "mkosi.postinst").read_text()
    assert 'chmod 0755 "$BUILDROOT/usr/local/bin/spatium-k3s-images"' in postinst
    assert os.access(SCRIPT, os.X_OK)


# ── verify ───────────────────────────────────────────────────────────────────


def test_verify_passes_when_every_tarball_imported_and_every_image_is_there(k3s: FakeK3s, capsys) -> None:
    k3s.booted()
    assert _verify(k3s) == 0
    assert "all 3 baked tarballs imported, 4 images present" in capsys.readouterr().out


def test_verify_names_a_tarball_k3s_failed_to_import(k3s: FakeK3s, capsys) -> None:
    k3s.booted(failed=("dhcp-kea.tar.zst",))
    k3s.store.discard(f"ghcr.io/spatiumnorth/dhcp-kea:{TAG}")

    assert _verify(k3s) == 1

    err = capsys.readouterr().err
    assert "k3s has not imported dhcp-kea.tar.zst" in err
    assert k3s.attempts == [], "without --repair nothing may be touched"


def test_a_cache_entry_for_an_older_copy_of_the_file_is_not_an_import(k3s: FakeK3s, capsys) -> None:
    k3s.booted()
    p = k3s.images_dir / "dns-bind9.tar.zst"
    p.write_bytes(b"the new slot's tarball, a different size")  # the upgrade copied it across
    assert _verify(k3s) == 1
    assert "k3s has not imported dns-bind9.tar.zst" in capsys.readouterr().err


def test_verify_names_an_image_containerd_lost(k3s: FakeK3s, capsys) -> None:
    k3s.booted()
    k3s.store.discard(f"ghcr.io/spatiumnorth/dns-bind9:{TAG}")
    assert _verify(k3s) == 1
    assert (f"ghcr.io/spatiumnorth/dns-bind9:{TAG} (from dns-bind9.tar.zst) is not in containerd"
            in capsys.readouterr().err)


def test_repair_clears_the_stale_ingest_and_has_k3s_reimport_what_it_missed(k3s: FakeK3s, capsys) -> None:
    # the #1630 boot: a 3071-byte stale index.json failed the two agents' tarballs
    stale = k3s.plant(3071)
    k3s.booted(failed=("dhcp-kea.tar.zst", "dns-bind9.tar.zst"))
    for img in ("dhcp-kea", "dns-bind9"):
        k3s.store.discard(f"ghcr.io/spatiumnorth/{img}:{TAG}")

    assert _verify(k3s, "--repair") == 0

    out = capsys.readouterr().out
    assert not stale.exists()
    assert "cleared stale containerd ingest k8s.io-12-tar-index.json (3071 bytes)" in out
    assert "re-importing 2 tarball(s) through k3s: dhcp-kea.tar.zst, dns-bind9.tar.zst" in out
    assert "all 3 baked tarballs imported, 4 images present" in out
    assert sorted(k3s.attempts) == ["dhcp-kea.tar.zst", "dns-bind9.tar.zst"], (
        "exactly the tarballs k3s missed must be re-imported"
    )
    assert {f"ghcr.io/spatiumnorth/dhcp-kea:{TAG}", f"ghcr.io/spatiumnorth/dns-bind9:{TAG}"} <= k3s.store


def test_repair_reimports_a_tarball_whose_image_was_lost(k3s: FakeK3s) -> None:
    k3s.booted()
    k3s.store.discard(f"ghcr.io/spatiumnorth/dhcp-kea:{TAG}")
    assert _verify(k3s, "--repair") == 0
    assert k3s.attempts == ["dhcp-kea.tar.zst"]


def test_repair_that_cannot_bring_an_image_back_fails_and_says_what(k3s: FakeK3s, capsys) -> None:
    k3s.booted(failed=("dhcp-kea.tar.zst",))
    k3s.store.discard(f"ghcr.io/spatiumnorth/dhcp-kea:{TAG}")
    k3s.broken.add("dhcp-kea.tar.zst")  # e.g. a truncated tarball

    assert _verify(k3s, "--repair") == 1

    err = capsys.readouterr().err
    assert "still missing after the re-import: dhcp-kea.tar.zst" in err
    assert k3s.attempts == ["dhcp-kea.tar.zst"]


def test_repair_leaves_an_ingest_in_flight_alone(k3s: FakeK3s, capsys) -> None:
    live = k3s.plant(3071, age=1)
    k3s.booted(failed=("dhcp-kea.tar.zst",))
    k3s.store.discard(f"ghcr.io/spatiumnorth/dhcp-kea:{TAG}")

    assert _verify(k3s, "--repair") == 1, "the import it could not make must still be reported"

    assert live.exists()
    assert "cleared stale containerd ingest" not in capsys.readouterr().out


def test_verify_fails_when_containerd_does_not_answer(k3s: FakeK3s, capsys) -> None:
    k3s.booted()
    k3s.down = True
    assert _verify(k3s, "--repair") == 1
    assert "containerd did not answer" in capsys.readouterr().err
    assert k3s.attempts == []


def test_verify_waits_for_the_kubelet_then_judges_what_it_has(k3s: FakeK3s, monkeypatch, capsys) -> None:
    k3s.booted()
    monkeypatch.setattr(k3s.mod, "kubelet_up", lambda: False)
    assert _verify(k3s, "--wait", "0") == 0
    captured = capsys.readouterr()
    assert "the kubelet did not answer within 0s" in captured.err
    assert "all 3 baked tarballs imported" in captured.out


def test_verify_reads_k3s_cache_format(k3s: FakeK3s) -> None:
    """The entry shape is k3s v1.36's watcher.go ``fileInfo``: size, modTime
    (metav1.Time, RFC 3339 to the second) and images, keyed by full path."""
    k3s.booted()
    raw = json.loads((k3s.images_dir / ".cache.json").read_text())
    key = str(k3s.images_dir / "dhcp-kea.tar.zst")
    assert set(raw[key]) == {"size", "modTime", "images"}
    assert k3s.mod.imported(k3s.images_dir / "dhcp-kea.tar.zst", raw[key])
    # a file touched after its import is not "this file as imported"
    later = OLD + 5
    os.utime(k3s.images_dir / "dhcp-kea.tar.zst", (later, later))
    assert not k3s.mod.imported(k3s.images_dir / "dhcp-kea.tar.zst", raw[key])


# ── #2109: k3s still importing when the check begins ─────────────────────────

AIRGAP = "k3s-airgap-images-amd64.tar.zst"


def test_a_slow_start_up_import_is_waited_for_and_nothing_is_touched(k3s: FakeK3s, capsys) -> None:
    """The #2109 seed: the kubelet did not answer for minutes because k3s
    was still working through the upgraded slot's tarballs. The check judged
    at 120 s, touched the one being imported (restarting it) and the ones not
    reached yet, and gave up before the second import ended."""
    k3s.booting(dhcp_kea=90, dns_bind9=80, k3s_airgap_images_amd64=150)

    assert _verify(k3s, "--repair") == 0

    captured = capsys.readouterr()
    assert sorted(k3s.attempts) == sorted(TARBALLS), (
        "a tarball was imported twice: the check touched one k3s was importing (#2109)"
    )
    assert "re-importing" not in captured.out, "nothing was missing; nothing may be touched"
    assert "k3s is importing" in captured.out
    assert "all 3 baked tarballs imported, 4 images present" in captured.out
    for name in TARBALLS:
        assert (k3s.images_dir / name).stat().st_mtime == OLD + 100, f"{name} was touched"
    assert k3s.clock >= max(k3s.done_at.values()), "judged before k3s's import ended"


def test_the_kubelet_up_with_the_last_tarball_still_importing_is_waited_for(k3s: FakeK3s, capsys) -> None:
    """k3s starts the kubelet once its queue is empty, i.e. with the last
    tarball still importing (seen on a real k3s v1.36.4: the kubelet started
    8 s before the last ``Imported 1 images``). A kubelet that answers is not
    the end of the import."""
    k3s.booting(k3s_airgap_images_amd64=200)  # sorted last, so imported last
    k3s.tick(0)
    assert k3s.kubelet() and k3s.current and k3s.current[0] == AIRGAP

    assert _verify(k3s, "--repair") == 0

    assert k3s.attempts.count(AIRGAP) == 1
    assert "re-importing" not in capsys.readouterr().out


def test_a_tarball_open_at_repair_time_is_never_touched(k3s: FakeK3s, capsys) -> None:
    """Out of time with k3s still importing: the others are repaired, the one
    k3s has open is left alone and reported as unfinished, not as missing."""
    k3s.booted(failed=("dns-bind9.tar.zst",))
    k3s.store.discard(f"ghcr.io/spatiumnorth/dns-bind9:{TAG}")
    k3s.slow["dhcp-kea.tar.zst"] = 10_000
    k3s.cache.pop(str(k3s.images_dir / "dhcp-kea.tar.zst"))
    k3s.store.discard(f"ghcr.io/spatiumnorth/dhcp-kea:{TAG}")
    os.utime(k3s.images_dir / "dhcp-kea.tar.zst", (OLD + 100, OLD + 100))
    k3s.tick(0)  # k3s opens dhcp-kea and is still on it at --max-wait
    kea_mtime = (k3s.images_dir / "dhcp-kea.tar.zst").stat().st_mtime

    assert _verify(k3s, "--repair", "--max-wait", "300") == 1

    captured = capsys.readouterr()
    assert (k3s.images_dir / "dhcp-kea.tar.zst").stat().st_mtime == kea_mtime
    assert k3s.attempts.count("dhcp-kea.tar.zst") == 1
    assert "leaving dhcp-kea.tar.zst alone: k3s is importing it right now" in captured.out
    assert "re-importing 1 tarball(s) through k3s: dns-bind9.tar.zst" in captured.out
    assert "k3s is still importing dhcp-kea.tar.zst after 300s" in captured.err
    assert "k3s is still importing dhcp-kea.tar.zst; its images are not checked yet" in captured.err
    assert "k3s had not finished importing dhcp-kea.tar.zst when the time ran out" in captured.err
    assert k3s.clock <= 300 + 5, "--max-wait bounds the whole check"


def test_the_time_runs_out_with_k3s_still_importing(k3s: FakeK3s, capsys) -> None:
    """Without --repair: the verdict is 1, and it says the import was still
    running rather than that the image is missing."""
    k3s.booting(dhcp_kea=10_000)
    assert _verify(k3s, "--max-wait", "200") == 1
    err = capsys.readouterr().err
    assert "k3s is still importing dhcp-kea.tar.zst after 200s" in err
    assert "k3s has not imported dhcp-kea.tar.zst" not in err
    assert k3s.attempts.count("dhcp-kea.tar.zst") == 1
    assert 200 <= k3s.clock <= 205


def test_the_repair_waits_past_repair_wait_while_k3s_is_reimporting(k3s: FakeK3s, capsys) -> None:
    """A re-import on slow storage outlasts --repair-wait (#1859's 180 s was
    one); while k3s has the tarball open the check keeps waiting."""
    k3s.booted(failed=("dhcp-kea.tar.zst",))
    k3s.store.discard(f"ghcr.io/spatiumnorth/dhcp-kea:{TAG}")
    k3s.slow["dhcp-kea.tar.zst"] = 240

    assert _verify(k3s, "--repair") == 0

    assert k3s.attempts == ["dhcp-kea.tar.zst"]
    assert "all 3 baked tarballs imported" in capsys.readouterr().out


def test_the_fast_path_adds_no_wait(k3s: FakeK3s, monkeypatch) -> None:
    """A node whose import ended long ago: the kubelet answers and nothing
    is open, so the check judges at once, without one poll."""
    k3s.booted()
    sleeps: list[float] = []
    monkeypatch.setattr(k3s.mod, "_sleep", sleeps.append)
    assert _verify(k3s, "--repair") == 0
    assert sleeps == [] and k3s.clock == 0


def test_importing_reads_the_real_proc(tmp_path, monkeypatch) -> None:
    """The signal itself, against this kernel's /proc: a tarball this very
    process holds open is reported, the others are not."""
    mod = _load(monkeypatch)
    held, idle = tmp_path / "held.tar.zst", tmp_path / "idle.tar.zst"
    held.write_bytes(b"x")
    idle.write_bytes(b"y")
    monkeypatch.setattr(mod, "PROC_DIR", Path("/proc"))
    with open(held, "rb"):
        assert mod.importing([held, idle]) == {held}
    assert mod.importing([held, idle]) == set()


def test_importing_knows_the_tarball_by_another_name(tmp_path, monkeypatch) -> None:
    """k3s may open the tarball under a name that is not ours: through a bind
    mount, or a symlinked directory. The kernel's fd link then reads that
    name, so a path compare misses the import and verify would touch the
    tarball k3s is importing, which is #2109 again. A hard link stands in for
    a bind mount: the same file under a path no realpath() turns into ours."""
    mod = _load(monkeypatch)
    images, other = tmp_path / "images", tmp_path / "bind"
    images.mkdir()
    other.mkdir()
    ours = images / "pg.tar.zst"
    ours.write_bytes(b"x")
    os.link(ours, other / "pg.tar.zst")
    (tmp_path / "linked").symlink_to(images)
    monkeypatch.setattr(mod, "PROC_DIR", Path("/proc"))
    for name in (other / "pg.tar.zst", tmp_path / "linked" / "pg.tar.zst"):
        with open(name, "rb"):
            assert mod.importing([ours]) == {ours}, name
    assert mod.importing([ours]) == set()


def test_importing_skips_a_process_that_exits_mid_scan(tmp_path, monkeypatch) -> None:
    """A pid listed in /proc can be gone by the time its fds are read, and an
    fd can close between its readlink and its stat. Neither is an error."""
    mod = _load(monkeypatch)
    tarball = tmp_path / "pg.tar.zst"
    tarball.write_bytes(b"x")
    proc = tmp_path / "proc"
    (proc / "41").mkdir(parents=True)                                  # exited: no fd dir
    (proc / "42" / "fd").mkdir(parents=True)
    (proc / "42" / "fd" / "3").symlink_to(tmp_path / "gone.tar.zst")   # closed mid-scan
    (proc / "43" / "fd").mkdir(parents=True)
    (proc / "43" / "fd" / "7").symlink_to(tarball)
    monkeypatch.setattr(mod, "PROC_DIR", proc)
    assert mod.importing([tarball]) == {tarball}


# ── firstboot ────────────────────────────────────────────────────────────────


def _extract_function(name: str) -> str:
    lines = FIRSTBOOT.read_text(encoding="utf-8").splitlines()
    opener = f"{name}() {{"
    for i, line in enumerate(lines):
        if line == opener:
            break
    else:
        raise AssertionError(f"{name}() not found in {FIRSTBOOT}")
    for j in range(i + 1, len(lines)):
        if lines[j] == "}":
            return "\n".join(lines[i : j + 1])
    raise AssertionError(f"{name}() has no closing brace at column 0")


def _has_function(name: str) -> bool:
    return f"{name}() {{" in FIRSTBOOT.read_text(encoding="utf-8").splitlines()


def _ready_branch() -> list[str]:
    lines = [ln.strip() for ln in FIRSTBOOT.read_text(encoding="utf-8").splitlines()]
    start = lines.index('if [ "$ready" = 1 ]; then')
    end = lines.index("exit 0", start)
    return lines[start:end]


def test_firstboot_checks_the_slots_images_before_the_slot_commit() -> None:
    branch = _ready_branch()
    # directly, or through the trial-boot gate (test_firstboot_slot_images_gate.py)
    calls = [i for i, ln in enumerate(branch)
             if ln.startswith(("check_slot_images", "slot_images_allow_commit"))]
    assert calls, (
        "firstboot never checks that the slot's images are in containerd before it "
        "commits the slot (#1630)"
    )
    assert calls[0] < branch.index("commit_slot_if_healthy")
    assert branch.index("place_deferred_control_manifest") < calls[0]


@pytest.mark.parametrize(
    ("helper_rc", "rc", "says"),
    [
        (0, 0, ""),
        (1, 1, "ERROR: this slot's images are not all in containerd, even after a re-import"),
        (None, 0, "is missing — this slot's images were not checked"),
    ],
)
def test_check_slot_images_runs_the_repair_and_reports_its_verdict(tmp_path, helper_rc, rc, says) -> None:
    helper = tmp_path / "spatium-k3s-images"
    if helper_rc is not None:
        helper.write_text(f'#!/bin/sh\necho "$*" > "{tmp_path}/args"\nexit {helper_rc}\n')
        helper.chmod(0o755)
    body = "\n".join(
        [_extract_function(f) for f in ("uptime_s", "slot_images_budget") if _has_function(f)]
        + ["FIRSTBOOT_TIMEOUT_S=600 FIRSTBOOT_T0=0 SLOT_IMAGES_MARGIN_S=45",
           _extract_function("check_slot_images")]
    ).replace("/usr/local/bin/spatium-k3s-images", str(helper))
    proc = subprocess.run(
        [SHELL, "-c", f"set -eu\n{body}\nif check_slot_images; then echo rc=0; else echo rc=$?; fi\n"],
        capture_output=True, text=True, check=False,
    )
    assert f"rc={rc}" in proc.stdout, proc.stdout + proc.stderr
    assert says in proc.stderr
    if helper_rc is not None:
        assert (tmp_path / "args").read_text().split()[:2] == ["verify", "--repair"]
