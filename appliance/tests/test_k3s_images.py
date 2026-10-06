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
    def __init__(self, mod, root: Path) -> None:
        self.mod = mod
        self.images_dir = root / "images"
        self.content = root / "content"
        self.images_dir.mkdir()
        (self.content / "ingest").mkdir(parents=True)
        (self.content / "blobs" / "sha256").mkdir(parents=True)
        (self.content / "blobs" / "sha256" / ("ab" * 32)).write_bytes(b"a committed blob")
        self.store: set[str] = set()
        self.down = False
        self.broken: set[str] = set()
        self.attempts: list[str] = []
        self.cache: dict[str, dict] = {}
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
                self._record(p)
        self.write_cache()

    def _record(self, p: Path) -> None:
        imgs = TARBALLS[p.name][0]
        st = p.stat()
        self.cache[str(p)] = {"size": st.st_size, "modTime": _rfc3339(st.st_mtime), "images": imgs}
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

    # the watcher: one pass over the files whose mtime moved since its last look
    def tick(self, _seconds: float = 0) -> None:
        for name in TARBALLS:
            p = self.images_dir / name
            mtime = p.stat().st_mtime
            if self._seen.get(name) == mtime:
                continue
            self._seen[name] = mtime
            self.attempts.append(name)
            if name in self.broken or self._poisoned(TARBALLS[name][1]):
                continue
            self._record(p)
        self.write_cache()

    def present(self):
        return None if self.down else set(self.store)


@pytest.fixture()
def k3s(tmp_path, monkeypatch) -> FakeK3s:
    mod = _load(monkeypatch)
    fake = FakeK3s(mod, tmp_path)
    monkeypatch.setattr(mod, "IMAGES_DIR", fake.images_dir)
    monkeypatch.setattr(mod, "CONTENT_DIR", fake.content)
    monkeypatch.setattr(mod, "present_images", fake.present)
    monkeypatch.setattr(mod, "kubelet_up", lambda: True)
    monkeypatch.setattr(mod, "_sleep", fake.tick)
    monkeypatch.setattr(mod, "POLL_S", 0)
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


def _ready_branch() -> list[str]:
    lines = [ln.strip() for ln in FIRSTBOOT.read_text(encoding="utf-8").splitlines()]
    start = lines.index('if [ "$ready" = 1 ]; then')
    end = lines.index("exit 0", start)
    return lines[start:end]


def test_firstboot_checks_the_slots_images_before_the_slot_commit() -> None:
    branch = _ready_branch()
    calls = [i for i, ln in enumerate(branch) if ln.startswith("check_slot_images")]
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
    body = _extract_function("check_slot_images").replace("/usr/local/bin/spatium-k3s-images", str(helper))
    proc = subprocess.run(
        [SHELL, "-c", f"set -eu\n{body}\nif check_slot_images; then echo rc=0; else echo rc=$?; fi\n"],
        capture_output=True, text=True, check=False,
    )
    assert f"rc={rc}" in proc.stdout, proc.stdout + proc.stderr
    assert says in proc.stderr
    if helper_rc is not None:
        assert (tmp_path / "args").read_text().split() == ["verify", "--repair"]
