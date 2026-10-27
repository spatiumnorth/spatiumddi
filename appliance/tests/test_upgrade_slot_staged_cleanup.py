"""#2400 — the staged .raw.xz never outlives the slot write.

``spatium-upgrade-slot apply`` downloads the image (~1.5 GiB) to
``/var/lib/spatiumddi/slot-staging`` and decompresses it into the inactive
slot. The success path removed it; the checksum-mismatch, xz and dd failure
paths did not, so the file sat on /var — the volume the kubelet evicts on —
until the next upgrade (which discards it before fetching anyway, so nothing
ever reused it).

These run ``cmd_apply`` for real against a temp staging dir, with the fetch
and the slot detection stubbed, and assert on the file system. Each also
proves the file existed when the write started, so "removed" never means
"never written".
"""

from __future__ import annotations

import importlib.util
import subprocess
import types
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatium-upgrade-slot"
)


def _load():
    loader = SourceFileLoader("spatium_upgrade_slot_cleanup", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture()
def slot(tmp_path, monkeypatch):
    mod = _load()
    staging = tmp_path / "slot-staging"
    monkeypatch.setattr(mod, "_STAGING_DIR", staging)
    monkeypatch.setattr(mod, "_PROGRESS_FILE", tmp_path / "progress.json")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        mod,
        "detect_active_inactive",
        lambda: (
            {"partlabel": "root_a", "device": "/dev/null"},
            {"partlabel": "root_b", "device": "/dev/null"},
        ),
    )

    def fake_fetch(src, staged, *, insecure):
        staged.write_bytes(b"not really xz")
        return 0

    monkeypatch.setattr(mod, "_fetch_image", fake_fetch)
    return mod, staging / "slot.raw.xz"


def _args(**kw):
    base = {"image": "https://cp/raw.xz", "checksum": None, "expected_sha256": None}
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_checksum_mismatch_removes_the_staged_image(slot) -> None:
    mod, staged = slot
    seen = {}
    real = mod.sha256_file

    def spy(path):
        seen["existed"] = Path(path).exists()
        return real(path)

    mod.sha256_file = spy
    rc = mod.cmd_apply(_args(expected_sha256="0" * 64))
    assert rc == 3
    assert seen["existed"] is True
    assert not staged.exists()


def test_a_failed_slot_write_removes_the_staged_image(slot, monkeypatch) -> None:
    mod, staged = slot
    seen = {}
    real_popen = subprocess.Popen

    def fake_popen(argv, **kw):
        if argv[0] == "xz":
            seen["existed"] = staged.exists()
            return real_popen(["cat", str(staged)], **kw)
        if argv[0] == "dd":
            return real_popen(["sh", "-c", "cat >/dev/null; exit 1"], **kw)
        raise AssertionError(argv)

    monkeypatch.setattr(mod.subprocess, "Popen", fake_popen)
    with pytest.raises(subprocess.CalledProcessError):
        mod.cmd_apply(_args())
    assert seen["existed"] is True
    assert not staged.exists()


def test_a_completed_slot_write_removes_the_staged_image(slot, monkeypatch) -> None:
    mod, staged = slot
    seen = {}
    real_popen = subprocess.Popen

    def fake_popen(argv, **kw):
        if argv[0] == "xz":
            seen["existed"] = staged.exists()
            return real_popen(["cat", str(staged)], **kw)
        if argv[0] == "dd":
            return real_popen(["sh", "-c", "cat >/dev/null"], **kw)
        raise AssertionError(argv)

    class Stop(Exception):
        pass

    def stop_at_bootloader(step, *a, **k):
        # The write is over by the time the bootloader step starts; nothing
        # after it is needed to show where the staged file went.
        if step == "bootloader":
            raise Stop

    monkeypatch.setattr(mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(mod, "_write_progress", stop_at_bootloader)
    with pytest.raises(Stop):
        mod.cmd_apply(_args())
    assert seen["existed"] is True
    assert not staged.exists()
