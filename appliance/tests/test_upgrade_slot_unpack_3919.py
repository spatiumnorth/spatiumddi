"""A slot upgrade unpacks the new images on the OLD boot (#3919).

k3s imports the copied tarballs while the old slot still serves, but
containerd only unpacks an image when the kubelet starts its first container
from it: 27 s of the role pods' first create after the reboot (0.7-1.2 s when
already unpacked). ``cmd_apply`` therefore runs ``spatium-k3s-images unpack``
right after the copy. It is an optimisation: never fatal, never unbounded.

HOW TO RUN:
    python3 -m pytest appliance/tests/test_upgrade_slot_unpack_3919.py -v
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import types
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-upgrade-slot"
)


@pytest.fixture()
def mod(monkeypatch):
    loader = SourceFileLoader("spatium_upgrade_slot_unpack_3919", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    monkeypatch.setattr(m.time, "sleep", lambda _s: None)
    monkeypatch.setattr(m.os, "access", lambda *_a, **_k: True)
    return m


def _stub_run(mod, monkeypatch, result):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((list(cmd), kwargs))
        if isinstance(result, Exception):
            raise result
        return subprocess.CompletedProcess(cmd, result)

    monkeypatch.setattr(
        mod, "subprocess", types.SimpleNamespace(run=fake_run, SubprocessError=subprocess.SubprocessError)
    )
    return calls


def test_unpack_runs_bounded(mod, monkeypatch):
    calls = _stub_run(mod, monkeypatch, 0)
    mod._unpack_new_images()
    (cmd, kw), = calls
    assert cmd[:2] == ["/usr/local/bin/spatium-k3s-images", "unpack"]
    assert cmd[cmd.index("--max-time") + 1] == str(mod._UNPACK_MAX_TIME_S)
    assert kw["timeout"] > mod._UNPACK_MAX_TIME_S


@pytest.mark.parametrize(
    "result", [1, subprocess.TimeoutExpired("x", 1), OSError("gone")]
)
def test_unpack_failure_is_never_fatal(mod, monkeypatch, result):
    _stub_run(mod, monkeypatch, result)
    mod._unpack_new_images()  # must not raise


def test_missing_tool_is_skipped(mod, monkeypatch):
    calls = _stub_run(mod, monkeypatch, 0)
    monkeypatch.setattr(mod.os, "access", lambda *_a, **_k: False)
    mod._unpack_new_images()
    assert calls == []


def test_apply_unpacks_right_after_the_copy_only_when_it_copied():
    src = SCRIPT.read_text(encoding="utf-8")
    assert re.search(
        r"if _refresh_baked_images\(target_dev\):\n\s+_unpack_new_images\(\)\n", src
    )
