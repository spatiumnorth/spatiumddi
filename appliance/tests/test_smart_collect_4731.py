"""The host SMART runner (#4731).

Runs the shipped ``spatiumddi-smart-collect`` against a fake sysfs tree and a
stub ``smartctl``, unprivileged as CI does. The runner is root on the
appliance and the release-state directory is writable by pods, so the one
property that must not regress is that it never writes THROUGH a name a pod
could have planted.

HOW TO RUN:  python3 -m pytest appliance/tests/test_smart_collect_4731.py -v
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path

import pytest

from _installer_source import BIN

RUNNER = BIN / "spatiumddi-smart-collect"
UNITS = BIN.parent.parent.parent / "etc" / "systemd" / "system"


def _load():
    loader = importlib.machinery.SourceFileLoader("smart_collect", str(RUNNER))
    spec = importlib.util.spec_from_loader("smart_collect", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _tree(tmp_path: Path, mod, names: list[str]) -> Path:
    sysb = tmp_path / "sys-block"
    for n in names:
        (sysb / n / "device").mkdir(parents=True)
    (sysb / "loop0").mkdir(parents=True)  # no device/: not a disk
    (sysb / "md0" / "device").mkdir(parents=True)  # skipped by name
    state = tmp_path / "state"
    state.mkdir()
    mod.SYS_BLOCK = sysb
    mod.STATE_DIR = state
    return state


def _stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    s = bindir / "smartctl"
    s.write_text(f"#!/bin/sh\n{body}\n")
    s.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")


def test_collects_physical_disks_and_trims(tmp_path, monkeypatch) -> None:
    mod = _load()
    state = _tree(tmp_path, mod, ["sda", "nvme0n1"])
    _stub(
        tmp_path,
        monkeypatch,
        'echo \'{"device":{"protocol":"ATA"},"smart_status":{"passed":true},'
        '"ata_smart_attributes":{"table":[{"id":5,"name":"R","value":100,"worst":1,'
        '"raw":{"value":3,"string":"3"}}]},"junk":"x"}\'; exit 4',
    )
    assert mod.main() == 0
    doc = json.loads((state / "disk-smart.json").read_text())
    assert doc["smartctl"] is True
    assert [d["name"] for d in doc["disks"]] == ["nvme0n1", "sda"]
    smart = doc["disks"][0]["smart"]
    assert "junk" not in smart and smart["smart_status"]["passed"] is True
    assert smart["ata_smart_attributes"]["table"][0] == {
        "id": 5,
        "name": "R",
        "value": 100,
        "raw": {"value": 3},
    }


def test_missing_smartctl_is_recorded(tmp_path, monkeypatch) -> None:
    mod = _load()
    state = _tree(tmp_path, mod, ["sda"])
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert mod.main() == 0
    doc = json.loads((state / "disk-smart.json").read_text())
    assert doc["smartctl"] is False and doc["disks"] == []


def test_unparseable_smartctl_output_is_an_entry_not_a_crash(tmp_path, monkeypatch) -> None:
    mod = _load()
    state = _tree(tmp_path, mod, ["sda"])
    _stub(tmp_path, monkeypatch, "echo not-json")
    assert mod.main() == 0
    doc = json.loads((state / "disk-smart.json").read_text())
    assert "error" in doc["disks"][0] and "smart" not in doc["disks"][0]


def test_never_writes_through_a_planted_symlink(tmp_path, monkeypatch) -> None:
    mod = _load()
    state = _tree(tmp_path, mod, ["sda"])
    victim = tmp_path / "victim"
    victim.write_text("precious\n")
    os.symlink(victim, state / "disk-smart.json")
    _stub(tmp_path, monkeypatch, 'echo \'{"smart_status":{"passed":true}}\'')
    assert mod.main() == 0
    assert victim.read_text() == "precious\n"
    assert not (state / "disk-smart.json").is_symlink()
    assert json.loads((state / "disk-smart.json").read_text())["smartctl"] is True


def test_timer_and_service_are_wired() -> None:
    assert "spatiumddi-smart-collect" in (UNITS / "spatiumddi-smart-collect.service").read_text()
    assert "OnUnitActiveSec=1h" in (UNITS / "spatiumddi-smart-collect.timer").read_text()
    post = (BIN.parent.parent.parent.parent / "mkosi.postinst").read_text()
    assert "spatiumddi-smart-collect.timer" in post
    conf = (BIN.parent.parent.parent.parent / "mkosi.conf").read_text()
    assert "smartmontools" in conf
