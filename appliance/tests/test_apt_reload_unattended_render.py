"""The unattended-upgrades policy reaches apt with every entry as saved (#1384).

``spatiumddi-apt-reload`` renders ``50unattended-upgrades`` from the APT
bundle. apt.conf has no escape syntax inside a double-quoted string: a
backslash is kept literally and a double quote ends the string. The renderer
used to double every backslash, so a blocklist regex like ``linux-image-\\d``
reached unattended-upgrades as ``linux-image-\\\\d`` (a literal backslash)
and blocked nothing. This runs the shipped Python block, the real bytes, and
reads the result back with ``apt-config`` when it is available.

    python3 -m pytest appliance/tests/test_apt_reload_unattended_render.py -v
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "appliance" / "mkosi.extra" / "usr" / "local" / "bin" / "spatiumddi-apt-reload"

pytestmark = pytest.mark.skipif(not SCRIPT.is_file(), reason="appliance tree not present")


def _unattended_program() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    body = text[text.index("render_unattended()") :]
    m = re.search(r"<<'PYEOF'\n(.*?)\nPYEOF\n", body, re.S)
    assert m, "render_unattended's python block not found"
    return m.group(1)


def _render(tmp_path: Path, unattended: dict) -> tuple[str, subprocess.CompletedProcess]:
    blob = tmp_path / "blob.json"
    blob.write_text(json.dumps({"unattended": unattended}), encoding="utf-8")
    policy, timer = tmp_path / "50unattended-upgrades", tmp_path / "20auto-upgrades"
    proc = subprocess.run(
        [sys.executable, "-", str(blob), str(policy), str(timer)],
        input=_unattended_program(),
        capture_output=True,
        text=True,
        check=True,
    )
    return policy.read_text(encoding="utf-8"), proc


def test_a_backslash_is_written_verbatim(tmp_path: Path) -> None:
    out, _ = _render(tmp_path, {"blocklist": [r"linux-image-\d", "^openssl$"]})
    assert '"linux-image-\\d";' in out
    assert "\\\\" not in out


def test_an_entry_apt_cannot_express_is_dropped_with_a_warning(tmp_path: Path) -> None:
    out, proc = _render(tmp_path, {"blocklist": ['bad"quote', "ok-pkg"], "origins": ["o=Debian"]})
    assert "bad" not in out
    assert '"ok-pkg";' in out
    assert "WARN" in proc.stdout


@pytest.mark.skipif(shutil.which("apt-config") is None, reason="apt-config not installed")
def test_apt_reads_back_what_was_saved(tmp_path: Path) -> None:
    out, _ = _render(tmp_path, {"blocklist": [r"linux-image-\d"]})
    conf = tmp_path / "apt.conf"
    conf.write_text(out, encoding="utf-8")
    dump = subprocess.run(
        ["apt-config", "-c", str(conf), "dump"], capture_output=True, text=True, check=True
    ).stdout
    assert 'Package-Blacklist:: "linux-image-\\d";' in dump
