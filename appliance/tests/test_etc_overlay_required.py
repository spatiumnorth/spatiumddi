"""k3s and first-boot do not run without the /etc overlay (#1910).

/etc is an overlay (etc.mount): the slot's image baseline below, the node's
own state above it in /var/persist/etc — its hostname, machine-id, the k3s
config drop-ins that carry its role label and CIDRs, the appliance .env and
role-config. etc.mount is only *wanted* by local-fs.target, so a boot whose
overlay mount failed goes on, and k3s.service and spatiumddi-firstboot.service
only ordered themselves after it. After a power-off a QA seed's overlay mount
failed: k3s started on the slot's bare /etc and registered a brand-new Node,
``localhost``, without its role or CIDRs, and firstboot generated a fresh .env
"(first boot)". Both units now require the overlay, as the host runners'
reload units do, and the console says why k3s is down instead of calling it
"disabled".

    python3 -m pytest appliance/tests/test_etc_overlay_required.py -v
"""

from __future__ import annotations

import __future__
import ast
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO / "appliance" / "mkosi.extra" / "etc" / "systemd" / "system"
CONSOLE = REPO / "appliance" / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-console"

pytestmark = pytest.mark.skipif(not UNIT_DIR.is_dir(), reason="appliance tree not present")


def _unit_deps(unit: str) -> dict[str, set[str]]:
    """The [Unit] section's dependency lists, every repeat of a key merged."""
    deps: dict[str, set[str]] = {}
    section = ""
    for raw in (UNIT_DIR / unit).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section != "[Unit]" or "=" not in line:
            continue
        key, _, value = line.partition("=")
        deps.setdefault(key.strip(), set()).update(value.split())
    return deps


@pytest.mark.parametrize("unit", ["k3s.service", "spatiumddi-firstboot.service"])
def test_the_unit_requires_the_etc_overlay(unit: str) -> None:
    deps = _unit_deps(unit)
    assert "etc.mount" in deps.get("Requires", set()), (
        f"{unit} must Require= etc.mount: an ordering alone lets it start on the "
        "slot's bare /etc when the overlay did not mount"
    )
    assert "etc.mount" in deps.get("After", set()), f"{unit} must order After=etc.mount"


def test_etc_mount_is_the_overlay_on_etc() -> None:
    text = (UNIT_DIR / "etc.mount").read_text(encoding="utf-8")
    assert "Where=/etc" in text and "Type=overlay" in text


# ── the console's k3s row ───────────────────────────────────────────────

_NAMES = {"_etc_overlay_missing", "k3s_status"}


def _console(root: Path, *, mounted: bool, unit_state: str) -> dict[str, Any]:
    """Lift the two functions out of the shipped console (it imports rich and
    psutil at load, which this suite does not install) and run them against
    a fake root: every absolute path is read under ``root``."""
    tree = ast.parse(CONSOLE.read_text(encoding="utf-8"))
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in _NAMES]

    def rooted(p: str) -> Path:
        return root / p.lstrip("/")

    def run(cmd: list[str], **_: Any) -> SimpleNamespace:
        assert cmd == ["systemctl", "is-active", "k3s.service"], cmd
        return SimpleNamespace(stdout=unit_state + "\n", returncode=0)

    namespace: dict[str, Any] = {
        "Path": rooted,
        "os": SimpleNamespace(path=SimpleNamespace(ismount=lambda p: mounted and p == "/etc")),
        "subprocess": SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired),
    }
    code = compile(
        ast.Module(body=body, type_ignores=[]),
        str(CONSOLE),
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    exec(code, namespace)  # noqa: S102 — the shipped console's own functions
    missing = _NAMES - set(namespace)
    assert not missing, f"not found in spatium-console: {sorted(missing)}"
    return namespace


def _slot(tmp_path: Path, *, cmdline: str = "root=PARTLABEL=root_A ro") -> Path:
    for d in ("usr/local/bin", "usr/share/doc/k3s", "usr/lib/etc.image", "proc"):
        (tmp_path / d).mkdir(parents=True)
    (tmp_path / "usr/local/bin/k3s").write_text("", encoding="utf-8")
    (tmp_path / "usr/share/doc/k3s/.version").write_text("v1.33.4+k3s1\n", encoding="utf-8")
    (tmp_path / "proc/cmdline").write_text(cmdline + "\n", encoding="utf-8")
    return tmp_path


def test_k3s_held_by_a_missing_overlay_says_so(tmp_path: Path) -> None:
    ns = _console(_slot(tmp_path), mounted=False, unit_state="inactive")
    assert ns["_etc_overlay_missing"]() is True
    label, style = ns["k3s_status"]()
    assert "held — /etc overlay not mounted" in label and "disabled" not in label
    assert style == "bold red"


def test_k3s_inactive_with_the_overlay_is_still_disabled(tmp_path: Path) -> None:
    ns = _console(_slot(tmp_path), mounted=True, unit_state="inactive")
    assert ns["_etc_overlay_missing"]() is False
    assert ns["k3s_status"]() == ("v1.33.4+k3s1 · disabled (systemctl enable --now k3s)", "yellow")


def test_the_live_iso_never_counts_as_a_missing_overlay(tmp_path: Path) -> None:
    ns = _console(_slot(tmp_path, cmdline="boot=live components quiet"), mounted=False,
                  unit_state="inactive")
    assert ns["_etc_overlay_missing"]() is False
    assert "disabled" in ns["k3s_status"]()[0]


def test_a_slot_without_the_overlay_baseline_never_counts(tmp_path: Path) -> None:
    root = _slot(tmp_path)
    os.rmdir(root / "usr/lib/etc.image")
    ns = _console(root, mounted=False, unit_state="inactive")
    assert ns["_etc_overlay_missing"]() is False
