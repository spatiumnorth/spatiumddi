"""A trial boot does not commit its slot while one of the slot's images is missing (#1630).

firstboot commits a trial slot (``commit_slot_if_healthy``, grub-set-default)
once the apiserver answers and the control chart is placed. Nothing checked the
slot's images. A slot upgrade whose first boot failed to import the DNS and
DHCP agents' tarballs committed anyway. The swap became durable with
``ErrImageNeverPull`` agents, and no reboot would bring the previous slot
back.

Now the ready branch runs ``slot_images_allow_commit`` before the commit. It
runs ``spatium-k3s-images verify --repair`` (through ``check_slot_images``).
When an image is still missing, a trial boot exits 1 before the commit, so the
previous slot stays the durable default and the next reboot reverts to it, as
a failed host-migrate does (#554). A steady-state boot has nothing to commit
and goes on.

These tests run firstboot's real ready branch and its real functions under
``sh`` (dash on the appliance and on the CI runner). The steps around them are
stubbed, as are the helper and ``is_trial_boot``.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_firstboot_slot_images_gate.py -v
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FIRSTBOOT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-firstboot"
)
SHELL = shutil.which("dash") or "sh"
HELPER = "/usr/local/bin/spatium-k3s-images"


def _lines() -> list[str]:
    return FIRSTBOOT.read_text(encoding="utf-8").splitlines()


def _function(name: str) -> str | None:
    lines = _lines()
    try:
        i = lines.index(f"{name}() {{")
    except ValueError:
        return None
    j = lines.index("}", i + 1)
    return "\n".join(lines[i : j + 1])


def _ready_branch() -> str:
    lines = _lines()
    i = lines.index('if [ "$ready" = 1 ]; then')
    j = lines.index("fi", i + 1)
    return "\n".join(lines[i : j + 1])


def _boot(tmp_path: Path, *, helper_rc: int, trial: bool):
    helper = tmp_path / "spatium-k3s-images"
    helper.write_text(f'#!/bin/sh\necho "$*" >> "{tmp_path}/helper.log"\nexit {helper_rc}\n')
    helper.chmod(0o755)
    selfcheck = tmp_path / "webui-selfcheck"
    selfcheck.write_text("#!/bin/sh\nexit 0\n")
    selfcheck.chmod(0o755)
    real = "\n".join(
        f for f in (_function("check_slot_images"), _function("slot_images_allow_commit")) if f
    )
    branch = _ready_branch().replace("/usr/local/bin/spatiumddi-webui-selfcheck", str(selfcheck))
    script = f"""set -eu
STAMP="{tmp_path}/stamp"
BOOTSTRAP_MANIFEST="{tmp_path}/spatium-bootstrap.yaml"
ready=1
date() {{ echo 2026-10-06T20:00:00+00:00; }}
ip() {{ :; }}
tighten_kubeconfig() {{ :; }}
pin_control_failure_policy() {{ :; }}
place_deferred_tls_manifest() {{ :; }}
reassert_control_plane_class() {{ :; }}
place_deferred_control_manifest() {{ :; }}
commit_slot_if_healthy() {{ echo committed > "{tmp_path}/committed"; }}
is_trial_boot() {{ return {0 if trial else 1}; }}
{real.replace(HELPER, str(helper))}
{branch}
"""
    proc = subprocess.run([SHELL, "-c", script], capture_output=True, text=True, check=False)
    return proc, (tmp_path / "committed").exists()


def test_a_trial_boot_with_an_image_missing_does_not_commit(tmp_path) -> None:
    proc, committed = _boot(tmp_path, helper_rc=1, trial=True)
    assert not committed, (
        "firstboot committed the trial slot while one of its images was missing: the "
        "swap is now durable with agents stuck in ErrImageNeverPull (#1630)"
    )
    assert proc.returncode == 1, "a trial boot that does not commit must leave firstboot failed"
    assert "trial boot: NOT committing this slot; next reboot reverts." in proc.stderr
    assert (tmp_path / "helper.log").read_text().split() == ["verify", "--repair"]


def test_a_trial_boot_with_every_image_present_commits(tmp_path) -> None:
    proc, committed = _boot(tmp_path, helper_rc=0, trial=True)
    assert committed
    assert proc.returncode == 0, proc.stderr


def test_a_steady_state_boot_with_an_image_missing_goes_on(tmp_path) -> None:
    proc, committed = _boot(tmp_path, helper_rc=1, trial=False)
    assert committed, "commit_slot_if_healthy is a no-op on a steady-state boot and must still run"
    assert proc.returncode == 0, proc.stderr
    assert "steady-state boot: nothing to commit; continuing." in proc.stderr


@pytest.mark.parametrize("name", ["check_slot_images", "slot_images_allow_commit"])
def test_the_gate_is_defined_once(name) -> None:
    assert sum(1 for ln in _lines() if ln == f"{name}() {{") == 1


def test_the_gate_sits_right_before_the_commit() -> None:
    branch = [ln.strip() for ln in _ready_branch().splitlines()]
    assert "slot_images_allow_commit || exit 1" in branch, "the ready branch has no image gate (#1630)"
    gate = branch.index("slot_images_allow_commit || exit 1")
    assert branch[gate + 1] == "commit_slot_if_healthy"
    assert branch.index("place_deferred_control_manifest") < gate
