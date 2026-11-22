"""A trial slot is not committed until its control chart has applied (#4707).

firstboot committed a trial slot as soon as k3s was Ready and the images
verified. A control chart that failed to apply (the helm controller refused the
api Deployment) left the upgrade committed in a split state: the api on the
previous release, worker / beat / frontend on the new one, the trial-boot
revert spent.

``control_converged_allow_commit`` now holds the commit until the api
Deployment carries this slot's tag and an api pod on it is Ready. On timeout:

  * the slot's migrate Job has NOT run -> exit 1, trial left uncommitted (a
    reboot reverts; Fleet "Approve trial" keeps it);
  * it HAS run -> commit (a revert would put the old api on a newer schema)
    and write the "control plane not converged" flag the supervisor ships.

The real functions run under dash and bash against a stub ``k3s``.

HOW TO RUN:
    python3 -m pytest appliance/tests/test_firstboot_control_converge_4707.py -v
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

FIRSTBOOT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatiumddi-firstboot"
)
SHELLS = [s for s in (shutil.which("dash"), shutil.which("bash")) if s]
VER = "1.0.2"
K3S = "/usr/local/bin/k3s"


def _lines() -> list[str]:
    return FIRSTBOOT.read_text(encoding="utf-8").splitlines()


def _function(name: str) -> str:
    lines = _lines()
    i = lines.index(f"{name}() {{")
    j = lines.index("}", i + 1)
    return "\n".join(lines[i : j + 1])


def _ready_branch() -> str:
    lines = _lines()
    i = lines.index('if [ "$ready" = 1 ]; then')
    j = lines.index("fi", i + 1)
    return "\n".join(lines[i : j + 1])


STUB = """#!/bin/sh
d="$(dirname "$0")"
case "$*" in
  *"get deployment"*) n=$(cat "$d/dcalls" 2>/dev/null || echo 0); echo $((n + 1)) > "$d/dcalls"
      if [ "$n" -ge "$(cat "$d/after")" ]; then cat "$d/img_new"; else cat "$d/img_old"; fi ;;
  *"get pods"*) n=$(cat "$d/dcalls" 2>/dev/null || echo 0)
      if [ "$n" -ge "$(cat "$d/after")" ]; then cat "$d/pods_new"; else cat "$d/pods_old"; fi ;;
  *"get jobs"*) cat "$d/jobs" ;;
esac
exit 0
"""


def _run(tmp_path, shell, *, after, trial=True, released=1, migrate=None):
    """after: k3s calls before the api shows the new tag (99 = never)."""
    k3s = tmp_path / "k3s"
    k3s.write_text(STUB)
    k3s.chmod(0o755)
    img = f"ghcr.io/spatiumnorth/spatiumddi-api:{VER}"
    old = "ghcr.io/spatiumnorth/spatiumddi-api:1.0.1"
    (tmp_path / "after").write_text(str(after))
    (tmp_path / "img_new").write_text(img)
    (tmp_path / "img_old").write_text(old)
    (tmp_path / "pods_new").write_text(f"{img}|True|\n")
    (tmp_path / "pods_old").write_text(f"{old}|True|\n")
    jobs = ""
    if migrate == "succeeded":
        jobs = f"{img}|1|\n"
    elif migrate == "old":
        jobs = f"{old}|1|\n"
    (tmp_path / "jobs").write_text(jobs)
    flag = tmp_path / "flag"
    fns = "\n".join(
        _function(n)
        for n in (
            "control_converge_budget",
            "control_chart_converged",
            "control_migrate_ran",
            "record_control_not_converged",
            "control_converged_allow_commit",
        )
    )
    script = f"""set -eu
SPATIUMDDI_VERSION={VER}
FIRSTBOOT_UNIT_T0=0
CONTROL_CONVERGE_TIMEOUT_S=3
CONTROL_CONVERGE_MARGIN_S=120
CONTROL_CONVERGE_POLL_S=1
CONTROL_API_DEPLOY=api
CONTROL_NOT_CONVERGED_FILE="{flag}"
CONTROL_CHART_RELEASED={released}
SPATIUM_HOST_GID=$(id -g)
uptime_s() {{ echo 0; }}
sleep() {{ :; }}
is_trial_boot() {{ return {0 if trial else 1}; }}
{fns.replace(K3S, str(k3s))}
control_converged_allow_commit
"""
    proc = subprocess.run([shell, "-c", script], capture_output=True, text=True, check=False)
    return proc, flag, tmp_path


@pytest.mark.parametrize("shell", SHELLS)
def test_commit_is_held_while_the_chart_has_not_applied_then_released(tmp_path, shell) -> None:
    proc, flag, d = _run(tmp_path, shell, after=2)
    assert proc.returncode == 0, proc.stderr
    assert int((d / "dcalls").read_text()) >= 3, "the gate did not wait for the api to move"
    assert "Control chart applied" in proc.stdout
    assert not flag.exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_commit_proceeds_at_once_when_the_chart_applied(tmp_path, shell) -> None:
    proc, flag, d = _run(tmp_path, shell, after=0)
    assert proc.returncode == 0, proc.stderr
    assert "Waiting up to" not in proc.stdout
    assert not flag.exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_timeout_without_a_migrate_run_leaves_the_trial_uncommitted(tmp_path, shell) -> None:
    proc, flag, _ = _run(tmp_path, shell, after=99, migrate=None)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "trial boot: NOT committing this slot; next reboot reverts." in proc.stderr
    assert "Fleet (Approve trial, on this node's slot)" in proc.stderr
    assert not flag.exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_a_previous_releases_migrate_job_does_not_count(tmp_path, shell) -> None:
    proc, flag, _ = _run(tmp_path, shell, after=99, migrate="old")
    assert proc.returncode == 1
    assert not flag.exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_timeout_after_a_migrate_run_commits_and_flags(tmp_path, shell) -> None:
    proc, flag, _ = _run(tmp_path, shell, after=99, migrate="succeeded")
    assert proc.returncode == 0, proc.stderr
    assert "revert to the previous slot is unsafe" in proc.stderr
    rec = json.loads(flag.read_text())
    assert rec["version"] == VER and "did not apply" in rec["detail"] and rec["at"]


@pytest.mark.parametrize("shell", SHELLS)
def test_a_node_that_did_not_release_the_chart_never_waits(tmp_path, shell) -> None:
    proc, flag, d = _run(tmp_path, shell, after=99, released=0)
    assert proc.returncode == 0, proc.stderr
    assert not (d / "dcalls").exists(), "a joined member / held chart must not query or wait"


@pytest.mark.parametrize("shell", SHELLS)
def test_a_steady_state_boot_is_never_delayed(tmp_path, shell) -> None:
    proc, flag, _ = _run(tmp_path, shell, after=99, trial=False)
    assert proc.returncode == 0, proc.stderr
    assert "Waiting up to" not in proc.stdout


def test_the_gate_sits_between_the_image_gate_and_the_commit() -> None:
    branch = [ln.strip() for ln in _ready_branch().splitlines()]
    gate = branch.index("control_converged_allow_commit || exit 1")
    assert branch[gate - 2] == "slot_images_allow_commit || exit 1"
    assert branch[gate + 1] == "commit_slot_if_healthy"


def test_only_a_live_chart_marks_this_node_as_the_one_to_wait() -> None:
    fn = _function("place_deferred_control_manifest")
    assert "CONTROL_CHART_RELEASED=1" in fn
    assert '[ ! -f "$CONTROL_MANIFEST_HELD" ]' in fn
