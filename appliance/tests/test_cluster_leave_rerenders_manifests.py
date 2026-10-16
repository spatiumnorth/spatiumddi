"""#1866 — a leave renders the bootstrap manifests for the build the node runs.

A member sets its own bootstrap manifests aside when it joins and its leave
puts them back. Those copies name the build it joined on: the chart they
embed and the image tags they ask for. A member slot upgraded since holds
only the new build's images, and the manifests never pull, so the leave
brought up no supervisor (ErrImageNeverPull) and the row never left
`leaving`. The leave now runs firstboot's render-only mode after the
restore and before k3s starts: the manifests are rendered for the running
build, as the node's next boot would render them.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

BIN = Path(__file__).resolve().parents[1] / "mkosi.extra" / "usr" / "local" / "bin"
JOIN = BIN / "spatium-cluster-join"
FIRSTBOOT = BIN / "spatiumddi-firstboot"


def _rerender(tmp_path: Path, rc: int) -> tuple[int, list[str], str]:
    """Run rerender_bootstrap_manifests against a stub firstboot that records
    the render-only flag and exits ``rc``."""
    seen = tmp_path / "seen"
    stub = tmp_path / "firstboot"
    stub.write_text(f'#!/bin/sh\necho "$SPATIUM_FIRSTBOOT_RENDER_ONLY" > "{seen}"\nexit {rc}\n')
    stub.chmod(0o755)
    version = tmp_path / "version"
    version.write_text("2026.10.15\n")
    script = f'source "{JOIN}"\nlog() {{ echo "LOG: $*"; }}\nrerender_bootstrap_manifests\n'
    proc = subprocess.run(
        ["bash", "-c", script],
        env={
            **os.environ,
            "SPATIUM_CLUSTER_JOIN_LIB": "1",
            "SPATIUM_FIRSTBOOT": str(stub),
            "SPATIUM_VERSION_FILE": str(version),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout.splitlines(), seen.read_text().strip()


def test_the_leave_asks_firstboot_for_a_render_only_run(tmp_path: Path) -> None:
    rc, out, flag = _rerender(tmp_path, 0)
    assert rc == 0
    assert flag == "1"
    assert out == ["LOG: re-rendered the bootstrap manifests for 2026.10.15 (#1866)"]


def test_a_failed_render_keeps_the_restored_copies_and_the_leave_going(tmp_path: Path) -> None:
    rc, out, _flag = _rerender(tmp_path, 3)
    assert rc == 0
    assert out == [
        "LOG: WARN: re-rendering the bootstrap manifests failed (rc=3); starting on the "
        "copies set aside at join time"
    ]


def _do_leave() -> str:
    text = JOIN.read_text()
    start = text.index("do_leave() {")
    return text[start : text.index("\n}\n", start)]


def test_the_render_runs_after_the_restore_and_before_k3s_starts() -> None:
    dl = _do_leave()
    render = dl.index("    rerender_bootstrap_manifests\n")
    # Firstboot renders nothing for a joined member: the drop-in goes first.
    assert dl.index('rm -f "$JOIN_DROPIN"') < render
    # The restore would otherwise overwrite the fresh render with the copies.
    assert dl.index('mv -f "$MANIFESTS_ASIDE"/*.yaml* "$K3S_MANIFESTS/"') < render
    assert dl.index('rm -f "$K3S_MANIFESTS/spatium-appliance-tls.yaml.skip"') < render
    assert render < dl.index("systemctl start k3s && leave_wait_ready")


def _firstboot_lines() -> list[str]:
    return FIRSTBOOT.read_text().splitlines()


def test_firstboots_render_only_mode_stops_right_after_the_render() -> None:
    lines = _firstboot_lines()
    guard = next(
        i for i, ln in enumerate(lines) if ln.startswith('if [ "${SPATIUM_FIRSTBOOT_RENDER_ONLY:-}"')
    )
    # The render's `case "$BOOTSTRAP_ROLE"` closes just above it ...
    render_case = next(i for i, ln in enumerate(lines) if ln == 'case "$BOOTSTRAP_ROLE" in')
    render_end = next(i for i in range(render_case, len(lines)) if lines[i] == "esac")
    assert render_case < render_end < guard
    assert "exit 0" in lines[guard + 2]
    # ... and nothing that waits on k3s, or changes it, runs before it: the
    # leave runs this with k3s stopped.
    code = [ln for ln in lines[:guard] if not ln.lstrip().startswith("#")]
    for forbidden in ("systemctl", "kubectl", "k3s ", "sleep "):
        offenders = [ln for ln in code if forbidden in ln]
        assert not offenders, f"{forbidden}: {offenders}"


def test_render_only_skips_what_a_boot_does_after_the_render() -> None:
    text = FIRSTBOOT.read_text()
    guard = text.index('if [ "${SPATIUM_FIRSTBOOT_RENDER_ONLY:-}" = "1" ]; then')
    for later in ("# ── Render agent landing page", "commit_slot_if_healthy() {"):
        assert guard < text.index(later), later
    assert re.search(r"render-only \(#1866\)", text)
