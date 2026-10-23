"""Host-portable pytest for spatiumddi-slot-upgrade (#421).

The runner carries most of acceptance criterion (1) — "a killed / stalled
apply surfaces as failed" — through three guards: an EXIT trap that writes
``failed`` on abrupt exit, a ``timeout`` cap that self-fails a stalled
apply, and a liveness ticker that re-stamps the in-flight marker so the
supervisor's staleness backstop can tell a live-but-slow apply from a dead
one. These tests drive the real script as a subprocess against a synthetic
tmp tree, stubbing the ``spatium-upgrade-slot`` binary it shells out to.

PATH OVERRIDES (defaulting to the production appliance locations, so the
tests just point them at a tmp tree — no script rewriting):
  SPATIUM_SLOT_TRIGGER, SPATIUM_SLOT_PROGRESS, SPATIUM_SLOT_LOG_DIR,
  SPATIUM_UPGRADE_SLOT_BIN, SPATIUM_SLOT_TICK_SECONDS,
  SPATIUM_SLOT_APPLY_TIMEOUT.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_slot_upgrade_runner.py -v

No database, no Docker, no appliance ISO required.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

RUNNER = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-slot-upgrade"
)


def _env(tmp_path: Path, stub_bin: Path, **extra: str) -> dict[str, str]:
    return {
        **os.environ,
        "SPATIUM_SLOT_TRIGGER": str(tmp_path / "slot-upgrade-pending"),
        "SPATIUM_SLOT_PROGRESS": str(tmp_path / "slot-upgrade.progress"),
        "SPATIUM_SLOT_LOG_DIR": str(tmp_path / "log"),
        "SPATIUM_UPGRADE_SLOT_BIN": str(stub_bin),
        "SPATIUM_SLOT_TICK_SECONDS": "1",
        **extra,
    }


def _write_stub(tmp_path: Path, body: str) -> Path:
    stub = tmp_path / "spatium-upgrade-slot"
    stub.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8")
    stub.chmod(0o755)
    return stub


def _seed_trigger(tmp_path: Path) -> Path:
    trigger = tmp_path / "slot-upgrade-pending"
    trigger.write_text("https://example/img.raw.xz\n", encoding="utf-8")
    return trigger


def _state(tmp_path: Path) -> str:
    p = tmp_path / "slot-upgrade-pending.state"
    return p.read_text(encoding="utf-8").strip() if p.exists() else ""


def test_clean_apply_writes_done_and_renames_trigger(tmp_path: Path) -> None:
    stub = _write_stub(
        tmp_path, "exit 0"
    )  # any subcommand (apply / set-next-boot) succeeds
    trigger = _seed_trigger(tmp_path)
    subprocess.run(
        ["bash", str(RUNNER)], env=_env(tmp_path, stub), capture_output=True, timeout=30
    )
    assert _state(tmp_path).startswith("done ")
    assert not trigger.exists()
    assert len(list(tmp_path.glob("slot-upgrade-pending.done.*"))) == 1


def test_reboot_pending_records_the_staged_boot_and_slot(tmp_path: Path) -> None:
    """#2007 — the supervisor settles reboot-pending off these two fields:
    a different boot_id later is the reboot, a different slot a rollback."""
    import json

    stub = _write_stub(tmp_path, "exit 0")
    _seed_trigger(tmp_path)
    grubenv = tmp_path / "grubenv"
    grubenv.write_text(
        "# GRUB Environment Block\nsaved_entry=slot_a\nnext_entry=slot_b\n" + "#" * 64,
        encoding="utf-8",
    )
    boot_id = tmp_path / "boot_id"
    boot_id.write_text("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\n", encoding="utf-8")
    subprocess.run(
        ["bash", str(RUNNER)],
        env=_env(
            tmp_path, stub, SPATIUM_GRUBENV=str(grubenv), SPATIUM_BOOT_ID_FILE=str(boot_id)
        ),
        capture_output=True,
        timeout=30,
    )
    prog = json.loads((tmp_path / "slot-upgrade.progress").read_text(encoding="utf-8"))
    assert prog["step"] == "reboot-pending"
    assert prog["staged_slot"] == "slot_b"
    assert prog["staged_boot_id"] == "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


def test_reboot_pending_omits_an_unreadable_identity(tmp_path: Path) -> None:
    import json

    stub = _write_stub(tmp_path, "exit 0")
    _seed_trigger(tmp_path)
    subprocess.run(
        ["bash", str(RUNNER)],
        env=_env(
            tmp_path,
            stub,
            SPATIUM_GRUBENV=str(tmp_path / "absent"),
            SPATIUM_BOOT_ID_FILE=str(tmp_path / "absent-too"),
        ),
        capture_output=True,
        timeout=30,
    )
    assert _state(tmp_path).startswith("done ")
    prog = json.loads((tmp_path / "slot-upgrade.progress").read_text(encoding="utf-8"))
    assert prog["step"] == "reboot-pending"
    assert "staged_slot" not in prog and "staged_boot_id" not in prog


def test_apply_failure_writes_failed(tmp_path: Path) -> None:
    stub = _write_stub(tmp_path, "exit 1")
    trigger = _seed_trigger(tmp_path)
    subprocess.run(
        ["bash", str(RUNNER)], env=_env(tmp_path, stub), capture_output=True, timeout=30
    )
    assert _state(tmp_path).startswith("failed ")
    assert not trigger.exists()
    assert len(list(tmp_path.glob("slot-upgrade-pending.failed.*"))) == 1


def test_stalled_apply_self_fails_via_timeout(tmp_path: Path) -> None:
    stub = _write_stub(tmp_path, "sleep 60")
    _seed_trigger(tmp_path)
    subprocess.run(
        ["bash", str(RUNNER)],
        env=_env(tmp_path, stub, SPATIUM_SLOT_APPLY_TIMEOUT="2"),
        capture_output=True,
        timeout=30,
    )
    assert _state(tmp_path).startswith("failed ")
    prog = (tmp_path / "slot-upgrade.progress").read_text(encoding="utf-8")
    assert "timed out" in prog


def test_sigterm_mid_apply_trap_writes_failed(tmp_path: Path) -> None:
    """systemd's TimeoutStartSec backstop SIGTERMs a wedged runner — the
    EXIT trap must then record failed rather than leaving in-flight."""
    stub = _write_stub(tmp_path, "sleep 60")
    _seed_trigger(tmp_path)
    proc = subprocess.Popen(
        ["bash", str(RUNNER)],
        env=_env(tmp_path, stub, SPATIUM_SLOT_APPLY_TIMEOUT="120"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait until it enters the in-flight region, then SIGTERM the runner.
    deadline = time.time() + 10
    while time.time() < deadline and not _state(tmp_path).startswith("in-flight"):
        time.sleep(0.1)
    assert _state(tmp_path).startswith("in-flight")
    proc.terminate()
    proc.wait(timeout=15)
    assert _state(tmp_path).startswith("failed ")


def test_ticker_keeps_stamp_fresh_then_cleans_up(tmp_path: Path) -> None:
    """A slow-but-successful apply: the 1 s ticker re-stamps the in-flight
    marker (so the supervisor never falsely reaps a live apply), then the
    ticker is reaped and the terminal state is done."""
    stub = _write_stub(
        tmp_path, '[ "$1" = "set-next-boot" ] && exit 0; sleep 3; exit 0'
    )
    _seed_trigger(tmp_path)
    proc = subprocess.Popen(
        ["bash", str(RUNNER)],
        env=_env(tmp_path, stub),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 10
    while time.time() < deadline and not _state(tmp_path).startswith("in-flight"):
        time.sleep(0.1)
    s1 = _state(tmp_path)
    time.sleep(1.3)
    s2 = _state(tmp_path)
    proc.wait(timeout=15)
    # The stamp advanced while the apply ran → ticker alive.
    assert s1.startswith("in-flight") and s2.startswith("in-flight")
    assert s1 != s2
    # And the run finished cleanly.
    assert _state(tmp_path).startswith("done ")


def test_no_trigger_is_noop(tmp_path: Path) -> None:
    """No trigger file → exit 0 with no terminal state churn (the EXIT
    trap is armed only inside the apply region)."""
    stub = _write_stub(tmp_path, "exit 0")
    proc = subprocess.run(
        ["bash", str(RUNNER)], env=_env(tmp_path, stub), capture_output=True, timeout=30
    )
    assert proc.returncode == 0
    assert _state(tmp_path) == ""


# --- #1747: durable sidecar writes -------------------------------------------

_HOST_RUNNERS = [
    "spatiumddi-slot-upgrade",
    "spatiumddi-slot-set-next-boot",
    "spatiumddi-slot-set-default",
    "spatiumddi-slot-rollback",
]


def _extract_atomic_write(script: str) -> str:
    import re

    text = (RUNNER.parent / script).read_text(encoding="utf-8")
    m = re.search(r"^fsync_path\(\).*?^atomic_write\(\) \{.*?^\}\n", text, re.S | re.M)
    assert m, f"{script} has no fsync_path/atomic_write helpers"
    return m.group(0)


def test_every_slot_runner_writes_state_durably() -> None:
    """No runner may redirect straight into a ``.state`` file any more: a
    power loss then leaves it NUL-filled and the node's heartbeats 422."""
    for script in _HOST_RUNNERS:
        text = (RUNNER.parent / script).read_text(encoding="utf-8")
        assert '> "${TRIGGER}.state"' not in text, script
        assert 'atomic_write "${TRIGGER}.state"' in text, script


def test_atomic_write_replaces_via_temp_and_fsyncs(tmp_path: Path) -> None:
    """Run the shipped helper under bash with a ``sync`` shim recording
    which paths were fsynced and what the temp file held at that moment."""
    shim = tmp_path / "shim"
    shim.mkdir()
    trace = tmp_path / "trace"
    (shim / "sync").write_text(
        '#!/bin/bash\nfor p in "$@"; do\n'
        f'  if [ -f "$p" ]; then echo "file:$p:$(cat "$p")" >> {trace}; '
        f'else echo "dir:$p" >> {trace}; fi\ndone\n',
        encoding="utf-8",
    )
    (shim / "sync").chmod(0o755)
    for script in _HOST_RUNNERS:
        trace.write_text("")
        target = tmp_path / f"{script}.state"
        target.write_text("old\n")
        target.chmod(0o640)
        src = _extract_atomic_write(script) + f'\natomic_write "{target}" "done X"\n'
        r = subprocess.run(
            ["bash", "-c", src],
            env={**os.environ, "PATH": f"{shim}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        assert target.read_text() == "done X\n"
        assert (target.stat().st_mode & 0o777) == 0o640  # mode preserved
        lines = trace.read_text().splitlines()
        # temp file fsynced WITH its full content before the rename ...
        assert any(
            ln.startswith("file:")
            and ln.endswith(":done X")
            and str(target) + "." in ln
            for ln in lines
        ), lines
        # ... then the directory.
        assert lines[-1] == f"dir:{tmp_path}", lines
        assert not [
            p for p in tmp_path.iterdir() if p.name.startswith(target.name + ".")
        ]


def test_atomic_write_creates_a_missing_target_readable(tmp_path: Path) -> None:
    """First write of a sidecar: mktemp's 0600 must not leak through, or the
    supervisor (a different user) could never read the state."""
    for script in _HOST_RUNNERS:
        target = tmp_path / f"{script}.new.state"
        src = _extract_atomic_write(script) + f'\natomic_write "{target}" "in-flight X"\n'
        r = subprocess.run(["bash", "-c", src], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert target.read_text() == "in-flight X\n"
        assert (target.stat().st_mode & 0o777) == 0o644


def test_atomic_write_failure_leaves_the_target_and_no_temp(tmp_path: Path) -> None:
    """A write that cannot complete returns non-zero and never replaces the
    target with a partial file."""
    for script in _HOST_RUNNERS:
        target = tmp_path / "missing-dir" / "x.state"
        src = _extract_atomic_write(script) + f'\natomic_write "{target}" "done"\n'
        r = subprocess.run(["bash", "-c", src], capture_output=True, text=True)
        assert r.returncode != 0
        assert not target.exists()


def test_exit_trap_is_armed_before_the_in_flight_stamp() -> None:
    """#2424: a SIGTERM landing between the in-flight stamp and the trap
    left the state at in-flight. The trap must come first."""
    text = RUNNER.read_text(encoding="utf-8")
    body = text[text.index('if [ ! -f "$TRIGGER" ]; then') :]
    assert body.index("trap on_exit EXIT") < body.index("\nmark_inflight")
