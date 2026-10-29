"""#3008 — the system status reports a reboot under way (the host wrapper's
flock on the release-state directory), which stays true after the trigger
file is renamed."""

import fcntl
import os
import subprocess
import sys

from app.config import settings
from app.services.appliance import system as sysmod


def test_false_without_the_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", tmp_path / "absent")
    assert sysmod.power_action_in_progress() is False


def test_false_when_nobody_holds_it(tmp_path, monkeypatch):
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", tmp_path)
    assert sysmod.power_action_in_progress() is False


def test_true_while_another_process_holds_it_and_clears_when_it_dies(tmp_path, monkeypatch):
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", tmp_path)
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl,os,sys,time\n"
            "fd=os.open(sys.argv[1],os.O_RDONLY); fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('held', flush=True); time.sleep(60)",
            str(tmp_path),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        assert sysmod.power_action_in_progress() is True
        assert sysmod.get_system_info().reboot_in_progress is True
    finally:
        holder.kill()
        holder.wait()
    # killed outright: the kernel released the lock, nothing is stuck
    assert sysmod.power_action_in_progress() is False


def test_the_probe_does_not_keep_the_lock_and_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", tmp_path)
    assert sysmod.power_action_in_progress() is False
    assert list(tmp_path.iterdir()) == []
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_the_lock_is_the_release_state_directory_itself():
    """A file in it could be a symlink the api or supervisor planted; the
    wrapper runs as root."""
    assert sysmod._POWER_ACTION_LOCK == sysmod._STATE_DIR


def test_the_info_names_the_node_it_describes(monkeypatch):
    """The reboot fields are read from the host of the node whose api pod
    served the request; on a cluster that is a per-request choice, so the
    answer says which node it is about."""
    monkeypatch.setattr(settings, "node_name", "ddi2")
    assert sysmod.get_system_info().node == "ddi2"
    monkeypatch.setattr(settings, "node_name", "")
    assert sysmod.get_system_info().node is None


# ---- the whole window (#3008, QA case 3) -------------------------------------
# The lock alone covered 0.4-1.8 s of a one-node reboot: nothing during the
# Fleet agent's grace, nothing after the wrapper had issued systemctl while the
# node was still going down.

BOOT = "11111111-2222-3333-4444-555555555555"


def _window(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot_id"
    boot.write_text(BOOT + "\n")
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", state)
    monkeypatch.setattr(sysmod, "_REBOOT_TRIGGER", state / "reboot-pending")
    monkeypatch.setattr(sysmod, "_FLEET_TRIGGER", state / "reboot-pending-fleet")
    monkeypatch.setattr(sysmod, "_FLEET_GRACE_MARKER", state / "reboot-fleet-grace")
    monkeypatch.setattr(sysmod, "_POWER_ACTION_ISSUED", state / "power-action-issued")
    monkeypatch.setattr(sysmod, "_BOOT_ID", boot)
    return state


def test_nothing_under_way_reads_false(tmp_path, monkeypatch):
    _window(tmp_path, monkeypatch)
    assert sysmod.reboot_in_progress() is False
    assert sysmod.get_system_info().reboot_in_progress is False


def test_a_pending_trigger_reads_true(tmp_path, monkeypatch):
    state = _window(tmp_path, monkeypatch)
    (state / "reboot-pending-fleet").write_text("stamp\n")
    assert sysmod.reboot_in_progress() is True
    (state / "reboot-pending-fleet").unlink()
    (state / "reboot-pending").write_text("stamp\n")
    assert sysmod.reboot_in_progress() is True


def test_the_fleet_agents_grace_marker_reads_true_in_this_boot_only(tmp_path, monkeypatch):
    state = _window(tmp_path, monkeypatch)
    marker = state / "reboot-fleet-grace"
    marker.write_text(f"4242 {BOOT}\n")
    assert sysmod.reboot_in_progress() is True
    marker.write_text("4242 99999999-0000-0000-0000-000000000000\n")
    assert sysmod.reboot_in_progress() is False


def test_a_grace_marker_left_by_a_killed_agent_expires(tmp_path, monkeypatch):
    """The api cannot check the agent's pid (its own pid namespace); an aged
    marker counts for nothing, and the wrapper's lock is the answer by then."""
    state = _window(tmp_path, monkeypatch)
    marker = state / "reboot-fleet-grace"
    marker.write_text(f"4242 {BOOT}\n")
    old = marker.stat().st_mtime - sysmod._GRACE_MARKER_MAX_AGE_S - 5
    os.utime(marker, (old, old))
    assert sysmod.reboot_in_progress() is False


def test_an_issued_marker_of_this_boot_reads_true_and_of_another_boot_false(tmp_path, monkeypatch):
    """Written by the wrapper just before systemctl reboot; the lock ends with
    the wrapper, the node is not down yet. A new boot has a new boot id, so the
    marker expires by itself."""
    state = _window(tmp_path, monkeypatch)
    issued = state / "power-action-issued"
    issued.write_text(f"reboot {BOOT}\n")
    assert sysmod.reboot_in_progress() is True
    assert sysmod.get_system_info().reboot_in_progress is True
    (tmp_path / "boot_id").write_text("99999999-0000-0000-0000-000000000000\n")
    assert sysmod.reboot_in_progress() is False


def test_markers_without_a_boot_id_to_compare_read_false(tmp_path, monkeypatch):
    state = _window(tmp_path, monkeypatch)
    (state / "power-action-issued").write_text(f"reboot {BOOT}\n")
    (state / "reboot-fleet-grace").write_text("garbage\n")
    monkeypatch.setattr(sysmod, "_BOOT_ID", tmp_path / "absent")
    assert sysmod.reboot_in_progress() is False
