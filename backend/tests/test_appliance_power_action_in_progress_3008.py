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
