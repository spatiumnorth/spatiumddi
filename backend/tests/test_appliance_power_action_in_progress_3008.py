"""#3008 — the system status reports a reboot under way (the host wrapper's
flock), which stays true after the trigger file is renamed."""

import fcntl
import subprocess
import sys

from app.services.appliance import system as sysmod


def test_false_without_a_lock_file(tmp_path, monkeypatch):
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", tmp_path / "absent")
    assert sysmod.power_action_in_progress() is False


def test_false_when_the_file_exists_but_nobody_holds_it(tmp_path, monkeypatch):
    lock = tmp_path / "power-action-active"
    lock.write_text("")
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", lock)
    assert sysmod.power_action_in_progress() is False


def test_true_while_another_process_holds_it_and_clears_when_it_dies(tmp_path, monkeypatch):
    lock = tmp_path / "power-action-active"
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", lock)
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl,sys,time\n"
            "f=open(sys.argv[1],'w'); fcntl.flock(f, fcntl.LOCK_EX)\n"
            "print('held', flush=True); time.sleep(60)",
            str(lock),
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


def test_the_probe_does_not_keep_the_lock(tmp_path, monkeypatch):
    lock = tmp_path / "power-action-active"
    lock.write_text("")
    monkeypatch.setattr(sysmod, "_POWER_ACTION_LOCK", lock)
    assert sysmod.power_action_in_progress() is False
    with open(lock, "rb") as f:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
