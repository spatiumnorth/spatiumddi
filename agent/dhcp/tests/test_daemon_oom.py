"""A Kea killed by the container's memory limit is reported (#2023).

The entrypoint restarts a killed Kea within two seconds and the agent
heartbeated ``ok`` throughout, so a DHCP server in an OOM crash loop read
healthy. These tests pin the agent-side record (Compose: Docker kills Kea
alone and the agent survives): the cgroup's ``oom_kill`` counter is sampled,
a kill is persisted across an agent restart, it outranks the sync loop's own
``ok`` on the heartbeat, and it clears once the counter has been still for
``STABLE_SECONDS``.
"""

from __future__ import annotations

from pathlib import Path

from spatium_dhcp_agent.heartbeat import HeartbeatClient
from spatium_dhcp_agent.oom_watch import (
    STABLE_SECONDS,
    OomWatch,
    cgroup_memory_limit_bytes,
    read_oom_kill_count,
)

GIB = 1 << 30


def _events(path: Path, kills: int) -> Path:
    path.write_text(f"low 0\nhigh 0\nmax 12\noom 3\noom_kill {kills}\noom_group_kill 0\n")
    return path


def test_reads_the_v2_and_v1_counters(tmp_path: Path) -> None:
    v2 = _events(tmp_path / "memory.events", 4)
    v1 = tmp_path / "memory.oom_control"
    v1.write_text("oom_kill_disable 0\nunder_oom 0\noom_kill 2\n")
    assert read_oom_kill_count((str(v2),)) == 4
    assert read_oom_kill_count((str(tmp_path / "absent"), str(v1))) == 2
    # No counter at all is UNKNOWN, not zero.
    assert read_oom_kill_count((str(tmp_path / "absent"),)) is None


def test_the_memory_limit_is_read_and_unlimited_is_none(tmp_path: Path) -> None:
    lim = tmp_path / "memory.max"
    lim.write_text(f"{GIB}\n")
    assert cgroup_memory_limit_bytes((str(lim),)) == GIB
    lim.write_text("max\n")
    assert cgroup_memory_limit_bytes((str(lim),)) is None


def test_a_kill_before_this_agent_started_is_not_ours(tmp_path: Path) -> None:
    ev = _events(tmp_path / "memory.events", 3)
    watch = OomWatch(tmp_path, files=(str(ev),))
    watch.poll(now=100)
    assert watch.daemon_status() is None


def test_a_counter_that_moves_is_recorded_and_reported(tmp_path: Path) -> None:
    ev = _events(tmp_path / "memory.events", 0)
    watch = OomWatch(tmp_path, files=(str(ev),), limit_bytes=GIB)
    _events(ev, 1)
    watch.poll(now=1000)
    status = watch.daemon_status()
    assert status is not None and status["status"] == "degraded"
    reason = status["reason"]
    assert reason.startswith("oom_killed:")
    assert "1 GiB memory limit" in reason and "once" in reason
    # The control plane reads a ``config_apply_`` prefix as a config verdict.
    assert not reason.startswith("config_apply_")

    # The same counter value is not a second kill.
    watch.poll(now=1001)
    assert "once" in (watch.daemon_status() or {})["reason"]
    _events(ev, 2)
    watch.poll(now=1002)
    assert "2 times" in (watch.daemon_status() or {})["reason"]


def test_the_record_survives_an_agent_restart_and_clears_when_still(
    tmp_path: Path,
) -> None:
    ev = _events(tmp_path / "memory.events", 0)
    watch = OomWatch(tmp_path, files=(str(ev),))
    _events(ev, 1)
    watch.poll(now=1000)

    restarted = OomWatch(tmp_path, files=(str(ev),))  # a new container: same state dir
    assert restarted.daemon_status() is not None
    restarted.poll(now=1000 + STABLE_SECONDS - 1)
    assert restarted.daemon_status() is not None
    restarted.poll(now=1000 + STABLE_SECONDS)
    assert restarted.daemon_status() is None
    assert OomWatch(tmp_path, files=(str(ev),)).daemon_status() is None


def test_the_record_outranks_the_sync_loops_ok_on_the_wire(agent_cfg, tmp_path: Path) -> None:
    ev = _events(tmp_path / "memory.events", 0)
    watch = OomWatch(tmp_path, files=(str(ev),))
    hb = HeartbeatClient(agent_cfg, ["tok"])
    hb.oom_watch = watch
    hb.daemon_status = {"status": "ok"}
    assert hb._wire_daemon() == {"status": "ok"}

    _events(ev, 1)
    watch.poll(now=5)
    # The sync loop writes ``ok`` after every good reload; a Kea that was just
    # killed reloads fine, so that write must not erase the kill.
    hb.daemon_status = {"status": "ok"}
    wire = hb._wire_daemon()
    assert wire["status"] == "degraded" and wire["reason"].startswith("oom_killed:")


def _kea(tmp_path: Path, v4: int | None, v6: int | None) -> tuple[tuple[str, str], Path]:
    """Pid files as the entrypoint leaves them, plus a fake ``/proc`` holding
    a directory for each live pid. None removes that pid file (the supervise
    loop deletes it before each restart)."""
    proc = tmp_path / "proc"
    proc.mkdir(exist_ok=True)
    files = (str(tmp_path / "kea-dhcp4.pid"), str(tmp_path / "kea-dhcp6.pid"))
    for path, pid in zip(files, (v4, v6), strict=True):
        if pid is None:
            Path(path).unlink(missing_ok=True)
        else:
            Path(path).write_text(f"{pid}\n")
            (proc / str(pid)).mkdir(exist_ok=True)
    return files, proc


def test_a_kill_kea_survived_is_not_reported(tmp_path: Path) -> None:
    """The config preflight (``kea-dhcp4 -t``) or radvd was the victim: both
    Kea daemons are the same live processes as at the last tick. Reporting it
    would raise "not serving" against a Kea that is serving."""
    ev = _events(tmp_path / "memory.events", 0)
    pids, proc = _kea(tmp_path, 40, 41)
    watch = OomWatch(tmp_path, files=(str(ev),), pid_files=pids, proc_root=str(proc))
    _events(ev, 1)
    watch.poll(now=10)
    assert watch.daemon_status() is None
    # Consumed: the same kill is not reported on a later tick either.
    watch.poll(now=11)
    assert watch.daemon_status() is None


def test_a_dead_or_replaced_kea_pid_is_a_confirmed_kill(tmp_path: Path) -> None:
    ev = _events(tmp_path / "memory.events", 0)
    pids, proc = _kea(tmp_path, 40, 41)
    watch = OomWatch(tmp_path, files=(str(ev),), pid_files=pids, proc_root=str(proc))
    # kea-dhcp4 is gone from /proc, its pid file not yet removed.
    (proc / "40").rmdir()
    _events(ev, 1)
    watch.poll(now=10)
    status = watch.daemon_status()
    assert status is not None and "Kea was killed by the OOM killer" in status["reason"]

    # A tick that came late, after the supervise loop restarted Kea: the pid
    # changed since the previous tick, which is a kill too.
    watch.clear()
    watch2 = OomWatch(tmp_path, files=(str(ev),), pid_files=pids, proc_root=str(proc))
    _kea(tmp_path, 50, 41)
    _events(ev, 2)
    watch2.poll(now=20)
    assert watch2.daemon_status() is not None


def test_unreadable_pid_files_still_report_but_hedge(tmp_path: Path) -> None:
    """No pid files (a custom pid dir, Kea between restarts at startup):
    nothing proves Kea survived, so the kill is reported, without claiming
    to know the victim."""
    ev = _events(tmp_path / "memory.events", 0)
    absent = (str(tmp_path / "no4.pid"), str(tmp_path / "no6.pid"))
    watch = OomWatch(tmp_path, files=(str(ev),), pid_files=absent)
    _events(ev, 1)
    watch.poll(now=10)
    status = watch.daemon_status()
    assert status is not None and "almost certainly" in status["reason"]
