"""A daemon killed by the container's memory limit is reported, not hidden (#1725).

The DNS pod now carries a memory limit, so a blocklist too big for it kills
``named`` inside the pod instead of evicting the control plane. Without a
signal that is a silent crash loop: the supervisor exits 2, the container
restarts into the same cached bundle, the first heartbeat says ``ok``, and the
limit kills named again. These tests pin the signal: the cgroup's OOM-kill
counter is read, a kill is persisted across the restart, and the restarted
agent reports ``degraded`` with a reason the control plane treats as "not
serving" (the ``agent_daemon_degraded`` alert), until the daemon stays up.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent import supervisor
from spatium_dns_agent.cache import commit_config, ensure_layout, save_config
from spatium_dns_agent.oom_watch import OomWatch, read_oom_kill_count

from .test_config_revert import _bundle, _Driver, _loop
from .test_supervisor_deferred_start import supervised  # noqa: F401 — fixture

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
    assert read_oom_kill_count((str(tmp_path / "absent"),)) is None


def test_fired_only_after_the_counter_moves(tmp_path: Path) -> None:
    ev = _events(tmp_path / "memory.events", 1)  # a kill from before this agent
    watch = OomWatch(tmp_path, files=(str(ev),))
    assert watch.fired() is False
    _events(ev, 2)
    assert watch.fired() is True


def test_a_kill_is_persisted_and_survives_a_restart(tmp_path: Path) -> None:
    ev = _events(tmp_path / "memory.events", 0)
    OomWatch(tmp_path, files=(str(ev),), limit_bytes=2 * GIB).note_daemon_killed(now=0)

    restarted = OomWatch(tmp_path, files=(str(ev),), limit_bytes=2 * GIB)
    status = restarted.daemon_status()
    assert status is not None and status["status"] == "degraded"
    reason = status["reason"]
    assert reason.startswith("oom_killed: named was killed for exceeding")
    assert "2 GiB memory limit" in reason and "once" in reason
    # The control plane reads a ``config_apply_`` prefix as a config verdict,
    # not a daemon that is down (#1067); this one must read as not serving.
    assert not reason.startswith("config_apply_")

    restarted.note_daemon_killed(now=60)
    assert "2 times" in (OomWatch(tmp_path, files=(str(ev),)).daemon_status() or {})["reason"]

    restarted.clear()
    assert OomWatch(tmp_path, files=(str(ev),)).daemon_status() is None


# ── the supervisor ─────────────────────────────────────────────────────────


@pytest.fixture
def oom_events(agent_cfg, monkeypatch, tmp_path: Path) -> Path:
    ev = _events(tmp_path / "memory.events", 0)
    real = OomWatch

    def _watch(state_dir: Path, **kw: Any) -> OomWatch:
        return real(state_dir, files=(str(ev),), **{k: v for k, v in kw.items() if k != "files"})

    monkeypatch.setattr(supervisor, "OomWatch", _watch)
    monkeypatch.setattr(supervisor, "cgroup_memory_limit_bytes", lambda: 2 * GIB)
    return ev


def test_a_death_with_the_oom_killer_is_recorded(supervised, oom_events) -> None:  # noqa: F811
    sv = supervised

    def oom_kill() -> None:
        _events(oom_events, 1)
        sv.drv.die()

    assert sv.run({1: sv.drv.launch, 3: oom_kill}) == 2
    assert ("error", "dns_daemon_exited", {"driver": "bind9"}) in sv.spy.calls
    assert (sv.drv.state_dir / "daemon_oom.json").exists()


def test_a_plain_death_records_nothing(supervised, oom_events) -> None:  # noqa: F811
    sv = supervised
    assert sv.run({1: sv.drv.launch, 3: sv.drv.die}) == 2
    assert not (sv.drv.state_dir / "daemon_oom.json").exists()


def test_the_restarted_agent_reports_not_serving_until_the_daemon_stays_up(
    supervised, oom_events, monkeypatch  # noqa: F811
) -> None:
    sv = supervised
    OomWatch(sv.drv.state_dir, files=(str(oom_events),), limit_bytes=2 * GIB).note_daemon_killed()
    seen: list[dict[str, Any]] = []

    def look() -> None:
        seen.append(dict(sv.idles[0].daemon_status))  # idles[0] is the heartbeat

    # The daemon coming up is not the daemon surviving: still degraded.
    assert sv.run({1: look, 2: sv.drv.launch, 4: look, 5: sv.sigterm}) == 0
    assert all(s.get("reason", "").startswith("oom_killed:") for s in seen), seen
    assert (sv.drv.state_dir / "daemon_oom.json").exists()


def test_the_record_clears_once_the_daemon_stays_up(
    supervised, oom_events, monkeypatch  # noqa: F811
) -> None:
    sv = supervised
    OomWatch(sv.drv.state_dir, files=(str(oom_events),), limit_bytes=2 * GIB).note_daemon_killed()
    monkeypatch.setattr(supervisor, "STABLE_SECONDS", 0.0)
    seen: list[dict[str, Any]] = []

    assert (
        sv.run(
            {
                1: sv.drv.launch,
                4: lambda: seen.append(dict(sv.idles[0].daemon_status)),
                5: sv.sigterm,
            }
        )
        == 0
    )
    assert seen == [{"status": "ok"}]
    assert not (sv.drv.state_dir / "daemon_oom.json").exists()


# ── the sync loop ──────────────────────────────────────────────────────────


def test_a_good_apply_does_not_clear_an_oom_verdict(tmp_path: Path) -> None:
    """An apply succeeding says nothing about named surviving the config."""
    ensure_layout(tmp_path)
    loop = _loop(tmp_path, _Driver(tmp_path))
    oom = {"status": "degraded", "reason": "oom_killed: named was killed"}
    loop.heartbeat.daemon_status = dict(oom)
    save_config(tmp_path, _bundle("new"), "new")
    assert loop._apply_with_revert(_bundle("new"), "new") is True
    assert loop.heartbeat.daemon_status == oom


def test_an_apply_failure_names_the_oom_kill(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    loop = _loop(tmp_path, driver)
    ev = _events(tmp_path / "memory.events", 0)
    loop.oom_watch = OomWatch(tmp_path, files=(str(ev),))
    _events(ev, 1)

    driver.fail_on = "validate"
    assert loop._apply_with_revert(_bundle("bad"), "bad") is False
    assert "OOM killer fired" in (loop.apply_status.error or "")
    # Still #882's verdict: the reason keeps its ``config_apply_`` prefix.
    assert loop.heartbeat.daemon_status["reason"].startswith("config_apply_reverted: ")

    # One kill is named once: a later, unrelated failure does not inherit it.
    assert loop._apply_with_revert(_bundle("bad2"), "bad2") is False
    assert "OOM killer fired" not in (loop.apply_status.error or "")
