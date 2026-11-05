"""A death during a config apply is named OOM when the cgroup says so (#3552)."""

from __future__ import annotations

from functools import partial
from pathlib import Path

import pytest

from spatium_dns_agent import apply_guard, sync
from spatium_dns_agent.apply_guard import ApplyGuard
from spatium_dns_agent.cache import commit_config, ensure_layout, save_config

from .test_config_revert import _bundle, _Driver, _loop


@pytest.fixture(autouse=True)
def _quiet(monkeypatch) -> None:
    monkeypatch.setattr(sync, "push_rendered_config", lambda *a: None)
    monkeypatch.setattr(sync.time, "sleep", lambda s: None)


def _events(tmp_path: Path, oom_kill: int) -> tuple[str, ...]:
    f = tmp_path / "memory.events"
    f.write_text(f"low 0\nhigh 0\nmax 4\noom 2\noom_kill {oom_kill}\noom_group_kill 0\n")
    return (str(f),)


def _fake_cgroup(monkeypatch, tmp_path: Path, oom_kill: int) -> None:
    files = _events(tmp_path, oom_kill)
    monkeypatch.setattr(sync, "ApplyGuard", partial(ApplyGuard, oom_files=files))
    limit = tmp_path / "memory.max"
    limit.write_text(str(512 << 20))
    monkeypatch.setattr(
        apply_guard,
        "cgroup_memory_limit_bytes",
        lambda: int(limit.read_text()),
    )


def test_a_rise_in_oom_kill_across_the_restart_is_an_oom_verdict(tmp_path: Path) -> None:
    (tmp_path / "cg").mkdir()
    files = _events(tmp_path / "cg", 3)
    state = tmp_path / "state"
    ensure_layout(state)
    g = ApplyGuard(state, oom_files=files)
    g.arm("big")  # records oom_kill=3
    Path(files[0]).write_text("oom_kill 4\n")  # named killed during the apply

    g2 = ApplyGuard(state, oom_files=files)
    assert g2.startup() == "big"
    assert g2.died_oom_killed is True


def test_an_unchanged_count_is_a_plain_crash(tmp_path: Path) -> None:
    (tmp_path / "cg").mkdir()
    files = _events(tmp_path / "cg", 3)
    state = tmp_path / "state"
    ensure_layout(state)
    ApplyGuard(state, oom_files=files).arm("big")

    g2 = ApplyGuard(state, oom_files=files)
    assert g2.startup() == "big"
    assert g2.died_oom_killed is False


def test_the_count_is_rebaselined_so_one_kill_is_not_blamed_twice(tmp_path: Path) -> None:
    (tmp_path / "cg").mkdir()
    files = _events(tmp_path / "cg", 1)
    state = tmp_path / "state"
    ensure_layout(state)
    ApplyGuard(state, oom_files=files).arm("big")
    Path(files[0]).write_text("oom_kill 2\n")
    ApplyGuard(state, oom_files=files).startup()  # sees the rise, records 2

    ApplyGuard(state, oom_files=files).arm("big")
    g4 = ApplyGuard(state, oom_files=files)
    assert g4.startup() == "big"
    assert g4.died_oom_killed is False


def test_no_cgroup_file_is_unknown_not_oom(tmp_path: Path) -> None:
    state = tmp_path / "state"
    ensure_layout(state)
    none = (str(tmp_path / "absent"),)
    ApplyGuard(state, oom_files=none).arm("big")
    g = ApplyGuard(state, oom_files=none)
    assert g.startup() == "big"
    assert g.died_oom_killed is False


def _die_on_cached(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("big"), "big")
    commit_config(tmp_path, "big")
    (tmp_path / "rendered").mkdir(exist_ok=True)
    (tmp_path / "rendered" / "named.conf").write_text("// big\n")
    _loop(tmp_path, _Driver(tmp_path))  # applies, arms, then is dropped


def test_the_heartbeat_verdict_names_oom_and_the_limit(tmp_path: Path, monkeypatch) -> None:
    cg = tmp_path / "cg"
    cg.mkdir()
    _fake_cgroup(monkeypatch, cg, 5)
    state = tmp_path / "state"
    _die_on_cached(state)
    (cg / "memory.events").write_text("oom_kill 6\n")

    loop = _loop(state, _Driver(state))

    assert loop.apply_status.reason == "oom"
    wire = loop.heartbeat.config_apply.as_dict()
    assert wire["reason"] == "oom"
    assert wire["memory_limit_bytes"] == 512 << 20
    assert "OOM killer" in (loop.apply_status.error or "")


def test_a_crash_with_no_evidence_says_daemon_died_not_oom(tmp_path: Path, monkeypatch) -> None:
    """No evidence is ``daemon_died``: the cause is unknown to the agent, and
    the control plane may still know it was an OOM kill (the kubelet)."""
    cg = tmp_path / "cg"
    cg.mkdir()
    _fake_cgroup(monkeypatch, cg, 5)
    state = tmp_path / "state"
    _die_on_cached(state)

    loop = _loop(state, _Driver(state))

    assert loop.apply_status.reason == "daemon_died"
    wire = loop.heartbeat.config_apply.as_dict()
    assert wire["reason"] == "daemon_died"
    assert "memory_limit_bytes" not in wire
    assert "OOM killer" not in (loop.apply_status.error or "")


# ── Compose: the counter does not survive the restart, the record does ──
#
# Docker's ``restart:`` starts the container in a NEW cgroup whose ``oom_kill``
# reads 0 (measured: 1 before the exit, 0 after), so the counter comparison
# above never fires there. The agent outlives ``named`` there, though, and the
# supervisor loop sees the counter move before it exits: that watched OOM death
# is what names the next start's verdict.


def test_a_watched_oom_death_is_an_oom_verdict_after_a_fresh_cgroup(tmp_path: Path) -> None:
    (tmp_path / "cg").mkdir()
    files = _events(tmp_path / "cg", 1)
    state = tmp_path / "state"
    ensure_layout(state)
    g = ApplyGuard(state, oom_files=files)
    g.arm("big")
    assert g.daemon_died(oom_killed=True) == "big"
    Path(files[0]).write_text("oom_kill 0\n")  # the restarted container's cgroup

    g2 = ApplyGuard(state, oom_files=files)
    assert g2.startup() == "big"
    assert g2.died_oom_killed is True


def test_a_watched_oom_death_is_reported_by_one_start_only(tmp_path: Path) -> None:
    (tmp_path / "cg").mkdir()
    files = _events(tmp_path / "cg", 0)
    state = tmp_path / "state"
    ensure_layout(state)
    g = ApplyGuard(state, oom_files=files)
    g.arm("big")
    g.daemon_died(oom_killed=True)
    assert ApplyGuard(state, oom_files=files).startup() == "big"

    # The next death of the same bundle is a plain one: no OOM this time.
    g3 = ApplyGuard(state, oom_files=files)
    g3.arm("big")
    g3.daemon_died(oom_killed=False)
    g4 = ApplyGuard(state, oom_files=files)
    assert g4.startup() == "big"
    assert g4.died_oom_killed is False


def test_a_watched_death_without_oom_is_not_oom(tmp_path: Path) -> None:
    (tmp_path / "cg").mkdir()
    files = _events(tmp_path / "cg", 0)
    state = tmp_path / "state"
    ensure_layout(state)
    g = ApplyGuard(state, oom_files=files)
    g.arm("big")
    g.daemon_died()
    g2 = ApplyGuard(state, oom_files=files)
    assert g2.startup() == "big"
    assert g2.died_oom_killed is False


def test_the_compose_heartbeat_verdict_names_oom(tmp_path: Path, monkeypatch) -> None:
    """End to end over the sync loop: the agent watched named die to the OOM
    killer, the container restarted into a fresh cgroup, and the next start's
    verdict still says ``oom`` with the limit read at the kill."""
    cg = tmp_path / "cg"
    cg.mkdir()
    _fake_cgroup(monkeypatch, cg, 3)
    state = tmp_path / "state"
    _die_on_cached(state)
    ApplyGuard(state, oom_files=(str(cg / "memory.events"),)).daemon_died(oom_killed=True)
    (cg / "memory.events").write_text("oom_kill 0\n")

    loop = _loop(state, _Driver(state))

    wire = loop.heartbeat.config_apply.as_dict()
    assert wire["reason"] == "oom"
    assert wire["memory_limit_bytes"] == 512 << 20
