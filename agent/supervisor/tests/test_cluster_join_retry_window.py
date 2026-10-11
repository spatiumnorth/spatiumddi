"""A transient join failure is retried across the backend's retry window (#1212).

The backend keeps a failed member's ``desired_cluster_role=member`` for 15
minutes after a transient join failure (#961), so that the member's supervisor
re-fires the join once the path to the seed is back. These tests drive the
supervisor's join path the way the heartbeat and the host runner do. The
heartbeat asks every 30 s. Each fire is consumed by the runner, and an attempt
against an unreachable seed fails about 21 s later. The rollback restarts the
supervisor's pod, so it is back about 20 s after that. The time each fire leaves
in the attempt ledger is all the supervisor knows about its earlier attempts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state

URL = "https://10.0.0.1:6443"
TOKEN = "K10abc::server:not-a-real-token"
WINDOW_S = 15 * 60  # the backend's _JOIN_AUTO_RETRY_WINDOW
HEARTBEAT_S = 30  # config.py's default interval
ATTEMPT_S = 21  # k3s's cacerts client timeout against an unreachable seed
RESTART_S = 20  # the supervisor pod back after the rollback


@pytest.fixture
def paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    for name, file in (
        ("_CLUSTER_JOIN_TRIGGER_FILE", "cluster-join-pending"),
        ("_CLUSTER_LEAVE_TRIGGER_FILE", "cluster-leave-pending"),
        ("_CLUSTER_JOIN_STATE_SIDECAR", "cluster-join.state"),
        ("_CLUSTER_JOIN_STATE_CONSUMED", "cluster-join.state.consumed"),
    ):
        monkeypatch.setattr(appliance_state, name, tmp_path / file)
    return tmp_path


class Clock:
    def __init__(self) -> None:
        self.start = datetime(2026, 9, 27, 7, 9, 4, tzinfo=UTC)
        self.now = self.start

    def at(self, seconds: float) -> None:
        self.now = self.start + timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """The supervisor's wall clock, which also stamps the attempt ledger."""
    c = Clock()

    class _Datetime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[no-untyped-def,override]
            return c.now if tz is not None else c.now.replace(tzinfo=None)

    monkeypatch.setattr(appliance_state, "datetime", _Datetime)
    return c


@dataclass
class Run:
    fires: list[int] = field(default_factory=list)
    joined_at: int | None = None


def _drive(
    paths: Path,
    clock: Clock,
    *,
    seconds: int,
    path_back_at: int | None = None,
    desired_until: int | None = None,
) -> Run:
    """Run the member's side of a promote for ``seconds``.

    The control plane sends ``desired_cluster_role=member`` until
    ``desired_until`` (default: the whole run). An attempt fired at or after
    ``path_back_at`` joins; every earlier one fails."""
    trigger = paths / "cluster-join-pending"
    state = paths / "cluster-join.state"
    run = Run()
    up_at = 0
    attempt_ends: int | None = None
    attempt_joins = False
    for t in range(seconds):
        clock.at(t)
        if attempt_ends is not None and t >= attempt_ends:
            attempt_ends = None
            if attempt_joins:
                state.write_text(f"ready\t{URL}")
                run.joined_at = t
                return run
            state.write_text("failed\tcould not reach the seed")
            up_at = t + RESTART_S
        if t % HEARTBEAT_S or t < up_at or attempt_ends is not None:
            continue
        desired = "member" if desired_until is None or t < desired_until else None
        if desired != "member":
            # heartbeat.py's no-desired-role branch.
            appliance_state.reset_cluster_join_attempts()
            appliance_state.mark_cluster_join_state_consumed()
            continue
        if appliance_state.maybe_fire_cluster_join(desired, URL, TOKEN):
            run.fires.append(t)
            # The runner consumes the trigger and starts the attempt.
            trigger.rename(trigger.with_name(f"{trigger.name}.done.{t}"))
            state.write_text(f"joining\t{URL}")
            attempt_ends = t + ATTEMPT_S
            attempt_joins = path_back_at is not None and t >= path_back_at
    return run


def test_a_path_that_returns_inside_the_window_is_joined(paths: Path, clock: Clock) -> None:
    """#1212: the seed's control-plane ports are unreachable for 4 minutes from the
    promote, longer than three back-to-back attempts take, and well inside the
    15 minutes the backend keeps the member's desired role. The member must
    still be trying when the path comes back."""
    run = _drive(paths, clock, seconds=WINDOW_S, path_back_at=240)
    assert run.joined_at is not None, (
        f"the member never re-joined: its attempts fired at {run.fires} s and the "
        "path came back at 240 s, inside the backend's 15-minute retry window"
    )


@pytest.mark.parametrize("path_back_at", [150, 300, 420, 540, 660])
def test_any_return_inside_the_window_is_joined(
    paths: Path, clock: Clock, path_back_at: int
) -> None:
    """Wherever the outage ends inside the window's first eleven minutes, an
    attempt follows it and the member joins before the window closes."""
    run = _drive(paths, clock, seconds=WINDOW_S, path_back_at=path_back_at)
    assert run.joined_at is not None, f"fires at {run.fires} s; path back at {path_back_at} s"
    assert run.joined_at - path_back_at <= 300


def test_attempts_are_spaced_out_across_the_window(paths: Path, clock: Clock) -> None:
    """With the seed unreachable for the whole window, the attempts are spread
    across it rather than spent in its first minutes. Every one of them wipes
    and rolls back the node's k3s identity."""
    run = _drive(paths, clock, seconds=WINDOW_S)
    gaps = [b - a for a, b in zip(run.fires, run.fires[1:], strict=False)]
    assert run.fires[:2] == [0, 60], "the first retry still comes a minute after the first"
    assert gaps == sorted(gaps), f"the gaps shrink: {gaps}"
    assert run.fires[-1] >= 11 * 60, (
        f"no attempt in the window's last four minutes: fires at {run.fires} s"
    )
    assert len(run.fires) <= appliance_state._CLUSTER_JOIN_MAX_ATTEMPTS


def test_the_ceiling_still_stops_a_control_plane_that_never_clears(
    paths: Path, clock: Clock
) -> None:
    """#590's backstop: a control plane that never processes the failure keeps
    sending desired=member for good, and the wipes must still stop."""
    run = _drive(paths, clock, seconds=3 * 60 * 60)
    assert len(run.fires) == appliance_state._CLUSTER_JOIN_MAX_ATTEMPTS
    assert run.fires[-1] < 45 * 60


def test_a_closed_window_ends_the_retries_and_a_new_promote_starts_over(
    paths: Path, clock: Clock
) -> None:
    """The backend clears the desired role when its window closes; the
    heartbeat then drops the ledger, so the operator's next promote fires at
    once instead of waiting out an old backoff."""
    run = _drive(paths, clock, seconds=WINDOW_S + 60, desired_until=WINDOW_S)
    assert all(t < WINDOW_S for t in run.fires)
    clock.at(WINDOW_S + 90)
    (paths / "cluster-join.state").write_text("failed\tcould not reach the seed")
    assert appliance_state.maybe_fire_cluster_join("member", URL, TOKEN) is True


def test_a_clock_stepped_back_never_stalls_the_join(paths: Path, clock: Clock) -> None:
    """A ledger stamped in the future (NTP stepped the clock back after boot)
    must not hold the next attempt back for the size of the step."""
    trigger = paths / "cluster-join-pending"
    clock.at(3600)
    assert appliance_state.maybe_fire_cluster_join("member", URL, TOKEN) is True
    trigger.rename(trigger.with_name("cluster-join-pending.failed"))
    clock.at(0)
    assert appliance_state.maybe_fire_cluster_join("member", URL, TOKEN) is True


def test_a_different_target_is_never_held_back(paths: Path, clock: Clock) -> None:
    """The spacing is per target: a promote against another seed fires at once."""
    trigger = paths / "cluster-join-pending"
    assert appliance_state.maybe_fire_cluster_join("member", URL, TOKEN) is True
    trigger.rename(trigger.with_name("cluster-join-pending.failed"))
    clock.at(5)
    assert appliance_state.maybe_fire_cluster_join("member", "https://10.0.0.9:6443", TOKEN)
