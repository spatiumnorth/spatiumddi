"""A deferred daemon start is a wait, not a death (#1056).

``supervisor.run`` calls ``driver.start_daemon()`` once at boot, then polls
``driver.daemon_running()`` every second and exits 2 — "the daemon died, let
the orchestrator restart us" — the first time it answers False. But
``start_daemon`` does not always start a daemon: the BIND9 and PowerDNS
drivers return WITHOUT one when no config has been rendered yet
(``named_conf_missing_startup_deferred`` / ``pdns_conf_missing_startup_deferred``)
and leave the launch to ``swap_and_reload``, which the sync loop reaches once
the control plane hands over the first bundle.

The first bind pod on a freshly joined cluster member always boots that way —
its state dir is empty and its bundle is not built yet — so the supervisor
read "never started" as "died" one tick after boot, exited 2, and kubelet
back-off-restarted the container until the bundle happened to land inside the
1 s window. Observed on a nested 3-node QA cluster (2026-09-11): the previous
container's whole log was ``named_conf_missing_startup_deferred`` at
15:24:32.232 → shipper + ingest starting → heartbeat 200 → ``dns_daemon_exited``
at 15:24:33.244; Last State exit 2; Restart Count 2; ``Back-off restarting
failed container`` on every bind pod the two new members created.

These tests pin the fixed contract: the liveness check is armed by the launch
(a spawned or adopted pid), not by the boot.

The same loop had a second misreading: on SIGTERM the handler stops every
worker thread (and a rollout may take the daemon too), and the next tick's
checks then found the threads it had just stopped dead and returned 2 —
``dns_agent_thread_died`` on every DaemonSet rollout (containerd on the seed:
``dns-bind9`` exit_status 2 at 21:20:53Z during the roles rollout, the
``dhcp-kea`` container exit 0 the same second). A stop that was requested is
the designed exit 0, whatever the stop killed.
"""

from __future__ import annotations

import dataclasses
import signal
import threading
import time
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent import supervisor
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.drivers import bind9, powerdns
from spatium_dns_agent.drivers.base import DriverBase
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver


class _LogSpy:
    """Records ``(level, event, kwargs)`` — independent of structlog's global
    configuration, which another test may have cached."""

    LEVELS = ("debug", "info", "warning", "error", "exception", "critical")

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def __getattr__(self, name: str):
        if name not in self.LEVELS:
            raise AttributeError(name)

        def _log(event: str, **kw: Any) -> None:
            self.calls.append((name, event, kw))

        return _log

    @property
    def events(self) -> list[str]:
        return [e for _, e, _ in self.calls]


# ── the drivers: what start_daemon leaves behind ──────────────────────────


def test_bind9_deferred_start_launches_nothing(tmp_path: Path, monkeypatch) -> None:
    """An empty state dir at boot: no named.conf, no spawn, no pid."""
    monkeypatch.setattr(bind9, "find_running_daemon", lambda comm: None)
    spy = _LogSpy()
    monkeypatch.setattr(bind9, "log", spy)
    drv = Bind9Driver(state_dir=tmp_path)

    drv.start_daemon()

    assert spy.events == ["named_conf_missing_startup_deferred"]
    assert drv.daemon_launched() is False
    assert drv.daemon_running() is False


def test_powerdns_deferred_start_launches_nothing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(powerdns, "find_running_daemon", lambda comm: None)
    spy = _LogSpy()
    monkeypatch.setattr(powerdns, "log", spy)
    drv = PowerDNSDriver(state_dir=tmp_path)

    drv.start_daemon()

    assert spy.events == ["pdns_conf_missing_startup_deferred"]
    assert drv.daemon_launched() is False
    assert drv.daemon_running() is False


def test_bind9_spawn_arms_the_liveness_check(tmp_path: Path, monkeypatch) -> None:
    """Once named.conf exists the spawn records the pid — the tell the
    supervisor arms on."""
    conf = tmp_path / "rendered" / "named.conf"
    conf.parent.mkdir()
    conf.write_text("options {};\n")
    monkeypatch.setattr(bind9, "find_running_daemon", lambda comm: None)
    monkeypatch.setattr(bind9, "wait_for_daemon", lambda comm, pid, timeout_s=5.0: True)
    spy = _LogSpy()
    monkeypatch.setattr(bind9, "log", spy)
    spawned: list[list[str]] = []

    class _Popen:
        pid = 4242

        def __init__(self, cmd: list[str], *a: Any, **kw: Any) -> None:
            spawned.append(list(cmd))

    monkeypatch.setattr(bind9.subprocess, "Popen", _Popen)
    drv = Bind9Driver(state_dir=tmp_path)

    drv.start_daemon()

    assert spawned == [["named", "-f", "-c", str(conf)]]
    assert spy.events == ["named_started"]
    assert drv.daemon_launched() is True
    assert drv.daemon_pid == 4242


def test_bind9_spawn_that_dies_is_not_logged_as_started(tmp_path: Path, monkeypatch) -> None:
    """A daemon that exits during startup is a zombie until reaped, and a
    zombie reads back as ``named`` too, so this used to log ``named_started``
    for a dead daemon (#1239)."""
    conf = tmp_path / "rendered" / "named.conf"
    conf.parent.mkdir()
    conf.write_text("options {};\n")
    monkeypatch.setattr(bind9, "find_running_daemon", lambda comm: None)
    monkeypatch.setattr(bind9, "wait_for_daemon", lambda comm, pid, timeout_s=5.0: False)
    spy = _LogSpy()
    monkeypatch.setattr(bind9, "log", spy)

    class _Popen:
        pid = 4243

        def __init__(self, cmd: list[str], *a: Any, **kw: Any) -> None:
            pass

    monkeypatch.setattr(bind9.subprocess, "Popen", _Popen)
    # The pid is fake: without this, a real process that happens to hold
    # it on the test host would read as a live named.
    monkeypatch.setattr(Bind9Driver, "daemon_running", lambda self: False)
    Bind9Driver(state_dir=tmp_path).start_daemon()

    assert spy.events == ["named_exited_during_startup"]


def test_bind9_spawn_that_is_slow_to_exec_is_not_logged_as_dead(
    tmp_path: Path, monkeypatch
) -> None:
    """``wait_for_daemon`` also returns False on its visibility timeout, when
    the child is alive but still pre-``execve``; that is not an exit."""
    conf = tmp_path / "rendered" / "named.conf"
    conf.parent.mkdir()
    conf.write_text("options {};\n")
    monkeypatch.setattr(bind9, "find_running_daemon", lambda comm: None)
    monkeypatch.setattr(bind9, "wait_for_daemon", lambda comm, pid, timeout_s=5.0: False)
    monkeypatch.setattr(Bind9Driver, "daemon_running", lambda self: True)
    spy = _LogSpy()
    monkeypatch.setattr(bind9, "log", spy)

    class _Popen:
        pid = 4244

        def __init__(self, cmd: list[str], *a: Any, **kw: Any) -> None:
            pass

    monkeypatch.setattr(bind9.subprocess, "Popen", _Popen)
    Bind9Driver(state_dir=tmp_path).start_daemon()

    assert spy.events == ["named_started"]


def test_adopting_a_running_daemon_counts_as_launched(tmp_path: Path, monkeypatch) -> None:
    """``daemon_running``'s system-wide look-up adopts a live daemon (#704);
    that arms the check the same way a spawn does."""
    monkeypatch.setattr(bind9, "find_running_daemon", lambda comm: 77)
    drv = Bind9Driver(state_dir=tmp_path)

    assert drv.daemon_launched() is False
    assert drv.daemon_running() is True
    assert drv.daemon_launched() is True
    assert drv.daemon_pid == 77


# ── the supervisor: armed by the launch, not the boot ─────────────────────


class _ScriptedDriver(DriverBase):
    """``start_daemon`` defers (no pid); the test flips the daemon up and down."""

    def __init__(self, state_dir: Path) -> None:
        super().__init__(state_dir)
        self.running = False
        self.start_calls = 0
        #: Runs inside ``daemon_running`` — the place a signal can land
        #: between the tick's stop check and the loop's crash exits.
        self.hook_running: Callable[[], None] | None = None
        #: What ``daemon_restarting`` answers; the restart tests script it.
        self.restarting = False

    def daemon_restarting(self) -> bool:
        return self.restarting

    def render(self, bundle: dict[str, Any]) -> None:
        return None

    def validate(self) -> None:
        return None

    def swap_and_reload(self) -> None:
        return None

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        return None

    def start_daemon(self) -> None:
        self.start_calls += 1  # deferred: nothing spawned, daemon_pid stays None

    def daemon_running(self) -> bool:
        if self.hook_running is not None:
            self.hook_running()
        return self.running

    def launch(self) -> None:
        self.daemon_pid = 4242
        self.running = True

    def die(self) -> None:
        self.running = False


class _Idle:
    """Stands in for every thread-bearing component: blocks until stopped."""

    def __init__(self, *a: Any, **kw: Any) -> None:
        self._stop = threading.Event()
        self.config_apply: Any = None
        self.pending_acks: list[Any] = []
        self.daemon_status: dict[str, Any] = {}

    def run(self) -> None:
        self._stop.wait()

    def stop(self) -> None:
        self._stop.set()


#: The names ``supervisor.run`` gives its worker threads, in construction
#: order of the stubs that back them (heartbeat=idles[0], sync=idles[1], …).
THREAD_NAMES = ("sync", "heartbeat", "metrics", "query-log", "rndc-status", "ingest")


@pytest.fixture
def supervised(agent_cfg: AgentConfig, monkeypatch):
    """``supervisor.run`` with the network-facing parts stubbed and the 1 s
    tick scripted.

    Yields a namespace: ``run(script, cfg=None)`` executes the supervisor,
    firing ``script[n]`` at tick ``n``, and returns the exit code; ``sigterm()``
    raises SIGTERM and then waits for the stopped worker threads to actually
    die — the order the live agent sees, since its 1 s sleep outlasts them;
    ``settle(names)`` waits for just those threads; ``idles`` are the stubs.
    """
    drv = _ScriptedDriver(agent_cfg.state_dir)
    idles: list[_Idle] = []
    real_sleep = time.sleep

    def settle(names: tuple[str, ...] = THREAD_NAMES, timeout_s: float = 2.0) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            alive = [t for t in threading.enumerate() if t.name in names and t.is_alive()]
            if not alive:
                return
            real_sleep(0.005)
        raise AssertionError(f"threads still alive: {[t.name for t in alive]}")

    def sigterm() -> None:
        signal.raise_signal(signal.SIGTERM)  # the handler runs before we return
        settle()

    def _idle(*a: Any, **kw: Any) -> _Idle:
        o = _Idle(*a, **kw)
        idles.append(o)
        return o

    monkeypatch.setattr(supervisor, "ensure_token", lambda cfg: ("agent-id", "token"))
    monkeypatch.setattr(supervisor, "_select_driver", lambda cfg: drv)
    for name in (
        "HeartbeatClient",
        "SyncLoop",
        "MetricsPoller",
        "QueryLogShipper",
        "RndcStatusPoller",
        "IngestWorker",
    ):
        monkeypatch.setattr(supervisor, name, _idle)
    spy = _LogSpy()
    monkeypatch.setattr(supervisor, "log", spy)
    ticks: list[int] = []

    def run(script: dict[int, Any], cfg: AgentConfig | None = None) -> int:
        def fake_sleep(seconds: float) -> None:
            assert seconds == 1.0
            ticks.append(len(ticks) + 1)
            action = script.get(ticks[-1])
            if action is not None:
                action()
            assert len(ticks) < 1000, "the supervisor never exited"

        monkeypatch.setattr(supervisor.time, "sleep", fake_sleep)
        saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        try:
            return supervisor.run(cfg if cfg is not None else agent_cfg)
        finally:
            for s, h in saved.items():
                signal.signal(s, h)
            for o in idles:
                o.stop()

    yield types.SimpleNamespace(drv=drv, ticks=ticks, spy=spy, run=run,
                                sigterm=sigterm, settle=settle, idles=idles)


def test_deferred_start_is_waited_out_then_a_real_death_exits_2(supervised) -> None:
    """Three ticks with nothing launched must not exit; the death at tick 6 must."""
    sv = supervised
    drv, ticks, spy = sv.drv, sv.ticks, sv.spy

    rc = sv.run({4: drv.launch, 6: drv.die})

    assert drv.start_calls == 1
    assert rc == 2
    assert ticks[-1] == 6
    events = spy.events
    assert events.count("dns_daemon_start_deferred_waiting") == 2  # wait ticks 1 and 2
    assert (
        events.index("dns_daemon_start_deferred_waiting")
        < events.index("dns_daemon_launched_after_deferred_start")
        < events.index("dns_daemon_exited")
    )
    launched = next(
        kw for _, e, kw in spy.calls if e == "dns_daemon_launched_after_deferred_start"
    )
    assert launched["driver"] == "bind9"
    assert launched["waited_s"] >= 0
    assert ("error", "dns_daemon_exited", {"driver": "bind9"}) in spy.calls


def test_a_deferred_start_that_never_launches_is_not_an_exit(supervised) -> None:
    """Nothing launched, ever: the loop waits until told to stop, and exits 0.
    (In the pod, the chart's liveness probe on :53 bounds this wait.)"""
    sv = supervised

    rc = sv.run({5: sv.sigterm})

    assert rc == 0
    assert sv.ticks[-1] == 5
    assert "dns_daemon_exited" not in sv.spy.events
    assert "dns_agent_thread_died" not in sv.spy.events
    # logged at ticks 1, 2 and 4 of the wait (the backoff schedule below)
    assert sv.spy.events.count("dns_daemon_start_deferred_waiting") == 3
    assert "dns_agent_signal_received" in sv.spy.events
    assert sv.spy.events[-1] == "dns_agent_exiting"


def test_a_stop_is_exit_0_even_when_it_takes_the_daemon_and_the_threads(supervised) -> None:
    """A rollout's SIGTERM stops the threads and may kill the daemon in the
    same instant; neither is a death the loop should report (the seed's bind
    container exited 2 on every DaemonSet rollout before this)."""
    sv = supervised

    def stop_everything() -> None:
        sv.drv.die()
        sv.sigterm()

    rc = sv.run({2: sv.drv.launch, 4: stop_everything})

    assert rc == 0
    assert sv.ticks[-1] == 4
    assert "dns_daemon_exited" not in sv.spy.events
    assert "dns_agent_thread_died" not in sv.spy.events
    assert sv.spy.events[-2:] == ["dns_agent_signal_received", "dns_agent_exiting"]


def test_a_thread_that_dies_while_not_stopping_still_exits_2(supervised) -> None:
    """The self-restart path for a dead worker (a sync loop that dropped its
    token, say) is intact: only a *requested* stop is exempt."""
    sv = supervised

    def kill_sync_thread() -> None:
        sv.idles[1].stop()  # SyncLoop's stub backs the "sync" thread
        sv.settle(("sync",))

    rc = sv.run({1: sv.drv.launch, 3: kill_sync_thread})

    assert rc == 2
    assert sv.ticks[-1] == 3
    assert ("error", "dns_agent_thread_died", {"threads": ["sync"]}) in sv.spy.calls
    assert "dns_agent_exiting" not in sv.spy.events


def test_a_stop_that_lands_inside_the_daemon_check_is_still_a_stop(supervised) -> None:
    """``_sig`` runs between bytecodes, so the tick's stop check closes the
    1 s sleep but not the checks themselves: a SIGTERM that lands while the
    loop is inside ``daemon_running()`` — a rollout that took named first —
    used to reach ``dns_daemon_exited`` and exit 2."""
    sv = supervised

    def stop_inside_the_check() -> None:
        sv.drv.hook_running = None
        sv.drv.die()
        sv.sigterm()

    rc = sv.run({1: sv.drv.launch, 3: lambda: setattr(sv.drv, "hook_running", stop_inside_the_check)})

    assert rc == 0
    assert sv.ticks[-1] == 3
    assert "dns_daemon_exited" not in sv.spy.events
    assert "dns_agent_thread_died" not in sv.spy.events
    assert sv.spy.events[-2:] == ["dns_agent_signal_received", "dns_agent_exiting"]


def test_a_stop_that_lands_inside_the_thread_check_is_still_a_stop(supervised) -> None:
    """The same window on the other check: the daemon is fine, the stop lands
    after the daemon check has passed, and the threads it stopped are dead by
    the time the thread check runs — ``dns_agent_thread_died``, exit 2."""
    sv = supervised

    def stop_after_the_daemon_check() -> None:
        sv.drv.hook_running = None
        sv.sigterm()

    rc = sv.run({1: sv.drv.launch, 3: lambda: setattr(sv.drv, "hook_running", stop_after_the_daemon_check)})

    assert rc == 0
    assert sv.ticks[-1] == 3
    assert "dns_agent_thread_died" not in sv.spy.events
    assert sv.spy.events[-2:] == ["dns_agent_signal_received", "dns_agent_exiting"]


def test_a_daemon_that_was_running_at_boot_still_exits_on_death(supervised) -> None:
    """The pre-#1056 contract is intact when ``start_daemon`` did spawn."""
    sv = supervised
    sv.drv.launch()  # what a real start_daemon leaves behind when named.conf exists

    rc = sv.run({2: sv.drv.die})

    assert rc == 2
    assert sv.ticks[-1] == 2
    assert "dns_daemon_start_deferred_waiting" not in sv.spy.events
    assert sv.spy.events[-1] == "dns_daemon_exited"


def test_a_driver_that_does_not_manage_a_daemon_is_never_checked(supervised, agent_cfg) -> None:
    """Only the daemon-managing drivers take the liveness exit at all."""
    sv = supervised
    cfg = dataclasses.replace(agent_cfg, driver="something-else")

    rc = sv.run({3: sv.sigterm}, cfg=cfg)

    assert rc == 0
    assert "dns_daemon_start_deferred_waiting" not in sv.spy.events
    assert "dns_daemon_exited" not in sv.spy.events


# ── the wait stays visible: re-logged on a backoff, degraded in the heartbeat ──


def test_wait_log_schedule() -> None:
    """The first tick, doubling to 32 s, then every minute — a ``--tail`` an
    hour into the wait still shows the state, without a line a second."""
    assert [n for n in range(1, 200) if supervisor.wait_log_due(n)] == [
        1, 2, 4, 8, 16, 32, 60, 120, 180,
    ]


def test_the_waiting_state_is_relogged_on_the_backoff(supervised) -> None:
    sv = supervised

    rc = sv.run({130: sv.sigterm})

    assert rc == 0
    waits = [kw for _, e, kw in sv.spy.calls if e == "dns_daemon_start_deferred_waiting"]
    assert len(waits) == 8  # ticks 1, 2, 4, 8, 16, 32, 60, 120
    assert all(isinstance(kw["waited_s"], float) and kw["driver"] == "bind9" for kw in waits)


def test_waiting_sets_the_heartbeat_daemon_status_and_the_launch_clears_it(supervised) -> None:
    """The heartbeat carries ``daemon: {status: degraded, reason: start
    deferred, no bundle yet}`` for as long as the wait lasts and ``ok`` once
    the daemon is up. Sampled from inside ``daemon_running`` each tick."""
    sv = supervised
    seen: list[dict[str, Any]] = []
    # sv.idles[0] is HeartbeatClient's stand-in; it exists once run() has
    # constructed it, hence the late lookup.
    sv.drv.hook_running = lambda: seen.append(dict(sv.idles[0].daemon_status))

    rc = sv.run({5: sv.drv.launch, 7: sv.drv.die})

    assert rc == 2
    # tick 1 samples before the wait is marked; 2-5 during it; 6-7 after the
    # launch cleared it. Tick 7 reads twice: a death is confirmed by a second
    # read before the exit, in case a restart finished in between (#1402).
    assert seen[0] == {}
    assert seen[1:5] == [supervisor.DEFERRED_DAEMON_STATUS] * 4
    assert seen[5:] == [{"status": "ok"}] * 3
    assert sv.idles[0].daemon_status == {"status": "ok"}


def test_a_sync_verdict_set_while_waiting_is_left_alone_on_launch(supervised) -> None:
    """``sync.py`` owns its own degraded verdicts (a failed apply); the
    supervisor clears only the one it set."""
    sv = supervised
    theirs = {"status": "degraded", "reason": "config_apply_reverted: bad acl"}

    rc = sv.run({3: lambda: setattr(sv.idles[0], "daemon_status", dict(theirs)),
                 5: sv.drv.launch, 7: sv.drv.die})

    assert rc == 2
    assert sv.idles[0].daemon_status == theirs


# ── a driver restarting its own daemon is not a death (#1402) ─────────────
#
# PowerDNS restarts pdns_server in place when pdns.conf changes, on the sync
# thread. The gate walk saw the agent exit 2 on 2 of 3 forwarder changes:
# ``powerdns_conf_changed_restarting``, then ``dns_daemon_exited`` 55-222 ms
# later, because the old pid was gone while ``daemon_pid`` still named it.


def _begin_restart(drv: _ScriptedDriver) -> None:
    """SIGTERM sent: the old daemon is gone, ``daemon_pid`` still names it."""
    drv.restarting = True
    drv.running = False


def _clear_pid(drv: _ScriptedDriver) -> None:
    """``_restart_daemon`` clears the pid before spawning the new daemon."""
    drv.daemon_pid = None


def _finish_restart(drv: _ScriptedDriver) -> None:
    drv.daemon_pid = 4343
    drv.running = True
    drv.restarting = False


def test_a_restart_is_neither_a_death_nor_a_deferred_start(supervised) -> None:
    """Every tick of the restart passes without a verdict, and the loop still
    catches a real death afterwards."""
    sv = supervised
    drv = sv.drv
    seen: list[dict[str, Any]] = []

    def sample() -> None:
        seen.append(dict(sv.idles[0].daemon_status))

    rc = sv.run({
        1: drv.launch,
        3: lambda: _begin_restart(drv),
        4: lambda: _clear_pid(drv),
        5: lambda: _finish_restart(drv),
        6: lambda: setattr(drv, "hook_running", sample),
        8: drv.die,
    })

    assert rc == 2
    assert sv.ticks[-1] == 8
    assert sv.spy.events.count("dns_daemon_exited") == 1
    assert "dns_daemon_start_deferred_waiting" not in sv.spy.events
    # The pid-cleared tick must not have marked the heartbeat as deferred.
    assert supervisor.DEFERRED_DAEMON_STATUS not in seen
    assert seen[0] == {"status": "ok"}


def test_a_restart_that_begins_inside_the_check_is_not_a_death(supervised) -> None:
    """The restart flag is read before ``daemon_running()``; a restart that
    starts between the two is what made the old pid read as dead."""
    sv = supervised
    drv = sv.drv

    def restart_starts_now() -> None:
        drv.hook_running = None
        _begin_restart(drv)

    rc = sv.run({
        1: drv.launch,
        3: lambda: setattr(drv, "hook_running", restart_starts_now),
        5: lambda: _finish_restart(drv),
        7: drv.die,
    })

    assert rc == 2
    assert sv.ticks[-1] == 7


def test_a_restart_that_finishes_inside_the_check_is_not_a_death(supervised) -> None:
    """The other side of the window: ``daemon_running()`` saw the old pid
    gone, then the restart completed before the verdict. The re-check finds
    the new daemon up."""
    sv = supervised
    drv = sv.drv
    calls = {"n": 0}

    def old_gone_then_new_up() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            drv.running = False  # this read sees the old daemon gone
        else:
            drv.hook_running = None
            _finish_restart(drv)  # ...and by the re-check the new one is up

    rc = sv.run({
        1: drv.launch,
        3: lambda: setattr(drv, "hook_running", old_gone_then_new_up),
        6: drv.die,
    })

    assert rc == 2
    assert sv.ticks[-1] == 6


def test_a_restart_that_fails_to_bring_the_daemon_up_still_exits_2(supervised) -> None:
    """The skip lasts only while the restart runs. A replacement that died
    at startup is a dead daemon on the first tick after the restart ends."""
    sv = supervised
    drv = sv.drv

    def restart_ends_with_a_dead_daemon() -> None:
        drv.daemon_pid = 4343
        drv.restarting = False  # running stays False: the new pdns exited

    rc = sv.run({1: drv.launch, 3: lambda: _begin_restart(drv), 5: restart_ends_with_a_dead_daemon})

    assert rc == 2
    assert sv.ticks[-1] == 5
    assert sv.spy.events[-1] == "dns_daemon_exited"
