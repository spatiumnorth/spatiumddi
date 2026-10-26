"""A revoked control-plane node backs its self-bootstrap retries off (#2789).

Since #2786 the main loop runs the revoke recovery while a control-plane node is
revoked, and the recovery asks the in-cluster self-bootstrap for a fresh pairing code
before it clears anything. The self-bootstrap refuses (409) while any live appliance
row exists, so a node whose own row is still there (a row revoked but not deleted, or
any node of a multi-node cluster, whose peers' rows stay live) was refused on every heartbeat tick. Each tick wrote and removed the
self-bootstrap token file, POSTed ``/self-register-bootstrap`` and logged four info
lines, for as long as the node stayed revoked.

The recovery now waits after an attempt that brought no code back: a minute, then
doubling up to four minutes. The schedule starts over once the node is out of the
revoked state. A node whose row is gone still re-registers at its first revoked tick
(#2786's contract), and one whose row goes away while it waits re-registers at its
next attempt.

The loop tests drive the real ``main()`` against the #2696 tests' stub control plane,
on a clock that moves 30 s per tick (the default heartbeat interval). Some run the
real ``_self_bootstrap_or_skip`` against a stub api, so its token-file writes and
POSTs are counted.
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest
from structlog.testing import capture_logs

from spatium_supervisor import __main__ as main_mod
from spatium_supervisor import (
    appliance_state,
    approval_state,
    cp_tls,
    kmsg_reader,
    pcap_proxy,
    self_bootstrap_token,
    storage_proxy,
)
from spatium_supervisor.identity import load_appliance_id, load_or_generate

from .test_revoked_reregister_2696 import (
    _API,
    FRESH,
    STALE,
    _ControlPlane,
    _events,
    _LoopDone,
    _no_client,
    _registered_before,
)

TICK_S = 30.0


class _Clock:
    """The loop's monotonic clock: it moves only while the loop sleeps."""

    def __init__(self) -> None:
        self.now = 5000.0

    def __call__(self) -> float:
        return self.now


class _Api:
    """The in-cluster api as the real ``_self_bootstrap_or_skip`` reaches it. A
    self-bootstrap is answered 409 while the control plane holds any row, and mints
    a code otherwise. The self-bootstrap token file's writes and removals are
    counted."""

    def __init__(self, cp: _ControlPlane) -> None:
        self.cp = cp
        self.posts = 0
        self.token_writes = 0
        self.token_removes = 0

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        api = self

        class _Client:
            def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                pass

            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_exc: object) -> None:
                return None

            def post(self, url: str, json: dict[str, Any]) -> SimpleNamespace:
                assert url.endswith("/api/v1/appliance/self-register-bootstrap")
                assert json["bootstrap_token"] == "token"
                api.posts += 1
                api.cp.bootstrap_calls += 1
                api.cp.bootstrap_at.append(len(api.cp.heartbeats))
                if api.cp.rows:
                    detail = '{"detail":"Live appliances already registered"}'
                    return SimpleNamespace(status_code=409, text=detail, json=dict)
                code = f"{len(api.cp.minted) + 1:08d}"
                api.cp.minted.append(code)
                body = {"code": code, "control_plane_url": _API, "expires_in_seconds": 600}
                return SimpleNamespace(status_code=200, text="", json=lambda: body)

        def write(*_args: Any, **_kwargs: Any) -> str:
            api.token_writes += 1
            return "token"

        def remove(*_args: Any, **_kwargs: Any) -> None:
            api.token_removes += 1

        monkeypatch.setattr(main_mod.httpx, "Client", _Client)
        monkeypatch.setattr(self_bootstrap_token, "write", write)
        monkeypatch.setattr(self_bootstrap_token, "remove", remove)


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    state_dir: Path,
    cp: _ControlPlane,
    *,
    ticks: int,
    events: dict[int, Callable[[_ControlPlane], None]] | None = None,
    api: _Api | None = None,
) -> list[MutableMapping[str, Any]]:
    """Run ``main()`` on a control-plane node for ``ticks`` loop iterations, on a
    clock that moves ``TICK_S`` per tick. ``events[n]`` runs on the control plane
    after tick ``n``. With ``api`` the real ``_self_bootstrap_or_skip`` runs against
    it; otherwise the stub control plane's. Returns the captured log events."""
    events = events or {}
    monkeypatch.setenv("STATE_DIR", str(state_dir))
    monkeypatch.setenv("HEARTBEAT_INTERVAL_SECONDS", "30")
    for name in ("CONTROL_PLANE_URL", "BOOTSTRAP_PAIRING_CODE", "K8S_PROXY_ENABLED"):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: "control-plane")
    monkeypatch.setattr(appliance_state, "is_control_plane_member", lambda: True)
    if api is None:
        monkeypatch.setattr(main_mod, "_self_bootstrap_or_skip", cp.self_bootstrap)
    else:
        api.install(monkeypatch)
    monkeypatch.setattr(main_mod, "register", cp.register)
    monkeypatch.setattr(main_mod, "heartbeat_once", cp.heartbeat)
    monkeypatch.setattr(cp_tls, "client", _no_client)
    monkeypatch.setattr(cp_tls, "check_pin_vouched_once", lambda *_a, **_k: None)

    # Nothing but the loop: no logging setup, threads or signal handlers.
    monkeypatch.setattr(main_mod, "configure_logging", lambda **_k: None)
    monkeypatch.setattr(main_mod, "start_proxy_thread", lambda *_a, **_k: None)
    monkeypatch.setattr(main_mod, "start_nettool_thread", lambda *_a, **_k: None)
    monkeypatch.setattr(storage_proxy, "start_storage_thread", lambda *_a, **_k: None)
    monkeypatch.setattr(pcap_proxy, "start_pcap_thread", lambda *_a, **_k: None)
    monkeypatch.setattr(kmsg_reader, "start", lambda *_a, **_k: None)
    monkeypatch.setattr(main_mod.signal, "signal", lambda *_a, **_k: None)

    # The retry schedule reads this clock. A build without the schedule has no such
    # name and runs as it always did.
    clock = _Clock()
    monkeypatch.setattr(main_mod, "_monotonic", clock, raising=False)

    # One ``time.sleep`` per tick, and the clock moves a heartbeat interval.
    tick = 0

    def sleep(_seconds: float) -> None:
        nonlocal tick
        tick += 1
        clock.now += TICK_S
        if tick in events:
            events[tick](cp)
        if tick >= ticks:
            raise _LoopDone

    monkeypatch.setattr(main_mod, "next_heartbeat_delay", lambda *_a, **_k: 1.0)
    monkeypatch.setattr(main_mod, "time", SimpleNamespace(sleep=sleep))

    with capture_logs() as logs, pytest.raises(_LoopDone):
        main_mod.main()
    return logs


def _asked_at(cp: _ControlPlane) -> list[float]:
    """When each self-bootstrap was asked, in seconds from start-up. A tick's
    recovery runs before its heartbeat, so the heartbeats sent before an attempt
    count the ticks before it."""
    return [TICK_S * sent for sent in cp.bootstrap_at]


def _revoke(cp: _ControlPlane) -> None:
    cp.rows[STALE] = "revoked"


def _reauthorize(cp: _ControlPlane) -> None:
    cp.rows[STALE] = "approved"


def _delete(cp: _ControlPlane) -> None:
    del cp.rows[STALE]


# ---- the schedule ---------------------------------------------------------------


def test_the_retry_waits_a_minute_then_doubles_up_to_four() -> None:
    now = [0.0]
    retry = main_mod.RevokedReregisterRetry(clock=lambda: now[0])
    assert retry.due()
    waits = []
    for _ in range(5):
        waits.append(retry.defer())
        now[0] += waits[-1] - 0.5
        assert not retry.due()
        now[0] += 0.5
        assert retry.due()
    assert waits == [60.0, 120.0, 240.0, 240.0, 240.0]


def test_a_reset_makes_the_next_attempt_due_at_once_and_starts_the_wait_over() -> None:
    now = [0.0]
    retry = main_mod.RevokedReregisterRetry(clock=lambda: now[0])
    retry.defer()
    retry.defer()
    assert not retry.due()
    retry.reset()
    assert retry.due()
    assert retry.defer() == 60.0


# ---- the loop -------------------------------------------------------------------


def test_a_revoked_node_with_a_live_row_backs_its_self_bootstrap_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revoked on the Fleet page but not deleted: every heartbeat is the marked
    403 (#2798) and the node's own row stays live, so every self-bootstrap is
    refused."""
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)

    logs = _run_main(monkeypatch, state_dir, cp, ticks=24, events={1: _revoke})

    # Ticks 2 and 3 are refused, and the second refusal revokes the node.
    assert cp.statuses[:4] == [200, 403, 403, 403]
    # Tick 4 (90 s) asks; then a minute later, then two, then four, not every tick.
    assert _asked_at(cp) == [90.0, 150.0, 270.0, 510.0], (
        f"self-bootstrap asked at {_asked_at(cp)} s over {len(cp.statuses)} ticks"
    )
    deferred = _events(logs, "supervisor.register.revoked_reregister_deferred")
    assert [e["retry_in_seconds"] for e in deferred] == [60.0, 120.0, 240.0, 240.0]
    # It keeps its identity and stays revoked, as #2786 left it.
    assert load_appliance_id(state_dir) == STALE
    assert approval_state.read_state(state_dir) == "revoked"
    assert cp.presented == []


def test_ticks_between_attempts_write_no_token_post_nothing_and_log_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real self-bootstrap call, against an api that answers 409."""
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)
    load_or_generate(state_dir)  # a node that restarted has its keypair already
    api = _Api(cp)

    logs = _run_main(monkeypatch, state_dir, cp, ticks=24, events={1: _revoke}, api=api)

    revoked_ticks = 24 - 3
    assert api.posts == 4, f"{api.posts} self-bootstrap POSTs in {revoked_ticks} revoked ticks"
    assert api.token_writes == api.token_removes == 4
    for name in (
        "supervisor.self_bootstrap.attempting",
        "supervisor.self_bootstrap.already_registered",
        "supervisor.register.revoked_reregister_deferred",
    ):
        assert len(_events(logs, name)) == 4, name
    # Once at start-up, then once per attempt.
    assert len(_events(logs, "supervisor.identity.loaded")) == 1 + 4


def test_the_wait_starts_over_once_the_node_is_approved_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)

    logs = _run_main(
        monkeypatch,
        state_dir,
        cp,
        ticks=18,
        events={1: _revoke, 11: _reauthorize, 13: _revoke},
    )

    # Revoked by tick 3's heartbeat, approved again by tick 12's, revoked again by
    # tick 15's. The second spell asks at its first revoked tick (450 s) and waits a
    # minute again, not the four the first spell had reached.
    assert cp.statuses[11:15] == [200, 200, 403, 403]
    assert _asked_at(cp) == [90.0, 150.0, 270.0, 450.0, 510.0]
    deferred = _events(logs, "supervisor.register.revoked_reregister_deferred")
    assert [e["retry_in_seconds"] for e in deferred] == [60.0, 120.0, 240.0, 60.0, 120.0]


def test_a_restart_while_revoked_asks_once_at_start_up_not_again_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)
    _revoke(cp)
    approval_state.record_revocation_signal(state_dir)
    approval_state.record_revocation_signal(state_dir)
    assert approval_state.read_state(state_dir) == "revoked"

    _run_main(monkeypatch, state_dir, cp, ticks=3)

    # Start-up asks (0 s); the next attempt is a minute later (tick 3), not tick 1.
    assert _asked_at(cp) == [0.0, 60.0]
    assert load_appliance_id(state_dir) == STALE


def test_a_revoked_node_whose_row_is_gone_reregisters_at_its_first_revoked_tick(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#2786's contract on the same clock: nothing refused, so nothing waits."""
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)

    logs = _run_main(monkeypatch, state_dir, cp, ticks=6, events={1: _delete}, api=_Api(cp))

    assert cp.statuses[:3] == [200, 403, 403]
    assert _asked_at(cp) == [90.0]
    assert len(_events(logs, "supervisor.register.revoked_reregister")) == 1
    assert load_appliance_id(state_dir) == FRESH
    assert approval_state.read_state(state_dir) == "approved"


def test_a_row_deleted_while_the_node_waits_is_replaced_at_its_next_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one case the wait delays: a row revoked first (refused while it is
    there) and deleted minutes later. The node re-registers at the first attempt
    its schedule allows, within the four-minute cap and a tick of the delete."""
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)

    logs = _run_main(
        monkeypatch, state_dir, cp, ticks=20, events={1: _revoke, 11: _delete}, api=_Api(cp)
    )

    # The delete lands after tick 11, at 330 s: tick 12 starts at that same moment.
    deleted_at = TICK_S * 11
    asked = _asked_at(cp)
    assert asked[-1] >= deleted_at and all(t < deleted_at for t in asked[:-1]), asked
    assert asked[-1] - deleted_at <= 240.0 + TICK_S
    assert len(_events(logs, "supervisor.register.revoked_reregister")) == 1
    assert load_appliance_id(state_dir) == FRESH
    assert approval_state.read_state(state_dir) == "approved"
