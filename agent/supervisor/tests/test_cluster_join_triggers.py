"""Supervisor control-plane join/leave trigger writers (#272 Phase 7b).

Covers the appliance-only gate, the trigger payload shape, idempotency
(no stacking while a trigger is unconsumed), and the .state / token
sidecar readers. The actual k3s reconfigure is the host-side runner
(spatium-cluster-join) which needs a real multi-VM cluster to validate.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state


@pytest.fixture
def appliance_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point every cluster trigger/sidecar path at a tmp dir + force the
    appliance deployment kind so the gates pass."""
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(
        appliance_state, "_CLUSTER_JOIN_TRIGGER_FILE", tmp_path / "cluster-join-pending"
    )
    monkeypatch.setattr(
        appliance_state, "_CLUSTER_LEAVE_TRIGGER_FILE", tmp_path / "cluster-leave-pending"
    )
    monkeypatch.setattr(
        appliance_state, "_CLUSTER_JOIN_STATE_SIDECAR", tmp_path / "cluster-join.state"
    )
    monkeypatch.setattr(appliance_state, "_K3S_JOIN_TOKEN_SIDECAR", tmp_path / "k3s-join-token")
    # #590 — keep the consumed marker off the real host. The attempt ledgers
    # derive from the trigger paths above (``<trigger>.fire-state``), so they
    # already land in tmp_path.
    monkeypatch.setattr(
        appliance_state,
        "_CLUSTER_JOIN_STATE_CONSUMED",
        tmp_path / "cluster-join.state.consumed",
    )
    return tmp_path


def test_join_writes_trigger_with_payload(appliance_paths: Path) -> None:
    fired = appliance_state.maybe_fire_cluster_join("member", "https://10.0.0.1:6443", "K10::tok")
    assert fired is True
    body = (appliance_paths / "cluster-join-pending").read_text()
    # Three lines: the guardrail confirm marker, then server_url + token.
    assert body == (
        f"{appliance_state._CLUSTER_JOIN_CONFIRM}\nhttps://10.0.0.1:6443\nK10::tok\n"
    )


def test_join_trigger_is_owner_only(appliance_paths: Path) -> None:
    # The payload carries the k3s join token (a control-plane-admin-
    # equivalent secret) into the shared release-state dir — the
    # trigger file must be 0o600 so no other unprivileged host user can
    # read it before the root runner consumes it (sec scanning #82).
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "tok") is True
    mode = stat.S_IMODE((appliance_paths / "cluster-join-pending").stat().st_mode)
    assert mode == 0o600


def test_join_idempotent_until_consumed(appliance_paths: Path) -> None:
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is True
    # Trigger already present → don't stack.
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is False


def test_join_requires_member_role_and_coordinates(appliance_paths: Path) -> None:
    assert appliance_state.maybe_fire_cluster_join("none", "https://s:6443", "t") is False
    assert appliance_state.maybe_fire_cluster_join("member", None, "t") is False
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", None) is False
    assert not (appliance_paths / "cluster-join-pending").exists()


def test_join_skipped_off_appliance(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(
        appliance_state, "_CLUSTER_JOIN_TRIGGER_FILE", tmp_path / "cluster-join-pending"
    )
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is False
    assert not (tmp_path / "cluster-join-pending").exists()


def test_leave_writes_trigger(appliance_paths: Path) -> None:
    assert appliance_state.maybe_fire_cluster_leave("none") is True
    assert (appliance_paths / "cluster-leave-pending").exists()


def test_leave_requires_none_role(appliance_paths: Path) -> None:
    assert appliance_state.maybe_fire_cluster_leave("member") is False
    assert not (appliance_paths / "cluster-leave-pending").exists()


def test_read_cluster_join_state(appliance_paths: Path) -> None:
    # Sidecar shape is "state\treason"; a bare state has no reason.
    (appliance_paths / "cluster-join.state").write_text("ready\t")
    assert appliance_state.read_cluster_join_state() == ("ready", None)
    (appliance_paths / "cluster-join.state").write_text("failed\tetcd join refused")
    assert appliance_state.read_cluster_join_state() == ("failed", "etcd join refused")


def test_read_cluster_join_state_missing(appliance_paths: Path) -> None:
    assert appliance_state.read_cluster_join_state() == (None, None)


def test_read_k3s_join_token(appliance_paths: Path) -> None:
    assert appliance_state.read_k3s_join_token() is None
    (appliance_paths / "k3s-join-token").write_text("K10::servertoken\n")
    assert appliance_state.read_k3s_join_token() == "K10::servertoken"


# ── join failure ceiling + terminal-state retirement (#590) ──────────
#
# Before #590 the ONLY guard on re-firing was trigger-file presence, and
# the host runner renames a failed trigger to ``.failed.<ts>`` — so a join
# that could never succeed re-ran a DESTRUCTIVE k3s wipe-and-rejoin on
# every heartbeat, forever, while the row read "joining".


def _consume(path: Path) -> None:
    """Simulate the host runner consuming the trigger (it renames it)."""
    path.rename(path.with_suffix(".failed"))


def test_join_refires_after_the_runner_consumes_the_trigger(appliance_paths: Path) -> None:
    """The re-fire itself is legitimate — retrying a transient failure is
    the point. It's the UNBOUNDED re-fire that was the bug."""
    trigger = appliance_paths / "cluster-join-pending"
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is True
    _consume(trigger)
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is True


def test_join_never_refires_after_it_already_succeeded(appliance_paths: Path) -> None:
    """REGRESSION GUARD (#590), observed live on a 1→3 promote.

    The runner renames the trigger to ``.done`` the moment it succeeds, but
    ``desired_cluster_role`` stays "member" until the backend sees a ``ready``
    heartbeat and settles it. In that window the trigger file is gone and the
    desired-state is still set — and the join re-fired, wiping the node's
    freshly-joined k3s identity. On the real cluster: "JOIN ok" at 15:43:31,
    re-fired at 15:43:58, second attempt failed. k3s counted the node as an
    etcd member; the control plane counted it as nothing."""
    trigger = appliance_paths / "cluster-join-pending"
    state = appliance_paths / "cluster-join.state"
    url = "https://10.0.0.1:6443"

    assert appliance_state.maybe_fire_cluster_join("member", url, "t") is True
    # Runner succeeds: writes ready + renames the trigger out of the way.
    state.write_text(f"ready\t{url}")
    trigger.rename(trigger.with_suffix(".done"))

    # Heartbeat still carries desired=member (backend hasn't settled yet).
    assert appliance_state.maybe_fire_cluster_join("member", url, "t") is False
    assert not trigger.exists()


def test_join_does_not_refire_while_the_runner_is_mid_flight(appliance_paths: Path) -> None:
    """The runner writes ``joining`` at the top of its run and renames the
    trigger before it finishes — so trigger-absence must not mean 'idle'."""
    trigger = appliance_paths / "cluster-join-pending"
    state = appliance_paths / "cluster-join.state"
    url = "https://10.0.0.1:6443"

    assert appliance_state.maybe_fire_cluster_join("member", url, "t") is True
    state.write_text(f"joining\t{url}")
    trigger.rename(trigger.with_suffix(".done"))

    assert appliance_state.maybe_fire_cluster_join("member", url, "t") is False


def test_join_refires_when_promoted_to_a_DIFFERENT_seed(appliance_paths: Path) -> None:
    """``ready`` against seed A must not block a join to seed B. The .state
    reason field carries the target, which is what makes this decidable."""
    trigger = appliance_paths / "cluster-join-pending"
    state = appliance_paths / "cluster-join.state"

    assert appliance_state.maybe_fire_cluster_join("member", "https://a:6443", "t") is True
    state.write_text("ready\thttps://a:6443")
    trigger.rename(trigger.with_suffix(".done"))

    assert appliance_state.maybe_fire_cluster_join("member", "https://a:6443", "t") is False
    assert appliance_state.maybe_fire_cluster_join("member", "https://b:6443", "t") is True


def test_join_still_retries_after_a_reported_failure(appliance_paths: Path) -> None:
    """A ``failed`` verdict must NOT block a retry — only ready/joining do."""
    trigger = appliance_paths / "cluster-join-pending"
    state = appliance_paths / "cluster-join.state"
    url = "https://10.0.0.1:6443"

    assert appliance_state.maybe_fire_cluster_join("member", url, "t") is True
    state.write_text("failed\tboom")
    _consume(trigger)
    assert appliance_state.maybe_fire_cluster_join("member", url, "t") is True


def test_leave_never_refires_after_it_already_succeeded(appliance_paths: Path) -> None:
    """do_leave runs the same destructive identity wipe and renames its
    trigger on success — identical window, identical guard."""
    trigger = appliance_paths / "cluster-leave-pending"
    state = appliance_paths / "cluster-join.state"

    assert appliance_state.maybe_fire_cluster_leave("none") is True
    state.write_text("left\t")
    trigger.rename(trigger.with_suffix(".done"))

    assert appliance_state.maybe_fire_cluster_leave("none") is False


def test_leave_does_not_refire_while_the_runner_is_mid_flight(appliance_paths: Path) -> None:
    trigger = appliance_paths / "cluster-leave-pending"
    state = appliance_paths / "cluster-join.state"

    assert appliance_state.maybe_fire_cluster_leave("none") is True
    state.write_text("leaving\t")
    trigger.rename(trigger.with_suffix(".done"))

    assert appliance_state.maybe_fire_cluster_leave("none") is False


def test_join_stops_firing_at_the_attempt_ceiling(appliance_paths: Path) -> None:
    trigger = appliance_paths / "cluster-join-pending"
    for _ in range(appliance_state._CLUSTER_JOIN_MAX_ATTEMPTS):
        assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is True
        _consume(trigger)
    # Budget exhausted — no more destructive wipes against this target.
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is False
    assert not trigger.exists()


def test_attempt_ledger_never_stores_the_join_token(appliance_paths: Path) -> None:
    """The token is control-plane-admin-equivalent; the ledger only needs
    to answer 'same target as last time?'."""
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "sekrit") is True
    ledger = (appliance_paths / "cluster-join-pending.fire-state").read_text()
    assert "sekrit" not in ledger


# ── the LEAVE path is exactly as destructive, and needs the same ceiling ──


def test_leave_refires_after_the_runner_consumes_the_trigger(appliance_paths: Path) -> None:
    trigger = appliance_paths / "cluster-leave-pending"
    assert appliance_state.maybe_fire_cluster_leave("none") is True
    _consume(trigger)
    assert appliance_state.maybe_fire_cluster_leave("none") is True


def test_leave_stops_firing_at_the_attempt_ceiling(appliance_paths: Path) -> None:
    """#590 — do_leave runs the same full identity wipe as do_join and
    renames a failed trigger away, so an unbounded leave loop would re-wipe
    k3s on every heartbeat."""
    trigger = appliance_paths / "cluster-leave-pending"
    for _ in range(appliance_state._CLUSTER_JOIN_MAX_ATTEMPTS):
        assert appliance_state.maybe_fire_cluster_leave("none") is True
        _consume(trigger)
    assert appliance_state.maybe_fire_cluster_leave("none") is False
    assert not trigger.exists()


def test_reset_restores_the_leave_budget_too(appliance_paths: Path) -> None:
    trigger = appliance_paths / "cluster-leave-pending"
    for _ in range(appliance_state._CLUSTER_JOIN_MAX_ATTEMPTS):
        appliance_state.maybe_fire_cluster_leave("none")
        _consume(trigger)
    assert appliance_state.maybe_fire_cluster_leave("none") is False
    appliance_state.reset_cluster_join_attempts()
    assert appliance_state.maybe_fire_cluster_leave("none") is True


def test_join_and_leave_budgets_are_independent(appliance_paths: Path) -> None:
    """Exhausting one transition must not lock out the other."""
    join_trigger = appliance_paths / "cluster-join-pending"
    for _ in range(appliance_state._CLUSTER_JOIN_MAX_ATTEMPTS):
        appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t")
        _consume(join_trigger)
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is False
    assert appliance_state.maybe_fire_cluster_leave("none") is True


def test_a_different_join_target_gets_a_fresh_budget(appliance_paths: Path) -> None:
    trigger = appliance_paths / "cluster-join-pending"
    for _ in range(appliance_state._CLUSTER_JOIN_MAX_ATTEMPTS):
        assert appliance_state.maybe_fire_cluster_join("member", "https://a:6443", "t") is True
        _consume(trigger)
    assert appliance_state.maybe_fire_cluster_join("member", "https://a:6443", "t") is False
    # Promoted against a different seed → new fingerprint → fires again.
    assert appliance_state.maybe_fire_cluster_join("member", "https://b:6443", "t") is True


def test_reset_restores_the_budget_for_the_same_target(appliance_paths: Path) -> None:
    """The heartbeat resets the ledger whenever the control plane stops
    asking for a join — so an operator re-promoting against the SAME seed
    doesn't inherit an exhausted budget."""
    trigger = appliance_paths / "cluster-join-pending"
    for _ in range(appliance_state._CLUSTER_JOIN_MAX_ATTEMPTS):
        appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t")
        _consume(trigger)
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is False

    appliance_state.reset_cluster_join_attempts()
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is True


def test_reset_is_a_noop_without_a_ledger(appliance_paths: Path) -> None:
    appliance_state.reset_cluster_join_attempts()  # must not raise


def test_consumed_terminal_state_stops_being_reported(appliance_paths: Path) -> None:
    """The core anti-deadlock property. The backend now clears the
    desired-state on a reported ``failed``; if the supervisor kept
    re-reporting that stale verdict it would clear the desired-state of
    the operator's NEXT promote before the join ever fired."""
    state = appliance_paths / "cluster-join.state"
    state.write_text("failed\tjoin failed; rolled back to single-node")

    # First report reaches the backend...
    assert appliance_state.read_cluster_join_state() == (
        "failed",
        "join failed; rolled back to single-node",
    )
    # ...the backend acts on it and drops the desired-state, so the
    # heartbeat retires the verdict.
    appliance_state.mark_cluster_join_state_consumed()
    assert appliance_state.read_cluster_join_state() == (None, None)


def test_a_new_runner_verdict_reports_again_after_consumption(appliance_paths: Path) -> None:
    """The runner rewrites .state at the top of every run, so a genuinely
    new episode must not be swallowed by the consumed marker."""
    state = appliance_paths / "cluster-join.state"
    state.write_text("failed\told")
    appliance_state.mark_cluster_join_state_consumed()
    assert appliance_state.read_cluster_join_state() == (None, None)

    # Runner starts a fresh join: new content, new mtime.
    state.write_text("joining\thttps://s:6443")
    os.utime(state, ns=(0, 1))
    assert appliance_state.read_cluster_join_state() == ("joining", "https://s:6443")

    state.write_text("failed\tnew reason")
    os.utime(state, ns=(0, 2))
    assert appliance_state.read_cluster_join_state() == ("failed", "new reason")


def test_in_flight_states_are_never_retired(appliance_paths: Path) -> None:
    """``joining`` / ``leaving`` are still in flight — the backend needs to
    keep seeing them, so the marker must refuse to swallow them."""
    state = appliance_paths / "cluster-join.state"
    for in_flight in ("joining", "leaving"):
        state.write_text(f"{in_flight}\t")
        appliance_state.mark_cluster_join_state_consumed()
        assert appliance_state.read_cluster_join_state() == (in_flight, None)
    assert not (appliance_paths / "cluster-join.state.consumed").exists()


def test_ready_is_never_retired(appliance_paths: Path) -> None:
    """REGRESSION GUARD (#590). ``ready`` is not merely a report to the
    control plane — it is this node's LOCAL source of truth for "I am a
    promoted control-plane member":

      * service_lifecycle.reconcile_node_labels() adds the control-plane
        node label on ``ready`` and STRIPS it otherwise, and that label
        gates api / frontend / worker / beat / CNPG / redis scheduling.
      * heartbeat._is_control_plane_member() uses it to pick the in-cluster
        api Service over the seed's external URL.

    Retiring it would deschedule the control plane off every promoted
    member on the first idle heartbeat after a SUCCESSFUL promote."""
    state = appliance_paths / "cluster-join.state"
    state.write_text("ready\thttps://s:6443")

    # The heartbeat's idle branch marks consumed on every steady-state tick.
    for _ in range(3):
        appliance_state.mark_cluster_join_state_consumed()
        assert appliance_state.read_cluster_join_state() == ("ready", "https://s:6443")
    assert not (appliance_paths / "cluster-join.state.consumed").exists()


def test_left_is_never_retired(appliance_paths: Path) -> None:
    """``left`` needs no retiring either: the backend's settle branches are
    gated on desired_cluster_role, so re-reporting it is already a no-op."""
    state = appliance_paths / "cluster-join.state"
    state.write_text("left\t")
    appliance_state.mark_cluster_join_state_consumed()
    assert appliance_state.read_cluster_join_state() == ("left", None)
    assert not (appliance_paths / "cluster-join.state.consumed").exists()


def test_mark_consumed_rewrites_an_unreadable_marker(appliance_paths: Path) -> None:
    """An unreadable marker is indistinguishable from a non-matching one, so
    it must be rewritten — otherwise a stale ``failed`` keeps being reported,
    which is exactly the failure the marker exists to prevent."""
    state = appliance_paths / "cluster-join.state"
    state.write_text("failed\tboom")
    # A directory where the marker file should be: read_text raises
    # IsADirectoryError (an OSError), not FileNotFoundError.
    marker = appliance_paths / "cluster-join.state.consumed"
    marker.mkdir()

    appliance_state.mark_cluster_join_state_consumed()  # must not raise
    # The rewrite can't clobber a directory, so the verdict still reports —
    # degraded but never silent, and never a wipe.
    assert appliance_state.read_cluster_join_state() == ("failed", "boom")


def test_reset_tolerates_an_absent_ledger_every_tick(appliance_paths: Path) -> None:
    """The idle heartbeat calls this on every tick of the appliance's life;
    a missing ledger is the expected case, not an error."""
    for _ in range(3):
        appliance_state.reset_cluster_join_attempts()  # must not raise


def test_mark_consumed_is_idempotent_and_does_not_rewrite(appliance_paths: Path) -> None:
    """It runs on every steady-state heartbeat; rewriting identical bytes
    would churn the flash-backed /var partition for the appliance's life."""
    state = appliance_paths / "cluster-join.state"
    state.write_text("failed\tboom")
    appliance_state.mark_cluster_join_state_consumed()
    marker = appliance_paths / "cluster-join.state.consumed"
    first_mtime = marker.stat().st_mtime_ns

    for _ in range(3):
        appliance_state.mark_cluster_join_state_consumed()
    assert marker.stat().st_mtime_ns == first_mtime


def test_mark_consumed_is_a_noop_without_a_sidecar(appliance_paths: Path) -> None:
    appliance_state.mark_cluster_join_state_consumed()  # must not raise
    assert not (appliance_paths / "cluster-join.state.consumed").exists()


def test_promote_fail_repromote_cycle_converges(appliance_paths: Path) -> None:
    """End-to-end guard on the deadlock the #590 fix could have introduced:
    a failed join must not poison the operator's next promote."""
    trigger = appliance_paths / "cluster-join-pending"
    state = appliance_paths / "cluster-join.state"

    # Promote #1 → runner runs → fails, rolls back.
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is True
    state.write_text("failed\tboom")
    os.utime(state, ns=(0, 1))
    _consume(trigger)

    # Heartbeat reports the failure; backend clears the desired-state, so
    # the next heartbeat takes the "no desired role" branch.
    assert appliance_state.read_cluster_join_state() == ("failed", "boom")
    appliance_state.reset_cluster_join_attempts()
    appliance_state.mark_cluster_join_state_consumed()

    # The stale verdict is retired, so the row keeps the JOINING the
    # promote endpoint stamped...
    assert appliance_state.read_cluster_join_state() == (None, None)
    # ...and promote #2 actually fires.
    assert appliance_state.maybe_fire_cluster_join("member", "https://s:6443", "t") is True


# ── guided etcd restore (#272 Phase 9b) ──────────────────────────────


@pytest.fixture
def restore_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the restore trigger + state sidecar at a tmp dir + force the
    appliance deployment kind so the gate passes."""
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(
        appliance_state, "_CLUSTER_RESTORE_TRIGGER_FILE", tmp_path / "cluster-restore-pending"
    )
    monkeypatch.setattr(
        appliance_state, "_CLUSTER_RESTORE_STATE_SIDECAR", tmp_path / "cluster-restore.state"
    )
    return tmp_path


def test_restore_writes_trigger_with_marker(restore_paths: Path) -> None:
    assert appliance_state.maybe_fire_cluster_restore("snap-A") is True
    body = (restore_paths / "cluster-restore-pending").read_text()
    # Two lines: the guardrail confirm marker, then the snapshot name.
    assert body == f"{appliance_state._CLUSTER_RESTORE_CONFIRM}\nsnap-A\n"


def test_restore_idempotent_until_consumed(restore_paths: Path) -> None:
    assert appliance_state.maybe_fire_cluster_restore("snap-A") is True
    assert appliance_state.maybe_fire_cluster_restore("snap-A") is False


def test_restore_requires_snapshot(restore_paths: Path) -> None:
    assert appliance_state.maybe_fire_cluster_restore(None) is False
    assert appliance_state.maybe_fire_cluster_restore("") is False
    assert not (restore_paths / "cluster-restore-pending").exists()


def test_restore_skipped_off_appliance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(
        appliance_state, "_CLUSTER_RESTORE_TRIGGER_FILE", tmp_path / "cluster-restore-pending"
    )
    assert appliance_state.maybe_fire_cluster_restore("snap-A") is False
    assert not (tmp_path / "cluster-restore-pending").exists()


def test_read_cluster_restore_state(restore_paths: Path) -> None:
    assert appliance_state.read_cluster_restore_state() == (None, None)
    (restore_paths / "cluster-restore.state").write_text("restoring\tsnap-A")
    assert appliance_state.read_cluster_restore_state() == ("restoring", "snap-A")
    (restore_paths / "cluster-restore.state").write_text("done\t")
    assert appliance_state.read_cluster_restore_state() == ("done", None)
