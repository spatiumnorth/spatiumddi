"""Approval-state tracking for the supervisor (#170 Wave E follow-up).

Before this module the supervisor cached ``cert.pem`` at first
approval and assumed it stayed approved forever. The console
dashboard read that cert's existence as the "Approved ✓" green chip,
even after the operator deleted the appliance row from the Fleet UI
and the heartbeat had been returning 403 / 404 for hours.

This module turns the implicit two-state (no-cert vs has-cert) into
an explicit three-state machine:

* ``pending``   — supervisor hasn't been approved yet (no cert on
                  disk + no claim, OR claim succeeded but admin
                  hasn't approved). Same as the absence-of-file
                  base case.
* ``approved``  — at least one heartbeat in the last
                  ``REVOCATION_STRIKE_LIMIT`` returned 200. This is
                  the steady-state green-chip path.
* ``revoked``   — ``REVOCATION_STRIKE_LIMIT`` consecutive heartbeats
                  returned 403 / 404. The appliance row was deleted
                  (or its supervisor cert was revoked) on the control
                  plane; the supervisor stops applying role
                  assignments and surfaces a red ``Approval revoked``
                  chip on the console dashboard.

The strike counter is the de-noise layer: a control-plane restart
or migration window can produce a short 404 burst that shouldn't
trip a revocation. We require N consecutive 403/404 responses
(N=3 default → ~3 min at the standard 60 s heartbeat cadence) before
flipping state.

Files written under ``state_dir`` (= ``/var/persist/spatium-supervisor``
on the appliance):

* ``approval-state``       — bare text ``approved`` / ``revoked``.
                             Absent = pending.
* ``revocation-strikes``   — integer; how many consecutive 403/404
                             responses since the last successful
                             heartbeat. Reset to 0 on any 200.

Both are atomically written so a supervisor crash mid-flush can't
leave a torn file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

ApprovalState = Literal["pending", "approved", "revoked"]

# Number of consecutive 403/404 heartbeats before we flip to
# ``revoked``. Two strikes × 60s heartbeat = ~2 min from operator
# click to services going dark — short enough to feel responsive,
# long enough that a single missed heartbeat (transient network
# blip) doesn't trip a false revocation. Phase 9 (#183) dropped
# this from 3 to 2 after live-testing the revocation flow felt
# slow; a real control-plane restart takes seconds, not minutes,
# so the previous "30-60 s outage tolerance" was overkill.
REVOCATION_STRIKE_LIMIT = 2

_STATE_FILE = "approval-state"
_STRIKES_FILE = "revocation-strikes"


def read_state(state_dir: Path) -> ApprovalState:
    """Return the persisted approval state. Absence = ``pending`` so
    a fresh install / cleared identity reads the natural default."""
    path = state_dir / _STATE_FILE
    try:
        body = path.read_text(encoding="utf-8").strip()
    except OSError:
        return "pending"
    if body == "approved":
        return "approved"
    if body == "revoked":
        return "revoked"
    return "pending"


def role_services_hold(state_dir: Path) -> ApprovalState | None:
    """The approval state that holds this node's role services down, or
    ``None`` when the node is approved and they may run (#2808).

    The one gate every path that brings role services up consults: the
    watchdog's auto-heal and the heartbeat's role apply. Only ``approved``
    lets them run. ``revoked`` is a node taken out of service (its teardown
    deliberately keeps ``role-compose.env`` so a re-registration can restore
    the roles, #2801, so the file alone says nothing about whether they should
    be running); ``pending`` is a node not yet approved, including one that
    re-registered after a revoke and is waiting for its new row's first
    accepted heartbeat."""
    state = read_state(state_dir)
    return None if state == "approved" else state


def read_strikes(state_dir: Path) -> int:
    """Read the consecutive-403/404 strike count. Missing / unreadable
    → 0 so a fresh supervisor starts with a clean counter."""
    path = state_dir / _STRIKES_FILE
    try:
        return int(path.read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return 0


def _atomic_write(path: Path, body: str) -> None:
    """Write + atomic-rename so a crash mid-flush can't leave a torn
    file. Failures are silently swallowed — the supervisor must keep
    running even if /var is read-only or out of space."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(body, encoding="utf-8")
        tmp.replace(path)
    except OSError:
        # Intentional: the strike-counter + state files are diagnostic,
        # not load-bearing. A read-only / full /var partition shouldn't
        # crash the supervisor's heartbeat loop. The next successful
        # write will catch up; in the meantime in-memory state remains
        # authoritative for this process.
        pass


def _atomic_delete(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # Same rationale as _atomic_write: best-effort cleanup. A
        # leftover .strikes file from a previous run is harmless
        # (read_strikes() handles missing + bogus content).
        pass


def record_success(state_dir: Path) -> ApprovalState:
    """Heartbeat returned 200. Clear the strike counter and stamp
    ``approved`` if we weren't already there. Returns the new state
    so the caller can log the transition without re-reading."""
    _atomic_delete(state_dir / _STRIKES_FILE)
    current = read_state(state_dir)
    if current != "approved":
        _atomic_write(state_dir / _STATE_FILE, "approved\n")
    return "approved"


def record_revocation_signal(state_dir: Path) -> tuple[ApprovalState, int]:
    """Heartbeat returned 403 or 404 — the control plane is telling
    us we shouldn't be talking to it. Increment the strike counter
    and flip to ``revoked`` once the threshold is hit.

    Returns ``(new_state, new_strikes)`` so the caller can log the
    transition or threshold crossing without re-reading. Already-
    revoked state stays revoked; the strike counter keeps incrementing
    just so the operator can see how long the condition has persisted
    (useful for "is this still happening?" forensics in the journal).
    """
    strikes = read_strikes(state_dir) + 1
    _atomic_write(state_dir / _STRIKES_FILE, str(strikes) + "\n")
    if strikes >= REVOCATION_STRIKE_LIMIT:
        current = read_state(state_dir)
        if current != "revoked":
            _atomic_write(state_dir / _STATE_FILE, "revoked\n")
        return "revoked", strikes
    # Below threshold — preserve whatever the prior state was. A
    # first-time pending supervisor that gets a 403 stays pending
    # (the control plane never approved it; same shape).
    return read_state(state_dir), strikes


def clear(state_dir: Path) -> None:
    """Reset to pending. Called from the recovery path that wipes the
    cached identity so a fresh pairing-code claim becomes the natural
    next step."""
    _atomic_delete(state_dir / _STATE_FILE)
    _atomic_delete(state_dir / _STRIKES_FILE)
