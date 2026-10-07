"""Cluster-wide single-upgrader mutex (#296 Phase A).

Built on ``coordination.k8s.io/v1/Lease`` — the same primitive Kubernetes
uses internally for controller-manager leader election. We pick this
shape over a DB row because:

* The lease lives in etcd, not Postgres. If CNPG fails over mid-upgrade
  we don't briefly lose the lock.
* Lease expiration is server-side. An api pod that holds the lease then
  crashes loses it after ``leaseDurationSeconds`` without anyone having
  to clean up; whichever pod next renews wins automatically.
* The lease's holder identity is operator-visible via ``kubectl get
  leases`` — a debugging surface that doesn't require app changes.

The lease is **not** the source of truth for the upgrade row in
Postgres; the ``SystemUpgradeRun`` row records what's planned + which
holder started it for audit. The lease just guarantees that at most
one api pod is *driving* the orchestrator at any moment.

Phase A ships the helper; Phase D's orchestrator beat task is what
calls ``acquire()`` / ``renew()`` / ``release()`` while it runs.
"""

from __future__ import annotations

import os
import socket
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.appliance import k8s

logger = structlog.get_logger(__name__)

# The Lease name + namespace are fixed per cluster — one lease object,
# always in the same place. Lives in the namespace the api pod runs in
# (``kube-system`` for the appliance shape; whatever namespace the
# Helm release was installed into for docker/k8s deployments).
LEASE_NAME = "spatium-upgrade-lock"
# 60 s default matches the upstream k8s leader-election library. The
# orchestrator (Phase D) renews every ``LEASE_DURATION_S / 3`` so two
# missed renewals still leave time before expiration.
LEASE_DURATION_S = 60


@dataclass(frozen=True)
class LeaseState:
    """Operator-visible lease state.

    ``held`` is true when the lease exists + has a non-expired
    ``renewTime``. ``holder`` is whoever wrote the lease last.
    ``transitions`` is k8s's leadership-change counter — a value
    higher than what the orchestrator recorded last means another
    api pod took over since.
    """

    held: bool
    holder: str | None
    renew_time: str | None
    transitions: int
    expired: bool


_NO_LEASE = LeaseState(held=False, holder=None, renew_time=None, transitions=0, expired=False)


def _identity() -> str:
    """The pod's hostname (k8s sets it to the pod name).

    Not, on its own, an identity a driver may hold the lease under (#1512): a
    worker pod runs several Celery tasks at once, and a second task in the same
    pod took ``acquire()``'s "already ours, renew" branch and ran a second drive
    loop. Drivers hold the lease as ``drive_identity()`` instead.
    """
    return os.environ.get("HOSTNAME") or socket.gethostname()


def drive_identity() -> str:
    """A lease identity for ONE drive of the orchestrator:
    ``<pod-name>_<random>`` (the k8s leader-election convention). Every
    acquire / renew / release of that drive names it, so no other task, in
    this pod or another, can renew or release its lease (#1512)."""
    return f"{_identity()}_{uuid.uuid4().hex[:12]}"


def _parse_lease(body: dict[str, Any] | None) -> LeaseState:
    if not body:
        return LeaseState(
            held=False,
            holder=None,
            renew_time=None,
            transitions=0,
            expired=False,
        )
    spec = body.get("spec") or {}
    holder = spec.get("holderIdentity")
    renew_time = spec.get("renewTime")
    duration = int(spec.get("leaseDurationSeconds") or LEASE_DURATION_S)
    transitions = int(spec.get("leaseTransitions") or 0)
    expired = False
    if renew_time:
        try:
            # ``renewTime`` is RFC3339 UTC, e.g. "2026-05-22T10:00:00Z".
            # ``fromisoformat`` accepts the trailing-Z form on 3.11+.
            renewed = datetime.fromisoformat(renew_time.replace("Z", "+00:00"))
            age = (datetime.now(UTC) - renewed).total_seconds()
            expired = age > duration
        except ValueError:
            # Unparseable timestamp — treat as expired so callers can
            # take over rather than refusing to start forever.
            expired = True
    return LeaseState(
        held=bool(holder) and not expired,
        holder=holder,
        renew_time=renew_time,
        transitions=transitions,
        expired=expired,
    )


def get_state(*, namespace: str | None = None) -> LeaseState:
    """Read the lease's current state without trying to claim it.

    Used by the preflight endpoint to surface "another upgrade is in
    flight" cleanly. Returns the all-false state if the lease doesn't
    exist yet (no upgrade has ever run on this cluster).
    """
    return _read(namespace=namespace)[0]


def _read(*, namespace: str | None = None) -> tuple[LeaseState, str | None]:
    """The lease's state and the ``metadata.resourceVersion`` it was read at,
    which a following write passes back as its compare-and-swap precondition
    (#1512). The version is None whenever there is no lease body to hold."""
    try:
        status, body = k8s.get_lease(LEASE_NAME, namespace=namespace)
    except k8s.KubeapiUnavailableError:
        # On docker-compose deployments the SA isn't mounted; treat as
        # "no lease, no concurrent upgrade" — single-node deployments
        # don't need a cluster-wide lock anyway.
        return _NO_LEASE, None
    if status == 404:
        return _NO_LEASE, None
    if status != 200 or body is None:
        # Distinguish RBAC-missing (403) from kubeapi-blip (5xx). Both
        # are "conservatively held" so we don't race a second upgrade
        # into a real concurrent run, but the holder label is the
        # operator's hint to fix the right thing — 403 means "fix your
        # RBAC", 5xx means "wait for the api to recover then retry".
        # (Verified on a 3-node appliance: pre-#296 charts that didn't
        # opt-in to upgradeOrchestratorRBAC surfaced the same code path
        # but with the misleading ``<unreachable>`` label.)
        holder_hint = (
            "<rbac-missing>"
            if status == 403
            else "<forbidden>" if status == 401 else "<unreachable>"
        )
        logger.warning("upgrade_lease_read_failed", status=status, holder=holder_hint)
        return (
            LeaseState(
                held=True,
                holder=holder_hint,
                renew_time=None,
                transitions=0,
                expired=False,
            ),
            None,
        )
    version = (body.get("metadata") or {}).get("resourceVersion")
    return _parse_lease(body), str(version) if version else None


def acquire(
    *,
    holder: str | None = None,
    namespace: str | None = None,
    lease_duration_seconds: int = LEASE_DURATION_S,
) -> tuple[bool, str | None]:
    """Acquire the upgrade lease as ``holder`` (default: this pod's hostname;
    the orchestrator passes its ``drive_identity()``).

    1. No lease → create it; (True, None).
    2. Held by ``holder`` → renew it.
    3. Held by someone else, unexpired → (False, "held by <holder>").
    4. Expired → take over with a transitions bump, as a compare-and-swap on
       the version just read (#1512): of two simultaneous takeovers exactly
       one wins, and the other is told it lost.

    ``lease_duration_seconds`` overrides the default for callers that run long
    enough that 60 s would expire mid-step (the orchestrator passes ~600 s).
    """
    me = holder or _identity()
    state, version = _read(namespace=namespace)
    if not state.held and state.holder is None:
        ok, err = k8s.create_lease(
            LEASE_NAME,
            me,
            namespace=namespace,
            lease_duration_seconds=lease_duration_seconds,
        )
        if ok:
            return True, None
        # Race: someone else created it between our read + write.
        # Re-read to surface their identity.
        state = get_state(namespace=namespace)
        if state.held and state.holder != me:
            return False, f"held by {state.holder}"
        # Some other failure (RBAC, kubeapi down) — propagate.
        return False, err
    if state.held and state.holder == me:
        return renew(holder=me, namespace=namespace, lease_duration_seconds=lease_duration_seconds)
    if state.held:
        return False, f"held by {state.holder}"
    # Expired — take over with a transitions bump.
    ok, err = k8s.update_lease(
        LEASE_NAME,
        me,
        namespace=namespace,
        lease_duration_seconds=lease_duration_seconds,
        bump_transitions=True,
        expected_transitions=state.transitions,
        resource_version=version,
    )
    if ok:
        return True, None
    return False, err


def renew(
    *,
    holder: str | None = None,
    namespace: str | None = None,
    lease_duration_seconds: int = LEASE_DURATION_S,
) -> tuple[bool, str | None]:
    """Renew a lease ``holder`` still holds.

    Does NOT bump ``leaseTransitions``. The orchestrator calls it every
    ``lease_duration_seconds / 3`` seconds. #1512 — it reads first and treats a
    holder other than ``holder`` as a lost lease, rather than writing its own
    name back: a legitimate takeover, or an Abort's release, used to be undone
    on the next tick. The write is a compare-and-swap on the version read, so a
    takeover between the read and the write loses this renewal instead. A
    failure means the caller no longer holds the cluster lock and must stop.
    """
    me = holder or _identity()
    state, version = _read(namespace=namespace)
    if state.holder != me:
        return False, f"lease lost: held by {state.holder or 'nobody'}"
    return k8s.update_lease(
        LEASE_NAME,
        me,
        namespace=namespace,
        lease_duration_seconds=lease_duration_seconds,
        resource_version=version,
    )


def release(*, holder: str | None = None, namespace: str | None = None) -> tuple[bool, str | None]:
    """Release the lease by setting an empty holder.

    With ``holder``, only that holder's lease is cleared (#1512): a driver
    whose lease was taken over must not release its successor's. Without it
    the lease is cleared whoever holds it, which is what an operator's Abort
    means; the driver it stops then fails its next renewal and exits.

    We don't ``DELETE`` the Lease object because keeping it around
    surfaces the historical "last upgrade ran at <timestamp> by
    <holder>" via ``kubectl get leases`` — operationally useful.
    Empty ``holderIdentity`` + a ``renewTime`` in the past lets the
    next ``acquire()`` claim it cleanly via the expired-takeover
    path.

    On docker-compose / non-k8s deployments (no SA mounted) returns
    (True, None) without making a call — single-instance deploys
    don't have a cluster lock to release.
    """
    if k8s.get_config() is None:
        return True, None
    if holder is None:
        return k8s.clear_lease_holder(LEASE_NAME, namespace=namespace)
    state, version = _read(namespace=namespace)
    if state.holder != holder:
        return True, None  # not ours: nothing of ours to release
    return k8s.clear_lease_holder(LEASE_NAME, namespace=namespace, resource_version=version)
