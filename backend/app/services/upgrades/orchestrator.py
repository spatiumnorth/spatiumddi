"""Cluster rolling-upgrade orchestrator (#296 Phase D).

Drives Phase C's per-node primitive across every node in the cluster.
DB-persisted state machine on ``SystemUpgradeRun`` rows. ``coordination.
k8s.io/v1/Lease``-based single-upgrader lock (renewed in a background
task so a 30-min upgrade doesn't expire mid-step). Quorum-aware "one
node at a time." Halt-on-failure: the first node that returns
``ok=False`` stops the loop + flips the run to ``state='failed'``.
Survives the orchestrator's own pod reschedule via the row state +
celery task re-enqueue.

Lifecycle (state transitions on the SystemUpgradeRun row):

    planned   ── operator calls /start ──> running
    running   ── all nodes succeeded   ──> succeeded
    running   ── per-node primitive ok=False  ──> failed
    running   ── operator /halt         ──> halted
    halted    ── operator /resume       ──> running
    running   ── operator /abort        ──> aborted
    halted    ── operator /abort        ──> aborted

Halt-on-failure semantics: ``failed`` is terminal. The orchestrator
does not auto-rollback — Phase 8c's slot health-gate already handles
the per-node revert path. To retry, the operator fixes the underlying
issue and starts a new run (plan + start).

Concurrency: the ``Lease`` is the cluster-wide mutex. At-most-one
orchestrator drives at any moment. The partial unique index on
``system_upgrade_run`` (Phase A's ``ix_system_upgrade_run_one_active``)
is the DB-level backstop.

Resumability: the celery task wrapper in ``app/tasks/upgrade_
orchestrator.py`` is idempotent. Re-enqueuing the same ``run_id`` (e.g.
after the celery worker dies mid-run) picks up from the row's
``progress.per_node`` map — completed nodes are skipped, the next
incomplete node is driven. A node a drive was in the middle of when it died
is driven first, whatever the plan order, and resumed at the step it was in,
from ``progress.in_flight`` (#2809): the checkpoint its chain wrote before
each step.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import literal, select, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.audit import AuditLog
from app.models.system_upgrade import LIFECYCLE_STATES, SystemUpgradeRun
from app.services.appliance import k8s
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import (
    alerts as upgrade_alerts,
)
from app.services.upgrades import (
    chart_bump,
    kubeapi_retry,
    mutex,
    node_order,
    per_node,
    preflight,
    safety,
    shared_tags,
)

logger = structlog.get_logger(__name__)

# The audit actor for the orchestrator's own transitions (started, node_failed,
# succeeded, chart_bump_failed, post_upgrade_verify_failed), which no operator
# drives. ``audit_log.user_display_name`` is NOT NULL.
SYSTEM_ACTOR = per_node.SYSTEM_ACTOR


def detect_cnpg_cluster_name(
    namespace: str | None = None, *, raise_unavailable: bool = False
) -> str:
    """The CNPG Cluster this control plane's database runs on, or ``""``.

    The chart points ``DATABASE_URL`` at the ``<cluster>-rw`` Service CNPG
    creates for the primary, so the cluster name is the host's first label
    without ``-rw``. It is confirmed by reading the Cluster CR, so a
    non-CNPG database whose host happens to end in ``-rw`` detects nothing.

    Plan used to take the name only from the operator, and the field is
    empty by default, so a default Plan skipped the CNPG maintenance window
    and the check that the primary has left a node before it is drained.
    """
    try:
        host = make_url(settings.database_url).host or ""
    except ArgumentError:
        return ""
    label = host.split(".", 1)[0]
    if not label.endswith("-rw") or len(label) <= 3:
        return ""
    candidate = label[: -len("-rw")]
    try:
        status, _ = k8s.get_cnpg_cluster(candidate, namespace=namespace)
    except k8s.KubeapiUnavailableError:
        if raise_unavailable:
            raise
        return ""
    if raise_unavailable and kubeapi_retry._status_transient(status):  # noqa: SLF001
        # #2767 — a 5xx is the API server not ready, not "no such cluster".
        raise k8s.KubeapiUnavailableError(f"kubeapi status {status}: CNPG Cluster read")
    return candidate if status == 200 else ""


# Lease duration for orchestrator runs — much longer than the 60 s
# default that suits read-only mutex.get_state() calls. A single
# node's health-gate step can spend ~30 min waiting on a slot dd +
# reboot + firstboot; the renewal loop renews every
# ``LEASE_DURATION_S / 3`` so two missed renewals still leave time
# before expiration.
LEASE_DURATION_S = 600  # 10 min
_LEASE_RENEW_INTERVAL_S = LEASE_DURATION_S / 3.0
# An unanswered renewal is retried this often (#1713).
_LEASE_RENEW_RETRY_S = 15.0
# #1713 — how long a drive may go on treating its Lease as held with no
# renewal confirmed. It must end strictly before anyone else may take the
# Lease over: a would-be acquirer reads ``renewTime`` (stamped by THIS
# worker's clock, after the renewal attempt started) and takes over once its
# own clock says ``leaseDurationSeconds`` have passed. The margin covers the
# skew between the two clocks and the length of the renewal call itself (a
# read and a write, each up to the kubeapi helpers' 10 s timeout), since the
# give-up is only checked when a call returns.
_LEASE_EXPIRY_MARGIN_S = 120.0
_LEASE_SAFE_HOLD_S = LEASE_DURATION_S - _LEASE_EXPIRY_MARGIN_S
# Patched by tests; asyncio's own clock must stay real.
_monotonic = time.monotonic


# When the per-node primitive succeeds the orchestrator gates the next
# node's start on a short cluster-wide health check + this minimum
# pause so the previous node's services have time to fully resync (DS
# bundle warm-up, CNPG replica streaming catches up).
_BETWEEN_NODES_PAUSE_S = 10.0

# How many times a run's end retries releasing the lease (2 s apart).
_LEASE_RELEASE_ATTEMPTS = 5

# A shared-tag step (the hold before a node, the flip at the end) whose
# kubeapi request went unanswered or was refused for now (a 5xx, 408, 409 or
# 429; ``shared_tags._transient``) is tried again this often,
# and fails the run only once it has kept failing this long. A k3s server
# answers 503 "apiserver not ready" while its apiserver is not up, as after
# a restart, and the kubernetes Service keeps routing to it until its
# endpoint lapses. Every re-assert and the flip follow a node's reboot.
_SHARED_TAG_RETRY_S = 15.0
_SHARED_TAG_RETRY_FOR_S = 300.0


class OrchestratorError(RuntimeError):
    """Surfaces as 409 / 422 on the api side — bad operator request."""


@dataclass(frozen=True)
class PlanResult:
    """Output of ``plan_upgrade`` — what the operator sees on the
    preview screen before clicking Start."""

    run_id: uuid.UUID
    target_version: str
    node_order: list[str]
    preflight_overall: str  # ok | warn | fail
    preflight_results: list[dict[str, Any]]


# ── Lookup helpers ───────────────────────────────────────────────────


async def get_run(db: AsyncSession, run_id: uuid.UUID) -> SystemUpgradeRun:
    """Fetch + 404-raise if the row doesn't exist."""
    row = await db.get(SystemUpgradeRun, run_id)
    if row is None:
        raise OrchestratorError(f"upgrade run {run_id} not found")
    return row


async def _get_run_locked(db: AsyncSession, run_id: uuid.UUID) -> SystemUpgradeRun:
    """The run, re-read and row-locked (``FOR UPDATE``) until the caller
    commits. Halt, Resume and Abort take it so they serialise with a drive's
    :func:`_fence`: an operator's change lands wholly before or wholly after
    the drive's next write, never between its check and the write (#1702)."""
    row = (
        await db.execute(
            select(SystemUpgradeRun)
            .where(SystemUpgradeRun.id == run_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if row is None:
        raise OrchestratorError(f"upgrade run {run_id} not found")
    return row


async def list_recent_runs(db: AsyncSession, *, limit: int = 25) -> list[SystemUpgradeRun]:
    """Most-recent-first list for the Fleet UI's history pane."""
    stmt = select(SystemUpgradeRun).order_by(SystemUpgradeRun.started_at.desc()).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


def _now() -> datetime:
    return datetime.now(UTC)


# ── plan_upgrade ─────────────────────────────────────────────────────


async def plan_upgrade(
    db: AsyncSession,
    *,
    target_version: str,
    slot_image: SlotImageTarget,
    cnpg_cluster_name: str = "",
    cnpg_namespace: str | None = None,
    started_by_user_id: uuid.UUID | None = None,
    audit_actor_display: str | None = None,
    audit_actor_source: str | None = None,
) -> PlanResult:
    """Plan a rolling upgrade (see :func:`_plan_upgrade`). Every kubeapi read the
    plan makes shares one deadline kept under the gateway's 60 s (#2767)."""
    with kubeapi_retry.request_deadline():
        return await _plan_upgrade(
            db,
            target_version=target_version,
            slot_image=slot_image,
            cnpg_cluster_name=cnpg_cluster_name,
            cnpg_namespace=cnpg_namespace,
            started_by_user_id=started_by_user_id,
            audit_actor_display=audit_actor_display,
            audit_actor_source=audit_actor_source,
        )


async def _plan_upgrade(
    db: AsyncSession,
    *,
    target_version: str,
    slot_image: SlotImageTarget,
    cnpg_cluster_name: str = "",
    cnpg_namespace: str | None = None,
    started_by_user_id: uuid.UUID | None = None,
    audit_actor_display: str | None = None,
    audit_actor_source: str | None = None,
) -> PlanResult:
    """Plan a rolling upgrade — read-only preflight + node enumeration +
    DB-persisted ``planned`` row. Does NOT acquire the lease yet; that
    happens on ``start_upgrade``.

    Refuses if:
      * The preflight aggregate returns ``overall='fail'``.
      * Another non-terminal SystemUpgradeRun row already exists (the
        partial unique index would 500 us anyway; we surface the
        409 cleanly first).
    """
    if not cnpg_cluster_name:
        # #2767 — retried like the node read below: a read refused for a
        # moment must not silently drop the CNPG maintenance window from the plan.
        try:
            cnpg_cluster_name = await kubeapi_retry.read_with_retry(
                lambda: (0, detect_cnpg_cluster_name(cnpg_namespace, raise_unavailable=True)),
                what="detect_cnpg_cluster",
            )
            cnpg_cluster_name = cnpg_cluster_name[1]
        except k8s.KubeapiUnavailableError:
            cnpg_cluster_name = ""
        if cnpg_cluster_name:
            logger.info("upgrade_plan_cnpg_cluster_detected", cluster=cnpg_cluster_name)

    # Preflight gate. #1709 — an uploaded target the mirror holds needs no
    # room on it.
    report = await preflight.run_all(
        target_version=target_version, slot_image_id=slot_image.image_id
    )
    if report.overall == "fail":
        fails = [r.name for r in report.results if r.level == "fail"]
        msg = f"preflight failed; refusing to plan: {', '.join(fails)}"
        # #2779 — an unreadable lease is the API, not another run: say so.
        if "kubeapi_unreachable" in fails:
            why = next(r.message for r in report.results if r.name == "kubeapi_unreachable")
            msg += f" ({why})"
        raise OrchestratorError(msg)

    # Refuse if a non-terminal run already exists. The unique partial
    # index would catch this too but the operator-facing error is
    # nicer.
    existing = (
        await db.execute(
            select(SystemUpgradeRun).where(
                SystemUpgradeRun.state.in_(["planned", "running", "halted"])
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise OrchestratorError(
            f"another upgrade is in flight (id={existing.id}, "
            f"state={existing.state}); finish or abort it first"
        )

    # Enumerate appliance nodes for the upgrade order.
    try:
        status, items = await kubeapi_retry.read_with_retry(
            lambda: k8s.list_nodes(label_selector="spatium.io/role=appliance"),
            what="list_nodes",
        )
    except k8s.KubeapiUnavailableError as exc:
        raise OrchestratorError(f"kubeapi unreachable: {exc}") from exc
    if status != 200:
        raise OrchestratorError(f"node list returned {status}")
    order = node_order.pick_node_order(items)
    if not order:
        raise OrchestratorError(
            "no appliance nodes found (label selector "
            "spatium.io/role=appliance) — refusing to plan an upgrade with "
            "zero targets"
        )

    # Capture source versions per node so the audit row shows the
    # before/after picture even if the appliance row's
    # installed_appliance_version is updated mid-run.
    from app.models.appliance import Appliance  # noqa: PLC0415
    from app.services.appliance.ownership import hostname_sql, k8s_node_name  # noqa: PLC0415

    source_versions: dict[str, str | None] = {}
    appliance_rows = (
        await db.execute(
            select(Appliance.hostname, Appliance.installed_appliance_version).where(
                hostname_sql(Appliance.hostname).in_([k8s_node_name(n) for n in order])
            )
        )
    ).all()
    for hostname, installed in appliance_rows:
        # Keyed by the Node name the plan and the per-node steps use (#1757).
        source_versions[k8s_node_name(hostname)] = installed

    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="planned",
        target_version=target_version,
        source_versions=source_versions,
        plan={
            "node_order": order,
            # url + sha256 + tls_insecure together — a plan carrying only
            # the URL is what left every per-node apply fetching our own
            # self-signed cert with verification on (#787 / #386).
            **slot_image.as_plan_fields(),
            "cnpg_cluster_name": cnpg_cluster_name,
            "cnpg_namespace": cnpg_namespace,
            "preflight_at_plan": [
                {"name": r.name, "level": r.level, "message": r.message} for r in report.results
            ],
        },
        progress={"per_node": {}, "events": []},
        started_by_user_id=started_by_user_id,
    )
    db.add(run)
    await db.flush()  # column-default id must exist before the audit row reads it (#2006)
    if audit_actor_display or started_by_user_id:
        db.add(
            AuditLog(
                user_id=started_by_user_id,
                user_display_name=audit_actor_display,
                auth_source=audit_actor_source,
                action="upgrade.planned",
                resource_type="system_upgrade_run",
                resource_id=str(run.id),
                resource_display=target_version,
                result="success",
                new_value={
                    "target_version": target_version,
                    "node_order": order,
                    "preflight_overall": report.overall,
                },
            )
        )
    await db.commit()
    await db.refresh(run)
    logger.info(
        "upgrade_planned",
        run_id=str(run.id),
        target_version=target_version,
        node_count=len(order),
    )
    return PlanResult(
        run_id=run.id,
        target_version=target_version,
        node_order=order,
        preflight_overall=report.overall,
        preflight_results=[
            {"name": r.name, "level": r.level, "message": r.message, "detail": r.detail}
            for r in report.results
        ],
    )


# ── State-transition operator endpoints ──────────────────────────────


async def _record_event(
    db: AsyncSession,
    run: SystemUpgradeRun,
    event: str,
    **detail: Any,
) -> None:
    """Append an entry to ``run.progress.events`` for audit + UI surface.

    SQLAlchemy doesn't track in-place JSONB mutation; replacing the
    dict + adding to the session is how we persist the change. The
    same pattern repeats in every progress-write below.
    """
    events = list(run.progress.get("events") or [])
    events.append({"event": event, "at": _now().isoformat(), **detail})
    run.progress = {**run.progress, "events": events}


async def _transition(
    db: AsyncSession,
    run: SystemUpgradeRun,
    new_state: str,
    *,
    allowed_from: tuple[str, ...],
    event: str,
    actor_user_id: uuid.UUID | None = None,
    actor_display: str | None = None,
    actor_source: str | None = None,
    **event_detail: Any,
) -> None:
    if new_state not in LIFECYCLE_STATES:
        raise OrchestratorError(f"unknown lifecycle state {new_state!r}")
    if run.state not in allowed_from:
        raise OrchestratorError(
            f"can't transition {run.state} → {new_state}; " f"allowed from {allowed_from}"
        )
    old = run.state
    run.state = new_state
    if new_state in ("succeeded", "failed", "aborted"):
        run.finished_at = _now()
    await _record_event(db, run, event, from_state=old, **event_detail)
    # #296 Phase H — write an AuditLog row on every transition so the
    # event_publisher's flush hook fires the matching typed
    # ``system.upgrade.<event>`` event to every subscribed webhook.
    # The (action, resource_type) pair maps via _SPECIAL_EVENT_MAP in
    # event_publisher.py. Internal orchestrator transitions (started /
    # succeeded / failed / chart_bump_failed / node_failed) leave the
    # actor null because they're not operator-driven; operator
    # transitions (halted / resumed / aborted) thread the calling
    # user through so the event body carries who did it.
    # Audit-log row result reflects the UPGRADE outcome, not the
    # transition operation. A transition to ``failed`` / ``aborted``
    # records ``result='error'`` so audit consumers (alerts dashboard,
    # forwarded SIEM) can filter on upgrade failures without parsing
    # ``new_value.to_state``. Operator-cancelled (aborted) counts as
    # error because the cluster is in a partial state; ``succeeded``
    # + non-terminal transitions are ``success``.
    audit_result = "error" if new_state in ("failed", "aborted") else "success"
    db.add(
        AuditLog(
            user_id=actor_user_id,
            # ``user_display_name`` and ``auth_source`` are NOT NULL, and the
            # orchestrator's own transitions have no operator. Writing None
            # failed the very first transition (``started``) of every run, so
            # no rolling upgrade could leave ``planned`` (found by ddi-pg on
            # #1449).
            user_display_name=actor_display or SYSTEM_ACTOR,
            auth_source=actor_source or "system",
            action=f"upgrade.{event}",
            resource_type="system_upgrade_run",
            resource_id=str(run.id),
            resource_display=run.target_version,
            result=audit_result,
            new_value={"from_state": old, "to_state": new_state, **event_detail},
        )
    )


async def halt_upgrade(
    db: AsyncSession,
    run_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None = None,
    actor_display: str | None = None,
    actor_source: str | None = None,
) -> SystemUpgradeRun:
    """Operator-initiated pause. Survives across orchestrator restarts —
    the next drive loop iteration sees state=halted + exits cleanly.
    """
    run = await _get_run_locked(db, run_id)
    await _transition(
        db,
        run,
        "halted",
        allowed_from=("running",),
        event="halted",
        actor_user_id=actor_user_id,
        actor_display=actor_display,
        actor_source=actor_source,
    )
    await db.commit()
    await db.refresh(run)
    return run


async def resume_upgrade(
    db: AsyncSession,
    run_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None = None,
    actor_display: str | None = None,
    actor_source: str | None = None,
) -> SystemUpgradeRun:
    """Operator-initiated resume from halt. Flips the row state but
    DOESN'T re-enqueue the celery task — the api endpoint handler does
    that after this call returns ok."""
    run = await _get_run_locked(db, run_id)
    await _transition(
        db,
        run,
        "running",
        allowed_from=("halted",),
        event="resumed",
        actor_user_id=actor_user_id,
        actor_display=actor_display,
        actor_source=actor_source,
    )
    await db.commit()
    await db.refresh(run)
    return run


async def abort_upgrade(
    db: AsyncSession,
    run_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None = None,
    actor_display: str | None = None,
    actor_source: str | None = None,
) -> SystemUpgradeRun:
    """Operator-initiated abort. Terminal — no resume. Leaves the
    cluster in whatever partial state the in-flight nodes ended in
    (some may be on the new slot, others on the old). Operator owns
    cleanup from here.
    """
    run = await _get_run_locked(db, run_id)
    was = run.state
    await _transition(
        db,
        run,
        "aborted",
        allowed_from=("planned", "running", "halted"),
        event="aborted",
        actor_user_id=actor_user_id,
        actor_display=actor_display,
        actor_source=actor_source,
    )
    await db.commit()
    # The Lease is the drive's to give up (#1707). A drive that is mid-node
    # keeps changing the cluster until that node ends, and a free Lease
    # would let a new run plan and start beside it. It sees the abort at its
    # next fence, releases its own Lease and exits. Only a run that never
    # started has no drive and no Lease of its own to wait for. A drive that
    # died holds the Lease until it expires (``LEASE_DURATION_S``).
    if was == "planned":
        ok, err = mutex.release()
        if not ok:
            logger.warning("upgrade_lease_release_failed", error=err)
    await db.refresh(run)
    return run


# A live drive renews its Lease every ``_LEASE_RENEW_INTERVAL_S``; one whose
# last renewal is older than this has missed one. Force-release is refused
# until then (#1707).
FORCE_RELEASE_MIN_IDLE_S = _LEASE_RENEW_INTERVAL_S * 1.5


class LeaseForceReleaseRefused(OrchestratorError):
    """The Lease cannot be force-released now; ``status`` is the HTTP code
    the API answers with."""

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


async def force_release_lease(
    db: AsyncSession,
    *,
    actor_user_id: uuid.UUID | None,
    actor_display: str,
    actor_source: str | None,
) -> mutex.ForceReleaseOutcome:
    """Free the upgrade Lease a dead drive left held (#1707).

    Abort no longer frees the Lease, so that a drive still on its node keeps
    other runs out; a drive that died instead holds it until it lapses
    (``LEASE_DURATION_S``). This is the operator's way out before then. It
    is refused while the holder is still renewing: freeing a live drive's
    Lease would let a second run drive the cluster beside it. Audited, and
    recorded on the run that names the holder."""
    out = mutex.force_release_idle(min_idle_s=FORCE_RELEASE_MIN_IDLE_S)
    if out.outcome == "no_lease":
        raise LeaseForceReleaseRefused("this deployment has no upgrade Lease", status=409)
    if out.outcome == "not_held":
        raise LeaseForceReleaseRefused("the upgrade Lease is not held", status=409)
    if out.outcome == "alive":
        idle = int(out.idle_s or 0)
        raise LeaseForceReleaseRefused(
            f"the holder {out.state.holder if out.state else '?'!r} renewed the Lease {idle} s "
            f"ago, so its drive is alive; it releases the Lease itself when the node it is on "
            f"ends. Retry once it has gone {int(FORCE_RELEASE_MIN_IDLE_S)} s without renewing.",
            status=409,
        )
    if out.outcome == "unreadable":
        raise LeaseForceReleaseRefused(
            f"the upgrade Lease could not be read: {out.error}", status=503
        )
    if out.outcome != "released":
        raise LeaseForceReleaseRefused(
            f"the upgrade Lease was not released: {out.error}", status=409
        )
    holder = out.state.holder if out.state else None
    run = (
        await db.execute(
            select(SystemUpgradeRun)
            .where(SystemUpgradeRun.lease_holder == holder)
            .order_by(SystemUpgradeRun.started_at.desc())
            .limit(1)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    detail = {
        "holder": holder,
        "renew_time": out.state.renew_time if out.state else None,
        "idle_s": round(out.idle_s, 1) if out.idle_s is not None else None,
    }
    if run is not None:
        await _record_event(db, run, "lease_force_released", actor=actor_display, **detail)
    db.add(
        AuditLog(
            user_id=actor_user_id,
            user_display_name=actor_display,
            auth_source=actor_source or "local",
            action="upgrade.lease_force_released",
            resource_type="system_upgrade_run",
            resource_id=str(run.id) if run is not None else mutex.LEASE_NAME,
            resource_display=run.target_version if run is not None else mutex.LEASE_NAME,
            result="success",
            new_value=detail,
        )
    )
    await db.commit()
    logger.warning("upgrade_lease_force_released", **detail)
    return out


# ── drive_upgrade — the actual orchestration loop ────────────────────


def _release_lease(run: SystemUpgradeRun, holder: str | None) -> None:
    """Release the upgrade lease when a run ends, retrying an unanswered
    API call. A run often ends while a node is rebooting, which is when
    the API times out; a lease left held refuses the next Start until it
    expires (#1449). Only ``holder``'s lease — this drive's own identity
    (#1512) — is released, never another drive's."""
    if not mutex.release_if_held(holder=holder, attempts=_LEASE_RELEASE_ATTEMPTS):
        logger.warning("upgrade_lease_release_failed", run_id=str(_run_pk(run)))


def _run_pk(run: SystemUpgradeRun) -> uuid.UUID:
    """``run.id`` without loading anything (#2809).

    A rollback expires every attribute of every object the session holds, the
    primary key included, and reading an expired attribute loads it with a
    lazy SELECT, which an async session cannot run outside ``await``: it
    raises ``MissingGreenlet``. The chain rolls the drive's session back
    whenever a statement meets a Postgres failover (#2177, #2809), so after a
    node the drive's ``run`` may well be expired. The identity key is kept
    through an expiry, and is what the session itself looks the row up by."""
    state = sa_inspect(run, raiseerr=False)
    if state is not None and state.identity:
        return uuid.UUID(str(state.identity[0]))
    return run.id


def _own_node() -> str | None:
    """The node this worker runs on (the chart's downward-API ``NODE_NAME``),
    or None when it is not known."""
    return os.environ.get("NODE_NAME") or None


def _enqueue_drive(run_id: uuid.UUID, *, avoid_node: str | None) -> None:
    """Enqueue the drive task; ``avoid_node`` asks that it not run there."""
    from app.tasks.upgrade_orchestrator import drive_upgrade_run  # noqa: PLC0415

    drive_upgrade_run.apply_async(args=[str(run_id)], kwargs={"avoid_node": avoid_node})


def _enqueue_continuation(run_id: uuid.UUID, *, avoid_version: str) -> None:
    """Enqueue the rest of the run for a worker that does NOT run
    ``avoid_version`` (#1710): the flip is rolling the workers off it."""
    from app.tasks.upgrade_orchestrator import drive_upgrade_run  # noqa: PLC0415

    drive_upgrade_run.apply_async(args=[str(run_id)], kwargs={"avoid_version": avoid_version})


def _stray_after_version_handoff(run: SystemUpgradeRun, avoid_version: str | None) -> str | None:
    """#2869 — the version ``run`` was handed off from, when this drive runs
    on it and is not the hand-off's continuation; else None.

    After the flip, a drive on the old version hands the rest of the run to a
    worker on the new one: it records ``drive_version_handoff``, releases its
    Lease and sends a continuation that old workers pass on
    (``avoid_version``, #1710). Any other drive still on the old version is a
    copy the hand-off did not send. At a broker drop Celery restores the
    running drive's message; on qa-review's drill of #2863 that copy ran the
    moment the first one handed off, took the free Lease over and went on to
    the settle wait on the old version, and the rollout stopped its worker
    with the Lease held: the new version's drive was refused until the Lease
    lapsed (600 s). The continuation itself still runs on the old version
    once it has been passed on its whole budget, as #1710 designed."""
    if not settings.version or avoid_version == settings.version:
        return None
    from_tag = shared_tags.record_of(run).get("from_tag")
    if not from_tag or str(from_tag) != settings.version:
        return None
    if not shared_tags.flip_record(run).get("handed_off_at"):
        return None
    return str(from_tag)


def _resumed_since_version_handoff(run: SystemUpgradeRun) -> bool:
    """Whether the run was resumed (a Halt, then Resume) after its last
    version hand-off: then the Resume's drive is what carries it on."""
    names = [e.get("event") for e in (run.progress or {}).get("events") or []]
    if "drive_version_handoff" not in names:
        return False
    last = len(names) - 1 - names[::-1].index("drive_version_handoff")
    return "resumed" in names[last + 1 :]


async def _locked_reread(db: AsyncSession, run: SystemUpgradeRun) -> SystemUpgradeRun | None:
    """Re-read ``run`` under ``FOR UPDATE``, discarding this session's
    unflushed changes to it.

    The ``expire`` comes first and is load-bearing: the session autoflushes
    before a query, so a ``run`` the drive has changed in memory (a shared-tag
    record, a ``progress`` key) would otherwise be written back over the
    operator's Halt or Abort by the very read meant to protect it. Callers
    that need such a change re-apply it to the fresh row."""
    run_id = _run_pk(run)
    db.expire(run)
    return (
        await db.execute(
            select(SystemUpgradeRun)
            .where(SystemUpgradeRun.id == run_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _fence(
    db: AsyncSession,
    run: SystemUpgradeRun,
    holder: str | None,
    *,
    carry: tuple[str, ...] = (),
) -> str | None:
    """Re-read the run under ``FOR UPDATE`` and say whether this drive may
    still write it: None if so, else why not (#1702, #1704, #1707).

    The drive holds its own copy of the row for the whole of a node (the
    session keeps objects past a commit), so what it writes back is stale
    the moment an operator halts or aborts, or a second drive takes over.
    Only the current holder of a ``running`` run writes it. The lock is held
    until the caller commits (or :func:`_bail` does), and Halt, Resume and
    Abort take the same lock, so nothing lands between the check and the
    write. Callers commit before anything slow (a kubeapi call, alert
    delivery): the lock is for the check and the write, nothing else.

    The holder is checked before the state: after a takeover the row is the
    other drive's whatever its state, and this drive writes nothing to it.

    ``carry`` names ``progress`` keys this drive set in memory that the
    re-read must not discard. They are kept when the run was halted or
    aborted too, since they record a change already made to the cluster
    (the shared-tag hold's pins) that the beat task or the next run must be
    able to find; only after a takeover are they dropped."""
    # An expired ``progress`` (the session was rolled back) holds no change of
    # this drive's: the rollback discarded it. Reading it would load it, which
    # an async session cannot do here (#2809).
    state = sa_inspect(run, raiseerr=False)
    progress_loaded = state is None or "progress" not in state.unloaded
    carried = (
        {k: run.progress[k] for k in carry if k in (run.progress or {})}
        if carry and progress_loaded
        else {}
    )
    fresh = await _locked_reread(db, run)
    if fresh is None:
        return "gone"
    if holder and fresh.lease_holder not in (None, holder):
        return "lease_lost"
    if carried and fresh.state in ("running", "halted", "aborted"):
        fresh.progress = {**(fresh.progress or {}), **carried}
    if fresh.state != "running":
        return str(fresh.state)
    return None


async def _bail(db: AsyncSession, run: SystemUpgradeRun, holder: str | None, why: str) -> None:
    """Leave a run this drive may no longer write: end the fence's lock, and
    give up this drive's own Lease unless a second drive has it. The run row
    is the operator's (or the other drive's) and is left exactly as it is."""
    await db.commit()
    # By identity, not ``run.id``: when the row is gone the expired object
    # cannot be loaded again.
    run_id = str(sa_inspect(run).identity[0])
    logger.info("upgrade_drive_exit_fenced", run_id=run_id, why=why)
    if why != "lease_lost" and not mutex.release_if_held(
        holder=holder, attempts=_LEASE_RELEASE_ATTEMPTS
    ):
        logger.warning("upgrade_lease_release_failed", run_id=run_id)


# ``progress`` key holding the checkpoint of the node being driven (#2809).
IN_FLIGHT_KEY = "in_flight"


def _without_in_flight(progress: dict[str, Any] | None) -> dict[str, Any]:
    """``progress`` with the node checkpoint dropped: the node has ended, so
    a later drive must not resume it (#2809)."""
    return {k: v for k, v in (progress or {}).items() if k != IN_FLIGHT_KEY}


def _in_flight_node(
    progress: dict[str, Any] | None, plan_order: list[str], completed_nodes: list[str]
) -> str | None:
    """The node an earlier drive was in the middle of, if it is one to resume
    (#2809): named by ``progress.in_flight``, in this run's plan, not yet
    completed, and past ``preflight``. A node checkpointed AT ``preflight``
    holds nothing (no stamp, no window, no cordon), so it waits its turn in
    plan order like any other."""
    entry = (progress or {}).get(IN_FLIGHT_KEY)
    if not isinstance(entry, dict):
        return None
    node = entry.get("node")
    if not isinstance(node, str) or node not in plan_order or node in completed_nodes:
        return None
    if per_node.resume_from_checkpoint(entry, node) is None:
        return None
    return node


def _checkpoint_writer(
    db: AsyncSession, run_id: uuid.UUID, holder: str | None
) -> per_node.Checkpoint:
    """Store the per-node chain's checkpoints on the run as
    ``progress.in_flight`` (#2809).

    One UPDATE merging the key into the stored JSON, never a write of the
    whole ``progress``: the drive's copy of the row is as it was when the
    node started, and writing it back would undo an operator's Halt event or
    a takeover's. Only while the run is still this drive's: after a takeover
    the other drive owns the checkpoint."""

    async def _write(entry: dict[str, Any]) -> None:
        stmt = (
            update(SystemUpgradeRun)
            .where(SystemUpgradeRun.id == run_id)
            .values(
                progress=SystemUpgradeRun.progress.op("||")(literal({IN_FLIGHT_KEY: entry}, JSONB))
            )
            .execution_options(synchronize_session=False)
        )
        if holder:
            stmt = stmt.where(SystemUpgradeRun.lease_holder == holder)
        await db.execute(stmt)
        await db.commit()

    return _write


async def _record_node_after_stop(
    db: AsyncSession,
    run: SystemUpgradeRun,
    node: str,
    entry: dict[str, Any],
    state: str,
) -> None:
    """A node ended after the operator had halted or aborted the run: keep
    what happened to it in ``progress.per_node`` and the events, but leave
    the operator's state alone (#1702). A halted run resumes from here."""
    per_node_progress = dict((run.progress or {}).get("per_node") or {})
    per_node_progress[node] = entry
    run.progress = {**_without_in_flight(run.progress), "per_node": per_node_progress}
    await _record_event(
        db,
        run,
        "node_ended_after_stop",
        node=node,
        ok=entry.get("ok"),
        failed_at=entry.get("failed_at"),
        run_state=state,
    )


async def _lease_renewal_loop(
    stop_event: asyncio.Event,
    holder: str,
    until: asyncio.Event | None = None,
    renewed_at: float | None = None,
    lease_ok: asyncio.Event | None = None,
) -> None:
    """Background task — renew the upgrade Lease every
    ``LEASE_DURATION_S / 3`` seconds until ``until`` is set (default:
    ``stop_event``).

    On a lost Lease (seen held by someone else, or gone, or a write refused
    with a conflict) we set ``stop_event`` so the main drive loop exits
    cleanly, and stop renewing. The drive loop checks ``stop_event`` between
    per-node iterations; we DON'T abort an in-flight per-node primitive
    because canceling a mid-drain / mid-cordon would leave the cluster in an
    ambiguous state. The next orchestrator that picks up the row resumes
    from the row's progress.

    #1713 — a renewal the kubeapi did not answer is UNKNOWN, not lost: the
    Lease is most likely still ours. ``lease_ok`` is cleared, which pauses
    the drive before its next node, and the renewal is retried every
    ``_LEASE_RENEW_RETRY_S``. Once ``_LEASE_SAFE_HOLD_S`` has passed since
    the last renewal that landed (measured from when that attempt STARTED,
    which is no later than the ``renewTime`` it wrote), the drive gives up:
    ``stop_event`` is set while the Lease is still unexpired for everyone
    else. With a separate ``until`` the retries go on after that, so a
    renewal that lands keeps the Lease ours while the node in flight
    finishes, and nothing else starts a drive beside it.
    """
    done = until or stop_event
    confirmed = _monotonic() if renewed_at is None else renewed_at
    gave_up = False
    wait_s = _LEASE_RENEW_INTERVAL_S
    while not done.is_set():
        try:
            await asyncio.wait_for(done.wait(), timeout=wait_s)
            return  # done during the wait
        except TimeoutError:
            pass
        attempt_started = _monotonic()
        try:
            ok, err = mutex.renew(holder=holder, lease_duration_seconds=LEASE_DURATION_S)
        except mutex.LeaseUnknownError as exc:
            if lease_ok is not None:
                lease_ok.clear()
            left = _LEASE_SAFE_HOLD_S - (_monotonic() - confirmed)
            if left > 0:
                logger.warning(
                    "upgrade_lease_renew_unanswered",
                    error=str(exc),
                    give_up_in_s=round(left, 1),
                )
                wait_s = min(_LEASE_RENEW_RETRY_S, left)
                continue
            if not gave_up:
                gave_up = True
                logger.warning("upgrade_lease_renew_failed", error=f"unanswered: {exc}")
                stop_event.set()
                if done is stop_event:
                    return
            wait_s = _LEASE_RENEW_RETRY_S
            continue
        except Exception as exc:  # noqa: BLE001 — any failure here means "not renewed"
            # An error the kubeapi helpers do not map (#1704) would end this
            # task silently, leaving the drive running on a Lease nothing
            # renews. Treat it as a lost Lease.
            logger.warning("upgrade_lease_renew_crashed", error=str(exc))
            if lease_ok is not None:
                lease_ok.clear()
            stop_event.set()
            return
        if not ok:
            logger.warning("upgrade_lease_renew_failed", error=err)
            if lease_ok is not None:
                lease_ok.clear()
            stop_event.set()
            return
        confirmed = attempt_started
        if lease_ok is not None:
            lease_ok.set()
        if gave_up:
            logger.info("upgrade_lease_renew_recovered")
        wait_s = _LEASE_RENEW_INTERVAL_S


async def drive_upgrade(
    db: AsyncSession,
    run_id: uuid.UUID,
    *,
    holder: str | None = None,
    avoid_version: str | None = None,
) -> SystemUpgradeRun:
    """Drive a planned / halted-and-resumed / partially-completed run
    through to terminal state.

    Idempotent + resumable: reading the row's ``progress.per_node`` map
    tells us which nodes are done; the rest get driven in plan order.

    Acquires the upgrade lease for the duration; spawns the renewal
    task; releases on terminal transition.

    ``holder`` is this drive's lease identity (default: a fresh
    ``mutex.drive_identity()``). The Celery task passes its own so that its
    crash handler can release the lease this drive took, and only that one
    (#1449, #1512).

    ``avoid_version`` is the version hand-off's request this drive carries,
    if any (#1710): set only on the continuation a drive sends once it has
    flipped the shared tags. A drive still on that old version without it
    does not take the handed-off run (#2869, ``_stray_after_version_handoff``).
    """
    # #1512 — the row under FOR UPDATE, re-read: two drives of one run (a
    # second Start, a second tab, Celery redelivery) used to both pass the
    # planned → running check on their own stale copies. The second now waits
    # here, then sees ``running`` and must win the lease to go on.
    run = (
        await db.execute(
            select(SystemUpgradeRun)
            .where(SystemUpgradeRun.id == run_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if run is None:
        raise OrchestratorError(f"upgrade run {run_id} not found")
    # One identity per drive, not per pod: a worker pod runs several tasks,
    # and a second task under the pod's name renewed the first one's lease
    # and ran a second drive loop beside it.
    me = holder or mutex.drive_identity()
    # #1713 — when this drive's Lease was last confirmed, from before the
    # acquire that writes its renewTime.
    acquire_started = _monotonic()
    if run.state == "planned":
        # First call — acquire the lease.
        ok, err = mutex.acquire(holder=me, lease_duration_seconds=LEASE_DURATION_S)
        if not ok:
            raise OrchestratorError(f"could not acquire upgrade lease: {err}")
        try:
            run.lease_holder = me
            run.lease_acquired_at = _now()
            await _transition(db, run, "running", allowed_from=("planned",), event="started")
            await db.commit()
        except BaseException:
            # The run never started, so nothing holds the lease for a reason:
            # left held, Celery's retry is refused it until it expires
            # (10 min), and an operator's next Start too (#1449).
            await db.rollback()
            mutex.release_if_held(holder=me)
            raise
        await db.refresh(run)
    elif run.state == "running":
        stray_of = _stray_after_version_handoff(run, avoid_version)
        if stray_of is not None:
            # #2869 — the run was handed to the new version and its Lease
            # released for that: not this drive's to take. The hand-off's own
            # continuation carries it; after a Resume, nothing else does, so
            # the Resume's drive goes on to the new version as that would.
            resumed = _resumed_since_version_handoff(run)
            if resumed:
                _enqueue_continuation(run.id, avoid_version=stray_of)
            logger.info(
                "upgrade_drive_stray_after_version_handoff",
                run_id=str(run.id),
                version=stray_of,
                holder=me,
                passed_on=resumed,
            )
            return run
        # Resume / re-enqueue path. A drive that is still alive holds the
        # lease under its own identity, so this one is refused; it takes over
        # only once that lease expired (the previous worker died) or was
        # released (a halt).
        ok, err = mutex.acquire(holder=me, lease_duration_seconds=LEASE_DURATION_S)
        if not ok:
            raise OrchestratorError(f"can't take over upgrade lease for resume: {err}")
        run.lease_holder = me
        run.lease_acquired_at = _now()
        await _record_event(db, run, "lease_takeover")
        await db.commit()
    else:
        # Terminal or halted — nothing to drive.
        return run

    stop_event = asyncio.Event()
    # The renewal outlives a give-up (#1713): it ends with the drive, so a
    # renewal that lands keeps the Lease while the node in flight finishes.
    renewal_done = asyncio.Event()
    lease_ok = asyncio.Event()
    lease_ok.set()
    renewal_task = asyncio.create_task(
        _lease_renewal_loop(stop_event, me, renewal_done, acquire_started, lease_ok)
    )
    try:
        await _drive_loop(db, run, stop_event, me, lease_ok=lease_ok)
    finally:
        stop_event.set()
        renewal_done.set()
        # Wait for the renewal loop to exit cleanly. The ``await`` IS
        # the side-effect — it blocks until the task finishes after
        # the ``stop_event.set()`` above. github-code-quality's
        # "Statement has no effect" check fires here as a false
        # positive (the check doesn't model ``await`` on a coroutine
        # / Task as effectful). Binding to ``_ = await renewal_task``
        # would silence it but trips mypy's ``func-returns-value``
        # since ``_lease_renewal_loop`` returns ``None`` — pick the
        # bare-await form because mypy is the gating CI check.
        await renewal_task

    await db.refresh(run)
    return run


async def _drive_loop(
    db: AsyncSession,
    run: SystemUpgradeRun,
    stop_event: asyncio.Event,
    holder: str | None = None,
    *,
    lease_ok: asyncio.Event | None = None,
) -> None:
    """The per-node iteration. Each cycle:

    * Refreshes the row (so operator halts land mid-loop).
    * Picks the next un-completed node from the plan.
    * Drives Phase C's ``single_node_upgrade`` for it.
    * On success: records progress + brief pause + cluster verify.
    * On failure: flips state to ``failed`` + halts.
    * On halt/abort signal: exits cleanly without further work.
    """
    plan_order: list[str] = run.plan.get("node_order") or []
    slot_image = SlotImageTarget.from_plan_fields(run.plan)
    cnpg_name: str = run.plan.get("cnpg_cluster_name") or ""
    cnpg_namespace: str | None = run.plan.get("cnpg_namespace")
    # #1463 — every node waits for this release's slot-image mirror before
    # it is told to fetch an uploaded image.
    release_name = run.plan.get("chart_name") or chart_bump.DEFAULT_CHART_NAME
    mirror_deployment = per_node.slot_image_mirror_deployment(release_name)
    # #1544 — the namespace the chart-bump poll reads the release's
    # Deployments in; the per-node control-plane gate reads the same one.
    release_namespace: str = run.plan.get("release_namespace") or chart_bump.DEFAULT_RELEASE_NS
    paused = False
    # When the shared-tag step now being tried first failed (None: it has not).
    shared_tag_failing_since: float | None = None

    while True:
        if stop_event.is_set():
            # Lease lost — leave the row in ``running``; the next
            # take-over will pick up. Don't flip to failed; that'd
            # mis-attribute a transient kubeapi blip as a real
            # upgrade failure.
            logger.warning("upgrade_drive_exit_lease_lost", run_id=str(_run_pk(run)))
            if holder and lease_ok is not None and lease_ok.is_set():
                # #1713 — the renewal gave up, then landed again while the
                # node in flight finished: the Lease is still this drive's.
                # Free it (only ours, as a compare-and-swap) so the orphan
                # sweep resumes the run now rather than after it lapses.
                mutex.release_if_held(holder=holder)
            return

        await db.refresh(run)
        if run.state in ("halted", "aborted", "succeeded", "failed"):
            logger.info(
                "upgrade_drive_exit_state",
                run_id=str(run.id),
                state=run.state,
            )
            # #1512 — give up the lease on a halt too, so Resume's drive (a
            # new identity) can take it at once instead of waiting out the
            # expiry. Only ours is released, retried like every other exit.
            _release_lease(run, holder)
            return
        if holder and run.lease_holder not in (None, holder):
            # A second drive took the Lease over (#1704): the run is its.
            logger.warning("upgrade_drive_exit_lease_taken", run_id=str(run.id))
            return
        if lease_ok is not None and not lease_ok.is_set():
            # #1713 — the last renewal went unanswered: the Lease is unknown,
            # so start nothing new (a node, a hand-off, the tag flip, the
            # chart bump) until one lands. The renewal sets ``stop_event``
            # before the Lease could lapse; re-checked every retry so a Halt
            # or Abort is still seen.
            if not paused:
                paused = True
                logger.warning("upgrade_drive_paused_lease_unknown", run_id=str(run.id))
            try:
                await asyncio.wait_for(lease_ok.wait(), timeout=_LEASE_RENEW_RETRY_S)
            except TimeoutError:
                pass  # still unknown: loop round to re-check Halt / Abort and the Lease
            continue
        if paused:
            paused = False
            # A step's time to keep failing counts only while it is tried.
            shared_tag_failing_since = None
            logger.info("upgrade_drive_resumed_lease_confirmed", run_id=str(run.id))

        per_node_progress = dict(run.progress.get("per_node") or {})
        completed_nodes = [
            name for name, entry in per_node_progress.items() if entry.get("ok") is True
        ]
        own_node = _own_node()
        next_node = node_order.next_node_to_upgrade(plan_order, completed_nodes, defer=own_node)
        # #2809 — a node an earlier drive was in the middle of comes first,
        # whatever the plan order and this worker's node say. It may be
        # stamped, cordoned, drained and in the CNPG window; starting another
        # node instead would run that node's preflight, whose CNPG wait
        # counts the instance the in-flight node's drain evicted, and a
        # failure there releases nothing the earlier drive took.
        in_flight = _in_flight_node(run.progress, plan_order, completed_nodes)
        if in_flight is not None:
            next_node = in_flight
        if next_node is not None and next_node == own_node and len(plan_order) > 1:
            # The node to drive is the one this worker runs on: every other
            # node is done, or it is the node in flight (#2809), which no
            # other node may start before. Draining it would evict this
            # drive mid-chain, and the run would sit in ``running`` with
            # nothing driving it until Celery redelivers the task an hour
            # later (#1449). Hand the drive to a worker on another node
            # instead: release the lease, enqueue the drive asking to be run
            # elsewhere, and stop.
            # The new drive takes the lease over and resumes at this node.
            why = await _fence(db, run, holder)
            if why is not None:
                await _bail(db, run, holder, why)
                return
            await _record_event(db, run, "drive_handoff", node=next_node)
            await db.commit()
            # Stop the renewal loop first. A renew after the release would
            # fail anyway (it re-reads the holder, #1512), but it would also
            # end this drive as "lease lost" instead of as a hand-off. The
            # release clears this drive's own identity only, as a
            # compare-and-swap, so the new drive's takeover is never undone.
            stop_event.set()
            _release_lease(run, holder)
            _enqueue_drive(run.id, avoid_node=own_node)
            logger.info("upgrade_drive_handoff", run_id=str(run.id), node=next_node)
            return
        if next_node is None and shared_tags.holds(run):
            # #1710 — every node reports the target: move the shared tags
            # once, then hand the rest to a worker on the target.
            untaken = await _finish_with_flip(
                db, run, stop_event, holder, cnpg_name=cnpg_name, cnpg_namespace=cnpg_namespace
            )
            if untaken is None:
                return
            # The kubeapi did not take the flip: pause, then try it again.
            shared_tag_failing_since = await _retry_shared_tag_step(
                db,
                run,
                holder,
                stop_event,
                failing_since=shared_tag_failing_since,
                step="shared_tag_flip",
                error=f"shared tag flip to {run.target_version} failed: {untaken.error}",
                event="chart_bump_failed",
                failed_at_step="chart_bump",
            )
            if shared_tag_failing_since is None:
                return
            continue
        if next_node is None:
            # Every node committed the new slot. Phase E — bump the
            # chart's image.tag so the api / worker / frontend
            # Deployments roll onto the new application code +
            # migrate Job runs against the new schema. Until this
            # fires, every pod is still on N-1 code despite N-baked
            # images sitting on every node's new slot. The bump is
            # idempotent so a resumed orchestrator (worker died
            # between the all-nodes-done state + the chart bump
            # completion) re-runs cleanly.
            why = await _fence(db, run, holder)
            if why is not None:
                await _bail(db, run, holder, why)
                return
            await _record_event(
                db,
                run,
                "all_nodes_complete",
                chart_bump_starting=True,
            )
            await db.commit()
            chart_name: str = run.plan.get("chart_name") or chart_bump.DEFAULT_CHART_NAME
            chart_ns: str = run.plan.get("chart_namespace") or chart_bump.DEFAULT_CHART_NS
            release_ns: str = run.plan.get("release_namespace") or chart_bump.DEFAULT_RELEASE_NS
            bump = await chart_bump.bump_chart_image_tag(
                run.target_version,
                chart_name=chart_name,
                chart_namespace=chart_ns,
                release_namespace=release_ns,
            )
            why = await _fence(db, run, holder)
            if why is not None:
                await _bail(db, run, holder, why)
                return
            run.progress = {
                **run.progress,
                "chart_bump": chart_bump.result_to_dict(bump),
            }
            if bump.ok:
                # Ends the fence's lock: the verify below waits (bounded)
                # on the cluster, and Halt / Abort must not wait on it.
                await db.commit()
            if not bump.ok:
                run.last_error = f"chart bump to {run.target_version} failed: {bump.error}"
                # Phase F — classify + fire the cluster-upgrade-failed
                # alert so the operator gets the same notification as
                # any other AlertRule firing rather than having to
                # poll ``GET /upgrades/runs``.
                category = upgrade_alerts.classify_per_node_failure(
                    failed_at="chart_bump", error=bump.error
                )
                await _transition(
                    db,
                    run,
                    "failed",
                    allowed_from=("running",),
                    event="chart_bump_failed",
                    error=bump.error,
                    failure_category=category,
                )
                await db.commit()
                # The alert is delivered (webhook / syslog / SMTP) after the commit
                # that ends the fence's lock, so Halt / Abort never wait on it.
                await upgrade_alerts.emit_upgrade_failed_alert(
                    db,
                    run,
                    failed_node=None,
                    failed_at_step="chart_bump",
                    category=category,
                )
                await db.commit()
                _release_lease(run, holder)
                logger.warning(
                    "upgrade_chart_bump_failed",
                    run_id=str(run.id),
                    error=bump.error,
                    category=category,
                )
                return

            # #296 Phase H — post-upgrade cluster verification. Runs
            # after the chart bump landed cleanly. Stamps results
            # into ``progress.post_upgrade_verify`` so the Fleet UI
            # can render a checklist; a ``fail`` aggregates to
            # ``state='failed'`` so a flaky cluster shape (CNPG
            # instance count, DS pods NotReady cluster-wide) doesn't
            # silently report success. The per-node chain already waited
            # for the CNPG count after each node's uncordon, the last
            # node's included (#1544, ``cluster_verify``); this re-confirms
            # it after the chart bump rolled the control-plane Deployments,
            # waiting (bounded) for an instance still rejoining (#1829).
            verify_results = await safety.verify_post_upgrade(
                cnpg_cluster_name=cnpg_name,
                cnpg_namespace=cnpg_namespace,
            )
            verify_overall = safety.verification_overall(verify_results)
            why = await _fence(db, run, holder, carry=("chart_bump",))
            if why is not None:
                await _bail(db, run, holder, why)
                return
            run.progress = {
                **run.progress,
                "post_upgrade_verify": {
                    "overall": verify_overall,
                    "results": [
                        {
                            "name": r.name,
                            "level": r.level,
                            "message": r.message,
                            "detail": r.detail,
                        }
                        for r in verify_results
                    ],
                },
            }
            if verify_overall == "fail":
                fails = [r.name for r in verify_results if r.level == "fail"]
                run.last_error = f"post-upgrade verification failed: {', '.join(fails)}"
                await _transition(
                    db,
                    run,
                    "failed",
                    allowed_from=("running",),
                    event="post_upgrade_verify_failed",
                    failed_checks=fails,
                )
                await db.commit()
                # The alert is delivered (webhook / syslog / SMTP) after the commit
                # that ends the fence's lock, so Halt / Abort never wait on it.
                await upgrade_alerts.emit_upgrade_failed_alert(
                    db,
                    run,
                    failed_node=None,
                    failed_at_step="post_upgrade_verify",
                    category=upgrade_alerts.CATEGORY_OTHER,
                )
                await db.commit()
                _release_lease(run, holder)
                logger.warning(
                    "upgrade_post_verify_failed",
                    run_id=str(run.id),
                    failed_checks=fails,
                )
                return

            await _transition(
                db,
                run,
                "succeeded",
                allowed_from=("running",),
                event="succeeded",
                rolled_deployments=bump.rolled_deployments,
                migrate_job_state=bump.migrate_job_state,
                skipped=bump.skipped,
                post_upgrade_verify=verify_overall,
            )
            await db.commit()
            _release_lease(run, holder)
            logger.info(
                "upgrade_succeeded",
                run_id=str(run.id),
                rolled=bump.rolled_deployments,
                post_upgrade_verify=verify_overall,
            )
            return

        # #1710 — hold the shared charts' image tag at the running version
        # before the first node boots the new slot, and re-assert it before
        # every node after.
        hold = await shared_tags.ensure_hold(db, run)
        if not hold.ok and hold.retryable:
            # The kubeapi did not take the hold: pause, then try it again from
            # the loop top, after Halt, Abort and the Lease. No node starts
            # with the shared tags free to move.
            shared_tag_failing_since = await _retry_shared_tag_step(
                db,
                run,
                holder,
                stop_event,
                failing_since=shared_tag_failing_since,
                step="shared_tag_hold",
                error=f"could not hold the shared charts' image tag: {hold.error}",
                event="shared_tag_hold_failed",
                failed_at_step="shared_tag_hold",
            )
            if shared_tag_failing_since is None:
                return
            continue
        if not hold.ok:
            await _fail_at_shared_tags(
                db,
                run,
                holder,
                event="shared_tag_hold_failed",
                failed_at_step="shared_tag_hold",
                error=f"could not hold the shared charts' image tag: {hold.error}",
            )
            return
        shared_tag_failing_since = None
        # The hold went to the kubeapi: re-read before writing it and the
        # node's start, so a Halt or Abort that landed meanwhile is neither
        # overwritten nor followed by a node it was meant to stop (#1702).
        # The hold's record is kept either way; the pins are on the charts.
        why = await _fence(db, run, holder, carry=(shared_tags.PROGRESS_KEY,))
        if why is not None:
            await _bail(db, run, holder, why)
            return

        # Drive Phase C for this node. #2809 — a node an earlier drive was in
        # the middle of resumes at the step it was in, not at ``preflight``:
        # by then it may be cordoned and drained, and the preflight's CNPG
        # wait would wait for the instance that drain evicted.
        resume = per_node.resume_from_checkpoint((run.progress or {}).get(IN_FLIGHT_KEY), next_node)
        if resume is not None:
            await _record_event(db, run, "node_started", node=next_node, resumed_at=resume.step)
            logger.info(
                "upgrade_node_resumed", run_id=str(run.id), node=next_node, step=resume.step
            )
        else:
            await _record_event(db, run, "node_started", node=next_node)
        await db.commit()
        result = await per_node.single_node_upgrade(
            db,
            node_name=next_node,
            target_version=run.target_version,
            slot_image=slot_image,
            cnpg_cluster_name=cnpg_name,
            cnpg_namespace=cnpg_namespace,
            lease_holder=run.lease_holder,
            mirror_deployment=mirror_deployment,
            control_plane_release=release_name,
            control_plane_namespace=release_namespace,
            # #1709 — the node's preflight asks for /var room only on the
            # nodes the run has still to upgrade. #2870 — in DRAIN order (this
            # node first, the drive's own node last), which the Redis master
            # move uses to pick the replica that drains last.
            remaining_nodes=node_order.drain_order(
                plan_order, completed_nodes, current=next_node, defer=own_node
            ),
            resume=resume,
            checkpoint=_checkpoint_writer(db, run.id, holder),
        )

        per_node_progress[next_node] = {
            "ok": result.ok,
            "failed_at": result.failed_at,
            "error": result.error,
            **({"resumed_at": resume.step} if resume is not None else {}),
            "steps": [
                {
                    "name": s.name,
                    "ok": s.ok,
                    "started_at": s.started_at,
                    "finished_at": s.finished_at,
                    "detail": s.detail,
                    "error": s.error,
                }
                for s in result.steps
            ],
        }
        # The node took minutes to hours; the row this drive holds is as it
        # was at the loop top. Re-read it, and write the node's outcome only
        # if the run is still this drive's and still running (#1702, #1704).
        why = await _fence(db, run, holder)
        if why is not None:
            if why in ("halted", "aborted"):
                await _record_node_after_stop(db, run, next_node, per_node_progress[next_node], why)
            await _bail(db, run, holder, why)
            return
        per_node_progress = {
            **dict(run.progress.get("per_node") or {}),
            next_node: per_node_progress[next_node],
        }
        run.progress = {**_without_in_flight(run.progress), "per_node": per_node_progress}

        if not result.ok:
            run.last_error = (
                f"node {next_node} failed at step {result.failed_at}: " f"{result.error}"
            )
            # Phase F — classify the per-node failure so the alert
            # body + ``progress.per_node[<node>].failure_category``
            # can hint at the right operator action (drain stuck vs
            # auto-revert vs dead-node replacement).
            category = upgrade_alerts.classify_per_node_failure(
                failed_at=result.failed_at, error=result.error
            )
            # #1542 — the compensating release failed too: the node is left
            # cordoned and/or the CNPG window on. Worse than the original
            # failure, so it gets its own category + alert text naming what
            # is stuck. The run still stops.
            stuck: list[str] | None = None
            release_failed = upgrade_alerts.release_failure(result.steps)
            if release_failed is not None:
                release_error, stuck = release_failed
                underlying_category = category
                category = upgrade_alerts.CATEGORY_RELEASE_FAILED
                run.last_error = (
                    f"{run.last_error}; release of node {next_node} failed "
                    f"(still held: {', '.join(stuck) or 'unknown'}): {release_error}"
                )
                per_node_progress[next_node]["release_failed"] = {
                    "error": release_error,
                    "stuck": stuck,
                    # What the step failure would have been classified as,
                    # so the original cause survives the override.
                    "underlying_category": underlying_category,
                }
            per_node_progress[next_node]["failure_category"] = category
            run.progress = {**run.progress, "per_node": per_node_progress}
            await _transition(
                db,
                run,
                "failed",
                allowed_from=("running",),
                event="node_failed",
                node=next_node,
                failed_at=result.failed_at,
                failure_category=category,
            )
            await db.commit()
            # The alert is delivered (webhook / syslog / SMTP) after the commit
            # that ends the fence's lock, so Halt / Abort never wait on it.
            await upgrade_alerts.emit_upgrade_failed_alert(
                db,
                run,
                failed_node=next_node,
                failed_at_step=result.failed_at,
                category=category,
                stuck=stuck,
            )
            await db.commit()
            _release_lease(run, holder)
            logger.warning(
                "upgrade_failed",
                run_id=str(run.id),
                node=next_node,
                failed_at=result.failed_at,
                category=category,
            )
            return

        # Success — log + brief settle pause before next node.
        await _record_event(db, run, "node_succeeded", node=next_node)
        await db.commit()
        logger.info("upgrade_node_complete", run_id=str(run.id), node=next_node)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=_BETWEEN_NODES_PAUSE_S)
            # stop_event fired during the pause — loop will exit.
        except TimeoutError:
            # Expected fall-through: the pause is a settle interval
            # between nodes, not a wait-for-stop. Timeout means no
            # halt/abort arrived during the window — proceed to the
            # next node on the next loop iteration. No log so we
            # don't add a line on every healthy between-node tick.
            pass


# ── #1710: the end of a run that held the shared tags ────────────────


async def _fail_at_shared_tags(
    db: AsyncSession,
    run: SystemUpgradeRun,
    holder: str | None,
    *,
    event: str,
    failed_at_step: str,
    error: str | None,
) -> None:
    """Fail the run at a shared-tag step, alert, and release the lease.

    The hold is left as it is: nodes on two versions are what it protects,
    and the next run's Start (or the beat task, once every node reports one
    version) takes it from here."""
    why = await _fence(db, run, holder, carry=(shared_tags.PROGRESS_KEY,))
    if why is not None:
        await _bail(db, run, holder, why)
        return
    run.last_error = error
    category = upgrade_alerts.classify_per_node_failure(failed_at=failed_at_step, error=error)
    await _transition(
        db,
        run,
        "failed",
        allowed_from=("running",),
        event=event,
        error=error,
        failure_category=category,
    )
    await db.commit()
    # The alert is delivered (webhook / syslog / SMTP) after the commit
    # that ends the fence's lock, so Halt / Abort never wait on it.
    await upgrade_alerts.emit_upgrade_failed_alert(
        db,
        run,
        failed_node=None,
        failed_at_step=failed_at_step,
        category=category,
    )
    await db.commit()
    _release_lease(run, holder)
    logger.warning(
        "upgrade_shared_tags_failed",
        run_id=str(run.id),
        step=failed_at_step,
        error=error,
        category=category,
    )


async def _retry_shared_tag_step(
    db: AsyncSession,
    run: SystemUpgradeRun,
    holder: str | None,
    stop_event: asyncio.Event,
    *,
    failing_since: float | None,
    step: str,
    error: str,
    event: str,
    failed_at_step: str,
) -> float | None:
    """A shared-tag step the kubeapi did not take: wait, so the drive tries
    it again from its loop top, where Halt, Abort and the Lease (#1713) are
    read first; or, once it has kept failing for ``_SHARED_TAG_RETRY_FOR_S``,
    fail the run on it with ``event``, as before.

    Returns when the step's failures began, for the next try, or None when
    the drive must stop (the run failed, or it is no longer this drive's).
    The hold's record is committed before the wait: its pins may be half on,
    and whoever ends the hold finds them by it."""
    now = _monotonic()
    if failing_since is not None and now - failing_since >= _SHARED_TAG_RETRY_FOR_S:
        await _fail_at_shared_tags(
            db,
            run,
            holder,
            event=event,
            failed_at_step=failed_at_step,
            error=f"{error} (still failing after {int(now - failing_since)} s)",
        )
        return None
    why = await _fence(db, run, holder, carry=(shared_tags.PROGRESS_KEY,))
    if why is not None:
        await _bail(db, run, holder, why)
        return None
    if failing_since is None:
        await _record_event(db, run, "shared_tag_step_retrying", step=step, error=error)
    await db.commit()
    logger.warning(
        "upgrade_shared_tag_step_retrying",
        run_id=str(run.id),
        step=step,
        error=error,
        retry_in_s=_SHARED_TAG_RETRY_S,
    )
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=_SHARED_TAG_RETRY_S)
    except TimeoutError:
        pass  # the loop top reads Halt / Abort and the Lease, then tries again
    return now if failing_since is None else failing_since


async def _finish_with_flip(
    db: AsyncSession,
    run: SystemUpgradeRun,
    stop_event: asyncio.Event,
    holder: str | None,
    *,
    cnpg_name: str,
    cnpg_namespace: str | None,
) -> shared_tags.StepOutcome | None:
    """Phase E of a run that held the shared tags (#1710, #1829).

    1. The flip: the run's last change to the cluster (the pins come off,
       the supervisors are freed to write the appliance chart).
    2. The flip rolls the worker this drive runs on, so a drive still on the
       old tag hands the rest to a worker on the new one, once, and stops.
       A drive that is killed anyway is redelivered and resumes here: the
       flip is recorded, so it is not repeated.
    3. Wait for every workload the flip moves, then the post-upgrade verify.

    Returns the flip's outcome when the kubeapi did not take it, for the
    drive to try again; None once the drive is done here, whatever the end.
    """
    record = shared_tags.record_of(run)
    from_tag = str(record.get("from_tag") or "")
    if shared_tags.flip_record(run).get("state") not in (
        shared_tags.FLIP_FLIPPED,
        shared_tags.FLIP_SETTLED,
    ):
        why = await _fence(db, run, holder)
        if why is not None:
            await _bail(db, run, holder, why)
            return None
        events = (run.progress or {}).get("events") or []
        if not any(e.get("event") == "all_nodes_complete" for e in events):
            # Once: a flip tried again (#2028), whether it failed before or
            # after it recorded its snapshot, or one a redelivered drive
            # resumes, has announced the end of the roll already.
            await _record_event(db, run, "all_nodes_complete", shared_tag_flip_starting=True)
        await db.commit()
        flipped = await shared_tags.flip(db, run)
        if not flipped.ok and flipped.retryable:
            return flipped
        if not flipped.ok:
            await _fail_at_shared_tags(
                db,
                run,
                holder,
                event="chart_bump_failed",
                failed_at_step="chart_bump",
                error=f"shared tag flip to {run.target_version} failed: {flipped.error}",
            )
            return None
        # The flip committed its own record (a locked merge); the run may
        # have been stopped while it talked to the kubeapi.
        why = await _fence(db, run, holder)
        if why is not None:
            await _bail(db, run, holder, why)
            return None
        await _record_event(
            db, run, "shared_tags_flipped", from_tag=from_tag, to_tag=run.target_version
        )
        await db.commit()

    flip_rec = shared_tags.flip_record(run)
    if from_tag and settings.version == from_tag and not flip_rec.get("handed_off_at"):
        # A Halt or Abort ends the run here instead: no continuation.
        why = await _fence(db, run, holder)
        if why is not None:
            await _bail(db, run, holder, why)
            return None
        flip_rec = shared_tags.flip_record(run)
        record = shared_tags.record_of(run)
        record["flip"] = {**flip_rec, "handed_off_at": _now().isoformat()}
        run.progress = {**run.progress, shared_tags.PROGRESS_KEY: record}
        await _record_event(db, run, "drive_version_handoff", from_tag=from_tag)
        await db.commit()
        # As the node hand-off: stop renewing, release this drive's lease,
        # and let the new drive take it over.
        stop_event.set()
        _release_lease(run, holder)
        _enqueue_continuation(run.id, avoid_version=from_tag)
        logger.info("upgrade_drive_version_handoff", run_id=str(run.id), from_tag=from_tag)
        return None

    settled = await shared_tags.settle(db, run)
    # The settle wait is long: the run may have been stopped meanwhile.
    why = await _fence(db, run, holder, carry=(shared_tags.PROGRESS_KEY,))
    if why is not None:
        await _bail(db, run, holder, why)
        return None
    await db.commit()
    if not settled.ok:
        await _fail_at_shared_tags(
            db,
            run,
            holder,
            event="chart_bump_failed",
            failed_at_step="chart_bump",
            error=f"the shared tag flip to {run.target_version} did not settle: {settled.error}",
        )
        return None

    verify_results = await safety.verify_post_upgrade(
        cnpg_cluster_name=cnpg_name,
        cnpg_namespace=cnpg_namespace,
    )
    verify_overall = safety.verification_overall(verify_results)
    why = await _fence(db, run, holder)
    if why is not None:
        await _bail(db, run, holder, why)
        return None
    run.progress = {
        **run.progress,
        "post_upgrade_verify": {
            "overall": verify_overall,
            "results": [
                {"name": r.name, "level": r.level, "message": r.message, "detail": r.detail}
                for r in verify_results
            ],
        },
    }
    if verify_overall == "fail":
        fails = [r.name for r in verify_results if r.level == "fail"]
        run.last_error = f"post-upgrade verification failed: {', '.join(fails)}"
        await _transition(
            db,
            run,
            "failed",
            allowed_from=("running",),
            event="post_upgrade_verify_failed",
            failed_checks=fails,
        )
        await db.commit()
        # The alert is delivered (webhook / syslog / SMTP) after the commit
        # that ends the fence's lock, so Halt / Abort never wait on it.
        await upgrade_alerts.emit_upgrade_failed_alert(
            db,
            run,
            failed_node=None,
            failed_at_step="post_upgrade_verify",
            category=upgrade_alerts.CATEGORY_OTHER,
        )
        await db.commit()
        _release_lease(run, holder)
        logger.warning("upgrade_post_verify_failed", run_id=str(run.id), failed_checks=fails)
        return None

    rolled = list(settled.detail.get("rolled") or [])
    await _transition(
        db,
        run,
        "succeeded",
        allowed_from=("running",),
        event="succeeded",
        shared_tags_rolled=rolled,
        post_upgrade_verify=verify_overall,
    )
    await db.commit()
    _release_lease(run, holder)
    logger.info(
        "upgrade_succeeded",
        run_id=str(run.id),
        rolled=rolled,
        post_upgrade_verify=verify_overall,
    )
    return None
