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
incomplete node is driven.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
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
    mutex,
    node_order,
    per_node,
    preflight,
    safety,
)

logger = structlog.get_logger(__name__)

# The audit actor for the orchestrator's own transitions (started, node_failed,
# succeeded, chart_bump_failed, post_upgrade_verify_failed), which no operator
# drives. ``audit_log.user_display_name`` is NOT NULL.
SYSTEM_ACTOR = "system:upgrade-orchestrator"


def detect_cnpg_cluster_name(namespace: str | None = None) -> str:
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
        return ""
    return candidate if status == 200 else ""


# Lease duration for orchestrator runs — much longer than the 60 s
# default that suits read-only mutex.get_state() calls. A single
# node's health-gate step can spend ~30 min waiting on a slot dd +
# reboot + firstboot; the renewal loop renews every
# ``LEASE_DURATION_S / 3`` so two missed renewals still leave time
# before expiration.
LEASE_DURATION_S = 600  # 10 min
_LEASE_RENEW_INTERVAL_S = LEASE_DURATION_S / 3.0


# When the per-node primitive succeeds the orchestrator gates the next
# node's start on a short cluster-wide health check + this minimum
# pause so the previous node's services have time to fully resync (DS
# bundle warm-up, CNPG replica streaming catches up).
_BETWEEN_NODES_PAUSE_S = 10.0


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
        cnpg_cluster_name = detect_cnpg_cluster_name(cnpg_namespace)
        if cnpg_cluster_name:
            logger.info("upgrade_plan_cnpg_cluster_detected", cluster=cnpg_cluster_name)

    # Preflight gate.
    report = await preflight.run_all(target_version=target_version)
    if report.overall == "fail":
        fails = [r.name for r in report.results if r.level == "fail"]
        raise OrchestratorError(f"preflight failed; refusing to plan: {', '.join(fails)}")

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
        status, items = k8s.list_nodes(label_selector="spatium.io/role=appliance")
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

    source_versions: dict[str, str | None] = {}
    appliance_rows = (
        await db.execute(
            select(Appliance.hostname, Appliance.installed_appliance_version).where(
                Appliance.hostname.in_(order)
            )
        )
    ).all()
    for hostname, installed in appliance_rows:
        source_versions[hostname] = installed

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
    run = await get_run(db, run_id)
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
    run = await get_run(db, run_id)
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
    run = await get_run(db, run_id)
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
    # Release the lease so a new run can plan immediately.
    ok, err = mutex.release()
    if not ok:
        logger.warning("upgrade_lease_release_failed", error=err)
    await db.refresh(run)
    return run


# ── drive_upgrade — the actual orchestration loop ────────────────────


async def _lease_renewal_loop(stop_event: asyncio.Event) -> None:
    """Background task — renew the upgrade Lease every
    ``LEASE_DURATION_S / 3`` seconds until ``stop_event`` is set.

    On renewal failure (someone else claimed the lease, or kubeapi
    transient) we set ``stop_event`` so the main drive loop exits
    cleanly. The drive loop checks ``stop_event`` between per-node
    iterations; we DON'T abort an in-flight per-node primitive
    because canceling a mid-drain / mid-cordon would leave the
    cluster in an ambiguous state. The next orchestrator that picks
    up the row resumes from the row's progress.
    """
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=_LEASE_RENEW_INTERVAL_S)
            return  # stop_event set during the wait
        except TimeoutError:
            pass
        ok, err = mutex.renew(lease_duration_seconds=LEASE_DURATION_S)
        if not ok:
            logger.warning("upgrade_lease_renew_failed", error=err)
            stop_event.set()
            return


async def drive_upgrade(
    db: AsyncSession,
    run_id: uuid.UUID,
) -> SystemUpgradeRun:
    """Drive a planned / halted-and-resumed / partially-completed run
    through to terminal state.

    Idempotent + resumable: reading the row's ``progress.per_node`` map
    tells us which nodes are done; the rest get driven in plan order.

    Acquires the upgrade lease for the duration; spawns the renewal
    task; releases on terminal transition.
    """
    run = await get_run(db, run_id)
    if run.state == "planned":
        # First call — acquire the lease.
        ok, err = mutex.acquire(lease_duration_seconds=LEASE_DURATION_S)
        if not ok:
            raise OrchestratorError(f"could not acquire upgrade lease: {err}")
        try:
            run.lease_holder = mutex._identity()  # noqa: SLF001 — same module family
            run.lease_acquired_at = _now()
            await _transition(db, run, "running", allowed_from=("planned",), event="started")
            await db.commit()
        except BaseException:
            # The run never started, so nothing holds the lease for a reason:
            # left held, Celery's retry is refused it until it expires
            # (10 min), and an operator's next Start too (#1449).
            await db.rollback()
            mutex.release_if_held()
            raise
        await db.refresh(run)
    elif run.state == "running":
        # Resume / re-enqueue path — confirm we still hold the lease,
        # taking over if it expired (the previous celery worker died).
        ok, err = mutex.acquire(lease_duration_seconds=LEASE_DURATION_S)
        if not ok:
            raise OrchestratorError(f"can't take over upgrade lease for resume: {err}")
        if run.lease_holder != mutex._identity():  # noqa: SLF001
            run.lease_holder = mutex._identity()  # noqa: SLF001
            run.lease_acquired_at = _now()
            await _record_event(db, run, "lease_takeover")
            await db.commit()
    else:
        # Terminal or halted — nothing to drive.
        return run

    stop_event = asyncio.Event()
    renewal_task = asyncio.create_task(_lease_renewal_loop(stop_event))
    try:
        await _drive_loop(db, run, stop_event)
    finally:
        stop_event.set()
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

    while True:
        if stop_event.is_set():
            # Lease lost — leave the row in ``running``; the next
            # take-over will pick up. Don't flip to failed; that'd
            # mis-attribute a transient kubeapi blip as a real
            # upgrade failure.
            logger.warning("upgrade_drive_exit_lease_lost", run_id=str(run.id))
            return

        await db.refresh(run)
        if run.state in ("halted", "aborted", "succeeded", "failed"):
            logger.info(
                "upgrade_drive_exit_state",
                run_id=str(run.id),
                state=run.state,
            )
            return

        per_node_progress = dict(run.progress.get("per_node") or {})
        completed_nodes = [
            name for name, entry in per_node_progress.items() if entry.get("ok") is True
        ]
        next_node = node_order.next_node_to_upgrade(plan_order, completed_nodes)
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
            run.progress = {
                **run.progress,
                "chart_bump": chart_bump.result_to_dict(bump),
            }
            if not bump.ok:
                run.last_error = f"chart bump to {run.target_version} failed: {bump.error}"
                # Phase F — classify + fire the cluster-upgrade-failed
                # alert so the operator gets the same notification as
                # any other AlertRule firing rather than having to
                # poll ``GET /upgrades/runs``.
                category = upgrade_alerts.classify_per_node_failure(
                    failed_at="chart_bump", error=bump.error
                )
                await upgrade_alerts.emit_upgrade_failed_alert(
                    db,
                    run,
                    failed_node=None,
                    failed_at_step="chart_bump",
                    category=category,
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
                ok, err = mutex.release()
                if not ok:
                    logger.warning("upgrade_lease_release_failed", error=err)
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
            # silently report success.
            verify_results = await safety.verify_post_upgrade(
                cnpg_cluster_name=cnpg_name,
                cnpg_namespace=cnpg_namespace,
            )
            verify_overall = safety.verification_overall(verify_results)
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
                await upgrade_alerts.emit_upgrade_failed_alert(
                    db,
                    run,
                    failed_node=None,
                    failed_at_step="post_upgrade_verify",
                    category=upgrade_alerts.CATEGORY_OTHER,
                )
                await _transition(
                    db,
                    run,
                    "failed",
                    allowed_from=("running",),
                    event="post_upgrade_verify_failed",
                    failed_checks=fails,
                )
                await db.commit()
                ok, err = mutex.release()
                if not ok:
                    logger.warning("upgrade_lease_release_failed", error=err)
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
            ok, err = mutex.release()
            if not ok:
                logger.warning("upgrade_lease_release_failed", error=err)
            logger.info(
                "upgrade_succeeded",
                run_id=str(run.id),
                rolled=bump.rolled_deployments,
                post_upgrade_verify=verify_overall,
            )
            return

        # Drive Phase C for this node.
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
        )

        per_node_progress[next_node] = {
            "ok": result.ok,
            "failed_at": result.failed_at,
            "error": result.error,
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
        run.progress = {**run.progress, "per_node": per_node_progress}

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
            per_node_progress[next_node]["failure_category"] = category
            run.progress = {**run.progress, "per_node": per_node_progress}
            await upgrade_alerts.emit_upgrade_failed_alert(
                db,
                run,
                failed_node=next_node,
                failed_at_step=result.failed_at,
                category=category,
            )
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
            ok, err = mutex.release()
            if not ok:
                logger.warning("upgrade_lease_release_failed", error=err)
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
