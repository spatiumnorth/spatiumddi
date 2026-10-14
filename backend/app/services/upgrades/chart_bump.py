"""Post-rolling-upgrade chart/app version bump (#296 Phase E).

The orchestrator's ``_drive_loop`` calls ``bump_chart_image_tag``
after every node has committed the new slot. Until this fires, every
api / worker / frontend Deployment pod runs the **old** application
image — the new images are baked into each node's new slot but the
chart's ``image.tag`` still points at the old version. This module
mutates the k3s HelmChartConfig that the supervisor + the firstboot
manifests collaborate on, which the helm-controller reacts to by
running ``helm upgrade`` → Deployments roll + migrate Job re-runs.

Q1 decision (one artifact, decouple in time): the slot image carries
both OS + app, but the application-tier rollout is held until every
node is on the new slot. That way:

* Pre-bump: chart tag = N-1; every api pod runs N-1 code; nodes are
  a mix of N-1 + N at the OS layer but irrelevant for the app.
* All nodes on new slot, no chart bump yet: still N-1 code on every
  pod, just sitting on N-baked-image nodes. Safe.
* Bump fires: helm-controller rolls Deployments. RollingUpdate
  strategy means N-1 + N pods coexist for the duration of the roll
  — the **mixed-version window**. Q2's expand/contract migration
  contract makes this safe because every shipped migration is
  backward-compatible with N-1 code.
* Post-bump: every pod on N; migrate Job has run; window closed.

What this module does NOT do:

* Roll back on Deployment failure. If the helm upgrade trips an
  ImagePullBackOff or the migrate Job fails, the orchestrator flips
  the run to ``state='failed'`` + the operator owns recovery (helm
  rollback / debug). Auto-rollback would mean the operator's chart
  customisations get undone every time something hiccups; the issue
  body's "forward-fix policy" decision applies here.
* Reconcile rouge HelmChartConfig writes from other operators.  We
  parse-modify-dump the existing valuesContent so supervisor-written
  cp-size / VIP overrides survive; the orchestrator owns just the
  ``image.tag`` key.
* Mirror to docker-compose deployments — chart-bump is k3s-specific.
  Docker-compose operators run ``docker compose pull && up -d``
  manually (the existing Releases tab's manual-upgrade modal).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import structlog
import yaml

from app.services.appliance import k8s
from app.services.upgrades.shared_tags import carries_tag

logger = structlog.get_logger(__name__)


# Names + namespaces match the appliance shape. ``spatium-control`` is
# the umbrella HelmChart the supervisor + firstboot manifests already
# own; ``spatium`` is the release namespace; ``kube-system`` is where
# k3s helm-controller watches HelmChartConfigs.
DEFAULT_CHART_NAME = "spatium-control"
DEFAULT_CHART_NS = "kube-system"
DEFAULT_RELEASE_NS = "spatium"


# Settled-state poll cadence + budgets.  Helm-controller takes ~10-30s
# to notice a HelmChartConfig change + run ``helm upgrade``; the
# rolling Deployment update typically lands in 30-90s per service;
# migrate Job runs in ~10-60s. 30 min total budget leaves room for a
# slow image pull / Postgres-side migration step.
_POLL_INTERVAL_S = 5.0
DEFAULT_BUMP_TIMEOUT_S = 1800.0


@dataclass
class ChartBumpResult:
    """Outcome of one chart bump — captured into the SystemUpgradeRun
    row's ``progress.chart_bump`` blob so the operator-facing UI can
    show how the mixed-version window opened + closed."""

    ok: bool
    new_tag: str
    chart_name: str
    namespace: str
    started_at: str
    finished_at: str | None = None
    rolled_deployments: list[str] | None = None
    migrate_job_state: str | None = None
    error: str | None = None
    skipped: bool = False
    skip_reason: str | None = None


def _now_iso() -> str:
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── valuesContent parse-modify-dump ──────────────────────────────────


def _patch_image_tag(values_yaml: str, new_tag: str) -> str:
    """Take the existing HelmChartConfig.valuesContent + return a new
    string with ``image.tag`` set to ``new_tag``.

    Preserves every other top-level + nested key in the YAML — the
    supervisor's cp-size / VIP / MetalLB overrides stay intact; only
    ``image.tag`` gets stamped. An empty / missing ``image`` block is
    created.

    Returns the **original** ``values_yaml`` unchanged when ``image.tag``
    is already ``new_tag``. The Copilot review caught a real issue
    here: ``yaml.safe_dump(sort_keys=True)`` rewrites key order, so
    even a no-op call (already-current tag) used to produce a different
    string than the input + the upsert's idempotent-check then
    triggered a spurious HelmChartConfig PATCH → helm-controller
    re-applies the chart → Deployments roll for no reason. The
    no-op short-circuit avoids that.

    YAML parse failures fall back to writing a minimal fresh document
    rather than crashing — a previous operator's hand-edit shouldn't
    block the rolling-upgrade chart bump.
    """
    try:
        doc = yaml.safe_load(values_yaml) if values_yaml.strip() else None
    except yaml.YAMLError:
        doc = None
    if not isinstance(doc, dict):
        doc = {}
    image_block = doc.get("image")
    # No-op short-circuit — if image.tag is already current AND the
    # image block is a dict (well-formed YAML), return the input
    # unchanged so the upsert's idempotent compare in
    # ``k8s.upsert_helmchartconfig`` sees the current valuesContent
    # equals the desired one + skips the PATCH.
    if isinstance(image_block, dict) and image_block.get("tag") == new_tag:
        return values_yaml
    if not isinstance(image_block, dict):
        image_block = {}
    image_block["tag"] = new_tag
    doc["image"] = image_block
    # Stable key order so two clean rewrites produce byte-identical
    # output. We only reach this path when the value actually needs to
    # change; the no-op case above protects the byte-stable-on-no-
    # change invariant.
    return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False)


# ── Settled-state polling ────────────────────────────────────────────


async def _wait_for_deployments_rolled(
    names: list[str],
    namespace: str,
    *,
    new_tag: str,
    stop_after_monotonic: float,
) -> tuple[bool, list[str], str | None]:
    """Poll each Deployment until it has rolled onto ``new_tag``. Returns
    ``(ok, rolled_names, error)``.

    #1829 — a Deployment counts only once its pod template runs ``new_tag``
    AND ``deployment_is_rolled_out`` holds for that template. The status
    alone is not enough: read before helm-controller re-rendered the
    Deployment, it is the old template's, long complete, and the bump
    reported the control plane rolled 32 s before its new ReplicaSets
    existed. A kubeapi error is retried until the deadline.

    A 404 on a name is treated as success — the operator may have
    customised the chart to drop one of the standard Deployments
    (e.g. plain-k8s install without the beat sidecar). We don't
    fail-loud on shapes we don't recognise.
    """
    rolled: list[str] = []
    remaining = set(names)
    last_error: str | None = None
    while remaining and time.monotonic() < stop_after_monotonic:
        for name in sorted(remaining):
            try:
                status, body = k8s.get_deployment(name, namespace=namespace)
            except k8s.KubeapiUnavailableError as exc:
                last_error = f"kubeapi unreachable: {exc}"
                break
            if status == 404:
                remaining.discard(name)
                continue
            if status != 200 or body is None:
                continue
            if carries_tag(body, new_tag) and k8s.deployment_is_rolled_out(body):
                rolled.append(name)
                remaining.discard(name)
        if remaining:
            await asyncio.sleep(_POLL_INTERVAL_S)
    if remaining:
        error = f"timed out waiting for {new_tag} on: {', '.join(sorted(remaining))}"
        if last_error:
            error = f"{error} (last kubeapi error: {last_error})"
        return False, rolled, error
    return True, rolled, None


def _newest_migrate_job(
    release: str, namespace: str, new_tag: str
) -> tuple[str | None, dict[str, Any] | None]:
    """The newest migrate Job of ``release`` whose pod template runs
    ``new_tag``, as ``(name, job)``, or ``(None, None)``.

    The chart names the Job ``<release>-migrate-r<revision>`` (a new name on
    every helm upgrade, migrate-job.yaml), so it is found by its labels; an
    older revision's Job, not yet collected by its TTL, runs an older tag."""
    selector = f"app.kubernetes.io/component=migrate,app.kubernetes.io/instance={release}"
    status, items = k8s.list_jobs(selector, namespace=namespace)
    if status != 200:
        raise k8s.KubeapiUnavailableError(f"Job list status {status}")
    jobs = [j for j in items if carries_tag(j, new_tag)]
    if not jobs:
        return None, None
    job = max(jobs, key=lambda j: str((j.get("metadata") or {}).get("creationTimestamp") or ""))
    return str((job.get("metadata") or {}).get("name") or ""), job


async def _wait_for_migrate_job(
    job_name: str | None,
    namespace: str,
    *,
    stop_after_monotonic: float,
    new_tag: str | None = None,
    release: str = DEFAULT_CHART_NAME,
) -> tuple[bool, str | None, str | None]:
    """Poll the migrate Job until terminal. Returns
    ``(ok, terminal_state, error)``. ``terminal_state`` is
    ``'succeeded'`` / ``'failed'`` / ``None``.

    ``job_name`` names the Job outright (a renamed release's override).
    Without it (#1829) the Job is the newest of ``release``'s migrate Jobs
    on ``new_tag``, found by its labels: the default name this read before,
    ``<chart>-spatiumddi-migrate``, is one the chart never uses, so the
    wait always read "absent".

    A Job not found is treated as ``terminal_state='absent'``: the chart's
    Job is collected by its ``ttlSecondsAfterFinished`` after it finishes,
    and the control Deployments, which this runs after, wait for the schema
    before they start (their wait-for-migrate init container). We don't
    fail-loud on that.
    """
    while time.monotonic() < stop_after_monotonic:
        try:
            if job_name is not None:
                name = job_name
                status, body = k8s.get_job(job_name, namespace=namespace)
            elif new_tag is None:
                return True, "absent", None
            else:
                found, body = _newest_migrate_job(release, namespace, new_tag)
                name = found or ""
                status = 200 if found else 404
        except k8s.KubeapiUnavailableError as exc:
            return False, None, f"kubeapi unreachable: {exc}"
        if status == 404:
            return True, "absent", None
        if status == 200 and body is not None:
            terminal = k8s.job_terminal_state(body)
            if terminal == "succeeded":
                return True, "succeeded", None
            if terminal == "failed":
                # Cluster-side migrate failure — operator needs to
                # debug + helm-rollback / re-run. We report cleanly.
                return False, "failed", f"migrate Job {name} failed"
        await asyncio.sleep(_POLL_INTERVAL_S)
    return False, None, f"timed out polling migrate Job {job_name or release!r}"


# ── Top-level entry ──────────────────────────────────────────────────


async def bump_chart_image_tag(
    new_tag: str,
    *,
    chart_name: str = DEFAULT_CHART_NAME,
    chart_namespace: str = DEFAULT_CHART_NS,
    release_namespace: str = DEFAULT_RELEASE_NS,
    deployment_names: list[str] | None = None,
    migrate_job_name: str | None = None,
    timeout_s: float = DEFAULT_BUMP_TIMEOUT_S,
) -> ChartBumpResult:
    """Patch the chart's HelmChartConfig + wait for the resulting
    rollout to settle.

    On docker-compose / non-kubeapi shapes returns ``skipped=True``
    so the orchestrator can record the no-op without failing the run.
    """
    started_at = _now_iso()
    started_monotonic = time.monotonic()

    # Default the rolled-Deployments + migrate-Job names off the chart
    # name. These match the umbrella chart's template naming;
    # operators with a renamed release pass explicit overrides.
    deployments = deployment_names or [
        f"{chart_name}-spatiumddi-api",
        f"{chart_name}-spatiumddi-frontend",
        f"{chart_name}-spatiumddi-worker",
        f"{chart_name}-spatiumddi-beat",
    ]
    # #1829 — the chart's migrate Job is ``<release>-migrate-r<revision>``,
    # found by its labels unless a name is passed.
    migrate_job = migrate_job_name

    if k8s.get_config() is None:
        return ChartBumpResult(
            ok=True,
            skipped=True,
            skip_reason="ServiceAccount not mounted — not running on k3s",
            new_tag=new_tag,
            chart_name=chart_name,
            namespace=chart_namespace,
            started_at=started_at,
            finished_at=_now_iso(),
        )

    # 1. Read the existing HelmChartConfig (or treat 404 as
    # "no config yet; we'll create one with the new tag").
    try:
        status, body = k8s.get_helmchartconfig(chart_name, namespace=chart_namespace)
    except k8s.KubeapiUnavailableError as exc:
        return ChartBumpResult(
            ok=False,
            new_tag=new_tag,
            chart_name=chart_name,
            namespace=chart_namespace,
            started_at=started_at,
            finished_at=_now_iso(),
            error=f"kubeapi unreachable: {exc}",
        )
    if status not in (200, 404):
        return ChartBumpResult(
            ok=False,
            new_tag=new_tag,
            chart_name=chart_name,
            namespace=chart_namespace,
            started_at=started_at,
            finished_at=_now_iso(),
            error=f"HelmChartConfig GET status {status}",
        )
    current_values = ""
    if status == 200 and body is not None:
        current_values = (body.get("spec") or {}).get("valuesContent") or ""

    # 2. Compute the new valuesContent.  No-op short-circuit if the
    # image.tag is already set to ``new_tag`` (idempotent re-runs).
    new_values = _patch_image_tag(current_values, new_tag)
    if new_values == current_values:
        logger.info("chart_bump_already_current", new_tag=new_tag)

    # 3. PATCH / POST the HelmChartConfig.
    ok, err = k8s.upsert_helmchartconfig(chart_name, new_values, namespace=chart_namespace)
    if not ok:
        return ChartBumpResult(
            ok=False,
            new_tag=new_tag,
            chart_name=chart_name,
            namespace=chart_namespace,
            started_at=started_at,
            finished_at=_now_iso(),
            error=f"HelmChartConfig upsert failed: {err}",
        )
    logger.info(
        "chart_bump_helmchartconfig_patched",
        chart=chart_name,
        new_tag=new_tag,
    )

    # 4. Wait for the helm-controller's rollout to settle. The migrate
    # Job and the Deployment rollout can land in either order
    # depending on the chart's Helm hooks; we wait for both
    # concurrently.
    deadline = started_monotonic + timeout_s

    deploy_ok, rolled, deploy_err = await _wait_for_deployments_rolled(
        deployments, release_namespace, new_tag=new_tag, stop_after_monotonic=deadline
    )
    if not deploy_ok:
        return ChartBumpResult(
            ok=False,
            new_tag=new_tag,
            chart_name=chart_name,
            namespace=chart_namespace,
            started_at=started_at,
            finished_at=_now_iso(),
            rolled_deployments=rolled,
            error=deploy_err,
        )

    migrate_ok, migrate_state, migrate_err = await _wait_for_migrate_job(
        migrate_job,
        release_namespace,
        stop_after_monotonic=deadline,
        new_tag=new_tag,
        release=chart_name,
    )
    if not migrate_ok:
        return ChartBumpResult(
            ok=False,
            new_tag=new_tag,
            chart_name=chart_name,
            namespace=chart_namespace,
            started_at=started_at,
            finished_at=_now_iso(),
            rolled_deployments=rolled,
            migrate_job_state=migrate_state,
            error=migrate_err,
        )

    return ChartBumpResult(
        ok=True,
        new_tag=new_tag,
        chart_name=chart_name,
        namespace=chart_namespace,
        started_at=started_at,
        finished_at=_now_iso(),
        rolled_deployments=rolled,
        migrate_job_state=migrate_state,
    )


def result_to_dict(result: ChartBumpResult) -> dict[str, Any]:
    """JSON-able shape for ``run.progress.chart_bump``."""
    return {
        "ok": result.ok,
        "new_tag": result.new_tag,
        "chart_name": result.chart_name,
        "namespace": result.namespace,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "rolled_deployments": result.rolled_deployments,
        "migrate_job_state": result.migrate_job_state,
        "error": result.error,
        "skipped": result.skipped,
        "skip_reason": result.skip_reason,
    }
