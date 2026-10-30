"""Hold the shared charts' image tag through a cluster rolling upgrade (#1710, #1427).

A cluster shares three k3s HelmCharts in ``kube-system``, and each one
carries ONE image tag for workloads that run on every node:

* ``spatium-bootstrap`` (``global.imageTag``): the supervisor DaemonSet. The
  seed's firstboot renders it from the seed's own slot on every boot.
* ``spatium-control`` (``image.tag``): api, worker, beat, frontend and the
  slot-image mirror. Rendered by the seed's firstboot the same way.
* ``spatiumddi-appliance`` (``global.imageTag``): the DNS / DHCP agent
  DaemonSets. Every member's supervisor writes it from its own slot.

So the first node to boot a new slot moved the tag for every node, and
the nodes still on the old slot were handed images they do not have
(every pod is ``imagePullPolicy: Never``; the cluster may be air-gapped).
Their DNS and DHCP agents went down mid-roll, and the seed's reboot moved
the control plane while members were still to be upgraded (#1710,
#1427's image half).

A rolling run now holds every shared tag at the version the cluster runs
until every node reports the target, then moves them once (mzac's call on
#1427):

* Before its first node, the run pins ``global.imageTag`` / ``image.tag``
  in the bootstrap and control charts' HelmChartConfigs. A HelmChartConfig's
  values win over the HelmChart's (the rule ``chart_bump`` relies on), so
  the seed's firstboot re-render no longer moves them. The pins are
  re-asserted before every node: the seed supervisor's own overrides write
  the control chart's HelmChartConfig as a read then a PATCH.
* The control chart's ``applianceVersion`` (APPLIANCE_VERSION in the api,
  worker and beat env, #2004) is pinned with them, to the version the
  control plane runs (#2176). The same re-render moves it with the slot,
  and a pod template that changes rolls those pods whatever their image:
  holding the tag alone still rolled the control plane mid-run, on the old
  image, and shut down the worker the drive runs on.
* A HelmChartConfig holds values, not the chart, and the seed's firstboot
  renders the control chart from its new slot: a release whose chart
  changed the api, worker or beat pod template rolled them mid-run all
  the same (#2865). So while these pins are on, that firstboot keeps the
  chart back (``spatium-control.yaml.held`` beside the control manifest),
  and its ``spatium-control-release`` runner releases it once the control
  chart's pins are gone: at the flip, whichever release drives the run,
  or when :func:`release_lingering_hold` ends a failed run's hold. The
  bootstrap pin comes off before the control pins, so the chart goes in
  after the last of them: one roll, onto the new chart, tag and version.
* The appliance chart cannot be pinned that way (the seed's supervisor
  rewrites that HelmChartConfig whole on every heartbeat), so the hold goes
  to the supervisors instead. Every member's heartbeat carries it
  (:func:`heartbeat_hold`), and a node that already runs the target writes
  nothing to that chart until the hold ends. The nodes still on the old
  slot keep writing it, so it keeps its old chart AND its old tag.
* When the drive has seen every node pass its health gate, :func:`flip`
  removes every pin and ends the hold in one step. The flip rolls the
  worker the drive runs on, so the rest of the run (:func:`settle`, the
  verify) moves to a worker that already runs the target.

A run that fails or is aborted keeps its hold: nodes on two versions are
exactly the state the hold protects. A new run's Start takes it over, and
:func:`release_lingering_hold` (a beat task) ends it once every member of
the cluster reports one version, for a roll the operator finished node by
node instead.

Everything here is a no-op off k3s (no ServiceAccount) and for a run of
fewer than two nodes, which has no mixed-version window.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.system_upgrade import SystemUpgradeRun
from app.services.appliance import k8s
from app.services.appliance.ownership import k8s_node_name

logger = structlog.get_logger(__name__)

CHART_NAMESPACE = "kube-system"
RELEASE_NAMESPACE = "spatium"

# The HelmChartConfig of each chart the seed's firstboot renders, and the
# key that carries its image tag.
PINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("spatium-bootstrap", ("global", "imageTag")),
    ("spatium-control", ("image", "tag")),
)

# #2176 — and the control chart's value for APPLIANCE_VERSION in the api,
# worker and beat env (#2004), which the seed's firstboot renders from its
# slot on the same boot as the tag. Held to the version the control plane
# runs, not to the tag: on a nightly the two differ (``nightly-YYYYMMDD``
# against ``0.0.0-nightly-YYYYMMDD+<sha>``).
VERSION_PIN: tuple[str, tuple[str, ...]] = ("spatium-control", ("applianceVersion",))

PROGRESS_KEY = "shared_tags"
MODE_HOLD = "hold"
# A run whose nodes a drive from before #1710 started: its tags may have
# moved already, so holding them now would roll the control plane back.
MODE_LEGACY = "legacy"

FLIP_FLIPPING = "flipping"
FLIP_FLIPPED = "flipped"
FLIP_SETTLED = "settled"

DEFAULT_SETTLE_TIMEOUT_S = 1800.0
_POLL_INTERVAL_S = 5.0


@dataclass(frozen=True)
class StepOutcome:
    """What one hold step did. ``mode`` is ``hold``, ``legacy``,
    ``released`` or ``skipped`` (no k3s, or a one-node run).

    ``retryable``: the step failed at the kubeapi in a way a later try can
    get past, a request unanswered or refused for now (:func:`_transient`).
    Every step is idempotent, so the drive tries it again rather than end
    the run on an apiserver that is restarting."""

    ok: bool
    mode: str = "skipped"
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    retryable: bool = False


# Statuses the kubeapi answers a request it may take on a later try with:
# timeout, conflict (a write that raced another one), throttling. Every 5xx
# is one too: k3s answers 503 "apiserver not ready" while it restarts.
_TRANSIENT_STATUSES = frozenset({408, 409, 429})
_STATUS_RE = re.compile(r"\bstatus (\d{3})\b")


def _transient(error: str | None) -> bool:
    """Whether a pin step's ``error`` is the kubeapi's not answering or
    refusing for now (#2028), which the drive tries again, rather than an
    answer no later try changes: a 403 (RBAC), a 422 (an invalid object), a
    missing ServiceAccount. Those fail the run at once, as before, so a real
    fault is never hidden behind five minutes of retries.

    Reads the status the k8s helpers put in their error text; an error with
    no status is a request that went unanswered."""
    if not error or "ServiceAccount not mounted" in error:
        return False
    match = _STATUS_RE.search(error)
    if match is None:
        return True
    status = int(match.group(1))
    return status >= 500 or status in _TRANSIENT_STATUSES


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── The run's record ─────────────────────────────────────────────────


def record_of(run: SystemUpgradeRun) -> dict[str, Any]:
    """A copy of the run's ``progress.shared_tags`` record ({} if none)."""
    return dict((run.progress or {}).get(PROGRESS_KEY) or {})


def _store(run: SystemUpgradeRun, record: dict[str, Any]) -> None:
    # A new dict, so SQLAlchemy sees the JSONB change.
    run.progress = {**(run.progress or {}), PROGRESS_KEY: record}


async def _commit_record(
    db: AsyncSession, run: SystemUpgradeRun, record: dict[str, Any], *, holder: str | None
) -> bool:
    """Write ``record`` as the run's ``progress.shared_tags`` and commit, as a
    merge onto the row re-read under ``FOR UPDATE`` (#1702).

    Writing ``run.progress`` whole from a copy read before a kubeapi call
    would put back the ``progress.events`` it was read with, dropping a
    Halt, Resume or Abort that landed during the call. Only this key is
    written. With ``holder`` (the drive's Lease identity), the write is
    refused, and False returned, when another drive has taken the run over:
    the record is that drive's now. The ``expire`` stops the read from
    autoflushing this session's stale copy first."""
    run_id = run.id
    db.expire(run)
    fresh = (
        await db.execute(
            select(SystemUpgradeRun)
            .where(SystemUpgradeRun.id == run_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if fresh is None or (holder and fresh.lease_holder not in (None, holder)):
        await db.commit()
        return False
    _store(fresh, record)
    await db.commit()
    return True


def holds(run: SystemUpgradeRun) -> bool:
    """True when this run placed a hold (released or not): its end of
    roll is the flip, not the old chart bump."""
    return record_of(run).get("mode") == MODE_HOLD


def flip_record(run: SystemUpgradeRun) -> dict[str, Any]:
    return dict(record_of(run).get("flip") or {})


# ── valuesContent edits ──────────────────────────────────────────────


def set_value(values_yaml: str, path: tuple[str, ...], value: str) -> str:
    """``values_yaml`` with ``path`` set to ``value``, every other key kept.

    Returns the input unchanged when the key already holds the value, so
    the upsert's compare skips the PATCH and helm-controller re-renders
    nothing. A document that does not parse is replaced by one holding just
    the key, as ``chart_bump`` does."""
    try:
        doc = yaml.safe_load(values_yaml) if values_yaml.strip() else None
    except yaml.YAMLError:
        doc = None
    if not isinstance(doc, dict):
        doc = {}
    node: dict[str, Any] = doc
    for key in path[:-1]:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    if node.get(path[-1]) == value and values_yaml.strip():
        return values_yaml
    node[path[-1]] = value
    return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False)


def drop_value(values_yaml: str, path: tuple[str, ...]) -> str:
    """``values_yaml`` without ``path`` (and without a parent the removal
    leaves empty). Returns the input unchanged when the key is absent or the
    document does not parse: nothing of ours is there to remove."""
    try:
        doc = yaml.safe_load(values_yaml) if values_yaml.strip() else None
    except yaml.YAMLError:
        return values_yaml
    if not isinstance(doc, dict):
        return values_yaml
    parents: list[dict[str, Any]] = [doc]
    node: Any = doc
    for key in path[:-1]:
        node = node.get(key) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            return values_yaml
        parents.append(node)
    if path[-1] not in node:
        return values_yaml
    del node[path[-1]]
    for depth in range(len(path) - 1, 0, -1):
        if parents[depth]:
            break
        del parents[depth - 1][path[depth - 1]]
    return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False) if doc else ""


def _pin_edits(
    tag: str | None, version: str | None
) -> dict[str, list[tuple[tuple[str, ...], str | None]]]:
    """Each chart's (key, value) edits: every tag pin to ``tag`` and the
    version pin to ``version``, or every key removed (value None) when
    ``tag`` is None. A ``version`` of None with a tag leaves the version key
    as it is: a hold whose record names no version, placed by a drive from
    before #2176, pins its tags only, as that drive did."""
    edits: dict[str, list[tuple[tuple[str, ...], str | None]]] = {}
    for name, path in PINS:
        edits.setdefault(name, []).append((path, tag))
    if tag is None or version is not None:
        name, path = VERSION_PIN
        edits.setdefault(name, []).append((path, None if tag is None else version))
    return edits


def _apply_pins(tag: str | None, version: str | None = None) -> tuple[bool, str | None]:
    """Set every tag pin to ``tag`` and the version pin to ``version``, or
    remove every pin when ``tag`` is None (:func:`_pin_edits`).

    Idempotent: a HelmChartConfig already in the wanted state is not
    written, so helm-controller re-renders nothing. One write per chart, so
    the control chart's tag and version move in one helm revision."""
    for name, pins in _pin_edits(tag, version).items():
        try:
            status, body = k8s.get_helmchartconfig(name, namespace=CHART_NAMESPACE)
        except k8s.KubeapiUnavailableError as exc:
            return False, f"{name}: kubeapi unreachable: {exc}"
        if status not in (200, 404):
            return False, f"{name}: HelmChartConfig GET status {status}"
        if status == 404 and tag is None:
            continue
        current = ""
        if status == 200 and body is not None:
            current = (body.get("spec") or {}).get("valuesContent") or ""
        wanted = current
        for path, value in pins:
            wanted = drop_value(wanted, path) if value is None else set_value(wanted, path, value)
        if status == 200 and wanted == current:
            continue
        ok, err = k8s.upsert_helmchartconfig(name, wanted, namespace=CHART_NAMESPACE)
        if not ok:
            return False, f"{name}: {err}"
        logger.info(
            "upgrade_shared_tag_pin_written",
            chart=name,
            key=",".join(".".join(path) for path, _value in pins),
            tag=tag,
            version=version if name == VERSION_PIN[0] else None,
        )
    return True, None


async def _wake_supervisors() -> None:
    """Wake every supervisor's held heartbeat, so the end of a hold reaches
    them now and not at the end of their long-poll. Best effort: without
    it they still learn within one heartbeat."""
    from app.core.agent_wake import HOSTCONFIG_ALL, publish_wake  # noqa: PLC0415

    try:
        await publish_wake(HOSTCONFIG_ALL)
    except Exception as exc:  # noqa: BLE001 — a missed wake costs one heartbeat
        logger.warning("upgrade_shared_tag_wake_failed", error=str(exc))


async def _unreleased_hold_runs(db: AsyncSession) -> list[SystemUpgradeRun]:
    """Every run whose hold has not ended, newest first.

    Found by the record itself, not among the newest few runs: a failed
    run's hold outlives any number of later Plans, and one missed here would
    keep its pins on the charts with nothing left to remove them."""
    record = SystemUpgradeRun.progress[PROGRESS_KEY]
    rows = await db.execute(
        select(SystemUpgradeRun)
        .where(
            SystemUpgradeRun.kind == "cluster_rolling",
            record["mode"].astext == MODE_HOLD,
            record["released_at"].astext.is_(None),
        )
        .order_by(SystemUpgradeRun.started_at.desc())
    )
    return list(rows.scalars().all())


async def _newest_hold_run(db: AsyncSession) -> SystemUpgradeRun | None:
    runs = await _unreleased_hold_runs(db)
    return runs[0] if runs else None


# ── Start: place (or re-assert) the hold ─────────────────────────────


async def ensure_hold(db: AsyncSession, run: SystemUpgradeRun) -> StepOutcome:
    """Place the hold before a run's first node, or re-assert its pins
    before every later one. The caller commits.

    A hold that cannot be placed is a failure: the run must stop before a
    node boots the new slot with the shared tags free to move. A failure the
    kubeapi may get past on a later try is ``retryable``: the drive pauses
    and tries the step again before it fails the run on it."""
    record = record_of(run)
    mode = record.get("mode")
    if mode == MODE_LEGACY:
        return StepOutcome(ok=True, mode=MODE_LEGACY)
    if mode == MODE_HOLD:
        if record.get("released_at"):
            return StepOutcome(ok=True, mode="released")
        held_tag = str(record.get("from_tag") or "")
        if not held_tag:
            return StepOutcome(ok=False, mode=MODE_HOLD, error="the hold records no tag")
        # The version the hold was placed with, never this process's now:
        # the record is what every drive of the run re-asserts.
        held_version = record.get("from_version")
        ok, err = _apply_pins(held_tag, None if held_version is None else str(held_version))
        return StepOutcome(ok=ok, mode=MODE_HOLD, error=err, retryable=not ok and _transient(err))

    nodes = [str(n) for n in (run.plan or {}).get("node_order") or []]
    if len(nodes) < 2 or k8s.get_config() is None:
        return StepOutcome(ok=True, mode="skipped")
    if (run.progress or {}).get("per_node"):
        _store(run, {"mode": MODE_LEGACY, "noted_at": _now_iso()})
        logger.info("upgrade_shared_tag_hold_legacy_run", run_id=str(run.id))
        return StepOutcome(ok=True, mode=MODE_LEGACY)

    from_tag = settings.version
    # #2176 — the version the control plane reports (APPLIANCE_VERSION, ""
    # when unknown), held with the tag: an unknown one is held as unknown.
    from_version = settings.appliance_version or ""
    _store(
        run,
        {
            "mode": MODE_HOLD,
            "from_tag": from_tag,
            "from_version": from_version,
            "to_tag": run.target_version,
            "nodes": nodes,
            "placed_at": _now_iso(),
            "released_at": None,
            "release_reason": None,
        },
    )
    # One hold at a time: this run's takes over a failed or aborted run's.
    for other in await _unreleased_hold_runs(db):
        other_record = record_of(other)
        if other.id != run.id:
            other_record["released_at"] = _now_iso()
            other_record["release_reason"] = f"superseded:{run.id}"
            _store(other, other_record)
    ok, err = _apply_pins(from_tag, from_version)
    logger.info(
        "upgrade_shared_tag_hold_placed",
        run_id=str(run.id),
        from_tag=from_tag,
        from_version=from_version,
        to_tag=run.target_version,
        ok=ok,
        error=err,
    )
    return StepOutcome(
        ok=ok,
        mode=MODE_HOLD,
        error=err,
        detail={"from_tag": from_tag, "from_version": from_version},
        retryable=not ok and _transient(err),
    )


# ── The flip ─────────────────────────────────────────────────────────


def _template_images(item: dict[str, Any]) -> list[str]:
    pod_spec = ((item.get("spec") or {}).get("template") or {}).get("spec") or {}
    images: list[str] = []
    for key in ("initContainers", "containers"):
        for container in pod_spec.get(key) or []:
            image = container.get("image")
            if isinstance(image, str):
                images.append(image)
    return images


def carries_tag(item: dict[str, Any], tag: str) -> bool:
    """True when any container of the workload's pod template runs ``tag``."""
    return any(":" in image and image.rsplit(":", 1)[1] == tag for image in _template_images(item))


def _list_workloads(namespace: str) -> dict[tuple[str, str], dict[str, Any]]:
    """Every Deployment and DaemonSet in ``namespace``, keyed (kind, name).
    Raises ``KubeapiUnavailableError`` when either list cannot be read."""
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for kind, lister in (("Deployment", k8s.list_deployments), ("DaemonSet", k8s.list_daemonsets)):
        status, items = lister("", namespace=namespace)
        if status != 200:
            raise k8s.KubeapiUnavailableError(f"{kind} list status {status}")
        for item in items:
            name = (item.get("metadata") or {}).get("name")
            if name:
                found[(kind, str(name))] = item
    return found


def _rolled_out(kind: str, item: dict[str, Any]) -> bool:
    if kind == "DaemonSet":
        return k8s.daemonset_is_rolled_out(item)
    return k8s.deployment_is_rolled_out(item)


async def wait_rolled(
    workloads: list[dict[str, str]],
    *,
    to_tag: str,
    from_tag: str | None = None,
    namespace: str = RELEASE_NAMESPACE,
    timeout_s: float = DEFAULT_SETTLE_TIMEOUT_S,
) -> tuple[bool, list[str], list[str], str | None]:
    """Wait until every workload has rolled onto ``to_tag`` (#1829).

    Keyed off the change, not off the status alone: a workload counts only
    once its pod template runs ``to_tag`` (and no longer ``from_tag``) AND
    its rollout is complete for that template. A status read before
    helm-controller re-rendered the workload therefore never counts. Only
    the current state is read, so a drive redelivered mid-wait can wait
    again. A workload the new chart removed counts as done. A kubeapi error
    is retried until the deadline.

    Returns ``(ok, rolled, pending, error)`` with ``kind/name`` strings."""
    deadline = time.monotonic() + timeout_s
    pending = {(w["kind"], w["name"]) for w in workloads}
    rolled: list[str] = []
    last_error: str | None = None
    while True:
        try:
            current = _list_workloads(namespace)
        except k8s.KubeapiUnavailableError as exc:
            current = None
            last_error = f"kubeapi unreachable: {exc}"
        if current is not None:
            for kind, name in sorted(pending):
                item = current.get((kind, name))
                if item is not None:
                    if not carries_tag(item, to_tag):
                        continue
                    if from_tag and carries_tag(item, from_tag):
                        continue
                    if not _rolled_out(kind, item):
                        continue
                pending.discard((kind, name))
                rolled.append(f"{kind}/{name}")
        if not pending:
            return True, rolled, [], None
        if time.monotonic() >= deadline:
            names = sorted(f"{k}/{n}" for k, n in pending)
            error = f"not rolled onto {to_tag} after {int(timeout_s)} s: {', '.join(names)}"
            if last_error:
                error = f"{error} (last kubeapi error: {last_error})"
            return False, rolled, names, error
        await asyncio.sleep(_POLL_INTERVAL_S)


async def flip(db: AsyncSession, run: SystemUpgradeRun) -> StepOutcome:
    """End the hold: the run's last change to the cluster.

    Records the workloads that run the old tag (what :func:`settle` waits
    for), removes every pin (removes the keys: a pin left set to the target
    would outlive the run and stop a later per-node upgrade's firstboot
    from moving the control plane), marks the hold released, which frees
    the supervisors to write the appliance chart, and wakes them. On the
    seed, the control chart its firstboot held back while the pins were on
    goes in once they are gone (``spatium-control-release``, #2865): that
    release is the control plane's roll.
    Idempotent: a drive redelivered mid-flip keeps the first snapshot."""
    record = record_of(run)
    flip_rec = dict(record.get("flip") or {})
    if flip_rec.get("state") in (FLIP_FLIPPED, FLIP_SETTLED):
        return StepOutcome(ok=True, mode=MODE_HOLD, detail=flip_rec)
    from_tag = str(record.get("from_tag") or "")
    holder = run.lease_holder
    if flip_rec.get("state") != FLIP_FLIPPING:
        try:
            current = _list_workloads(RELEASE_NAMESPACE)
        except k8s.KubeapiUnavailableError as exc:
            return StepOutcome(
                ok=False,
                mode=MODE_HOLD,
                error=f"kubeapi unreachable: {exc}",
                retryable=_transient(str(exc)),
            )
        workloads = [
            {"kind": kind, "name": name}
            for (kind, name), item in sorted(current.items())
            if carries_tag(item, from_tag)
        ]
        flip_rec = {"state": FLIP_FLIPPING, "started_at": _now_iso(), "workloads": workloads}
        record["flip"] = flip_rec
        if not await _commit_record(db, run, record, holder=holder):
            return StepOutcome(ok=False, mode=MODE_HOLD, error="the run has another drive now")

    ok, err = _apply_pins(None)
    if not ok:
        return StepOutcome(
            ok=False,
            mode=MODE_HOLD,
            error=f"could not remove a tag pin: {err}",
            retryable=_transient(err),
        )
    now = _now_iso()
    flip_rec.update(state=FLIP_FLIPPED, flipped_at=now)
    record.update(flip=flip_rec, released_at=now, release_reason="flip")
    if not await _commit_record(db, run, record, holder=holder):
        return StepOutcome(ok=False, mode=MODE_HOLD, error="the run has another drive now")
    await _wake_supervisors()
    logger.info(
        "upgrade_shared_tags_flipped",
        run_id=str(run.id),
        from_tag=from_tag,
        to_tag=record.get("to_tag"),
        workloads=len(flip_rec.get("workloads") or []),
    )
    return StepOutcome(ok=True, mode=MODE_HOLD, detail=flip_rec)


async def settle(
    db: AsyncSession, run: SystemUpgradeRun, *, timeout_s: float = DEFAULT_SETTLE_TIMEOUT_S
) -> StepOutcome:
    """Wait for every workload the flip recorded to roll onto the target.
    The caller commits."""
    record = record_of(run)
    flip_rec = dict(record.get("flip") or {})
    if flip_rec.get("state") == FLIP_SETTLED:
        return StepOutcome(ok=True, mode=MODE_HOLD, detail=flip_rec)
    ok, rolled, pending, error = await wait_rolled(
        list(flip_rec.get("workloads") or []),
        to_tag=str(record.get("to_tag") or ""),
        from_tag=str(record.get("from_tag") or "") or None,
        timeout_s=timeout_s,
    )
    flip_rec["rolled"] = rolled
    if ok:
        flip_rec.update(state=FLIP_SETTLED, settled_at=_now_iso(), pending=[])
    else:
        flip_rec["pending"] = pending
    record["flip"] = flip_rec
    _store(run, record)
    return StepOutcome(ok=ok, mode=MODE_HOLD, error=error, detail=flip_rec)


# ── The supervisors' side ────────────────────────────────────────────


async def heartbeat_hold(db: AsyncSession, hostname: str | None) -> dict[str, str] | None:
    """The hold a member's heartbeat carries, or None.

    Only the nodes of the holding run's plan are held (matched as k8s Node names,
    as node names and hostnames may differ in case): an appliance outside
    the cluster writes its own chart, which nothing shares. The supervisor
    compares ``target_version`` with its host's installed version, the
    value the per-node health gate reads, and a node already on it writes
    nothing to the shared chart until the hold ends."""
    if not hostname:
        return None
    run = await _newest_hold_run(db)
    if run is None:
        return None
    record = record_of(run)
    if record.get("released_at"):
        return None
    nodes = {k8s_node_name(str(n)) for n in record.get("nodes") or []}
    if k8s_node_name(hostname) not in nodes:
        return None
    return {
        "run_id": str(run.id),
        "from_tag": str(record.get("from_tag") or ""),
        "target_version": str(record.get("to_tag") or ""),
    }


async def release_lingering_hold(db: AsyncSession) -> dict[str, str] | None:
    """End the hold of a run that failed or was aborted once every member
    of the cluster reports one installed version (the beat task).

    That is the way out when the operator finishes the roll node by node
    (or takes every node back): with every node on one version there is
    nothing left to hold, and a hold kept for ever would leave the control
    plane on the old tag. Whichever version it is, the charts then follow
    the nodes: the seed's firstboot has rendered its own, and a control
    chart it held back while the hold was on goes in once the pins are
    gone (#2865). A run still in flight is never touched: its drive owns
    the hold."""
    run = await _newest_hold_run(db)
    if run is None:
        return None
    record = record_of(run)
    if record.get("released_at") or run.state not in ("failed", "aborted"):
        return None
    rows = await db.execute(
        select(Appliance.hostname, Appliance.installed_appliance_version).where(
            Appliance.state == APPLIANCE_STATE_APPROVED,
            Appliance.cluster_role.in_(("primary", "member")),
        )
    )
    versions = {version for _hostname, version in rows.all()}
    if len(versions) != 1 or None in versions:
        return None
    version = str(versions.pop())
    if k8s.get_config() is None:
        return None
    # An aborted run's drive keeps the Lease until the node it was on ends
    # (#1707), and that node may still boot the new slot: one version
    # across the members now says nothing about a minute from now. Wait
    # for the drive to let go (or its Lease to lapse).
    from app.services.upgrades import mutex  # noqa: PLC0415

    # A failed run's drive has let go already: it fails the run only as it ends.
    lease = mutex.get_state() if run.state == "aborted" and run.lease_holder else None
    # An unreadable Lease (#1713) may be that drive's too: wait for an answer.
    if (
        lease is not None
        and lease.held
        and (lease.holder == run.lease_holder or (lease.holder or "").startswith("<"))
    ):
        logger.info("upgrade_shared_tag_release_deferred_drive_alive", run_id=str(run.id))
        return None
    run_id = str(run.id)
    ok, err = _apply_pins(None)
    if not ok:
        logger.warning("upgrade_shared_tag_release_failed", run_id=run_id, error=err)
        return None
    record.update(released_at=_now_iso(), release_reason=f"uniform:{version}")
    # A merge onto the locked row: the aborted drive may have written its
    # node's outcome while the pins were coming off.
    await _commit_record(db, run, record, holder=None)
    await _wake_supervisors()
    logger.info("upgrade_shared_tag_hold_released", run_id=run_id, version=version)
    return {"run_id": run_id, "version": version}


__all__ = [
    "CHART_NAMESPACE",
    "DEFAULT_SETTLE_TIMEOUT_S",
    "MODE_HOLD",
    "MODE_LEGACY",
    "PINS",
    "PROGRESS_KEY",
    "RELEASE_NAMESPACE",
    "StepOutcome",
    "VERSION_PIN",
    "carries_tag",
    "drop_value",
    "ensure_hold",
    "flip",
    "flip_record",
    "heartbeat_hold",
    "holds",
    "record_of",
    "release_lingering_hold",
    "set_value",
    "settle",
    "wait_rolled",
]
