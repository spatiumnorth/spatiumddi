"""Pre-flight safety checks for a multi-node rolling upgrade (#296 Phase A).

Phase A ships read-only checks the operator runs **before** committing
to an upgrade. The endpoint at ``GET /api/v1/upgrades/preflight?target=<tag>``
calls ``run_all()`` and returns the aggregate; nothing here mutates
cluster state.

Each check is its own async function returning a ``PreflightResult``.
We deliberately keep them independent — a failure in any one shouldn't
stop the others from running, so the operator sees the full picture
in one round-trip. The endpoint serializes the result list + an
``overall`` summary; the UI renders red/amber/green per row.

Checks shipped in Phase A:

* ``check_inflight_conflict`` — another upgrade in flight (lease state).
* ``check_replication_lag`` — CNPG replicas caught up (queryable via SQL).
* ``check_disk_headroom`` — ``/var`` partition has room for the slot
  image + a safety margin.
* ``check_version_path`` — target tag is a valid forward jump from
  ``settings.version``, compared with ``app.core.versions`` (CalVer before
  1.0.0, SemVer from it, #1182); no skip-release across the supported skew
  window.
* ``check_kea_ha_version_skew`` — a Kea HA pair on pre-3.0 cannot be
  upgraded node-at-a-time (3.0's HA hook won't talk to a < 2.7 peer);
  warn the operator before they start. Scoped to appliance nodes and to
  real HA pairs only, and never returns ``fail`` (blocking would strand a
  broken pair in its broken state). See issue #637.
* ``check_powerdns_lmdb_migration`` — crossing PowerDNS 4.x → 5.x performs a
  one-way LMDB schema migration that an A/B slot rollback cannot undo, because
  ``/var`` is the shared persistent partition. The agent snapshots the database
  automatically, but recovering means restoring that snapshot, not just
  redeploying the old image — so say so before Start. Warn-only. See #638.
* ``check_pre_upgrade_backup`` — the upgrade migrates the database on the
  persistent ``/var``, and the release being left cannot start on it
  afterwards, so a slot rollback alone is not a way back. Warns when no
  backup target has succeeded in the last day. Warn-only. See #1227.
* ``check_quorum`` — cluster size is odd + ≥ 3 + every node currently
  Ready (so we don't start a rolling upgrade with a node already down).

What we **don't** check here that Phases C/D will own:

* Live etcd member health (the orchestrator owns the per-node etcd
  rejoin gate).
* DaemonSet readiness on each node (gated in the per-node primitive,
  not at preflight time — the probe lands in A2).
* Slot-image presence on the mirror node (Phase B's responsibility
  to surface its own readiness).
"""

from __future__ import annotations

import asyncio
import shutil
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from sqlalchemy import select, text

from app.config import settings
from app.core.versions import canonical_version, includes_release, parse_release
from app.db import AsyncSessionLocal
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
    ApplianceUpgradeImage,
)
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer
from app.services.appliance.ownership import k8s_node_name, orchestrated_server_condition
from app.services.upgrades import kubeapi_retry, mutex

logger = structlog.get_logger(__name__)


PreflightLevel = Literal["ok", "warn", "fail"]


@dataclass(frozen=True)
class PreflightResult:
    """One check's outcome.

    ``level``:
      * ``ok``    — safe to proceed (rendered green)
      * ``warn``  — degraded but upgrade can still start; surface to
        operator (rendered amber)
      * ``fail``  — must be resolved before starting (rendered red,
        blocks the Start button)

    ``detail`` is structured data the UI can render inline (e.g. the
    replication-lag bytes per replica). ``message`` is the one-line
    human summary.
    """

    name: str
    level: PreflightLevel
    message: str
    detail: dict[str, Any]


# The skip-release warning's thresholds: days between two CalVer tags,
# and major versions between two SemVer ones (#1182).
_SKIP_RELEASE_WARN_DAYS = 90
_SKIP_RELEASE_WARN_MAJORS = 1

# How old the newest successful backup may be before the pre-upgrade backup
# row warns (#1227). A day, matching the common nightly schedule.
_PRE_UPGRADE_BACKUP_MAX_AGE_HOURS = 24


# ── Individual checks ─────────────────────────────────────────────────


def check_inflight_conflict(
    *,
    namespace: str | None = None,
    own_holder: str | None = None,
    retry_budget_s: float = 0.0,
) -> PreflightResult:
    """Refuses if another upgrade is already in flight cluster-wide.

    Reads the ``spatium-upgrade-lock`` Lease; if it's held + not
    expired we ``fail`` with the holder's identity. An expired lease
    is fine (the previous holder crashed before releasing — we'll
    take over on acquire).

    ``own_holder`` is the identity of the run asking. The orchestrator
    takes the lease at Start and then runs this preflight again for every
    node, so without it each run failed its own first node on the lease
    it had just taken (#1445).
    """
    state = mutex.get_state(namespace=namespace, retry_budget_s=retry_budget_s)
    if state.held and not state.expired and own_holder and state.holder == own_holder:
        return PreflightResult(
            name="inflight_conflict",
            level="ok",
            message="the upgrade lease is held by this run",
            detail={"holder": state.holder, "transitions": state.transitions},
        )
    if own_holder and state.holder == mutex.UNREACHABLE_HOLDER:
        # #1713 — the kubeapi did not answer the read. The run asking holds
        # the Lease by its own renewals, which stop the drive if it is lost;
        # failing its node on a read nobody answered would fail the run on
        # the reboot blip that follows every node.
        return PreflightResult(
            name="inflight_conflict",
            level="warn",
            message="the upgrade lease could not be read; this run's renewals hold it",
            detail={"holder": state.holder},
        )
    if state.holder == mutex.UNREACHABLE_HOLDER:
        # #2779 — the kubeapi did not answer the lease read (after the read's
        # own retries). That is not another run holding the lease: say the API
        # could not be reached, so the operator checks it instead of hunting a
        # run that does not exist.
        return PreflightResult(
            name="kubeapi_unreachable",
            level="fail",
            message=(
                "the Kubernetes API did not answer the read of the upgrade lease "
                f"({mutex.LEASE_NAME}), so whether another upgrade is in flight is "
                "unknown; check the control-plane nodes and retry"
            ),
            detail={"read": "get_lease", "lease": mutex.LEASE_NAME, "holder": state.holder},
        )
    if state.held and not state.expired:
        return PreflightResult(
            name="inflight_conflict",
            level="fail",
            message=f"another upgrade is in flight (lease held by {state.holder!r})",
            detail={
                "holder": state.holder,
                "renew_time": state.renew_time,
                "transitions": state.transitions,
            },
        )
    return PreflightResult(
        name="inflight_conflict",
        level="ok",
        message="no upgrade in flight",
        detail={
            "previous_holder": state.holder,
            "previous_transitions": state.transitions,
        },
    )


async def check_replication_lag(*, threshold_bytes: int = 16 * 1024) -> PreflightResult:
    """Verify every CNPG replica is caught up enough for a switchover.

    Reads ``pg_stat_replication`` via the api's existing connection.
    Each replica row should have ``state='streaming'`` and
    ``pg_wal_lsn_diff(sent_lsn, replay_lsn) <= threshold_bytes``.

    A lagging replica isn't a fail (the orchestrator will pick a
    different replica for the switchover) but >0 lag is a ``warn``
    so the operator knows the picture before clicking Start.
    """
    try:
        async with AsyncSessionLocal() as session:
            rows = (await session.execute(text("""
                        SELECT
                            application_name,
                            state,
                            pg_wal_lsn_diff(sent_lsn, replay_lsn) AS lag_bytes
                        FROM pg_stat_replication
                        """))).all()
    except Exception as exc:  # noqa: BLE001 — surface any DB error
        logger.warning("preflight_replication_query_failed", error=str(exc))
        return PreflightResult(
            name="replication_lag",
            level="warn",
            message=f"could not query pg_stat_replication: {exc}",
            detail={"error": str(exc)},
        )
    replicas = [
        {
            "name": r.application_name,
            "state": r.state,
            "lag_bytes": int(r.lag_bytes or 0),
        }
        for r in rows
    ]
    # Single-node CNPG (or no CNPG) — no replicas to check; not a
    # rolling-upgrade fail because the standalone shape never tries one.
    if not replicas:
        return PreflightResult(
            name="replication_lag",
            level="ok",
            message="no streaming replicas (single-node shape)",
            detail={"replicas": []},
        )
    # #1445 — ``pg_stat_replication`` shows a replica's ``state`` and LSNs
    # only to a superuser or a member of ``pg_monitor``; to anyone else the
    # row is there but those columns are NULL. The app's role is neither on
    # the appliance (CNPG manages it and reverts a manual GRANT), so every
    # replica read as "not streaming" and the preflight refused to start a
    # healthy cluster's upgrade. A NULL state is unverified, not broken.
    unverified = [r for r in replicas if r["state"] is None]
    if len(unverified) == len(replicas):
        return PreflightResult(
            name="replication_lag",
            level="warn",
            message=(
                f"{len(replicas)} replica(s) connected; their streaming state "
                "is not visible to the app's database role (needs pg_monitor), "
                "so it was not verified"
            ),
            detail={"replicas": replicas, "unverified": True},
        )
    streaming = [r for r in replicas if r["state"] == "streaming"]
    lagging = [r for r in streaming if r["lag_bytes"] > threshold_bytes]
    not_streaming = [r for r in replicas if r["state"] is not None and r["state"] != "streaming"]
    if not_streaming:
        return PreflightResult(
            name="replication_lag",
            level="fail",
            message=(
                f"{len(not_streaming)} replica(s) not streaming "
                "— refuse to start; resolve before upgrading"
            ),
            detail={"replicas": replicas},
        )
    if lagging:
        return PreflightResult(
            name="replication_lag",
            level="warn",
            message=(
                f"{len(lagging)} replica(s) lagging > {threshold_bytes} B "
                "— orchestrator will pick a caught-up replica per node"
            ),
            detail={"replicas": replicas, "threshold_bytes": threshold_bytes},
        )
    return PreflightResult(
        name="replication_lag",
        level="ok",
        message=f"{len(streaming)} replica(s) streaming + caught up",
        detail={"replicas": replicas},
    )


def check_disk_headroom(
    *,
    var_path: str = "/var",
    slot_image_size_bytes: int = 4 * 1024 * 1024 * 1024,
    safety_margin_bytes: int = 1 * 1024 * 1024 * 1024,
) -> PreflightResult:
    """``/var`` has room for the slot image + a safety margin.

    The slot image lives on ``/var/lib/spatiumddi/slot-images/`` (or is
    streamed from the mirror node) and gets ``dd``-ed onto the inactive
    root partition. We need free space for:

    * The downloaded image (~1-4 GiB).
    * Headroom for etcd snapshots that the upgrade triggers
      (``etcd-snapshot save`` runs as a pre-upgrade safety net).
    * ``/var`` operator margin (logs, container layers).

    Default budget: 4 GiB slot image + 1 GiB margin = 5 GiB. Tune via
    args if the operator picks a non-default slot image size.
    """
    try:
        usage = shutil.disk_usage(var_path)
    except OSError as exc:
        return PreflightResult(
            name="disk_headroom",
            level="warn",
            message=f"could not stat {var_path}: {exc}",
            detail={"path": var_path, "error": str(exc)},
        )
    need = slot_image_size_bytes + safety_margin_bytes
    if usage.free < need:
        return PreflightResult(
            name="disk_headroom",
            level="fail",
            message=(
                f"{var_path} has {usage.free // (1024**3)} GiB free; "
                f"need {need // (1024**3)} GiB (slot image + margin)"
            ),
            detail={
                "path": var_path,
                "free_bytes": usage.free,
                "needed_bytes": need,
                "total_bytes": usage.total,
            },
        )
    return PreflightResult(
        name="disk_headroom",
        level="ok",
        message=(
            f"{var_path}: {usage.free // (1024**3)} GiB free " f"(need {need // (1024**3)} GiB)"
        ),
        detail={
            "path": var_path,
            "free_bytes": usage.free,
            "needed_bytes": need,
            "total_bytes": usage.total,
        },
    )


# A node whose last heartbeat is older than this has a /var reading that no
# longer says anything about now (#1234). The supervisor heartbeats every
# ~30 s, so ten minutes is many missed beats, not jitter.
_NODE_DISK_REPORT_MAX_AGE_SECONDS = 10 * 60


def _node_var_free_bytes(cluster_health: Any) -> int | None:
    """Free bytes on a node's ``/var`` from its reported partitions.

    ``None`` = no usable reading (key absent, entry absent, malformed) —
    UNKNOWN, never zero and never "plenty".
    """
    if not isinstance(cluster_health, dict):
        return None
    parts = cluster_health.get("host_disk_partitions")
    if not isinstance(parts, list):
        return None
    for p in parts:
        if not isinstance(p, dict) or p.get("mount") != "/var":
            continue
        total, used = p.get("total_bytes"), p.get("used_bytes")
        if (
            isinstance(total, int)
            and isinstance(used, int)
            and not isinstance(total, bool)
            and not isinstance(used, bool)
            and total > 0
        ):
            return max(total - used, 0)
    return None


def judge_node_disk_headroom(
    nodes: list[Any],
    *,
    need_bytes: int,
    now: datetime,
    max_age_seconds: int = _NODE_DISK_REPORT_MAX_AGE_SECONDS,
) -> PreflightResult:
    """Judge each appliance node's reported ``/var`` headroom (#1234).

    ``spatium-upgrade-slot`` stages the slot image under the NODE's
    ``/var``, so the api pod's own filesystem says nothing about whether a
    member can take the upgrade. ``fail`` names every node short of
    ``need_bytes``; a node with no reading, or one older than
    ``max_age_seconds``, is ``warn`` and named (NULL = unknown, never ok).
    """
    short: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []
    for n in nodes:
        label = getattr(n, "hostname", None) or str(getattr(n, "id", "?"))
        seen = getattr(n, "last_seen_at", None)
        if seen is not None and seen.tzinfo is None:
            seen = seen.replace(tzinfo=UTC)
        free = _node_var_free_bytes(getattr(n, "cluster_health", None))
        if free is None:
            unknown.append({"node": label, "reason": "no /var disk report"})
            continue
        if seen is None or (now - seen).total_seconds() > max_age_seconds:
            unknown.append({"node": label, "reason": "disk report is stale", "free_bytes": free})
            continue
        entry = {"node": label, "free_bytes": free}
        checked.append(entry)
        if free < need_bytes:
            short.append(entry)
    detail: dict[str, Any] = {
        "needed_bytes": need_bytes,
        "nodes": checked,
        "short": short,
        "unverified": unknown,
    }
    gib = 1024**3
    if short:
        names = ", ".join(f"{e['node']} ({e['free_bytes'] // gib} GiB free)" for e in short)
        return PreflightResult(
            name="disk_headroom",
            level="fail",
            message=(
                f"/var too small on {names}; need {need_bytes // gib} GiB "
                "(slot image + margin) — free space before upgrading"
            ),
            detail=detail,
        )
    if unknown:
        names = ", ".join(f"{e['node']} ({e['reason']})" for e in unknown)
        return PreflightResult(
            name="disk_headroom",
            level="warn",
            message=f"/var headroom unverified on {names}",
            detail=detail,
        )
    return PreflightResult(
        name="disk_headroom",
        level="ok",
        message=f"/var has room on all {len(checked)} node(s) (need {need_bytes // gib} GiB)",
        detail=detail,
    )


async def check_node_disk_headroom(
    *,
    nodes: list[str] | None = None,
    target_version: str | None = None,
    slot_image_size_bytes: int = 4 * 1024 * 1024 * 1024,
    safety_margin_bytes: int = 1 * 1024 * 1024 * 1024,
) -> PreflightResult:
    """Per-node ``/var`` headroom for appliance fleets (#1234).

    ``nodes`` narrows the judgement to those hostnames (matched as k8s Node names):
    a rolling run's chain passes the nodes it has still to upgrade. Upgrading
    a node shrinks its ``/var`` (it keeps the old slot's images beside the
    new ones), and a node the run has finished, or an approved row that is
    not part of the run, never stages this image; judging them failed the
    run's own next node (ddi-pg, nightly-20261012: both upgraded nodes short,
    the node left to upgrade with 8 GiB free). A named node with no row is
    unverified (``warn``). Plan passes no ``nodes`` and judges every row.

    ``target_version`` leaves out the rows that already report it, Plan and
    chain alike: such a node stages nothing (the chain's ``mirror_ready`` and
    ``stage`` skip a node whose ``installed_appliance_version`` is the
    target). So a new Plan after a failed run, which is the way out of it, is
    not refused on the nodes that run already upgraded. They are named in
    ``detail.on_target``.

    Falls back to :func:`check_disk_headroom` (the api container's own
    ``/var``) when there are no approved appliance rows — docker-compose /
    plain k8s — which is the only place that check is meaningful.
    """
    try:
        async with AsyncSessionLocal() as db:
            rows = list(
                (
                    await db.execute(
                        select(Appliance).where(
                            Appliance.state == APPLIANCE_STATE_APPROVED,
                            Appliance.deployment_kind == "appliance",
                        )
                    )
                )
                .scalars()
                .all()
            )
    except Exception as e:  # pragma: no cover - DB unavailable is its own signal
        logger.warning("preflight_node_disk_query_failed", error=str(e))
        return PreflightResult(
            name="disk_headroom",
            level="warn",
            message="Could not read per-node disk reports — check /var headroom manually.",
            detail={"error": str(e)},
        )
    if not rows:
        return check_disk_headroom(
            slot_image_size_bytes=slot_image_size_bytes,
            safety_margin_bytes=safety_margin_bytes,
        )
    need = slot_image_size_bytes + safety_margin_bytes
    missing: list[str] = []
    if nodes is not None:
        # #1757 — the Node name k3s gives a host is its lowercased hostname.
        wanted = {k8s_node_name(n) for n in nodes}
        rows = [r for r in rows if k8s_node_name(r.hostname) in wanted]
        missing = sorted(wanted - {k8s_node_name(r.hostname) for r in rows})
    on_target: list[str] = []
    if target_version:
        on_target = sorted(
            r.hostname or str(r.id) for r in rows if r.installed_appliance_version == target_version
        )
        rows = [r for r in rows if r.installed_appliance_version != target_version]
    result = judge_node_disk_headroom(rows, need_bytes=need, now=datetime.now(UTC))
    detail = {**result.detail, "on_target": on_target} if target_version else result.detail
    if missing and result.level != "fail":
        unknown = [{"node": n, "reason": "no appliance row"} for n in missing]
        names = ", ".join(f"{e['node']} ({e['reason']})" for e in unknown)
        return PreflightResult(
            name="disk_headroom",
            level="warn",
            message=f"/var headroom unverified on {names}",
            detail={**detail, "unverified": detail["unverified"] + unknown},
        )
    if not on_target:
        return result
    message = result.message
    if result.level == "ok":
        message = (
            f"{message}; already on {target_version}, nothing to stage: {', '.join(on_target)}"
        )
    return PreflightResult(name="disk_headroom", level=result.level, message=message, detail=detail)


async def check_mirror_disk_headroom(
    *,
    slot_image_id: uuid.UUID | None = None,
    slot_image_size_bytes: int = 4 * 1024 * 1024 * 1024,
    safety_margin_bytes: int = 1 * 1024 * 1024 * 1024,
) -> PreflightResult:
    """Mirror node has room for the slot image + a safety margin.

    #1709 — ``slot_image_id`` is the run's target when it is an uploaded
    image. An upload streams its bytes to the mirror, so when the mirror is
    short of the full need the check asks it (a HEAD, as the re-upload
    presence check does) whether it already holds that image; if it does,
    only the margin is needed. An external URL, an image the mirror does not
    hold, or a presence check that fails keep the full need.

    Phase B-only check — only fires when ``settings.slot_image_mirror_url``
    is set. Queries the mirror's ``/api/v1/appliance/internal/slot-
    images/_/disk-usage`` endpoint over the in-cluster Service to get
    the real PVC volume's free space; ``check_node_disk_headroom`` above
    covers each node's /var (#1234), which is not the mirror's volume.

    On docker-compose / non-mirror shapes returns ``ok`` with detail
    noting "no mirror configured" so the operator-facing report still
    shows the row but doesn't surface a false warning.
    """
    if not settings.slot_image_mirror_url:
        return PreflightResult(
            name="mirror_disk_headroom",
            level="ok",
            message="no mirror configured — local disk_headroom covers it",
            detail={"mirror_url": ""},
        )

    # Inline imports — the mirror client uses httpx which is a heavy-ish
    # import. Skipping it on the docker-compose path keeps the cold-
    # start cost on those deploys identical to pre-Phase-B.
    import httpx  # noqa: PLC0415

    from app.api.v1.appliance.slot_image_mirror import mirror_auth_token  # noqa: PLC0415

    zero_id = uuid.UUID(int=0)
    url = f"{settings.slot_image_mirror_url.rstrip('/')}/api/v1/appliance/internal/slot-images/_/disk-usage"
    headers = {"X-Mirror-Auth": mirror_auth_token("disk-usage", zero_id)}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            resp = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return PreflightResult(
            name="mirror_disk_headroom",
            level="warn",
            message=f"could not reach mirror Service: {exc}",
            detail={"url": url, "error": str(exc)},
        )
    if resp.status_code != 200:
        return PreflightResult(
            name="mirror_disk_headroom",
            level="warn",
            message=f"mirror returned {resp.status_code}",
            detail={"status": resp.status_code, "body": resp.text[:200]},
        )
    body = resp.json()
    free = int(body.get("free_bytes") or 0)
    total = int(body.get("total_bytes") or 0)
    need = slot_image_size_bytes + safety_margin_bytes
    on_mirror: bool | None = None
    if free < need and slot_image_id is not None:
        on_mirror = await _mirror_holds_image(slot_image_id)
        if on_mirror:
            need = safety_margin_bytes
    if free < need:
        return PreflightResult(
            name="mirror_disk_headroom",
            level="fail",
            message=(
                f"mirror has {free // (1024**3)} GiB free; "
                f"need {need // (1024**3)} GiB (slot image + margin)"
            ),
            detail={
                "free_bytes": free,
                "needed_bytes": need,
                "total_bytes": total,
                "path": body.get("path"),
                "slot_image_id": str(slot_image_id) if slot_image_id else None,
                "target_on_mirror": on_mirror,
            },
        )
    message = f"mirror: {free // (1024**3)} GiB free (need {need // (1024**3)} GiB)"
    if on_mirror:
        message = (
            f"mirror: {free // (1024**3)} GiB free; the target is already on the mirror, "
            f"so it needs only the {need // (1024**3)} GiB margin"
        )
    return PreflightResult(
        name="mirror_disk_headroom",
        level="ok",
        message=message,
        detail={
            "free_bytes": free,
            "needed_bytes": need,
            "total_bytes": total,
            "path": body.get("path"),
            "slot_image_id": str(slot_image_id) if slot_image_id else None,
            "target_on_mirror": on_mirror,
        },
    )


async def _mirror_holds_image(image_id: uuid.UUID) -> bool | None:
    """Does the slot-image mirror hold ``image_id``'s bytes? True / False,
    or None when it could not tell (unreachable, or an answer other than
    200 / 404). A HEAD costs headers, not the 1-4 GiB body (#1709)."""
    import httpx  # noqa: PLC0415

    from app.api.v1.appliance.slot_image_mirror import mirror_auth_token  # noqa: PLC0415

    url = (
        f"{settings.slot_image_mirror_url.rstrip('/')}"
        f"/api/v1/appliance/internal/slot-images/{image_id}"
    )
    headers = {"X-Mirror-Auth": mirror_auth_token("get", image_id)}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            resp = await client.head(url, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning(
            "preflight_mirror_presence_unreachable", image_id=str(image_id), error=str(exc)
        )
        return None
    if resp.status_code == 200:
        return True
    if resp.status_code == 404:
        return False
    logger.warning(
        "preflight_mirror_presence_unexpected", image_id=str(image_id), status=resp.status_code
    )
    return None


def check_version_path(
    *,
    target_version: str,
    current_version: str | None = None,
) -> PreflightResult:
    """Target is a valid forward jump from the current version.

    Versions are compared with :mod:`app.core.versions` (#1182), never as
    strings: CalVer (``YYYY.MM.DD-N``) until 1.0.0, SemVer from then on,
    and every SemVer release newer than every CalVer one.

    Rules:

    * The target must be a release. A dev or nightly build, or a
      placeholder like ``0.1.0``, is not one.
    * Target > current (no rollback through the upgrade flow — that's
      a separate slot-rollback button). SemVer → CalVer is backward.
    * A current version that is not a release (a dev or nightly build)
      can't be validated: warn, unless it is a nightly that already has
      the target, which is a rollback and fails.
    * Skip-release: warn when two CalVer tags are more than 90 days
      apart. We don't refuse because the appliance supports it via two
      rolling upgrades back to back, but the operator should know.
      SemVer tags carry no date, so between two SemVer releases the
      same warning fires when the jump crosses more than one major
      version (1.x to 3.x): 1.x to 2.x is the normal path, and minor
      and patch jumps never warn (#1182). The switch from CalVer to
      SemVer is never a skip.
    """
    current = current_version or canonical_version(settings.version, settings.app_version) or "dev"
    base_detail: dict[str, Any] = {"current": current, "target": target_version}
    target = parse_release(target_version)
    if target is None:
        return PreflightResult(
            name="version_path",
            level="fail",
            message=(
                f"target {target_version!r} is not a release version: expected "
                "YYYY.MM.DD-N before 1.0.0 or MAJOR.MINOR.PATCH from 1.0.0"
            ),
            detail=base_detail,
        )
    running = parse_release(current)
    if running is None:
        if includes_release(current, target_version):
            return PreflightResult(
                name="version_path",
                level="fail",
                message=(
                    f"current build {current!r} already includes {target_version}; "
                    "rolling upgrade only moves forward — use slot rollback to revert"
                ),
                detail=base_detail,
            )
        return PreflightResult(
            name="version_path",
            level="warn",
            message=(
                f"current version {current!r} is not a release (a dev or nightly "
                "build) — can't validate the upgrade path. Rolling upgrade from "
                "an untagged build is unsupported; do a full redeploy from a "
                "tagged release first."
            ),
            detail=base_detail,
        )
    if target <= running:
        return PreflightResult(
            name="version_path",
            level="fail",
            message=(
                f"target {target_version} is not newer than current "
                f"{current}; rolling upgrade only moves forward — use "
                "slot rollback to revert"
            ),
            detail=base_detail,
        )
    if running.tagged_on is not None and target.tagged_on is None:
        # The bridge to 1.0.0 (or later): every SemVer release is newer
        # than every CalVer one, and there is no date on the SemVer side
        # to measure a gap with.
        return PreflightResult(
            name="version_path",
            level="ok",
            message="forward jump across the switch from CalVer to SemVer",
            detail={**base_detail, "gap_days": None},
        )
    if target.tagged_on is None:
        # Both SemVer (a target newer than a SemVer release is SemVer
        # too). key is (1, major, minor, patch, pre).
        majors = target.key[1] - running.key[1]
        detail = {**base_detail, "gap_days": None, "gap_majors": majors}
        if majors > _SKIP_RELEASE_WARN_MAJORS:
            return PreflightResult(
                name="version_path",
                level="warn",
                message=(
                    f"target {target_version} is {majors} major versions newer "
                    f"than current {current}; consider stopping at each major "
                    "version in between"
                ),
                detail=detail,
            )
        return PreflightResult(
            name="version_path",
            level="ok",
            message=f"forward jump from {current} to {target_version}",
            detail=detail,
        )
    gap_days = (target.tagged_on - running.tagged_on).days
    if gap_days > _SKIP_RELEASE_WARN_DAYS:
        return PreflightResult(
            name="version_path",
            level="warn",
            message=(
                f"target is {gap_days} days newer than current "
                f"(>{_SKIP_RELEASE_WARN_DAYS} d); consider an intermediate stop"
            ),
            detail={**base_detail, "gap_days": gap_days},
        )
    return PreflightResult(
        name="version_path",
        level="ok",
        message=f"forward jump of {gap_days} days",
        detail={**base_detail, "gap_days": gap_days},
    )


def check_quorum(retry_budget_s: float = 0.0) -> PreflightResult:
    """Cluster size is odd + ≥ 3 + every node Ready.

    Reads the kubeapi via the existing SA mount. On docker-compose
    deployments (no SA) we report ``ok`` with detail noting "single-
    instance shape" — single-node has no rolling upgrade.

    We only count nodes with our role label so a customer who's
    joined extra worker-only nodes for app workloads doesn't get
    misreported here. The label is the same one used to gate every
    appliance workload: ``spatium.io/role=appliance``.
    """
    from app.services.appliance import k8s  # noqa: PLC0415 — avoid top-level

    try:
        cfg = k8s.get_config()
    except k8s.KubeapiUnavailableError:
        cfg = None
    if cfg is None:
        return PreflightResult(
            name="quorum",
            level="ok",
            message="docker-compose / single-instance shape — no quorum check",
            detail={"deployment": "single_instance"},
        )
    # Pull node list directly via _request — we don't have a public
    # list_nodes helper today and don't want to grow one for one caller.
    from urllib.parse import quote  # noqa: PLC0415

    label = "spatium.io/role=appliance"
    path = f"/api/v1/nodes?labelSelector={quote(label)}"
    try:
        # #2767 — a refused connection while one API server restarts is retried.
        status, body = kubeapi_retry.read_with_retry_blocking(
            lambda: k8s._request("GET", path),  # noqa: SLF001
            what="quorum_node_list",
            budget_s=retry_budget_s,
        )
    except k8s.KubeapiUnavailableError as exc:
        return PreflightResult(
            name="quorum",
            level="warn",
            message=f"kubeapi unreachable: {exc}",
            detail={"error": str(exc)},
        )
    if status != 200:
        return PreflightResult(
            name="quorum",
            level="warn",
            message=f"kubeapi node list returned {status}",
            detail={"status": status},
        )
    import json  # noqa: PLC0415

    try:
        data = json.loads(body)
    except ValueError:
        return PreflightResult(
            name="quorum",
            level="warn",
            message="kubeapi node list JSON parse failed",
            detail={},
        )
    items = data.get("items") or []
    n = len(items)
    ready_count = 0
    not_ready: list[str] = []
    for node in items:
        name = (node.get("metadata") or {}).get("name", "<unknown>")
        conditions = (node.get("status") or {}).get("conditions") or []
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
        if ready:
            ready_count += 1
        else:
            not_ready.append(name)
    if n < 3:
        return PreflightResult(
            name="quorum",
            level="fail",
            message=(
                f"only {n} appliance node(s) — rolling upgrade requires ≥ 3 "
                "(quorum-safe). Use single-node OS image upgrade instead."
            ),
            detail={"node_count": n},
        )
    if n % 2 == 0:
        return PreflightResult(
            name="quorum",
            level="fail",
            message=(
                f"even node count ({n}) — etcd quorum requires odd. "
                "Promote/demote to 3, 5, or 7 first."
            ),
            detail={"node_count": n},
        )
    if not_ready:
        return PreflightResult(
            name="quorum",
            level="fail",
            message=(
                f"{len(not_ready)} of {n} node(s) NotReady "
                f"({', '.join(not_ready)}); resolve before upgrading — "
                "rolling needs all healthy at start"
            ),
            detail={
                "node_count": n,
                "ready_count": ready_count,
                "not_ready": not_ready,
            },
        )
    return PreflightResult(
        name="quorum",
        level="ok",
        message=f"{n} appliance nodes, all Ready",
        detail={"node_count": n, "ready_count": ready_count},
    )


# ── Aggregator ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PreflightReport:
    """Aggregate of every check + a derived overall verdict."""

    target_version: str
    current_version: str
    overall: PreflightLevel  # worst level across results
    can_start: bool  # convenience: overall != "fail"
    results: list[PreflightResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_version": self.target_version,
            "current_version": self.current_version,
            "overall": self.overall,
            "can_start": self.can_start,
            "results": [asdict(r) for r in self.results],
        }


_DEFAULT_SLOT_IMAGE_BYTES = 4 * 1024 * 1024 * 1024

# #1919 — what a node's /var must take for an image of ``size_bytes``, as a
# multiple of it. Two writes, one after the other (spatium-upgrade-slot):
# the compressed ``.raw.xz`` is staged whole on /var, streamed through xz
# into the inactive partition and deleted; then, on the new slot's first
# boot, k3s imports that slot's container images into containerd on /var
# BESIDE the old slot's (spatiumddi-image-prune drops the oldest set only
# after the slot commits). The import is the larger of the two: it is the
# release's own images unpacked, ~1.6x the compressed slot image measured
# on a 1.9 GB image, and the staged file is 1x. 2x covers the larger with
# room; the 1 GiB margin stays on top for the etcd snapshot and logs. The
# mirror stores the compressed file only, so its need is 1x.
_NODE_NEED_IMAGE_MULTIPLE = 2


async def _slot_image_size(slot_image_id: uuid.UUID | None) -> int | None:
    """The run's uploaded image's ``size_bytes`` (the compressed artifact),
    or None when the Plan names none, the row is gone or zero, or the DB
    could not be read. None keeps each check's 4 GiB default, which fails
    closed (#1919)."""
    if slot_image_id is None:
        return None
    try:
        async with AsyncSessionLocal() as db:
            size = (
                await db.execute(
                    select(ApplianceUpgradeImage.size_bytes).where(
                        ApplianceUpgradeImage.id == slot_image_id
                    )
                )
            ).scalar_one_or_none()
    except Exception as e:  # pragma: no cover - DB unavailable keeps the default
        logger.warning("preflight_image_size_query_failed", error=str(e))
        return None
    if size is None or size <= 0:
        return None
    return int(size)


async def run_all(
    *,
    target_version: str,
    namespace: str | None = None,
    own_holder: str | None = None,
    slot_image_id: uuid.UUID | None = None,
    disk_nodes: list[str] | None = None,
) -> PreflightReport:
    """Run every check + return the aggregate report.

    ``own_holder`` is passed by a run that already holds the upgrade
    lease (see :func:`check_inflight_conflict`); Plan passes nothing.
    ``slot_image_id`` is the run's target when it is an uploaded image
    (#1709, :func:`check_mirror_disk_headroom`). ``disk_nodes`` is a
    rolling run's nodes still to upgrade (:func:`check_node_disk_headroom`,
    which also leaves out every node already on ``target_version``).

    Order doesn't matter (independent checks); we run them
    sequentially for now since none of them are slow. If any block
    of checks starts to dominate latency we can parallelise via
    ``asyncio.gather``.
    """
    with kubeapi_retry.request_deadline():
        return await _run_all(
            target_version=target_version,
            namespace=namespace,
            own_holder=own_holder,
            slot_image_id=slot_image_id,
            disk_nodes=disk_nodes,
        )


async def _run_all(
    *,
    target_version: str,
    namespace: str | None,
    own_holder: str | None,
    slot_image_id: uuid.UUID | None,
    disk_nodes: list[str] | None,
) -> PreflightReport:
    image_bytes = await _slot_image_size(slot_image_id)
    node_image_bytes = (
        image_bytes * _NODE_NEED_IMAGE_MULTIPLE if image_bytes else _DEFAULT_SLOT_IMAGE_BYTES
    )
    results: list[PreflightResult] = [
        # #2767 — both kubeapi reads here ride out a refused connection while
        # one API server restarts; off the event loop, since they sleep.
        await asyncio.to_thread(
            check_inflight_conflict,
            namespace=namespace,
            own_holder=own_holder,
            retry_budget_s=kubeapi_retry.READ_RETRY_BUDGET_S,
        ),
        await check_replication_lag(),
        await check_node_disk_headroom(
            nodes=disk_nodes,
            target_version=target_version,
            slot_image_size_bytes=node_image_bytes,
        ),
        await check_mirror_disk_headroom(
            slot_image_id=slot_image_id,
            slot_image_size_bytes=image_bytes or _DEFAULT_SLOT_IMAGE_BYTES,
        ),
        check_version_path(target_version=target_version),
        await asyncio.to_thread(check_quorum, retry_budget_s=kubeapi_retry.READ_RETRY_BUDGET_S),
        await check_kea_ha_version_skew(),
        await check_powerdns_lmdb_migration(),
        await check_etcd_snapshot_freshness(),
        await check_pre_upgrade_backup(),
    ]
    levels = {r.level for r in results}
    if "fail" in levels:
        overall: PreflightLevel = "fail"
    elif "warn" in levels:
        overall = "warn"
    else:
        overall = "ok"
    return PreflightReport(
        target_version=target_version,
        current_version=canonical_version(settings.version, settings.app_version) or "dev",
        overall=overall,
        can_start=overall != "fail",
        results=results,
    )


# Kea 3.0's HA hook cannot exchange lease updates with a peer older than this.
# 3.0 added the "released" lease state (value 3) to the updates partners send
# each other; a pre-2.7 peer rejects them outright. Upstream is explicit that
# every HA member must be upgraded at the same time.
_KEA_HA_MIN_COMPATIBLE_MAJOR = 3


def _kea_major(version: str | None) -> int | None:
    """Major version from a Kea version string ("3.0.3" → 3). None if unknown."""
    if not version:
        return None
    head = version.strip().split(".", 1)[0]
    try:
        return int(head)
    except ValueError:
        return None


async def check_kea_ha_version_skew() -> PreflightResult:
    """Warn when a rolling upgrade will disrupt a Kea HA pair (#637).

    The #296 orchestrator upgrades nodes **one at a time** — cordon, drain, swap
    slot, reboot, uncordon, next. That is exactly the sequence Kea 3.0's HA hook
    cannot survive when the pair starts on 2.6: mid-run one member is on 3.0 and
    its partner is still on 2.6, they reject each other's lease updates, and the
    pair falls out of sync until BOTH have crossed. There is no fix inside the
    orchestrator — the incompatibility is in Kea's wire protocol, and ISC's
    guidance is to upgrade every HA member together. So the honest thing is to
    tell the operator before they press Start.

    The versions compared are the ones each agent reads live off its Kea
    control socket (``dhcp_server.kea_version``) — what the daemons actually
    speak to each other now. An appliance's slot version says nothing about the
    Kea it runs, and a member that has never reported is UNKNOWN, never old.

    Two pieces of scoping matter, and getting either wrong turns this check into
    a liar:

    * **Only HA groups with a member on an appliance node.** The orchestrator
      only ever touches appliance nodes; docker / k8s DHCP agents upgrade
      through the manual copy-paste path and are never cordoned, drained or
      slot-swapped by this run. A group made only of those is never counted —
      two unrelated docker containers must not turn an appliance-cluster
      upgrade amber.

      Recognising an appliance node is the subtle part (#2179). The obvious
      predicate, ``dhcp_server.deployment_kind = 'appliance'``, is a trap: #170
      Wave C1 moved deployment telemetry onto the supervisor's heartbeat, so the
      DHCP agent never sends it and the column is NULL on every post-#170
      appliance — filtering on it made this check report "no Kea HA pairs" on
      every appliance cluster it was written for. Membership comes from
      ``orchestrated_server_condition`` instead, the rule
      ``check_powerdns_lmdb_migration`` shares: an approved appliance owning the
      row by FK or by the agent's host. The strictness the original column
      match was after survives in that rule — the appliance has to be approved
      and report ``deployment_kind = 'appliance'`` itself; an unclaimed row is
      never assumed to be one.
    * **Only *real* HA pairs.** HA is not "≥ 2 Kea members" — that is half the
      condition. ``_resolve_failover`` in ``services/dhcp/config_bundle.py``
      renders the HA hook only when there are ≥ 2 Kea members AND every one of
      them carries a non-empty ``ha_peer_url``; without a URL a peer cannot be
      reached for heartbeats or lease updates, so no HA relationship exists and
      there is nothing for an upgrade to disrupt. The predicate is evaluated
      over EVERY Kea member of the group, as the renderer does — not over the
      appliance members alone, which would miss a pair whose partner is a
      docker agent and invent one where a third, URL-less member suppresses HA.

    A pair with a member off the appliance fleet is still reported, and that
    member is named: this run upgrades only the appliance side, so converging
    the pair needs the other one upgraded separately.

    **This check never returns ``fail``.** A ``fail`` sets ``can_start=False``,
    and blocking the upgrade would be exactly backwards: if a pair is *already*
    split across Kea majors its HA is broken right now, and completing the
    rolling upgrade is what converges both members onto one version. Refusing to
    start would strand the operator in the broken state. So an already-mixed pair
    is a loud ``warn`` that says "proceeding will fix this", not a gate.
    """
    try:
        async with AsyncSessionLocal() as db:
            rows = (
                (
                    await db.execute(
                        select(
                            DHCPServerGroup.name.label("group_name"),
                            DHCPServer.name.label("server_name"),
                            DHCPServer.kea_version.label("kea_version"),
                            DHCPServer.ha_peer_url.label("ha_peer_url"),
                            orchestrated_server_condition(DHCPServer).label("on_appliance"),
                        )
                        .join(DHCPServer, DHCPServer.server_group_id == DHCPServerGroup.id)
                        .where(DHCPServer.driver == "kea")
                        .order_by(DHCPServerGroup.name, DHCPServer.name)
                    )
                )
                .mappings()
                .all()
            )
    except Exception as e:  # pragma: no cover - DB unavailable is its own signal
        logger.warning("preflight_kea_ha_skew_query_failed", error=str(e))
        return PreflightResult(
            name="kea_ha_version_skew",
            level="warn",
            message="Could not determine Kea versions — verify HA members manually.",
            detail={"error": str(e)},
        )

    by_group: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_group.setdefault(r["group_name"], []).append(dict(r))

    # Mirror _resolve_failover exactly: ≥ 2 Kea members AND every member has a
    # peer URL. Anything else renders no HA hook, so there is no HA to disrupt.
    # Then keep only the pairs this run touches: at least one appliance member.
    ha_groups = {
        name: members
        for name, members in by_group.items()
        if len(members) >= 2
        and all(m["ha_peer_url"] for m in members)
        and any(m["on_appliance"] for m in members)
    }
    if not ha_groups:
        return PreflightResult(
            name="kea_ha_version_skew",
            level="ok",
            message="No Kea HA pairs on appliance nodes — no same-window upgrade constraint.",
            detail={"ha_groups": 0},
        )

    # Classification is mutually exclusive, worst-first, so a group is reported
    # under exactly one heading and the structured detail can't contradict itself.
    mixed: list[str] = []
    pre_3: list[str] = []
    unknown: list[str] = []
    groups: list[dict[str, Any]] = []
    off_appliance: list[str] = []
    off_by_group: dict[str, list[str]] = {}
    for name, members in ha_groups.items():
        majors = {_kea_major(m["kea_version"]) for m in members}
        known = {m for m in majors if m is not None}
        affected = True
        if len(known) > 1:
            mixed.append(name)
        elif None in majors:
            # At least one member has never reported. Unknown, never "old" —
            # even if a sibling reports a pre-3.0 version, we can't say what the
            # silent one runs, so "unknown" is the honest heading.
            unknown.append(name)
        elif known and next(iter(known)) < _KEA_HA_MIN_COMPATIBLE_MAJOR:
            pre_3.append(name)
        else:
            affected = False
        if affected:
            outsiders = [m["server_name"] for m in members if not m["on_appliance"]]
            off_by_group[name] = outsiders
            off_appliance.extend(outsiders)
        groups.append(
            {
                "group": name,
                "members": [
                    {
                        "server": m["server_name"],
                        "kea_version": m["kea_version"],
                        "on_appliance": bool(m["on_appliance"]),
                    }
                    for m in members
                ],
            }
        )

    detail: dict[str, Any] = {
        "ha_groups": len(ha_groups),
        "mixed_major": mixed,
        "pre_3_0": pre_3,
        "unknown_version": unknown,
        "off_appliance_members": off_appliance,
        "groups": groups,
    }

    # A member this run does not upgrade cannot be converged by it — say so,
    # or "completing this upgrade fixes it" is false for that pair. Only the
    # outsiders of the groups the returned message names: a note naming a
    # member of a group the message never mentions reads as belonging to it.
    def off_note(named: list[str]) -> str:
        names = [s for g in named for s in off_by_group.get(g, [])]
        if not names:
            return ""
        many = len(names) > 1
        return (
            f" {'Members' if many else 'Member'} {', '.join(names)} "
            f"{'are' if many else 'is'} not on an appliance node, so this upgrade "
            f"does not touch {'them' if many else 'it'} — upgrade "
            f"{'them' if many else 'it'} separately to the same Kea major."
        )

    if mixed:
        return PreflightResult(
            name="kea_ha_version_skew",
            level="warn",
            message=(
                f"Kea HA {'pairs' if len(mixed) > 1 else 'pair'} {', '.join(mixed)} "
                "already span different Kea major versions, so HA lease sync is "
                "broken right now. Completing this upgrade is what converges every "
                "member onto one version — expect HA to stay degraded until it finishes."
                + off_note(mixed)
            ),
            detail=detail,
        )
    if pre_3:
        return PreflightResult(
            name="kea_ha_version_skew",
            level="warn",
            message=(
                f"Kea HA {'pairs' if len(pre_3) > 1 else 'pair'} {', '.join(pre_3)} "
                "run Kea < 3.0. This upgrade moves nodes one at a time, and Kea 3.0's "
                "HA hook cannot exchange lease updates with a pre-2.7 peer — so the "
                "pair will fall out of sync until every member has crossed. DHCP keeps "
                "serving throughout; only HA replication between the peers is affected."
                + off_note(pre_3)
            ),
            detail=detail,
        )
    if unknown:
        return PreflightResult(
            name="kea_ha_version_skew",
            level="warn",
            message=(
                f"Kea version unknown for {'groups' if len(unknown) > 1 else 'group'} "
                f"{', '.join(unknown)} (agent has not reported it yet). If those members "
                "are on Kea < 3.0, HA will be degraded mid-upgrade." + off_note(unknown)
            ),
            detail=detail,
        )
    return PreflightResult(
        name="kea_ha_version_skew",
        level="ok",
        message=f"All {len(ha_groups)} Kea HA group(s) already on Kea ≥ 3.0.",
        detail=detail,
    )


# PowerDNS 5.0's LMDB backend migrates the on-disk schema from v5 to v6 the
# first time it opens the database. Any pdns below this major writes/reads v5
# and cannot open a v6 database at all ("Somehow, we are not at schema version
# 5. Giving up").
_PDNS_LMDB_SCHEMA6_MAJOR = 5


def _pdns_major(version: str | None) -> int | None:
    """Major version from a pdns version string ("5.0.5" → 5). None if unknown."""
    if not version:
        return None
    head = version.strip().split(".", 1)[0]
    try:
        return int(head)
    except ValueError:
        return None


async def check_powerdns_lmdb_migration() -> PreflightResult:
    """Warn that a PowerDNS 4.x → 5.x upgrade is one-way for the database (#638).

    PowerDNS 5.0 silently and irreversibly migrates the LMDB schema (v5 → v6)
    the first time it opens the database — a read is enough, there is no
    opt-out, and upstream ships no downgrade. Afterwards pdns 4.9 cannot open
    the database at all.

    That interacts badly with everything the rolling upgrade relies on for
    recovery. The A/B slot rollback swaps the ROOTFS, while ``/var`` — where
    the LMDB lives — is the shared persistent partition and is untouched. So
    "roll back the node" leaves the older pdns crash-looping on a database it
    can no longer read, and Phase 8c's health-gated auto-revert drives straight
    into that state on its own.

    The agent image handles the data half: its entrypoint snapshots the
    database before the first 5.x start and fails closed if it cannot (see
    ``agent/dns/images/powerdns/lmdb-guard.sh``). What it cannot do is tell the
    operator, beforehand, that their rollback plan now has a second step. That
    is this check's whole job.

    Scoping:

    * **Only the PowerDNS driver.** BIND9 nodes keep zone data as text on disk
      and have no equivalent hazard.
    * **Only appliance nodes**, because the orchestrator only ever slot-swaps
      those; docker / k8s PowerDNS agents upgrade through the manual path and
      are never touched by this run.

      Identifying them is the subtle part. The obvious predicate —
      ``deployment_kind = 'appliance'`` — is a **trap on ``dns_server``** (and on
      ``dhcp_server``, where it made ``check_kea_ha_version_skew`` inert until
      #2179): #170 Wave C1 moved slot /
      deployment telemetry off the service containers onto the supervisor's
      heartbeat, so the DNS agent no longer sends ``deployment_kind`` at all
      and the column is NULL on every post-#170 appliance. Filtering on it
      would match nothing and report a cheerful "no PowerDNS nodes" on exactly
      the fleet this check exists for.

      So membership comes from ``orchestrated_server_condition``, the rule the
      Kea HA check shares so the two cannot drift apart again (#2179): an
      approved ``deployment_kind = 'appliance'`` appliance owning the row by
      FK, else by the agent-reported ``host``, which ``register`` fills with
      the appliance's hostname. ``deployment_kind`` on the server row stays in
      the OR for any agent that does still report it. The host match can in
      principle over-match an off-fleet agent an operator labelled with an
      appliance's hostname — acceptable for a warn-only check, and the same
      trade #305 accepted for a *destructive* one.

    **This check never returns ``fail``.** A ``fail`` sets ``can_start=False``,
    and blocking would be wrong twice over: the migration is a supported,
    data-preserving upgrade, and the snapshot makes it recoverable. The
    operator needs to be *informed*, not stopped.
    """
    try:
        async with AsyncSessionLocal() as db:
            rows = (
                (
                    await db.execute(
                        select(
                            DNSServer.name.label("server_name"),
                            DNSServer.daemon_version.label("daemon_version"),
                        )
                        .where(
                            DNSServer.driver == "powerdns",
                            orchestrated_server_condition(DNSServer),
                        )
                        .order_by(DNSServer.name)
                    )
                )
                .mappings()
                .all()
            )
    except Exception as e:  # pragma: no cover - DB unavailable is its own signal
        logger.warning("preflight_powerdns_lmdb_query_failed", error=str(e))
        return PreflightResult(
            name="powerdns_lmdb_migration",
            level="warn",
            message=(
                "Could not determine PowerDNS versions — if any appliance node runs "
                "PowerDNS 4.x, this upgrade migrates its database one-way."
            ),
            detail={"error": str(e)},
        )

    if not rows:
        return PreflightResult(
            name="powerdns_lmdb_migration",
            level="ok",
            message="No PowerDNS nodes on this appliance cluster — no LMDB migration to perform.",
            detail={"powerdns_nodes": 0},
        )

    servers = [dict(r) for r in rows]
    # Classification is mutually exclusive so a node appears under exactly one
    # heading: a reported major below 5, or nothing reported at all. A node
    # that reports an unparseable version counts as unknown, not as "old".
    pre_5: list[str] = []
    unknown: list[str] = []
    for s in servers:
        major = _pdns_major(s["daemon_version"])
        if major is None:
            unknown.append(s["server_name"])
        elif major < _PDNS_LMDB_SCHEMA6_MAJOR:
            pre_5.append(s["server_name"])

    detail: dict[str, Any] = {
        "powerdns_nodes": len(servers),
        "pre_5_0": pre_5,
        "unknown_version": unknown,
        "servers": [
            {"server": s["server_name"], "daemon_version": s["daemon_version"]} for s in servers
        ],
        # Repeated in the detail blob so it survives into audit / MCP output,
        # where the operator may never see the rendered message.
        "rollback_command": "spatium-pdns-lmdb-guard restore latest",
    }

    if pre_5 or unknown:
        affected = pre_5 + unknown
        # "unknown" covers both never-reported and unparseable. It stays
        # UNKNOWN — the warning is about the possibility, not a claim that
        # those nodes are old.
        qualifier = "" if not unknown else " (version unknown for some of them)"
        return PreflightResult(
            name="powerdns_lmdb_migration",
            level="warn",
            message=(
                f"PowerDNS {'nodes' if len(affected) > 1 else 'node'} "
                f"{', '.join(affected)} may still run pdns 4.x{qualifier}. "
                "PowerDNS 5.0 performs a ONE-WAY LMDB schema migration on first "
                "start — the A/B slot rollback swaps the rootfs but /var, where the "
                "database lives, is shared and is not reverted. The agent snapshots "
                "the database automatically before migrating; rolling a node back "
                "therefore means redeploying the old image AND running "
                "'spatium-pdns-lmdb-guard restore latest' in the DNS container. "
                "Zone data is preserved either way."
            ),
            detail=detail,
        )

    return PreflightResult(
        name="powerdns_lmdb_migration",
        level="ok",
        message=(
            f"All {len(servers)} PowerDNS node(s) already on pdns ≥ 5.0 — "
            "the LMDB schema migration has already happened."
        ),
        detail=detail,
    )


# The appliance's k3s runs ``etcd-snapshot-schedule-cron: "0 */6 * * *"``
# (appliance/mkosi.extra/etc/rancher/k3s/config.yaml). Plus an hour of
# grace so a snapshot that has just missed its slot — or a heartbeat that
# has not landed yet — does not read as a fault.
_ETCD_SNAPSHOT_MAX_AGE_S = 7 * 3600

# How far into the future a snapshot timestamp may sit before it is read
# as clock skew rather than as a very fresh snapshot. The timestamp comes
# off the seed's own clock and is relayed on a heartbeat, so a few
# seconds of disagreement is normal; five minutes is not, and a
# materially-future stamp is the one case where "age" silently passes the
# staleness test while meaning nothing. Same lesson as #925's beat
# heartbeat, where a future stamp read as perfectly fresh.
_ETCD_SNAPSHOT_FUTURE_GRACE_S = 300


def _newest_snapshot(snapshots: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, float | None]:
    """Newest entry by ``created_at`` and its age in seconds.

    Entries come from the seed's ``k3s etcd-snapshot list``, relayed on
    the heartbeat, so the shape is the seed's and unparseable timestamps
    are possible. Those are skipped rather than raising — an inventory
    we cannot read is reported as "no usable snapshot", which is the
    conservative reading.
    """
    now = datetime.now(UTC)
    newest: dict[str, Any] | None = None
    newest_at: datetime | None = None
    for snap in snapshots or []:
        raw = (snap or {}).get("created_at")
        if not raw:
            continue
        try:
            when = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        if newest_at is None or when > newest_at:
            newest, newest_at = snap, when
    if newest is None or newest_at is None:
        return None, None
    # Negative = the seed's clock is ahead of ours. Returned as-is; the
    # caller decides whether that is jitter to clamp or skew to report,
    # because silently taking max(0, age) would let a wildly-future stamp
    # pass the staleness test as "0 h old".
    return newest, (now - newest_at).total_seconds()


async def check_etcd_snapshot_freshness() -> PreflightResult:
    """How old is the newest etcd snapshot? (#974)

    Every k3s bump before v1.36 was same-minor, where an A/B slot revert
    IS the rollback: boot the previous slot and the node is as it was.
    Across a Kubernetes **minor** it is not. The k3s datastore lives on
    the persistent ``/var``, outside the slot, and an older apiserver is
    not supported against a store a newer one has written — so the
    rollback is slot revert **plus** an etcd restore from before the
    upgrade. That makes the age of the newest snapshot part of the
    upgrade's safety rather than a nicety, and it is the one input the
    operator can still act on while the Start button is unpressed.

    Nothing here can tell whether *this* upgrade crosses a minor: the
    target is an appliance release tag and the k3s version it bakes is not
    known to the control plane until the image boots. So the check
    reports what it can measure — how much history a restore would
    discard — and leaves the minor-or-not judgement to the operator, who
    has the release notes. The current k3s versions across the cluster
    ride along in ``detail`` for exactly that comparison.

    **Never ``fail``.** ``fail`` sets ``can_start=False``, and refusing
    to upgrade because a snapshot is stale would be the wrong lever: the
    fix is one ``k3s etcd-snapshot save`` on the seed, not abandoning
    the run. A ``warn`` that names the age and the command is the honest
    shape, matching ``check_kea_ha_version_skew``.

    Cheap by construction: the seed already reports ``k3s etcd-snapshot
    list`` into ``Appliance.etcd_snapshots`` on every heartbeat, so this
    is a single indexed read, not a new mechanism. Creating a fresh
    pre-upgrade snapshot still needs the host-side runner tracked in
    #296 — see ``per_node._step_etcd_snapshot``.
    """
    name = "etcd_snapshot_freshness"
    try:
        async with AsyncSessionLocal() as db:
            rows = (
                (
                    await db.execute(
                        select(Appliance).where(
                            Appliance.state == APPLIANCE_STATE_APPROVED,
                            Appliance.deployment_kind == "appliance",
                        )
                    )
                )
                .scalars()
                .all()
            )
    except Exception as e:  # pragma: no cover - DB unavailable is its own signal
        logger.warning("preflight_etcd_snapshot_query_failed", error=str(e))
        return PreflightResult(
            name=name,
            level="warn",
            message="Could not read the etcd snapshot inventory — check it manually.",
            detail={"error": str(e)},
        )

    if not rows:
        # Docker / plain-k8s control plane: no appliance rows, no k3s,
        # no A/B slots. Nothing this check is about applies.
        return PreflightResult(
            name=name,
            level="ok",
            message="No appliance nodes — etcd snapshot freshness does not apply.",
            detail={"appliances": 0},
        )

    k3s_versions = sorted({r.k3s_version for r in rows if r.k3s_version})
    primaries = [r for r in rows if r.cluster_role == CLUSTER_ROLE_PRIMARY]
    if len(primaries) > 1:
        # Two rows claiming to be the etcd seed is a fault in itself, and
        # picking whichever the database returned first would report one
        # node's inventory as if it were the cluster's. Say so instead.
        return PreflightResult(
            name=name,
            level="warn",
            message=(
                f"{len(primaries)} appliances claim cluster_role=primary "
                f"({', '.join(sorted(p.hostname for p in primaries))}), so the etcd seed is "
                "ambiguous and snapshot freshness cannot be established. Resolve the "
                "duplicate before starting."
            ),
            detail={
                "appliances": len(rows),
                "k3s_versions": k3s_versions,
                "primaries": sorted(p.hostname for p in primaries),
            },
        )
    seed = primaries[0] if primaries else None
    if seed is None and len(rows) == 1:
        # Single-node, pre-promote: cluster_role is still NULL but the
        # lone control-plane appliance IS the etcd seed.
        seed = rows[0]
    detail: dict[str, Any] = {
        "appliances": len(rows),
        "k3s_versions": k3s_versions,
        "max_age_hours": _ETCD_SNAPSHOT_MAX_AGE_S / 3600,
    }

    if seed is None:
        return PreflightResult(
            name=name,
            level="warn",
            message=(
                "Could not identify the etcd seed, so snapshot freshness is unknown. "
                "Confirm a recent snapshot exists before starting."
            ),
            detail=detail,
        )

    snapshots = list(seed.etcd_snapshots or [])
    newest, age_s = _newest_snapshot(snapshots)
    detail["seed"] = seed.hostname
    detail["snapshots"] = len(snapshots)
    if newest is not None and age_s is not None:
        detail["newest"] = newest.get("name")
        # Inside the grace window a small negative is clock jitter, not a
        # snapshot from the future. Report it as 0 rather than "-0.1 h".
        detail["age_hours"] = round(max(age_s, 0.0) / 3600, 1)

    advice = (
        "Take one with `k3s etcd-snapshot save` on the seed before starting — across a "
        "Kubernetes minor, rollback is a slot revert PLUS an etcd restore, so anything "
        "written since the newest snapshot is what a rollback would discard."
    )
    if newest is None:
        return PreflightResult(
            name=name,
            level="warn",
            message=f"The seed reports no usable etcd snapshot. {advice}",
            detail=detail,
        )
    if age_s is not None and age_s < -_ETCD_SNAPSHOT_FUTURE_GRACE_S:
        return PreflightResult(
            name=name,
            level="warn",
            message=(
                f"The newest etcd snapshot ({newest.get('name')}) is dated "
                f"{abs(age_s) / 3600:.1f} h in the FUTURE — the seed's clock disagrees with "
                "the control plane's, so its age cannot be trusted. Check NTP on the seed, "
                "then confirm a recent snapshot exists before starting."
            ),
            detail=detail,
        )
    if age_s is not None and age_s > _ETCD_SNAPSHOT_MAX_AGE_S:
        return PreflightResult(
            name=name,
            level="warn",
            message=(
                f"The newest etcd snapshot is {age_s / 3600:.1f} h old "
                f"({newest.get('name')}). {advice}"
            ),
            detail=detail,
        )
    return PreflightResult(
        name=name,
        level="ok",
        message=(
            f"Newest etcd snapshot is {max(age_s or 0.0, 0.0) / 3600:.1f} h old "
            f"({newest.get('name')}). A rollback across a Kubernetes minor restores "
            "to that point."
        ),
        detail=detail,
    )


async def check_pre_upgrade_backup() -> PreflightResult:
    """Is there a recent backup to go back to? (#1227)

    The upgrade migrates the database forward, and the database lives on the
    persistent ``/var``, not in a slot. After it, the release being left
    cannot start on that database: a slot rollback boots its code, its
    migrate step fails with ``Can't locate revision``, and its api never
    starts. So "roll back the slot" is not a way back on its own; a copy of
    the database from before the upgrade is. Nothing takes one automatically
    yet, so the newest successful backup IS the way back, and its age is how
    much would be lost using it.

    **Never ``fail``**, for the same reason as the etcd snapshot row: the fix
    is one backup run, not abandoning the upgrade. Reads
    ``backup_target.last_run_*``, which records the newest run whether it
    succeeded or not, so a target whose last run failed does not count even
    if an older run succeeded.
    """
    from app.models.backup import BackupTarget  # noqa: PLC0415

    name = "pre_upgrade_backup"
    try:
        async with AsyncSessionLocal() as db:
            appliances = (
                await db.execute(
                    select(Appliance.id)
                    .where(
                        Appliance.state == APPLIANCE_STATE_APPROVED,
                        Appliance.deployment_kind == "appliance",
                    )
                    .limit(1)
                )
            ).first()
            newest = (
                await db.execute(
                    select(BackupTarget.name, BackupTarget.last_run_at)
                    .where(
                        BackupTarget.enabled.is_(True),
                        BackupTarget.last_run_status == "success",
                        BackupTarget.last_run_at.is_not(None),
                    )
                    .order_by(BackupTarget.last_run_at.desc())
                    .limit(1)
                )
            ).first()
    except Exception as e:  # pragma: no cover - DB unavailable is its own signal
        logger.warning("preflight_backup_query_failed", error=str(e))
        return PreflightResult(
            name=name,
            level="warn",
            message="Could not read the backup targets — confirm a recent backup exists.",
            detail={"error": str(e)},
        )

    if appliances is None:
        # No A/B slots, so no slot rollback to protect.
        return PreflightResult(
            name=name,
            level="ok",
            message="No appliance nodes — slot rollback does not apply.",
            detail={"appliances": 0},
        )

    advice = (
        "This upgrade migrates the database forward, and the release you are "
        "leaving cannot run on it afterwards: a slot rollback alone does not bring "
        "it back. Run a backup (Administration → Backup) before starting, so a copy from "
        "before the upgrade exists."
    )
    if newest is None:
        return PreflightResult(
            name=name,
            level="warn",
            message=f"No backup target has a successful backup. {advice}",
            detail={"newest_backup_at": None, "target": None},
        )
    target_name, last_run_at = newest
    age_hours = (datetime.now(UTC) - last_run_at).total_seconds() / 3600
    detail = {
        "newest_backup_at": last_run_at.isoformat(),
        "target": target_name,
        "age_hours": round(age_hours, 1),
        "max_age_hours": _PRE_UPGRADE_BACKUP_MAX_AGE_HOURS,
    }
    if age_hours > _PRE_UPGRADE_BACKUP_MAX_AGE_HOURS:
        return PreflightResult(
            name=name,
            level="warn",
            message=(
                f"The newest successful backup ({target_name}) is "
                f"{age_hours:.0f} hours old. {advice}"
            ),
            detail=detail,
        )
    return PreflightResult(
        name=name,
        level="ok",
        message=f"Newest successful backup ({target_name}) is {age_hours:.1f} hours old.",
        detail=detail,
    )
