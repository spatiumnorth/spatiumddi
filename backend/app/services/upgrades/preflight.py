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

import shutil
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from sqlalchemy import select, text

from app.config import settings
from app.core.versions import includes_release, parse_release
from app.db import AsyncSessionLocal
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
)
from app.services.upgrades import mutex

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


# The skip-release warning's threshold, in days between two CalVer tags.
_SKIP_RELEASE_WARN_DAYS = 90


# ── Individual checks ─────────────────────────────────────────────────


def check_inflight_conflict(*, namespace: str | None = None) -> PreflightResult:
    """Refuses if another upgrade is already in flight cluster-wide.

    Reads the ``spatium-upgrade-lock`` Lease; if it's held + not
    expired we ``fail`` with the holder's identity. An expired lease
    is fine (the previous holder crashed before releasing — we'll
    take over on acquire).
    """
    state = mutex.get_state(namespace=namespace)
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
    streaming = [r for r in replicas if r["state"] == "streaming"]
    lagging = [r for r in streaming if r["lag_bytes"] > threshold_bytes]
    not_streaming = [r for r in replicas if r["state"] != "streaming"]
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


async def check_mirror_disk_headroom(
    *,
    slot_image_size_bytes: int = 4 * 1024 * 1024 * 1024,
    safety_margin_bytes: int = 1 * 1024 * 1024 * 1024,
) -> PreflightResult:
    """Mirror node has room for the slot image + a safety margin.

    Phase B-only check — only fires when ``settings.slot_image_mirror_url``
    is set. Queries the mirror's ``/api/v1/appliance/internal/slot-
    images/_/disk-usage`` endpoint over the in-cluster Service to get
    the real PVC volume's free space; ``check_disk_headroom`` above
    looks at the api pod's /var which isn't where the slot image
    actually lands in mirror mode.

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
            },
        )
    return PreflightResult(
        name="mirror_disk_headroom",
        level="ok",
        message=(f"mirror: {free // (1024**3)} GiB free " f"(need {need // (1024**3)} GiB)"),
        detail={
            "free_bytes": free,
            "needed_bytes": need,
            "total_bytes": total,
            "path": body.get("path"),
        },
    )


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
      rolling upgrades back to back, but the operator should know. A
      jump that involves a SemVer version has no dates to compare, so
      it gets no such warning (#1182).
    """
    current = current_version or settings.version or "dev"
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
    if running.tagged_on is None or target.tagged_on is None:
        # At least one side is SemVer: there is no date to measure a gap
        # with. What should count as skipping releases under SemVer is
        # still open (#1182); until then the jump is reported as forward.
        crossing = running.tagged_on is not None
        return PreflightResult(
            name="version_path",
            level="ok",
            message=(
                "forward jump across the switch from CalVer to SemVer"
                if crossing
                else f"forward jump from {current} to {target_version}"
            ),
            detail={**base_detail, "gap_days": None},
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


def check_quorum() -> PreflightResult:
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
        status, body = k8s._request("GET", path)  # noqa: SLF001
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


async def run_all(
    *,
    target_version: str,
    namespace: str | None = None,
) -> PreflightReport:
    """Run every check + return the aggregate report.

    Order doesn't matter (independent checks); we run them
    sequentially for now since none of them are slow. If any block
    of checks starts to dominate latency we can parallelise via
    ``asyncio.gather``.
    """
    results: list[PreflightResult] = [
        check_inflight_conflict(namespace=namespace),
        await check_replication_lag(),
        check_disk_headroom(),
        await check_mirror_disk_headroom(),
        check_version_path(target_version=target_version),
        check_quorum(),
        await check_kea_ha_version_skew(),
        await check_powerdns_lmdb_migration(),
        await check_etcd_snapshot_freshness(),
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
        current_version=settings.version or "dev",
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

    Two pieces of scoping matter, and getting either wrong turns this check into
    a liar that blocks unrelated work:

    * **Only appliance nodes.** The orchestrator only ever touches appliance
      nodes; docker / k8s DHCP agents upgrade through the manual copy-paste path
      and are never cordoned, drained or slot-swapped by this run. Counting them
      would let two unrelated docker containers veto an appliance-cluster
      upgrade. ``deployment_kind`` is matched strictly against ``appliance`` (an
      ``appliance`` OR ``NULL`` fallback would lie about a row that has not
      checked in yet — same convention as the Upgrade / Reboot affordances).
    * **Only *real* HA pairs.** HA is not "≥ 2 Kea members" — that is half the
      condition. ``_resolve_failover`` in ``services/dhcp/config_bundle.py``
      renders the HA hook only when there are ≥ 2 Kea members AND every one of
      them carries a non-empty ``ha_peer_url``; without a URL a peer cannot be
      reached for heartbeats or lease updates, so no HA relationship exists and
      there is nothing for an upgrade to disrupt. This check must use the same
      predicate or it invents HA pairs that the renderer never built.

    **This check never returns ``fail``.** A ``fail`` sets ``can_start=False``,
    and blocking the upgrade would be exactly backwards: if a pair is *already*
    split across Kea majors its HA is broken right now, and completing the
    rolling upgrade is what converges both members onto one version. Refusing to
    start would strand the operator in the broken state. So an already-mixed pair
    is a loud ``warn`` that says "proceeding will fix this", not a gate.
    """
    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("""
                            SELECT g.name         AS group_name,
                                   s.name         AS server_name,
                                   s.kea_version  AS kea_version,
                                   s.ha_peer_url  AS ha_peer_url
                            FROM dhcp_server_group g
                            JOIN dhcp_server s ON s.server_group_id = g.id
                            WHERE s.driver = 'kea'
                              AND s.deployment_kind = 'appliance'
                            ORDER BY g.name, s.name
                            """))).mappings().all()
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
    ha_groups = {
        name: members
        for name, members in by_group.items()
        if len(members) >= 2 and all(m["ha_peer_url"] for m in members)
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
    for name, members in ha_groups.items():
        majors = {_kea_major(m["kea_version"]) for m in members}
        known = {m for m in majors if m is not None}
        if len(known) > 1:
            mixed.append(name)
        elif None in majors:
            # At least one member has never reported. Unknown, never "old" —
            # even if a sibling reports a pre-3.0 version, we can't say what the
            # silent one runs, so "unknown" is the honest heading.
            unknown.append(name)
        elif known and next(iter(known)) < _KEA_HA_MIN_COMPATIBLE_MAJOR:
            pre_3.append(name)
        groups.append(
            {
                "group": name,
                "members": [
                    {"server": m["server_name"], "kea_version": m["kea_version"]} for m in members
                ],
            }
        )

    detail: dict[str, Any] = {
        "ha_groups": len(ha_groups),
        "mixed_major": mixed,
        "pre_3_0": pre_3,
        "unknown_version": unknown,
        "groups": groups,
    }

    if mixed:
        return PreflightResult(
            name="kea_ha_version_skew",
            level="warn",
            message=(
                f"Kea HA {'pairs' if len(mixed) > 1 else 'pair'} {', '.join(mixed)} "
                "already span different Kea major versions, so HA lease sync is "
                "broken right now. Completing this upgrade is what converges every "
                "member onto one version — expect HA to stay degraded until it finishes."
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
                "are on Kea < 3.0, HA will be degraded mid-upgrade."
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
      ``deployment_kind = 'appliance'``, which is what ``check_kea_ha_version_skew``
      uses — is a **trap on ``dns_server``**: #170 Wave C1 moved slot /
      deployment telemetry off the service containers onto the supervisor's
      heartbeat, so the DNS agent no longer sends ``deployment_kind`` at all
      and the column is NULL on every post-#170 appliance. Filtering on it
      would match nothing and report a cheerful "no PowerDNS nodes" on exactly
      the fleet this check exists for.

      So match the way ``_cascade_delete_appliance_children`` already does
      (#305): the FK when it is set, else the agent-reported ``host``, which
      ``register`` fills with the appliance's hostname. ``deployment_kind``
      stays in the OR for any agent that does still report it. The host match
      can in principle over-match an off-fleet server an operator labelled
      with an appliance's hostname — acceptable for a warn-only check, and the
      same trade #305 accepted for a *destructive* one.

    **This check never returns ``fail``.** A ``fail`` sets ``can_start=False``,
    and blocking would be wrong twice over: the migration is a supported,
    data-preserving upgrade, and the snapshot makes it recoverable. The
    operator needs to be *informed*, not stopped.
    """
    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("""
                            SELECT s.name           AS server_name,
                                   s.daemon_version AS daemon_version
                            FROM dns_server s
                            WHERE s.driver = 'powerdns'
                              AND (
                                    s.appliance_id IS NOT NULL
                                 OR s.deployment_kind = 'appliance'
                                 OR EXISTS (
                                        SELECT 1 FROM appliance a
                                        WHERE a.hostname = s.host
                                    )
                              )
                            ORDER BY s.name
                            """))).mappings().all()
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
    target is a CalVer appliance tag and the k3s version it bakes is not
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
