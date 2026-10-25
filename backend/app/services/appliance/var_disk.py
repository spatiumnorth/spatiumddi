"""An appliance node's ``/var`` headroom, judged against kubelet eviction (#2400).

``/var`` on the appliance holds everything that grows: container images,
the database, the upgrade-image store and the node-side staging copy of a
slot image. The kubelet evicts pods at ``nodefs.available<5%`` and, once it
has started, keeps evicting until a further ``evictionMinimumReclaim`` (10 %)
is free — so a node that dips under 5 % is not healthy again until 15 % is
free (:data:`upgrade_image_space.EVICTION_HEADROOM_PCT`). On a single-node
appliance the evicted pods are the api, worker and supervisor, and nothing
said so until they died.

One reader and one evaluator, shared by the Fleet row, the Cluster node
card, the copilot's fleet tools and the slot-upgrade scheduling pre-flight.
The alert is NOT a second implementation: it is the default-on
``appliance_disk_usage`` rule (#2240), and this evaluator's warning and
critical lines are the same two numbers it uses (80 % / 87 % used, counted
the way the supervisor reports ``used``), pinned equal by a test, so the
Fleet warning and the alert cannot disagree about a node. What this adds is
the kubelet's ``DiskPressure`` condition, which the Fleet and Cluster views
have (the alert evaluates in the worker, which does not).

The reading is the supervisor's ``host_disk_partitions`` entry for ``/var``
(folded into ``cluster_health`` on every heartbeat, #402). ``available_bytes``
(statvfs ``f_bavail``) is what the kubelet measures; a supervisor too old to
send it leaves only ``total - used`` (``f_bfree``), which includes ext4's 5 %
root reserve and so reads optimistic. That fallback is used rather than
reporting nothing, and marked as such.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# The kubelet's hard nodefs threshold (``eviction-hard`` in
# appliance/mkosi.extra/etc/rancher/k3s/config.yaml) plus k3s's built-in
# ``evictionMinimumReclaim`` of 10 % (not set in that file; k3s's own
# default). The control plane cannot read the kubelet's live config without
# the broad ``nodes/proxy`` grant #983 is retiring, so these are the shipped
# values. Keep in step with ``_EVICTION_HEADROOM_PCT`` in spatium-upgrade-slot.
EVICTION_HARD_PCT = 5
EVICTION_MINIMUM_RECLAIM_PCT = 10
EVICTION_HEADROOM_PCT = EVICTION_HARD_PCT + EVICTION_MINIMUM_RECLAIM_PCT

# The ``appliance_disk_usage`` alert's lines (``alerts._APPLIANCE_DISK_USAGE
# _DEFAULT_PCT`` / ``_APPLIANCE_DISK_CRITICAL_PCT``), in the same terms: percent
# of /var USED, counted as the supervisor reports it (``blocks - bfree``, so
# ext4's 5 % root reserve counts as free). A test asserts they are equal.
WARN_USED_PCT = 80
CRITICAL_USED_PCT = 87

# A reading older than this says nothing about now (the supervisor heartbeats
# every ~30 s). Matches the rolling pre-flight's freshness window (#1234).
READING_MAX_AGE_SECONDS = 10 * 60

_MIB = 1024 * 1024


@dataclass(frozen=True)
class VarDiskReading:
    total_bytes: int
    free_bytes: int
    # True when ``free_bytes`` is the kubelet's own measure (f_bavail);
    # False when it fell back to ``total - used`` from an older supervisor.
    exact: bool
    # ``used_bytes`` as reported (``blocks - bfree``), the alert's own
    # measure; None when the supervisor sent no such figure.
    used_bytes: int | None = None

    @property
    def free_pct(self) -> float:
        return 100.0 * self.free_bytes / self.total_bytes

    @property
    def alert_used_pct(self) -> float:
        """Percent used in the ``appliance_disk_usage`` alert's terms."""
        if self.used_bytes is not None:
            return 100.0 * self.used_bytes / self.total_bytes
        return 100.0 - self.free_pct


@dataclass(frozen=True)
class VarDiskFinding:
    severity: str  # "warning" | "critical"
    free_pct: float | None
    detail: str


def _int(v: Any) -> int | None:
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return v


def var_disk_reading(cluster_health: Any) -> VarDiskReading | None:
    """The ``/var`` reading from an appliance's ``cluster_health`` JSONB.

    ``None`` = no usable reading (no key, no ``/var`` entry, malformed).
    That is UNKNOWN — never zero free and never plenty.
    """
    if not isinstance(cluster_health, dict):
        return None
    parts = cluster_health.get("host_disk_partitions")
    if not isinstance(parts, list):
        return None
    for p in parts:
        if not isinstance(p, dict) or p.get("mount") != "/var":
            continue
        total = _int(p.get("total_bytes"))
        if total is None or total <= 0:
            return None
        avail = _int(p.get("available_bytes"))
        used = _int(p.get("used_bytes"))
        if avail is not None:
            return VarDiskReading(
                total,
                max(min(avail, total), 0),
                exact=True,
                used_bytes=min(used, total) if used is not None and used >= 0 else None,
            )
        if used is None:
            return None
        return VarDiskReading(total, max(total - used, 0), exact=False, used_bytes=min(used, total))
    return None


def reading_is_fresh(last_seen_at: datetime | None, now: datetime | None = None) -> bool:
    if last_seen_at is None:
        return False
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=UTC)
    now = now or datetime.now(UTC)
    return (now - last_seen_at).total_seconds() <= READING_MAX_AGE_SECONDS


def evaluate_var_disk(
    reading: VarDiskReading | None,
    *,
    disk_pressure: bool | None = None,
    warn_used_pct: float = WARN_USED_PCT,
) -> VarDiskFinding | None:
    """``None`` when ``/var`` is fine (or unknown), else a finding.

    * The kubelet reporting ``DiskPressure`` is **critical**: it is
      evicting pods now, and keeps doing so until 15 % is free.
    * At :data:`CRITICAL_USED_PCT` used is **critical**, the
      ``appliance_disk_usage`` alert's own line: a few points before the
      kubelet starts evicting, and once it does it holds until 15 % is free.
    * At ``warn_used_pct`` used is a **warning**.
    """
    pct = reading.free_pct if reading is not None else None
    used_pct = reading.alert_used_pct if reading is not None else None
    numbers = ""
    if reading is not None:
        numbers = (
            f"{reading.free_bytes // _MIB} MiB of {reading.total_bytes // _MIB} MiB "
            f"free on /var ({pct:.0f}%)"
        )
    if disk_pressure:
        return VarDiskFinding(
            severity="critical",
            free_pct=pct,
            detail=(
                "The kubelet reports DiskPressure and is evicting pods"
                + (f"; {numbers}" if numbers else "")
                + f". It keeps evicting until {EVICTION_HEADROOM_PCT}% of /var is free. "
                "Delete unused upgrade images in Fleet to free space."
            ),
        )
    if reading is None or pct is None or used_pct is None:
        return None
    if used_pct >= CRITICAL_USED_PCT:
        return VarDiskFinding(
            severity="critical",
            free_pct=pct,
            detail=(
                f"{numbers}; {used_pct:.0f}% used, at or past the {CRITICAL_USED_PCT}% "
                "critical line: one large write (an upgrade image, an image pull) can "
                "push the node into kubelet eviction, which then holds until "
                f"{EVICTION_HEADROOM_PCT}% is free again. "
                "Delete unused upgrade images in Fleet to free space."
            ),
        )
    if used_pct >= warn_used_pct:
        return VarDiskFinding(
            severity="warning",
            free_pct=pct,
            detail=(
                f"{numbers}; {used_pct:.0f}% used, at or past the {warn_used_pct:.0f}% "
                f"warning level. The kubelet starts evicting at 5% free and does not "
                f"stop until {EVICTION_HEADROOM_PCT}% is free; an upgrade image needs "
                "room on top of that."
            ),
        )
    return None


def staging_shortfall(reading: VarDiskReading, image_bytes: int, hostname: str) -> str | None:
    """None when staging ``image_bytes`` on the node leaves the eviction
    headroom free, else a sentence naming the numbers (#2400)."""
    keep = reading.total_bytes * EVICTION_HEADROOM_PCT // 100
    if reading.free_bytes - image_bytes >= keep:
        return None
    return (
        f"Not enough free disk space on {hostname} to stage this upgrade: the node "
        f"downloads the image to /var ({image_bytes // _MIB} MiB), and "
        f"{keep // _MIB} MiB ({EVICTION_HEADROOM_PCT}% of /var) must stay free "
        f"afterwards or the kubelet will evict the control plane, but only "
        f"{reading.free_bytes // _MIB} MiB of {reading.total_bytes // _MIB} MiB is free. "
        f"Free at least {(image_bytes + keep - reading.free_bytes) // _MIB + 1} MiB "
        f"(delete unused upgrade images in Fleet) and retry."
    )


def var_disk_fields(cluster_health: Any, last_seen_at: datetime | None) -> dict[str, Any]:
    """The /var half of an appliance row for the copilot's fleet tools.

    ``var_free_bytes`` / ``var_total_bytes`` are None when there is no
    reading (UNKNOWN, not empty). The finding is only judged on a fresh
    reading, as everywhere else.
    """
    reading = var_disk_reading(cluster_health)
    finding = evaluate_var_disk(reading) if reading_is_fresh(last_seen_at) else None
    return {
        "var_free_bytes": reading.free_bytes if reading else None,
        "var_total_bytes": reading.total_bytes if reading else None,
        "var_disk_finding": (
            {"severity": finding.severity, "free_pct": finding.free_pct, "detail": finding.detail}
            if finding
            else None
        ),
    }
