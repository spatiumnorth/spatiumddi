"""Per-disk SMART / wear classification (#4731).

The supervisor reports a reduced ``smartctl --json -a`` reading per
physical disk inside its ``cluster_health["disk_health"]`` dict
(``read_disk_health`` in ``agent/supervisor/spatium_supervisor/
appliance_state.py``). This module turns that reading into findings and is
the ONLY place the decision is made: the two alert matchers, the
``find_appliance_disk_health`` copilot tool and the API schema all call it,
so the Fleet chip and the alert cannot disagree about one disk.

**A disk that hides SMART is "not available", never healthy.** A VM's
virtual disk and a RAID controller's volume answer smartctl with no
verdict. They produce no finding and no clean status; ``summarise`` counts
them separately so every surface can say so.

**Two rules, one classifier.** ``smart`` findings (the disk says it is
failing, remaps or cannot read sectors, has exhausted its spare capacity)
feed ``appliance_disk_smart_failing``; ``wear`` findings (life used at or
above an operator-tunable percentage) feed ``appliance_disk_wear_high``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

#: Default wear (percentage of rated life used) that raises a warning.
DEFAULT_WEAR_THRESHOLD = 90

#: A reading older than this is not a reading. The runner fires hourly.
REPORT_MAX_AGE_SECONDS = 3 * 3600 + 600

RULE_SMART = "smart"
RULE_WEAR = "wear"

_SEVERITY_ORDER = ("critical", "warning")


@dataclass(frozen=True)
class DiskFinding:
    #: ``critical`` or ``warning``.
    severity: str
    #: ``smart`` or ``wear`` — which alert rule owns it.
    rule: str
    #: ``smart_failed`` / ``pending_sectors`` / ``reallocated_sectors`` /
    #: ``media_errors`` / ``spare_low`` / ``wear``.
    kind: str
    #: Device name (``sda`` / ``nvme0n1``).
    disk: str
    #: Operator-facing sentence, complete on its own.
    detail: str


def _num(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _label(disk: dict[str, Any]) -> str:
    name = str(disk.get("name") or "?")
    model = disk.get("model")
    return f"{name} ({model})" if model else name


def is_current(block: Any, now: float | None = None) -> bool:
    """True when ``block`` is a reading taken recently enough to act on."""
    if not isinstance(block, dict):
        return False
    at = _num(block.get("collected_at"))
    if at is None:
        return False
    return (now if now is not None else time.time()) - at <= REPORT_MAX_AGE_SECONDS


def has_disk_report(cluster_health: Any) -> bool:
    """True when the supervisor shipped a ``disk_health`` block at all
    (old supervisors and non-appliance hosts do not)."""
    return isinstance(cluster_health, dict) and isinstance(cluster_health.get("disk_health"), dict)


def _disk_findings(disk: dict[str, Any], wear_threshold: int) -> list[DiskFinding]:
    name = str(disk.get("name") or "?")
    label = _label(disk)
    out: list[DiskFinding] = []
    if disk.get("smart_passed") is False:
        out.append(
            DiskFinding(
                "critical",
                RULE_SMART,
                "smart_failed",
                name,
                f"Disk {label} reports SMART overall-health FAILED — the drive "
                "expects to fail. Replace it and restore from backup or a mirror.",
            )
        )
    pending = _num(disk.get("pending_sectors"))
    if pending:
        out.append(
            DiskFinding(
                "warning",
                RULE_SMART,
                "pending_sectors",
                name,
                f"Disk {label} has {pending} sector(s) waiting to be remapped "
                "(unreadable right now) — an early sign of media failure.",
            )
        )
    realloc = _num(disk.get("reallocated_sectors"))
    if realloc:
        out.append(
            DiskFinding(
                "warning",
                RULE_SMART,
                "reallocated_sectors",
                name,
                f"Disk {label} has remapped {realloc} bad sector(s).",
            )
        )
    media = _num(disk.get("media_errors"))
    if media:
        out.append(
            DiskFinding(
                "warning",
                RULE_SMART,
                "media_errors",
                name,
                f"Disk {label} has logged {media} unrecovered media / data-integrity error(s).",
            )
        )
    spare = _num(disk.get("available_spare"))
    spare_min = _num(disk.get("available_spare_threshold"))
    if spare is not None and spare_min is not None and spare <= spare_min:
        out.append(
            DiskFinding(
                "critical",
                RULE_SMART,
                "spare_low",
                name,
                f"Disk {label} has {spare}% spare capacity left, at or below its "
                f"{spare_min}% critical threshold.",
            )
        )
    used = _num(disk.get("percentage_used"))
    if used is not None and used >= wear_threshold:
        out.append(
            DiskFinding(
                "critical" if used >= 100 else "warning",
                RULE_WEAR,
                "wear",
                name,
                f"Disk {label} has used {used}% of its rated endurance "
                f"(threshold {wear_threshold}%).",
            )
        )
    return out


def evaluate_disks(
    block: Any,
    *,
    wear_threshold: int = DEFAULT_WEAR_THRESHOLD,
    rule: str | None = None,
) -> list[DiskFinding]:
    """Findings for one node's ``disk_health`` block, worst first.

    ``rule`` limits the result to ``smart`` or ``wear`` findings. A missing
    or malformed block yields nothing: no reading is UNKNOWN, which the
    callers distinguish with :func:`has_disk_report`.
    """
    if not isinstance(block, dict):
        return []
    out: list[DiskFinding] = []
    for disk in block.get("disks") or []:
        if isinstance(disk, dict):
            out.extend(_disk_findings(disk, wear_threshold))
    if rule is not None:
        out = [f for f in out if f.rule == rule]
    out.sort(key=lambda f: _SEVERITY_ORDER.index(f.severity))
    return out


def worst_severity(findings: list[DiskFinding]) -> str | None:
    for sev in _SEVERITY_ORDER:
        if any(f.severity == sev for f in findings):
            return sev
    return None


def summarise(block: Any) -> dict[str, Any]:
    """Counts the surfaces show next to the chip."""
    disks = [d for d in (block.get("disks") if isinstance(block, dict) else None) or []]
    disks = [d for d in disks if isinstance(d, dict)]
    return {
        "disk_count": len(disks),
        "smart_available_count": sum(1 for d in disks if d.get("smart_available") is True),
        "not_available_count": sum(1 for d in disks if d.get("smart_available") is not True),
    }
