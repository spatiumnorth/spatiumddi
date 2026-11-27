/**
 * Presentation helpers for per-disk SMART / wear (#4731).
 *
 * No classification here: whether a disk is failing or worn is decided
 * once in `backend/app/services/appliance/disk_health.py` and shipped as
 * `disk_findings` / `disk_worst_severity`. This only chooses the chip label
 * and style, and the one rule that matters for rendering: a node whose
 * disks hide SMART (a VM) is "not available", never green.
 */
import {
  storageSeverityClass,
  STORAGE_SEVERITY_CLASSES,
} from "./storage-health";

export interface DiskChipInput {
  disk_reported: boolean;
  disk_worst_severity: string | null;
  disk_smart_available_count: number;
  disk_count: number;
}

export interface DiskChip {
  label: string;
  className: string;
}

/** The Fleet row's chip, or null when the node never reported (no chip). */
export function diskChip(row: DiskChipInput): DiskChip | null {
  if (!row.disk_reported) return null;
  if (row.disk_worst_severity === "critical") {
    return {
      label: "disk: failing",
      className: storageSeverityClass("critical"),
    };
  }
  if (row.disk_worst_severity === "warning") {
    return {
      label: "disk: attention",
      className: storageSeverityClass("warning"),
    };
  }
  if (row.disk_smart_available_count === 0) {
    return {
      label: "disk: n/a",
      className: STORAGE_SEVERITY_CLASSES.unknown,
    };
  }
  return { label: "disk: ok", className: storageSeverityClass(null) };
}

/** `12,345 h` / `—`. */
export function fmtPowerOn(hours: number | null | undefined): string {
  return hours == null ? "—" : `${hours.toLocaleString()} h`;
}
