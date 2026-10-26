import { HardDrive } from "lucide-react";

import type { VarDiskFinding } from "@/lib/api";
import { storageSeverityClass } from "@/lib/storage-health";
import { cn } from "@/lib/utils";

/**
 * #2400 — a node whose /var is low, or whose kubelet reports DiskPressure.
 *
 * Renders the server's verdict only (the evaluator behind the
 * `appliance_disk_usage` alert), so this panel and the alert cannot disagree.
 * Renders nothing when there is no finding.
 */
export function VarDiskWarning({
  finding,
  compact = false,
}: {
  finding: VarDiskFinding | null | undefined;
  compact?: boolean;
}) {
  if (!finding) return null;
  return (
    <div
      role="alert"
      className={cn(
        "flex items-start gap-1.5 rounded-md border",
        compact ? "px-1.5 py-1 text-[10px]" : "px-2 py-1.5 text-xs",
        storageSeverityClass(finding.severity),
      )}
    >
      <HardDrive
        className={cn("mt-0.5 shrink-0", compact ? "h-2.5 w-2.5" : "h-3 w-3")}
      />
      <span className="min-w-0 break-words">
        <span className="font-medium">
          {finding.severity === "critical"
            ? "Disk space critical"
            : "Disk space low"}
          {finding.free_pct != null &&
            ` · ${Math.round(finding.free_pct)}% free`}
          :
        </span>{" "}
        {finding.detail}
      </span>
    </div>
  );
}
