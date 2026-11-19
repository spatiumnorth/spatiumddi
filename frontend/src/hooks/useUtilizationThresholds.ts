import { useQuery } from "@tanstack/react-query";

import { settingsApi } from "@/lib/api";

export interface UtilizationThresholds {
  warn: number;
  critical: number;
}

/** The backend's defaults, used until the settings arrive (or when the
 *  caller may not read them). */
export const DEFAULT_UTILIZATION_THRESHOLDS: UtilizationThresholds = {
  warn: 80,
  critical: 95,
};

/** Settings → IPAM "Warning Threshold" / "Critical Threshold" (#3327): the
 *  percentages every utilization indicator turns amber and red at. Shares
 *  the ``["settings"]`` cache entry with the other settings readers. */
export function useUtilizationThresholds(): UtilizationThresholds {
  const { data } = useQuery({
    queryKey: ["settings"],
    queryFn: () => settingsApi.get(),
    staleTime: 30_000,
    retry: false,
  });
  return {
    warn:
      data?.utilization_warn_threshold ?? DEFAULT_UTILIZATION_THRESHOLDS.warn,
    critical:
      data?.utilization_critical_threshold ??
      DEFAULT_UTILIZATION_THRESHOLDS.critical,
  };
}

/** Band a percentage against the thresholds. */
export function utilizationBand(
  percent: number,
  t: UtilizationThresholds,
): "critical" | "warn" | "ok" {
  return percent >= t.critical ? "critical" : percent >= t.warn ? "warn" : "ok";
}

/** The fill class the IPAM bars and dots draw a percentage in. */
export function utilizationColor(
  percent: number,
  t: UtilizationThresholds,
): string {
  const band = utilizationBand(percent, t);
  return band === "critical"
    ? "bg-red-500"
    : band === "warn"
      ? "bg-amber-400"
      : "bg-green-500";
}
