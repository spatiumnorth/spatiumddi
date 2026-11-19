import { useQuery } from "@tanstack/react-query";
import { Link, useLocation } from "react-router-dom";
import { ShieldAlert } from "lucide-react";

import { applianceSystemApi, versionApi } from "@/lib/api";
import { usePermissions } from "@/hooks/usePermissions";
import { isRefused } from "@/lib/refusal";

/**
 * Phase 4f — maintenance-mode banner.
 *
 * Rendered on every authenticated page when:
 *   - the deployment is appliance-mode, and
 *   - the maintenance-mode flag file is present (operator enabled it
 *     from /appliance#maintenance).
 *
 * Mirrors the SetupBanner pattern but stays put as long as the flag
 * is active — there's no "dismiss" affordance because the whole point
 * of the banner is that someone (potentially a different operator
 * from the one who enabled it) sees the state and can flip it off.
 */
export function MaintenanceBanner() {
  const location = useLocation();
  // The probe behind this banner is `read` on `appliance`; a user without it
  // is refused every 15 s and each refusal is an audited `denied` row (#1864).
  // It never asks, so the banner is simply not theirs to see.
  const canRead = usePermissions().can("read", "appliance");

  const version = useQuery({
    queryKey: ["version"],
    queryFn: versionApi.get,
    staleTime: 60 * 60 * 1000,
  });
  const sys = useQuery({
    queryKey: ["appliance", "system", "info"],
    queryFn: applianceSystemApi.info,
    enabled: !!version.data?.appliance_mode && canRead,
    // Poll a bit faster than the wizard banner — operators who flip
    // the toggle deserve immediate feedback in the global UI.
    refetchInterval: (q) =>
      isRefused(q.state.error)
        ? false
        : q.state.data?.maintenance_mode || version.data?.appliance_mode
          ? 15_000
          : false,
    staleTime: 10_000,
  });

  if (!version.data?.appliance_mode) return null;
  if (!canRead || !sys.data?.maintenance_mode) return null;
  // No need to nag when the operator is on the page that disables it.
  if (location.pathname.startsWith("/appliance")) return null;

  return (
    <div className="border-b border-amber-500/40 bg-amber-500/15 px-4 py-2 text-xs text-amber-800 dark:text-amber-300">
      <div className="mx-auto flex max-w-7xl items-center gap-2">
        <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
        <span className="flex-1">
          <strong>Maintenance mode is on.</strong> Scheduled DNS/DHCP updates
          will pause while this flag is set. Disable it from the Appliance
          management hub when you're done.
        </span>
        <Link
          to="/appliance"
          className="inline-flex shrink-0 items-center gap-1 rounded-md border border-amber-500/40 bg-background px-2 py-0.5 font-medium hover:bg-amber-500/15"
        >
          Open Maintenance
        </Link>
      </div>
    </div>
  );
}
