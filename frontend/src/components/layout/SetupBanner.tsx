import { useQuery } from "@tanstack/react-query";
import { Link, useLocation } from "react-router-dom";
import { ArrowRight, Sparkles } from "lucide-react";

import { applianceSetupApi, versionApi } from "@/lib/api";
import { usePermissions } from "@/hooks/usePermissions";

/**
 * Phase 4g — first-boot setup-wizard banner.
 *
 * Rendered on every authenticated page when:
 *   - the deployment is appliance-mode (versionApi.appliance_mode),
 *   - the setup-complete flag is false, and
 *   - the operator isn't already on /appliance/setup (no
 *     "Complete setup" link pointing at the page you're on).
 *
 * Banner-only — no auto-redirect — so the operator can keep working
 * with the appliance even before they've walked through optional
 * polish steps.
 */
export function SetupBanner() {
  // #1342 — finishing first-boot setup takes `admin` on `appliance`;
  // the call to action is for a user who can answer it.
  const canFinishSetup = usePermissions().can("admin", "appliance");
  const location = useLocation();

  const version = useQuery({
    queryKey: ["version"],
    queryFn: versionApi.get,
    staleTime: 60 * 60 * 1000,
  });
  const setup = useQuery({
    queryKey: ["appliance", "setup"],
    queryFn: applianceSetupApi.state,
    // Only run when we know it's an appliance deploy — otherwise
    // /appliance/system/setup returns 401/403 noise on plain deploys.
    enabled: !!version.data?.appliance_mode,
    staleTime: 60 * 1000,
  });

  if (!version.data?.appliance_mode) return null;
  if (!canFinishSetup) return null;
  if (!setup.data || setup.data.complete) return null;
  if (location.pathname.startsWith("/appliance/setup")) return null;

  return (
    <div className="border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-700 dark:text-amber-400">
      <div className="mx-auto flex max-w-7xl items-center gap-2">
        <Sparkles className="h-3.5 w-3.5 shrink-0" />
        <span className="flex-1">
          New appliance — finish first-boot setup to upload a TLS cert, review
          host config, and dismiss this banner.
        </span>
        <Link
          to="/appliance/setup"
          className="inline-flex shrink-0 items-center gap-1 rounded-md border border-amber-500/40 bg-background px-2 py-0.5 font-medium hover:bg-amber-500/10"
        >
          Open setup
          <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
    </div>
  );
}
