import { useState } from "react";
import { Outlet, useLocation } from "react-router-dom";

import { ErrorBoundary } from "@/components/ErrorBoundary";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import { DemoBanner } from "./DemoBanner";
import { EnvironmentBanner } from "./EnvironmentBanner";
import { MaintenanceBanner } from "./MaintenanceBanner";
import { MaintenanceModeBanner } from "./MaintenanceModeBanner";
import { SetupBanner } from "./SetupBanner";
import { IdleLogout } from "./IdleLogout";
import { CopilotButton } from "@/components/copilot/CopilotButton";
import { useFeatureModules } from "@/hooks/useFeatureModules";

export function AppLayout() {
  // Mobile drawer state. On desktop (md+) the sidebar is always visible and
  // this flag is ignored by the Sidebar's responsive classes.
  const [mobileOpen, setMobileOpen] = useState(false);

  // ai.copilot feature-module gate. Disabled hides the floating
  // button + chat drawer entirely; the /ai/* REST endpoints 404 from
  // the same gate on the backend.
  const { enabled } = useFeatureModules();
  const copilotEnabled = enabled("ai.copilot");

  // Keys the route-level error boundary below. Without it the boundary's
  // hasError state survives navigation: a crashed page would keep showing
  // the fallback for every route the user clicks to next, making the whole
  // app look broken until a full reload. Remounting on path change gives
  // each page a fresh boundary.
  const { pathname } = useLocation();

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Which box am I on (#887) comes before what state it's in — the
            other banners describe the platform, this one identifies it. */}
        <EnvironmentBanner edge="top" />
        <DemoBanner />
        <SetupBanner />
        <MaintenanceBanner />
        <MaintenanceModeBanner />
        <Header onMobileMenu={() => setMobileOpen(true)} />
        <main className="flex-1 overflow-auto">
          <ErrorBoundary
            key={pathname}
            fallback={
              <div className="m-6 rounded-lg border bg-card p-6 text-center">
                <h2 className="text-base font-semibold">
                  This page failed to load
                </h2>
                <p className="mt-2 text-sm text-muted-foreground">
                  Something went wrong while rendering this page.
                </p>
                <button
                  type="button"
                  onClick={() => window.location.reload()}
                  className="mt-4 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                >
                  Reload
                </button>
              </div>
            }
          >
            <Outlet />
          </ErrorBoundary>
        </main>
        <EnvironmentBanner edge="bottom" />
      </div>
      {/* Issue #90 — Operator Copilot floating button. Hidden when no
          AI provider is enabled, opens the chat drawer otherwise. */}
      {copilotEnabled && <CopilotButton />}
      {/* Settings → Sessions: Auto-Logout Warning + Session Timeout. */}
      <IdleLogout />
    </div>
  );
}
