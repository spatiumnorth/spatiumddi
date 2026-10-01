import { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Github,
  ChevronsLeft,
  ChevronsRight,
  ChevronDown,
  ChevronRight,
  Settings,
  Sparkles,
  ToggleLeft,
  Wrench,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { safeExternalHref } from "@/lib/safeUrl";
import { changeRequestsApi, versionApi } from "@/lib/api";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { useSessionState } from "@/lib/useSessionState";
import { BrandLogo } from "@/components/BrandLogo";
import {
  usePublicSettings,
  DEFAULT_APP_TITLE,
} from "@/hooks/usePublicSettings";
import {
  adminConfigurationNav,
  adminIdentityNav,
  adminInsightsNav,
  adminNotificationsNav,
  adminReferenceNav,
  baseMainNav,
  dnsSectionNav,
  coreIpamNav,
  filterNav,
  integrationsNav,
  networkInfrastructureNav,
  networkLogicalNav,
  operationsNav,
  reportsNav,
  toolsNav,
} from "@/lib/navigation";

// The nav tree itself lives in ``lib/navigation.ts`` so the Cmd/Ctrl+K
// command palette can render the same destinations without a second,
// drifting copy of the list (issue #879). Adding a page means adding it
// there; both surfaces pick it up.

function NavSection({
  label,
  storageKey,
  collapsed,
  children,
  showDivider = false,
}: {
  label: string;
  storageKey: string;
  collapsed: boolean;
  children: React.ReactNode;
  showDivider?: boolean;
}) {
  const [open, setOpen] = useSessionState<boolean>(storageKey, true);

  if (collapsed) {
    return (
      <>
        {showDivider && <div className="my-2 border-t border-sidebar-border" />}
        <div className="space-y-1">{children}</div>
      </>
    );
  }

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="group flex w-full items-center gap-1 px-2 py-1 text-xs font-semibold uppercase tracking-wider text-sidebar-muted-foreground/70 hover:text-sidebar-foreground"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="h-3 w-3 flex-shrink-0" />
        ) : (
          <ChevronRight className="h-3 w-3 flex-shrink-0" />
        )}
        <span>{label}</span>
      </button>
      {open && <div className="space-y-1">{children}</div>}
    </div>
  );
}

// Small non-collapsible label that breaks a long NavSection (like
// Administration → Platform) into themed sub-groups. Lighter weight
// than NavSection — no chevron, no collapse, no own storageKey.
function SubNavLabel({
  label,
  collapsed,
}: {
  label: string;
  collapsed: boolean;
}) {
  if (collapsed) {
    return <div className="my-1 border-t border-sidebar-border/60" />;
  }
  return (
    <div className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-sidebar-muted-foreground/50">
      {label}
    </div>
  );
}

function NavItem({
  label,
  icon: Icon,
  to,
  disabled,
  collapsed,
  onNavigate,
  end,
  badge,
}: {
  label: string;
  icon: React.ElementType;
  to: string;
  disabled?: boolean;
  collapsed: boolean;
  onNavigate?: () => void;
  end?: boolean;
  /** Optional count pill rendered after the label (e.g. the pending
   *  approval-queue size). Only shown expanded when ``badge > 0``. */
  badge?: number;
}) {
  return (
    <NavLink
      to={to}
      end={end}
      aria-disabled={disabled}
      tabIndex={disabled ? -1 : undefined}
      title={collapsed ? label : undefined}
      onClick={onNavigate}
      className={({ isActive }) =>
        cn(
          "flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors",
          collapsed ? "justify-center gap-0" : "gap-3",
          isActive
            ? "bg-sidebar-primary text-sidebar-primary-foreground"
            : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
          disabled && "pointer-events-none opacity-40",
        )
      }
    >
      <Icon className="h-4 w-4 flex-shrink-0" />
      {!collapsed && <span className="flex-1">{label}</span>}
      {!collapsed && badge != null && badge > 0 && (
        <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-amber-600 dark:text-amber-400">
          {badge}
        </span>
      )}
    </NavLink>
  );
}

/** External-link variant of :func:`NavItem`. Renders a plain ``<a>``
 *  rather than a ``NavLink`` so links to non-SPA URLs (FastAPI's
 *  ``/api/redoc`` etc.) leave the React Router tree cleanly. The
 *  visual style mirrors ``NavItem``'s inactive state — there's no
 *  "active" highlighting because we never navigate to it.
 */
function NavExternalItem({
  label,
  icon: Icon,
  href,
  collapsed,
  title,
}: {
  label: string;
  icon: React.ElementType;
  href: string;
  collapsed: boolean;
  /** Override for the hover tooltip — defaults to the label. Used
   *  when the collapsed-rail tooltip should differ from the visible
   *  label (or when an external link wants to advertise it opens
   *  in a new tab). */
  title?: string;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={title ?? (collapsed ? label : `${label} (opens in new tab)`)}
      className={cn(
        "flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors",
        collapsed ? "justify-center gap-0" : "gap-3",
        "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
      )}
    >
      <Icon className="h-4 w-4 flex-shrink-0" />
      {!collapsed && label}
    </a>
  );
}

export function Sidebar({
  mobileOpen = false,
  onMobileClose,
}: {
  mobileOpen?: boolean;
  onMobileClose?: () => void;
} = {}) {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("sidebar-collapsed") === "true",
  );
  const location = useLocation();

  // Operator-configured product name (#888) — the wordmark used to be a
  // hard-coded literal here, which is why setting a title changed nothing.
  const { settings } = usePublicSettings();
  const appTitle = settings.app_title.trim() || DEFAULT_APP_TITLE;

  // Close the mobile drawer whenever the user navigates.
  useEffect(() => {
    if (mobileOpen) onMobileClose?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  function toggle() {
    setCollapsed((v) => {
      const next = !v;
      localStorage.setItem("sidebar-collapsed", String(next));
      return next;
    });
  }

  // In the mobile drawer, ignore the "collapsed" state — always show labels.
  const effectiveCollapsed = mobileOpen ? false : collapsed;

  // Pull the running version from the backend so the sidebar always
  // reflects the deployed image, not the value baked in at build time.
  // Falls back to ``__APP_VERSION__`` (the build-time stamp) if the
  // API is unreachable — the login screen still renders a version
  // that way. Refresh hourly; release checks are daily so there's
  // nothing to gain from polling faster.
  const { data: versionInfo } = useQuery({
    queryKey: ["version"],
    queryFn: versionApi.get,
    staleTime: 60 * 60 * 1000,
    refetchInterval: 60 * 60 * 1000,
  });
  const displayVersion = versionInfo?.version ?? __APP_VERSION__;
  const updateAvailable = versionInfo?.update_available ?? false;
  const latestVersion = versionInfo?.latest_version ?? null;
  // From the GitHub API: linked only when http(s) (#1361).
  const latestReleaseUrl = safeExternalHref(versionInfo?.latest_release_url);

  // Feature-module toggles — disabled modules drop their nav items
  // entirely (drive both the togglable feature surfaces and the
  // integration visibility flags formerly read from PlatformSettings).
  // Loading / error state defaults to "everything visible" so the
  // sidebar never blinks empty on a slow network.
  const { enabled: moduleEnabled } = useFeatureModules();
  // Shared with the command palette (``lib/navigation.ts``) so a
  // module-gated page is hidden identically in both places.
  const filterByModule = <T extends { module?: string; anyModule?: string[] }>(
    items: T[],
  ): T[] => filterNav(items, moduleEnabled);

  // Pending approval-queue count → the Change Requests nav badge. Only
  // polls when the (default-off) governance.approvals module is on, so a
  // disabled module fires zero requests.
  const approvalsOn = moduleEnabled("governance.approvals");
  const pendingChangeCount = useQuery({
    queryKey: ["change-requests", "pending-count"],
    queryFn: changeRequestsApi.countPending,
    enabled: approvalsOn,
    refetchInterval: 30000,
  }).data;

  // Integrations live in their own sidebar section, rendered between
  // the main nav and the admin nav, but only when at least one
  // integration is enabled. Each integration's visibility is gated
  // by its feature_module id (Settings → Features → Integrations);
  // the matching ``PlatformSettings.integration_*_enabled`` columns
  // are kept in lock-step by the toggle endpoint so reconciler tasks
  // don't need to migrate.
  // Sorted alphabetically by label so the order is stable regardless
  // of the order we added integrations here — adding a new one later
  // shouldn't re-shuffle the sidebar for operators already using it.
  const visibleIntegrations = filterByModule(integrationsNav);
  // #696 — baseMainNav now carries a module-gated entry (Requests), so it
  // has to go through the same filter every other nav group uses. Without
  // this the item renders on every install even though governance.requests
  // is default-off, and clicking it lands on a page whose API 404s.
  const mainNav = filterByModule(baseMainNav);

  return (
    <>
      {/* Backdrop — click outside to close (mobile only) */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={onMobileClose}
          aria-hidden
        />
      )}
      <aside
        className={cn(
          "flex flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-all duration-200",
          // Desktop: inline, fixed width, always visible (md+).
          "md:flex-shrink-0",
          collapsed ? "md:w-14" : "md:w-56",
          // Mobile: hidden by default, fixed-positioned drawer when open.
          mobileOpen
            ? "fixed inset-y-0 left-0 z-50 w-64 md:static md:z-auto"
            : "hidden md:flex",
        )}
      >
        {/* Logo + mobile close button */}
        <div
          className={cn(
            "flex h-14 items-center border-b border-sidebar-border",
            effectiveCollapsed ? "justify-center px-0" : "gap-2 px-4",
          )}
        >
          <BrandLogo className="h-7 w-7 flex-shrink-0" />
          {!effectiveCollapsed && (
            <span className="truncate font-semibold tracking-tight">
              {appTitle}
            </span>
          )}
          {mobileOpen && (
            <button
              type="button"
              onClick={onMobileClose}
              aria-label="Close navigation"
              className="ml-auto rounded-md p-1 text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground md:hidden"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto p-2 space-y-4">
          <NavSection
            label="Core"
            storageKey="sidebar-section-core-open"
            collapsed={effectiveCollapsed}
          >
            {mainNav.map((item) => (
              <NavItem
                key={item.to}
                {...item}
                collapsed={effectiveCollapsed}
                onNavigate={mobileOpen ? onMobileClose : undefined}
              />
            ))}
            {/* #1068 — both sub-groups go through the module filter and
             *  their heading is suppressed when nothing survives it. The
             *  DNS group carried module tags that nothing applied, so with
             *  core.dns off you got a "DNS" heading over a lone Domains
             *  row: not a missing feature, just a stray label that reads
             *  like the menu has been reshuffled. */}
            {(() => {
              const ipamItems = filterByModule(coreIpamNav);
              const dnsItems = filterByModule(dnsSectionNav);
              return (
                <>
                  {ipamItems.length > 0 && (
                    <SubNavLabel label="IPAM" collapsed={effectiveCollapsed} />
                  )}
                  {ipamItems.map((item) => (
                    <NavItem
                      key={item.to}
                      {...item}
                      collapsed={effectiveCollapsed}
                      onNavigate={mobileOpen ? onMobileClose : undefined}
                    />
                  ))}
                  {dnsItems.length > 0 && (
                    <SubNavLabel label="DNS" collapsed={effectiveCollapsed} />
                  )}
                  {dnsItems.map((item) => (
                    <NavItem
                      key={item.to}
                      {...item}
                      collapsed={effectiveCollapsed}
                      onNavigate={mobileOpen ? onMobileClose : undefined}
                    />
                  ))}
                </>
              );
            })()}
          </NavSection>

          <NavSection
            label="Operations"
            storageKey="sidebar-section-operations-open"
            collapsed={effectiveCollapsed}
            showDivider
          >
            {operationsNav.map((item) => (
              <NavItem
                key={item.to}
                {...item}
                collapsed={effectiveCollapsed}
                onNavigate={mobileOpen ? onMobileClose : undefined}
              />
            ))}
          </NavSection>

          {(() => {
            const visibleLogical = filterByModule(networkLogicalNav);
            const visibleInfra = filterByModule(networkInfrastructureNav);
            // Hide the whole Network section if everything inside is
            // disabled — otherwise we'd render an empty header.
            if (visibleLogical.length + visibleInfra.length === 0) return null;
            return (
              <NavSection
                label="Network"
                storageKey="sidebar-section-network-open"
                collapsed={effectiveCollapsed}
                showDivider
              >
                {visibleLogical.length > 0 && (
                  <>
                    <SubNavLabel
                      label="Logical"
                      collapsed={effectiveCollapsed}
                    />
                    {visibleLogical.map((item) => (
                      <NavItem
                        key={item.to}
                        {...item}
                        collapsed={effectiveCollapsed}
                        onNavigate={mobileOpen ? onMobileClose : undefined}
                      />
                    ))}
                  </>
                )}
                {visibleInfra.length > 0 && (
                  <>
                    <SubNavLabel
                      label="Infrastructure"
                      collapsed={effectiveCollapsed}
                    />
                    {visibleInfra.map((item) => (
                      <NavItem
                        key={item.to}
                        {...item}
                        collapsed={effectiveCollapsed}
                        onNavigate={mobileOpen ? onMobileClose : undefined}
                      />
                    ))}
                  </>
                )}
              </NavSection>
            );
          })()}

          {(() => {
            const visibleTools = filterByModule(toolsNav);
            if (visibleTools.length === 0) return null;
            return (
              <NavSection
                label="Tools"
                storageKey="sidebar-section-tools-open"
                collapsed={effectiveCollapsed}
                showDivider
              >
                {visibleTools.map((item) => (
                  <NavItem
                    key={item.to}
                    {...item}
                    collapsed={effectiveCollapsed}
                    onNavigate={mobileOpen ? onMobileClose : undefined}
                  />
                ))}
              </NavSection>
            );
          })()}

          {(() => {
            const visibleReports = filterByModule(reportsNav);
            if (visibleReports.length === 0) return null;
            return (
              <NavSection
                label="Reports"
                storageKey="sidebar-section-reports-open"
                collapsed={effectiveCollapsed}
                showDivider
              >
                {visibleReports.map((item) => (
                  <NavItem
                    key={item.to}
                    {...item}
                    collapsed={effectiveCollapsed}
                    onNavigate={mobileOpen ? onMobileClose : undefined}
                  />
                ))}
              </NavSection>
            );
          })()}

          {visibleIntegrations.length > 0 && (
            <NavSection
              label="Integrations"
              storageKey="sidebar-section-integrations-open"
              collapsed={effectiveCollapsed}
              showDivider
            >
              {visibleIntegrations.map((item) => (
                <NavItem
                  key={item.to}
                  {...item}
                  collapsed={effectiveCollapsed}
                  onNavigate={mobileOpen ? onMobileClose : undefined}
                />
              ))}
            </NavSection>
          )}

          <NavSection
            label="Administration"
            storageKey="sidebar-section-admin-open"
            collapsed={effectiveCollapsed}
            showDivider
          >
            <SubNavLabel label="Identity" collapsed={effectiveCollapsed} />
            {adminIdentityNav.map((item) => (
              <NavItem
                key={item.to}
                {...item}
                collapsed={effectiveCollapsed}
                onNavigate={mobileOpen ? onMobileClose : undefined}
              />
            ))}
            <SubNavLabel label="Configuration" collapsed={effectiveCollapsed} />
            {filterByModule(adminConfigurationNav).map((item) => (
              <NavItem
                key={item.to}
                {...item}
                collapsed={effectiveCollapsed}
                onNavigate={mobileOpen ? onMobileClose : undefined}
              />
            ))}
            <SubNavLabel label="Notifications" collapsed={effectiveCollapsed} />
            {filterByModule(adminNotificationsNav).map((item) => (
              <NavItem
                key={item.to}
                {...item}
                badge={
                  item.to === "/admin/change-requests"
                    ? pendingChangeCount
                    : undefined
                }
                collapsed={effectiveCollapsed}
                onNavigate={mobileOpen ? onMobileClose : undefined}
              />
            ))}
            <SubNavLabel
              label="Insights & Audit"
              collapsed={effectiveCollapsed}
            />
            {filterByModule(adminInsightsNav).map((item) => (
              <NavItem
                key={item.to}
                {...item}
                collapsed={effectiveCollapsed}
                onNavigate={mobileOpen ? onMobileClose : undefined}
              />
            ))}
            <SubNavLabel label="Reference" collapsed={effectiveCollapsed} />
            {adminReferenceNav.map((item) => (
              <NavExternalItem
                key={item.href}
                {...item}
                collapsed={effectiveCollapsed}
              />
            ))}
            <div className="my-1 border-t border-sidebar-border/60" />
          </NavSection>
        </nav>

        {/* Footer */}
        <div
          className={cn(
            "border-t border-sidebar-border p-2 space-y-1",
            effectiveCollapsed && "flex flex-col items-center",
          )}
        >
          {!effectiveCollapsed && (
            <div className="flex items-center gap-2 px-3 py-1">
              <span className="text-xs font-mono text-sidebar-muted-foreground/80">
                v{displayVersion}
              </span>
              {updateAvailable && latestReleaseUrl && (
                <a
                  href={latestReleaseUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={`Update available: ${latestVersion ?? "newer release"}`}
                  className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 hover:bg-emerald-500/25 dark:text-emerald-400"
                >
                  <Sparkles className="h-3 w-3" />
                  update
                </a>
              )}
            </div>
          )}
          {effectiveCollapsed && updateAvailable && latestReleaseUrl && (
            <a
              href={latestReleaseUrl}
              target="_blank"
              rel="noopener noreferrer"
              title={`Update available: ${latestVersion ?? "newer release"}`}
              className="flex items-center justify-center rounded-md p-2 text-emerald-600 hover:bg-sidebar-accent dark:text-emerald-400"
            >
              <Sparkles className="h-4 w-4" />
            </a>
          )}

          {/*
            Appliance management — always visible. When the API host
            itself runs the SpatiumDDI OS appliance ISO, /appliance
            shows the full tab set (TLS, releases, OS versions,
            containers, host logs, network, maintenance). On
            docker/k8s control planes, the page is still useful for
            the Releases catalog + the OS Versions table (which lets
            operators drive slot upgrades on *remote* appliance
            agents that registered against this control plane); the
            self-only tabs are hidden inside the page. Hiding the
            entry entirely was overly aggressive — the hybrid topology
            (docker/k8s control plane + appliance agents) is a real
            deployment shape.
          */}
          <NavItem
            label="Appliance"
            icon={Wrench}
            to="/appliance"
            collapsed={effectiveCollapsed}
            onNavigate={mobileOpen ? onMobileClose : undefined}
          />

          <NavItem
            label="Features & Integrations"
            icon={ToggleLeft}
            to="/admin/features"
            collapsed={effectiveCollapsed}
            onNavigate={mobileOpen ? onMobileClose : undefined}
          />

          <NavItem
            label="Settings"
            icon={Settings}
            to="/settings"
            collapsed={effectiveCollapsed}
            onNavigate={mobileOpen ? onMobileClose : undefined}
          />

          <a
            href="https://github.com/spatiumnorth/spatiumddi"
            target="_blank"
            rel="noopener noreferrer"
            title={effectiveCollapsed ? "GitHub" : undefined}
            className={cn(
              "flex items-center rounded-md px-3 py-2 text-sm font-medium text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground transition-colors",
              effectiveCollapsed ? "justify-center" : "gap-3",
            )}
          >
            <Github className="h-4 w-4 flex-shrink-0" />
            {!effectiveCollapsed && "GitHub"}
          </a>

          {/* Collapse toggle — desktop only */}
          <button
            onClick={toggle}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={cn(
              "hidden md:flex w-full items-center rounded-md px-3 py-2 text-sm text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground transition-colors",
              collapsed ? "justify-center" : "gap-3",
            )}
          >
            {collapsed ? (
              <ChevronsRight className="h-4 w-4 flex-shrink-0" />
            ) : (
              <>
                <ChevronsLeft className="h-4 w-4 flex-shrink-0" />
                <span>Collapse</span>
              </>
            )}
          </button>
        </div>
      </aside>
    </>
  );
}
