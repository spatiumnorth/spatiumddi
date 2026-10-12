import { useEffect } from "react";

import { cn } from "@/lib/utils";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { useSessionState } from "@/lib/useSessionState";
import { CutoverPage } from "./CutoverPage";
import { DHCPImportPage } from "./DHCPImportPage";
import { DNSImportPage } from "./DNSImportPage";
import { NetBoxImportPage } from "./NetBoxImportPage";

/**
 * Configuration → Import hub.
 *
 * Consolidates the three one-shot importers (DHCP #129 / DNS #128 / NetBox
 * #36) plus the guided Windows cutover (#756) under a single Configuration
 * nav entry with a left sub-nav, mirroring the Appliance → Fleet left-sidebar
 * pattern. Each section keeps its own page component (and its own source
 * sub-tabs); this shell just picks which family is active and gates each
 * section on its feature module.
 *
 * Mounted at /admin/import plus the legacy per-importer routes
 * (/admin/{dhcp,dns,netbox}-import, /admin/cutover) so existing deep-links —
 * notably the DNS page's "Sync from provider"
 * navigate("/admin/dns-import", {state}) — keep working: the legacy route
 * renders this shell with the matching initialTab, and the embedded page still
 * reads its router state.
 */
export type ImportTab = "dhcp" | "dns" | "netbox" | "cutover";

const SECTIONS: {
  key: ImportTab;
  label: string;
  summary: string;
  module: string;
}[] = [
  {
    key: "dhcp",
    label: "DHCP",
    summary: "Kea / ISC dhcpd / Windows DHCP config",
    module: "dhcp.import",
  },
  {
    key: "dns",
    label: "DNS",
    summary: "BIND9 zonefiles / Windows DNS / cloud providers",
    module: "dns.import",
  },
  {
    key: "netbox",
    label: "NetBox",
    summary: "One-shot IPAM migration from a NetBox install",
    module: "ipam.import.netbox",
  },
  {
    key: "cutover",
    label: "Windows cutover",
    summary: "Guided migration off Windows DNS / DHCP",
    module: "migration.cutover",
  },
];

export function ImportPage({ initialTab }: { initialTab?: ImportTab }) {
  const { enabled: moduleEnabled } = useFeatureModules();
  const [tab, setTab] = useSessionState<ImportTab>(
    "admin.import.tab",
    initialTab ?? "dhcp",
  );

  // A legacy per-importer route (/admin/dns-import, …) wins over the
  // session-stored last tab on mount so deep-links land on the right family.
  useEffect(() => {
    if (initialTab) setTab(initialTab);
  }, [initialTab, setTab]);

  // Only show families whose feature module is enabled; fall back to the
  // first visible family if the stored/initial tab's module is off.
  const visible = SECTIONS.filter((s) => moduleEnabled(s.module));
  const active = visible.find((s) => s.key === tab) ?? visible[0];

  return (
    <div className="flex h-full overflow-hidden">
      {/* ── Left sub-nav (mirrors Appliance → Fleet) ── */}
      <aside className="w-56 flex-shrink-0 overflow-y-auto border-r bg-card">
        <div className="border-b px-4 py-3">
          <h1 className="text-sm font-semibold">Import</h1>
          <p className="text-xs text-muted-foreground">
            One-shot config &amp; inventory importers.
          </p>
        </div>
        <nav className="p-2">
          {visible.map((s) => (
            <button
              key={s.key}
              type="button"
              onClick={() => setTab(s.key)}
              className={cn(
                "block w-full rounded-md px-3 py-2 text-left text-sm hover:bg-accent",
                active?.key === s.key && "bg-accent font-medium",
              )}
            >
              <span>{s.label}</span>
              <span className="mt-0.5 block text-[11px] text-muted-foreground">
                {s.summary}
              </span>
            </button>
          ))}
          {visible.length === 0 && (
            <p className="px-3 py-2 text-xs text-muted-foreground">
              No importers are enabled. Turn them on under Features &
              Integrations.
            </p>
          )}
        </nav>
      </aside>

      {/* ── Main pane: the selected importer (self-scrolls) ── */}
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {active?.key === "dhcp" ? (
          <DHCPImportPage />
        ) : active?.key === "dns" ? (
          <DNSImportPage />
        ) : active?.key === "netbox" ? (
          <NetBoxImportPage />
        ) : active?.key === "cutover" ? (
          <CutoverPage />
        ) : null}
      </main>
    </div>
  );
}
