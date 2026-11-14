import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";

import { authApi, settingsApi, versionApi } from "@/lib/api";
import { SNMPSection } from "@/components/SNMPSection";

/**
 * Appliance → SNMP tab (issue #153).
 *
 * Thin wrapper around the shared <code className="font-mono">SNMPSection</code> component. The same
 * form drives both the standalone Settings entry and this tab — but
 * the Appliance page is the canonical home because SNMP belongs
 * conceptually next to Releases / OS Versions / host-level config,
 * not down in IPAM / DNS / DHCP-flavoured Settings.
 *
 * Settings → Appliance → SNMP stays as a hidden alias for muscle-memory
 * + search — see <code className="font-mono">SettingsPage</code> SECTIONS for the entry that points
 * here.
 */
export function SNMPTab() {
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: authApi.me,
    staleTime: 60_000,
  });
  const { data: settings, isLoading } = useQuery({
    queryKey: ["settings"],
    queryFn: settingsApi.get,
  });
  const { data: versionInfo } = useQuery({
    queryKey: ["version"],
    queryFn: versionApi.get,
    staleTime: 60 * 60 * 1000,
  });

  if (isLoading || !settings) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading SNMP settings…
      </div>
    );
  }

  const isSuperadmin = me?.is_superadmin ?? false;
  // Same default-true-while-loading behaviour the Settings entry uses
  // so the non-appliance banner doesn't flash on appliance hosts.
  const applianceMode = versionInfo?.appliance_mode ?? true;
  const inputCls =
    "rounded-md border bg-background px-3 py-1.5 text-sm disabled:opacity-60";

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-4">
        <h2 className="text-base font-semibold">SNMP</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          snmpd runs at the OS level on every SpatiumDDI appliance host — local
          + every registered remote agent. The rendered{" "}
          <code className="font-mono">snmpd.conf</code> ships through the
          ConfigBundle long-poll, validated host-side via{" "}
          <code className="font-mono">snmpd -t</code> before activation. v2c
          uses <code className="font-mono">rocommunity</code> per source CIDR;
          v3 uses <code className="font-mono">createUser</code> + USM (snmpd
          hashes passwords against its engineID on apply — engineID rotates each
          reload, acceptable tradeoff for the first cut). Disabled out of the
          box.
        </p>
      </div>
      <SNMPSection
        values={settings}
        isSuperadmin={isSuperadmin}
        applianceMode={applianceMode}
        inputCls={inputCls}
      />
    </div>
  );
}
