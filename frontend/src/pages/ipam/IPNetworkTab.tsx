import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ExternalLink, Loader2, Network as NetworkIcon } from "lucide-react";

import { networkApi } from "@/lib/api";
import { usePermissions } from "@/hooks/usePermissions";
import { cn } from "@/lib/utils";
import { FdbTypePill, humanTime } from "@/pages/network/_shared";

// ── Hook ─────────────────────────────────────────────────────────────

// Tiny shared hook so the host (EditAddressModal) can both render the
// tab body and also know whether to show a count badge on the tab pip.
// eslint-disable-next-line react-refresh/only-export-components
export function useNetworkContext(addressId: string | undefined) {
  return useQuery({
    queryKey: ["network-context", addressId],
    queryFn: () => networkApi.getAddressNetworkContext(addressId!),
    enabled: !!addressId,
  });
}

// ── Tab body ─────────────────────────────────────────────────────────

const PILL_BASE =
  "inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium";

// The response is a list of (switch × interface × VLAN × MAC) tuples.
// Multiple rows for the same IP are not collapsed — a hypervisor can
// surface its own MAC plus a row per VM, and an IP phone with PC
// passthrough surfaces the phone on the voice VLAN and the PC on the
// data VLAN. Each tuple gets its own row, sorted by ``last_seen DESC``.
export function IPNetworkTab({ addressId }: { addressId: string }) {
  const { data: rows = [], isLoading, isError } = useNetworkContext(addressId);
  // Devices are added on /network behind write on network devices (#4588).
  const canAddDevice = usePermissions().can("write", "manage_network_devices");

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Loading network context…
      </div>
    );
  }
  if (isError) {
    return (
      <p className="text-xs text-destructive">
        Failed to load network context.
      </p>
    );
  }
  if (rows.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-muted/20 p-4 text-center">
        <NetworkIcon className="mx-auto mb-1 h-4 w-4 text-muted-foreground" />
        <p className="text-xs text-muted-foreground">
          No network discovery data
          {canAddDevice && (
            <>
              {" "}
              — add the upstream switch in{" "}
              <Link to="/network" className="text-primary hover:underline">
                /network
              </Link>{" "}
              and wait a polling cycle
            </>
          )}
          .
        </p>
      </div>
    );
  }

  const sorted = [...rows].sort((a, b) =>
    a.last_seen < b.last_seen ? 1 : a.last_seen > b.last_seen ? -1 : 0,
  );

  return (
    <div className="space-y-2">
      <p className="text-[11px] text-muted-foreground">
        From the FDB join across managed switches. Sorted by last-seen (newest
        first). One row per (switch × interface × VLAN × MAC) — multiple rows
        for the same IP are normal on hypervisors and IP phones with PC
        passthrough.
      </p>
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[600px] text-xs">
          <thead>
            <tr className="border-b bg-muted/30">
              <th className="px-3 py-2 text-left font-medium">Switch</th>
              <th className="px-3 py-2 text-left font-medium">Port</th>
              <th className="px-3 py-2 text-left font-medium">VLAN</th>
              <th className="px-3 py-2 text-left font-medium">MAC</th>
              <th className="px-3 py-2 text-left font-medium">Type</th>
              <th className="px-3 py-2 text-left font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((r) => (
              <tr
                key={`${r.device_id}-${r.interface_id}-${r.vlan_id ?? "none"}-${r.mac_address}`}
                className="border-b last:border-0"
              >
                <td className="whitespace-nowrap px-3 py-1.5">
                  <Link
                    to={`/network/devices/${r.device_id}`}
                    className="inline-flex items-center gap-1 text-primary hover:underline"
                  >
                    {r.device_name}
                    <ExternalLink className="h-3 w-3 opacity-70" />
                  </Link>
                </td>
                <td className="whitespace-nowrap px-3 py-1.5">
                  <span className="font-mono text-[11px]">
                    {r.interface_name}
                  </span>
                  {r.interface_alias && (
                    <span className="ml-1 text-muted-foreground">
                      — {r.interface_alias}
                    </span>
                  )}
                </td>
                <td className="whitespace-nowrap px-3 py-1.5 tabular-nums">
                  {r.vlan_id ?? (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
                <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[11px]">
                  {r.mac_address}
                </td>
                <td className="px-3 py-1.5">
                  <FdbTypePill
                    type={
                      (r.fdb_type as "learned" | "static" | "mgmt" | "other") ||
                      "other"
                    }
                  />
                </td>
                <td
                  className="whitespace-nowrap px-3 py-1.5 text-muted-foreground"
                  title={r.last_seen}
                >
                  {humanTime(r.last_seen)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Standalone count badge used by the host modal to render the tab's
// trailing pip ("Network 3").
export function NetworkTabBadge({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span
      className={cn(
        PILL_BASE,
        "ml-1.5 bg-primary/10 text-primary",
        "tabular-nums",
      )}
    >
      {count}
    </span>
  );
}
