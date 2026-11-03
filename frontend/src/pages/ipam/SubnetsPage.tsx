import { useQuery } from "@tanstack/react-query";
import { ipamApi, type Subnet } from "@/lib/api";
import { StatusTag } from "@/components/ui/status-tag";
import { zebraBodyCls } from "@/lib/utils";
import {
  useUtilizationThresholds,
  utilizationColor,
} from "@/hooks/useUtilizationThresholds";

export function SubnetsPage() {
  const { data: subnets, isLoading } = useQuery({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
  });

  if (isLoading) return <p className="text-muted-foreground">Loading…</p>;

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold tracking-tight">Subnets</h1>
      {subnets?.length === 0 && (
        <p className="text-sm text-muted-foreground">No subnets yet.</p>
      )}
      <div className="rounded-lg border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/50">
              <th className="px-4 py-3 text-left font-medium">Network</th>
              <th className="px-4 py-3 text-left font-medium">Name</th>
              <th className="px-4 py-3 text-left font-medium">Gateway</th>
              <th className="px-4 py-3 text-left font-medium">VLAN</th>
              <th className="px-4 py-3 text-left font-medium">Status</th>
              <th className="px-4 py-3 text-left font-medium">Utilization</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {subnets?.map((subnet: Subnet) => (
              <tr
                key={subnet.id}
                className="border-b last:border-0 hover:bg-muted/30"
              >
                <td className="px-4 py-3 font-mono font-medium">
                  {subnet.network}
                </td>
                <td className="px-4 py-3 text-muted-foreground">
                  {subnet.name || "—"}
                </td>
                <td className="px-4 py-3 font-mono">{subnet.gateway ?? "—"}</td>
                <td className="px-4 py-3">{subnet.vlan_id ?? "—"}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={subnet.status} />
                </td>
                <td className="px-4 py-3">
                  <UtilizationBar percent={subnet.utilization_percent} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  return <StatusTag status={status} />;
}

function UtilizationBar({ percent }: { percent: number }) {
  const color = utilizationColor(percent, useUtilizationThresholds());
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 rounded-full bg-muted">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${Math.min(percent, 100)}%` }}
        />
      </div>
      <span className="text-xs text-muted-foreground">
        {percent.toFixed(0)}%
      </span>
    </div>
  );
}
