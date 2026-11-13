import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, Heart, Globe2, Loader2 } from "lucide-react";
import { ipamApi, type Subnet, type IPSpace } from "@/lib/api";
import { ListEmpty } from "@/components/ui/list-read-error";

/**
 * Compliance dashboard. Three independent buckets keyed off the
 * subnet classification flags (issue #75): PCI / HIPAA / Internet-
 * facing. Each bucket queries `/ipam/subnets` with the matching
 * filter and lists the tagged subnets with network / space /
 * description / last-changed columns. Read-only — auditors click
 * through to the IPAM tree to inspect.
 *
 * The three queries fan out in parallel; each hits a partial index
 * (`WHERE pci_scope = true` etc.) so even with thousands of
 * subnets the dashboard stays snappy.
 */
export function CompliancePage() {
  const {
    data: pci = [],
    isLoading: pciLoading,
    error: pciError,
  } = useQuery({
    queryKey: ["compliance-subnets", "pci"],
    queryFn: () => ipamApi.listSubnets({ pci_scope: true }),
  });
  const {
    data: hipaa = [],
    isLoading: hipaaLoading,
    error: hipaaError,
  } = useQuery({
    queryKey: ["compliance-subnets", "hipaa"],
    queryFn: () => ipamApi.listSubnets({ hipaa_scope: true }),
  });
  const {
    data: inet = [],
    isLoading: inetLoading,
    error: inetError,
  } = useQuery({
    queryKey: ["compliance-subnets", "internet-facing"],
    queryFn: () => ipamApi.listSubnets({ internet_facing: true }),
  });

  const { data: spaces = [] } = useQuery({
    queryKey: ["spaces"],
    queryFn: () => ipamApi.listSpaces(),
  });
  const spaceById = useMemo(
    () => new Map(spaces.map((s) => [s.id, s])),
    [spaces],
  );

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Compliance</h1>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              Subnets tagged with regulatory or exposure scope. Flip flags on a
              subnet via the Edit Subnet modal.
            </p>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="grid gap-6 lg:grid-cols-1 xl:grid-cols-3">
          <ComplianceCard
            title="PCI scope"
            icon={<ShieldCheck className="h-4 w-4" />}
            description="Subnets handling cardholder data per PCI DSS."
            subnets={pci}
            loading={pciLoading}
            error={pciError}
            spaceById={spaceById}
            emptyHint="No subnets tagged PCI scope yet."
          />
          <ComplianceCard
            title="HIPAA scope"
            icon={<Heart className="h-4 w-4" />}
            description="Subnets handling electronic protected health information."
            subnets={hipaa}
            loading={hipaaLoading}
            error={hipaaError}
            spaceById={spaceById}
            emptyHint="No subnets tagged HIPAA scope yet."
          />
          <ComplianceCard
            title="Internet-facing"
            icon={<Globe2 className="h-4 w-4" />}
            description="Subnets reachable directly from the public internet."
            subnets={inet}
            loading={inetLoading}
            error={inetError}
            spaceById={spaceById}
            emptyHint="No subnets tagged internet-facing yet."
          />
        </div>
      </div>
    </div>
  );
}

function ComplianceCard({
  title,
  icon,
  description,
  subnets,
  loading,
  error,
  spaceById,
  emptyHint,
}: {
  title: string;
  icon: React.ReactNode;
  description: string;
  subnets: Subnet[];
  loading: boolean;
  error: unknown;
  spaceById: Map<string, IPSpace>;
  emptyHint: string;
}) {
  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">{icon}</span>
          <span className="text-sm font-semibold">{title}</span>
        </div>
        <span className="rounded bg-muted px-1.5 py-0.5 text-[11px] tabular-nums">
          {loading || error ? "—" : subnets.length}
        </span>
      </div>
      <p className="border-b px-4 py-2 text-[11px] text-muted-foreground">
        {description}
      </p>
      {loading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
        </div>
      ) : subnets.length === 0 || error ? (
        <p className="px-4 py-6 text-center text-xs text-muted-foreground">
          <ListEmpty error={error} what="subnets">
            {emptyHint}
          </ListEmpty>
        </p>
      ) : (
        <table className="w-full text-xs">
          <thead className="bg-card text-[11px] uppercase tracking-wider text-muted-foreground shadow-[inset_0_-1px_0] shadow-border">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Network</th>
              <th className="px-3 py-2 text-left font-medium">Name</th>
              <th className="px-3 py-2 text-left font-medium">Space</th>
              <th className="px-3 py-2 text-left font-medium whitespace-nowrap">
                Last modified
              </th>
            </tr>
          </thead>
          <tbody>
            {subnets.map((s) => (
              <tr
                key={s.id}
                className="border-b last:border-0 hover:bg-muted/20"
              >
                <td className="px-3 py-2 font-mono">
                  <Link to="/ipam" className="text-primary hover:underline">
                    {s.network}
                  </Link>
                </td>
                <td className="px-3 py-2">{s.name || "—"}</td>
                <td className="px-3 py-2 text-muted-foreground">
                  {spaceById.get(s.space_id)?.name ?? "—"}
                </td>
                <td className="px-3 py-2 text-muted-foreground tabular-nums whitespace-nowrap">
                  {s.modified_at
                    ? new Date(s.modified_at).toLocaleString()
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
