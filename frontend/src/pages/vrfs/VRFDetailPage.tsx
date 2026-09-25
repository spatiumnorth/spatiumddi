import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Loader2, Pencil, Route as RouteIcon } from "lucide-react";
import {
  asnsApi,
  ipamApi,
  lookingGlassApi,
  vrfsApi,
  type VRF,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { ServicesUsingButton } from "@/components/ServicesUsingButton";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import {
  BgpRouteMiniTable,
  type VrfRtContext,
} from "@/components/network/bgp-route-table";
import { VRFEditorModal } from "./VRFsPage";

type Tab = "spaces" | "blocks" | "routes";

function Card({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border bg-card">
      <div className="border-b px-4 py-2 text-sm font-semibold">{title}</div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function RtChips({ values }: { values: string[] }) {
  if (!values || values.length === 0) {
    return <span className="text-muted-foreground">— none —</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {values.map((v) => (
        <span
          key={v}
          className="inline-flex rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
        >
          {v}
        </span>
      ))}
    </div>
  );
}

// Issue #566 Phase 3 introduced "matched_vrf_id" meaning "the VRF assigned
// to whichever IPAM block/space this route's prefix falls under" (the
// effective-VRF walk in backend/app/services/looking_glass/ipam_link.py).
// Phase 6 adds a second, DISTINCT way a route ends up with this VRF's id:
// a direct Route-Target cross-check against ``ext_communities`` for
// vpnv4/vpnv6 paths (backend/app/services/looking_glass/vrf_match.py),
// which takes precedence over the IPAM walk when a route carries a
// Route Distinguisher. This panel doesn't need to tell the two apart at
// the query level (both set ``matched_vrf_id``) — it just renders the
// RT cross-check columns (via ``vrfRtContext``) whenever a row happens to
// carry ``ext_communities``/``route_distinguisher``; plain ipv4/ipv6-unicast
// routes matched purely by IPAM footprint show "—" in those columns.
function VrfRoutesPanel({ vrf }: { vrf: VRF }) {
  const { data, isLoading } = useQuery({
    queryKey: ["bgp-lg-routes-by-vrf", vrf.id],
    queryFn: () =>
      lookingGlassApi.searchRoutes({
        matched_vrf_id: vrf.id,
        withdrawn: false,
        limit: 200,
      }),
    staleTime: 15_000,
  });
  if (isLoading) {
    return <p className="p-6 text-sm text-muted-foreground">Loading…</p>;
  }
  const items = data?.items ?? [];
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 p-10 text-center">
        <p className="text-sm text-muted-foreground">
          No BGP routes matched to this VRF's IPAM footprint.
        </p>
      </div>
    );
  }
  const rtContext: VrfRtContext = {
    importTargets: vrf.import_targets,
    exportTargets: vrf.export_targets,
  };
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        Every active BGP Looking Glass route whose matched IPAM block or space
        carries this VRF, or whose VPNv4/VPNv6 Route Target matched this VRF's
        import/export lists directly. The "Route targets" column highlights
        which of this VRF's RTs a route's extended communities hit.
      </p>
      <BgpRouteMiniTable items={items} vrfRtContext={rtContext} />
    </div>
  );
}

function TagChips({ tags }: { tags: Record<string, unknown> }) {
  const entries = Object.entries(tags ?? {});
  if (entries.length === 0) {
    return <span className="text-muted-foreground">— none —</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {entries.map(([k, v]) => (
        <span
          key={k}
          className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px]"
        >
          {v != null && v !== "" && v !== true ? `${k}: ${v}` : k}
        </span>
      ))}
    </div>
  );
}

function InfoRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-2 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span>{children}</span>
    </div>
  );
}

export function VRFDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>("spaces");
  const [showEdit, setShowEdit] = useState(false);
  const { enabled: featureEnabled } = useFeatureModules();

  const {
    data: vrf,
    isLoading,
    isError,
  } = useQuery({
    queryKey: ["vrfs", id],
    queryFn: () => vrfsApi.get(id),
    enabled: !!id,
  });

  const { data: asn } = useQuery({
    queryKey: ["asns", vrf?.asn_id],
    queryFn: () => asnsApi.get(vrf!.asn_id!),
    enabled: !!vrf?.asn_id,
  });

  const { data: allSpaces = [] } = useQuery({
    queryKey: ["ipam-spaces"],
    queryFn: () => ipamApi.listSpaces(),
  });

  const { data: allBlocks = [] } = useQuery({
    queryKey: ["ipam-blocks"],
    queryFn: () => ipamApi.listBlocks(),
  });

  const spaces = allSpaces.filter((s) => s.vrf_id === id);
  const blocks = allBlocks.filter((b) => b.vrf_id === id);

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (isError || !vrf) {
    return (
      <div className="p-6">
        <p className="text-sm text-destructive">VRF not found.</p>
        <Link
          to="/network/vrfs"
          className="mt-2 inline-flex items-center gap-1 text-sm text-primary hover:underline"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to VRFs
        </Link>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <Link
          to="/network/vrfs"
          className="mb-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-3 w-3" /> Back to VRFs
        </Link>
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <RouteIcon className="h-4 w-4 text-muted-foreground" />
              <h1 className="truncate text-lg font-semibold font-mono">
                {vrf.name}
              </h1>
              {vrf.route_distinguisher && (
                <span className="inline-flex rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                  RD {vrf.route_distinguisher}
                </span>
              )}
            </div>
            {vrf.description && (
              <p className="mt-1 text-xs text-muted-foreground">
                {vrf.description}
              </p>
            )}
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <ServicesUsingButton
              kind="vrf"
              resourceId={vrf.id}
              label={vrf.name}
            />
            <HeaderButton icon={Pencil} onClick={() => setShowEdit(true)}>
              Edit
            </HeaderButton>
          </div>
        </div>

        <div className="mt-4 -mb-px flex gap-1">
          {(
            [
              ["spaces", `IP Spaces (${spaces.length})`],
              ["blocks", `IP Blocks (${blocks.length})`],
              ...(featureEnabled("network.looking_glass")
                ? [["routes", "Routes"] as [Tab, string]]
                : []),
            ] as Array<[Tab, string]>
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${
                tab === key
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="mb-6">
          <Card title="VRF Details">
            <div className="grid gap-3 sm:grid-cols-2">
              <InfoRow label="Route Distinguisher">
                {vrf.route_distinguisher ?? (
                  <span className="text-muted-foreground">— not set —</span>
                )}
              </InfoRow>
              <InfoRow label="Linked ASN">
                {vrf.asn_id && asn ? (
                  <Link
                    to={`/network/asns/${vrf.asn_id}`}
                    className="text-primary hover:underline"
                  >
                    AS{asn.number}
                    {asn.name ? ` — ${asn.name}` : ""}
                  </Link>
                ) : vrf.asn_id ? (
                  <span className="font-mono text-[11px]">{vrf.asn_id}</span>
                ) : (
                  <span className="text-muted-foreground">— none —</span>
                )}
              </InfoRow>
              <InfoRow label="Import RTs">
                <RtChips values={vrf.import_targets} />
              </InfoRow>
              <InfoRow label="Export RTs">
                <RtChips values={vrf.export_targets} />
              </InfoRow>
              <InfoRow label="Tags">
                <TagChips tags={vrf.tags} />
              </InfoRow>
              <InfoRow label="Created">
                {new Date(vrf.created_at).toLocaleString()}
              </InfoRow>
            </div>
          </Card>
        </div>

        {tab === "spaces" && (
          <div className="rounded-lg border">
            {spaces.length === 0 ? (
              <div className="flex flex-col items-center gap-2 p-10 text-center">
                <p className="text-sm text-muted-foreground">
                  No IP spaces linked to this VRF
                </p>
              </div>
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-muted/30">
                  <tr className="border-b">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Name
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Description
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Created At
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {spaces.map((space) => (
                    <tr
                      key={space.id}
                      className="border-b last:border-0 hover:bg-muted/20"
                    >
                      <td className="whitespace-nowrap px-3 py-2 font-medium">
                        <Link
                          to="/ipam"
                          className="text-primary hover:underline"
                        >
                          {space.name}
                        </Link>
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {space.description || "—"}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                        {space.created_at
                          ? new Date(space.created_at).toLocaleString()
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === "blocks" && (
          <div className="rounded-lg border">
            {blocks.length === 0 ? (
              <div className="flex flex-col items-center gap-2 p-10 text-center">
                <p className="text-sm text-muted-foreground">
                  No IP blocks linked to this VRF
                </p>
              </div>
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-muted/30">
                  <tr className="border-b">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Network
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Space
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Description
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {blocks.map((block) => {
                    const space = allSpaces.find(
                      (s) => s.id === block.space_id,
                    );
                    return (
                      <tr
                        key={block.id}
                        className="border-b last:border-0 hover:bg-muted/20"
                      >
                        <td className="whitespace-nowrap px-3 py-2 font-mono">
                          {block.network}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {space ? (
                            <Link
                              to="/ipam"
                              className="text-primary hover:underline"
                            >
                              {space.name}
                            </Link>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {block.description || "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === "routes" && <VrfRoutesPanel vrf={vrf} />}
      </div>

      {showEdit && (
        <VRFEditorModal existing={vrf} onClose={() => setShowEdit(false)} />
      )}
    </div>
  );
}
