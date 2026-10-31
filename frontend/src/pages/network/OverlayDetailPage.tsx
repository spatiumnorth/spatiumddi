import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  X,
} from "lucide-react";
import {
  applicationsApi,
  circuitsApi,
  customersApi,
  formatApiError,
  ipamApi,
  networkApi,
  overlaysApi,
  sitesApi,
  type ApplicationRead,
  type CircuitRead,
  type OverlayRead,
  type OverlaySiteRead,
  type OverlaySiteRole,
  type RoutingAction,
  type RoutingMatchKind,
  type RoutingPolicyCreate,
  type RoutingPolicyRead,
  type RoutingPolicyUpdate,
  type SimulatedPolicyResolution,
  type SimulatedSiteResolution,
  type SimulateResponse,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

type Tab = "overview" | "topology" | "sites" | "policies" | "simulate";

const ROLES: OverlaySiteRole[] = ["hub", "spoke", "transit", "gateway"];
const ROLE_COLORS: Record<OverlaySiteRole, string> = {
  hub: "#7c3aed", // violet — the primary anchor
  spoke: "#0ea5e9", // sky — most sites
  transit: "#10b981", // emerald — pass-through
  gateway: "#f59e0b", // amber — egress / cloud edge
};

const MATCH_KINDS: RoutingMatchKind[] = [
  "application",
  "dscp",
  "source_subnet",
  "destination_subnet",
  "port_range",
  "acl",
];
const MATCH_KIND_LABELS: Record<RoutingMatchKind, string> = {
  application: "Application",
  dscp: "DSCP",
  source_subnet: "Source subnet",
  destination_subnet: "Destination subnet",
  port_range: "Port range",
  acl: "ACL",
};

const ACTIONS: RoutingAction[] = [
  "steer_to_circuit",
  "steer_to_transport_class",
  "steer_to_site_via_path",
  "drop",
  "shape",
  "mark_dscp",
];
const ACTION_LABELS: Record<RoutingAction, string> = {
  steer_to_circuit: "Steer to specific circuit",
  steer_to_transport_class: "Steer to transport class",
  steer_to_site_via_path: "Steer to site via named path",
  drop: "Drop",
  shape: "Shape (rate-limit)",
  mark_dscp: "Mark DSCP",
};

const TRANSPORT_CLASSES = [
  "mpls",
  "internet_broadband",
  "fiber_direct",
  "wavelength",
  "lte",
  "satellite",
  "direct_connect_aws",
  "express_route_azure",
  "interconnect_gcp",
];

// #2518 — the router asks write (delete) on 'overlay_network' for every
// site and policy route, as the overlay list does.
function useOverlayGates() {
  const perms = usePermissions();
  return {
    writeGate: permissionGate(
      perms.can("write", "overlay_network"),
      "Requires write permission on overlay networks",
    ),
    deleteGate: permissionGate(
      perms.can("delete", "overlay_network"),
      "Requires delete permission on overlay networks",
    ),
  };
}

// ── Tabs container ─────────────────────────────────────────────────

export function OverlayDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>("overview");

  const overlayQ = useQuery({
    enabled: !!id,
    queryKey: ["overlay", id],
    queryFn: () => overlaysApi.get(id),
  });

  if (overlayQ.isLoading) {
    return (
      <div className="p-6 text-sm text-muted-foreground">Loading overlay…</div>
    );
  }
  if (overlayQ.isError || !overlayQ.data) {
    return (
      <div className="p-6 text-sm text-destructive">
        Overlay not found.{" "}
        <Link to="/network/overlays" className="underline">
          Back to overlays
        </Link>
      </div>
    );
  }
  const overlay = overlayQ.data;

  const TABS: [Tab, string][] = [
    ["overview", "Overview"],
    ["topology", "Topology"],
    ["sites", `Sites (${overlay.site_count})`],
    ["policies", `Policies (${overlay.policy_count})`],
    ["simulate", "Simulate"],
  ];

  return (
    <div className="flex h-full flex-col">
      <div className="border-b bg-card px-6 pt-4">
        <Link
          to="/network/overlays"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-3 w-3" /> All overlays
        </Link>
        <div className="mt-1 flex flex-wrap items-baseline justify-between gap-2">
          <h1 className="text-xl font-semibold">{overlay.name}</h1>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span className="rounded bg-muted px-2 py-0.5 uppercase tracking-wider">
              {overlay.kind}
            </span>
            <span className="rounded bg-muted px-2 py-0.5 uppercase tracking-wider">
              {overlay.status}
            </span>
            {overlay.vendor && (
              <span className="rounded bg-muted px-2 py-0.5">
                {overlay.vendor}
              </span>
            )}
          </div>
        </div>

        <div className="mt-4 -mb-px flex gap-1 border-b">
          {TABS.map(([key, label]) => (
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
        {tab === "overview" && <OverviewTab overlay={overlay} />}
        {tab === "topology" && <TopologyTab overlayId={overlay.id} />}
        {tab === "sites" && <SitesTab overlayId={overlay.id} />}
        {tab === "policies" && <PoliciesTab overlayId={overlay.id} />}
        {tab === "simulate" && <SimulateTab overlayId={overlay.id} />}
      </div>
    </div>
  );
}

// ── Overview ───────────────────────────────────────────────────────

function OverviewTab({ overlay }: { overlay: OverlayRead }) {
  const customerQ = useQuery({
    enabled: !!overlay.customer_id,
    queryKey: ["customer", overlay.customer_id],
    queryFn: () => customersApi.get(overlay.customer_id!),
    retry: false,
  });
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Card label="Kind">{overlay.kind}</Card>
        <Card label="Vendor">{overlay.vendor ?? "—"}</Card>
        <Card label="Status">{overlay.status}</Card>
        <Card label="Default path strategy">
          {overlay.default_path_strategy}
        </Card>
        <Card label="Encryption profile">
          {overlay.encryption_profile ?? "—"}
        </Card>
        <Card label="Customer">
          {overlay.customer_id
            ? customerQ.data?.name ||
              (customerQ.isError ? "(customer in Trash)" : "Loading…")
            : "Internal / unattributed"}
        </Card>
        <Card label="Sites">{overlay.site_count}</Card>
        <Card label="Policies">{overlay.policy_count}</Card>
      </div>

      {overlay.notes && (
        <div className="rounded-md border bg-muted/20 p-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Notes
          </div>
          <p className="mt-1 whitespace-pre-wrap text-sm">{overlay.notes}</p>
        </div>
      )}
    </div>
  );
}

function Card({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 text-sm font-medium break-words">{children}</div>
    </div>
  );
}

// ── Topology — SVG circular layout ─────────────────────────────────
//
// v1 visualization: place sites evenly on a circle. Draw a line between
// any two sites whose ``preferred_circuits`` lists overlap (the
// backend hands us the intersection per edge). Colour nodes by role,
// edges by mixed transport class. Force-directed / D3 layouts are a
// polish pass.

function TopologyTab({ overlayId }: { overlayId: string }) {
  const topoQ = useQuery({
    queryKey: ["overlay-topology", overlayId],
    queryFn: () => overlaysApi.topology(overlayId),
  });

  const circuitsQ = useQuery({
    queryKey: ["circuits", "all"],
    queryFn: () => circuitsApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  if (topoQ.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading topology…</p>;
  }
  if (!topoQ.data) return null;
  const { nodes, edges } = topoQ.data;

  const transportByCircuit: Record<string, string> = {};
  for (const c of circuitsQ.data?.items ?? []) {
    transportByCircuit[c.id] = c.transport_class;
  }

  if (nodes.length === 0) {
    return (
      <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
        No sites attached yet. Use the Sites tab to add hub / spoke / transit /
        gateway sites with their preferred underlay circuits.
      </div>
    );
  }

  // Layout: sites on a circle of radius R inside a 600x600 viewBox.
  const W = 600;
  const H = 600;
  const cx = W / 2;
  const cy = H / 2;
  const R = Math.min(W, H) / 2 - 60;

  type LaidOutNode = (typeof nodes)[number] & { x: number; y: number };
  const laidOut: LaidOutNode[] = nodes.map((n, i) => {
    const theta = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    return { ...n, x: cx + R * Math.cos(theta), y: cy + R * Math.sin(theta) };
  });
  const byId = new Map(laidOut.map((n) => [n.overlay_site_id, n]));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 text-xs">
        {ROLES.map((r) => (
          <span key={r} className="inline-flex items-center gap-1">
            <span
              className="inline-block h-3 w-3 rounded-full"
              style={{ background: ROLE_COLORS[r] }}
            />
            {r}
          </span>
        ))}
      </div>

      <div className="rounded-lg border bg-card p-2">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full"
          style={{ aspectRatio: "1 / 1", maxHeight: "min(70vh, 600px)" }}
        >
          {/* Edges first so nodes render on top. */}
          {edges.map((e, i) => {
            const a = byId.get(e.a_overlay_site_id);
            const b = byId.get(e.z_overlay_site_id);
            if (!a || !b) return null;
            const transports = new Set(
              e.shared_circuits
                .map((c) => transportByCircuit[c])
                .filter(Boolean),
            );
            // Mixed transport → dashed grey; single class → solid colour.
            const stroke =
              transports.size === 1
                ? transportColor(Array.from(transports)[0]!)
                : "#94a3b8";
            const strokeDasharray = transports.size > 1 ? "6 4" : undefined;
            return (
              <line
                key={i}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={stroke}
                strokeWidth={2}
                strokeDasharray={strokeDasharray}
                opacity={0.7}
              />
            );
          })}

          {laidOut.map((n) => (
            <g key={n.overlay_site_id}>
              <circle
                cx={n.x}
                cy={n.y}
                r={22}
                fill={ROLE_COLORS[n.role as OverlaySiteRole] ?? "#64748b"}
                stroke="#0f172a"
                strokeWidth={1.5}
              />
              <text
                x={n.x}
                y={n.y + 4}
                textAnchor="middle"
                fontSize={11}
                fill="#fff"
                fontWeight="bold"
              >
                {(n.site_code || n.site_name).slice(0, 4).toUpperCase()}
              </text>
              <text
                x={n.x}
                y={n.y + 40}
                textAnchor="middle"
                fontSize={11}
                fill="currentColor"
              >
                {n.site_name}
              </text>
            </g>
          ))}
        </svg>
      </div>

      <div className="text-xs text-muted-foreground">
        Edges show site pairs that share at least one preferred circuit. Solid
        edges sit on a single transport class; dashed edges use mixed
        transports.
      </div>
    </div>
  );
}

function transportColor(transportClass: string): string {
  switch (transportClass) {
    case "mpls":
      return "#7c3aed";
    case "internet_broadband":
      return "#0ea5e9";
    case "fiber_direct":
      return "#10b981";
    case "wavelength":
      return "#a855f7";
    case "lte":
      return "#f59e0b";
    case "satellite":
      return "#f97316";
    case "direct_connect_aws":
    case "express_route_azure":
    case "interconnect_gcp":
      return "#06b6d4";
    default:
      return "#94a3b8";
  }
}

// ── Sites tab ──────────────────────────────────────────────────────

function SitesTab({ overlayId }: { overlayId: string }) {
  const qc = useQueryClient();
  const { writeGate } = useOverlayGates();
  const sitesQ = useQuery({
    queryKey: ["overlay-sites", overlayId],
    queryFn: () => overlaysApi.listSites(overlayId),
  });
  const [showAdd, setShowAdd] = useState(false);
  const [editing, setEditing] = useState<OverlaySiteRead | null>(null);
  const [confirmDetachId, setConfirmDetachId] = useState<string | null>(null);

  const detach = useMutation({
    mutationFn: (rowId: string) => overlaysApi.detachSite(overlayId, rowId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["overlay-sites", overlayId] });
      qc.invalidateQueries({ queryKey: ["overlay", overlayId] });
      qc.invalidateQueries({ queryKey: ["overlay-topology", overlayId] });
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <HeaderButton
          variant="primary"
          icon={Plus}
          onClick={() => setShowAdd(true)}
          {...writeGate}
        >
          Attach site
        </HeaderButton>
      </div>

      <SiteTable
        rows={sitesQ.data ?? []}
        onEdit={(r) => setEditing(r)}
        onDelete={(r) => setConfirmDetachId(r.id)}
      />

      {showAdd && (
        <SiteEditorModal
          overlayId={overlayId}
          existing={null}
          onClose={() => setShowAdd(false)}
        />
      )}
      {editing && (
        <SiteEditorModal
          overlayId={overlayId}
          existing={editing}
          onClose={() => setEditing(null)}
        />
      )}
      <ConfirmModal
        open={confirmDetachId !== null}
        title="Detach site"
        loading={detach.isPending}
        message={
          <>
            Detach this site from the overlay?
            {detach.isError && (
              <span role="alert" className="mt-2 block text-destructive">
                Could not detach the site:{" "}
                {formatApiError(detach.error, "the request failed")}
              </span>
            )}
          </>
        }
        confirmLabel="Detach"
        tone="destructive"
        onConfirm={() => {
          // Stays open on a refusal, so it never reads as having worked.
          if (confirmDetachId)
            detach.mutate(confirmDetachId, {
              onSuccess: () => setConfirmDetachId(null),
            });
        }}
        onClose={() => {
          detach.reset();
          setConfirmDetachId(null);
        }}
      />
    </div>
  );
}

function SiteTable({
  rows,
  onEdit,
  onDelete,
}: {
  rows: OverlaySiteRead[];
  onEdit: (r: OverlaySiteRead) => void;
  onDelete: (r: OverlaySiteRead) => void;
}) {
  const { writeGate, deleteGate } = useOverlayGates();
  const sitesQ = useQuery({
    queryKey: ["sites", "all"],
    queryFn: () => sitesApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const sitesById = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of sitesQ.data?.items ?? []) {
      m.set(s.id, s.code ? `${s.name} (${s.code})` : s.name);
    }
    return m;
  }, [sitesQ.data]);

  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-sm">
        <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-3 py-2 text-left">Site</th>
            <th className="px-3 py-2 text-left">Role</th>
            <th className="px-3 py-2 text-left">Preferred circuits</th>
            <th className="w-20 px-3 py-2 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className={zebraBodyCls}>
          {rows.length === 0 && (
            <tr>
              <td
                colSpan={4}
                className="px-3 py-6 text-center text-muted-foreground"
              >
                No sites attached yet.
              </td>
            </tr>
          )}
          {rows.map((r) => (
            <tr key={r.id} className="border-t">
              <td className="px-3 py-2 align-top">
                {sitesById.get(r.site_id) || r.site_id.slice(0, 8)}
              </td>
              <td className="px-3 py-2 align-top">
                <span
                  className="inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider text-white"
                  style={{ background: ROLE_COLORS[r.role] }}
                >
                  {r.role}
                </span>
              </td>
              <td className="px-3 py-2 align-top">
                {r.preferred_circuits.length === 0 ? (
                  <span className="text-muted-foreground/50">—</span>
                ) : (
                  <ol className="text-xs tabular-nums text-muted-foreground space-y-0.5">
                    {r.preferred_circuits.map((c, i) => (
                      <CircuitListEntry key={c} index={i} circuitId={c} />
                    ))}
                  </ol>
                )}
              </td>
              <td className="px-3 py-2 align-top text-right">
                <button
                  type="button"
                  title="Edit"
                  onClick={() => onEdit(r)}
                  className="rounded p-1 hover:bg-muted disabled:opacity-30"
                  {...writeGate}
                >
                  <Pencil className="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  title="Detach"
                  onClick={() => onDelete(r)}
                  className="ml-1 rounded p-1 text-destructive hover:bg-destructive/10 disabled:opacity-30"
                  {...deleteGate}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CircuitListEntry({
  index,
  circuitId,
}: {
  index: number;
  circuitId: string;
}) {
  const cQ = useQuery({
    queryKey: ["circuits", "all"],
    queryFn: () => circuitsApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const c = (cQ.data?.items ?? []).find((x) => x.id === circuitId);
  return (
    <li>
      <span className="mr-1 inline-flex h-4 w-4 items-center justify-center rounded bg-muted text-[10px] font-medium">
        {index + 1}
      </span>
      {c ? (
        <>
          {c.name}{" "}
          <span className="text-muted-foreground/70">
            ({c.transport_class})
          </span>
        </>
      ) : (
        circuitId.slice(0, 8)
      )}
    </li>
  );
}

function SiteEditorModal({
  overlayId,
  existing,
  onClose,
}: {
  overlayId: string;
  existing: OverlaySiteRead | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [siteId, setSiteId] = useState(existing?.site_id ?? "");
  const [role, setRole] = useState<OverlaySiteRole>(existing?.role ?? "spoke");
  const [deviceId, setDeviceId] = useState<string | null>(
    existing?.device_id ?? null,
  );
  const [loopbackSubnetId, setLoopbackSubnetId] = useState<string | null>(
    existing?.loopback_subnet_id ?? null,
  );
  const [preferredCircuits, setPreferredCircuits] = useState<string[]>(
    existing?.preferred_circuits ?? [],
  );
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);

  const sitesQ = useQuery({
    queryKey: ["sites", "all"],
    queryFn: () => sitesApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const devicesQ = useQuery({
    queryKey: ["network-devices", "all"],
    queryFn: () => networkApi.listDevices(),
    staleTime: 60_000,
  });
  const subnetsQ = useQuery({
    queryKey: ["ipam", "subnets", "all"],
    queryFn: () => ipamApi.listSubnets(),
    staleTime: 60_000,
  });
  const circuitsQ = useQuery({
    queryKey: ["circuits", "all"],
    queryFn: () => circuitsApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  const allCircuits = circuitsQ.data?.items ?? [];
  const availableCircuits = allCircuits.filter(
    (c) => !preferredCircuits.includes(c.id),
  );

  const mut = useMutation({
    mutationFn: async () => {
      if (!siteId) throw new Error("Site is required");
      const body = {
        role,
        device_id: deviceId,
        loopback_subnet_id: loopbackSubnetId,
        preferred_circuits: preferredCircuits,
        notes,
      };
      if (existing) {
        return overlaysApi.updateSite(overlayId, existing.id, body);
      }
      return overlaysApi.attachSite(overlayId, { site_id: siteId, ...body });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["overlay-sites", overlayId] });
      qc.invalidateQueries({ queryKey: ["overlay", overlayId] });
      qc.invalidateQueries({ queryKey: ["overlay-topology", overlayId] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  function moveCircuit(idx: number, dir: -1 | 1) {
    setPreferredCircuits((prev) => {
      const next = [...prev];
      const target = idx + dir;
      if (target < 0 || target >= next.length) return prev;
      [next[idx], next[target]] = [next[target], next[idx]];
      return next;
    });
  }

  return (
    <Modal
      onClose={onClose}
      title={existing ? "Edit overlay site" : "Attach site"}
      wide
    >
      <div className="space-y-3">
        {!existing && (
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Site
            </label>
            <select
              className={inputCls}
              value={siteId}
              onChange={(e) => setSiteId(e.target.value)}
            >
              <option value="">— select —</option>
              {(sitesQ.data?.items ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                  {s.code ? ` (${s.code})` : ""}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Role
            </label>
            <select
              className={inputCls}
              value={role}
              onChange={(e) => setRole(e.target.value as OverlaySiteRole)}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Edge device (optional)
            </label>
            <select
              className={inputCls}
              value={deviceId ?? ""}
              onChange={(e) => setDeviceId(e.target.value || null)}
            >
              <option value="">— None —</option>
              {(devicesQ.data?.items ?? []).map((d) => (
                <option key={d.id} value={d.id}>
                  {d.hostname || d.name}
                </option>
              ))}
            </select>
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Loopback / TLOC subnet (optional)
            </label>
            <select
              className={inputCls}
              value={loopbackSubnetId ?? ""}
              onChange={(e) => setLoopbackSubnetId(e.target.value || null)}
            >
              <option value="">— None —</option>
              {(subnetsQ.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.network} {s.name ? `— ${s.name}` : ""}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Preferred circuits (failover order)
          </label>
          <div className="mt-1 rounded-md border">
            {preferredCircuits.length === 0 ? (
              <p className="px-3 py-3 text-xs text-muted-foreground">
                No circuits yet — pick from the dropdown below.
              </p>
            ) : (
              <ul className="divide-y">
                {preferredCircuits.map((cid, idx) => {
                  const c = allCircuits.find((x) => x.id === cid);
                  return (
                    <li
                      key={cid}
                      className="flex items-center gap-2 px-3 py-2 text-sm"
                    >
                      <span className="inline-flex h-5 w-5 items-center justify-center rounded bg-muted text-[10px] font-medium">
                        {idx + 1}
                      </span>
                      <span className="flex-1">
                        {c?.name ?? cid.slice(0, 8)}
                        {c && (
                          <span className="ml-2 text-xs text-muted-foreground">
                            {c.transport_class}
                          </span>
                        )}
                      </span>
                      <button
                        type="button"
                        title="Move up"
                        disabled={idx === 0}
                        onClick={() => moveCircuit(idx, -1)}
                        className="rounded p-1 hover:bg-muted disabled:opacity-30"
                      >
                        <ArrowUp className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        title="Move down"
                        disabled={idx === preferredCircuits.length - 1}
                        onClick={() => moveCircuit(idx, 1)}
                        className="rounded p-1 hover:bg-muted disabled:opacity-30"
                      >
                        <ArrowDown className="h-3.5 w-3.5" />
                      </button>
                      <button
                        type="button"
                        title="Remove"
                        onClick={() =>
                          setPreferredCircuits((prev) =>
                            prev.filter((x) => x !== cid),
                          )
                        }
                        className="rounded p-1 text-destructive hover:bg-destructive/10"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
          <select
            className={cn(inputCls, "mt-2")}
            value=""
            onChange={(e) => {
              if (e.target.value) {
                setPreferredCircuits((prev) => [...prev, e.target.value]);
              }
            }}
          >
            <option value="">+ add circuit</option>
            {availableCircuits.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.transport_class})
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Notes
          </label>
          <textarea
            className={cn(inputCls, "min-h-[60px]")}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>
      </div>

      {error && <p className="mt-3 text-sm text-destructive">{error}</p>}

      <div className="mt-6 flex justify-end gap-2 border-t pt-3">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={mut.isPending}
          onClick={() => mut.mutate()}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {mut.isPending ? "Saving…" : existing ? "Save" : "Attach"}
        </button>
      </div>
    </Modal>
  );
}

// ── Policies tab ───────────────────────────────────────────────────

function PoliciesTab({ overlayId }: { overlayId: string }) {
  const qc = useQueryClient();
  const { writeGate, deleteGate } = useOverlayGates();
  const policiesQ = useQuery({
    queryKey: ["overlay-policies", overlayId],
    queryFn: () => overlaysApi.listPolicies(overlayId),
  });
  const [showAdd, setShowAdd] = useState(false);
  const [editing, setEditing] = useState<RoutingPolicyRead | null>(null);
  const [confirm, setConfirm] = useState<{
    name: string;
    onConfirm: () => void;
  } | null>(null);

  const remove = useMutation({
    mutationFn: (id: string) => overlaysApi.deletePolicy(overlayId, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["overlay-policies", overlayId] });
      qc.invalidateQueries({ queryKey: ["overlay", overlayId] });
    },
  });

  // Reorder: compute the new priority by averaging neighbours so we
  // don't have to renumber the whole list. ``move(p, -1)`` slots p
  // above its previous sibling; ``move(p, 1)`` slots it below the next.
  const updatePriority = useMutation({
    mutationFn: (args: { id: string; priority: number }) =>
      overlaysApi.updatePolicy(overlayId, args.id, { priority: args.priority }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["overlay-policies", overlayId] });
    },
  });

  function move(idx: number, dir: -1 | 1) {
    const list = policiesQ.data ?? [];
    const target = idx + dir;
    if (target < 0 || target >= list.length) return;
    const me = list[idx];
    const them = list[target];
    // Swap priorities. The server orders by priority asc; equal
    // priorities tie-break by created_at, so we bump the moving row
    // by one to avoid an undefined order on equal priorities.
    const newPriority =
      dir === -1 ? Math.max(0, them.priority - 1) : them.priority + 1;
    updatePriority.mutate({ id: me.id, priority: newPriority });
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <HeaderButton
          variant="primary"
          icon={Plus}
          onClick={() => setShowAdd(true)}
          {...writeGate}
        >
          New policy
        </HeaderButton>
      </div>

      {(remove.isError || updatePriority.isError) && (
        <p role="alert" className="text-sm text-destructive">
          {formatApiError(
            remove.error ?? updatePriority.error,
            "Change failed",
          )}
        </p>
      )}
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-sm">
          <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="w-16 px-3 py-2 text-left">Priority</th>
              <th className="px-3 py-2 text-left">Name</th>
              <th className="px-3 py-2 text-left">Match</th>
              <th className="px-3 py-2 text-left">Action</th>
              <th className="px-3 py-2 text-left">Target</th>
              <th className="w-16 px-3 py-2 text-left">Enabled</th>
              <th className="w-32 px-3 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {(policiesQ.data ?? []).length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  No policies yet — create one to override the default path
                  strategy.
                </td>
              </tr>
            )}
            {(policiesQ.data ?? []).map((p, idx) => (
              <tr key={p.id} className="border-t">
                <td className="px-3 py-2 align-top tabular-nums">
                  {p.priority}
                </td>
                <td className="px-3 py-2 align-top break-words font-medium">
                  {p.name}
                </td>
                <td className="px-3 py-2 align-top text-xs text-muted-foreground">
                  <span className="rounded bg-muted px-2 py-0.5 mr-1">
                    {MATCH_KIND_LABELS[p.match_kind]}
                  </span>
                  <code className="text-[11px]">{p.match_value}</code>
                </td>
                <td className="px-3 py-2 align-top text-xs text-muted-foreground">
                  {ACTION_LABELS[p.action]}
                </td>
                <td className="px-3 py-2 align-top text-xs text-muted-foreground">
                  {p.action_target ? <code>{p.action_target}</code> : "—"}
                </td>
                <td className="px-3 py-2 align-top text-xs">
                  {p.enabled ? (
                    <span className="text-emerald-600 dark:text-emerald-400">
                      ✓
                    </span>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
                <td className="px-3 py-2 align-top text-right">
                  <button
                    type="button"
                    title="Move up"
                    disabled={idx === 0 || updatePriority.isPending}
                    onClick={() => move(idx, -1)}
                    className="rounded p-1 hover:bg-muted disabled:opacity-30"
                    {...writeGate}
                  >
                    <ArrowUp className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    title="Move down"
                    disabled={
                      idx === (policiesQ.data?.length ?? 0) - 1 ||
                      updatePriority.isPending
                    }
                    onClick={() => move(idx, 1)}
                    className="rounded p-1 hover:bg-muted disabled:opacity-30"
                    {...writeGate}
                  >
                    <ArrowDown className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    title="Edit"
                    onClick={() => setEditing(p)}
                    className="rounded p-1 hover:bg-muted disabled:opacity-30"
                    {...writeGate}
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    title="Delete"
                    onClick={() => {
                      setConfirm({
                        name: p.name,
                        onConfirm: () => remove.mutate(p.id),
                      });
                    }}
                    className="rounded p-1 text-destructive hover:bg-destructive/10 disabled:opacity-30"
                    {...deleteGate}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showAdd && (
        <PolicyEditorModal
          overlayId={overlayId}
          existing={null}
          onClose={() => setShowAdd(false)}
        />
      )}
      {editing && (
        <PolicyEditorModal
          overlayId={overlayId}
          existing={editing}
          onClose={() => setEditing(null)}
        />
      )}
      <ConfirmModal
        open={confirm !== null}
        title="Delete policy"
        message={`Delete policy "${confirm?.name ?? ""}"?`}
        confirmLabel="Delete"
        tone="destructive"
        onConfirm={() => {
          confirm?.onConfirm();
          setConfirm(null);
        }}
        onClose={() => setConfirm(null)}
      />
    </div>
  );
}

function PolicyEditorModal({
  overlayId,
  existing,
  onClose,
}: {
  overlayId: string;
  existing: RoutingPolicyRead | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [priority, setPriority] = useState(String(existing?.priority ?? 100));
  const [matchKind, setMatchKind] = useState<RoutingMatchKind>(
    existing?.match_kind ?? "application",
  );
  const [matchValue, setMatchValue] = useState(existing?.match_value ?? "");
  const [action, setAction] = useState<RoutingAction>(
    existing?.action ?? "steer_to_transport_class",
  );
  const [actionTarget, setActionTarget] = useState(
    existing?.action_target ?? "",
  );
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);

  const appsQ = useQuery({
    enabled: matchKind === "application",
    queryKey: ["applications", "all"],
    queryFn: () => applicationsApi.list(),
    staleTime: 60_000,
  });
  const circuitsQ = useQuery({
    enabled: action === "steer_to_circuit",
    queryKey: ["circuits", "all"],
    queryFn: () => circuitsApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error("Name is required");
      if (!matchValue.trim()) throw new Error("Match value is required");
      const body: RoutingPolicyCreate | RoutingPolicyUpdate = {
        name,
        priority: Number(priority) || 100,
        match_kind: matchKind,
        match_value: matchValue,
        action,
        action_target: actionTarget || null,
        enabled,
        notes,
      };
      if (existing) {
        return overlaysApi.updatePolicy(overlayId, existing.id, body);
      }
      return overlaysApi.createPolicy(overlayId, body as RoutingPolicyCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["overlay-policies", overlayId] });
      qc.invalidateQueries({ queryKey: ["overlay", overlayId] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  function matchValueHelper() {
    switch (matchKind) {
      case "application":
        return "An entry from the application catalog (e.g. office365).";
      case "dscp":
        return "DSCP value 0-63 or named (EF, AF11, …).";
      case "source_subnet":
      case "destination_subnet":
        return "CIDR (e.g. 10.0.0.0/8).";
      case "port_range":
        return 'Format: "tcp:80-443" / "udp:53".';
      case "acl":
        return "Free-form ACL identifier — vendor-specific.";
    }
  }

  function actionTargetHelper() {
    switch (action) {
      case "steer_to_circuit":
        return "Circuit UUID (pick below).";
      case "steer_to_transport_class":
        return "Transport class (mpls / internet_broadband / …).";
      case "steer_to_site_via_path":
        return "Site UUID + named path (operator-defined format).";
      case "drop":
        return "Leave blank.";
      case "shape":
        return "Bandwidth limit, e.g. 10mbps.";
      case "mark_dscp":
        return "DSCP value 0-63 or named.";
    }
  }

  return (
    <Modal
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "New routing policy"}
      wide
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="text-xs font-medium text-muted-foreground">
            Name
          </label>
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Steer Office365 to MPLS"
            autoFocus={!existing}
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Priority
          </label>
          <input
            type="number"
            min={0}
            max={10000}
            className={inputCls}
            value={priority}
            onChange={(e) => setPriority(e.target.value)}
          />
          <p className="mt-0.5 text-[11px] text-muted-foreground/80">
            Lower = evaluated first. Tied priorities tie-break by creation
            order.
          </p>
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enabled
          </label>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Match kind
          </label>
          <select
            className={inputCls}
            value={matchKind}
            onChange={(e) => {
              setMatchKind(e.target.value as RoutingMatchKind);
              setMatchValue("");
            }}
          >
            {MATCH_KINDS.map((k) => (
              <option key={k} value={k}>
                {MATCH_KIND_LABELS[k]}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Match value
          </label>
          {matchKind === "application" ? (
            <select
              className={inputCls}
              value={matchValue}
              onChange={(e) => setMatchValue(e.target.value)}
            >
              <option value="">— select —</option>
              {(appsQ.data?.items ?? []).map((a: ApplicationRead) => (
                <option key={a.id} value={a.name}>
                  {a.name}
                </option>
              ))}
            </select>
          ) : (
            <input
              className={inputCls}
              value={matchValue}
              onChange={(e) => setMatchValue(e.target.value)}
            />
          )}
          <p className="mt-0.5 text-[11px] text-muted-foreground/80">
            {matchValueHelper()}
          </p>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Action
          </label>
          <select
            className={inputCls}
            value={action}
            onChange={(e) => {
              setAction(e.target.value as RoutingAction);
              setActionTarget("");
            }}
          >
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {ACTION_LABELS[a]}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Action target
          </label>
          {action === "steer_to_transport_class" ? (
            <select
              className={inputCls}
              value={actionTarget}
              onChange={(e) => setActionTarget(e.target.value)}
            >
              <option value="">— select —</option>
              {TRANSPORT_CLASSES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          ) : action === "steer_to_circuit" ? (
            <select
              className={inputCls}
              value={actionTarget}
              onChange={(e) => setActionTarget(e.target.value)}
            >
              <option value="">— select —</option>
              {(circuitsQ.data?.items ?? []).map((c: CircuitRead) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.transport_class})
                </option>
              ))}
            </select>
          ) : (
            <input
              className={inputCls}
              value={actionTarget}
              onChange={(e) => setActionTarget(e.target.value)}
            />
          )}
          <p className="mt-0.5 text-[11px] text-muted-foreground/80">
            {actionTargetHelper()}
          </p>
        </div>
        <div className="sm:col-span-2">
          <label className="text-xs font-medium text-muted-foreground">
            Notes
          </label>
          <textarea
            className={cn(inputCls, "min-h-[60px]")}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>
      </div>

      {error && <p className="mt-3 text-sm text-destructive">{error}</p>}

      <div className="mt-6 flex justify-end gap-2 border-t pt-3">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={mut.isPending}
          onClick={() => mut.mutate()}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
        </button>
      </div>
    </Modal>
  );
}

// ── Simulate tab ───────────────────────────────────────────────────

function SimulateTab({ overlayId }: { overlayId: string }) {
  const [downCircuits, setDownCircuits] = useState<Set<string>>(new Set());
  const [result, setResult] = useState<SimulateResponse | null>(null);

  const circuitsQ = useQuery({
    queryKey: ["circuits", "all"],
    queryFn: () => circuitsApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  const sitesQ = useQuery({
    queryKey: ["overlay-sites", overlayId],
    queryFn: () => overlaysApi.listSites(overlayId),
  });

  // Filter the circuits list to those actually referenced anywhere in
  // the overlay so the operator doesn't see 200 unrelated rows.
  const referencedCircuitIds = useMemo(() => {
    const ids = new Set<string>();
    for (const s of sitesQ.data ?? []) {
      for (const c of s.preferred_circuits) ids.add(c);
    }
    return ids;
  }, [sitesQ.data]);
  const candidates =
    (circuitsQ.data?.items ?? []).filter((c) =>
      referencedCircuitIds.has(c.id),
    ) ?? [];

  const sim = useMutation({
    mutationFn: () =>
      overlaysApi.simulate(overlayId, {
        down_circuits: Array.from(downCircuits),
      }),
    onSuccess: (data) => setResult(data),
  });

  function toggle(id: string) {
    setDownCircuits((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-4">
        <p className="text-sm">
          Pure read-only what-if. Toggle one or more circuits to "down" and run
          the simulation to see the effective routing — per site, the surviving
          preferred-circuit chain + the new primary; per policy, whether it's
          impacted and the operator-readable consequence.
        </p>
        <p className="mt-2 text-xs text-muted-foreground">
          Only circuits referenced by this overlay's sites are listed. Nothing
          is written.
        </p>
      </div>

      <div className="rounded-lg border">
        <div className="border-b bg-muted/30 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Mark circuits down
        </div>
        {candidates.length === 0 ? (
          <p className="px-3 py-6 text-center text-sm text-muted-foreground">
            No circuits referenced by this overlay's sites yet — attach sites
            with preferred circuits first.
          </p>
        ) : (
          <ul className="divide-y">
            {candidates.map((c) => (
              <li
                key={c.id}
                className="flex items-center gap-3 px-3 py-2 text-sm"
              >
                <input
                  type="checkbox"
                  checked={downCircuits.has(c.id)}
                  onChange={() => toggle(c.id)}
                />
                <span className="flex-1">
                  <span className="font-medium">{c.name}</span>{" "}
                  <span className="text-xs text-muted-foreground">
                    ({c.transport_class})
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={sim.isPending}
          onClick={() => sim.mutate()}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {sim.isPending ? "Simulating…" : "Run simulation"}
        </button>
        {downCircuits.size > 0 && (
          <button
            type="button"
            onClick={() => {
              setDownCircuits(new Set());
              setResult(null);
            }}
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            Clear
          </button>
        )}
        {sim.isError && (
          <p className="text-xs text-destructive">Simulation failed</p>
        )}
      </div>

      {result && <SimulateResults result={result} />}
    </div>
  );
}

function SimulateResults({ result }: { result: SimulateResponse }) {
  const blackholeCount = result.site_resolutions.filter(
    (s) => s.blackholed,
  ).length;
  const impactedCount = result.policy_resolutions.filter(
    (p) => p.impacted,
  ).length;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <Card label="Down circuits">{result.down_circuits.length}</Card>
        <Card label="Blackholed sites">{blackholeCount}</Card>
        <Card label="Impacted policies">{impactedCount}</Card>
      </div>

      <div className="rounded-lg border">
        <div className="border-b bg-muted/30 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Per-site resolution
        </div>
        <table className="w-full text-sm">
          <thead className="bg-muted/20 text-xs uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left">Site</th>
              <th className="px-3 py-2 text-left">Original</th>
              <th className="px-3 py-2 text-left">Surviving</th>
              <th className="px-3 py-2 text-left">New primary</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {result.site_resolutions.map((s: SimulatedSiteResolution) => (
              <tr key={s.overlay_site_id} className="border-t">
                <td className="px-3 py-2 align-top font-medium">
                  {s.site_name}
                </td>
                <td className="px-3 py-2 align-top text-xs tabular-nums text-muted-foreground">
                  {s.original_preferred_circuits.length}
                </td>
                <td
                  className={cn(
                    "px-3 py-2 align-top text-xs tabular-nums",
                    s.blackholed ? "text-destructive" : "text-muted-foreground",
                  )}
                >
                  {s.surviving_preferred_circuits.length}
                </td>
                <td className="px-3 py-2 align-top text-xs">
                  {s.blackholed ? (
                    <span className="rounded bg-red-100 px-2 py-0.5 text-red-700 dark:bg-red-950/40 dark:text-red-300">
                      blackholed
                    </span>
                  ) : (
                    <>
                      <span className="font-medium">
                        {s.primary_circuit_name ?? "—"}
                      </span>
                      {s.primary_transport_class && (
                        <span className="ml-1 text-muted-foreground">
                          ({s.primary_transport_class})
                        </span>
                      )}
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-lg border">
        <div className="border-b bg-muted/30 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Per-policy resolution
        </div>
        <table className="w-full text-sm">
          <thead className="bg-muted/20 text-xs uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left">Policy</th>
              <th className="px-3 py-2 text-left">Action</th>
              <th className="px-3 py-2 text-left">Original target</th>
              <th className="px-3 py-2 text-left">Effective target</th>
              <th className="px-3 py-2 text-left">Note</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {result.policy_resolutions.map((p: SimulatedPolicyResolution) => (
              <tr
                key={p.policy_id}
                className={cn(
                  "border-t",
                  p.impacted && "bg-amber-50 dark:bg-amber-950/20",
                )}
              >
                <td className="px-3 py-2 align-top font-medium">
                  {p.policy_name}
                </td>
                <td className="px-3 py-2 align-top text-xs text-muted-foreground">
                  {ACTION_LABELS[p.action]}
                </td>
                <td className="px-3 py-2 align-top text-xs tabular-nums text-muted-foreground break-all">
                  {p.original_target ?? "—"}
                </td>
                <td className="px-3 py-2 align-top text-xs tabular-nums text-muted-foreground break-all">
                  {p.effective_target ?? "—"}
                </td>
                <td className="px-3 py-2 align-top text-xs text-muted-foreground break-words">
                  {p.note ?? (p.impacted ? "impacted" : "—")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Suppress unused-import warning for ``RefreshCw`` — kept available
// for a future refresh button on detail tabs.
const _unused = RefreshCw;
void _unused;
