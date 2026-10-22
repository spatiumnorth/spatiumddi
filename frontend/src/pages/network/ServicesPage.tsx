import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Filter, Pencil, Plus, RefreshCw, Trash2, X } from "lucide-react";
import {
  circuitsApi,
  customersApi,
  dhcpApi,
  dnsApi,
  ipamApi,
  overlaysApi,
  servicesApi,
  sitesApi,
  vrfsApi,
  type CustomGroupedSummary,
  type L3VPNSummary,
  type ServiceCreate,
  type ServiceKind,
  type ServiceRead,
  type ServiceResourceKind,
  type ServiceResourceRead,
  type ServiceStatus,
  type ServiceUpdate,
} from "@/lib/api";
import { formatDateOnly, termDaysLeft } from "@/lib/localTime";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal, ModalTabs } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { TagFilterChips } from "@/components/TagFilterChips";
import { CustomerChip } from "@/components/ownership/pickers";
import { SavedViewsMenu } from "@/components/SavedViewsMenu";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { useModuleOn } from "@/hooks/useModuleOn";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const KINDS: ServiceKind[] = ["mpls_l3vpn", "sdwan", "custom"];
const KIND_LABELS: Record<ServiceKind, string> = {
  mpls_l3vpn: "MPLS L3VPN",
  sdwan: "SD-WAN",
  custom: "Custom bundle",
};

const STATUSES: ServiceStatus[] = [
  "active",
  "provisioning",
  "suspended",
  "decom",
];

// Resource kinds the v1 router accepts. ``overlay_network`` lit up
// alongside #95 — services with ``kind=sdwan`` typically bundle one as
// the central deliverable.
const RESOURCE_KINDS: ServiceResourceKind[] = [
  "vrf",
  "subnet",
  "ip_block",
  "dns_zone",
  "dhcp_scope",
  "circuit",
  "site",
  "overlay_network",
];

const RESOURCE_KIND_LABELS: Record<ServiceResourceKind, string> = {
  vrf: "VRF",
  subnet: "Subnet",
  ip_block: "IP block",
  dns_zone: "DNS zone",
  dhcp_scope: "DHCP scope",
  circuit: "Circuit",
  overlay_network: "SD-WAN overlay",
  site: "Site",
};

function StatusBadge({ status }: { status: ServiceStatus }) {
  const styles: Record<ServiceStatus, string> = {
    active:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    provisioning:
      "bg-sky-100 text-sky-700 dark:bg-sky-950/30 dark:text-sky-400",
    suspended:
      "bg-rose-100 text-rose-700 dark:bg-rose-950/30 dark:text-rose-400",
    decom: "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        styles[status],
      )}
    >
      {status}
    </span>
  );
}

function KindBadge({ kind }: { kind: ServiceKind }) {
  const styles: Record<ServiceKind, string> = {
    mpls_l3vpn:
      "bg-violet-100 text-violet-700 dark:bg-violet-950/30 dark:text-violet-300",
    sdwan:
      "bg-fuchsia-100 text-fuchsia-700 dark:bg-fuchsia-950/30 dark:text-fuchsia-300",
    custom: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium",
        styles[kind],
      )}
    >
      {KIND_LABELS[kind]}
    </span>
  );
}

function TermBadge({ termEnd }: { termEnd: string | null }) {
  if (!termEnd) return <span className="text-muted-foreground/50">—</span>;
  const days = termDaysLeft(termEnd);
  let cls =
    "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400";
  let label = `${days}d`;
  if (days < 0) {
    cls = "bg-red-200 text-red-900 dark:bg-red-950/50 dark:text-red-300";
    label = `expired ${Math.abs(days)}d ago`;
  } else if (days < 30) {
    cls = "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400";
  } else if (days <= 90) {
    cls =
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400";
  }
  return (
    <span className="inline-flex items-center gap-2">
      <span className="text-[11px] tabular-nums text-muted-foreground">
        {formatDateOnly(termEnd)}
      </span>
      <span
        className={cn(
          "rounded px-2 py-0.5 text-[10px] font-medium tabular-nums",
          cls,
        )}
      >
        {label}
      </span>
    </span>
  );
}

function formatCost(cost: string | null, currency: string): string {
  if (!cost) return "—";
  const n = Number(cost);
  if (Number.isNaN(n)) return cost;
  return `${n.toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })} ${currency}`;
}

// ── Resource picker hooks ──────────────────────────────────────────
//
// Each kind has its own list query. DNS zones and DHCP scopes are
// per-group on the backend so we fan out across groups and aggregate
// here — typical deployments have 1-3 groups so the fan-out cost is
// acceptable.

function useResourcePool() {
  const vrfs = useQuery({
    queryKey: ["vrfs", "all"],
    queryFn: () => vrfsApi.list(),
    staleTime: 60_000,
  });
  const subnets = useQuery({
    queryKey: ["ipam", "subnets", "all"],
    queryFn: () => ipamApi.listSubnets(),
    staleTime: 60_000,
  });
  const blocks = useQuery({
    queryKey: ["ipam", "blocks", "all"],
    queryFn: () => ipamApi.listBlocks(),
    staleTime: 60_000,
  });
  const sites = useQuery({
    queryKey: ["sites", "all"],
    queryFn: () => sitesApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const circuits = useQuery({
    queryKey: ["circuits", "all"],
    queryFn: () => circuitsApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const overlays = useQuery({
    queryKey: ["overlays", "all"],
    queryFn: () => overlaysApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  // #2135 — DNS zones can only be attached while core.dns is on; the reads
  // would 404 otherwise.
  const dnsOn = useModuleOn("core.dns");
  const dnsGroups = useQuery({
    queryKey: ["dns-groups", "all"],
    queryFn: () => dnsApi.listGroups(),
    staleTime: 60_000,
    enabled: dnsOn,
  });
  const dnsZones = useQuery({
    enabled: dnsOn && !!dnsGroups.data,
    queryKey: ["dns-zones", "all", (dnsGroups.data ?? []).map((g) => g.id)],
    queryFn: async () => {
      const groups = dnsGroups.data ?? [];
      const lists = await Promise.all(
        groups.map((g) =>
          dnsApi
            .listZones(g.id)
            .then((zs) => zs.map((z) => ({ ...z, _groupName: g.name }))),
        ),
      );
      return lists.flat();
    },
    staleTime: 60_000,
  });

  // #2130 — DHCP scopes can only be attached while core.dhcp is on; the
  // reads would 404 otherwise.
  const dhcpOn = useModuleOn("core.dhcp");
  const dhcpGroups = useQuery({
    queryKey: ["dhcp-groups", "all"],
    queryFn: () => dhcpApi.listGroups(),
    staleTime: 60_000,
    enabled: dhcpOn,
  });
  const dhcpScopes = useQuery({
    enabled: dhcpOn && !!dhcpGroups.data,
    queryKey: ["dhcp-scopes", "all", (dhcpGroups.data ?? []).map((g) => g.id)],
    queryFn: async () => {
      const groups = dhcpGroups.data ?? [];
      const lists = await Promise.all(
        groups.map((g) =>
          dhcpApi
            .listScopesByGroup(g.id)
            .then((ss) => ss.map((s) => ({ ...s, _groupName: g.name }))),
        ),
      );
      return lists.flat();
    },
    staleTime: 60_000,
  });

  return {
    vrf: vrfs.data ?? [],
    subnet: subnets.data ?? [],
    ip_block: blocks.data ?? [],
    site: sites.data?.items ?? [],
    circuit: circuits.data?.items ?? [],
    overlay_network: overlays.data?.items ?? [],
    dns_zone: dnsZones.data ?? [],
    dhcp_scope: dhcpScopes.data ?? [],
  };
}

function resourceLabel(
  kind: ServiceResourceKind,
  id: string,
  pool: ReturnType<typeof useResourcePool>,
): string {
  const short = id.slice(0, 8);
  switch (kind) {
    case "vrf": {
      const v = pool.vrf.find((x) => x.id === id);
      return v ? v.name : `vrf:${short}`;
    }
    case "subnet": {
      const s = pool.subnet.find((x) => x.id === id);
      return s
        ? `${s.network}${s.name ? ` — ${s.name}` : ""}`
        : `subnet:${short}`;
    }
    case "ip_block": {
      const b = pool.ip_block.find((x) => x.id === id);
      return b
        ? `${b.network}${b.name ? ` — ${b.name}` : ""}`
        : `block:${short}`;
    }
    case "site": {
      const s = pool.site.find((x) => x.id === id);
      return s ? `${s.name}${s.code ? ` (${s.code})` : ""}` : `site:${short}`;
    }
    case "circuit": {
      const c = pool.circuit.find((x) => x.id === id);
      return c ? c.name : `circuit:${short}`;
    }
    case "dns_zone": {
      const z = pool.dns_zone.find((x) => x.id === id);
      return z ? z.name : `zone:${short}`;
    }
    case "dhcp_scope": {
      const sc = pool.dhcp_scope.find((x) => x.id === id);
      return sc ? sc.name || `scope:${short}` : `scope:${short}`;
    }
    case "overlay_network": {
      const o = pool.overlay_network.find((x) => x.id === id);
      return o
        ? `${o.name}${o.kind ? ` · ${o.kind}` : ""}`
        : `overlay:${short}`;
    }
  }
}

// ── Resources tab — attach / detach UI ─────────────────────────────

function ResourcesTab({
  service,
  onChange,
}: {
  service: ServiceRead;
  onChange: () => void;
}) {
  const qc = useQueryClient();
  const pool = useResourcePool();
  const dhcpOn = useModuleOn("core.dhcp");
  const dnsOn = useModuleOn("core.dns");

  const [addKind, setAddKind] = useState<ServiceResourceKind>("vrf");
  const [addId, setAddId] = useState<string>("");
  const [addRole, setAddRole] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{
    message: string;
    onConfirm: () => void;
  } | null>(null);

  const attach = useMutation({
    mutationFn: () =>
      servicesApi.attachResource(service.id, {
        resource_kind: addKind,
        resource_id: addId,
        role: addRole || null,
      }),
    onSuccess: () => {
      setAddId("");
      setAddRole("");
      setError(null);
      qc.invalidateQueries({ queryKey: ["services"] });
      qc.invalidateQueries({ queryKey: ["service", service.id] });
      qc.invalidateQueries({ queryKey: ["service-summary", service.id] });
      onChange();
    },
    onError: (e: unknown) => {
      const err = e as { response?: { data?: { detail?: string } } };
      setError(err?.response?.data?.detail ?? "Attach failed");
    },
  });

  const detach = useMutation({
    mutationFn: (linkId: string) =>
      servicesApi.detachResource(service.id, linkId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["services"] });
      qc.invalidateQueries({ queryKey: ["service", service.id] });
      qc.invalidateQueries({ queryKey: ["service-summary", service.id] });
      onChange();
    },
  });

  // Build the per-kind <option> list for the resource picker.
  const optionsFor = (kind: ServiceResourceKind) => {
    switch (kind) {
      case "vrf":
        return pool.vrf.map((v) => ({
          id: v.id,
          label: `${v.name}${v.route_distinguisher ? ` (${v.route_distinguisher})` : ""}`,
        }));
      case "subnet":
        return pool.subnet.map((s) => ({
          id: s.id,
          label: `${s.network}${s.name ? ` — ${s.name}` : ""}`,
        }));
      case "ip_block":
        return pool.ip_block.map((b) => ({
          id: b.id,
          label: `${b.network}${b.name ? ` — ${b.name}` : ""}`,
        }));
      case "site":
        return pool.site.map((s) => ({
          id: s.id,
          label: `${s.name}${s.code ? ` (${s.code})` : ""}`,
        }));
      case "circuit":
        return pool.circuit.map((c) => ({
          id: c.id,
          label: `${c.name}${c.ckt_id ? ` (${c.ckt_id})` : ""}`,
        }));
      case "dns_zone":
        return pool.dns_zone.map((z) => ({
          id: z.id,
          label: `${z.name}${
            (z as { _groupName?: string })._groupName
              ? ` · ${(z as { _groupName?: string })._groupName}`
              : ""
          }`,
        }));
      case "dhcp_scope":
        return pool.dhcp_scope.map((sc) => ({
          id: sc.id,
          label: `${sc.name || sc.id.slice(0, 8)}${
            (sc as { _groupName?: string })._groupName
              ? ` · ${(sc as { _groupName?: string })._groupName}`
              : ""
          }`,
        }));
      case "overlay_network":
        return pool.overlay_network.map((o) => ({
          id: o.id,
          label: `${o.name} · ${o.kind}${o.vendor ? ` (${o.vendor})` : ""}`,
        }));
    }
  };

  const options = optionsFor(addKind);

  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-3">
        <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Attach resource
        </div>
        <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-[140px_1fr_140px_auto]">
          <select
            className={inputCls}
            value={addKind}
            onChange={(e) => {
              setAddKind(e.target.value as ServiceResourceKind);
              setAddId("");
            }}
          >
            {RESOURCE_KINDS.filter(
              (k) =>
                (dhcpOn || k !== "dhcp_scope") && (dnsOn || k !== "dns_zone"),
            ).map((k) => (
              <option key={k} value={k}>
                {RESOURCE_KIND_LABELS[k]}
              </option>
            ))}
          </select>
          <select
            className={inputCls}
            value={addId}
            onChange={(e) => setAddId(e.target.value)}
          >
            <option value="">
              — select a {RESOURCE_KIND_LABELS[addKind]} —
            </option>
            {options.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
          <input
            className={inputCls}
            value={addRole}
            onChange={(e) => setAddRole(e.target.value)}
            placeholder="role (optional)"
          />
          <button
            type="button"
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            disabled={!addId || attach.isPending}
            onClick={() => attach.mutate()}
          >
            {attach.isPending ? "Attaching…" : "Attach"}
          </button>
        </div>
        {error && <p className="mt-2 text-xs text-destructive">{error}</p>}
        <p className="mt-2 text-[11px] text-muted-foreground/80">
          Common L3VPN roles: <code>primary</code> / <code>backup</code> /{" "}
          <code>hub</code> / <code>spoke</code>. Free-form — use whatever your
          team's runbooks already use.
        </p>
      </div>

      <div className="rounded-md border">
        <div className="border-b bg-muted/30 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Attached resources ({service.resources.length})
        </div>
        {service.resources.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-muted-foreground">
            No resources attached yet — pick one above.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/20 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Kind</th>
                <th className="px-3 py-2 text-left">Resource</th>
                <th className="px-3 py-2 text-left">Role</th>
                <th className="w-12 px-3 py-2 text-right" />
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {service.resources.map((r) => (
                <tr key={r.id} className="border-t">
                  <td className="px-3 py-2 align-top">
                    <span className="rounded bg-muted px-2 py-0.5 text-[11px] uppercase tracking-wider text-muted-foreground">
                      {RESOURCE_KIND_LABELS[r.resource_kind]}
                    </span>
                  </td>
                  <td className="px-3 py-2 align-top break-all font-medium">
                    {resourceLabel(r.resource_kind, r.resource_id, pool)}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground">
                    {r.role ?? "—"}
                  </td>
                  <td className="px-3 py-2 align-top text-right">
                    <button
                      type="button"
                      title="Detach"
                      onClick={() => {
                        setConfirm({
                          message: `Detach ${RESOURCE_KIND_LABELS[r.resource_kind]} from this service?`,
                          onConfirm: () => detach.mutate(r.id),
                        });
                      }}
                      className="rounded p-1 text-destructive hover:bg-destructive/10"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <ConfirmModal
        open={confirm !== null}
        title="Detach resource"
        message={confirm?.message ?? ""}
        confirmLabel="Detach"
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

// ── Summary tab — kind-aware view ──────────────────────────────────

function SummaryTab({ serviceId }: { serviceId: string }) {
  const summaryQ = useQuery({
    queryKey: ["service-summary", serviceId],
    queryFn: () => servicesApi.summary(serviceId),
  });

  if (summaryQ.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }
  const summary = summaryQ.data;
  if (!summary) return null;

  if (summary.kind === "mpls_l3vpn") {
    return <L3VPNSummaryView summary={summary} />;
  }
  return <CustomSummaryView summary={summary} />;
}

function L3VPNSummaryView({ summary }: { summary: L3VPNSummary }) {
  return (
    <div className="space-y-3">
      <div className="rounded-md border bg-muted/20 p-3">
        <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          VRF
        </div>
        {summary.vrf ? (
          <div className="mt-1 text-sm">
            <div className="font-medium">{summary.vrf.name}</div>
            <div className="text-xs text-muted-foreground tabular-nums">
              RD {summary.vrf.route_distinguisher ?? "—"} · import{" "}
              {summary.vrf.import_targets.join(", ") || "—"} · export{" "}
              {summary.vrf.export_targets.join(", ") || "—"}
            </div>
          </div>
        ) : (
          <p className="mt-1 text-sm text-muted-foreground">
            No VRF attached. L3VPN services should have exactly one — attach via
            the Resources tab.
          </p>
        )}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="rounded-md border p-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Edge sites ({summary.edge_sites.length})
          </div>
          {summary.edge_sites.length === 0 ? (
            <p className="mt-1 text-xs text-muted-foreground">None</p>
          ) : (
            <ul className="mt-1 space-y-1 text-sm">
              {summary.edge_sites.map((s) => (
                <li key={s.id}>
                  <span className="font-medium">{s.name}</span>
                  {s.code && (
                    <span className="text-muted-foreground"> ({s.code})</span>
                  )}
                  {s.role && (
                    <span className="ml-1 text-xs text-muted-foreground">
                      · {s.role}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="rounded-md border p-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Edge circuits ({summary.edge_circuits.length})
          </div>
          {summary.edge_circuits.length === 0 ? (
            <p className="mt-1 text-xs text-muted-foreground">None</p>
          ) : (
            <ul className="mt-1 space-y-1 text-sm">
              {summary.edge_circuits.map((c) => (
                <li key={c.id}>
                  <span className="font-medium">{c.name}</span>
                  <span className="text-xs text-muted-foreground">
                    {" "}
                    · {c.transport_class}
                  </span>
                  {c.role && (
                    <span className="ml-1 text-xs text-muted-foreground">
                      · {c.role}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="rounded-md border p-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Edge subnets ({summary.edge_subnets.length})
          </div>
          {summary.edge_subnets.length === 0 ? (
            <p className="mt-1 text-xs text-muted-foreground">None</p>
          ) : (
            <ul className="mt-1 space-y-1 text-sm tabular-nums">
              {summary.edge_subnets.map((s) => (
                <li key={s.id}>
                  {s.cidr}
                  {s.role && (
                    <span className="ml-1 text-xs text-muted-foreground">
                      · {s.role}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {summary.warnings.length > 0 && (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 dark:border-amber-900/40 dark:bg-amber-950/20">
          <div className="text-xs font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-400">
            Warnings
          </div>
          <ul className="mt-1 list-disc pl-5 text-xs text-amber-700 dark:text-amber-300">
            {summary.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function CustomSummaryView({ summary }: { summary: CustomGroupedSummary }) {
  const total = Object.values(summary.by_kind).reduce(
    (a: number, b: number) => a + b,
    0,
  );
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        Custom service bundle — {total} attached resource
        {total === 1 ? "" : "s"} across {Object.keys(summary.by_kind).length}{" "}
        kind
        {Object.keys(summary.by_kind).length === 1 ? "" : "s"}.
      </p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {Object.entries(summary.by_kind).map(([kind, count]) => (
          <div key={kind} className="rounded-md border p-3">
            <div className="text-xs uppercase tracking-wider text-muted-foreground">
              {RESOURCE_KIND_LABELS[kind as ServiceResourceKind] ?? kind}
            </div>
            <div className="mt-1 text-2xl font-semibold tabular-nums">
              {count}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Editor modal ───────────────────────────────────────────────────

type EditorTab = "general" | "resources" | "term" | "notes" | "summary";

function ServiceEditorModal({
  existing,
  onClose,
}: {
  existing: ServiceRead | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [tab, setTab] = useState<EditorTab>("general");

  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState<ServiceKind>(existing?.kind ?? "custom");
  const [customerId, setCustomerId] = useState(existing?.customer_id ?? "");
  const [status, setStatus] = useState<ServiceStatus>(
    existing?.status ?? "provisioning",
  );
  const [slaTier, setSlaTier] = useState(existing?.sla_tier ?? "");
  const [termStart, setTermStart] = useState(existing?.term_start_date ?? "");
  const [termEnd, setTermEnd] = useState(existing?.term_end_date ?? "");
  const [monthlyCost, setMonthlyCost] = useState(
    existing?.monthly_cost_usd ?? "",
  );
  const [currency, setCurrency] = useState(existing?.currency ?? "USD");
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);

  const customersQ = useQuery({
    queryKey: ["customers", "all"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const customers = customersQ.data?.items ?? [];

  // Re-fetch the existing service so that newly attached / detached
  // resources flow into the Resources tab without remounting the modal.
  const refreshed = useQuery({
    enabled: !!existing,
    queryKey: ["service", existing?.id],
    queryFn: () => servicesApi.get(existing!.id),
    initialData: existing ?? undefined,
  });
  const liveExisting = refreshed.data ?? existing;

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error("Name is required");
      if (!customerId) throw new Error("Customer is required");
      const body: ServiceCreate | ServiceUpdate = {
        name,
        kind,
        customer_id: customerId,
        status,
        term_start_date: termStart || null,
        term_end_date: termEnd || null,
        monthly_cost_usd: monthlyCost || null,
        currency: currency || "USD",
        sla_tier: slaTier || null,
        notes,
      };
      if (existing) return servicesApi.update(existing.id, body);
      return servicesApi.create(body as ServiceCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["services"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string } };
      };
      setError(err?.response?.data?.detail ?? err?.message ?? "Save failed");
    },
  });

  const tabs: { key: EditorTab; label: string }[] = [
    { key: "general", label: "General" },
    ...(existing
      ? [
          { key: "resources" as EditorTab, label: "Resources" },
          { key: "summary" as EditorTab, label: "Summary" },
        ]
      : []),
    { key: "term", label: "Term + cost" },
    { key: "notes", label: "Notes" },
  ];

  return (
    <Modal
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "New service"}
      wide
    >
      <div className="space-y-3 pb-4">
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Name
          </label>
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Acme Corp HQ-DC L3VPN"
            autoFocus={!existing}
          />
          <p className="mt-0.5 text-[11px] text-muted-foreground/80">
            Unique within a customer — two customers can both have a service
            named "HQ-DC L3VPN".
          </p>
        </div>
      </div>

      <ModalTabs<EditorTab> tabs={tabs} active={tab} onChange={setTab} />

      {tab === "general" && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Kind
            </label>
            <select
              className={inputCls}
              value={kind}
              onChange={(e) => setKind(e.target.value as ServiceKind)}
            >
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </select>
            <p className="mt-0.5 text-[11px] text-muted-foreground/80">
              Other kinds (DIA, hosted DNS / DHCP, MPLS L2VPN, VPLS, EVPN) light
              up in later phases.
            </p>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Customer
            </label>
            <select
              className={inputCls}
              value={customerId}
              onChange={(e) => setCustomerId(e.target.value)}
            >
              <option value="">— select —</option>
              {customers.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Status
            </label>
            <select
              className={inputCls}
              value={status}
              onChange={(e) => setStatus(e.target.value as ServiceStatus)}
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              SLA tier (optional)
            </label>
            <input
              className={inputCls}
              value={slaTier}
              onChange={(e) => setSlaTier(e.target.value)}
              placeholder="e.g. gold / silver / bronze"
            />
            <p className="mt-0.5 text-[11px] text-muted-foreground/80">
              Free-form label — actual SLA enforcement is out of scope for this
              entity.
            </p>
          </div>
        </div>
      )}

      {tab === "resources" && liveExisting && (
        <ResourcesTab
          service={liveExisting}
          onChange={() => refreshed.refetch()}
        />
      )}

      {tab === "summary" && existing && <SummaryTab serviceId={existing.id} />}

      {tab === "term" && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Term start
            </label>
            <input
              type="date"
              className={inputCls}
              value={termStart}
              onChange={(e) => setTermStart(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Term end
            </label>
            <input
              type="date"
              className={inputCls}
              value={termEnd}
              onChange={(e) => setTermEnd(e.target.value)}
            />
            <p className="mt-0.5 text-[11px] text-muted-foreground/80">
              Drives the <code>service_term_expiring</code> alert rule.
            </p>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Monthly cost
            </label>
            <input
              type="text"
              inputMode="decimal"
              className={inputCls}
              value={monthlyCost}
              onChange={(e) => setMonthlyCost(e.target.value)}
              placeholder="e.g. 12500.00"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Currency
            </label>
            <input
              className={cn(inputCls, "uppercase")}
              maxLength={3}
              value={currency}
              onChange={(e) => setCurrency(e.target.value.toUpperCase())}
              placeholder="USD"
            />
            <p className="mt-0.5 text-[11px] text-muted-foreground/80">
              ISO 4217 3-letter code. Reports group by currency rather than
              converting.
            </p>
          </div>
        </div>
      )}

      {tab === "notes" && (
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Notes
          </label>
          <textarea
            className={cn(inputCls, "min-h-[160px]")}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Service-specific runbook notes, customer contacts, escalation paths."
          />
        </div>
      )}

      {error && <p className="mt-3 text-sm text-destructive">{error}</p>}

      <div className="mt-6 flex justify-end gap-2 border-t pt-3">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          {existing ? "Close" : "Cancel"}
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

// ── Page ───────────────────────────────────────────────────────────

export function ServicesPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the network_service router asks write (delete) on 'network_service'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "network_service"),
    "Requires write permission on network services",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "network_service"),
    "Requires delete permission on network services",
  );
  const qc = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  // Reverse-lookup mode (#99): when both params are present we show only the
  // services that reference the given resource instead of the full catalog.
  const resourceKindParam = searchParams.get(
    "resource_kind",
  ) as ServiceResourceKind | null;
  const resourceIdParam = searchParams.get("resource_id");
  const resourceLabelParam = searchParams.get("resource_label");
  const byResourceActive = Boolean(resourceKindParam && resourceIdParam);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<ServiceStatus | "">("");
  const [kindFilter, setKindFilter] = useState<ServiceKind | "">("");
  const [customerFilter, setCustomerFilter] = useState("");
  const [editing, setEditing] = useState<ServiceRead | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [tagFilters, setTagFilters] = useState<string[]>([]);

  const customersQ = useQuery({
    queryKey: ["customers", "all"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  const query = useQuery({
    queryKey: [
      "services",
      search,
      statusFilter,
      kindFilter,
      customerFilter,
      tagFilters,
    ],
    queryFn: () =>
      servicesApi.list({
        limit: 500,
        search: search || undefined,
        status: (statusFilter || undefined) as ServiceStatus | undefined,
        kind: (kindFilter || undefined) as ServiceKind | undefined,
        customer_id: customerFilter || undefined,
        tag: tagFilters.length > 0 ? tagFilters : undefined,
      }),
    enabled: !byResourceActive,
  });

  const byResourceQuery = useQuery({
    queryKey: ["services-by-resource", resourceKindParam, resourceIdParam],
    queryFn: () =>
      servicesApi.byResource(
        resourceKindParam as ServiceResourceKind,
        resourceIdParam as string,
      ),
    enabled: byResourceActive,
  });

  // One handle the rest of the page reads from regardless of mode.
  const activeQuery = byResourceActive ? byResourceQuery : query;
  const items = byResourceActive
    ? (byResourceQuery.data ?? [])
    : (query.data?.items ?? []);

  // Saved-views payload (#77) — the page's filter state, stored verbatim.
  type ServicesViewPayload = {
    search: string;
    status: ServiceStatus | "";
    kind: ServiceKind | "";
    customer_id: string;
    tags: string[];
  };
  const viewPayload: ServicesViewPayload = {
    search,
    status: statusFilter,
    kind: kindFilter,
    customer_id: customerFilter,
    tags: tagFilters,
  };
  function applyView(p: ServicesViewPayload) {
    setSearch(typeof p.search === "string" ? p.search : "");
    setStatusFilter((p.status ?? "") as ServiceStatus | "");
    setKindFilter((p.kind ?? "") as ServiceKind | "");
    setCustomerFilter(typeof p.customer_id === "string" ? p.customer_id : "");
    setTagFilters(Array.isArray(p.tags) ? p.tags : []);
  }

  const allChecked = useMemo(
    () => items.length > 0 && items.every((s) => selectedIds.has(s.id)),
    [items, selectedIds],
  );

  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => servicesApi.bulkDelete(ids),
    onSuccess: () => {
      setSelectedIds(new Set());
      qc.invalidateQueries({ queryKey: ["services"] });
    },
  });

  const removeOne = useMutation({
    mutationFn: (id: string) => servicesApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["services"] }),
  });

  function toggle(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }
  function toggleAll() {
    if (allChecked) setSelectedIds(new Set());
    else setSelectedIds(new Set(items.map((s) => s.id)));
  }

  // Edge-site count from the resources array — small enough to compute
  // client-side without a separate summary call per row.
  function edgeSiteCount(s: ServiceRead): number {
    return s.resources.filter(
      (r: ServiceResourceRead) => r.resource_kind === "site",
    ).length;
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-semibold">Services</h1>
            <p className="text-sm text-muted-foreground">
              Customer-deliverable bundles. <code>mpls_l3vpn</code> is the VRF +
              edge sites + edge circuits flavour; <code>sdwan</code> bundles an
              overlay network + edge sites + circuits; <code>custom</code> is
              the catch-all bag of resources. Other kinds (DIA, hosted DNS /
              DHCP, MPLS L2VPN, VPLS, EVPN) light up in later phases.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {!byResourceActive && (
              <SavedViewsMenu
                page="network.services"
                currentPayload={viewPayload}
                onApply={applyView}
              />
            )}
            <HeaderButton
              icon={RefreshCw}
              onClick={() => activeQuery.refetch()}
              iconClassName={
                activeQuery.isFetching ? "animate-spin" : undefined
              }
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowNew(true)}
              {...writeGate}
            >
              New service
            </HeaderButton>
          </div>
        </div>

        {byResourceActive && (
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-sm">
            <span className="flex items-center gap-2 text-muted-foreground">
              <Filter className="h-4 w-4 shrink-0 text-primary" />
              Showing services that reference{" "}
              {resourceKindParam && (
                <span className="font-medium text-foreground">
                  {RESOURCE_KIND_LABELS[resourceKindParam]}
                </span>
              )}{" "}
              <span className="font-medium text-foreground break-all">
                {resourceLabelParam ?? resourceIdParam}
              </span>
              .
            </span>
            <button
              type="button"
              onClick={() => setSearchParams({})}
              className="inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 hover:bg-muted"
            >
              <X className="h-3.5 w-3.5" /> Clear filter
            </button>
          </div>
        )}

        {!byResourceActive && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <input
                className={cn(inputCls, "max-w-xs")}
                placeholder="Search name…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <select
                className={cn(inputCls, "max-w-[180px]")}
                value={kindFilter}
                onChange={(e) =>
                  setKindFilter(e.target.value as ServiceKind | "")
                }
              >
                <option value="">All kinds</option>
                {KINDS.map((k) => (
                  <option key={k} value={k}>
                    {KIND_LABELS[k]}
                  </option>
                ))}
              </select>
              <select
                className={cn(inputCls, "max-w-[180px]")}
                value={statusFilter}
                onChange={(e) =>
                  setStatusFilter(e.target.value as ServiceStatus | "")
                }
              >
                <option value="">All statuses</option>
                {STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
              <select
                className={cn(inputCls, "max-w-[200px]")}
                value={customerFilter}
                onChange={(e) => setCustomerFilter(e.target.value)}
              >
                <option value="">All customers</option>
                {(customersQ.data?.items ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>

            <TagFilterChips
              value={tagFilters}
              onChange={setTagFilters}
              placeholder="Filter by tag — try env or env:prod…"
            />
          </>
        )}

        {selectedIds.size > 0 && (
          <div className="flex items-center justify-between rounded-md border bg-muted/50 px-3 py-2 text-sm">
            <span>{selectedIds.size} selected</span>
            <HeaderButton
              variant="destructive"
              icon={Trash2}
              disabled={bulkDelete.isPending}
              onClick={() => {
                const ids = Array.from(selectedIds);
                setConfirm({
                  title: "Delete services",
                  message: `Delete ${ids.length} service${ids.length === 1 ? "" : "s"}?`,
                  confirmLabel: "Delete",
                  onConfirm: () => bulkDelete.mutate(ids),
                });
              }}
              {...deleteGate}
            >
              Delete selected
            </HeaderButton>
          </div>
        )}

        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="w-8 px-3 py-2">
                  <input
                    type="checkbox"
                    checked={allChecked}
                    onChange={toggleAll}
                    aria-label="Select all"
                  />
                </th>
                <th className="px-3 py-2 text-left">Name</th>
                <th className="px-3 py-2 text-left">Customer</th>
                <th className="px-3 py-2 text-left">Kind</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Edge sites</th>
                <th className="px-3 py-2 text-left">Resources</th>
                <th className="px-3 py-2 text-left">Term ends</th>
                <th className="px-3 py-2 text-left">Monthly</th>
                <th className="w-24 px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {activeQuery.isLoading && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={10}
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!activeQuery.isLoading && items.length === 0 && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={10}
                  >
                    {byResourceActive
                      ? `No services reference this ${resourceKindParam ? RESOURCE_KIND_LABELS[resourceKindParam] : "resource"}.`
                      : 'No services yet — click "New service" to add one.'}
                  </td>
                </tr>
              )}
              {items.map((s) => (
                <tr key={s.id} className="border-t">
                  <td className="px-3 py-2 align-top">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(s.id)}
                      onChange={() => toggle(s.id)}
                    />
                  </td>
                  <td className="px-3 py-2 align-top break-words font-medium">
                    {s.name}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <CustomerChip customerId={s.customer_id} />
                  </td>
                  <td className="px-3 py-2 align-top">
                    <KindBadge kind={s.kind} />
                  </td>
                  <td className="px-3 py-2 align-top">
                    <StatusBadge status={s.status} />
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground tabular-nums">
                    {edgeSiteCount(s)}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground tabular-nums">
                    {s.resource_count}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <TermBadge termEnd={s.term_end_date} />
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground tabular-nums">
                    {formatCost(s.monthly_cost_usd, s.currency)}
                  </td>
                  <td className="px-3 py-2 align-top text-right">
                    <button
                      type="button"
                      title="Edit"
                      onClick={() => setEditing(s)}
                      className="rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                      {...writeGate}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      title="Delete"
                      onClick={() => {
                        setConfirm({
                          title: "Delete service",
                          message: `Delete service "${s.name}"?`,
                          confirmLabel: "Delete",
                          onConfirm: () => removeOne.mutate(s.id),
                        });
                      }}
                      className="ml-1 rounded p-1 text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"
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

        {showNew && (
          <ServiceEditorModal
            existing={null}
            onClose={() => setShowNew(false)}
          />
        )}
        {editing && (
          <ServiceEditorModal
            existing={editing}
            onClose={() => setEditing(null)}
          />
        )}
        <ConfirmModal
          open={confirm !== null}
          title={confirm?.title ?? ""}
          message={confirm?.message ?? ""}
          confirmLabel={confirm?.confirmLabel}
          tone="destructive"
          onConfirm={() => {
            confirm?.onConfirm();
            setConfirm(null);
          }}
          onClose={() => setConfirm(null)}
        />
      </div>
    </div>
  );
}
