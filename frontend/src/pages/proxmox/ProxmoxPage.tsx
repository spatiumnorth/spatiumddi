import { useModuleOn } from "@/hooks/useModuleOn";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Clipboard,
  HardDrive,
  Info,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  TestTube2,
  RotateCw,
  XCircle,
} from "lucide-react";

import {
  proxmoxApi,
  dnsApi,
  type DNSServerGroup,
  type ProxmoxDiscoveryGuest,
  type ProxmoxNode,
  type ProxmoxNodeCreate,
  type ProxmoxNodeUpdate,
  type ProxmoxTestResult,
} from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { IPSpacePicker } from "@/components/ipam/space-picker";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import { secondsFieldError, SYNC_INTERVAL_BOUNDS } from "@/lib/seconds";

// ── Setup guide ─────────────────────────────────────────────────────
// One-shot snippet operators can paste into a root shell on any PVE
// node to produce a read-only API token scoped to the minimum
// privileges this integration needs.

const SETUP_TOKEN = `# On any Proxmox VE node, in a root shell:

# 1. Create a dedicated user for SpatiumDDI (realm 'pve' is local).
pveum useradd spatiumddi@pve --comment "SpatiumDDI read-only"

# 2. Give it the built-in PVEAuditor role on the whole datacentre.
#    PVEAuditor = read-only on all resources + pools + storage.
pveum aclmod / -user spatiumddi@pve -role PVEAuditor

# 3. Issue an API token for it — copy the printed value once.
#    The --privsep=0 flag says "inherit user's ACLs" (no extra scope
#    narrowing). For tighter scope, set --privsep=1 and grant ACLs
#    to the token separately.
pveum user token add spatiumddi@pve spatiumddi --privsep=0

#    Prints:
#    ┌──────────────┬──────────────────────────────────────┐
#    │ key          │ value                                │
#    ╞══════════════╪══════════════════════════════════════╡
#    │ full-tokenid │ spatiumddi@pve!spatiumddi            │
#    │ value        │ 12345678-abcd-ef01-2345-67890abcdef0 │
#    └──────────────┴──────────────────────────────────────┘

# Paste 'full-tokenid' into "Token ID" and 'value' into "Token Secret".`;

// ── Page ─────────────────────────────────────────────────────────────

export function ProxmoxPage() {
  // #1340 — every write on this integration takes a superadmin (its
  // router's create / update / delete / sync / test handlers take
  // SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: nodes = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["proxmox-nodes"],
    queryFn: proxmoxApi.listNodes,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<ProxmoxNode | null>(null);
  const [del, setDel] = useState<ProxmoxNode | null>(null);
  const [discover, setDiscover] = useState<ProxmoxNode | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, ProxmoxTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => proxmoxApi.deleteNode(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["proxmox-nodes"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => proxmoxApi.testConnection({ node_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["proxmox-nodes"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => proxmoxApi.syncNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["proxmox-nodes"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["proxmox-nodes"] }),
        5000,
      );
    },
  });

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="border-b px-6 py-4 bg-card">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <HardDrive className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Proxmox Endpoints</h1>
              <span className="text-xs text-muted-foreground">
                {nodes.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each endpoint is polled via the PVE REST
              API with an API token; a single row can represent a whole cluster.
              Bridges with a CIDR land in the bound IPAM space as subnets; VMs
              and LXC guests land as IP addresses (with runtime IPs via the QEMU
              guest agent when available). SpatiumDDI never writes to Proxmox.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["proxmox-nodes"] })
              }
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowCreate(true)}
              {...superadminGate}
            >
              Add Endpoint
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {nodes.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="Proxmox endpoints">
                  No Proxmox endpoints configured yet.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> Add Endpoint
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1020px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Name
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Enabled
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Endpoint
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      PVE
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Cluster
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Last sync
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Test
                    </th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {nodes.map((n) => {
                    const tr = inlineTest[n.id];
                    return (
                      <tr key={n.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          {n.name}
                          {n.description && (
                            <div
                              className="text-[11px] text-muted-foreground max-w-md truncate"
                              title={n.description}
                            >
                              {n.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {n.enabled ? (
                            <span className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
                              enabled
                            </span>
                          ) : (
                            <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                              disabled
                            </span>
                          )}
                        </td>
                        <td
                          className="max-w-xs truncate px-3 py-2 font-mono text-[11px]"
                          title={`https://${n.host}:${n.port}`}
                        >
                          <span className="text-muted-foreground">
                            https://
                          </span>
                          {n.host}:{n.port}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {n.pve_version ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {n.cluster_name
                            ? `${n.cluster_name} (${n.node_count ?? "?"})`
                            : n.node_count
                              ? `${n.node_count} node${n.node_count === 1 ? "" : "s"}`
                              : "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {n.last_synced_at
                            ? new Date(n.last_synced_at).toLocaleString()
                            : "never"}
                          {n.last_sync_error && (
                            <div
                              className="text-[11px] text-destructive max-w-xs truncate"
                              title={n.last_sync_error}
                            >
                              {n.last_sync_error}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <button
                            onClick={() => testMut.mutate(n.id)}
                            disabled={testMut.isPending}
                            className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
                            {...superadminGate}
                          >
                            <TestTube2 className="h-3 w-3" />
                            Test
                          </button>
                          {tr && (
                            <div
                              className={`mt-1 max-w-xs truncate text-[11px] ${
                                tr.ok
                                  ? "text-emerald-600 dark:text-emerald-400"
                                  : "text-destructive"
                              }`}
                              title={tr.message}
                            >
                              {tr.ok ? "✓" : "✗"} {tr.message}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <button
                            onClick={() => syncMut.mutate(n.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === n.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
                            {...superadminGate}
                          >
                            <RotateCw
                              className={`h-3.5 w-3.5 ${
                                syncMut.isPending && syncMut.variables === n.id
                                  ? "animate-spin"
                                  : ""
                              }`}
                            />
                          </button>
                          <button
                            onClick={() => setDiscover(n)}
                            disabled={!n.last_discovery}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed"
                            title={
                              n.last_discovery
                                ? "Discovery — see which guests aren't reporting IPs"
                                : "Sync at least once to populate discovery"
                            }
                          >
                            <Search className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setEdit(n)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                            title="Edit"
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(n)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                            title="Delete"
                            {...superadminGate}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {showCreate && <NodeModal onClose={() => setShowCreate(false)} />}
      {edit && <NodeModal node={edit} onClose={() => setEdit(null)} />}
      {discover && (
        <DiscoveryModal node={discover} onClose={() => setDiscover(null)} />
      )}
      {del && (
        <DeleteNodeModal
          node={del}
          onClose={() => setDel(null)}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Discovery modal ─────────────────────────────────────────────────
//
// Renders the per-guest diagnostic snapshot the reconciler writes on
// every successful sync. Gives operators an eyeball view of why a VM
// isn't reporting an IP (agent off / agent not responding / no NICs /
// no static IP) with copy-ready hints, without having to read the
// reconciler logs.

type IssueFilter = "all" | "issues" | ProxmoxDiscoveryGuest["issue"];

function DiscoveryModal({
  node,
  onClose,
}: {
  node: ProxmoxNode;
  onClose: () => void;
}) {
  const [filter, setFilter] = useState<IssueFilter>("issues");
  const [query, setQuery] = useState("");

  const d = node.last_discovery;
  if (!d) {
    return (
      <Modal title={`Discovery — ${node.name}`} onClose={onClose} wide>
        <p className="text-sm text-muted-foreground">
          No discovery data yet — run a sync first.
        </p>
        <div className="flex justify-end pt-3">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Close
          </button>
        </div>
      </Modal>
    );
  }

  const rows = d.guests.filter((g) => {
    if (filter === "issues" && g.issue === null) return false;
    if (filter !== "all" && filter !== "issues" && g.issue !== filter)
      return false;
    if (!query.trim()) return true;
    const q = query.trim().toLowerCase();
    return (
      g.name.toLowerCase().includes(q) ||
      String(g.vmid).includes(q) ||
      g.node.toLowerCase().includes(q) ||
      g.bridges.some((b) => b.toLowerCase().includes(q))
    );
  });

  const issueCount = d.guests.filter((g) => g.issue !== null).length;

  const counterPill = (
    label: string,
    value: number,
    tone: "ok" | "warn" | "neutral",
  ) => {
    const toneCls =
      tone === "ok"
        ? "text-emerald-700 bg-emerald-50 dark:bg-emerald-500/10 dark:text-emerald-300"
        : tone === "warn"
          ? "text-amber-700 bg-amber-50 dark:bg-amber-500/10 dark:text-amber-300"
          : "text-muted-foreground bg-muted";
    return (
      <div className={`rounded-md px-2 py-1 text-xs leading-tight ${toneCls}`}>
        <div className="font-semibold text-sm">{value}</div>
        <div className="text-[10px] uppercase tracking-wide opacity-70">
          {label}
        </div>
      </div>
    );
  };

  return (
    <Modal title={`Discovery — ${node.name}`} onClose={onClose} wide>
      <div className="space-y-4">
        {/* Generated + source line */}
        <p className="text-[11px] text-muted-foreground">
          Snapshot from last sync {new Date(d.generated_at).toLocaleString()} —
          re-sync to refresh.
        </p>

        {/* Counter grid */}
        <div className="grid grid-cols-4 sm:grid-cols-6 gap-2">
          {counterPill(
            "VMs",
            d.summary.vm_total,
            d.summary.vm_total === 0 ? "neutral" : "neutral",
          )}
          {counterPill("VM agent ok", d.summary.vm_agent_reporting, "ok")}
          {counterPill(
            "VM agent off",
            d.summary.vm_agent_off,
            d.summary.vm_agent_off > 0 ? "warn" : "neutral",
          )}
          {counterPill(
            "VM no agent resp.",
            d.summary.vm_agent_not_responding,
            d.summary.vm_agent_not_responding > 0 ? "warn" : "neutral",
          )}
          {counterPill("LXC reporting", d.summary.lxc_reporting, "ok")}
          {counterPill(
            "LXC no IP",
            d.summary.lxc_no_ip,
            d.summary.lxc_no_ip > 0 ? "warn" : "neutral",
          )}
          {counterPill("SDN VNets", d.summary.sdn_vnets_total, "neutral")}
          {counterPill(
            "VNets w/ subnet",
            d.summary.sdn_vnets_with_subnet,
            "ok",
          )}
          {counterPill(
            "VNets unresolved",
            d.summary.sdn_vnets_unresolved,
            d.summary.sdn_vnets_unresolved > 0 ? "warn" : "neutral",
          )}
          {counterPill(
            "Subnets mirrored",
            d.summary.desired_subnets,
            "neutral",
          )}
          {counterPill(
            "IPs skipped",
            d.summary.addresses_skipped_no_subnet,
            d.summary.addresses_skipped_no_subnet > 0 ? "warn" : "neutral",
          )}
        </div>

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-2 border-y py-2">
          <div className="flex items-center gap-1 text-xs">
            {(
              [
                ["issues", `Issues (${issueCount})`],
                ["all", `All (${d.guests.length})`],
                ["agent_not_responding", "Agent not responding"],
                ["agent_off", "Agent off"],
                ["no_ip", "No IP"],
                ["no_nic", "No NIC"],
                ["static_only", "Static only"],
              ] as [IssueFilter, string][]
            ).map(([v, label]) => (
              <button
                key={String(v)}
                onClick={() => setFilter(v)}
                className={`rounded-md border px-2 py-1 text-[11px] ${
                  filter === v
                    ? "bg-primary text-primary-foreground border-primary"
                    : "hover:bg-muted"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="ml-auto">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by name / vmid / node / bridge…"
              className="w-64 rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
        </div>

        {/* Guest table */}
        {rows.length === 0 ? (
          <div className="py-10 text-center text-sm text-muted-foreground">
            {filter === "issues"
              ? "No issues found — every guest is mirroring IPs into IPAM."
              : "No guests match the current filter."}
          </div>
        ) : (
          <div className="max-h-[50vh] overflow-y-auto rounded-md border">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-muted/40 z-10">
                <tr className="border-b">
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    Kind
                  </th>
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    VMID
                  </th>
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    Name
                  </th>
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    Node
                  </th>
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    Status
                  </th>
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    Agent
                  </th>
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    Bridges
                  </th>
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    IPs mirrored
                  </th>
                  <th className="whitespace-nowrap px-2 py-1.5 text-left font-medium">
                    Issue / Hint
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((g) => (
                  <tr
                    key={`${g.kind}-${g.vmid}`}
                    className="border-b last:border-0 align-top"
                  >
                    <td className="px-2 py-1.5 font-mono text-[10px] uppercase">
                      {g.kind}
                    </td>
                    <td className="px-2 py-1.5 font-mono">{g.vmid}</td>
                    <td className="px-2 py-1.5 font-medium">{g.name}</td>
                    <td className="px-2 py-1.5 text-muted-foreground">
                      {g.node}
                    </td>
                    <td className="px-2 py-1.5">
                      <span
                        className={
                          g.status === "running"
                            ? "text-emerald-600 dark:text-emerald-400"
                            : "text-muted-foreground"
                        }
                      >
                        {g.status}
                      </span>
                    </td>
                    <td className="px-2 py-1.5">
                      <AgentPill state={g.agent_state} />
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-muted-foreground">
                      {g.bridges.length === 0 ? "—" : g.bridges.join(", ")}
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="font-mono">
                        {g.ips_mirrored}
                        {g.ips_mirrored > 0 && (
                          <span className="text-muted-foreground">
                            {" "}
                            ({g.ips_from_agent}a/{g.ips_from_static}s)
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="px-2 py-1.5 max-w-xs">
                      <IssueCell issue={g.issue} hint={g.hint} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

function AgentPill({ state }: { state: ProxmoxDiscoveryGuest["agent_state"] }) {
  if (state === "reporting") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-1.5 py-0.5 text-[10px] text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300">
        <CheckCircle2 className="h-3 w-3" /> reporting
      </span>
    );
  }
  if (state === "not_responding") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-1.5 py-0.5 text-[10px] text-amber-700 dark:bg-amber-500/10 dark:text-amber-300">
        <AlertTriangle className="h-3 w-3" /> not responding
      </span>
    );
  }
  if (state === "off") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
        <XCircle className="h-3 w-3" /> off
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
      n/a
    </span>
  );
}

function IssueCell({
  issue,
  hint,
}: {
  issue: ProxmoxDiscoveryGuest["issue"];
  hint: string | null;
}) {
  if (issue === null) {
    return (
      <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
        <Check className="h-3 w-3" /> ok
      </span>
    );
  }
  const LABEL: Record<NonNullable<ProxmoxDiscoveryGuest["issue"]>, string> = {
    agent_not_responding: "Agent not responding",
    agent_off: "Agent off",
    no_ip: "No IP",
    no_nic: "No NIC",
    static_only: "Static only",
  };
  const tone = issue === "static_only" ? "info" : "warn";
  const toneCls =
    tone === "warn"
      ? "text-amber-700 dark:text-amber-300"
      : "text-blue-700 dark:text-blue-300";
  const Icon = tone === "warn" ? AlertTriangle : Info;
  return (
    <div className={`text-[11px] ${toneCls}`}>
      <div className="inline-flex items-center gap-1 font-medium">
        <Icon className="h-3 w-3" /> {LABEL[issue]}
      </div>
      {hint && (
        <div className="mt-0.5 text-muted-foreground leading-snug">{hint}</div>
      )}
    </div>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function NodeModal({
  node,
  onClose,
}: {
  node?: ProxmoxNode;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!node;

  // DNS off (#2135): no /dns/groups read and no picker. The stored
  // dns_group_id is sent back untouched, so saving here cannot clear it.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: dnsOn,
  });

  const [name, setName] = useState(node?.name ?? "");
  const [description, setDescription] = useState(node?.description ?? "");
  const [enabled, setEnabled] = useState(node?.enabled ?? true);
  const [host, setHost] = useState(node?.host ?? "");
  const [port, setPort] = useState(node?.port ?? 8006);
  const [verifyTls, setVerifyTls] = useState(node?.verify_tls ?? true);
  const [caBundlePem, setCaBundlePem] = useState("");
  const [tokenId, setTokenId] = useState(node?.token_id ?? "");
  const [tokenSecret, setTokenSecret] = useState("");
  const [spaceId, setSpaceId] = useState(node?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(node?.dns_group_id ?? "");
  const [mirrorVms, setMirrorVms] = useState(node?.mirror_vms ?? true);
  const [mirrorLxc, setMirrorLxc] = useState(node?.mirror_lxc ?? true);
  const [includeStopped, setIncludeStopped] = useState(
    node?.include_stopped ?? false,
  );
  const [inferVnetSubnets, setInferVnetSubnets] = useState(
    node?.infer_vnet_subnets ?? false,
  );
  const [syncInterval, setSyncInterval] = useState(
    String(node?.sync_interval_seconds ?? 120),
  );
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");

  const [testResult, setTestResult] = useState<ProxmoxTestResult | null>(null);

  const testMut = useMutation({
    mutationFn: () =>
      proxmoxApi.testConnection({
        node_id: node?.id,
        host: host || undefined,
        port,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundlePem || undefined,
        token_id: tokenId || undefined,
        token_secret: tokenSecret || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        pve_version: null,
        cluster_name: null,
        node_count: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: ProxmoxNodeUpdate = {
          name,
          description,
          enabled,
          host,
          port,
          verify_tls: verifyTls,
          token_id: tokenId,
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          mirror_vms: mirrorVms,
          mirror_lxc: mirrorLxc,
          include_stopped: includeStopped,
          infer_vnet_subnets: inferVnetSubnets,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (caBundlePem) update.ca_bundle_pem = caBundlePem;
        if (tokenSecret) update.token_secret = tokenSecret;
        return proxmoxApi.updateNode(node!.id, update);
      }
      const create: ProxmoxNodeCreate = {
        name,
        description,
        enabled,
        host,
        port,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundlePem,
        token_id: tokenId,
        token_secret: tokenSecret,
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        mirror_vms: mirrorVms,
        mirror_lxc: mirrorLxc,
        include_stopped: includeStopped,
        infer_vnet_subnets: inferVnetSubnets,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return proxmoxApi.createNode(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["proxmox-nodes"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save endpoint")),
  });

  return (
    <Modal
      title={editing ? "Edit Proxmox Endpoint" : "Add Proxmox Endpoint"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          // #2110 — "1h" and an empty field are refused, not read as 1 / the default.
          const intervalError = secondsFieldError(
            "Sync interval",
            syncInterval,
            SYNC_INTERVAL_BOUNDS,
          );
          if (intervalError) {
            setError(intervalError);
            return;
          }
          setError("");
          saveMut.mutate();
        }}
        className="space-y-3"
      >
        <div className="rounded-md border bg-muted/30 p-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">Setup guide</h3>
            <button
              type="button"
              onClick={() => setShowGuide((v) => !v)}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              {showGuide ? "Hide" : "Show"}
            </button>
          </div>
          {showGuide && (
            <div className="mt-2 space-y-2 text-xs">
              <p className="text-muted-foreground">
                Create a read-only API token on PVE using PVEAuditor (the
                built-in read-only role). SpatiumDDI authenticates with this
                token — no username/password exchange, no cookie.
              </p>
              <CopyablePre text={SETUP_TOKEN} label="PVE token setup" />
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </Field>
          <label className="flex cursor-pointer items-center gap-2 pt-6 text-sm">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>Enabled</span>
          </label>
        </div>

        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <Field
              label="Host"
              hint="Hostname or IP of any node in the cluster (e.g. pve01.example.com)."
            >
              <input
                className={`${inputCls} font-mono text-[11px]`}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="pve01.example.com"
                required
              />
            </Field>
          </div>
          <Field label="Port">
            <input
              type="number"
              className={inputCls}
              value={port}
              min={1}
              max={65535}
              onChange={(e) => setPort(parseInt(e.target.value) || 8006)}
            />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Token ID"
            hint="Format: user@realm!tokenid (e.g. spatiumddi@pve!spatiumddi)."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={tokenId}
              onChange={(e) => setTokenId(e.target.value)}
              placeholder="spatiumddi@pve!spatiumddi"
              required
            />
          </Field>
          <Field label="Token Secret">
            <input
              type="password"
              className={`${inputCls} font-mono text-[11px]`}
              value={tokenSecret}
              onChange={(e) => setTokenSecret(e.target.value)}
              placeholder={
                editing && node?.token_secret_present
                  ? "••• stored — enter to replace"
                  : "UUID printed by pveum"
              }
              required={!editing}
            />
          </Field>
        </div>

        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={verifyTls}
            onChange={(e) => setVerifyTls(e.target.checked)}
            className="mt-0.5"
          />
          <div>
            <span>Verify TLS certificate</span>
            <p className="text-[11px] text-muted-foreground/70">
              On by default. Uncheck for a self-signed lab host, or paste the
              PVE CA bundle below and leave this on.
            </p>
          </div>
        </label>

        <Field
          label="CA bundle (PEM, optional)"
          hint="Leave blank to trust the system CA store. Useful for internal CAs."
        >
          <textarea
            className={`${inputCls} font-mono text-[11px]`}
            rows={3}
            value={caBundlePem}
            onChange={(e) => setCaBundlePem(e.target.value)}
            placeholder={
              editing && node?.ca_bundle_present
                ? "••• stored — paste to replace"
                : "-----BEGIN CERTIFICATE-----\n..."
            }
          />
        </Field>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !host || !tokenId}
            className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            <TestTube2 className="h-3.5 w-3.5" />
            {testMut.isPending ? "Testing…" : "Test Connection"}
          </button>
          {testResult && (
            <span
              className={`text-xs ${
                testResult.ok
                  ? "text-emerald-600 dark:text-emerald-400"
                  : "text-destructive"
              }`}
              title={testResult.message}
            >
              {testResult.ok ? "✓" : "✗"} {testResult.message}
            </span>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3 border-t pt-3">
          <Field label="IPAM space">
            <IPSpacePicker value={spaceId} onChange={setSpaceId} required />
          </Field>
          {dnsOn && (
            <Field label="DNS server group (optional)">
              <select
                className={inputCls}
                value={dnsGroupId ?? ""}
                onChange={(e) => setDnsGroupId(e.target.value)}
              >
                <option value="">— none —</option>
                {dnsGroups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </Field>
          )}
        </div>

        <Field label="Sync interval (seconds)" hint="Minimum 30 s.">
          <input
            type="number"
            className={inputCls}
            value={syncInterval}
            min={30}
            onChange={(e) => setSyncInterval(e.target.value)}
          />
        </Field>

        <div className="space-y-2 border-t pt-2">
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorVms}
              onChange={(e) => setMirrorVms(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror VM IPs into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Runtime IPs come from the QEMU guest-agent when
                available; otherwise the <code>ipconfig0</code> static IP is
                used. Turn off to only mirror bridges.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorLxc}
              onChange={(e) => setMirrorLxc(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror LXC container IPs into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Runtime IPs come from the per-container{" "}
                <code>/interfaces</code> endpoint.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={includeStopped}
              onChange={(e) => setIncludeStopped(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Include stopped guests</span>
              <p className="text-[11px] text-muted-foreground/70">
                By default only running VMs / LXCs land in IPAM. Enable to
                capture capacity-planning views of stopped guests too.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={inferVnetSubnets}
              onChange={(e) => setInferVnetSubnets(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>
                Infer subnet CIDRs for SDN VNets without declared subnets
              </span>
              <p className="text-[11px] text-muted-foreground/70">
                Off by default. When on, the reconciler derives each empty
                VNet&apos;s CIDR from the guests attached to it — exact when a
                guest NIC carries a <code>static_cidr</code>, otherwise a /24
                guess from runtime IPs. The guess is wrong for /23 or /25
                deployments; declare SDN subnets in PVE (
                <code>
                  pvesh create /cluster/sdn/vnets/&lt;vnet&gt;/subnets
                </code>
                ) for exact behaviour.
              </p>
            </div>
          </label>
        </div>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saveMut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : editing ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DeleteNodeModal({
  node,
  onConfirm,
  onClose,
  isPending,
}: {
  node: ProxmoxNode;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete Proxmox Endpoint" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the Proxmox endpoint{" "}
          <span className="font-semibold">{node.name}</span>? This only affects
          SpatiumDDI — nothing on the Proxmox side changes. Only rows that were
          purely mirrored are removed. Anything you added yourself (addresses,
          DHCP scopes, reservations, edited rows, custom fields) is kept and
          detached from this integration.
        </p>
        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => setChecked(e.target.checked)}
            className="mt-0.5"
          />
          <span>I understand.</span>
        </label>
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            disabled={!checked || isPending}
            onClick={onConfirm}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {isPending ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Helpers (local to this page) ────────────────────────────────────

function CopyablePre({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function handle() {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }
  }
  return (
    <div className="relative">
      <pre className="overflow-auto rounded bg-background p-2 pr-20 font-mono text-[11px] leading-tight">
        {text}
      </pre>
      <button
        type="button"
        onClick={handle}
        className="absolute right-1.5 top-1.5 inline-flex items-center gap-1 rounded border bg-background px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground"
        aria-label={`Copy ${label}`}
        title={`Copy ${label}`}
      >
        {copied ? (
          <>
            <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
            Copied
          </>
        ) : (
          <>
            <Clipboard className="h-3 w-3" />
            Copy
          </>
        )}
      </button>
    </div>
  );
}

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground/70">{hint}</p>}
    </div>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ae = e as {
    response?: { data?: { detail?: unknown } };
    message?: string;
  };
  const d = ae?.response?.data?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    return (
      (d as Array<{ loc?: (string | number)[]; msg?: string }>)
        .map((err) => {
          const field = (err.loc ?? []).filter((p) => p !== "body").join(".");
          return field ? `${field}: ${err.msg}` : err.msg;
        })
        .filter(Boolean)
        .join("; ") || fallback
    );
  }
  return ae?.message || fallback;
}
