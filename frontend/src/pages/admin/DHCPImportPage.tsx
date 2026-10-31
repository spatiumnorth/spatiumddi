import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  FileUp,
  Info,
  Loader2,
  RotateCcw,
  Server as ServerIcon,
  Trash2,
  Upload,
} from "lucide-react";

import {
  dhcpApi,
  dhcpImportApi,
  ipamApi,
  type DHCPImportCommitResult,
  type DHCPImportConflictDecision,
  type DHCPImportPreview,
  type DHCPImportScopeConflict,
  type DHCPImportSource,
  type WindowsDHCPServerOption,
  formatApiError,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { HeaderButton } from "@/components/ui/header-button";
import { ListReadError } from "@/components/ui/list-read-error";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";

/** Every import route (preview, test and commit) takes a superadmin, so the
 *  controls that start one say so rather than letting a Viewer fill in the
 *  form and be refused (#1940's DNS importer, #2523). Commit is reachable
 *  only from a successful preview. */
function useImportGate(): { disabled?: boolean; title?: string } {
  return permissionGate(usePermissions().isSuperadmin, NEEDS_SUPERADMIN);
}

type TabId = DHCPImportSource;

interface TabDef {
  id: TabId;
  label: string;
  short: string;
  description: string;
}

// Tabs sorted alphabetically by label (ISC DHCP / Kea / Windows DHCP).
const TABS: TabDef[] = [
  {
    id: "isc_dhcp",
    label: "ISC DHCP",
    short: "dhcpd.conf",
    description:
      "Upload an ISC dhcpd.conf. The importer tokenises subnet / pool / range / host / class declarations and maps the modellable subset. ISC classifier expressions (class match rules) don't translate to SpatiumDDI's class model — they're surfaced for manual review, never auto-created. failover / key / zone / include declarations are listed in the 'didn't import' panel.",
  },
  {
    id: "kea",
    label: "Kea",
    short: "kea-dhcp4.conf / kea-dhcp6.conf",
    description:
      "Upload a Kea JSON config from a non-managed daemon. The importer strips Kea's comment extensions, walks every Dhcp4 subnet4 / Dhcp6 subnet6 and maps pools, reservations, option-data, and client-classes into the canonical shape. HA / host-cache / lease-cmds hook config is not carried across — set HA up at the SpatiumDDI server-group level post-import.",
  },
  {
    id: "windows_dhcp",
    label: "Windows DHCP",
    short: "WinRM live pull",
    description:
      "Live-pull every IPv4 scope from a Windows DHCP server using the same WinRM read driver the Logs surface uses. Pick a registered windows_dhcp server (with credentials configured) and the importer walks Get-DhcpServerv4Scope + option values + exclusions + reservations. IPv4 only.",
  },
];

type Phase = "select" | "previewing" | "ready" | "committing" | "result";

interface ImportState {
  file: File | null;
  serverId: string;
  groupId: string;
  spaceId: string;
  blockId: string;
  preview: DHCPImportPreview | null;
  decisions: Record<string, DHCPImportConflictDecision>;
  result: DHCPImportCommitResult | null;
  phase: Phase;
  error: string | null;
}

function emptyState(): ImportState {
  return {
    file: null,
    serverId: "",
    groupId: "",
    spaceId: "",
    blockId: "",
    preview: null,
    decisions: {},
    result: null,
    phase: "select",
    error: null,
  };
}

export function DHCPImportPage() {
  const [tab, setTab] = useState<TabId>("kea");
  const active = TABS.find((t) => t.id === tab) ?? TABS[0];

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b p-4">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Upload className="h-5 w-5 flex-shrink-0 text-primary" />
          <div className="min-w-0">
            <h1 className="text-lg font-semibold">DHCP configuration import</h1>
            <p className="text-xs text-muted-foreground">
              One-shot import of scopes + pools + reservations + classes from
              Kea / Windows DHCP / ISC dhcpd.conf into native SpatiumDDI rows.
              Once imported, SpatiumDDI is the source of truth — there is no
              continuous two-way mirror.
            </p>
          </div>
        </div>
      </div>

      <div className="border-b">
        <div className="flex flex-wrap gap-1 px-4">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={cn(
                "-mb-px flex items-center gap-2 border-b-2 px-3 py-2 text-sm transition-colors",
                tab === t.id
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-4">
        <div className="mb-4 rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
          <div className="mb-1 font-medium text-foreground">
            {active.label} — {active.short}
          </div>
          {active.description}
        </div>

        {tab === "kea" && <ImportTab key="kea" source="kea" />}
        {tab === "windows_dhcp" && (
          <ImportTab key="windows_dhcp" source="windows_dhcp" />
        )}
        {tab === "isc_dhcp" && <ImportTab key="isc_dhcp" source="isc_dhcp" />}
      </div>
    </div>
  );
}

// ── one source's flow ────────────────────────────────────────────────

function ImportTab({ source }: { source: DHCPImportSource }) {
  const [state, setState] = useState<ImportState>(emptyState());
  const isFileSource = source === "kea" || source === "isc_dhcp";

  const groupsQ = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: () => dhcpApi.listGroups(),
  });
  const spacesQ = useQuery({
    queryKey: ["ipam-spaces"],
    queryFn: () => ipamApi.listSpaces(),
  });
  const blocksQ = useQuery({
    queryKey: ["ipam-blocks", state.spaceId],
    queryFn: () =>
      state.spaceId ? ipamApi.listBlocks(state.spaceId) : Promise.resolve([]),
    enabled: Boolean(state.spaceId),
  });
  const serversQ = useQuery({
    queryKey: ["dhcp-import-windows-servers"],
    queryFn: () => dhcpImportApi.windowsServers(),
    enabled: source === "windows_dhcp",
  });

  const previewMut = useMutation({
    mutationFn: () => {
      if (!state.groupId)
        throw new Error("Pick a target DHCP server group first");
      if (isFileSource) {
        if (!state.file) throw new Error("Choose a config file first");
        const fn =
          source === "kea"
            ? dhcpImportApi.keaPreview
            : dhcpImportApi.iscPreview;
        return fn(state.file, state.groupId, state.spaceId || undefined);
      }
      if (!state.serverId) throw new Error("Pick a Windows DHCP server first");
      return dhcpImportApi.windowsPreview({
        server_id: state.serverId,
        target_group_id: state.groupId,
        ipam_space_id: state.spaceId || null,
      });
    },
    onSuccess: (preview) => {
      const decisions: Record<string, DHCPImportConflictDecision> = {};
      for (const c of preview.conflicts) {
        if (c.existing_scope_id)
          decisions[c.subnet_cidr] = { action: c.action };
      }
      setState((s) => ({
        ...s,
        preview,
        decisions,
        phase: "ready",
        error: null,
      }));
    },
    onError: (err: unknown) =>
      setState((s) => ({ ...s, phase: "select", error: extractError(err) })),
  });

  const commitMut = useMutation({
    mutationFn: () => {
      if (!state.preview) throw new Error("Preview first");
      const body = {
        target_group_id: state.groupId,
        ipam_space_id: state.spaceId || null,
        ipam_block_id: state.blockId || null,
        plan: state.preview,
        conflict_actions: state.decisions,
      };
      const fn =
        source === "kea"
          ? dhcpImportApi.keaCommit
          : source === "isc_dhcp"
            ? dhcpImportApi.iscCommit
            : dhcpImportApi.windowsCommit;
      return fn(body);
    },
    onSuccess: (result) =>
      setState((s) => ({ ...s, result, phase: "result", error: null })),
    onError: (err: unknown) =>
      setState((s) => ({ ...s, phase: "ready", error: extractError(err) })),
  });

  const conflictByCidr = useMemo(() => {
    const m = new Map<string, DHCPImportScopeConflict>();
    for (const c of state.preview?.conflicts ?? []) m.set(c.subnet_cidr, c);
    return m;
  }, [state.preview]);

  const reset = () => setState(emptyState());

  return (
    <div className="space-y-4">
      {state.error && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <div>{state.error}</div>
        </div>
      )}

      {state.phase === "result" && state.result ? (
        <CommitResultPanel result={state.result} onReset={reset} />
      ) : (
        <>
          <ConfigureForm
            source={source}
            state={state}
            setState={setState}
            groups={groupsQ.data ?? []}
            spaces={spacesQ.data ?? []}
            blocks={blocksQ.data ?? []}
            servers={serversQ.data ?? []}
            serversLoading={serversQ.isLoading}
            serversError={serversQ.error}
            onPreview={() => {
              setState((s) => ({ ...s, phase: "previewing", error: null }));
              previewMut.mutate();
            }}
            previewing={previewMut.isPending}
          />

          {state.preview && state.phase !== "previewing" && (
            <PreviewPanel
              preview={state.preview}
              decisions={state.decisions}
              setDecisions={(updater) =>
                setState((s) => ({ ...s, decisions: updater(s.decisions) }))
              }
              conflictByCidr={conflictByCidr}
              canCreateSubnets={Boolean(state.spaceId && state.blockId)}
              onCommit={() => {
                setState((s) => ({ ...s, phase: "committing", error: null }));
                commitMut.mutate();
              }}
              committing={commitMut.isPending}
              onReset={reset}
            />
          )}
        </>
      )}
    </div>
  );
}

function extractError(err: unknown): string {
  return formatApiError(err);
}

// ── configure source + target ────────────────────────────────────────

function ConfigureForm({
  source,
  state,
  setState,
  groups,
  spaces,
  blocks,
  servers,
  serversLoading,
  serversError,
  onPreview,
  previewing,
}: {
  source: DHCPImportSource;
  state: ImportState;
  setState: React.Dispatch<React.SetStateAction<ImportState>>;
  groups: { id: string; name: string }[];
  spaces: { id: string; name: string }[];
  blocks: { id: string; name: string; network: string }[];
  servers: WindowsDHCPServerOption[];
  serversLoading: boolean;
  serversError: unknown;
  onPreview: () => void;
  previewing: boolean;
}) {
  const isFileSource = source === "kea" || source === "isc_dhcp";
  const accept =
    source === "kea" ? ".conf,.json,application/json" : ".conf,.txt,text/plain";
  const sourceReady = isFileSource
    ? Boolean(state.file)
    : Boolean(state.serverId);
  const canPreview = sourceReady && Boolean(state.groupId) && !previewing;
  const gate = useImportGate();
  const eligibleServers = servers.filter((s) => s.has_credentials);

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        1. Configure source + target
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* Source */}
        <div className="space-y-3">
          {isFileSource ? (
            <div>
              <label className="block text-sm font-medium">Config file</label>
              <p className="mb-2 text-[11px] text-muted-foreground">
                {source === "kea"
                  ? "Kea kea-dhcp4.conf / kea-dhcp6.conf (JSON, comments OK). Max 25 MB."
                  : "ISC dhcpd.conf. Inline any include files first. Max 25 MB."}
              </p>
              <label
                className={cn(
                  "flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed px-4 py-6 text-sm hover:bg-muted",
                  state.file && "bg-muted/40 text-foreground",
                )}
              >
                <FileUp className="h-4 w-4 text-muted-foreground" />
                <span>
                  {state.file
                    ? `${state.file.name} (${(state.file.size / 1024).toFixed(1)} KB)`
                    : "Choose file…"}
                </span>
                <input
                  type="file"
                  accept={accept}
                  className="sr-only"
                  onChange={(e) =>
                    setState((s) => ({
                      ...s,
                      file: e.target.files?.[0] ?? null,
                      preview: null,
                      phase: "select",
                      error: null,
                    }))
                  }
                />
              </label>
            </div>
          ) : (
            <div>
              <label className="block text-sm font-medium">
                Windows DHCP server
              </label>
              <p className="mb-2 text-[11px] text-muted-foreground">
                Registered windows_dhcp server with WinRM credentials. Servers
                without credentials are greyed out.
              </p>
              <select
                value={state.serverId}
                onChange={(e) =>
                  setState((s) => ({
                    ...s,
                    serverId: e.target.value,
                    preview: null,
                    error: null,
                  }))
                }
                disabled={serversLoading}
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">
                  {serversLoading
                    ? "Loading…"
                    : serversError
                      ? "— servers unavailable —"
                      : eligibleServers.length === 0
                        ? "— no eligible servers —"
                        : "— select —"}
                </option>
                {servers.map((srv) => (
                  <option
                    key={srv.id}
                    value={srv.id}
                    disabled={!srv.has_credentials}
                  >
                    {srv.name} ({srv.host})
                    {!srv.has_credentials ? " — no creds" : ""}
                  </option>
                ))}
              </select>
              {serversError ? (
                <p className="mt-1 text-xs">
                  <ListReadError
                    error={serversError}
                    what="the servers to import from"
                  />
                </p>
              ) : null}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium">
              Target DHCP server group
            </label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Imported scopes land in this group. Pick one with at least one Kea
              server so the agent renders them on its next sync.
            </p>
            <select
              value={state.groupId}
              onChange={(e) =>
                setState((s) => ({ ...s, groupId: e.target.value }))
              }
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="">— select —</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* IPAM linkage */}
        <div className="space-y-3">
          <div className="rounded-md border border-dashed bg-background/40 p-3">
            <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              <Info className="h-3 w-3" /> IPAM linkage
            </div>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Every DHCP scope binds to an IPAM subnet. The importer links to an
              existing subnet whose CIDR matches; to auto-create the ones that
              don't exist yet, pick an IP space + block below. Leave them blank
              to link-only (unmatched scopes will report an error you can fix
              and re-run).
            </p>
            <label className="block text-sm font-medium">IP space</label>
            <select
              value={state.spaceId}
              onChange={(e) =>
                setState((s) => ({
                  ...s,
                  spaceId: e.target.value,
                  blockId: "",
                }))
              }
              className="mb-2 w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="">— link-only (no auto-create) —</option>
              {spaces.map((sp) => (
                <option key={sp.id} value={sp.id}>
                  {sp.name}
                </option>
              ))}
            </select>
            {state.spaceId && (
              <>
                <label className="block text-sm font-medium">
                  Parent block (for new subnets)
                </label>
                <select
                  value={state.blockId}
                  onChange={(e) =>
                    setState((s) => ({ ...s, blockId: e.target.value }))
                  }
                  className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="">— select a block —</option>
                  {blocks.map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.name || b.network} ({b.network})
                    </option>
                  ))}
                </select>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="mt-4 flex justify-end gap-2">
        <HeaderButton
          variant="primary"
          icon={previewing ? Loader2 : isFileSource ? Upload : ServerIcon}
          iconClassName={previewing ? "animate-spin" : undefined}
          onClick={onPreview}
          disabled={!canPreview || !!gate.disabled}
          title={gate.title}
        >
          {previewing
            ? isFileSource
              ? "Parsing…"
              : "Pulling scopes…"
            : "Preview import"}
        </HeaderButton>
      </div>
    </div>
  );
}

// ── preview + commit ──────────────────────────────────────────────────

export function PreviewPanel({
  preview,
  decisions,
  setDecisions,
  conflictByCidr,
  canCreateSubnets,
  onCommit,
  committing,
  onReset,
}: {
  preview: DHCPImportPreview;
  decisions: Record<string, DHCPImportConflictDecision>;
  setDecisions: (
    updater: (
      prev: Record<string, DHCPImportConflictDecision>,
    ) => Record<string, DHCPImportConflictDecision>,
  ) => void;
  conflictByCidr: Map<string, DHCPImportScopeConflict>;
  canCreateSubnets: boolean;
  onCommit: () => void;
  committing: boolean;
  onReset: () => void;
}) {
  const supportedClasses = preview.client_classes.filter((c) => c.supported);
  const unsupportedClasses = preview.client_classes.filter((c) => !c.supported);

  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            2. Review &amp; commit
          </div>
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <span>
              <strong>{preview.scopes.length}</strong> scope
              {preview.scopes.length === 1 ? "" : "s"}
            </span>
            <span>·</span>
            <span>
              <strong>{preview.total_pools}</strong> pools
            </span>
            <span>·</span>
            <span>
              <strong>{preview.total_reservations}</strong> reservations
            </span>
            <span>·</span>
            <span>
              <strong>{supportedClasses.length}</strong> classes
            </span>
          </div>
        </div>

        {preview.warnings.length > 0 && (
          <WarnBlock title="Warnings" items={preview.warnings} />
        )}
        {preview.unsupported.length > 0 && (
          <WarnBlock title="Didn't import" items={preview.unsupported} />
        )}

        <div className="overflow-x-auto rounded-md border bg-background">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Subnet</th>
                <th className="px-3 py-2 text-left">Family</th>
                <th className="px-3 py-2 text-right">Pools</th>
                <th className="px-3 py-2 text-right">Reservations</th>
                <th className="px-3 py-2 text-left">IPAM</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">On conflict</th>
              </tr>
            </thead>
            <tbody>
              {preview.scopes.map((sc) => {
                const conflict = conflictByCidr.get(sc.subnet_cidr);
                const hasScopeConflict = Boolean(conflict?.existing_scope_id);
                const linksToSubnet = Boolean(conflict?.existing_subnet_id);
                const decision = decisions[sc.subnet_cidr] ?? {
                  action: "skip",
                };
                return (
                  <tr key={sc.subnet_cidr} className="border-t align-top">
                    <td className="px-3 py-2 font-mono text-xs">
                      {sc.subnet_cidr}
                      {sc.parse_warnings.length > 0 && (
                        <ul
                          aria-label={`Notes for ${sc.subnet_cidr}`}
                          className="mt-1 max-w-md list-disc space-y-0.5 pl-4 font-sans text-[11px] text-amber-700 [overflow-wrap:anywhere] dark:text-amber-400"
                        >
                          {sc.parse_warnings.map((w, i) => (
                            <li key={i}>{w}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs">{sc.address_family}</td>
                    <td className="px-3 py-2 text-right text-xs tabular-nums">
                      {sc.pools.length}
                    </td>
                    <td className="px-3 py-2 text-right text-xs tabular-nums">
                      {sc.reservations.length}
                    </td>
                    <td className="px-3 py-2 text-xs">
                      {linksToSubnet ? (
                        <span className="text-muted-foreground">
                          link → {conflict?.existing_subnet_name}
                        </span>
                      ) : canCreateSubnets ? (
                        <span className="text-emerald-700 dark:text-emerald-400">
                          create subnet
                        </span>
                      ) : (
                        <span className="text-destructive">
                          no match — pick space+block
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {hasScopeConflict ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400">
                          <AlertTriangle className="h-3 w-3" />
                          {conflict?.soft_deleted
                            ? "scope in Trash"
                            : "scope exists"}{" "}
                          ({conflict?.existing_pool_count}p/
                          {conflict?.existing_reservation_count}r)
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" />
                          new
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {hasScopeConflict ? (
                        <select
                          value={decision.action}
                          onChange={(e) =>
                            setDecisions((prev) => ({
                              ...prev,
                              [sc.subnet_cidr]: {
                                action: e.target
                                  .value as DHCPImportConflictDecision["action"],
                              },
                            }))
                          }
                          className="rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                        >
                          <option value="skip">Skip</option>
                          <option value="overwrite">Overwrite</option>
                        </select>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {(supportedClasses.length > 0 || unsupportedClasses.length > 0) && (
          <div className="mt-3 space-y-2 rounded-md border bg-background p-3 text-xs">
            <div className="font-medium">Client classes</div>
            {supportedClasses.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {supportedClasses.map((c) => (
                  <span
                    key={c.name}
                    className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400"
                  >
                    <CheckCircle2 className="h-3 w-3" />
                    {c.name}
                  </span>
                ))}
              </div>
            )}
            {unsupportedClasses.length > 0 && (
              <div className="text-amber-700 dark:text-amber-400">
                {unsupportedClasses.length} class
                {unsupportedClasses.length === 1 ? "" : "es"} left for manual
                review (classifier expression not auto-translated):{" "}
                <span className="font-mono">
                  {unsupportedClasses.map((c) => c.name).join(", ")}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-end gap-2">
        <HeaderButton icon={RotateCcw} onClick={onReset} disabled={committing}>
          Start over
        </HeaderButton>
        <HeaderButton
          variant="primary"
          icon={committing ? Loader2 : Database}
          iconClassName={committing ? "animate-spin" : undefined}
          onClick={onCommit}
          disabled={committing}
        >
          {committing ? "Committing…" : "Commit import"}
        </HeaderButton>
      </div>
    </div>
  );
}

function WarnBlock({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="mb-3 space-y-1 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
      <div className="font-medium text-amber-700 dark:text-amber-400">
        {title}
      </div>
      {items.map((w, i) => (
        <div key={i} className="text-amber-700/90 dark:text-amber-300/90">
          {w}
        </div>
      ))}
    </div>
  );
}

function CommitResultPanel({
  result,
  onReset,
}: {
  result: DHCPImportCommitResult;
  onReset: () => void;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Import complete
          </div>
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <Stat
              label="Created"
              value={result.total_scopes_created}
              tone="success"
            />
            <Stat
              label="Overwrote"
              value={result.total_scopes_overwrote}
              tone="amber"
            />
            <Stat
              label="Skipped"
              value={result.total_scopes_skipped}
              tone="muted"
            />
            <Stat
              label="Failed"
              value={result.total_scopes_failed}
              tone="destructive"
            />
            <span className="text-muted-foreground">·</span>
            <Stat
              label="Subnets"
              value={result.total_subnets_created}
              tone="success"
            />
            <Stat
              label="Pools"
              value={result.total_pools_created}
              tone="success"
            />
            <Stat
              label="Reservations"
              value={result.total_reservations_created}
              tone="success"
            />
            <Stat
              label="Classes"
              value={result.client_classes_created}
              tone="success"
            />
          </div>
        </div>

        <div className="overflow-x-auto rounded-md border bg-background">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Subnet</th>
                <th className="px-3 py-2 text-left">Action</th>
                <th className="px-3 py-2 text-right">Pools</th>
                <th className="px-3 py-2 text-right">Reservations</th>
                <th className="px-3 py-2 text-left">Error</th>
              </tr>
            </thead>
            <tbody>
              {result.scopes.map((s) => (
                <tr key={s.subnet_cidr} className="border-t align-top">
                  <td className="px-3 py-2 font-mono text-xs">
                    {s.subnet_cidr}
                    {s.subnet_created && (
                      <span className="ml-1 rounded bg-emerald-500/15 px-1 text-[9px] text-emerald-700 dark:text-emerald-400">
                        +subnet
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <ActionPill action={s.action_taken} />
                  </td>
                  <td className="px-3 py-2 text-right text-xs tabular-nums">
                    {s.pools_created}
                  </td>
                  <td className="px-3 py-2 text-right text-xs tabular-nums">
                    {s.reservations_created}
                  </td>
                  <td className="px-3 py-2 text-xs text-destructive">
                    {s.error ?? ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {result.warnings.length > 0 && (
          <WarnBlock title="Warnings" items={result.warnings} />
        )}
      </div>

      <div className="flex justify-end">
        <HeaderButton icon={Trash2} onClick={onReset}>
          Import another
        </HeaderButton>
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "success" | "amber" | "muted" | "destructive";
}) {
  const tones: Record<string, string> = {
    success: "text-emerald-700 dark:text-emerald-400",
    amber: "text-amber-700 dark:text-amber-400",
    muted: "text-muted-foreground",
    destructive: "text-destructive",
  };
  return (
    <span className="inline-flex items-baseline gap-1">
      <span className={cn("font-semibold tabular-nums", tones[tone])}>
        {value}
      </span>
      <span className="text-muted-foreground">{label}</span>
    </span>
  );
}

function ActionPill({ action }: { action: string }) {
  const map: Record<string, { tone: string; label: string }> = {
    created: {
      tone: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
      label: "created",
    },
    overwrote: {
      tone: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
      label: "overwrote",
    },
    skipped: {
      tone: "bg-zinc-500/15 text-zinc-700 dark:text-zinc-400",
      label: "skipped",
    },
    failed: { tone: "bg-destructive/15 text-destructive", label: "failed" },
  };
  const m = map[action] ?? map["skipped"];
  return (
    <span
      className={cn(
        "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium",
        m.tone,
      )}
    >
      {m.label}
    </span>
  );
}
