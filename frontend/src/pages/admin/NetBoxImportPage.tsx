import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Database,
  Loader2,
  Plug,
  RotateCcw,
  Server as ServerIcon,
  Trash2,
  Upload,
} from "lucide-react";

import {
  ipamApi,
  netboxImportApi,
  type IPSpace,
  type NetBoxEntityConflict,
  type NetBoxImportCommitResult,
  type NetBoxImportConflictDecision,
  type NetBoxImportPreview,
  type NetBoxPreviewFilters,
  type NetBoxSpaceStrategy,
  type NetBoxTestOut,
  formatApiError,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { HeaderButton } from "@/components/ui/header-button";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";

// NetBox is a single live-API source (test-connection → preview → commit),
// so there's no tab bar — just a full-page three-phase flow. Clones the
// DNSImportPage idiom (PowerDNS connect form + PreviewPanel +
// CommitResultPanel) and grafts NetBox's IPAM-wide canonical IR across the
// eight entity types (Customers / Sites / VRFs / Spaces / VLANs / Blocks /
// Subnets / Addresses). Wire shapes follow netboxImportApi in lib/api.ts.

/** Every import route (preview, test and commit) takes a superadmin, so the
 *  controls that start one say so rather than letting a Viewer fill in the
 *  form and be refused (#1940's DNS importer, #2523). Commit is reachable
 *  only from a successful preview. */
function useImportGate(): { disabled?: boolean; title?: string } {
  return permissionGate(usePermissions().isSuperadmin, NEEDS_SUPERADMIN);
}

type Phase = "select" | "previewing" | "ready" | "committing" | "result";

// Entities, in dependency order — the same order the preview accordion +
// commit ledger render. ``key`` is the field on the preview / counts map.
const ENTITY_DEFS: {
  key:
    | "customers"
    | "sites"
    | "vrfs"
    | "spaces"
    | "vlans"
    | "blocks"
    | "subnets"
    | "addresses";
  label: string;
  // The singular EntityConflict.kind the backend stamps for this entity
  // (preview[def.key] is plural; preview.conflicts[].kind is singular).
  conflictKind: string;
  // How to render one row's identity in the per-entity table.
  identity: (row: Record<string, unknown>) => string;
  // Rebuild the backend's stable conflict key for a row — mirrors the
  // ``_*_key`` helpers in services/netbox_import/commit.py so a row can be
  // matched against preview.conflicts[].key (and decisions[key]).
  keyOf: (row: Record<string, unknown>) => string;
}[] = [
  {
    key: "customers",
    label: "Customers",
    conflictKind: "customer",
    identity: (r) => String(r.name),
    keyOf: (r) => `customer:${r.name}`,
  },
  {
    key: "sites",
    label: "Sites",
    conflictKind: "site",
    identity: (r) => String(r.code ?? r.name),
    keyOf: (r) => `site:${r.code ?? r.name}`,
  },
  {
    key: "vrfs",
    label: "VRFs",
    conflictKind: "vrf",
    identity: (r) => String(r.rd ?? r.name),
    keyOf: (r) => `vrf:${r.rd ?? r.name}`,
  },
  {
    key: "spaces",
    label: "Spaces",
    conflictKind: "ip_space",
    identity: (r) => String(r.name),
    keyOf: (r) => `ip_space:${r.name}`,
  },
  {
    key: "vlans",
    label: "VLANs",
    conflictKind: "vlan",
    identity: (r) => `${r.vid} · ${r.name}`,
    keyOf: (r) => `vlan:${r.vid}`,
  },
  {
    key: "blocks",
    label: "Blocks",
    conflictKind: "ip_block",
    identity: (r) => String(r.network),
    keyOf: (r) => `ip_block:${r.space_name ?? ""}:${r.network}`,
  },
  {
    key: "subnets",
    label: "Subnets",
    conflictKind: "subnet",
    identity: (r) => String(r.network),
    keyOf: (r) => `subnet:${r.space_name ?? ""}:${r.network}`,
  },
  {
    key: "addresses",
    label: "Addresses",
    conflictKind: "ip_address",
    identity: (r) => String(r.address),
    keyOf: (r) => `ip_address:${r.subnet_cidr ?? ""}:${r.address}`,
  },
];

interface NetBoxState {
  baseUrl: string;
  token: string;
  verifyTls: boolean;
  spaceStrategy: NetBoxSpaceStrategy;
  targetSpaceId: string;
  filters: NetBoxPreviewFilters;
  testInfo: NetBoxTestOut | null;
  preview: NetBoxImportPreview | null;
  decisions: Record<string, NetBoxImportConflictDecision>;
  result: NetBoxImportCommitResult | null;
  phase: Phase;
  error: string | null;
}

function emptyState(): NetBoxState {
  return {
    baseUrl: "",
    token: "",
    verifyTls: true,
    spaceStrategy: "per_vrf",
    targetSpaceId: "",
    filters: {},
    testInfo: null,
    preview: null,
    decisions: {},
    result: null,
    phase: "select",
    error: null,
  };
}

function extractError(err: unknown): string {
  return (
    (err as { response?: { data?: { detail?: string } } })?.response?.data
      ?.detail ?? formatApiError(err)
  );
}

export function NetBoxImportPage() {
  const [state, setState] = useState<NetBoxState>(emptyState());
  const [confirmOpen, setConfirmOpen] = useState(false);

  const spacesQ = useQuery({
    queryKey: ["ipam-spaces"],
    queryFn: () => ipamApi.listSpaces(),
  });

  const testMut = useMutation({
    mutationFn: () => {
      if (!state.baseUrl || !state.token) {
        throw new Error("Provide a NetBox base URL and API token first");
      }
      return netboxImportApi.testConnection({
        base_url: state.baseUrl,
        token: state.token,
        verify_tls: state.verifyTls,
      });
    },
    onSuccess: (info) => {
      setState((s) => ({ ...s, testInfo: info, error: null }));
    },
    onError: (err: unknown) => {
      setState((s) => ({ ...s, testInfo: null, error: extractError(err) }));
    },
  });

  const previewMut = useMutation({
    mutationFn: () => {
      if (!state.baseUrl || !state.token) {
        throw new Error("Provide a NetBox base URL and API token first");
      }
      if (state.spaceStrategy === "single" && !state.targetSpaceId) {
        throw new Error(
          "Pick a target IP space when collapsing into a single space",
        );
      }
      const filters = cleanFilters(state.filters);
      return netboxImportApi.preview({
        base_url: state.baseUrl,
        token: state.token,
        verify_tls: state.verifyTls,
        space_strategy: state.spaceStrategy,
        target_space_id:
          state.spaceStrategy === "single" ? state.targetSpaceId : null,
        filters,
      });
    },
    onSuccess: (preview) => {
      // Seed conflict decisions from whatever the server suggested
      // (defaults to "skip"). Operator edits per-row before commit.
      const decisions: Record<string, NetBoxImportConflictDecision> = {};
      for (const c of preview.conflicts) {
        decisions[c.key] = { action: c.action };
      }
      setState((s) => ({
        ...s,
        preview,
        decisions,
        phase: "ready",
        error: null,
      }));
    },
    onError: (err: unknown) => {
      setState((s) => ({ ...s, phase: "select", error: extractError(err) }));
    },
  });

  const commitMut = useMutation({
    mutationFn: () => {
      if (!state.preview) throw new Error("Preview the NetBox install first");
      return netboxImportApi.commit({
        plan: state.preview,
        conflict_actions: state.decisions,
        space_strategy: state.spaceStrategy,
        target_space_id:
          state.spaceStrategy === "single" ? state.targetSpaceId : null,
      });
    },
    onSuccess: (result) => {
      setState((s) => ({ ...s, result, phase: "result", error: null }));
    },
    onError: (err: unknown) => {
      setState((s) => ({ ...s, phase: "ready", error: extractError(err) }));
    },
  });

  const reset = () => {
    setState(emptyState());
    setConfirmOpen(false);
  };

  const runCommit = () => {
    setConfirmOpen(false);
    setState((s) => ({ ...s, phase: "committing", error: null }));
    commitMut.mutate();
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b p-4">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Upload className="h-5 w-5 flex-shrink-0 text-primary" />
          <div className="min-w-0">
            <h1 className="text-lg font-semibold">NetBox IPAM import</h1>
            <p className="text-xs text-muted-foreground">
              One-shot read-only import of customers, sites, VRFs, spaces,
              VLANs, blocks, subnets, and addresses from a live NetBox install
              into native SpatiumDDI rows. Once imported, SpatiumDDI is the
              source of truth — there is no continuous two-way mirror.
            </p>
          </div>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-4">
        <div className="mb-4 rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
          <div className="mb-1 font-medium text-foreground">
            NetBox — live API pull
          </div>
          Provide the NetBox base URL + an API token. The importer walks
          NetBox's prefixes / IP-addresses / VRFs / VLANs / tenants / sites REST
          APIs and stages a canonical plan for review. Credentials are read-once
          and never persisted — re-importing means re-pasting the token.
        </div>

        <div className="space-y-4">
          {state.error && (
            <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">
              <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
              <div className="break-all">{state.error}</div>
            </div>
          )}

          {state.phase === "result" && state.result ? (
            <CommitResultPanel result={state.result} onReset={reset} />
          ) : (
            <>
              <ConnectForm
                state={state}
                setState={setState}
                spaces={spacesQ.data ?? []}
                spacesLoading={spacesQ.isLoading}
                onTest={() => testMut.mutate()}
                testing={testMut.isPending}
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
                  onCommit={() => setConfirmOpen(true)}
                  committing={commitMut.isPending}
                  onReset={reset}
                />
              )}
            </>
          )}
        </div>
      </div>

      <ConfirmModal
        open={confirmOpen}
        title="Commit NetBox import?"
        message={
          <span>
            This writes <strong>{totalCreatable(state.preview)}</strong> new
            entities into native IPAM rows. Conflicting rows follow your per-row
            skip / overwrite decisions. This cannot be undone in one click.
          </span>
        }
        confirmLabel="Commit import"
        loading={commitMut.isPending}
        onConfirm={runCommit}
        onClose={() => setConfirmOpen(false)}
      />
    </div>
  );
}

// Drop empty filter fields so the body only carries the slice the operator
// actually set (NetBox treats absent == no filter).
function cleanFilters(f: NetBoxPreviewFilters): NetBoxPreviewFilters | null {
  const out: NetBoxPreviewFilters = {};
  if (f.vrf_id != null && !Number.isNaN(f.vrf_id)) out.vrf_id = f.vrf_id;
  if (f.tenant_id != null && !Number.isNaN(f.tenant_id))
    out.tenant_id = f.tenant_id;
  if (f.status) out.status = f.status;
  if (f.family) out.family = f.family;
  if (f.within_include) out.within_include = f.within_include;
  return Object.keys(out).length > 0 ? out : null;
}

function totalCreatable(preview: NetBoxImportPreview | null): number {
  if (!preview) return 0;
  return (
    preview.customers.length +
    preview.sites.length +
    preview.vrfs.length +
    preview.spaces.length +
    preview.vlans.length +
    preview.blocks.length +
    preview.subnets.length +
    preview.addresses.length
  );
}

// ── Connect form ─────────────────────────────────────────────────────

function ConnectForm({
  state,
  setState,
  spaces,
  spacesLoading,
  onTest,
  testing,
  onPreview,
  previewing,
}: {
  state: NetBoxState;
  setState: React.Dispatch<React.SetStateAction<NetBoxState>>;
  spaces: IPSpace[];
  spacesLoading: boolean;
  onTest: () => void;
  testing: boolean;
  onPreview: () => void;
  previewing: boolean;
}) {
  const gate = useImportGate();
  const canTest =
    Boolean(state.baseUrl && state.token) && !testing && !previewing;
  const needSpace =
    state.spaceStrategy === "single" && !state.targetSpaceId ? true : false;
  const canPreview =
    Boolean(state.baseUrl && state.token) &&
    !needSpace &&
    !previewing &&
    !testing;

  const setFilter = (patch: Partial<NetBoxPreviewFilters>) =>
    setState((s) => ({
      ...s,
      filters: { ...s.filters, ...patch },
      error: null,
    }));

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        1. NetBox source + target
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* ── Connection ── */}
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">Base URL</label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              NetBox base URL — no <code>/api</code> suffix. Example:{" "}
              <code>https://netbox.internal:8080</code>.
            </p>
            <input
              value={state.baseUrl}
              onChange={(e) =>
                setState((s) => ({
                  ...s,
                  baseUrl: e.target.value,
                  testInfo: null,
                }))
              }
              placeholder="https://netbox.internal:8080"
              className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <div>
            <label className="block text-sm font-medium">API token</label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              NetBox API token (read-once; never persisted). Accepts the v1{" "}
              <code className="text-[10px]">Token</code> or v2{" "}
              <code className="text-[10px]">nbt_…</code> scheme.
            </p>
            <input
              type="password"
              value={state.token}
              onChange={(e) =>
                setState((s) => ({
                  ...s,
                  token: e.target.value,
                  testInfo: null,
                }))
              }
              placeholder="netbox api token"
              className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={state.verifyTls}
              onChange={(e) =>
                setState((s) => ({
                  ...s,
                  verifyTls: e.target.checked,
                  testInfo: null,
                }))
              }
              className="h-4 w-4 rounded border focus:ring-2 focus:ring-ring"
            />
            Verify TLS certificate
          </label>
          <div className="flex items-center gap-2">
            <HeaderButton
              icon={testing ? Loader2 : Plug}
              iconClassName={testing ? "animate-spin" : undefined}
              onClick={onTest}
              disabled={!canTest || !!gate.disabled}
              title={gate.title}
            >
              {testing ? "Testing…" : "Test connection"}
            </HeaderButton>
            {state.testInfo?.ok && (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
                <CheckCircle2 className="h-3 w-3" />
                NetBox {state.testInfo.netbox_version || ""}
                {state.testInfo.api_version
                  ? ` · API ${state.testInfo.api_version}`
                  : ""}
              </span>
            )}
          </div>
        </div>

        {/* ── Target + strategy ── */}
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">Space strategy</label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              How NetBox prefixes map onto SpatiumDDI IP spaces.
            </p>
            <div className="space-y-2">
              <label className="flex items-start gap-2 text-xs">
                <input
                  type="radio"
                  name="space-strategy"
                  checked={state.spaceStrategy === "per_vrf"}
                  onChange={() =>
                    setState((s) => ({
                      ...s,
                      spaceStrategy: "per_vrf",
                      preview: null,
                    }))
                  }
                  className="mt-0.5 h-4 w-4"
                />
                <span>
                  <span className="font-medium text-foreground">
                    One space per VRF
                  </span>
                  <span className="block text-[11px] text-muted-foreground">
                    Each NetBox VRF (plus a default for the global table)
                    becomes its own IP space.
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2 text-xs">
                <input
                  type="radio"
                  name="space-strategy"
                  checked={state.spaceStrategy === "single"}
                  onChange={() =>
                    setState((s) => ({
                      ...s,
                      spaceStrategy: "single",
                      preview: null,
                    }))
                  }
                  className="mt-0.5 h-4 w-4"
                />
                <span>
                  <span className="font-medium text-foreground">
                    Single target space
                  </span>
                  <span className="block text-[11px] text-muted-foreground">
                    Collapse everything into one existing IP space.
                  </span>
                </span>
              </label>
            </div>
          </div>

          {state.spaceStrategy === "single" && (
            <div>
              <label className="block text-sm font-medium">
                Target IP space
              </label>
              <select
                value={state.targetSpaceId}
                onChange={(e) =>
                  setState((s) => ({
                    ...s,
                    targetSpaceId: e.target.value,
                    preview: null,
                  }))
                }
                disabled={spacesLoading}
                className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">
                  {spacesLoading ? "Loading…" : "— select —"}
                </option>
                {spaces.map((sp) => (
                  <option key={sp.id} value={sp.id}>
                    {sp.name}
                    {sp.is_default ? " (default)" : ""}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* ── Optional scope filters ── */}
          <details className="rounded-md border bg-background/40 p-3">
            <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
              Optional scope filters
            </summary>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[11px] font-medium">VRF id</label>
                <input
                  type="number"
                  value={state.filters.vrf_id ?? ""}
                  onChange={(e) =>
                    setFilter({
                      vrf_id:
                        e.target.value === "" ? null : Number(e.target.value),
                    })
                  }
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium">
                  Tenant id
                </label>
                <input
                  type="number"
                  value={state.filters.tenant_id ?? ""}
                  onChange={(e) =>
                    setFilter({
                      tenant_id:
                        e.target.value === "" ? null : Number(e.target.value),
                    })
                  }
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium">Status</label>
                <input
                  value={state.filters.status ?? ""}
                  onChange={(e) =>
                    setFilter({ status: e.target.value || null })
                  }
                  placeholder="active"
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium">Family</label>
                <select
                  value={state.filters.family ?? ""}
                  onChange={(e) =>
                    setFilter({
                      family:
                        e.target.value === ""
                          ? null
                          : (Number(e.target.value) as 4 | 6),
                    })
                  }
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="">Both</option>
                  <option value="4">IPv4</option>
                  <option value="6">IPv6</option>
                </select>
              </div>
              <div className="col-span-2">
                <label className="block text-[11px] font-medium">
                  Within (CIDR)
                </label>
                <input
                  value={state.filters.within_include ?? ""}
                  onChange={(e) =>
                    setFilter({ within_include: e.target.value || null })
                  }
                  placeholder="10.0.0.0/8"
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
            </div>
          </details>
        </div>
      </div>

      <div className="mt-4 flex justify-end gap-2">
        <HeaderButton
          variant="primary"
          icon={previewing ? Loader2 : ServerIcon}
          iconClassName={previewing ? "animate-spin" : undefined}
          onClick={onPreview}
          disabled={!canPreview || !!gate.disabled}
          title={gate.title}
        >
          {previewing ? "Pulling…" : "Preview import"}
        </HeaderButton>
      </div>
    </div>
  );
}

// ── Preview panel ────────────────────────────────────────────────────

function PreviewPanel({
  preview,
  decisions,
  setDecisions,
  onCommit,
  committing,
  onReset,
}: {
  preview: NetBoxImportPreview;
  decisions: Record<string, NetBoxImportConflictDecision>;
  setDecisions: (
    updater: (
      prev: Record<string, NetBoxImportConflictDecision>,
    ) => Record<string, NetBoxImportConflictDecision>,
  ) => void;
  onCommit: () => void;
  committing: boolean;
  onReset: () => void;
}) {
  // Group conflicts by entity kind so each accordion shows its own count.
  const conflictsByKind = useMemo(() => {
    const m = new Map<string, NetBoxEntityConflict[]>();
    for (const c of preview.conflicts) {
      const arr = m.get(c.kind) ?? [];
      arr.push(c);
      m.set(c.kind, arr);
    }
    return m;
  }, [preview.conflicts]);

  const totalRows = totalCreatable(preview);

  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            2. Review &amp; commit
          </div>
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <span>
              <strong>{totalRows}</strong> entit
              {totalRows === 1 ? "y" : "ies"}
            </span>
            <span>·</span>
            <span>
              <strong>{preview.conflicts.length}</strong> conflict
              {preview.conflicts.length === 1 ? "" : "s"}
            </span>
          </div>
        </div>

        {preview.warnings.length > 0 && (
          <div className="mb-3 space-y-1 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
            <div className="font-medium text-amber-700 dark:text-amber-400">
              Warnings
            </div>
            {preview.warnings.map((w, i) => (
              <div
                key={i}
                className="break-all text-amber-700/90 dark:text-amber-300/90"
              >
                {w}
              </div>
            ))}
          </div>
        )}

        {/* Per-entity accordion. */}
        <div className="space-y-2">
          {ENTITY_DEFS.map((def) => {
            const rows = preview[def.key] as unknown as Record<
              string,
              unknown
            >[];
            const conflicts = conflictsByKind.get(def.conflictKind) ?? [];
            return (
              <EntityAccordion
                key={def.key}
                label={def.label}
                rows={rows}
                identity={def.identity}
                keyOf={def.keyOf}
                conflicts={conflicts}
                decisions={decisions}
              />
            );
          })}
        </div>

        {/* Collision table — every conflict with a per-row skip/overwrite. */}
        {preview.conflicts.length > 0 && (
          <div className="mt-4">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Collisions
            </div>
            <div className="overflow-x-auto rounded-md border bg-background">
              <table className="w-full text-sm">
                <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 text-left">Kind</th>
                    <th className="px-3 py-2 text-left">Key</th>
                    <th className="px-3 py-2 text-left">Reason</th>
                    <th className="px-3 py-2 text-left">Existing</th>
                    <th className="px-3 py-2 text-left">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.conflicts.map((c) => {
                    const decision = decisions[c.key] ?? {
                      action: c.action,
                    };
                    return (
                      <tr key={`${c.kind}:${c.key}`} className="border-t">
                        <td className="px-3 py-2 align-top text-xs capitalize">
                          {c.kind}
                        </td>
                        <td className="break-all px-3 py-2 align-top font-mono text-xs">
                          {c.key}
                        </td>
                        <td className="px-3 py-2 align-top text-xs text-muted-foreground">
                          {c.reason}
                        </td>
                        <td className="break-all px-3 py-2 align-top font-mono text-[10px] text-muted-foreground">
                          {c.existing_id}
                        </td>
                        <td className="px-3 py-2 align-top">
                          <select
                            value={decision.action}
                            onChange={(e) =>
                              setDecisions((prev) => ({
                                ...prev,
                                [c.key]: {
                                  action: e.target
                                    .value as NetBoxImportConflictDecision["action"],
                                },
                              }))
                            }
                            className="rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                          >
                            <option value="skip">Skip</option>
                            <option value="overwrite">Overwrite</option>
                          </select>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
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
          disabled={committing || totalRows === 0}
        >
          {committing ? "Committing…" : "Commit import"}
        </HeaderButton>
      </div>
    </div>
  );
}

function EntityAccordion({
  label,
  rows,
  identity,
  keyOf,
  conflicts,
  decisions,
}: {
  label: string;
  rows: Record<string, unknown>[];
  identity: (row: Record<string, unknown>) => string;
  keyOf: (row: Record<string, unknown>) => string;
  conflicts: NetBoxEntityConflict[];
  decisions: Record<string, NetBoxImportConflictDecision>;
}) {
  const [open, setOpen] = useState(false);
  const conflictKeys = useMemo(
    () => new Set(conflicts.map((c) => c.key)),
    [conflicts],
  );
  // Per-row badge buckets. A row is "conflict" if its rebuilt backend key
  // (keyOf, mirroring services/netbox_import/commit.py) is in the conflict-key
  // set; the conflict's chosen action splits it into overwrite vs skip;
  // everything else is "create".
  let createN = 0;
  let updateN = 0;
  let skipN = 0;
  for (const r of rows) {
    const k = keyOf(r);
    if (conflictKeys.has(k)) {
      const action = decisions[k]?.action ?? "skip";
      if (action === "overwrite") updateN += 1;
      else skipN += 1;
    } else {
      createN += 1;
    }
  }
  const conflictN = conflicts.length;

  return (
    <div className="rounded-md border bg-background">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-muted/40"
      >
        <span className="flex items-center gap-2">
          {open ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
          <span className="font-medium">{label}</span>
          <span className="text-xs text-muted-foreground">({rows.length})</span>
        </span>
        <span className="flex flex-wrap items-center gap-1">
          {createN > 0 && <Badge tone="success">{createN} create</Badge>}
          {updateN > 0 && <Badge tone="amber">{updateN} update</Badge>}
          {conflictN > 0 && <Badge tone="amber">{conflictN} conflict</Badge>}
          {skipN > 0 && <Badge tone="muted">{skipN} skip</Badge>}
        </span>
      </button>
      {open && rows.length > 0 && (
        <div className="max-h-72 overflow-auto border-t">
          <table className="w-full text-sm">
            <tbody>
              {rows.map((r, i) => {
                const id = identity(r);
                const isConflict = conflictKeys.has(keyOf(r));
                return (
                  <tr key={`${id}:${i}`} className="border-t first:border-t-0">
                    <td className="break-all px-3 py-1.5 font-mono text-xs">
                      {id}
                    </td>
                    <td className="px-3 py-1.5 text-right">
                      {isConflict ? (
                        <Badge tone="amber">conflict</Badge>
                      ) : (
                        <Badge tone="success">new</Badge>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Commit result panel ──────────────────────────────────────────────

function CommitResultPanel({
  result,
  onReset,
}: {
  result: NetBoxImportCommitResult;
  onReset: () => void;
}) {
  // Per-kind created rollup, in the same dependency order as the preview.
  const perKind: { label: string; value: number }[] = [
    { label: "Customers", value: result.customers_created },
    { label: "Sites", value: result.sites_created },
    { label: "VRFs", value: result.vrfs_created },
    { label: "Spaces", value: result.spaces_created },
    { label: "VLANs", value: result.vlans_created },
    { label: "Blocks", value: result.blocks_created },
    { label: "Subnets", value: result.subnets_created },
    { label: "Addresses", value: result.addresses_created },
  ];

  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Import complete
          </div>
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <Stat label="Created" value={result.total_created} tone="success" />
            <Stat
              label="Overwrote"
              value={result.total_overwrote}
              tone="amber"
            />
            <Stat label="Skipped" value={result.total_skipped} tone="muted" />
            <Stat
              label="Failed"
              value={result.total_failed}
              tone="destructive"
            />
          </div>
        </div>

        {/* Per-kind created rollup ribbon. */}
        <div className="mb-3 flex flex-wrap gap-2">
          {perKind.map((k) => (
            <span
              key={k.label}
              className="inline-flex items-center gap-1 rounded-full border bg-background px-2 py-0.5 text-[11px]"
            >
              <span className="font-semibold tabular-nums">{k.value}</span>
              <span className="text-muted-foreground">{k.label}</span>
            </span>
          ))}
        </div>

        <div className="overflow-x-auto rounded-md border bg-background">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Kind</th>
                <th className="px-3 py-2 text-left">Key</th>
                <th className="px-3 py-2 text-left">Action</th>
                <th className="px-3 py-2 text-left">Error</th>
              </tr>
            </thead>
            <tbody>
              {result.entities.map((e, i) => (
                <tr key={`${e.kind}:${e.key}:${i}`} className="border-t">
                  <td className="px-3 py-2 align-top text-xs capitalize">
                    {e.kind}
                  </td>
                  <td className="break-all px-3 py-2 align-top font-mono text-xs">
                    {e.key}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <ActionPill action={e.action_taken} />
                  </td>
                  <td className="break-all px-3 py-2 align-top text-xs text-destructive">
                    {e.error ?? ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {result.warnings.length > 0 && (
          <div className="mt-3 space-y-1 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
            <div className="font-medium text-amber-700 dark:text-amber-400">
              Warnings
            </div>
            {result.warnings.map((w, i) => (
              <div
                key={i}
                className="break-all text-amber-700/90 dark:text-amber-300/90"
              >
                {w}
              </div>
            ))}
          </div>
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

// ── Small presentational helpers ─────────────────────────────────────

function Badge({
  tone,
  children,
}: {
  tone: "success" | "amber" | "muted" | "destructive";
  children: React.ReactNode;
}) {
  const tones: Record<string, string> = {
    success: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
    amber: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
    muted: "bg-zinc-500/15 text-zinc-700 dark:text-zinc-400",
    destructive: "bg-destructive/15 text-destructive",
  };
  return (
    <span
      className={cn(
        "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium",
        tones[tone],
      )}
    >
      {children}
    </span>
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
    failed: {
      tone: "bg-destructive/15 text-destructive",
      label: "failed",
    },
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
