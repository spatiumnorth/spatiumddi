import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  Database,
  Download,
  FileArchive,
  Globe,
  Loader2,
  Plug,
  RotateCcw,
  Server as ServerIcon,
  Trash2,
  Upload,
} from "lucide-react";

import {
  dnsApi,
  dnsImportApi,
  type CloudDNSServerOption,
  type DNSImportApexNsPolicy,
  type DNSImportCommitResult,
  type DNSImportConflictDecision,
  type DNSImportedZone,
  type DNSImportPreview,
  type DNSImportSource,
  type DNSImportZoneConflict,
  type PowerDNSConnectionInfo,
  type TechnitiumConnectionInfo,
  type WindowsDNSServerOption,
  formatApiError,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { HeaderButton } from "@/components/ui/header-button";
import { ListReadError } from "@/components/ui/list-read-error";
import { ZoneScopePill } from "@/components/ZoneScopePill";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";

// Tab metadata. Every source is live; ``available: false`` remains the
// hook for rendering a not-yet-shipped source (so the operator sees the
// roadmap) click-disabled with a phase badge.
// ``cloud`` isn't a ``DNSImportSource`` (that union is the wire-level
// importer type and lives in lib/api.ts); it's a UI-only tab that pulls
// from a registered cloud-DNS server row via the dedicated endpoints.
type TabId = DNSImportSource | "cloud";

interface TabDef {
  id: TabId;
  label: string;
  short: string;
  available: boolean;
  badge?: string;
  description: string;
}

// Tabs ordered alphabetically by label: BIND9 / Cloud / PowerDNS /
// Technitium / Windows DNS.
const TABS: TabDef[] = [
  {
    id: "bind9",
    label: "BIND9",
    short: "named.conf + zone files",
    available: true,
    description:
      "Upload a tarball or zip containing your named.conf plus all referenced zone files. The importer parses every zone declaration (including those nested inside view {} blocks), reads the master file from the archive, and stages the canonical zone + record IR for review. SOA, MX priority, SRV priority/weight/port, and CNAME records all carry through. DNSSEC records (DNSKEY/RRSIG/NSEC*/DS) get stripped — re-sign post-import via the zone DNSSEC tab.",
  },
  {
    id: "cloud",
    label: "Cloud",
    short: "provider API live pull",
    available: true,
    description:
      "Live-pull every hosted zone + record set from a cloud DNS provider (Cloudflare / AWS Route 53 / Azure DNS / Google Cloud DNS) already registered as a cloud-driver DNS server in SpatiumDDI. Pick the server — its stored provider credentials drive the pull — and the importer walks the provider's hosted-zone + record APIs. Provider-managed apex records (SOA / provider NS) get default values you can edit post-import.",
  },
  {
    id: "powerdns",
    label: "PowerDNS",
    short: "REST API live pull",
    available: true,
    description:
      "Live-pull every zone + record from a PowerDNS Authoritative REST API. Provide the API URL + API key; the importer walks /api/v1/servers/{server}/zones and resolves each zone's full record set. Credentials are read-once and never persisted. DNSSEC records get stripped — re-sign post-import via the zone DNSSEC tab.",
  },
  {
    id: "technitium",
    label: "Technitium",
    short: "REST API live pull",
    available: true,
    description:
      "Live-pull every Primary zone + record from a Technitium DNS Server. Provide the console URL + an API token; the importer walks /api/zones/list and resolves each zone's full record set. Credentials are read-once and never persisted. Only Primary zones import — secondary, stub, forwarder and catalog zones are reported as warnings, since a secondary is a copy of another server's data. Disabled zones and records are skipped rather than silently re-enabled, and DNSSEC records get stripped — re-sign post-import via the zone DNSSEC tab.",
  },
  {
    id: "windows_dns",
    label: "Windows DNS",
    short: "WinRM live pull",
    available: true,
    description:
      "Live-pull every zone + record from a Windows DNS server using the same WinRM read driver the Logs surface uses. Pick a Windows DNS server already registered in SpatiumDDI (with WinRM credentials configured) and the importer walks Get-DnsServerZone + Get-DnsServerResourceRecord. Windows owns SOA on the server side — imported zones get default SOA values that you can edit via the zone editor post-import.",
  },
];

type Phase = "select" | "previewing" | "ready" | "committing" | "result";

interface BindUploadState {
  file: File | null;
  groupId: string;
  viewId: string;
  preview: DNSImportPreview | null;
  decisions: Record<string, DNSImportConflictDecision>;
  result: DNSImportCommitResult | null;
  phase: Phase;
  error: string | null;
}

/** Every DNS import route — preview, test and commit — takes a superadmin
 *  (`dns_import/router.py`), so the controls that start one say so rather
 *  than letting a DNS Editor upload an archive and be refused (#1879's
 *  sweep). Commit is reachable only from a successful preview. */
function useImportGate(): { disabled?: boolean; title?: string } {
  return permissionGate(usePermissions().isSuperadmin, NEEDS_SUPERADMIN);
}

function emptyState(): BindUploadState {
  return {
    file: null,
    groupId: "",
    viewId: "",
    preview: null,
    decisions: {},
    result: null,
    phase: "select",
    error: null,
  };
}

export function DNSImportPage() {
  const location = useLocation();
  // Deep-link from the DNS server modal / list "Sync from provider" button:
  // navigate("/admin/dns-import", { state: { cloudServerId } }). Open the
  // Cloud tab pre-selected to that server.
  const deepLinkServerId =
    (location.state as { cloudServerId?: string } | null)?.cloudServerId ??
    null;
  const [tab, setTab] = useState<TabId>(deepLinkServerId ? "cloud" : "bind9");
  const active = TABS.find((t) => t.id === tab) ?? TABS[0];

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b p-4">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Upload className="h-5 w-5 flex-shrink-0 text-primary" />
          <div className="min-w-0">
            <h1 className="text-lg font-semibold">DNS configuration import</h1>
            <p className="text-xs text-muted-foreground">
              One-shot import of zones + records from BIND9 / Cloud DNS /
              PowerDNS / Windows DNS into native SpatiumDDI rows. Once imported,
              SpatiumDDI is the source of truth — there is no continuous two-way
              mirror.
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
              onClick={() => t.available && setTab(t.id)}
              disabled={!t.available}
              className={cn(
                "-mb-px flex items-center gap-2 border-b-2 px-3 py-2 text-sm transition-colors",
                tab === t.id
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
                !t.available && "cursor-not-allowed opacity-60",
              )}
            >
              {t.label}
              {t.badge && (
                <span className="rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-amber-700 dark:text-amber-400">
                  {t.badge}
                </span>
              )}
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

        {tab === "bind9" && <BindTab />}
        {tab === "cloud" && (
          <CloudDNSTab initialServerId={deepLinkServerId ?? undefined} />
        )}
        {tab === "windows_dns" && <WindowsDNSTab />}
        {tab === "powerdns" && <PowerDNSTab />}
        {tab === "technitium" && <TechnitiumTab />}
      </div>
    </div>
  );
}

// ── BIND9 tab body ───────────────────────────────────────────────────

function BindTab() {
  const [state, setState] = useState<BindUploadState>(emptyState());

  const groupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });
  const viewsQ = useQuery({
    queryKey: ["dns-views", state.groupId],
    queryFn: () =>
      state.groupId ? dnsApi.listViews(state.groupId) : Promise.resolve([]),
    enabled: Boolean(state.groupId),
  });

  const previewMut = useMutation({
    mutationFn: () => {
      if (!state.file || !state.groupId) {
        throw new Error("Pick a file and target server group first");
      }
      return dnsImportApi.bind9Preview(
        state.file,
        state.groupId,
        state.viewId || undefined,
      );
    },
    onSuccess: (preview) => {
      // Seed conflict decisions with whatever the server suggests
      // (defaults to "skip"). Operator edits per-row before commit.
      const decisions: Record<string, DNSImportConflictDecision> = {};
      for (const c of preview.conflicts) {
        decisions[c.zone_name] = { action: c.action, rename_to: c.rename_to };
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
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "select", error: detail }));
    },
  });

  const commitMut = useMutation({
    mutationFn: (apexNsPolicy: DNSImportApexNsPolicy) => {
      if (!state.preview) throw new Error("Preview the archive first");
      return dnsImportApi.bind9Commit({
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
        plan: state.preview,
        conflict_actions: state.decisions,
        apex_ns_policy: apexNsPolicy,
      });
    },
    onSuccess: (result) => {
      setState((s) => ({ ...s, result, phase: "result", error: null }));
    },
    onError: (err: unknown) => {
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "ready", error: detail }));
    },
  });

  const conflictByZone = useMemo(() => {
    const m = new Map<string, DNSImportZoneConflict>();
    for (const c of state.preview?.conflicts ?? []) m.set(c.zone_name, c);
    return m;
  }, [state.preview]);

  const reset = () => setState(emptyState());

  const onFileChange = (f: File | null) => {
    setState((s) => ({
      ...s,
      file: f,
      preview: null,
      result: null,
      phase: "select",
      error: null,
    }));
  };

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
          <UploadForm
            state={state}
            setState={setState}
            groups={groupsQ.data ?? []}
            views={viewsQ.data ?? []}
            onFileChange={onFileChange}
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
              conflictByZone={conflictByZone}
              onCommit={(apexNsPolicy) => {
                setState((s) => ({ ...s, phase: "committing", error: null }));
                commitMut.mutate(apexNsPolicy);
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

// ── Windows DNS tab body ─────────────────────────────────────────────

interface WindowsDNSState {
  serverId: string;
  groupId: string;
  viewId: string;
  preview: DNSImportPreview | null;
  decisions: Record<string, DNSImportConflictDecision>;
  result: DNSImportCommitResult | null;
  phase: Phase;
  error: string | null;
}

function emptyWindowsState(): WindowsDNSState {
  return {
    serverId: "",
    groupId: "",
    viewId: "",
    preview: null,
    decisions: {},
    result: null,
    phase: "select",
    error: null,
  };
}

function WindowsDNSTab() {
  const [state, setState] = useState<WindowsDNSState>(emptyWindowsState());

  const groupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });
  const viewsQ = useQuery({
    queryKey: ["dns-views", state.groupId],
    queryFn: () =>
      state.groupId ? dnsApi.listViews(state.groupId) : Promise.resolve([]),
    enabled: Boolean(state.groupId),
  });
  const serversQ = useQuery({
    queryKey: ["dns-import-windows-servers"],
    queryFn: () => dnsImportApi.windowsDNSServers(),
  });

  const previewMut = useMutation({
    mutationFn: () => {
      if (!state.serverId || !state.groupId) {
        throw new Error(
          "Pick a Windows DNS server and target server group first",
        );
      }
      return dnsImportApi.windowsDNSPreview({
        server_id: state.serverId,
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
      });
    },
    onSuccess: (preview) => {
      const decisions: Record<string, DNSImportConflictDecision> = {};
      for (const c of preview.conflicts) {
        decisions[c.zone_name] = { action: c.action, rename_to: c.rename_to };
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
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "select", error: detail }));
    },
  });

  const commitMut = useMutation({
    mutationFn: (apexNsPolicy: DNSImportApexNsPolicy) => {
      if (!state.preview) throw new Error("Preview the server first");
      return dnsImportApi.windowsDNSCommit({
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
        plan: state.preview,
        conflict_actions: state.decisions,
        apex_ns_policy: apexNsPolicy,
      });
    },
    onSuccess: (result) => {
      setState((s) => ({ ...s, result, phase: "result", error: null }));
    },
    onError: (err: unknown) => {
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "ready", error: detail }));
    },
  });

  const conflictByZone = useMemo(() => {
    const m = new Map<string, DNSImportZoneConflict>();
    for (const c of state.preview?.conflicts ?? []) m.set(c.zone_name, c);
    return m;
  }, [state.preview]);

  const reset = () => setState(emptyWindowsState());

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
          <WindowsDNSPullForm
            state={state}
            setState={setState}
            servers={serversQ.data ?? []}
            serversLoading={serversQ.isLoading}
            serversError={serversQ.error}
            groups={groupsQ.data ?? []}
            views={viewsQ.data ?? []}
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
              conflictByZone={conflictByZone}
              onCommit={(apexNsPolicy) => {
                setState((s) => ({ ...s, phase: "committing", error: null }));
                commitMut.mutate(apexNsPolicy);
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

function WindowsDNSPullForm({
  state,
  setState,
  servers,
  serversLoading,
  serversError,
  groups,
  views,
  onPreview,
  previewing,
}: {
  state: WindowsDNSState;
  setState: React.Dispatch<React.SetStateAction<WindowsDNSState>>;
  servers: WindowsDNSServerOption[];
  serversLoading: boolean;
  serversError: unknown;
  groups: { id: string; name: string }[];
  views: { id: string; name: string }[];
  onPreview: () => void;
  previewing: boolean;
}) {
  const gate = useImportGate();
  const canPreview = Boolean(state.serverId && state.groupId) && !previewing;
  const eligible = servers.filter((s) => s.has_credentials);
  const hasIneligible = servers.length > eligible.length;

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        1. Pick source + target
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div>
          <label className="block text-sm font-medium">
            Windows DNS server
          </label>
          <p className="mb-2 text-[11px] text-muted-foreground">
            Pick a registered windows_dns server with WinRM credentials already
            configured. The pull walks Get-DnsServerZone +
            Get-DnsServerResourceRecord. Servers without credentials are greyed
            out — open the DNS server modal to add them.
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
                  : eligible.length === 0
                    ? "— no eligible servers —"
                    : "— select —"}
            </option>
            {servers.map((srv) => (
              <option
                key={srv.id}
                value={srv.id}
                disabled={!srv.has_credentials}
              >
                {srv.group_name} / {srv.name} ({srv.host})
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
          {hasIneligible && (
            <p className="mt-1 text-[11px] text-amber-700 dark:text-amber-400">
              Some servers are listed but disabled — they don't have WinRM
              credentials configured yet.
            </p>
          )}
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">
              Target server group
            </label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Imported zones land in this group — usually the same one the
              source server already belongs to, but you can land them in a
              different group (e.g., a staging group) for review.
            </p>
            <select
              value={state.groupId}
              onChange={(e) =>
                setState((s) => ({ ...s, groupId: e.target.value, viewId: "" }))
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
          {views.length > 0 && (
            <div>
              <label className="block text-sm font-medium">
                Target view (optional)
              </label>
              <select
                value={state.viewId}
                onChange={(e) =>
                  setState((s) => ({ ...s, viewId: e.target.value }))
                }
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Default view</option>
                {views.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </select>
            </div>
          )}
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
          {previewing ? "Pulling zones…" : "Preview import"}
        </HeaderButton>
      </div>
    </div>
  );
}

// ── Cloud DNS tab body (issue #37, Part B) ───────────────────────────

const CLOUD_DRIVER_LABELS: Record<string, string> = {
  cloudflare: "Cloudflare",
  route53: "AWS Route 53",
  azure_dns: "Azure DNS",
  google_dns: "Google Cloud DNS",
  digitalocean: "DigitalOcean",
  hetzner: "Hetzner DNS",
  linode: "Linode",
  vultr: "Vultr",
};

function cloudDriverLabel(driver: string): string {
  return CLOUD_DRIVER_LABELS[driver] ?? driver;
}

interface CloudDNSState {
  serverId: string;
  groupId: string;
  viewId: string;
  preview: DNSImportPreview | null;
  decisions: Record<string, DNSImportConflictDecision>;
  result: DNSImportCommitResult | null;
  phase: Phase;
  error: string | null;
}

function emptyCloudState(serverId = ""): CloudDNSState {
  return {
    serverId,
    groupId: "",
    viewId: "",
    preview: null,
    decisions: {},
    result: null,
    phase: "select",
    error: null,
  };
}

function CloudDNSTab({ initialServerId }: { initialServerId?: string }) {
  const [state, setState] = useState<CloudDNSState>(() =>
    emptyCloudState(initialServerId),
  );

  const groupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });
  const viewsQ = useQuery({
    queryKey: ["dns-views", state.groupId],
    queryFn: () =>
      state.groupId ? dnsApi.listViews(state.groupId) : Promise.resolve([]),
    enabled: Boolean(state.groupId),
  });
  const serversQ = useQuery({
    queryKey: ["dns-import-cloud-servers"],
    queryFn: () => dnsImportApi.cloudDNSServers(),
  });

  // When deep-linked to a server that has no creds (or that isn't in the
  // list yet), don't silently keep an invalid id selected. Once the server
  // list resolves, clear the selection if the deep-linked row isn't eligible.
  useEffect(() => {
    if (!state.serverId || !serversQ.data) return;
    const row = serversQ.data.find((s) => s.id === state.serverId);
    if (!row || !row.has_credentials) {
      setState((s) => ({ ...s, serverId: "" }));
    }
    // Only re-run when the server list arrives.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serversQ.data]);

  const selectedServer = useMemo(
    () => serversQ.data?.find((s) => s.id === state.serverId) ?? null,
    [serversQ.data, state.serverId],
  );

  const previewMut = useMutation({
    mutationFn: () => {
      if (!state.serverId || !state.groupId) {
        throw new Error(
          "Pick a cloud DNS server and target server group first",
        );
      }
      return dnsImportApi.cloudDNSPreview({
        server_id: state.serverId,
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
      });
    },
    onSuccess: (preview) => {
      const decisions: Record<string, DNSImportConflictDecision> = {};
      for (const c of preview.conflicts) {
        decisions[c.zone_name] = { action: c.action, rename_to: c.rename_to };
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
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "select", error: detail }));
    },
  });

  const commitMut = useMutation({
    mutationFn: (apexNsPolicy: DNSImportApexNsPolicy) => {
      if (!state.preview) throw new Error("Preview the server first");
      return dnsImportApi.cloudDNSCommit({
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
        plan: state.preview,
        conflict_actions: state.decisions,
        apex_ns_policy: apexNsPolicy,
      });
    },
    onSuccess: (result) => {
      setState((s) => ({ ...s, result, phase: "result", error: null }));
    },
    onError: (err: unknown) => {
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "ready", error: detail }));
    },
  });

  const conflictByZone = useMemo(() => {
    const m = new Map<string, DNSImportZoneConflict>();
    for (const c of state.preview?.conflicts ?? []) m.set(c.zone_name, c);
    return m;
  }, [state.preview]);

  const reset = () => setState(emptyCloudState());

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
          <CloudDNSPullForm
            state={state}
            setState={setState}
            servers={serversQ.data ?? []}
            serversLoading={serversQ.isLoading}
            serversError={serversQ.error}
            selectedServer={selectedServer}
            groups={groupsQ.data ?? []}
            views={viewsQ.data ?? []}
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
              conflictByZone={conflictByZone}
              onCommit={(apexNsPolicy) => {
                setState((s) => ({ ...s, phase: "committing", error: null }));
                commitMut.mutate(apexNsPolicy);
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

function CloudDNSPullForm({
  state,
  setState,
  servers,
  serversLoading,
  serversError,
  selectedServer,
  groups,
  views,
  onPreview,
  previewing,
}: {
  state: CloudDNSState;
  setState: React.Dispatch<React.SetStateAction<CloudDNSState>>;
  servers: CloudDNSServerOption[];
  serversLoading: boolean;
  serversError: unknown;
  selectedServer: CloudDNSServerOption | null;
  groups: { id: string; name: string }[];
  views: { id: string; name: string }[];
  onPreview: () => void;
  previewing: boolean;
}) {
  const gate = useImportGate();
  const canPreview = Boolean(state.serverId && state.groupId) && !previewing;
  const eligible = servers.filter((s) => s.has_credentials);
  const hasIneligible = servers.length > eligible.length;

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        1. Pick source + target
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div>
          <label className="block text-sm font-medium">Cloud DNS server</label>
          <p className="mb-2 text-[11px] text-muted-foreground">
            Pick a registered cloud-driver DNS server (Cloudflare / Route 53 /
            Azure DNS / Google Cloud DNS) with provider credentials configured.
            The pull walks the provider's hosted-zone + record APIs. Servers
            without credentials are greyed out — open the DNS server modal to
            add them.
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
                  : eligible.length === 0
                    ? "— no eligible servers —"
                    : "— select —"}
            </option>
            {servers.map((srv) => (
              <option
                key={srv.id}
                value={srv.id}
                disabled={!srv.has_credentials}
              >
                {srv.group_name} / {srv.name} ({cloudDriverLabel(srv.driver)})
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
          {selectedServer && (
            <p className="mt-1 text-[11px] text-muted-foreground">
              Source provider:{" "}
              <span className="font-medium text-foreground">
                {cloudDriverLabel(selectedServer.driver)}
              </span>
            </p>
          )}
          {hasIneligible && (
            <p className="mt-1 text-[11px] text-amber-700 dark:text-amber-400">
              Some servers are listed but disabled — they don't have provider
              credentials configured yet.
            </p>
          )}
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">
              Target server group
            </label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Imported zones land in this group — usually the same one the
              source server already belongs to, but you can land them in a
              different group (e.g., a staging group) for review.
            </p>
            <select
              value={state.groupId}
              onChange={(e) =>
                setState((s) => ({ ...s, groupId: e.target.value, viewId: "" }))
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
          {views.length > 0 && (
            <div>
              <label className="block text-sm font-medium">
                Target view (optional)
              </label>
              <select
                value={state.viewId}
                onChange={(e) =>
                  setState((s) => ({ ...s, viewId: e.target.value }))
                }
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Default view</option>
                {views.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <HeaderButton
          variant="primary"
          icon={previewing ? Loader2 : Cloud}
          iconClassName={previewing ? "animate-spin" : undefined}
          onClick={onPreview}
          disabled={!canPreview || !!gate.disabled}
          title={gate.title}
        >
          {previewing ? "Pulling zones…" : "Preview import"}
        </HeaderButton>
      </div>
    </div>
  );
}

// ── PowerDNS tab body ────────────────────────────────────────────────

interface PowerDNSState {
  apiUrl: string;
  apiKey: string;
  serverName: string;
  groupId: string;
  viewId: string;
  testInfo: PowerDNSConnectionInfo | null;
  preview: DNSImportPreview | null;
  decisions: Record<string, DNSImportConflictDecision>;
  result: DNSImportCommitResult | null;
  phase: Phase;
  error: string | null;
}

function emptyPowerDNSState(): PowerDNSState {
  return {
    apiUrl: "",
    apiKey: "",
    serverName: "localhost",
    groupId: "",
    viewId: "",
    testInfo: null,
    preview: null,
    decisions: {},
    result: null,
    phase: "select",
    error: null,
  };
}

function PowerDNSTab() {
  const [state, setState] = useState<PowerDNSState>(emptyPowerDNSState());

  const groupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });
  const viewsQ = useQuery({
    queryKey: ["dns-views", state.groupId],
    queryFn: () =>
      state.groupId ? dnsApi.listViews(state.groupId) : Promise.resolve([]),
    enabled: Boolean(state.groupId),
  });

  const testMut = useMutation({
    mutationFn: () => {
      if (!state.apiUrl || !state.apiKey) {
        throw new Error("Provide an API URL and API key first");
      }
      return dnsImportApi.powerDNSTestConnection({
        api_url: state.apiUrl,
        api_key: state.apiKey,
        server_name: state.serverName || "localhost",
      });
    },
    onSuccess: (info) => {
      setState((s) => ({ ...s, testInfo: info, error: null }));
    },
    onError: (err: unknown) => {
      const detail = formatApiError(err);
      setState((s) => ({ ...s, testInfo: null, error: detail }));
    },
  });

  const previewMut = useMutation({
    mutationFn: () => {
      if (!state.apiUrl || !state.apiKey || !state.groupId) {
        throw new Error(
          "Provide an API URL, API key, and target server group first",
        );
      }
      return dnsImportApi.powerDNSPreview({
        api_url: state.apiUrl,
        api_key: state.apiKey,
        server_name: state.serverName || "localhost",
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
      });
    },
    onSuccess: (preview) => {
      const decisions: Record<string, DNSImportConflictDecision> = {};
      for (const c of preview.conflicts) {
        decisions[c.zone_name] = { action: c.action, rename_to: c.rename_to };
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
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "select", error: detail }));
    },
  });

  const commitMut = useMutation({
    mutationFn: (apexNsPolicy: DNSImportApexNsPolicy) => {
      if (!state.preview) throw new Error("Preview the server first");
      return dnsImportApi.powerDNSCommit({
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
        plan: state.preview,
        conflict_actions: state.decisions,
        apex_ns_policy: apexNsPolicy,
      });
    },
    onSuccess: (result) => {
      setState((s) => ({ ...s, result, phase: "result", error: null }));
    },
    onError: (err: unknown) => {
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "ready", error: detail }));
    },
  });

  const conflictByZone = useMemo(() => {
    const m = new Map<string, DNSImportZoneConflict>();
    for (const c of state.preview?.conflicts ?? []) m.set(c.zone_name, c);
    return m;
  }, [state.preview]);

  const reset = () => setState(emptyPowerDNSState());

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
          <PowerDNSPullForm
            state={state}
            setState={setState}
            groups={groupsQ.data ?? []}
            views={viewsQ.data ?? []}
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
              conflictByZone={conflictByZone}
              onCommit={(apexNsPolicy) => {
                setState((s) => ({ ...s, phase: "committing", error: null }));
                commitMut.mutate(apexNsPolicy);
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

function PowerDNSPullForm({
  state,
  setState,
  groups,
  views,
  onTest,
  testing,
  onPreview,
  previewing,
}: {
  state: PowerDNSState;
  setState: React.Dispatch<React.SetStateAction<PowerDNSState>>;
  groups: { id: string; name: string }[];
  views: { id: string; name: string }[];
  onTest: () => void;
  testing: boolean;
  onPreview: () => void;
  previewing: boolean;
}) {
  const gate = useImportGate();
  const canTest =
    Boolean(state.apiUrl && state.apiKey) && !testing && !previewing;
  const canPreview =
    Boolean(state.apiUrl && state.apiKey && state.groupId) &&
    !previewing &&
    !testing;

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        1. PowerDNS source + target
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">API URL</label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Base URL of the PowerDNS Authoritative API. Example:{" "}
              <code>http://pdns.internal:8081</code>. Don't include the{" "}
              <code>/api/v1</code> suffix — we append it.
            </p>
            <input
              value={state.apiUrl}
              onChange={(e) =>
                setState((s) => ({
                  ...s,
                  apiUrl: e.target.value,
                  testInfo: null,
                }))
              }
              placeholder="http://pdns.internal:8081"
              className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <div>
            <label className="block text-sm font-medium">API key</label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              The PowerDNS <code className="text-[10px]">api-key</code> setting
              from <code>pdns.conf</code>. Read once and never persisted — if
              you re-import you'll re-paste.
            </p>
            <input
              type="password"
              value={state.apiKey}
              onChange={(e) =>
                setState((s) => ({
                  ...s,
                  apiKey: e.target.value,
                  testInfo: null,
                }))
              }
              placeholder="pdns api key"
              className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <div>
            <label className="block text-sm font-medium">
              Server name (optional)
            </label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              PowerDNS's <code className="text-[10px]">server-id</code> for the
              daemon. Defaults to <code>localhost</code> — only change this if
              your upstream is fronted by a multi-server API.
            </p>
            <input
              value={state.serverName}
              onChange={(e) =>
                setState((s) => ({ ...s, serverName: e.target.value }))
              }
              placeholder="localhost"
              className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
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
            {state.testInfo && (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
                <CheckCircle2 className="h-3 w-3" />
                {state.testInfo.daemon_type || "PowerDNS"}{" "}
                {state.testInfo.version || ""}
              </span>
            )}
          </div>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">
              Target server group
            </label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Imported zones land in this group. Pick one with at least one
              registered server so the agent picks them up on its next sync.
            </p>
            <select
              value={state.groupId}
              onChange={(e) =>
                setState((s) => ({ ...s, groupId: e.target.value, viewId: "" }))
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
          {views.length > 0 && (
            <div>
              <label className="block text-sm font-medium">
                Target view (optional)
              </label>
              <select
                value={state.viewId}
                onChange={(e) =>
                  setState((s) => ({ ...s, viewId: e.target.value }))
                }
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Default view</option>
                {views.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <HeaderButton
          variant="primary"
          icon={previewing ? Loader2 : Globe}
          iconClassName={previewing ? "animate-spin" : undefined}
          onClick={onPreview}
          disabled={!canPreview || !!gate.disabled}
          title={gate.title}
        >
          {previewing ? "Pulling zones…" : "Preview import"}
        </HeaderButton>
      </div>
    </div>
  );
}

// ── Technitium tab body (issue #744) ─────────────────────────────────

interface TechnitiumState {
  apiUrl: string;
  apiToken: string;
  groupId: string;
  viewId: string;
  testInfo: TechnitiumConnectionInfo | null;
  preview: DNSImportPreview | null;
  decisions: Record<string, DNSImportConflictDecision>;
  result: DNSImportCommitResult | null;
  phase: Phase;
  error: string | null;
}

function emptyTechnitiumState(): TechnitiumState {
  return {
    apiUrl: "",
    apiToken: "",
    groupId: "",
    viewId: "",
    testInfo: null,
    preview: null,
    decisions: {},
    result: null,
    phase: "select",
    error: null,
  };
}

function TechnitiumTab() {
  const [state, setState] = useState<TechnitiumState>(emptyTechnitiumState());

  const groupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });
  const viewsQ = useQuery({
    queryKey: ["dns-views", state.groupId],
    queryFn: () =>
      state.groupId ? dnsApi.listViews(state.groupId) : Promise.resolve([]),
    enabled: Boolean(state.groupId),
  });

  const testMut = useMutation({
    mutationFn: () => {
      if (!state.apiUrl || !state.apiToken) {
        throw new Error("Provide an API URL and API key first");
      }
      return dnsImportApi.technitiumTestConnection({
        api_url: state.apiUrl,
        api_token: state.apiToken,
      });
    },
    onSuccess: (info) => {
      setState((s) => ({ ...s, testInfo: info, error: null }));
    },
    onError: (err: unknown) => {
      const detail = formatApiError(err);
      setState((s) => ({ ...s, testInfo: null, error: detail }));
    },
  });

  const previewMut = useMutation({
    mutationFn: () => {
      if (!state.apiUrl || !state.apiToken || !state.groupId) {
        throw new Error(
          "Provide an API URL, API key, and target server group first",
        );
      }
      return dnsImportApi.technitiumPreview({
        api_url: state.apiUrl,
        api_token: state.apiToken,
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
      });
    },
    onSuccess: (preview) => {
      const decisions: Record<string, DNSImportConflictDecision> = {};
      for (const c of preview.conflicts) {
        decisions[c.zone_name] = { action: c.action, rename_to: c.rename_to };
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
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "select", error: detail }));
    },
  });

  const commitMut = useMutation({
    mutationFn: (apexNsPolicy: DNSImportApexNsPolicy) => {
      if (!state.preview) throw new Error("Preview the server first");
      return dnsImportApi.technitiumCommit({
        target_group_id: state.groupId,
        target_view_id: state.viewId || null,
        plan: state.preview,
        conflict_actions: state.decisions,
        apex_ns_policy: apexNsPolicy,
      });
    },
    onSuccess: (result) => {
      setState((s) => ({ ...s, result, phase: "result", error: null }));
    },
    onError: (err: unknown) => {
      const detail = formatApiError(err);
      setState((s) => ({ ...s, phase: "ready", error: detail }));
    },
  });

  const conflictByZone = useMemo(() => {
    const m = new Map<string, DNSImportZoneConflict>();
    for (const c of state.preview?.conflicts ?? []) m.set(c.zone_name, c);
    return m;
  }, [state.preview]);

  const reset = () => setState(emptyTechnitiumState());

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
          <TechnitiumPullForm
            state={state}
            setState={setState}
            groups={groupsQ.data ?? []}
            views={viewsQ.data ?? []}
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
              conflictByZone={conflictByZone}
              onCommit={(apexNsPolicy) => {
                setState((s) => ({ ...s, phase: "committing", error: null }));
                commitMut.mutate(apexNsPolicy);
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

function TechnitiumPullForm({
  state,
  setState,
  groups,
  views,
  onTest,
  testing,
  onPreview,
  previewing,
}: {
  state: TechnitiumState;
  setState: React.Dispatch<React.SetStateAction<TechnitiumState>>;
  groups: { id: string; name: string }[];
  views: { id: string; name: string }[];
  onTest: () => void;
  testing: boolean;
  onPreview: () => void;
  previewing: boolean;
}) {
  const gate = useImportGate();
  const canTest =
    Boolean(state.apiUrl && state.apiToken) && !testing && !previewing;
  const canPreview =
    Boolean(state.apiUrl && state.apiToken && state.groupId) &&
    !previewing &&
    !testing;

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        1. Technitium source + target
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">API URL</label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Base URL of the Technitium Authoritative API. Example:{" "}
              <code>http://pdns.internal:8081</code>. Don't include the{" "}
              <code>/api/v1</code> suffix — we append it.
            </p>
            <input
              value={state.apiUrl}
              onChange={(e) =>
                setState((s) => ({
                  ...s,
                  apiUrl: e.target.value,
                  testInfo: null,
                }))
              }
              placeholder="http://pdns.internal:8081"
              className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <div>
            <label className="block text-sm font-medium">API key</label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              The Technitium <code className="text-[10px]">api-key</code>{" "}
              setting from <code>pdns.conf</code>. Read once and never persisted
              — if you re-import you'll re-paste.
            </p>
            <input
              type="password"
              value={state.apiToken}
              onChange={(e) =>
                setState((s) => ({
                  ...s,
                  apiToken: e.target.value,
                  testInfo: null,
                }))
              }
              placeholder="pdns api key"
              className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
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
            {state.testInfo && (
              <p className="text-xs text-emerald-600">
                Connected — {state.testInfo.zone_count} zone
                {state.testInfo.zone_count === 1 ? "" : "s"} found,{" "}
                {state.testInfo.importable_zone_count} importable. Only Primary
                zones are imported; secondary, stub, forwarder and catalog zones
                are reported as warnings.
              </p>
            )}
          </div>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">
              Target server group
            </label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Imported zones land in this group. Pick one with at least one
              registered server so the agent picks them up on its next sync.
            </p>
            <select
              value={state.groupId}
              onChange={(e) =>
                setState((s) => ({ ...s, groupId: e.target.value, viewId: "" }))
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
          {views.length > 0 && (
            <div>
              <label className="block text-sm font-medium">
                Target view (optional)
              </label>
              <select
                value={state.viewId}
                onChange={(e) =>
                  setState((s) => ({ ...s, viewId: e.target.value }))
                }
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Default view</option>
                {views.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <HeaderButton
          variant="primary"
          icon={previewing ? Loader2 : Globe}
          iconClassName={previewing ? "animate-spin" : undefined}
          onClick={onPreview}
          disabled={!canPreview || !!gate.disabled}
          title={gate.title}
        >
          {previewing ? "Pulling zones…" : "Preview import"}
        </HeaderButton>
      </div>
    </div>
  );
}

function UploadForm({
  state,
  setState,
  groups,
  views,
  onFileChange,
  onPreview,
  previewing,
}: {
  state: BindUploadState;
  setState: React.Dispatch<React.SetStateAction<BindUploadState>>;
  groups: { id: string; name: string }[];
  views: { id: string; name: string }[];
  onFileChange: (f: File | null) => void;
  onPreview: () => void;
  previewing: boolean;
}) {
  const gate = useImportGate();
  const canPreview = Boolean(state.file && state.groupId) && !previewing;
  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        1. Configure source
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div>
          <label className="block text-sm font-medium">Archive</label>
          <p className="mb-2 text-[11px] text-muted-foreground">
            ZIP, .tar.gz, .tar.bz2, or .tar.xz. Max 50 MB. Must contain a
            named.conf plus all referenced zone files.
          </p>
          <label
            className={cn(
              "flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed px-4 py-6 text-sm hover:bg-muted",
              state.file && "bg-muted/40 text-foreground",
            )}
          >
            <FileArchive className="h-4 w-4 text-muted-foreground" />
            <span>
              {state.file
                ? `${state.file.name} (${(state.file.size / 1024).toFixed(1)} KB)`
                : "Choose archive…"}
            </span>
            <input
              type="file"
              accept=".zip,.tar,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.txz,application/zip,application/x-tar,application/gzip"
              className="sr-only"
              onChange={(e) => onFileChange(e.target.files?.[0] ?? null)}
            />
          </label>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium">
              Target server group
            </label>
            <p className="mb-2 text-[11px] text-muted-foreground">
              Imported zones land in this group. Pick one with at least one
              registered server so the agent picks them up on its next sync.
            </p>
            <select
              value={state.groupId}
              onChange={(e) =>
                setState((s) => ({ ...s, groupId: e.target.value, viewId: "" }))
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
          {views.length > 0 && (
            <div>
              <label className="block text-sm font-medium">
                Target view (optional)
              </label>
              <select
                value={state.viewId}
                onChange={(e) =>
                  setState((s) => ({ ...s, viewId: e.target.value }))
                }
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Default view</option>
                {views.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <HeaderButton
          variant="primary"
          icon={previewing ? Loader2 : Download}
          iconClassName={previewing ? "animate-spin" : undefined}
          onClick={onPreview}
          disabled={!canPreview || !!gate.disabled}
          title={gate.title}
        >
          {previewing ? "Parsing…" : "Preview import"}
        </HeaderButton>
      </div>
    </div>
  );
}

/**
 * #1892 — an imported zone carries the source server's apex NS, and the
 * group's agents serve those rows as the zone's whole NS set, so without this
 * the managed zone stays delegated to the host it was migrated off. Off by
 * default: an apex NS outside the group can be deliberate (a hidden primary
 * whose public NS are a provider's), so replacing it is the operator's call.
 */
function ApexNsPolicyChoice({
  zones,
  replace,
  onChange,
}: {
  zones: DNSImportedZone[];
  replace: boolean;
  onChange: (replace: boolean) => void;
}) {
  const affected = zones.filter((z) => (z.foreign_apex_ns ?? []).length > 0);
  if (affected.length === 0) return null;
  return (
    <div className="mb-3 space-y-2 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
      <div className="font-medium text-amber-700 dark:text-amber-400">
        Apex NS outside the target group
      </div>
      <div className="text-amber-700/90 dark:text-amber-300/90">
        These zones name a server that is not in the target group as their NS.
        Kept, the imported zone stays delegated to that host and goes lame once
        it is retired.
      </div>
      <ul className="space-y-0.5">
        {affected.map((z) => (
          <li key={z.name} className="break-all font-mono">
            {z.name} → {(z.foreign_apex_ns ?? []).join(", ")}
          </li>
        ))}
      </ul>
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={replace}
          onChange={(e) => onChange(e.target.checked)}
          className="mt-0.5"
        />
        <span>
          Replace them with the target group&apos;s servers (only servers whose
          host is a DNS name; NS records below the apex are kept). Leave
          unticked if the zone is deliberately served from these hosts.
        </span>
      </label>
    </div>
  );
}

export function PreviewPanel({
  preview,
  decisions,
  setDecisions,
  conflictByZone,
  onCommit,
  committing,
  onReset,
}: {
  preview: DNSImportPreview;
  decisions: Record<string, DNSImportConflictDecision>;
  setDecisions: (
    updater: (
      prev: Record<string, DNSImportConflictDecision>,
    ) => Record<string, DNSImportConflictDecision>,
  ) => void;
  conflictByZone: Map<string, DNSImportZoneConflict>;
  onCommit: (apexNsPolicy: DNSImportApexNsPolicy) => void;
  committing: boolean;
  onReset: () => void;
}) {
  const [replaceApexNs, setReplaceApexNs] = useState(false);
  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            2. Review &amp; commit
          </div>
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span>
              <strong>{preview.zones.length}</strong> zone
              {preview.zones.length === 1 ? "" : "s"}
            </span>
            <span>·</span>
            <span>
              <strong>{preview.total_records}</strong> record
              {preview.total_records === 1 ? "" : "s"}
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
              <div key={i} className="text-amber-700/90 dark:text-amber-300/90">
                {w}
              </div>
            ))}
          </div>
        )}

        <ApexNsPolicyChoice
          zones={preview.zones}
          replace={replaceApexNs}
          onChange={setReplaceApexNs}
        />

        {Object.keys(preview.record_type_histogram).length > 0 && (
          <div className="mb-3 flex flex-wrap gap-2">
            {Object.entries(preview.record_type_histogram)
              .sort((a, b) => b[1] - a[1])
              .map(([type, n]) => (
                <span
                  key={type}
                  className="inline-flex items-center gap-1 rounded-full border bg-background px-2 py-0.5 text-[11px]"
                >
                  <span className="font-mono font-semibold">{type}</span>
                  <span className="text-muted-foreground">×{n}</span>
                </span>
              ))}
          </div>
        )}

        <div className="overflow-x-auto rounded-md border bg-background">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Zone</th>
                <th className="px-3 py-2 text-left">Scope</th>
                <th className="px-3 py-2 text-left">Type</th>
                <th className="px-3 py-2 text-left">Kind</th>
                <th className="px-3 py-2 text-right">Records</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Action on conflict</th>
              </tr>
            </thead>
            <tbody>
              {preview.zones.map((z) => {
                const conflict = conflictByZone.get(
                  z.name.endsWith(".")
                    ? z.name.toLowerCase()
                    : (z.name + ".").toLowerCase(),
                );
                const decision: DNSImportConflictDecision = decisions[
                  z.name
                ] ?? {
                  action: "skip",
                  rename_to: null,
                };
                return (
                  <tr key={z.name} className="border-t">
                    <td className="px-3 py-2 align-top font-mono text-xs">
                      {z.name}
                      {z.view_name && (
                        <div className="mt-0.5 text-[10px] text-muted-foreground">
                          view <span className="font-mono">{z.view_name}</span>
                        </div>
                      )}
                      {/* #3097: the "warnings" pill said a zone had notes
                          and never what they were. */}
                      {z.parse_warnings.length > 0 && (
                        <ul
                          aria-label={`Notes for ${z.name}`}
                          className="mt-1 max-w-md list-disc space-y-0.5 pl-4 font-sans text-[11px] text-amber-700 [overflow-wrap:anywhere] dark:text-amber-400"
                        >
                          {z.parse_warnings.map((w, i) => (
                            <li key={i}>{w}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td className="px-3 py-2 align-top">
                      {/* #986 — a bulk import is where an estate full of
                          .lan zones first becomes visible, and it is the
                          last point before they are committed. */}
                      <ZoneScopePill scope={z.name_scope} />
                    </td>
                    <td className="px-3 py-2 align-top text-xs">
                      {z.zone_type}
                    </td>
                    <td className="px-3 py-2 align-top text-xs">{z.kind}</td>
                    <td className="px-3 py-2 align-top text-right text-xs tabular-nums">
                      {z.records.length}
                    </td>
                    <td className="px-3 py-2 align-top">
                      {conflict ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400">
                          <AlertTriangle className="h-3 w-3" />
                          conflicts ({conflict.existing_record_count} records)
                        </span>
                      ) : z.parse_warnings.length > 0 ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400">
                          <AlertTriangle className="h-3 w-3" />
                          warnings
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" />
                          new
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 align-top">
                      {conflict ? (
                        <div className="flex items-center gap-2">
                          <select
                            value={decision.action}
                            onChange={(e) =>
                              setDecisions((prev) => ({
                                ...prev,
                                [z.name]: {
                                  action: e.target
                                    .value as DNSImportConflictDecision["action"],
                                  rename_to: prev[z.name]?.rename_to ?? null,
                                },
                              }))
                            }
                            className="rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                          >
                            <option value="skip">Skip</option>
                            <option value="overwrite">Overwrite</option>
                            <option value="rename">Rename</option>
                          </select>
                          {decision.action === "rename" && (
                            <input
                              value={decision.rename_to ?? ""}
                              onChange={(e) =>
                                setDecisions((prev) => ({
                                  ...prev,
                                  [z.name]: {
                                    action: "rename",
                                    rename_to: e.target.value,
                                  },
                                }))
                              }
                              placeholder="new-name.example.com."
                              className="w-48 rounded-md border bg-background px-2 py-1 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                            />
                          )}
                        </div>
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
      </div>

      <div className="flex flex-wrap items-center justify-end gap-2">
        <HeaderButton icon={RotateCcw} onClick={onReset} disabled={committing}>
          Start over
        </HeaderButton>
        <HeaderButton
          variant="primary"
          icon={committing ? Loader2 : Database}
          iconClassName={committing ? "animate-spin" : undefined}
          onClick={() => onCommit(replaceApexNs ? "replace" : "keep")}
          disabled={committing}
        >
          {committing ? "Committing…" : "Commit import"}
        </HeaderButton>
      </div>
    </div>
  );
}

function CommitResultPanel({
  result,
  onReset,
}: {
  result: DNSImportCommitResult;
  onReset: () => void;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Import complete
          </div>
          <div className="flex items-center gap-3 text-xs">
            <Stat
              label="Created"
              value={result.total_zones_created}
              tone="success"
            />
            <Stat
              label="Overwrote"
              value={result.total_zones_overwrote}
              tone="amber"
            />
            <Stat
              label="Renamed"
              value={result.total_zones_renamed}
              tone="amber"
            />
            <Stat
              label="Skipped"
              value={result.total_zones_skipped}
              tone="muted"
            />
            <Stat
              label="Failed"
              value={result.total_zones_failed}
              tone="destructive"
            />
            <span className="text-muted-foreground">·</span>
            <Stat
              label="Records"
              value={result.total_records_created}
              tone="success"
            />
          </div>
        </div>

        <div className="overflow-x-auto rounded-md border bg-background">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Zone</th>
                <th className="px-3 py-2 text-left">Action</th>
                <th className="px-3 py-2 text-right">Records created</th>
                <th className="px-3 py-2 text-right">Records deleted</th>
                <th className="px-3 py-2 text-left">Error</th>
              </tr>
            </thead>
            <tbody>
              {result.zones.map((z) => (
                <tr key={z.zone_name} className="border-t">
                  <td className="px-3 py-2 align-top font-mono text-xs">
                    {z.zone_name}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <ActionPill action={z.action_taken} />
                  </td>
                  <td className="px-3 py-2 align-top text-right text-xs tabular-nums">
                    {z.records_created}
                  </td>
                  <td className="px-3 py-2 align-top text-right text-xs tabular-nums">
                    {z.records_deleted}
                  </td>
                  <td className="px-3 py-2 align-top text-xs text-destructive">
                    {z.error ?? ""}
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
              <div key={i} className="text-amber-700/90 dark:text-amber-300/90">
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
    renamed: {
      tone: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
      label: "renamed",
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
