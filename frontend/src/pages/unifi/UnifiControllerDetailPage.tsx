import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Pencil,
  RefreshCw,
  RotateCw,
  Wifi,
  TestTube2,
  AlertTriangle,
} from "lucide-react";

import { formatApiError, unifiApi, type UnifiTestResult } from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { ModalTabs } from "@/components/ui/modal";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";

// Per-controller "what does the gateway see right now" page. Reads
// the single-shot dashboard endpoint that joins subnets + vlans +
// clients in one round-trip — no fanned-out queries on mount, the
// page reflows when the user clicks Refresh or Sync Now.

type Tab = "overview" | "subnets" | "vlans" | "clients" | "discovery";

export function UnifiControllerDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  // #3104 — test and sync take a superadmin (the list page gates both).
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const [tab, setTab] = useState<Tab>("overview");
  const [testResult, setTestResult] = useState<UnifiTestResult | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);

  const { data, isFetching, isError, error } = useQuery({
    queryKey: ["unifi-dashboard", id],
    queryFn: () => unifiApi.getDashboard(id!),
    enabled: !!id,
    refetchInterval: 30_000,
  });

  const syncMut = useMutation({
    mutationFn: () => unifiApi.syncNow(id!),
    onMutate: () => setSyncError(null),
    onError: (e) => setSyncError(formatApiError(e, "Sync failed")),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["unifi-dashboard", id] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["unifi-dashboard", id] }),
        5000,
      );
    },
  });

  const testMut = useMutation({
    mutationFn: () => unifiApi.testConnection({ controller_id: id }),
    onSuccess: (r) => setTestResult(r),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        controller_version: null,
        site_count: null,
      }),
  });

  if (isError) {
    return (
      <div className="p-6">
        <p className="text-sm text-destructive">
          {errMsg(error, "Failed to load controller")}
        </p>
        <Link
          to="/unifi"
          className="mt-3 inline-flex items-center gap-1 text-xs text-primary hover:underline"
        >
          <ArrowLeft className="h-3 w-3" /> Back to UniFi controllers
        </Link>
      </div>
    );
  }

  if (!data) {
    return <div className="p-6 text-sm text-muted-foreground">Loading…</div>;
  }

  const c = data.controller;
  const endpoint =
    c.mode === "cloud"
      ? c.cloud_host_id
        ? `cloud · ${c.cloud_host_id}`
        : "cloud"
      : c.host
        ? `${c.host}:${c.port}`
        : "—";

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Link to="/unifi" className="hover:text-foreground">
                UniFi
              </Link>
              <span>/</span>
              <span className="text-foreground">{c.name}</span>
            </div>
            <div className="mt-1 flex items-center gap-2">
              <Wifi className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">{c.name}</h1>
              <span
                className={
                  c.enabled
                    ? "inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400"
                    : "inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground"
                }
              >
                {c.enabled ? "enabled" : "disabled"}
              </span>
              <span
                className={
                  c.mode === "cloud"
                    ? "inline-flex rounded bg-sky-500/10 px-1.5 py-0.5 text-[11px] text-sky-700 dark:text-sky-400"
                    : "inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px]"
                }
              >
                {c.mode}
              </span>
              {c.controller_version && (
                <span className="font-mono text-[11px] text-muted-foreground">
                  v{c.controller_version}
                </span>
              )}
            </div>
            {c.description && (
              <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
                {c.description}
              </p>
            )}
            <p className="mt-2 text-xs text-muted-foreground">
              <span className="font-mono">{endpoint}</span> · last sync{" "}
              {c.last_synced_at
                ? new Date(c.last_synced_at).toLocaleString()
                : "never"}
            </p>
            {c.last_sync_error && (
              <div className="mt-2 flex items-start gap-1 rounded border border-destructive/30 bg-destructive/5 px-2 py-1 text-xs text-destructive">
                <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                <span className="break-all">{c.last_sync_error}</span>
              </div>
            )}
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["unifi-dashboard", id] })
              }
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              icon={TestTube2}
              onClick={() => testMut.mutate()}
              disabled={testMut.isPending}
              {...superadminGate}
            >
              {testMut.isPending ? "Testing…" : "Test"}
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={RotateCw}
              iconClassName={syncMut.isPending ? "animate-spin" : ""}
              onClick={() => syncMut.mutate()}
              disabled={syncMut.isPending}
              {...superadminGate}
            >
              Sync Now
            </HeaderButton>
            <Link
              to="/unifi"
              className="inline-flex h-7 items-center gap-1 rounded-md border px-2 text-xs hover:bg-accent"
              title="Edit on the UniFi list page"
            >
              <Pencil className="h-3 w-3" /> Edit
            </Link>
          </div>
        </div>
        {testResult && (
          <p
            className={`mt-2 text-xs ${
              testResult.ok
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-destructive"
            }`}
          >
            {testResult.ok ? "✓" : "✗"} {testResult.message}
          </p>
        )}
        {syncError && (
          <p className="mt-2 text-xs text-destructive">✗ {syncError}</p>
        )}
      </div>

      <div className="border-b bg-card px-6 pt-2">
        <ModalTabs<Tab>
          tabs={[
            { key: "overview", label: "Overview" },
            { key: "subnets", label: `Subnets (${data.subnets.length})` },
            { key: "vlans", label: `VLANs (${data.vlans.length})` },
            {
              key: "clients",
              label: `Clients (${data.clients.length}${
                data.client_count_total > data.clients.length
                  ? `/${data.client_count_total}`
                  : ""
              })`,
            },
            { key: "discovery", label: "Discovery" },
          ]}
          active={tab}
          onChange={setTab}
        />
      </div>

      <div className="flex-1 overflow-auto p-6">
        {tab === "overview" && <OverviewTab data={data} />}
        {tab === "subnets" && <SubnetsTab subnets={data.subnets} />}
        {tab === "vlans" && (
          <VlansTab vlans={data.vlans} subnets={data.subnets} />
        )}
        {tab === "clients" && (
          <ClientsTab clients={data.clients} subnets={data.subnets} />
        )}
        {tab === "discovery" && <DiscoveryTab discovery={c.last_discovery} />}
      </div>
    </div>
  );
}

// ── Tab content ────────────────────────────────────────────────────

function OverviewTab({
  data,
}: {
  data: import("@/lib/api").UnifiDashboardResponse;
}) {
  const c = data.controller;
  const cards = [
    { label: "Sites", value: c.site_count ?? "—" },
    { label: "Networks", value: c.network_count ?? "—" },
    { label: "Active clients", value: data.client_count_total },
    { label: "Mirrored subnets", value: data.subnets.length },
    { label: "Mirrored VLANs", value: data.vlans.length },
    { label: "Sync interval", value: `${c.sync_interval_seconds}s` },
  ];
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {cards.map((k) => (
          <div key={k.label} className="rounded-lg border bg-card p-3">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              {k.label}
            </div>
            <div className="mt-1 text-2xl font-semibold">{k.value}</div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border bg-card">
        <div className="border-b px-4 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Mirror policy
        </div>
        <div className="grid grid-cols-2 gap-x-6 gap-y-2 p-4 text-xs sm:grid-cols-3">
          <PolicyRow label="Networks" on={c.mirror_networks} />
          <PolicyRow label="Active clients" on={c.mirror_clients} />
          <PolicyRow label="Fixed-IP reservations" on={c.mirror_fixed_ips} />
          <PolicyRow label="Wired clients" on={c.include_wired} />
          <PolicyRow label="Wireless clients" on={c.include_wireless} />
          <PolicyRow label="VPN clients" on={c.include_vpn} />
        </div>
      </div>

      {c.site_allowlist.length > 0 && (
        <div className="rounded-lg border bg-card">
          <div className="border-b px-4 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Site allowlist
          </div>
          <div className="flex flex-wrap gap-1.5 p-4">
            {c.site_allowlist.map((s) => (
              <span
                key={s}
                className="inline-flex rounded bg-muted px-2 py-0.5 font-mono text-[11px]"
              >
                {s}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PolicyRow({ label, on }: { label: string; on: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span
        className={
          on
            ? "rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400"
            : "rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground"
        }
      >
        {on ? "on" : "off"}
      </span>
    </div>
  );
}

function SubnetsTab({
  subnets,
}: {
  subnets: import("@/lib/api").UnifiDashboardSubnet[];
}) {
  if (subnets.length === 0)
    return <EmptyTab message="No subnets mirrored yet — try Sync Now." />;
  return (
    <div className="overflow-x-auto rounded-lg border bg-card">
      <table className="w-full min-w-[800px] text-xs">
        <thead>
          <tr className="border-b bg-muted/30">
            <Th>Network</Th>
            <Th>Name</Th>
            <Th>VLAN</Th>
            <Th>Gateway</Th>
            <Th>Allocated</Th>
            <Th>Util</Th>
          </tr>
        </thead>
        <tbody>
          {subnets.map((s) => (
            <tr key={s.id} className="border-b last:border-0">
              <td className="px-3 py-2 font-mono">
                <Link
                  to={`/ipam?subnet=${s.id}`}
                  className="text-primary hover:underline"
                >
                  {s.network}
                </Link>
              </td>
              <td className="px-3 py-2 truncate" title={s.description}>
                {s.name || "—"}
              </td>
              <td className="px-3 py-2">{s.vlan_id ?? "—"}</td>
              <td className="px-3 py-2 font-mono text-muted-foreground">
                {s.gateway ?? "—"}
              </td>
              <td className="px-3 py-2 text-muted-foreground">
                {s.allocated_ips}/{s.total_ips}
              </td>
              <td className="px-3 py-2">
                <UtilBar percent={s.utilization_percent} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UtilBar({ percent }: { percent: number }) {
  const tone =
    percent >= 95
      ? "bg-red-500"
      : percent >= 80
        ? "bg-amber-500"
        : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 rounded-full bg-muted">
        <div
          className={`h-1.5 rounded-full ${tone}`}
          style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
        />
      </div>
      <span className="text-[11px] tabular-nums text-muted-foreground">
        {percent.toFixed(0)}%
      </span>
    </div>
  );
}

function VlansTab({
  vlans,
  subnets,
}: {
  vlans: import("@/lib/api").UnifiDashboardVlan[];
  subnets: import("@/lib/api").UnifiDashboardSubnet[];
}) {
  if (vlans.length === 0)
    return (
      <EmptyTab message="No VLANs mirrored — UniFi networks without 802.1Q tags don't surface here." />
    );
  // Build a quick subnet-by-vlan-tag lookup so each VLAN row shows
  // which subnets it's attached to.
  const byTag = new Map<number, typeof subnets>();
  for (const s of subnets) {
    if (s.vlan_id != null) {
      const arr = byTag.get(s.vlan_id) ?? [];
      arr.push(s);
      byTag.set(s.vlan_id, arr);
    }
  }
  return (
    <div className="overflow-x-auto rounded-lg border bg-card">
      <table className="w-full min-w-[700px] text-xs">
        <thead>
          <tr className="border-b bg-muted/30">
            <Th>Tag</Th>
            <Th>Name</Th>
            <Th>Description</Th>
            <Th>Attached subnets</Th>
          </tr>
        </thead>
        <tbody>
          {vlans.map((v) => {
            const attached = byTag.get(v.vlan_id) ?? [];
            return (
              <tr key={v.id} className="border-b last:border-0">
                <td className="px-3 py-2 font-mono">{v.vlan_id}</td>
                <td className="px-3 py-2">{v.name}</td>
                <td
                  className="px-3 py-2 text-muted-foreground"
                  title={v.description}
                >
                  {v.description || "—"}
                </td>
                <td className="px-3 py-2">
                  {attached.length === 0 ? (
                    <span className="text-muted-foreground/60">—</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {attached.map((s) => (
                        <Link
                          key={s.id}
                          to={`/ipam?subnet=${s.id}`}
                          className="inline-flex rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] hover:bg-accent"
                        >
                          {s.network}
                        </Link>
                      ))}
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ClientsTab({
  clients,
  subnets,
}: {
  clients: import("@/lib/api").UnifiDashboardClient[];
  subnets: import("@/lib/api").UnifiDashboardSubnet[];
}) {
  const subnetById = new Map(subnets.map((s) => [s.id, s]));
  if (clients.length === 0)
    return (
      <EmptyTab message="No clients mirrored. Mirror clients toggle may be off, or the controller has no live clients." />
    );
  return (
    <div className="overflow-x-auto rounded-lg border bg-card">
      <table className="w-full min-w-[900px] text-xs">
        <thead>
          <tr className="border-b bg-muted/30">
            <Th>IP</Th>
            <Th>Hostname</Th>
            <Th>MAC</Th>
            <Th>Status</Th>
            <Th>Subnet</Th>
            <Th>Description</Th>
          </tr>
        </thead>
        <tbody>
          {clients.map((c) => {
            const subnet = c.subnet_id ? subnetById.get(c.subnet_id) : null;
            return (
              <tr key={c.id} className="border-b last:border-0">
                <td className="px-3 py-2 font-mono">{c.address}</td>
                <td className="px-3 py-2 truncate">{c.hostname || "—"}</td>
                <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                  {c.mac_address || "—"}
                </td>
                <td className="px-3 py-2">
                  <StatusPill status={c.status} />
                </td>
                <td className="px-3 py-2 font-mono text-[11px]">
                  {subnet ? subnet.network : "—"}
                </td>
                <td
                  className="px-3 py-2 truncate text-muted-foreground"
                  title={c.description}
                >
                  {c.description || "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const tone =
    status === "reserved"
      ? "bg-violet-500/10 text-violet-700 dark:text-violet-400"
      : status === "unifi-client"
        ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
        : "bg-muted text-muted-foreground";
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-[11px] ${tone}`}>
      {status}
    </span>
  );
}

function DiscoveryTab({ discovery }: { discovery: unknown }) {
  if (!discovery) {
    return (
      <EmptyTab message="No discovery data yet — runs after the first successful sync." />
    );
  }
  return (
    <pre className="overflow-x-auto rounded-lg border bg-muted/20 p-4 text-[11px] leading-tight">
      {JSON.stringify(discovery, null, 2)}
    </pre>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
      {children}
    </th>
  );
}

function EmptyTab({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-dashed bg-card p-10 text-center">
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );
}

function errMsg(e: unknown, fallback: string): string {
  return formatApiError(e, fallback);
}
