import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Loader2,
  Pencil,
  PlayCircle,
  RefreshCw,
  TestTube2,
  Trash2,
  XCircle,
} from "lucide-react";

import {
  LLDP_CHASSIS_ID_SUBTYPES,
  LLDP_PORT_ID_SUBTYPES,
  networkApi,
  type NetworkArpQuery,
  type NetworkFdbQuery,
  type NetworkNeighbourQuery,
  type NetworkTestConnectionResult,
} from "@/lib/api";
import { formatApiError } from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { Modal } from "@/components/ui/modal";
import { AskAIButton } from "@/components/copilot/AskAIButton";

import {
  ArpStatePill,
  DeviceTypePill,
  FdbTypePill,
  InterfaceStatusPill,
  PollStatusPill,
  SnmpVersionPill,
  errMsg,
  humanDuration,
  humanSpeed,
  humanTime,
  inputCls,
} from "./_shared";
import { DeviceFormModal } from "./DeviceFormModal";

type Tab = "overview" | "interfaces" | "arp" | "fdb" | "neighbours";

// ── Detail page ──────────────────────────────────────────────────────

export function DeviceDetailView() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [tab, setTab] = useState<Tab>("overview");
  const [showEdit, setShowEdit] = useState(false);
  const [showDelete, setShowDelete] = useState(false);
  const [testResult, setTestResult] =
    useState<NetworkTestConnectionResult | null>(null);

  const {
    data: device,
    isFetching,
    isError,
  } = useQuery({
    queryKey: ["network-device", id],
    queryFn: () => networkApi.getDevice(id),
    enabled: !!id,
  });

  // #2518 — the router asks write (delete) on 'manage_network_devices', as
  // the device list does since #1851.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_network_devices"),
    "Requires write permission on network devices",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "manage_network_devices"),
    "Requires delete permission on network devices",
  );

  const testMut = useMutation({
    mutationFn: () => networkApi.testConnection(id),
    onSuccess: (result) => {
      setTestResult(result);
      qc.invalidateQueries({ queryKey: ["network-device", id] });
    },
    onError: (e) =>
      setTestResult({
        success: false,
        sys_descr: null,
        sys_object_id: null,
        sys_name: null,
        vendor: null,
        error_kind: "internal",
        error_message: errMsg(e, "Test failed"),
        elapsed_ms: 0,
      }),
  });

  const pollMut = useMutation({
    mutationFn: () => networkApi.pollNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["network-device", id] });
      // Re-fetch a moment later — beat workers usually finish a single
      // poll within a few seconds.
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["network-device", id] }),
        3000,
      );
    },
  });

  if (isError) {
    return (
      <div className="p-6">
        <p className="text-sm text-destructive">Device not found.</p>
        <Link
          to="/network/devices"
          className="mt-2 inline-flex items-center gap-1 text-sm text-primary hover:underline"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Network
        </Link>
      </div>
    );
  }

  if (!device) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Header */}
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <Link
              to="/network/devices"
              className="mb-1 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3 w-3" /> All devices
            </Link>
            <div className="flex items-center gap-2">
              <h1 className="truncate text-lg font-semibold">{device.name}</h1>
              <DeviceTypePill type={device.device_type} />
              <SnmpVersionPill version={device.snmp_version} />
              <PollStatusPill status={device.last_poll_status} />
              {!device.is_active && (
                <span className="inline-flex items-center rounded-full bg-zinc-100 px-1.5 py-0.5 text-[10px] text-zinc-600 dark:bg-zinc-500/15 dark:text-zinc-300">
                  inactive
                </span>
              )}
            </div>
            <div className="mt-1 text-xs text-muted-foreground">
              <span className="font-mono">{device.hostname}</span>{" "}
              <span className="text-muted-foreground/60">·</span>{" "}
              <span className="font-mono">{device.ip_address}</span>
              {device.vendor && (
                <>
                  {" · "}
                  {device.vendor}
                </>
              )}
              {device.sys_name && (
                <>
                  {" · "}
                  <span className="font-mono">{device.sys_name}</span>
                </>
              )}
              {" · "}
              <span title={device.last_poll_at ?? ""}>
                last poll {humanTime(device.last_poll_at)}
              </span>
              {device.sys_uptime_seconds != null && (
                <>
                  {" · "}
                  uptime {humanDuration(device.sys_uptime_seconds)}
                </>
              )}
            </div>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <AskAIButton
              context={[
                `Network device ${device.name}`,
                `type: ${device.device_type}`,
                `hostname: ${device.hostname}`,
                `IP: ${device.ip_address}`,
                device.vendor ? `vendor: ${device.vendor}` : null,
                device.sys_name ? `sys_name: ${device.sys_name}` : null,
                `SNMP: ${device.snmp_version}`,
                `last poll status: ${device.last_poll_status ?? "unknown"}`,
                device.last_poll_at
                  ? `last poll at: ${device.last_poll_at}`
                  : null,
                device.is_active ? "active" : "inactive",
                `device_id: ${device.id}`,
              ]
                .filter(Boolean)
                .join(", ")}
              tooltip="Ask AI about this device"
              prompt="Summarise this device — connected interfaces, MAC/ARP coverage, recent polls, and anything I should follow up on."
            />
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() => {
                qc.invalidateQueries({ queryKey: ["network-device", id] });
                qc.invalidateQueries({
                  queryKey: ["network-interfaces", id],
                });
                qc.invalidateQueries({ queryKey: ["network-arp", id] });
                qc.invalidateQueries({ queryKey: ["network-fdb", id] });
                qc.invalidateQueries({ queryKey: ["network-neighbours", id] });
              }}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              icon={TestTube2}
              onClick={() => testMut.mutate()}
              disabled={testMut.isPending}
              {...writeGate}
            >
              Test Connection
            </HeaderButton>
            <HeaderButton
              icon={PlayCircle}
              onClick={() => pollMut.mutate()}
              disabled={pollMut.isPending}
              {...writeGate}
            >
              Poll Now
            </HeaderButton>
            <HeaderButton
              icon={Pencil}
              onClick={() => setShowEdit(true)}
              {...writeGate}
            >
              Edit
            </HeaderButton>
            <HeaderButton
              variant="destructive"
              icon={Trash2}
              onClick={() => setShowDelete(true)}
              {...deleteGate}
            >
              Delete
            </HeaderButton>
          </div>
        </div>
        {testResult && (
          <div className="mt-3">
            <TestResultBanner result={testResult} />
          </div>
        )}
        {pollMut.isError && (
          <p role="alert" className="mt-3 text-xs text-destructive">
            Poll Now was refused:{" "}
            {formatApiError(pollMut.error, "the request failed")}
          </p>
        )}
        {pollMut.isSuccess && pollMut.data && (
          <div className="mt-3 inline-flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-1.5 text-xs text-emerald-700 dark:text-emerald-300">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Poll queued at{" "}
            {new Date(pollMut.data.queued_at).toLocaleTimeString()} (task{" "}
            <span className="font-mono">{pollMut.data.task_id}</span>)
          </div>
        )}

        {/* Tabs */}
        <div className="mt-4 -mb-px flex gap-1 border-b">
          {(
            [
              ["overview", "Overview"],
              ["interfaces", "Interfaces"],
              ["arp", "ARP"],
              ["fdb", "FDB"],
              ["neighbours", "Neighbours"],
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

      {/* Tab content */}
      <div className="flex-1 overflow-auto p-6">
        {tab === "overview" && (
          <OverviewTab deviceId={device.id} device={device} />
        )}
        {tab === "interfaces" && <InterfacesTab deviceId={device.id} />}
        {tab === "arp" && <ArpTab deviceId={device.id} />}
        {tab === "fdb" && <FdbTab deviceId={device.id} />}
        {tab === "neighbours" && (
          <NeighboursTab deviceId={device.id} vendor={device.vendor} />
        )}
      </div>

      {/* Modals */}
      {showEdit && (
        <DeviceFormModal device={device} onClose={() => setShowEdit(false)} />
      )}
      {showDelete && (
        <DeleteDeviceModal
          deviceId={device.id}
          deviceName={device.name}
          onClose={() => setShowDelete(false)}
          onDeleted={() => {
            setShowDelete(false);
            navigate("/network/devices");
          }}
        />
      )}
    </div>
  );
}

// ── Overview tab ─────────────────────────────────────────────────────

function OverviewTab({
  device,
}: {
  deviceId: string;
  device: ReturnType<typeof networkApi.getDevice> extends Promise<infer T>
    ? T
    : never;
}) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="System info">
        <Detail label="sysDescr" value={device.sys_descr} mono breakAll />
        <Detail label="sysObjectID" value={device.sys_object_id} mono />
        <Detail label="sysName" value={device.sys_name} mono />
        <Detail
          label="sysUpTime"
          value={
            device.sys_uptime_seconds != null
              ? humanDuration(device.sys_uptime_seconds)
              : null
          }
        />
        <Detail label="IP space" value={device.ip_space_name} />
        <Detail label="Description" value={device.description} />
      </Card>
      <Card title="Polling configuration">
        <Detail label="Interval" value={`${device.poll_interval_seconds}s`} />
        <Detail
          label="Enabled tables"
          value={
            [
              device.poll_interfaces ? "Interfaces" : null,
              device.poll_arp ? "ARP" : null,
              device.poll_fdb ? "FDB" : null,
            ]
              .filter(Boolean)
              .join(", ") || "—"
          }
        />
        <Detail
          label="Auto-create discovered IPs"
          value={device.auto_create_discovered ? "On" : "Off"}
        />
        <Detail
          label="Last poll"
          value={
            device.last_poll_at
              ? `${humanTime(device.last_poll_at)} (${device.last_poll_status})`
              : "Never"
          }
        />
        <Detail
          label="Next poll"
          value={device.next_poll_at ? humanTime(device.next_poll_at) : "—"}
        />
        <Detail
          label="Counts (last poll)"
          value={`${device.last_poll_arp_count ?? 0} ARP · ${
            device.last_poll_interface_count ?? 0
          } interfaces · ${device.last_poll_fdb_count ?? 0} FDB`}
        />
      </Card>
      {device.last_poll_error && (
        <div className="lg:col-span-2 rounded-md border border-destructive/40 bg-destructive/10 p-4 text-xs text-destructive">
          <div className="mb-1 inline-flex items-center gap-1.5 font-semibold">
            <AlertTriangle className="h-3.5 w-3.5" /> Last poll error
          </div>
          <pre className="whitespace-pre-wrap break-all font-mono text-[11px]">
            {device.last_poll_error}
          </pre>
        </div>
      )}
    </div>
  );
}

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
      <div className="p-4 space-y-2 text-xs">{children}</div>
    </div>
  );
}

function Detail({
  label,
  value,
  mono,
  breakAll,
}: {
  label: string;
  value: string | number | null | undefined;
  mono?: boolean;
  breakAll?: boolean;
}) {
  return (
    <div className="grid grid-cols-3 gap-2">
      <span className="col-span-1 text-muted-foreground">{label}</span>
      <span
        className={`col-span-2 ${mono ? "font-mono text-[11px]" : ""} ${
          breakAll ? "break-all" : ""
        }`}
      >
        {value == null || value === "" ? "—" : value}
      </span>
    </div>
  );
}

// ── Interfaces tab ───────────────────────────────────────────────────

function InterfacesTab({ deviceId }: { deviceId: string }) {
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const { data, isFetching } = useQuery({
    queryKey: ["network-interfaces", deviceId, page],
    queryFn: () =>
      networkApi.listInterfaces(deviceId, { page, page_size: pageSize }),
  });
  const items = data?.items ?? [];
  const sorted = useMemo(
    () => [...items].sort((a, b) => a.if_index - b.if_index),
    [items],
  );

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        From IF-MIB <span className="font-mono">ifTable</span> +{" "}
        <span className="font-mono">ifXTable</span>. {data?.total ?? 0} total.
        {isFetching && <Loader2 className="ml-1 inline h-3 w-3 animate-spin" />}
      </p>
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full min-w-[900px] text-xs">
          <thead>
            <tr className="border-b bg-muted/30">
              <th className="px-3 py-2 text-left font-medium">ifIndex</th>
              <th className="px-3 py-2 text-left font-medium">Name</th>
              <th className="px-3 py-2 text-left font-medium">Alias</th>
              <th className="px-3 py-2 text-left font-medium">Speed</th>
              <th className="px-3 py-2 text-left font-medium">MAC</th>
              <th className="px-3 py-2 text-left font-medium">Admin</th>
              <th className="px-3 py-2 text-left font-medium">Oper</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  No interfaces yet — wait for the first poll.
                </td>
              </tr>
            ) : (
              sorted.map((i) => (
                <tr key={i.id} className="border-b last:border-0">
                  <td className="whitespace-nowrap px-3 py-1.5 tabular-nums">
                    {i.if_index}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[11px]">
                    {i.name}
                  </td>
                  <td className="px-3 py-1.5">{i.alias ?? ""}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 text-muted-foreground">
                    {humanSpeed(i.speed_bps)}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[11px]">
                    {i.mac_address ?? ""}
                  </td>
                  <td className="px-3 py-1.5">
                    <InterfaceStatusPill status={i.admin_status} />
                  </td>
                  <td className="px-3 py-1.5">
                    <InterfaceStatusPill status={i.oper_status} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <Pager
        page={page}
        total={data?.total ?? 0}
        pageSize={pageSize}
        onChange={setPage}
      />
    </div>
  );
}

// ── ARP tab ──────────────────────────────────────────────────────────

function ArpTab({ deviceId }: { deviceId: string }) {
  const [page, setPage] = useState(1);
  const [ipFilter, setIpFilter] = useState("");
  const [macFilter, setMacFilter] = useState("");
  const [vrfFilter, setVrfFilter] = useState("");
  const [stateFilter, setStateFilter] = useState<NetworkArpQuery["state"] | "">(
    "",
  );
  const pageSize = 50;

  const params = useMemo<NetworkArpQuery>(() => {
    const p: NetworkArpQuery = { page, page_size: pageSize };
    if (ipFilter.trim()) p.ip = ipFilter.trim();
    if (macFilter.trim()) p.mac = macFilter.trim();
    if (vrfFilter.trim()) p.vrf = vrfFilter.trim();
    if (stateFilter) p.state = stateFilter;
    return p;
  }, [page, ipFilter, macFilter, vrfFilter, stateFilter]);

  const { data, isFetching } = useQuery({
    queryKey: ["network-arp", deviceId, params],
    queryFn: () => networkApi.listArp(deviceId, params),
  });
  const items = data?.items ?? [];

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        From IP-MIB <span className="font-mono">ipNetToPhysicalTable</span>.{" "}
        {data?.total ?? 0} total.
        {isFetching && <Loader2 className="ml-1 inline h-3 w-3 animate-spin" />}
      </p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <input
          className={inputCls}
          placeholder="IP filter"
          value={ipFilter}
          onChange={(e) => {
            setIpFilter(e.target.value);
            setPage(1);
          }}
        />
        <input
          className={inputCls}
          placeholder="MAC filter"
          value={macFilter}
          onChange={(e) => {
            setMacFilter(e.target.value);
            setPage(1);
          }}
        />
        <input
          className={inputCls}
          placeholder="VRF filter"
          value={vrfFilter}
          onChange={(e) => {
            setVrfFilter(e.target.value);
            setPage(1);
          }}
        />
        <select
          className={inputCls}
          value={stateFilter}
          onChange={(e) => {
            setStateFilter(e.target.value as NetworkArpQuery["state"] | "");
            setPage(1);
          }}
        >
          <option value="">— all states —</option>
          {(
            [
              "reachable",
              "stale",
              "delay",
              "probe",
              "invalid",
              "unknown",
            ] as const
          ).map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full min-w-[900px] text-xs">
          <thead>
            <tr className="border-b bg-muted/30">
              <th className="px-3 py-2 text-left font-medium">IP</th>
              <th className="px-3 py-2 text-left font-medium">MAC</th>
              <th className="px-3 py-2 text-left font-medium">Interface</th>
              <th className="px-3 py-2 text-left font-medium">VRF</th>
              <th className="px-3 py-2 text-left font-medium">State</th>
              <th className="px-3 py-2 text-left font-medium">First seen</th>
              <th className="px-3 py-2 text-left font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  No ARP entries.
                </td>
              </tr>
            ) : (
              items.map((a) => (
                <tr key={a.id} className="border-b last:border-0">
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[11px]">
                    {a.ip_address}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[11px]">
                    {a.mac_address}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5">
                    {a.interface_name ?? (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5">
                    {a.vrf_name ?? (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5">
                    <ArpStatePill state={a.state} />
                  </td>
                  <td
                    className="whitespace-nowrap px-3 py-1.5 text-muted-foreground"
                    title={a.first_seen}
                  >
                    {humanTime(a.first_seen)}
                  </td>
                  <td
                    className="whitespace-nowrap px-3 py-1.5 text-muted-foreground"
                    title={a.last_seen}
                  >
                    {humanTime(a.last_seen)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <Pager
        page={page}
        total={data?.total ?? 0}
        pageSize={pageSize}
        onChange={setPage}
      />
    </div>
  );
}

// ── FDB tab ──────────────────────────────────────────────────────────

function FdbTab({ deviceId }: { deviceId: string }) {
  const [page, setPage] = useState(1);
  const [macFilter, setMacFilter] = useState("");
  const [vlanFilter, setVlanFilter] = useState<string>("");
  const [ifaceFilter, setIfaceFilter] = useState<string>("");
  const pageSize = 50;

  const params = useMemo<NetworkFdbQuery>(() => {
    const p: NetworkFdbQuery = { page, page_size: pageSize };
    if (macFilter.trim()) p.mac = macFilter.trim();
    if (vlanFilter.trim()) {
      const n = parseInt(vlanFilter, 10);
      if (!Number.isNaN(n)) p.vlan_id = n;
    }
    if (ifaceFilter.trim()) p.interface_id = ifaceFilter.trim();
    return p;
  }, [page, macFilter, vlanFilter, ifaceFilter]);

  const { data, isFetching } = useQuery({
    queryKey: ["network-fdb", deviceId, params],
    queryFn: () => networkApi.listFdb(deviceId, params),
  });
  const items = data?.items ?? [];

  // Default sort: by interface name then VLAN. The same port can carry
  // multiple MACs across multiple VLANs (hypervisors and IP phones with
  // PC passthrough are the obvious cases) — group those visually.
  const sorted = useMemo(
    () =>
      [...items].sort((a, b) => {
        // interface_name is server-joined and may be null when the
        // interface row hasn't been polled yet. Fall back to the UUID
        // so sort is total and deterministic, never undefined.
        const an = a.interface_name ?? a.interface_id ?? "";
        const bn = b.interface_name ?? b.interface_id ?? "";
        const cmp = an.localeCompare(bn);
        if (cmp !== 0) return cmp;
        return (a.vlan_id ?? -1) - (b.vlan_id ?? -1);
      }),
    [items],
  );

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-800 dark:text-amber-300">
        <strong>
          A single port can carry multiple MACs across multiple VLANs.
        </strong>{" "}
        Hypervisors expose the host MAC plus one per VM; IP phones with PC
        passthrough show the phone on the voice VLAN and the desktop on the data
        VLAN. Every (MAC, VLAN) pair is its own row — they are not collapsed.
      </div>
      <p className="text-xs text-muted-foreground">
        From BRIDGE-MIB <span className="font-mono">dot1dTpFdbTable</span> +
        Q-BRIDGE-MIB <span className="font-mono">dot1qTpFdbTable</span>.{" "}
        {data?.total ?? 0} total.
        {isFetching && <Loader2 className="ml-1 inline h-3 w-3 animate-spin" />}
      </p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <input
          className={inputCls}
          placeholder="MAC filter"
          value={macFilter}
          onChange={(e) => {
            setMacFilter(e.target.value);
            setPage(1);
          }}
        />
        <input
          className={inputCls}
          placeholder="VLAN id"
          value={vlanFilter}
          inputMode="numeric"
          onChange={(e) => {
            setVlanFilter(e.target.value);
            setPage(1);
          }}
        />
        <input
          className={inputCls}
          placeholder="Interface id"
          value={ifaceFilter}
          onChange={(e) => {
            setIfaceFilter(e.target.value);
            setPage(1);
          }}
        />
      </div>
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full min-w-[900px] text-xs">
          <thead>
            <tr className="border-b bg-muted/30">
              <th className="px-3 py-2 text-left font-medium">MAC</th>
              <th className="px-3 py-2 text-left font-medium">VLAN</th>
              <th className="px-3 py-2 text-left font-medium">Interface</th>
              <th className="px-3 py-2 text-left font-medium">Type</th>
              <th className="px-3 py-2 text-left font-medium">First seen</th>
              <th className="px-3 py-2 text-left font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  No FDB entries.
                </td>
              </tr>
            ) : (
              sorted.map((f) => (
                <tr key={f.id} className="border-b last:border-0">
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[11px]">
                    {f.mac_address}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 tabular-nums">
                    {f.vlan_id ?? (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5">
                    {f.interface_name}
                  </td>
                  <td className="px-3 py-1.5">
                    <FdbTypePill type={f.fdb_type} />
                  </td>
                  <td
                    className="whitespace-nowrap px-3 py-1.5 text-muted-foreground"
                    title={f.first_seen}
                  >
                    {humanTime(f.first_seen)}
                  </td>
                  <td
                    className="whitespace-nowrap px-3 py-1.5 text-muted-foreground"
                    title={f.last_seen}
                  >
                    {humanTime(f.last_seen)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <Pager
        page={page}
        total={data?.total ?? 0}
        pageSize={pageSize}
        onChange={setPage}
      />
    </div>
  );
}

// ── Neighbours tab (LLDP) ────────────────────────────────────────────

// Vendor-specific commands shown in the empty-state banner so an
// operator who sees zero neighbours can flip LLDP on without leaving
// the page. Best-effort by sysDescr substring; falls through to the
// generic hint when nothing matches.
const _LLDP_ENABLE_HINTS: { match: string; cmd: string }[] = [
  { match: "Cisco IOS", cmd: "(config)# lldp run" },
  { match: "NX-OS", cmd: "(config)# feature lldp" },
  { match: "Junos", cmd: "set protocols lldp interface all" },
  { match: "Arista", cmd: "(config)# lldp run" },
  { match: "ProCurve", cmd: "(config)# lldp run" },
  { match: "Aruba", cmd: "(config)# lldp run" },
  {
    match: "MikroTik",
    cmd: "/ip neighbor discovery-settings set discover-interface-list=all protocol=lldp",
  },
  {
    match: "RouterOS",
    cmd: "/ip neighbor discovery-settings set discover-interface-list=all protocol=lldp",
  },
  {
    match: "OPNsense",
    cmd: "Install os-lldpd, then enable in System → Settings → LLDP",
  },
  {
    match: "pfSense",
    cmd: "Install pfSense-pkg-LLDP, then enable in Services → LLDP",
  },
];

function _enableHint(vendorOrDescr: string | null | undefined): string | null {
  if (!vendorOrDescr) return null;
  for (const { match, cmd } of _LLDP_ENABLE_HINTS) {
    if (vendorOrDescr.toLowerCase().includes(match.toLowerCase())) return cmd;
  }
  return null;
}

// Decode LldpSystemCapabilitiesMap bitmask into compact labels.
const _CAP_LABELS: { bit: number; label: string }[] = [
  { bit: 1, label: "other" },
  { bit: 2, label: "repeater" },
  { bit: 4, label: "bridge" },
  { bit: 8, label: "wlanAP" },
  { bit: 16, label: "router" },
  { bit: 32, label: "phone" },
  { bit: 64, label: "docsis" },
  { bit: 128, label: "stationOnly" },
  { bit: 256, label: "cVLAN" },
  { bit: 512, label: "sVLAN" },
  { bit: 1024, label: "twoPortMACRelay" },
];

function _decodeCaps(mask: number | null | undefined): string {
  if (mask == null) return "";
  return _CAP_LABELS
    .filter((c) => (mask & c.bit) !== 0)
    .map((c) => c.label)
    .join(", ");
}

function NeighboursTab({
  deviceId,
  vendor,
}: {
  deviceId: string;
  vendor: string | null;
}) {
  const [page, setPage] = useState(1);
  const [sysNameFilter, setSysNameFilter] = useState("");
  const [chassisFilter, setChassisFilter] = useState("");
  const pageSize = 50;

  const params = useMemo<NetworkNeighbourQuery>(() => {
    const p: NetworkNeighbourQuery = { page, page_size: pageSize };
    if (sysNameFilter.trim()) p.sys_name = sysNameFilter.trim();
    if (chassisFilter.trim()) p.chassis_id = chassisFilter.trim();
    return p;
  }, [page, sysNameFilter, chassisFilter]);

  const { data, isFetching } = useQuery({
    queryKey: ["network-neighbours", deviceId, params],
    queryFn: () => networkApi.listNeighbours(deviceId, params),
  });
  const items = data?.items ?? [];
  const enableCmd = _enableHint(vendor);

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        From LLDP-MIB <span className="font-mono">lldpRemTable</span>{" "}
        (IEEE&nbsp;802.1AB). {data?.total ?? 0} neighbour
        {(data?.total ?? 0) === 1 ? "" : "s"}.
        {isFetching && <Loader2 className="ml-1 inline h-3 w-3 animate-spin" />}
      </p>
      {items.length === 0 && !isFetching && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-800 dark:text-amber-300">
          <strong>No neighbours seen.</strong> LLDP is often disabled by default
          or only on uplink ports. Check that LLDP is enabled on the device and
          that the polling user can read the LLDP-MIB.
          {enableCmd && (
            <>
              {" "}
              For this vendor:{" "}
              <code className="rounded bg-amber-500/10 px-1 py-0.5 font-mono">
                {enableCmd}
              </code>
              .
            </>
          )}
        </div>
      )}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <input
          className={inputCls}
          placeholder="Filter by remote sys name"
          value={sysNameFilter}
          onChange={(e) => {
            setSysNameFilter(e.target.value);
            setPage(1);
          }}
        />
        <input
          className={inputCls}
          placeholder="Filter by remote chassis id"
          value={chassisFilter}
          onChange={(e) => {
            setChassisFilter(e.target.value);
            setPage(1);
          }}
        />
      </div>
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full min-w-[1100px] text-xs">
          <thead>
            <tr className="border-b bg-muted/30">
              <th className="px-3 py-2 text-left font-medium">Local port</th>
              <th className="px-3 py-2 text-left font-medium">Remote system</th>
              <th className="px-3 py-2 text-left font-medium">Chassis ID</th>
              <th className="px-3 py-2 text-left font-medium">Port ID</th>
              <th className="px-3 py-2 text-left font-medium">Capabilities</th>
              <th className="px-3 py-2 text-left font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  {isFetching ? "Loading…" : "No neighbours."}
                </td>
              </tr>
            ) : (
              items.map((n) => (
                <tr key={n.id} className="border-b last:border-0">
                  <td className="whitespace-nowrap px-3 py-1.5">
                    {n.interface_name ?? (
                      <span className="font-mono text-muted-foreground">
                        port#{n.local_port_num}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="font-medium">
                      {n.remote_sys_name ?? (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </div>
                    {n.remote_sys_desc && (
                      <div
                        className="text-[10px] text-muted-foreground line-clamp-2"
                        title={n.remote_sys_desc}
                      >
                        {n.remote_sys_desc}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[11px]">
                    <div>{n.remote_chassis_id}</div>
                    <div className="text-[10px] text-muted-foreground">
                      {LLDP_CHASSIS_ID_SUBTYPES[n.remote_chassis_id_subtype] ??
                        `subtype ${n.remote_chassis_id_subtype}`}
                    </div>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[11px]">
                    <div>{n.remote_port_id}</div>
                    {n.remote_port_desc && (
                      <div className="text-[10px] text-muted-foreground">
                        {n.remote_port_desc}
                      </div>
                    )}
                    <div className="text-[10px] text-muted-foreground">
                      {LLDP_PORT_ID_SUBTYPES[n.remote_port_id_subtype] ??
                        `subtype ${n.remote_port_id_subtype}`}
                    </div>
                  </td>
                  <td className="px-3 py-1.5 text-[11px] text-muted-foreground">
                    {_decodeCaps(n.remote_sys_cap_enabled) || "—"}
                  </td>
                  <td
                    className="whitespace-nowrap px-3 py-1.5 text-muted-foreground"
                    title={n.last_seen}
                  >
                    {humanTime(n.last_seen)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <Pager
        page={page}
        total={data?.total ?? 0}
        pageSize={pageSize}
        onChange={setPage}
      />
    </div>
  );
}

// ── Pager ────────────────────────────────────────────────────────────

function Pager({
  page,
  total,
  pageSize,
  onChange,
}: {
  page: number;
  total: number;
  pageSize: number;
  onChange: (p: number) => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-end gap-2 text-xs">
      <button
        type="button"
        onClick={() => onChange(Math.max(1, page - 1))}
        disabled={page <= 1}
        className="rounded-md border px-2 py-1 disabled:opacity-40 hover:bg-muted"
      >
        Prev
      </button>
      <span className="text-muted-foreground">
        Page {page} of {totalPages}
      </span>
      <button
        type="button"
        onClick={() => onChange(Math.min(totalPages, page + 1))}
        disabled={page >= totalPages}
        className="rounded-md border px-2 py-1 disabled:opacity-40 hover:bg-muted"
      >
        Next
      </button>
    </div>
  );
}

// ── Test-result banner (shared with the form modal in spirit) ───────

function TestResultBanner({ result }: { result: NetworkTestConnectionResult }) {
  if (result.success) {
    return (
      <div className="flex items-start gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
        <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0" />
        <div className="space-y-0.5">
          <div className="font-medium">Reachable in {result.elapsed_ms} ms</div>
          {result.sys_name && (
            <div>
              <span className="text-muted-foreground">sysName:</span>{" "}
              <span className="font-mono">{result.sys_name}</span>
            </div>
          )}
          {result.sys_descr && (
            <div className="break-all">
              <span className="text-muted-foreground">sysDescr:</span>{" "}
              {result.sys_descr}
            </div>
          )}
          {result.vendor && (
            <div>
              <span className="text-muted-foreground">vendor:</span>{" "}
              {result.vendor}
            </div>
          )}
        </div>
      </div>
    );
  }
  return (
    <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
      <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
      <div className="space-y-0.5">
        <div className="font-medium">
          Test failed{result.error_kind ? ` (${result.error_kind})` : ""} after{" "}
          {result.elapsed_ms} ms
        </div>
        {result.error_message && <div>{result.error_message}</div>}
      </div>
    </div>
  );
}

// ── Delete modal ────────────────────────────────────────────────────

function DeleteDeviceModal({
  deviceId,
  deviceName,
  onClose,
  onDeleted,
}: {
  deviceId: string;
  deviceName: string;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: () => networkApi.deleteDevice(deviceId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["network-devices"] });
      onDeleted();
    },
    onError: (e) => setError(errMsg(e, "Failed to delete device")),
  });
  return (
    <Modal title={`Delete ${deviceName}?`} onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p>
          This permanently removes the device along with its discovered
          interfaces, ARP, and FDB entries.
        </p>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => mut.mutate()}
            disabled={mut.isPending}
            className="inline-flex items-center gap-1 rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            <Trash2 className="h-3.5 w-3.5" />
            {mut.isPending ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </Modal>
  );
}
