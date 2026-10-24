import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  Download,
  Network as NetworkIcon,
  Pencil,
  Play,
  Plus,
  Power,
  RefreshCw,
  TestTube2,
  Trash2,
  Upload,
} from "lucide-react";

import {
  networkApi,
  type NetworkDeviceListQuery,
  type NetworkDeviceRead,
  type NetworkDeviceType,
  type NetworkPollStatus,
} from "@/lib/api";
import { formatApiError } from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { TagFilterChips } from "@/components/TagFilterChips";

import {
  DEVICE_TYPE_OPTIONS,
  DeviceTypePill,
  PollStatusPill,
  SnmpVersionPill,
  errMsg,
  humanTime,
} from "./_shared";
import { DeviceFormModal } from "./DeviceFormModal";
import {
  NetworkImportModal,
  exportDevicesCsv,
} from "./NetworkImportExportModal";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

// ── Filter chip helper ────────────────────────────────────────────────

function FilterChips<T extends string>({
  label,
  value,
  options,
  onChange,
  formatter,
}: {
  label: string;
  value: T | "all";
  options: T[];
  onChange: (v: T | "all") => void;
  formatter?: (v: T) => string;
}) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <button
        type="button"
        onClick={() => onChange("all")}
        className={`rounded-full px-2 py-0.5 text-[11px] ${
          value === "all"
            ? "bg-primary text-primary-foreground"
            : "border hover:bg-muted"
        }`}
      >
        All
      </button>
      {options.map((opt) => (
        <button
          key={opt}
          type="button"
          onClick={() => onChange(opt)}
          className={`rounded-full px-2 py-0.5 text-[11px] capitalize ${
            value === opt
              ? "bg-primary text-primary-foreground"
              : "border hover:bg-muted"
          }`}
        >
          {formatter ? formatter(opt) : opt}
        </button>
      ))}
    </div>
  );
}

// ── Bulk actions ─────────────────────────────────────────────────────

interface BulkResult {
  ok: number;
  failed: { id: string; name: string; error: string }[];
}

function BulkResultsModal({
  action,
  result,
  onClose,
}: {
  action: string;
  result: BulkResult;
  onClose: () => void;
}) {
  return (
    <Modal title={`Bulk ${action} — results`} onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        <div className="text-xs text-muted-foreground">
          {result.ok} succeeded, {result.failed.length} failed.
        </div>
        {result.failed.length > 0 && (
          <div className="max-h-72 overflow-auto rounded-md border">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="border-b bg-muted/30 text-left">
                  <th className="px-2 py-1">Device</th>
                  <th className="px-2 py-1">Error</th>
                </tr>
              </thead>
              <tbody>
                {result.failed.map((f) => (
                  <tr key={f.id} className="border-b last:border-0">
                    <td className="px-2 py-1">{f.name}</td>
                    <td className="px-2 py-1 text-red-600">{f.error}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

function ConfirmBulkDeleteModal({
  count,
  onConfirm,
  onClose,
  pending,
}: {
  count: number;
  onConfirm: () => void;
  onClose: () => void;
  pending: boolean;
}) {
  return (
    <Modal title="Delete network devices" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p>
          Delete <span className="font-semibold">{count}</span> device
          {count === 1 ? "" : "s"}? This removes the device row plus any
          associated interfaces, ARP, and FDB entries (CASCADE). IPAM rows are
          not touched.
        </p>
        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            disabled={pending}
            className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={pending}
            className="rounded-md bg-destructive px-3 py-1.5 text-xs text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {pending ? "Deleting…" : `Delete ${count}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Page ─────────────────────────────────────────────────────────────

export function NetworkPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'manage_network_devices'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_network_devices"),
    "Requires write permission on network devices",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "manage_network_devices"),
    "Requires delete permission on network devices",
  );
  const qc = useQueryClient();
  const navigate = useNavigate();

  const [typeFilter, setTypeFilter] = useState<NetworkDeviceType | "all">(
    "all",
  );
  const [statusFilter, setStatusFilter] = useState<NetworkPollStatus | "all">(
    "all",
  );
  const [activeFilter, setActiveFilter] = useState<
    "all" | "active" | "inactive"
  >("all");
  const [tagFilters, setTagFilters] = useState<string[]>([]);

  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<NetworkDeviceRead | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [bulkResult, setBulkResult] = useState<{
    action: string;
    result: BulkResult;
  } | null>(null);

  const queryParams = useMemo<NetworkDeviceListQuery>(() => {
    const p: NetworkDeviceListQuery = { page: 1, page_size: 100 };
    if (typeFilter !== "all") p.device_type = typeFilter;
    if (statusFilter !== "all") p.last_poll_status = statusFilter;
    if (activeFilter === "active") p.active = true;
    else if (activeFilter === "inactive") p.active = false;
    if (tagFilters.length > 0) p.tag = tagFilters;
    return p;
  }, [typeFilter, statusFilter, activeFilter, tagFilters]);

  const {
    data,
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["network-devices", queryParams],
    queryFn: () => networkApi.listDevices(queryParams),
  });
  const devices = data?.items ?? [];

  const toggleActiveMut = useMutation({
    mutationFn: (d: NetworkDeviceRead) =>
      networkApi.updateDevice(d.id, { is_active: !d.is_active }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["network-devices"] });
    },
  });

  const selectedDevices = useMemo(
    () => devices.filter((d) => selected.has(d.id)),
    [devices, selected],
  );

  const allSelected =
    devices.length > 0 && devices.every((d) => selected.has(d.id));
  const someSelected = !allSelected && devices.some((d) => selected.has(d.id));

  function toggleAll() {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(devices.map((d) => d.id)));
    }
  }
  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  // ── Generic bulk runner ──
  // Runs an async per-device call across every selected device with
  // ``Promise.allSettled`` so a single failure can't abort the rest.
  // Surfaces per-row failure detail in the BulkResultsModal — operators
  // need to know which device(s) failed and why, not just a count.
  async function runBulk(
    action: string,
    fn: (d: NetworkDeviceRead) => Promise<unknown>,
  ) {
    const targets = selectedDevices;
    const settled = await Promise.allSettled(targets.map((d) => fn(d)));
    const failed: BulkResult["failed"] = [];
    let ok = 0;
    settled.forEach((s, i) => {
      if (s.status === "fulfilled") ok++;
      else
        failed.push({
          id: targets[i].id,
          name: targets[i].name,
          error: errMsg(s.reason, "failed"),
        });
    });
    setBulkResult({ action, result: { ok, failed } });
    setSelected(new Set());
    qc.invalidateQueries({ queryKey: ["network-devices"] });
  }

  const bulkTestMut = useMutation({
    mutationFn: () => runBulk("test", (d) => networkApi.testConnection(d.id)),
  });
  const bulkPollMut = useMutation({
    mutationFn: () => runBulk("poll", (d) => networkApi.pollNow(d.id)),
  });
  const bulkActivateMut = useMutation({
    mutationFn: (active: boolean) =>
      runBulk(active ? "activate" : "deactivate", (d) =>
        networkApi.updateDevice(d.id, { is_active: active }),
      ),
  });
  const bulkDeleteMut = useMutation({
    mutationFn: async () => {
      await runBulk("delete", (d) => networkApi.deleteDevice(d.id));
      setConfirmDelete(false);
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <NetworkIcon className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Network Discovery</h1>
              <span className="text-xs text-muted-foreground">
                {devices.length} device{devices.length === 1 ? "" : "s"}
                {selected.size > 0 && (
                  <span className="ml-2 text-primary">
                    {selected.size} selected
                  </span>
                )}
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              Discovery via standard SNMP MIBs. Add routers + switches; polling
              fills ARP, FDB, and interface tables. Discovered IPs cross-
              reference into IPAM.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["network-devices"] })
              }
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              icon={Upload}
              onClick={() => setShowImport(true)}
              {...writeGate}
            >
              Import
            </HeaderButton>
            <HeaderButton
              icon={Download}
              onClick={() => exportDevicesCsv(devices)}
              disabled={devices.length === 0}
            >
              Export
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowCreate(true)}
              {...writeGate}
            >
              Add Device
            </HeaderButton>
          </div>
        </div>
        {/* Filters + bulk toolbar */}
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <FilterChips
            label="Type"
            value={typeFilter}
            options={DEVICE_TYPE_OPTIONS}
            onChange={setTypeFilter}
          />
          <FilterChips
            label="Status"
            value={statusFilter}
            options={
              [
                "pending",
                "success",
                "partial",
                "failed",
                "timeout",
              ] as NetworkPollStatus[]
            }
            onChange={setStatusFilter}
          />
          <FilterChips
            label="Active"
            value={activeFilter}
            options={["active", "inactive"]}
            onChange={(v) =>
              setActiveFilter(v as "active" | "inactive" | "all")
            }
          />
        </div>
        <div className="mt-2">
          <TagFilterChips
            value={tagFilters}
            onChange={setTagFilters}
            placeholder="Filter by tag — try env or env:prod…"
          />
        </div>
        {selected.size > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md border bg-muted/20 px-3 py-2">
            <span className="text-xs font-medium">Bulk:</span>
            <button
              onClick={() => bulkTestMut.mutate()}
              disabled={bulkTestMut.isPending}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
              {...writeGate}
            >
              <TestTube2 className="h-3 w-3" /> Test
            </button>
            <button
              onClick={() => bulkPollMut.mutate()}
              disabled={bulkPollMut.isPending}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
              {...writeGate}
            >
              <Play className="h-3 w-3" /> Poll Now
            </button>
            <button
              onClick={() => bulkActivateMut.mutate(true)}
              disabled={bulkActivateMut.isPending}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
              {...writeGate}
            >
              <Power className="h-3 w-3" /> Activate
            </button>
            <button
              onClick={() => bulkActivateMut.mutate(false)}
              disabled={bulkActivateMut.isPending}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
              {...writeGate}
            >
              <Power className="h-3 w-3" /> Deactivate
            </button>
            <button
              onClick={() => setConfirmDelete(true)}
              className="inline-flex items-center gap-1 rounded-md bg-destructive px-2 py-1 text-xs text-destructive-foreground hover:bg-destructive/90 disabled:cursor-not-allowed disabled:opacity-50"
              {...deleteGate}
            >
              <Trash2 className="h-3 w-3" /> Delete {selected.size}
            </button>
            <span className="h-4 w-px bg-border" />
            <button
              onClick={() => setSelected(new Set())}
              className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
            >
              Clear
            </button>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-auto p-6">
        {toggleActiveMut.isError && (
          <p role="alert" className="mb-3 text-xs text-destructive">
            Could not change the device's Active setting:{" "}
            {formatApiError(toggleActiveMut.error, "the request failed")}
          </p>
        )}
        <div className="rounded-lg border">
          {devices.length === 0 ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <NetworkIcon className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                <ListEmpty
                  error={listError}
                  what="network devices"
                  filtered={
                    typeFilter !== "all" ||
                    statusFilter !== "all" ||
                    activeFilter !== "all" ||
                    tagFilters.length > 0
                  }
                  onClearFilters={() => {
                    setTypeFilter("all");
                    setStatusFilter("all");
                    setActiveFilter("all");
                    setTagFilters([]);
                  }}
                >
                  No network devices yet — add a router or switch to start
                  discovering IPs.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-1 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...writeGate}
              >
                <Plus className="h-3 w-3" /> Add Device
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1100px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="w-8 px-2 py-2">
                      <input
                        type="checkbox"
                        checked={allSelected}
                        ref={(el) => {
                          if (el) el.indeterminate = someSelected;
                        }}
                        onChange={toggleAll}
                        aria-label="Select all"
                      />
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Name
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Hostname / IP
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Type
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Vendor
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      SNMP
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Status
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Last poll
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-right font-medium">
                      ARP / IF / FDB
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-center font-medium">
                      Active
                    </th>
                    <th className="w-10 px-2 py-2" />
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => {
                    const sel = selected.has(d.id);
                    return (
                      <tr
                        key={d.id}
                        onClick={() => navigate(`/network/devices/${d.id}`)}
                        className={`cursor-pointer border-b last:border-0 hover:bg-muted/20 ${
                          sel ? "bg-primary/5" : ""
                        }`}
                      >
                        <td
                          className="w-8 px-2 py-2"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <input
                            type="checkbox"
                            checked={sel}
                            onChange={() => toggleOne(d.id)}
                            aria-label={`Select ${d.name}`}
                          />
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <div className="font-medium">{d.name}</div>
                          {d.description && (
                            <div className="text-[11px] text-muted-foreground">
                              {d.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                          <div>{d.hostname}</div>
                          <div className="text-muted-foreground">
                            {d.ip_address}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <DeviceTypePill type={d.device_type} />
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {d.vendor ?? (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <SnmpVersionPill version={d.snmp_version} />
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-1">
                            <PollStatusPill status={d.last_poll_status} />
                            {d.last_poll_error && (
                              <AlertTriangle
                                className="h-3 w-3 text-amber-500"
                                aria-label={d.last_poll_error}
                              />
                            )}
                          </div>
                        </td>
                        <td
                          className="whitespace-nowrap px-3 py-2 text-muted-foreground"
                          title={d.last_poll_at ?? ""}
                        >
                          {humanTime(d.last_poll_at)}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right tabular-nums text-muted-foreground">
                          {d.last_poll_arp_count ?? 0} /{" "}
                          {d.last_poll_interface_count ?? 0} /{" "}
                          {d.last_poll_fdb_count ?? 0}
                        </td>
                        <td
                          className="whitespace-nowrap px-3 py-2 text-center"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <label className="inline-flex cursor-pointer items-center">
                            <input
                              type="checkbox"
                              checked={d.is_active}
                              aria-label={`Active ${d.name}`}
                              disabled={toggleActiveMut.isPending}
                              onChange={() => toggleActiveMut.mutate(d)}
                              {...writeGate}
                            />
                          </label>
                        </td>
                        <td
                          className="w-10 px-2 py-2 text-right"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            onClick={() => setEditing(d)}
                            title="Edit device"
                            className="inline-flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                            {...writeGate}
                          >
                            <Pencil className="h-3 w-3" />
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

      {showCreate && <DeviceFormModal onClose={() => setShowCreate(false)} />}
      {editing && (
        <DeviceFormModal device={editing} onClose={() => setEditing(null)} />
      )}
      {showImport && (
        <NetworkImportModal onClose={() => setShowImport(false)} />
      )}
      {confirmDelete && (
        <ConfirmBulkDeleteModal
          count={selected.size}
          pending={bulkDeleteMut.isPending}
          onConfirm={() => bulkDeleteMut.mutate()}
          onClose={() => setConfirmDelete(false)}
        />
      )}
      {bulkResult && (
        <BulkResultsModal
          action={bulkResult.action}
          result={bulkResult.result}
          onClose={() => setBulkResult(null)}
        />
      )}
    </div>
  );
}
