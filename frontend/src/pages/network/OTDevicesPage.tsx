import { ListEmpty, ListReadError } from "@/components/ui/list-read-error";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Factory, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";

import {
  formatApiError,
  ipamApi,
  otApi,
  type OTDevice,
  type OTDeviceCreate,
  type OTDeviceSource,
  type OTDeviceUpdate,
  type OTProtocol,
  type OTRole,
  type OTZone,
  type OTZoneCreate,
  type OTZoneUpdate,
  type PurdueLevel,
} from "@/lib/api";
import {
  OT_PROTOCOL_LABELS,
  OT_ROLE_LABELS,
  OT_SOURCE_LABELS,
  PURDUE_DESCRIPTIONS,
  PURDUE_LEVELS,
} from "@/lib/otLabels";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { Pager } from "@/components/ui/pager";
import { IPAddressPicker } from "@/components/IPAddressPicker";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";

// OT / industrial device registry + Purdue zoning (issue #542, part of
// #543). Read-only identification: nothing here probes, scans, reads a
// tag or writes a control protocol. Every value was typed by an operator
// or came out of an engineering-tool export.

const PAGE_SIZE = 50;

// ── Page ─────────────────────────────────────────────────────────────

export function OTDevicesPage() {
  const qc = useQueryClient();
  const { enabled, ready } = useFeatureModules();
  const otEnabled = enabled("network.ot");
  // ``enabled()`` returns true while the module set is still loading, so
  // data queries also wait on ``ready`` — otherwise a hard page load
  // fires one request that 404s when the module is off.
  const canQuery = ready && otEnabled;
  const perms = usePermissions();
  const canWrite = perms.can("write", "ot_device");
  const canDelete = perms.can("delete", "ot_device");

  const [page, setPage] = useState(1);
  const [protocolFilter, setProtocolFilter] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [purdueFilter, setPurdueFilter] = useState("");
  const [subnetFilter, setSubnetFilter] = useState("");
  const [search, setSearch] = useState("");

  const [deviceModal, setDeviceModal] = useState<
    { mode: "create" } | { mode: "edit"; device: OTDevice } | null
  >(null);
  const [deleteDevice, setDeleteDevice] = useState<OTDevice | null>(null);
  const [zoneModal, setZoneModal] = useState<
    { mode: "create" } | { mode: "edit"; zone: OTZone } | null
  >(null);
  const [deleteZone, setDeleteZone] = useState<OTZone | null>(null);

  const subnetsQ = useQuery({
    queryKey: ["subnets", "all"],
    queryFn: () => ipamApi.listSubnets(),
    staleTime: 60_000,
  });
  const subnets = subnetsQ.data ?? [];

  const devicesQ = useQuery({
    queryKey: [
      "ot-devices",
      page,
      protocolFilter,
      roleFilter,
      purdueFilter,
      subnetFilter,
      search,
    ],
    queryFn: () =>
      otApi.listDevices({
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
        ot_protocol: protocolFilter || undefined,
        ot_role: roleFilter || undefined,
        purdue_level: purdueFilter || undefined,
        subnet_id: subnetFilter || undefined,
        q: search.trim() || undefined,
      }),
    enabled: canQuery,
  });
  const devices = devicesQ.data?.items ?? [];
  const total = devicesQ.data?.total ?? 0;

  const zonesQ = useQuery({
    queryKey: ["ot-zones"],
    queryFn: () => otApi.listZones(),
    enabled: canQuery,
  });
  const zones = zonesQ.data ?? [];
  // Zone level by subnet, so a device's declared level can be shown
  // against the zone it actually sits in (the ot_device_crosses_purdue_
  // boundary conformity check does the same comparison server-side).
  const zoneLevelBySubnet = zones.reduce<Record<string, string>>((acc, z) => {
    acc[z.subnet_id] = z.purdue_level;
    return acc;
  }, {});

  const deleteDeviceMut = useMutation({
    mutationFn: (id: string) => otApi.removeDevice(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ot-devices"] });
      qc.invalidateQueries({ queryKey: ["ot-zones"] });
      setDeleteDevice(null);
    },
  });

  const deleteZoneMut = useMutation({
    mutationFn: (id: string) => otApi.removeZone(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ot-zones"] });
      setDeleteZone(null);
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Factory className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">OT / industrial devices</h1>
              <span className="text-xs text-muted-foreground">
                {devicesQ.error ? (
                  <ListReadError error={devicesQ.error} what="OT devices" />
                ) : (
                  `${total} device${total === 1 ? "" : "s"}`
                )}{" "}
                ·{" "}
                {zonesQ.error ? (
                  <ListReadError error={zonesQ.error} what="Purdue zones" />
                ) : (
                  `${zones.length} zone${zones.length === 1 ? "" : "s"}`
                )}
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              Industrial descriptors on top of IPAM addresses — protocol, role,
              vendor and the declared Purdue level — plus one zone record per
              subnet, which is where segmentation is actually drawn.
              Identification only: SpatiumDDI never reads a tag and never writes
              a control protocol.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={
                devicesQ.isFetching || zonesQ.isFetching ? "animate-spin" : ""
              }
              onClick={() => {
                qc.invalidateQueries({ queryKey: ["ot-devices"] });
                qc.invalidateQueries({ queryKey: ["ot-zones"] });
              }}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              disabled={!canWrite}
              title={
                canWrite ? undefined : "Requires write permission on OT devices"
              }
              onClick={() => setDeviceModal({ mode: "create" })}
            >
              New device
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 space-y-6 overflow-auto p-6">
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={protocolFilter}
              onChange={(e) => {
                setProtocolFilter(e.target.value);
                setPage(1);
              }}
              className={filterCls}
              aria-label="Filter by OT protocol"
            >
              <option value="">All protocols</option>
              {Object.entries(OT_PROTOCOL_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
            <select
              value={roleFilter}
              onChange={(e) => {
                setRoleFilter(e.target.value);
                setPage(1);
              }}
              className={filterCls}
              aria-label="Filter by device role"
            >
              <option value="">All roles</option>
              {Object.entries(OT_ROLE_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
            <select
              value={purdueFilter}
              onChange={(e) => {
                setPurdueFilter(e.target.value);
                setPage(1);
              }}
              className={filterCls}
              aria-label="Filter by Purdue level"
            >
              <option value="">All Purdue levels</option>
              {PURDUE_LEVELS.map((l) => (
                <option key={l} value={l}>
                  {PURDUE_DESCRIPTIONS[l]}
                </option>
              ))}
            </select>
            <select
              value={subnetFilter}
              onChange={(e) => {
                setSubnetFilter(e.target.value);
                setPage(1);
              }}
              className={`${filterCls} max-w-[16rem]`}
              aria-label="Filter by subnet"
            >
              <option value="">All subnets</option>
              {subnets.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.network}
                  {s.name ? ` — ${s.name}` : ""}
                </option>
              ))}
            </select>
            <input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search name / vendor / product / serial…"
              className={`${filterCls} w-72`}
              aria-label="Search OT devices"
            />
            <div className="ml-auto">
              <Pager
                page={page}
                total={total}
                pageSize={PAGE_SIZE}
                onChange={setPage}
              />
            </div>
          </div>

          <div className="rounded-lg border">
            {devices.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                {devicesQ.isLoading ? (
                  "Loading devices…"
                ) : (
                  <ListEmpty
                    error={devicesQ.error}
                    what="OT devices"
                    filtered={
                      search.trim() !== "" ||
                      protocolFilter !== "" ||
                      roleFilter !== "" ||
                      purdueFilter !== "" ||
                      subnetFilter !== ""
                    }
                    onClearFilters={() => {
                      setSearch("");
                      setProtocolFilter("");
                      setRoleFilter("");
                      setPurdueFilter("");
                      setSubnetFilter("");
                      setPage(1);
                    }}
                  >
                    No OT descriptors recorded. Attach one to an existing IPAM
                    address to start documenting the plant.
                  </ListEmpty>
                )}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[1050px] text-xs">
                  <thead>
                    <tr className="border-b bg-muted/30">
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Address
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Device name
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Protocol
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Role
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Purdue
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Cell / area
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Vendor
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Product
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Source
                      </th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.map((d) => {
                      const zoneLevel = zoneLevelBySubnet[d.subnet_id];
                      const mismatch =
                        d.purdue_level !== null &&
                        zoneLevel !== undefined &&
                        d.purdue_level !== zoneLevel;
                      return (
                        <tr key={d.id} className="border-b last:border-0">
                          <td className="whitespace-nowrap px-3 py-2 font-mono">
                            {d.address}
                          </td>
                          <td className="px-3 py-2">
                            {d.profinet_device_name || "—"}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2">
                            {OT_PROTOCOL_LABELS[d.ot_protocol] ?? d.ot_protocol}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                            {d.ot_role
                              ? (OT_ROLE_LABELS[d.ot_role] ?? d.ot_role)
                              : "—"}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2">
                            <PurdueChip level={d.purdue_level} />
                            {mismatch && (
                              <span
                                className="ml-1 inline-flex rounded bg-amber-500/10 px-1.5 py-0.5 text-[11px] text-amber-700 dark:text-amber-400"
                                title={`The subnet's zone declares Purdue ${zoneLevel}`}
                              >
                                ≠ zone {zoneLevel}
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-2 text-muted-foreground">
                            {d.cell_area || "—"}
                          </td>
                          <td className="px-3 py-2 text-muted-foreground">
                            {d.ot_vendor || "—"}
                          </td>
                          <td className="px-3 py-2 text-muted-foreground">
                            {d.ot_product || "—"}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                            {OT_SOURCE_LABELS[d.seen_via] ?? d.seen_via}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 text-right">
                            <button
                              type="button"
                              disabled={!canWrite}
                              onClick={() =>
                                setDeviceModal({ mode: "edit", device: d })
                              }
                              className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40"
                              title="Edit descriptor"
                            >
                              <Pencil className="h-3.5 w-3.5" />
                            </button>
                            <button
                              type="button"
                              disabled={!canDelete}
                              onClick={() => setDeleteDevice(d)}
                              className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
                              title="Delete descriptor"
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
        </section>

        {/* ── Purdue zones ─────────────────────────────────────────── */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold">Purdue zones</h2>
            <p className="min-w-0 flex-1 text-xs text-muted-foreground">
              One zone per subnet. An unzoned subnet reads as
              &ldquo;unknown&rdquo; rather than conforming, so devices in it are
              never compared against a level.
            </p>
            <HeaderButton
              icon={Plus}
              disabled={!canWrite}
              title={
                canWrite ? undefined : "Requires write permission on OT devices"
              }
              onClick={() => setZoneModal({ mode: "create" })}
            >
              New zone
            </HeaderButton>
          </div>

          <div className="rounded-lg border">
            {zones.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                {zonesQ.isLoading ? (
                  "Loading zones…"
                ) : (
                  <ListEmpty error={zonesQ.error} what="Purdue zones">
                    No subnet has been classified yet.
                  </ListEmpty>
                )}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[800px] text-xs">
                  <thead>
                    <tr className="border-b bg-muted/30">
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Subnet
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Purdue level
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Zone name
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Cell / area
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Devices
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Description
                      </th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {zones.map((z) => (
                      <tr key={z.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-mono">
                          {z.subnet_network}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <PurdueChip level={z.purdue_level} />
                        </td>
                        <td className="px-3 py-2">{z.name || "—"}</td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {z.cell_area || "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 tabular-nums text-muted-foreground">
                          {z.device_count}
                        </td>
                        <td
                          className="max-w-md truncate px-3 py-2 text-muted-foreground"
                          title={z.description}
                        >
                          {z.description || "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <button
                            type="button"
                            disabled={!canWrite}
                            onClick={() =>
                              setZoneModal({ mode: "edit", zone: z })
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40"
                            title="Edit zone"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            disabled={!canDelete}
                            onClick={() => setDeleteZone(z)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
                            title="Delete zone"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      </div>

      {deviceModal && (
        <DeviceModal
          mode={deviceModal.mode}
          device={deviceModal.mode === "edit" ? deviceModal.device : null}
          onClose={() => setDeviceModal(null)}
        />
      )}
      {zoneModal && (
        <ZoneModal
          mode={zoneModal.mode}
          zone={zoneModal.mode === "edit" ? zoneModal.zone : null}
          onClose={() => setZoneModal(null)}
        />
      )}
      <ConfirmModal
        open={deleteDevice !== null}
        title="Delete OT descriptor"
        message={
          <>
            Delete the OT descriptor for{" "}
            <span className="font-mono">{deleteDevice?.address}</span>? This
            says &ldquo;no longer an OT device&rdquo;, not &ldquo;this address
            is free&rdquo; — the IPAM row itself is untouched.
          </>
        }
        tone="destructive"
        confirmLabel="Delete"
        loading={deleteDeviceMut.isPending}
        onConfirm={() =>
          deleteDevice && deleteDeviceMut.mutate(deleteDevice.id)
        }
        onClose={() => setDeleteDevice(null)}
      />
      <ConfirmModal
        open={deleteZone !== null}
        title="Delete Purdue zone"
        message={
          <>
            Un-zone{" "}
            <span className="font-mono">{deleteZone?.subnet_network}</span>?
            Devices inside keep their own declared levels; they simply stop
            having a zone to be compared against.
          </>
        }
        tone="destructive"
        confirmLabel="Delete"
        loading={deleteZoneMut.isPending}
        onConfirm={() => deleteZone && deleteZoneMut.mutate(deleteZone.id)}
        onClose={() => setDeleteZone(null)}
      />
    </div>
  );
}

function PurdueChip({ level }: { level: string | null }) {
  if (level === null || level === "") {
    return <span className="text-muted-foreground">—</span>;
  }
  return (
    <span
      className="inline-flex rounded bg-indigo-500/10 px-1.5 py-0.5 text-[11px] font-medium tabular-nums text-indigo-700 dark:text-indigo-400"
      title={PURDUE_DESCRIPTIONS[level] ?? `Purdue level ${level}`}
    >
      L{level}
    </span>
  );
}

// ── Device create / edit ─────────────────────────────────────────────

function DeviceModal({
  mode,
  device,
  onClose,
}: {
  mode: "create" | "edit";
  device: OTDevice | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [ipAddressId, setIpAddressId] = useState<string | null>(
    device?.ip_address_id ?? null,
  );
  const [protocol, setProtocol] = useState(device?.ot_protocol ?? "profinet");
  const [role, setRole] = useState(device?.ot_role ?? "");
  const [deviceName, setDeviceName] = useState(
    device?.profinet_device_name ?? "",
  );
  const [vendor, setVendor] = useState(device?.ot_vendor ?? "");
  const [product, setProduct] = useState(device?.ot_product ?? "");
  const [serial, setSerial] = useState(device?.ot_serial ?? "");
  const [firmware, setFirmware] = useState(device?.firmware_rev ?? "");
  const [purdue, setPurdue] = useState(device?.purdue_level ?? "");
  const [cellArea, setCellArea] = useState(device?.cell_area ?? "");
  const [seenVia, setSeenVia] = useState(device?.seen_via ?? "manual");
  const [notes, setNotes] = useState(device?.notes ?? "");
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: () => {
      const shared = {
        ot_protocol: protocol as OTProtocol,
        ot_role: (role || null) as OTRole | null,
        profinet_device_name: deviceName,
        ot_vendor: vendor,
        ot_product: product,
        ot_serial: serial,
        firmware_rev: firmware,
        purdue_level: (purdue || null) as PurdueLevel | null,
        cell_area: cellArea,
        seen_via: seenVia as OTDeviceSource,
        notes,
      };
      if (mode === "edit" && device) {
        const body: OTDeviceUpdate = shared;
        return otApi.updateDevice(device.id, body);
      }
      const body: OTDeviceCreate = {
        ...shared,
        ip_address_id: ipAddressId as string,
      };
      return otApi.createDevice(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ot-devices"] });
      qc.invalidateQueries({ queryKey: ["ot-zones"] });
      onClose();
    },
    onError: (e) => setError(formatApiError(e, "Failed to save descriptor")),
  });

  const canSubmit = !!ipAddressId && !mut.isPending;

  return (
    <Modal
      title={mode === "create" ? "New OT descriptor" : "Edit OT descriptor"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit) mut.mutate();
        }}
        className="space-y-3"
      >
        {mode === "create" ? (
          <Field label="IPAM address">
            <IPAddressPicker
              value={ipAddressId}
              onChange={(id) => setIpAddressId(id)}
            />
            <p className="text-[11px] text-muted-foreground">
              The address must already exist in IPAM — a descriptor enriches an
              address, it never creates one.
            </p>
          </Field>
        ) : (
          // The sidecar is 1:1 with its address and dies with it, so the
          // backend has no re-parent path: moving one is delete + create.
          <Field label="IPAM address">
            <p className="rounded-md border bg-muted/30 px-3 py-1.5 font-mono text-sm">
              {device?.address}
            </p>
            <p className="text-[11px] text-muted-foreground">
              A descriptor can&rsquo;t be moved to another address — delete it
              and create one on the new address.
            </p>
          </Field>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Protocol">
            <select
              className={inputCls}
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
            >
              {Object.entries(OT_PROTOCOL_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Role">
            <select
              className={inputCls}
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              <option value="">Unknown</option>
              {Object.entries(OT_ROLE_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Device name (PROFINET / station)">
            <input
              className={inputCls}
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              placeholder="e.g. plc-line3-main"
            />
          </Field>
          <Field label="Cell / area">
            <input
              className={inputCls}
              value={cellArea}
              onChange={(e) => setCellArea(e.target.value)}
              placeholder="e.g. Line 3 packaging"
            />
          </Field>
          <Field label="Purdue level">
            <select
              className={inputCls}
              value={purdue}
              onChange={(e) => setPurdue(e.target.value)}
            >
              <option value="">Unknown</option>
              {PURDUE_LEVELS.map((l) => (
                <option key={l} value={l}>
                  {PURDUE_DESCRIPTIONS[l]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Source">
            <select
              className={inputCls}
              value={seenVia}
              onChange={(e) => setSeenVia(e.target.value)}
            >
              {Object.entries(OT_SOURCE_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Vendor">
            <input
              className={inputCls}
              value={vendor}
              onChange={(e) => setVendor(e.target.value)}
            />
          </Field>
          <Field label="Product">
            <input
              className={inputCls}
              value={product}
              onChange={(e) => setProduct(e.target.value)}
            />
          </Field>
          <Field label="Serial">
            <input
              className={inputCls}
              value={serial}
              onChange={(e) => setSerial(e.target.value)}
            />
          </Field>
          <Field label="Firmware revision">
            <input
              className={inputCls}
              value={firmware}
              onChange={(e) => setFirmware(e.target.value)}
            />
          </Field>
        </div>

        <Field label="Notes">
          <textarea
            className={`${inputCls} min-h-[70px]`}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </Field>

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
            disabled={!canSubmit}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── Zone create / edit ───────────────────────────────────────────────

function ZoneModal({
  mode,
  zone,
  onClose,
}: {
  mode: "create" | "edit";
  zone: OTZone | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [subnetId, setSubnetId] = useState(zone?.subnet_id ?? "");
  const [purdue, setPurdue] = useState<string>(zone?.purdue_level ?? "3");
  const [cellArea, setCellArea] = useState(zone?.cell_area ?? "");
  const [name, setName] = useState(zone?.name ?? "");
  const [description, setDescription] = useState(zone?.description ?? "");
  const [error, setError] = useState("");

  const subnetsQ = useQuery({
    queryKey: ["subnets", "all"],
    queryFn: () => ipamApi.listSubnets(),
    enabled: mode === "create",
    staleTime: 60_000,
  });
  const subnets = subnetsQ.data ?? [];

  const mut = useMutation({
    mutationFn: () => {
      if (mode === "edit" && zone) {
        const body: OTZoneUpdate = {
          purdue_level: purdue as PurdueLevel,
          cell_area: cellArea,
          name,
          description,
        };
        return otApi.updateZone(zone.id, body);
      }
      const body: OTZoneCreate = {
        subnet_id: subnetId,
        purdue_level: purdue as PurdueLevel,
        cell_area: cellArea,
        name,
        description,
      };
      return otApi.createZone(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ot-zones"] });
      onClose();
    },
    onError: (e) => setError(formatApiError(e, "Failed to save zone")),
  });

  return (
    <Modal
      title={mode === "create" ? "New Purdue zone" : "Edit Purdue zone"}
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        {mode === "create" ? (
          <Field label="Subnet">
            <select
              className={inputCls}
              value={subnetId}
              onChange={(e) => setSubnetId(e.target.value)}
              required
            >
              <option value="">Select a subnet…</option>
              {subnets.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.network}
                  {s.name ? ` — ${s.name}` : ""}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-muted-foreground">
              One zone per subnet — a second classification of the same subnet
              is refused, because it would make every boundary report ambiguous.
            </p>
          </Field>
        ) : (
          <Field label="Subnet">
            <p className="rounded-md border bg-muted/30 px-3 py-1.5 font-mono text-sm">
              {zone?.subnet_network}
            </p>
            <p className="text-[11px] text-muted-foreground">
              A zone belongs to its subnet and can&rsquo;t be re-pointed —
              delete it and create one on the other subnet.
            </p>
          </Field>
        )}

        <Field label="Purdue level">
          <select
            className={inputCls}
            value={purdue}
            onChange={(e) => setPurdue(e.target.value)}
            required
          >
            {PURDUE_LEVELS.map((l) => (
              <option key={l} value={l}>
                {PURDUE_DESCRIPTIONS[l]}
              </option>
            ))}
          </select>
          <p className="text-[11px] text-muted-foreground">
            Required — a zone with no level is not a zone. To clear it, delete
            the zone.
          </p>
        </Field>

        <Field label="Zone name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Line 3 control zone"
          />
        </Field>
        <Field label="Cell / area">
          <input
            className={inputCls}
            value={cellArea}
            onChange={(e) => setCellArea(e.target.value)}
          />
        </Field>
        <Field label="Description">
          <textarea
            className={`${inputCls} min-h-[70px]`}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

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
            disabled={
              mut.isPending || !purdue || (mode === "create" && !subnetId)
            }
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── Local form primitives ────────────────────────────────────────────

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const filterCls =
  "rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
    </div>
  );
}
