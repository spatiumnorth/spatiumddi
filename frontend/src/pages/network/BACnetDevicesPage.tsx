import { ListEmpty, ListReadError } from "@/components/ui/list-read-error";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";

import {
  bacnetApi,
  formatApiError,
  ipamApi,
  type BACnetDevice,
  type BACnetDeviceCreate,
  type BACnetDeviceSource,
  type BACnetDeviceUpdate,
  type BACnetSegmentation,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { Pager } from "@/components/ui/pager";
import { IPAddressPicker } from "@/components/IPAddressPicker";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";

// BACnet/IP device registry (issue #541, part of #543). Documentation
// only — nothing on this page reads or writes a device object; rows come
// from operators and importers.

const PAGE_SIZE = 50;

// BACnet/IP's IANA-assigned port (0xBAC0). Mirrors
// app.models.bacnet.BACNET_DEFAULT_PORT — a device on any other port is
// worth calling out in the list, and it is the create-form default.
const BACNET_DEFAULT_PORT = 47808;

// Mirrors app.models.bacnet.BACNET_SEGMENTATION / BACNET_DEVICE_SOURCES.
const SEGMENTATION_OPTIONS: BACnetSegmentation[] = [
  "both",
  "transmit",
  "receive",
  "no-segmentation",
];

const SOURCE_LABELS: Record<string, string> = {
  manual: "Manual",
  whois: "Who-Is sweep",
  mirror: "Integration mirror",
  import: "Import",
};

// ── Page ─────────────────────────────────────────────────────────────

export function BACnetDevicesPage() {
  const qc = useQueryClient();
  const { enabled, ready } = useFeatureModules();
  const bacnetEnabled = enabled("network.bacnet");
  // ``enabled()`` is optimistic while the module list loads, so data
  // queries wait for ``ready`` as well — a hard page load must not fire
  // a request that 404s.
  const canQuery = ready && bacnetEnabled;
  const perms = usePermissions();
  const canWrite = perms.can("write", "bacnet_device");
  const canDelete = perms.can("delete", "bacnet_device");

  const [page, setPage] = useState(1);
  const [subnetFilter, setSubnetFilter] = useState("");
  const [vendorFilter, setVendorFilter] = useState("");
  const [bbmdOnly, setBbmdOnly] = useState(false);
  const [search, setSearch] = useState("");

  const [modal, setModal] = useState<
    { mode: "create" } | { mode: "edit"; device: BACnetDevice } | null
  >(null);
  const [del, setDel] = useState<BACnetDevice | null>(null);

  const subnetsQ = useQuery({
    queryKey: ["subnets", "all"],
    queryFn: () => ipamApi.listSubnets(),
    staleTime: 60_000,
  });
  const subnets = subnetsQ.data ?? [];

  const vendorId =
    vendorFilter.trim() !== "" && /^\d+$/.test(vendorFilter.trim())
      ? Number(vendorFilter.trim())
      : undefined;

  const devicesQ = useQuery({
    queryKey: [
      "bacnet-devices",
      page,
      subnetFilter,
      vendorId ?? "",
      bbmdOnly,
      search,
    ],
    queryFn: () =>
      bacnetApi.listDevices({
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
        subnet_id: subnetFilter || undefined,
        vendor_id: vendorId,
        is_bbmd: bbmdOnly ? true : undefined,
        q: search.trim() || undefined,
      }),
    enabled: canQuery,
  });
  const devices = devicesQ.data?.items ?? [];
  const total = devicesQ.data?.total ?? 0;

  const bbmdsQ = useQuery({
    queryKey: ["bacnet-bbmds"],
    queryFn: bacnetApi.listBbmds,
    enabled: canQuery,
  });
  const bbmds = bbmdsQ.data ?? [];
  // Two BBMDs on one subnet duplicate every forwarded broadcast — the
  // bbmd_one_per_subnet conformity check flags it, and the list marks it.
  const subnetBbmdCounts = bbmds.reduce<Record<string, number>>((acc, b) => {
    if (b.subnet_id) acc[b.subnet_id] = (acc[b.subnet_id] ?? 0) + 1;
    return acc;
  }, {});

  const delMut = useMutation({
    mutationFn: (id: string) => bacnetApi.removeDevice(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["bacnet-devices"] });
      qc.invalidateQueries({ queryKey: ["bacnet-bbmds"] });
      setDel(null);
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Building2 className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">BACnet/IP devices</h1>
              <span className="text-xs text-muted-foreground">
                {devicesQ.error ? (
                  <ListReadError error={devicesQ.error} what="BACnet devices" />
                ) : (
                  `${total} device${total === 1 ? "" : "s"}`
                )}{" "}
                ·{" "}
                {bbmdsQ.error ? (
                  <ListReadError error={bbmdsQ.error} what="BBMDs" />
                ) : (
                  `${bbmds.length} BBMD${bbmds.length === 1 ? "" : "s"}`
                )}
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              Building-automation registry anchored to IPAM addresses. Device
              instance numbers are unique across the whole BACnet internetwork,
              so this list is the place a duplicate shows up before a
              commissioning engineer finds it the hard way. BBMD designation is
              recorded per subnet — BACnet broadcasts don&rsquo;t cross IP
              routers, so each subnet needs exactly one.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={
                devicesQ.isFetching || bbmdsQ.isFetching ? "animate-spin" : ""
              }
              onClick={() => {
                qc.invalidateQueries({ queryKey: ["bacnet-devices"] });
                qc.invalidateQueries({ queryKey: ["bacnet-bbmds"] });
              }}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              disabled={!canWrite}
              title={
                canWrite
                  ? undefined
                  : "Requires write permission on BACnet devices"
              }
              onClick={() => setModal({ mode: "create" })}
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
              value={vendorFilter}
              onChange={(e) => {
                setVendorFilter(e.target.value);
                setPage(1);
              }}
              inputMode="numeric"
              placeholder="Vendor ID"
              className={`${filterCls} w-28`}
              aria-label="Filter by ASHRAE vendor id"
            />
            <label className="flex cursor-pointer items-center gap-1.5 text-xs">
              <input
                type="checkbox"
                checked={bbmdOnly}
                onChange={(e) => {
                  setBbmdOnly(e.target.checked);
                  setPage(1);
                }}
              />
              BBMDs only
            </label>
            <input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search name / model / vendor / instance…"
              className={`${filterCls} w-72`}
              aria-label="Search BACnet devices"
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
                    what="BACnet devices"
                    filtered={
                      search.trim() !== "" ||
                      subnetFilter !== "" ||
                      vendorFilter.trim() !== "" ||
                      bbmdOnly
                    }
                    onClearFilters={() => {
                      setSearch("");
                      setSubnetFilter("");
                      setVendorFilter("");
                      setBbmdOnly(false);
                      setPage(1);
                    }}
                  >
                    No BACnet devices recorded.
                  </ListEmpty>
                )}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[1000px] text-xs">
                  <thead>
                    <tr className="border-b bg-muted/30">
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Instance
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Device
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Address
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Vendor
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Model
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Location
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Network
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Source
                      </th>
                      <th className="px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.map((d) => (
                      <tr key={d.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2">
                          {/* The identifier operators search by — kept
                              mono + bold so it reads at a glance. */}
                          <span className="font-mono text-[13px] font-semibold tabular-nums">
                            {d.device_instance}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-1.5">
                            <span>{d.device_name || "—"}</span>
                            {d.is_bbmd && <BBMDBadge />}
                            {d.is_foreign_device && (
                              <span className="inline-flex rounded bg-sky-500/10 px-1.5 py-0.5 text-[11px] text-sky-700 dark:text-sky-400">
                                foreign
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono">
                          {d.address ?? "—"}
                          {d.udp_port !== BACNET_DEFAULT_PORT && (
                            <span className="ml-1 text-[11px] text-muted-foreground">
                              :{d.udp_port}
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {d.vendor_label || d.vendor_name || "—"}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {d.model_name || "—"}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {d.location || "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {d.network_number ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {SOURCE_LABELS[d.seen_via] ?? d.seen_via}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <button
                            type="button"
                            disabled={!canWrite}
                            onClick={() =>
                              setModal({ mode: "edit", device: d })
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40"
                            title="Edit device"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            disabled={!canDelete}
                            onClick={() => setDel(d)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
                            title="Delete device"
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

        {/* ── BBMD topology ────────────────────────────────────────── */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold">BBMD topology</h2>
            <p className="min-w-0 flex-1 text-xs text-muted-foreground">
              One Broadcast Distribution Device per subnet: none and devices are
              invisible across subnets, two and every forwarded broadcast is
              duplicated.
            </p>
          </div>
          <div className="rounded-lg border">
            {bbmds.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                {bbmdsQ.isLoading
                  ? "Loading BBMDs…"
                  : "No BBMD designated. On a multi-subnet BACnet/IP network that means broadcasts stay inside their own subnet."}
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
                        Instance
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Device
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        Address
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        BDT
                      </th>
                      <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                        FDT
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {bbmds.map((b) => (
                      <tr key={b.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2">
                          <span className="font-mono">
                            {b.subnet_network ?? "unassigned"}
                          </span>
                          {b.subnet_name && (
                            <span className="ml-1 text-[11px] text-muted-foreground">
                              {b.subnet_name}
                            </span>
                          )}
                          {b.subnet_id &&
                            (subnetBbmdCounts[b.subnet_id] ?? 0) > 1 && (
                              <span className="ml-1 inline-flex rounded bg-amber-500/10 px-1.5 py-0.5 text-[11px] text-amber-700 dark:text-amber-400">
                                duplicate BBMD
                              </span>
                            )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono font-semibold tabular-nums">
                          {b.device_instance}
                        </td>
                        <td className="px-3 py-2">{b.device_name || "—"}</td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono">
                          {b.address ?? "—"}:{b.udp_port}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {b.bdt_entries} entr
                          {b.bdt_entries === 1 ? "y" : "ies"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {b.fdt_entries} entr
                          {b.fdt_entries === 1 ? "y" : "ies"}
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

      {modal && (
        <DeviceModal
          mode={modal.mode}
          device={modal.mode === "edit" ? modal.device : null}
          onClose={() => setModal(null)}
        />
      )}
      <ConfirmModal
        open={del !== null}
        title="Delete BACnet device"
        message={
          <>
            Delete device instance{" "}
            <span className="font-mono font-semibold">
              {del?.device_instance}
            </span>
            {del?.device_name ? ` (${del.device_name})` : ""}? The instance
            number is freed for re-use; the IPAM address itself is untouched.
          </>
        }
        tone="destructive"
        confirmLabel="Delete"
        loading={delMut.isPending}
        onConfirm={() => del && delMut.mutate(del.id)}
        onClose={() => setDel(null)}
      />
    </div>
  );
}

function BBMDBadge() {
  return (
    <span
      className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400"
      title="Broadcast Distribution Device — forwards BACnet broadcasts between subnets"
    >
      BBMD
    </span>
  );
}

// ── Create / edit ────────────────────────────────────────────────────

function DeviceModal({
  mode,
  device,
  onClose,
}: {
  mode: "create" | "edit";
  device: BACnetDevice | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [ipAddressId, setIpAddressId] = useState<string | null>(
    device?.ip_address_id ?? null,
  );
  const [ipLabel, setIpLabel] = useState<string | null>(
    device?.address ?? null,
  );
  const [instance, setInstance] = useState(
    device ? String(device.device_instance) : "",
  );
  const [vendorId, setVendorId] = useState(
    device?.vendor_id === null || device?.vendor_id === undefined
      ? ""
      : String(device.vendor_id),
  );
  const [vendorName, setVendorName] = useState(device?.vendor_name ?? "");
  const [deviceName, setDeviceName] = useState(device?.device_name ?? "");
  const [modelName, setModelName] = useState(device?.model_name ?? "");
  const [firmware, setFirmware] = useState(device?.firmware_rev ?? "");
  const [location, setLocation] = useState(device?.location ?? "");
  const [maxApdu, setMaxApdu] = useState(
    device?.max_apdu === null || device?.max_apdu === undefined
      ? ""
      : String(device.max_apdu),
  );
  const [segmentation, setSegmentation] = useState(
    device?.segmentation_supported ?? "",
  );
  const [networkNumber, setNetworkNumber] = useState(
    device?.network_number === null || device?.network_number === undefined
      ? ""
      : String(device.network_number),
  );
  const [udpPort, setUdpPort] = useState(
    String(device?.udp_port ?? BACNET_DEFAULT_PORT),
  );
  const [isBbmd, setIsBbmd] = useState(device?.is_bbmd ?? false);
  const [isForeign, setIsForeign] = useState(
    device?.is_foreign_device ?? false,
  );
  const [seenVia, setSeenVia] = useState(device?.seen_via ?? "manual");
  const [notes, setNotes] = useState(device?.notes ?? "");
  const [error, setError] = useState("");

  const nextInstanceMut = useMutation({
    mutationFn: () => bacnetApi.nextInstance(),
    onSuccess: (res) => {
      if (res.device_instance !== null)
        setInstance(String(res.device_instance));
      else
        setError(
          "No free device instance found above the start of the range — pick a lower starting block.",
        );
    },
    onError: (e) =>
      setError(formatApiError(e, "Failed to suggest a device instance")),
  });

  const numOrNull = (v: string): number | null =>
    v.trim() === "" ? null : Number(v.trim());

  const mut = useMutation({
    mutationFn: () => {
      const shared = {
        vendor_id: numOrNull(vendorId),
        vendor_name: vendorName,
        device_name: deviceName,
        model_name: modelName,
        firmware_rev: firmware,
        location,
        max_apdu: numOrNull(maxApdu),
        segmentation_supported: (segmentation ||
          null) as BACnetSegmentation | null,
        network_number: numOrNull(networkNumber),
        udp_port: Number(udpPort.trim() || BACNET_DEFAULT_PORT),
        is_bbmd: isBbmd,
        is_foreign_device: isForeign,
        seen_via: seenVia as BACnetDeviceSource,
        notes,
      };
      if (mode === "edit" && device) {
        const body: BACnetDeviceUpdate = {
          ...shared,
          ip_address_id: ipAddressId ?? undefined,
          device_instance: Number(instance.trim()),
        };
        return bacnetApi.updateDevice(device.id, body);
      }
      const body: BACnetDeviceCreate = {
        ...shared,
        ip_address_id: ipAddressId as string,
        device_instance: Number(instance.trim()),
      };
      return bacnetApi.createDevice(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["bacnet-devices"] });
      qc.invalidateQueries({ queryKey: ["bacnet-bbmds"] });
      onClose();
    },
    onError: (e) => setError(formatApiError(e, "Failed to save device")),
  });

  const instanceValid = /^\d+$/.test(instance.trim());
  const canSubmit = !!ipAddressId && instanceValid && !mut.isPending;

  return (
    <Modal
      title={mode === "create" ? "New BACnet device" : "Edit BACnet device"}
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
        <Field label="IPAM address">
          {ipLabel && (
            <p className="text-[11px] text-muted-foreground">
              Currently: <span className="font-mono">{ipLabel}</span>
            </p>
          )}
          <IPAddressPicker
            value={ipAddressId}
            onChange={(id, label) => {
              setIpAddressId(id);
              setIpLabel(label);
            }}
          />
        </Field>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Device instance">
            <div className="flex gap-2">
              <input
                className={`${inputCls} font-mono`}
                inputMode="numeric"
                value={instance}
                onChange={(e) => setInstance(e.target.value)}
                placeholder="0 – 4194302"
                required
              />
              <button
                type="button"
                onClick={() => nextInstanceMut.mutate()}
                disabled={nextInstanceMut.isPending}
                className="flex-shrink-0 rounded-md border px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
                title="Suggest the lowest free instance number"
              >
                {nextInstanceMut.isPending ? "…" : "Suggest"}
              </button>
            </div>
            <p className="text-[11px] text-muted-foreground">
              Unique across the whole internetwork. The suggestion is advisory —
              it is not reserved, so a concurrent commissioning can still take
              it first.
            </p>
          </Field>
          <Field label="Device name">
            <input
              className={inputCls}
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              placeholder="e.g. AHU-3 controller"
            />
          </Field>
          <Field label="Vendor ID (ASHRAE)">
            <input
              className={inputCls}
              inputMode="numeric"
              value={vendorId}
              onChange={(e) => setVendorId(e.target.value)}
              placeholder="e.g. 5"
            />
          </Field>
          <Field label="Vendor name">
            <input
              className={inputCls}
              value={vendorName}
              onChange={(e) => setVendorName(e.target.value)}
            />
          </Field>
          <Field label="Model">
            <input
              className={inputCls}
              value={modelName}
              onChange={(e) => setModelName(e.target.value)}
            />
          </Field>
          <Field label="Firmware revision">
            <input
              className={inputCls}
              value={firmware}
              onChange={(e) => setFirmware(e.target.value)}
            />
          </Field>
          <Field label="Location">
            <input
              className={inputCls}
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              placeholder="e.g. Level 3 plant room"
            />
          </Field>
          <Field label="Max APDU (octets)">
            <input
              className={inputCls}
              inputMode="numeric"
              value={maxApdu}
              onChange={(e) => setMaxApdu(e.target.value)}
              placeholder="e.g. 1476"
            />
          </Field>
          <Field label="Segmentation">
            <select
              className={inputCls}
              value={segmentation}
              onChange={(e) => setSegmentation(e.target.value)}
            >
              <option value="">Unknown</option>
              {SEGMENTATION_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </Field>
          <Field label="BACnet network number">
            <input
              className={inputCls}
              inputMode="numeric"
              value={networkNumber}
              onChange={(e) => setNetworkNumber(e.target.value)}
              placeholder="1 – 65534"
            />
          </Field>
          <Field label="UDP port">
            <input
              className={inputCls}
              inputMode="numeric"
              value={udpPort}
              onChange={(e) => setUdpPort(e.target.value)}
            />
          </Field>
          <Field label="Source">
            <select
              className={inputCls}
              value={seenVia}
              onChange={(e) => setSeenVia(e.target.value)}
            >
              {Object.entries(SOURCE_LABELS).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <div className="space-y-2 rounded-md border p-3">
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={isBbmd}
              onChange={(e) => {
                setIsBbmd(e.target.checked);
                if (e.target.checked) setIsForeign(false);
              }}
              className="mt-0.5"
            />
            <span>
              Broadcast Distribution Device (BBMD)
              <span className="block text-[11px] text-muted-foreground">
                Forwards BACnet broadcasts between IP subnets. Exactly one per
                subnet.
              </span>
            </span>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={isForeign}
              onChange={(e) => {
                setIsForeign(e.target.checked);
                if (e.target.checked) setIsBbmd(false);
              }}
              className="mt-0.5"
            />
            <span>
              Foreign device
              <span className="block text-[11px] text-muted-foreground">
                Registers with a remote BBMD because its own subnet has none. A
                device is one or the other, never both.
              </span>
            </span>
          </label>
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
