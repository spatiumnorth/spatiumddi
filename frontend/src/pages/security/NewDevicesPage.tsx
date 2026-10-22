import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
  Ban,
  ListChecks,
  Trash2,
  Plus,
  History,
} from "lucide-react";

import {
  newDeviceApi,
  ipamApi,
  type NewDeviceSighting,
  type NewDeviceClassification,
  type NewDeviceSource,
  type NewDeviceAllowlistEntry,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { Pager } from "@/components/ui/pager";
import { errMsg, inputCls } from "@/pages/dhcp/_shared";
import { useModuleOn } from "@/hooks/useModuleOn";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const PAGE_SIZE = 100;

const CLASSIFICATIONS: {
  value: NewDeviceClassification;
  label: string;
}[] = [
  { value: "new", label: "New" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "known", label: "Known" },
];

const SOURCE_LABELS: Record<NewDeviceSource, string> = {
  dhcp_lease: "DHCP lease",
  snmp: "SNMP",
  sweep: "Sweep",
  l2_sniff: "L2 sniff",
};

const SOURCE_COLORS: Record<NewDeviceSource, string> = {
  dhcp_lease: "bg-blue-500/10 text-blue-700 dark:text-blue-400",
  snmp: "bg-violet-500/10 text-violet-700 dark:text-violet-400",
  sweep: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
  l2_sniff: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
};

function SourcePill({ source }: { source: NewDeviceSource }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${SOURCE_COLORS[source]}`}
    >
      {SOURCE_LABELS[source] ?? source}
    </span>
  );
}

// Relative "time ago" for the Seen column. Cheap, no dependency.
function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  return `${days}d ago`;
}

export function NewDevicesPage() {
  // #1341 — a read-only user is offered no write it would be refused:
  // the router asks write on 'ip_address'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "ip_address"),
    "Requires write permission on IP addresses",
  );
  const qc = useQueryClient();

  const [classification, setClassification] =
    useState<NewDeviceClassification>("new");
  const [subnetId, setSubnetId] = useState("");
  const [includeRandomized, setIncludeRandomized] = useState(false);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const [showAllowlist, setShowAllowlist] = useState(false);
  const [showBaseline, setShowBaseline] = useState(false);
  const [showAddAllowlist, setShowAddAllowlist] = useState(false);
  const [showBlock, setShowBlock] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // #601 — the "also quarantine upstream" affordance in the block modal
  // only makes sense when the active block-sync module is enabled.
  const blockSyncEnabled = useModuleOn("security.block_sync");
  // #2134 — the DHCP half of Block writes dhcp_mac_block rows, which only
  // exist while core.dhcp is on. With it off the action survives only as the
  // upstream quarantine (when block-sync is on), and is hidden otherwise.
  const dhcpOn = useModuleOn("core.dhcp");
  const canBlock = dhcpOn || blockSyncEnabled;

  const summaryQ = useQuery({
    queryKey: ["new-devices", "summary"],
    queryFn: newDeviceApi.summary,
    refetchInterval: 30_000,
  });

  // Subnets power the filter dropdown. Best-effort — if it fails the
  // filter just stays empty.
  const subnetsQ = useQuery({
    queryKey: ["new-devices", "subnets"],
    queryFn: () => ipamApi.listSubnets(),
    staleTime: 5 * 60 * 1000,
  });

  const sightingsQ = useQuery({
    queryKey: [
      "new-devices",
      "sightings",
      classification,
      subnetId,
      includeRandomized,
      search,
      page,
    ],
    queryFn: () =>
      newDeviceApi.listSightings({
        classification,
        subnet_id: subnetId || undefined,
        include_randomized: includeRandomized,
        search: search.trim() || undefined,
        page,
        page_size: PAGE_SIZE,
      }),
    placeholderData: (prev) => prev,
  });

  const rows = sightingsQ.data?.items ?? [];
  const total = sightingsQ.data?.total ?? 0;

  function invalidateAll() {
    qc.invalidateQueries({ queryKey: ["new-devices"] });
  }

  function resetToFirstPage() {
    setPage(1);
    setSelected(new Set());
  }

  const allSelected = rows.length > 0 && rows.every((r) => selected.has(r.id));
  const someSelected = selected.size > 0;

  function toggleRow(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }
  function toggleAll() {
    setSelected((prev) => {
      if (rows.every((r) => prev.has(r.id))) {
        const next = new Set(prev);
        rows.forEach((r) => next.delete(r.id));
        return next;
      }
      const next = new Set(prev);
      rows.forEach((r) => next.add(r.id));
      return next;
    });
  }

  const selectedRows = useMemo(
    () => rows.filter((r) => selected.has(r.id)),
    [rows, selected],
  );

  // Bulk acknowledge — fan out per selected row.
  const ackMut = useMutation({
    mutationFn: async () => {
      setActionError(null);
      const results = await Promise.allSettled(
        selectedRows.map((r) => newDeviceApi.acknowledge(r.id)),
      );
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0)
        throw new Error(
          `${failed} of ${selectedRows.length} failed to acknowledge`,
        );
    },
    onSuccess: () => {
      invalidateAll();
      setSelected(new Set());
    },
    onError: (e) => setActionError(errMsg(e, "Acknowledge failed")),
  });

  const baselineMut = useMutation({
    mutationFn: newDeviceApi.baseline,
    onSuccess: () => {
      invalidateAll();
      setShowBaseline(false);
    },
    onError: (e) => setActionError(errMsg(e, "Baseline import failed")),
  });

  const moduleSummary = summaryQ.data;

  return (
    <div className="space-y-4 p-4 md:p-6">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1">
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <ShieldQuestion className="h-5 w-5 flex-shrink-0" />
            New device watch
          </h1>
          <p className="text-sm text-muted-foreground">
            arpwatch-style first-seen MAC tracking — triage previously-unseen
            devices across DHCP, SNMP, sweep and L2 sources.
          </p>
        </div>
        <HeaderButton
          icon={RefreshCw}
          iconClassName={sightingsQ.isFetching ? "animate-spin" : undefined}
          onClick={() => invalidateAll()}
          disabled={sightingsQ.isFetching}
        >
          Refresh
        </HeaderButton>
        <HeaderButton icon={ListChecks} onClick={() => setShowAllowlist(true)}>
          Allowlist
        </HeaderButton>
        <HeaderButton
          icon={History}
          onClick={() => setShowBaseline(true)}
          {...writeGate}
        >
          Run baseline import
        </HeaderButton>
      </div>

      {/* Summary counts */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <SummaryCard
          label="New"
          value={moduleSummary?.new_count}
          sub={
            moduleSummary != null
              ? `${moduleSummary.new_last_24h} in 24h`
              : undefined
          }
          tone="bad"
        />
        <SummaryCard
          label="New (randomized)"
          value={moduleSummary?.new_randomized_count}
          sub="hidden by default"
        />
        <SummaryCard
          label="Acknowledged"
          value={moduleSummary?.acknowledged_count}
        />
        <SummaryCard label="Known" value={moduleSummary?.known_count} />
        <SummaryCard label="Allowlist" value={moduleSummary?.allowlist_count} />
        <SummaryCard
          label="New (24h)"
          value={moduleSummary?.new_last_24h}
          tone="bad"
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex overflow-hidden rounded-md border">
          {CLASSIFICATIONS.map((c) => (
            <button
              key={c.value}
              type="button"
              onClick={() => {
                setClassification(c.value);
                resetToFirstPage();
              }}
              className={`px-3 py-1.5 text-sm ${
                classification === c.value
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted"
              }`}
            >
              {c.label}
            </button>
          ))}
        </div>

        <select
          value={subnetId}
          onChange={(e) => {
            setSubnetId(e.target.value);
            resetToFirstPage();
          }}
          className="rounded-md border bg-background px-2 py-1.5 text-sm"
        >
          <option value="">All subnets</option>
          {(subnetsQ.data ?? []).map((s) => (
            <option key={s.id} value={s.id}>
              {s.network}
              {s.name ? ` · ${s.name}` : ""}
            </option>
          ))}
        </select>

        <label className="flex cursor-pointer items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={includeRandomized}
            onChange={(e) => {
              setIncludeRandomized(e.target.checked);
              resetToFirstPage();
            }}
          />
          <span>Include randomized MACs</span>
        </label>

        <input
          placeholder="Search IP, MAC, vendor…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          className="w-64 rounded-md border bg-background px-2 py-1.5 text-sm"
        />

        <span className="ml-auto text-xs text-muted-foreground">
          {total} sighting{total === 1 ? "" : "s"}
        </span>
      </div>

      {actionError && (
        <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          {actionError}
        </div>
      )}
      {actionNotice && (
        <div className="flex items-start justify-between gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-400">
          <span>{actionNotice}</span>
          <button
            type="button"
            onClick={() => setActionNotice(null)}
            className="text-emerald-700/70 hover:text-emerald-700 dark:text-emerald-400/70"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Bulk toolbar — slides in when rows are selected. */}
      {someSelected && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 px-3 py-2">
          <span className="text-sm font-medium">{selected.size} selected</span>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <HeaderButton
              icon={ShieldCheck}
              onClick={() => ackMut.mutate()}
              disabled={ackMut.isPending}
              {...writeGate}
            >
              Acknowledge
            </HeaderButton>
            <HeaderButton
              icon={Plus}
              onClick={() => {
                setActionError(null);
                setShowAddAllowlist(true);
              }}
              {...writeGate}
            >
              Add to allowlist
            </HeaderButton>
            {canBlock && (
              <HeaderButton
                icon={Ban}
                variant="destructive"
                onClick={() => {
                  setActionError(null);
                  setShowBlock(true);
                }}
                {...writeGate}
              >
                {dhcpOn ? "Block" : "Quarantine upstream"}
              </HeaderButton>
            )}
          </div>
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border">
        {rows.length === 0 ? (
          <p className="p-8 text-center text-sm text-muted-foreground">
            {sightingsQ.isLoading
              ? "Loading…"
              : "No sightings match these filters."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[960px] text-xs">
              <thead>
                <tr className="border-b bg-muted/30">
                  <th className="w-8 px-3 py-2">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={toggleAll}
                      aria-label="Select all"
                    />
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    IP
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    MAC
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Vendor
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Subnet
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Source
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    First seen
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Seen
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    className={`border-b last:border-0 ${
                      selected.has(r.id) ? "bg-primary/5" : ""
                    }`}
                  >
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        checked={selected.has(r.id)}
                        onChange={() => toggleRow(r.id)}
                        aria-label={`Select ${r.mac_address}`}
                      />
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono">
                      {r.ip_address}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <span className="break-all font-mono">
                        {r.mac_address}
                      </span>
                      {r.is_randomized && (
                        <span className="ml-1.5 rounded bg-muted px-1 py-0.5 text-[10px] text-muted-foreground">
                          random
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {r.oui_vendor ?? "—"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                      {r.subnet_name ?? "—"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <SourcePill source={r.source} />
                    </td>
                    <td
                      className="whitespace-nowrap px-3 py-2 text-muted-foreground"
                      title={new Date(r.first_seen).toLocaleString()}
                    >
                      {timeAgo(r.first_seen)}
                    </td>
                    <td
                      className="whitespace-nowrap px-3 py-2 text-muted-foreground"
                      title={new Date(r.last_seen).toLocaleString()}
                    >
                      {timeAgo(r.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="flex justify-end">
        <Pager
          page={page}
          total={total}
          pageSize={PAGE_SIZE}
          onChange={(p) => {
            setPage(p);
            setSelected(new Set());
          }}
        />
      </div>

      {/* Modals */}
      {showAllowlist && (
        <AllowlistModal onClose={() => setShowAllowlist(false)} />
      )}
      {showAddAllowlist && (
        <AddSelectedToAllowlistModal
          sightings={selectedRows}
          onClose={() => setShowAddAllowlist(false)}
          onDone={() => {
            invalidateAll();
            setSelected(new Set());
            setShowAddAllowlist(false);
          }}
          onError={(m) => setActionError(m)}
        />
      )}
      {showBlock && canBlock && (
        <BlockSelectedModal
          dhcpOn={dhcpOn}
          sightings={selectedRows}
          blockSyncEnabled={blockSyncEnabled}
          onClose={() => setShowBlock(false)}
          onDone={(notice) => {
            invalidateAll();
            setSelected(new Set());
            setShowBlock(false);
            setActionNotice(notice ?? null);
          }}
          onError={(m) => setActionError(m)}
        />
      )}
      <ConfirmModal
        open={showBaseline}
        title="Run baseline import"
        message={
          <>
            This marks every currently-observed MAC on the network as{" "}
            <strong>known</strong>, so the review queue starts clean. Run this
            once after enabling the module, then arm — anything seen afterwards
            shows up as a new device. Existing acknowledgements are preserved.
          </>
        }
        confirmLabel="Mark fleet as known"
        loading={baselineMut.isPending}
        onConfirm={() => baselineMut.mutate()}
        onClose={() => setShowBaseline(false)}
      />
    </div>
  );
}

function SummaryCard({
  label,
  value,
  sub,
  tone = "default",
}: {
  label: string;
  value: number | undefined;
  sub?: string;
  tone?: "default" | "bad";
}) {
  return (
    <div className="rounded-lg border bg-card p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
      <p
        className={`mt-1 text-2xl font-bold tabular-nums ${
          tone === "bad" && (value ?? 0) > 0
            ? "text-red-600 dark:text-red-400"
            : ""
        }`}
      >
        {value ?? "—"}
      </p>
      {sub && <p className="text-[11px] text-muted-foreground">{sub}</p>}
    </div>
  );
}

// ── Allowlist management modal ────────────────────────────────────────
function AllowlistModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  // Allowlist writes take write on 'ip_address' (new_devices/router.py);
  // the list itself stays readable.
  const writeGate = permissionGate(
    usePermissions().can("write", "ip_address"),
    "Requires write permission on IP addresses",
  );
  const [mac, setMac] = useState("");
  const [oui, setOui] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [del, setDel] = useState<NewDeviceAllowlistEntry | null>(null);

  const listQ = useQuery({
    queryKey: ["new-devices", "allowlist"],
    queryFn: newDeviceApi.listAllowlist,
  });

  function invalidate() {
    qc.invalidateQueries({ queryKey: ["new-devices"] });
  }

  const addMut = useMutation({
    mutationFn: () =>
      newDeviceApi.addAllowlist({
        mac_address: mac.trim() || undefined,
        oui_prefix: oui.trim() || undefined,
        note: note.trim() || undefined,
      }),
    onSuccess: () => {
      invalidate();
      setMac("");
      setOui("");
      setNote("");
      setError(null);
    },
    onError: (e) => setError(errMsg(e, "Failed to add allowlist entry")),
  });

  const virtMut = useMutation({
    mutationFn: newDeviceApi.addVirtDefaults,
    onSuccess: () => {
      invalidate();
      setError(null);
    },
    onError: (e) => setError(errMsg(e, "Failed to add virtualization OUIs")),
  });

  const delMut = useMutation({
    mutationFn: (id: string) => newDeviceApi.deleteAllowlist(id),
    onSuccess: () => {
      invalidate();
      setDel(null);
    },
  });

  const entries = listQ.data ?? [];

  return (
    <Modal title="Allowlist" onClose={onClose} wide>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Trusted MACs (or OUI prefixes for VMs/containers) are reclassified as
          known and never page you. Provide a full MAC or an OUI prefix.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            addMut.mutate();
          }}
          className="grid grid-cols-1 gap-2 sm:grid-cols-4"
        >
          <input
            className={`${inputCls} font-mono sm:col-span-1`}
            placeholder="MAC (aa:bb:cc:…)"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
          />
          <input
            className={`${inputCls} font-mono sm:col-span-1`}
            placeholder="OUI (aa:bb:cc)"
            value={oui}
            onChange={(e) => setOui(e.target.value)}
          />
          <input
            className={`${inputCls} sm:col-span-1`}
            placeholder="Note (optional)"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <button
            type="submit"
            disabled={addMut.isPending || (!mac.trim() && !oui.trim())}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50 sm:col-span-1"
            {...writeGate}
          >
            Add
          </button>
        </form>

        <div className="flex items-center justify-between">
          <HeaderButton
            icon={Plus}
            onClick={() => virtMut.mutate()}
            disabled={virtMut.isPending}
            {...writeGate}
          >
            Add common virtualization OUIs
          </HeaderButton>
          <span className="text-xs text-muted-foreground">
            {entries.length} entr{entries.length === 1 ? "y" : "ies"}
          </span>
        </div>

        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}

        <div className="max-h-72 overflow-auto rounded-md border">
          {entries.length === 0 ? (
            <p className="p-6 text-center text-sm text-muted-foreground">
              No allowlist entries yet.
            </p>
          ) : (
            <table className="w-full min-w-[520px] text-xs">
              <thead>
                <tr className="border-b bg-muted/30">
                  <th className="px-3 py-2 text-left font-medium">MAC</th>
                  <th className="px-3 py-2 text-left font-medium">OUI</th>
                  <th className="px-3 py-2 text-left font-medium">Note</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {entries.map((en) => (
                  <tr key={en.id} className="border-b last:border-0">
                    <td className="break-all px-3 py-2 font-mono">
                      {en.mac_address ?? "—"}
                    </td>
                    <td className="break-all px-3 py-2 font-mono">
                      {en.oui_prefix ?? "—"}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {en.note || "—"}
                      {en.is_builtin && (
                        <span className="ml-1.5 rounded bg-muted px-1 py-0.5 text-[10px]">
                          built-in
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        onClick={() => setDel(en)}
                        className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-40"
                        title="Remove"
                        {...writeGate}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <ConfirmModal
        open={!!del}
        title="Remove allowlist entry"
        message={
          <>
            Remove{" "}
            <span className="font-mono">
              {del?.mac_address ?? del?.oui_prefix}
            </span>{" "}
            from the allowlist? Matching devices will be re-evaluated and may
            re-appear in the new-device queue.
          </>
        }
        tone="destructive"
        confirmLabel="Remove"
        loading={delMut.isPending}
        onConfirm={() => del && delMut.mutate(del.id)}
        onClose={() => setDel(null)}
      />
    </Modal>
  );
}

// ── Add selected sightings to allowlist (by MAC) ──────────────────────
function AddSelectedToAllowlistModal({
  sightings,
  onClose,
  onDone,
  onError,
}: {
  sightings: NewDeviceSighting[];
  onClose: () => void;
  onDone: () => void;
  onError: (msg: string) => void;
}) {
  const [note, setNote] = useState("");
  const mut = useMutation({
    mutationFn: async () => {
      const results = await Promise.allSettled(
        sightings.map((s) =>
          newDeviceApi.addAllowlist({
            mac_address: s.mac_address,
            note: note.trim() || undefined,
          }),
        ),
      );
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0)
        throw new Error(`${failed} of ${sightings.length} failed`);
    },
    onSuccess: onDone,
    onError: (e) => onError(errMsg(e, "Failed to add to allowlist")),
  });

  return (
    <Modal title="Add to allowlist" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        <p className="text-sm text-muted-foreground">
          Allowlist {sightings.length} MAC
          {sightings.length === 1 ? "" : "s"} — they'll be marked known and
          won't page you again.
        </p>
        <input
          className={inputCls}
          placeholder="Note (optional)"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
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
            disabled={mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Adding…" : "Add to allowlist"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── Block selected MACs across DHCP server groups ─────────────────────
function BlockSelectedModal({
  sightings,
  dhcpOn,
  blockSyncEnabled,
  onClose,
  onDone,
  onError,
}: {
  sightings: NewDeviceSighting[];
  dhcpOn: boolean;
  blockSyncEnabled: boolean;
  onClose: () => void;
  onDone: (notice?: string) => void;
  onError: (msg: string) => void;
}) {
  const [reason, setReason] = useState("");
  // #601 — optionally also push an L2 quarantine to armed UniFi block-sync
  // targets, not just starve the device of DHCP.
  const [blockUpstream, setBlockUpstream] = useState(false);
  const mut = useMutation({
    mutationFn: async () => {
      const results = await Promise.allSettled(
        sightings.map((s) =>
          newDeviceApi.block({
            mac_address: s.mac_address,
            reason: reason.trim() || undefined,
            block_upstream: blockUpstream || !dhcpOn || undefined,
          }),
        ),
      );
      const rejected = results.filter(
        (r): r is PromiseRejectedResult => r.status === "rejected",
      );
      if (rejected.length > 0)
        // Carry the server's reason: with DHCP off a refusal (no permission,
        // no armed target) is the whole answer, not a partial failure.
        throw new Error(
          `${rejected.length} of ${sightings.length} failed to block: ${errMsg(
            rejected[0].reason,
            "unknown error",
          )}`,
        );
      // Summarise the upstream outcome so the operator knows whether the
      // L2 quarantine landed or is waiting on a second approver.
      let upstreamCreated = 0;
      let upstreamQueued = 0;
      for (const r of results) {
        if (r.status !== "fulfilled") continue;
        if (r.value.upstream_block_created) upstreamCreated += 1;
        if (r.value.upstream_change_request_id) upstreamQueued += 1;
      }
      const parts: string[] = [];
      if (upstreamCreated > 0)
        parts.push(`${upstreamCreated} upstream quarantine(s) pushed`);
      if (upstreamQueued > 0)
        parts.push(
          `${upstreamQueued} upstream quarantine(s) queued for approval`,
        );
      return parts.length > 0 ? parts.join("; ") + "." : undefined;
    },
    onSuccess: (notice) => onDone(notice),
    onError: (e) => onError(errMsg(e, "Failed to block")),
  });

  return (
    <Modal
      title={dhcpOn ? "Block MACs" : "Quarantine MACs upstream"}
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        <p className="text-sm text-muted-foreground">
          {dhcpOn ? (
            <>
              Block {sightings.length} MAC
              {sightings.length === 1 ? "" : "s"} in <strong>every</strong> DHCP
              server group. Blocked devices can't obtain a lease.
            </>
          ) : (
            <>
              Quarantine {sightings.length} MAC
              {sightings.length === 1 ? "" : "s"} upstream (UniFi block-sta) on
              armed block-sync targets. May queue for two-person approval.
            </>
          )}
        </p>
        <div className="max-h-32 overflow-auto rounded-md border bg-muted/30 p-2">
          {sightings.map((s) => (
            <div key={s.id} className="break-all font-mono text-xs">
              {s.mac_address}
            </div>
          ))}
        </div>
        <input
          className={inputCls}
          placeholder="Reason (optional)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        {dhcpOn && blockSyncEnabled && (
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={blockUpstream}
              onChange={(e) => setBlockUpstream(e.target.checked)}
            />
            <span>
              Also quarantine upstream (UniFi block-sta)
              <span className="block text-xs text-muted-foreground">
                Pushes an L2 client quarantine to armed UniFi block-sync
                targets, not only a DHCP block. May queue for two-person
                approval.
              </span>
            </span>
          </label>
        )}
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
            disabled={mut.isPending}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {mut.isPending ? "Blocking…" : dhcpOn ? "Block" : "Quarantine"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
