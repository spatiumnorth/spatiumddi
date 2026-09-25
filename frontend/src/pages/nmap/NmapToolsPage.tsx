import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Radar, Trash2 } from "lucide-react";
import { type NmapScanRead, nmapApi } from "@/lib/api";
import { useModalDialog } from "@/components/ui/use-draggable-modal";
import { cn } from "@/lib/utils";
import { NmapScanForm } from "./NmapScanForm";
import { NmapScanLiveViewer } from "./NmapScanLiveViewer";
import { NmapResultPanel } from "./NmapResultPanel";
import { ConfirmDeleteScanModal } from "./ConfirmDeleteScanModal";
import { humanTime } from "@/pages/network/_shared";

type RightTab = "live" | "history" | "result";

export function NmapToolsPage() {
  const [activeScan, setActiveScan] = useState<NmapScanRead | null>(null);
  const [displayScan, setDisplayScan] = useState<NmapScanRead | null>(null);
  const [tab, setTab] = useState<RightTab>("history");

  const onScanStarted = (s: NmapScanRead) => {
    setActiveScan(s);
    setTab("live");
  };

  const onScanComplete = (s: NmapScanRead) => {
    setDisplayScan(s);
    setActiveScan(null);
    setTab("result");
  };

  const onSelectFromHistory = (s: NmapScanRead) => {
    setDisplayScan(s);
    setTab("result");
  };

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-center gap-2">
          <Radar className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold">Nmap scanner</h1>
        </div>
        <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
          Run nmap against any IPv4 / IPv6 host, CIDR, or hostname from the
          SpatiumDDI host perspective. Output streams live; CIDR targets expand
          to a multi-host result panel under the chosen preset.
        </p>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-lg border bg-card p-4">
            <h2 className="mb-3 text-sm font-medium">New scan</h2>
            <NmapScanForm onScanStarted={onScanStarted} />
          </div>

          <div className="flex flex-col rounded-lg border bg-card">
            <div className="flex items-center gap-1 border-b px-2">
              <TabButton
                active={tab === "live"}
                onClick={() => setTab("live")}
                badge={activeScan ? "•" : undefined}
              >
                Live
              </TabButton>
              <TabButton
                active={tab === "history"}
                onClick={() => setTab("history")}
              >
                History
              </TabButton>
              <TabButton
                active={tab === "result"}
                onClick={() => setTab("result")}
                disabled={!displayScan}
              >
                Last result
              </TabButton>
            </div>
            <div className="p-4">
              {tab === "live" && (
                <LiveTab
                  activeScan={activeScan}
                  onComplete={onScanComplete}
                  onCancelClose={() => setActiveScan(null)}
                />
              )}
              {tab === "history" && (
                <HistoryTab onSelect={onSelectFromHistory} />
              )}
              {tab === "result" && (
                <ResultTab
                  scan={displayScan}
                  onClear={() => setDisplayScan(null)}
                />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function TabButton({
  active,
  disabled,
  badge,
  onClick,
  children,
}: {
  active: boolean;
  disabled?: boolean;
  badge?: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "border-b-2 px-3 py-2 text-xs font-medium transition-colors",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground",
        disabled && "cursor-not-allowed opacity-40 hover:text-muted-foreground",
      )}
    >
      {children}
      {badge && (
        <span className="ml-1 inline-flex h-1.5 w-1.5 rounded-full bg-blue-500 align-middle" />
      )}
    </button>
  );
}

function LiveTab({
  activeScan,
  onComplete,
  onCancelClose,
}: {
  activeScan: NmapScanRead | null;
  onComplete: (s: NmapScanRead) => void;
  onCancelClose: () => void;
}) {
  if (!activeScan) {
    return (
      <p className="text-xs text-muted-foreground">
        No scan running — kick one off on the left. Live output will stream
        here.
      </p>
    );
  }
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        Live output — <span className="font-mono">{activeScan.target_ip}</span>
      </p>
      <NmapScanLiveViewer
        scanId={activeScan.id}
        onClose={onCancelClose}
        onComplete={onComplete}
      />
    </div>
  );
}

function ResultTab({
  scan,
  onClear,
}: {
  scan: NmapScanRead | null;
  onClear: () => void;
}) {
  // Re-fetch so we always render the freshest persisted state — the
  // History click might pass an item from a list query that hasn't
  // refreshed since the scan completed, so the summary may be stale.
  const { data } = useQuery({
    enabled: !!scan,
    queryKey: ["nmap-scan", scan?.id],
    queryFn: () => nmapApi.getScan(scan!.id),
    initialData: scan ?? undefined,
  });
  if (!data) {
    return (
      <p className="text-xs text-muted-foreground">
        Nothing to show yet. Click a row in History or run a fresh scan.
      </p>
    );
  }
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {humanTime(data.created_at)} —{" "}
          <span className="font-mono">{data.target_ip}</span> · preset{" "}
          {data.preset} · {data.status}
        </p>
        <button
          type="button"
          onClick={onClear}
          className="text-[11px] text-muted-foreground hover:text-foreground"
        >
          Clear
        </button>
      </div>
      {data.error_message && (
        <p className="rounded-md border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
          {data.error_message}
        </p>
      )}
      {data.summary ? (
        <NmapResultPanel scan={data} />
      ) : (
        <p className="text-xs text-muted-foreground italic">
          No parsed summary on this scan (it may have been cancelled before
          producing output).
        </p>
      )}
    </div>
  );
}

function HistoryTab({ onSelect }: { onSelect: (s: NmapScanRead) => void }) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [pendingSingle, setPendingSingle] = useState<NmapScanRead | null>(null);
  const [pendingBulk, setPendingBulk] = useState<NmapScanRead[] | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["nmap-scans", "recent"],
    queryFn: () => nmapApi.listScans({ page_size: 50 }),
    refetchInterval: 5000,
  });
  const items = data?.items ?? [];

  // Drop selections that no longer exist (e.g. after a refresh).
  useEffect(() => {
    if (selected.size === 0) return;
    const ids = new Set(items.map((s) => s.id));
    let changed = false;
    const next = new Set<string>();
    for (const id of selected) {
      if (ids.has(id)) next.add(id);
      else changed = true;
    }
    if (changed) setSelected(next);
  }, [items, selected]);

  const singleDelete = useMutation({
    mutationFn: (id: string) => nmapApi.cancelScan(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["nmap-scans"] });
      setPendingSingle(null);
    },
  });

  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => nmapApi.bulkDeleteScans(ids),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["nmap-scans"] });
      setSelected(new Set());
      setPendingBulk(null);
    },
  });

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const allChecked = items.length > 0 && selected.size === items.length;
  const someChecked = selected.size > 0 && !allChecked;
  const toggleAll = () => {
    if (allChecked) {
      setSelected(new Set());
    } else {
      setSelected(new Set(items.map((s) => s.id)));
    }
  };

  if (isLoading) {
    return (
      <p className="inline-flex items-center gap-2 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" /> Loading recent scans…
      </p>
    );
  }
  if (isError) {
    return (
      <p className="text-xs text-destructive">Failed to load recent scans.</p>
    );
  }
  if (items.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        No scans yet — kick one off on the left.
      </p>
    );
  }

  const selectedItems = items.filter((s) => selected.has(s.id));

  return (
    <div className="space-y-2">
      {selected.size > 0 && (
        <div className="flex items-center justify-between rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs">
          <span>
            {selected.size} scan{selected.size === 1 ? "" : "s"} selected
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setSelected(new Set())}
              className="rounded border px-2 py-0.5 text-[11px] hover:bg-accent"
            >
              Clear
            </button>
            <button
              type="button"
              onClick={() => setPendingBulk(selectedItems)}
              disabled={bulkDelete.isPending}
              className="inline-flex items-center gap-1 rounded border border-destructive/40 px-2 py-0.5 text-[11px] text-destructive hover:bg-destructive/10 disabled:opacity-60"
            >
              <Trash2 className="h-3 w-3" />
              Delete {selected.size}
            </button>
          </div>
        </div>
      )}

      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[520px] text-xs">
          <thead>
            <tr className="border-b bg-muted/30">
              <th className="w-8 px-2 py-1.5 text-left">
                <input
                  type="checkbox"
                  aria-label="Select all"
                  checked={allChecked}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked;
                  }}
                  onChange={toggleAll}
                />
              </th>
              <th className="px-2 py-1.5 text-left">When</th>
              <th className="px-2 py-1.5 text-left">Target</th>
              <th className="px-2 py-1.5 text-left">Preset</th>
              <th className="px-2 py-1.5 text-left">Status</th>
              <th className="px-2 py-1.5 text-left">Open</th>
              <th className="px-2 py-1.5"></th>
            </tr>
          </thead>
          <tbody>
            {items.map((s) => {
              const open =
                s.summary?.ports.filter((p) => p.state === "open").length ?? 0;
              const isSel = selected.has(s.id);
              return (
                <tr
                  key={s.id}
                  onClick={() => onSelect(s)}
                  className={cn(
                    "cursor-pointer border-b last:border-0 hover:bg-muted/20",
                    isSel && "bg-amber-500/5",
                  )}
                >
                  <td
                    className="px-2 py-1"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <input
                      type="checkbox"
                      aria-label={`Select scan of ${s.target_ip}`}
                      checked={isSel}
                      onChange={() => toggle(s.id)}
                    />
                  </td>
                  <td className="px-2 py-1 text-muted-foreground">
                    {humanTime(s.created_at)}
                  </td>
                  <td className="px-2 py-1 font-mono">{s.target_ip}</td>
                  <td className="px-2 py-1">{s.preset}</td>
                  <td className="px-2 py-1">{s.status}</td>
                  <td className="px-2 py-1 tabular-nums">{open}</td>
                  <td
                    className="px-2 py-1 text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      type="button"
                      title={
                        s.status === "queued" || s.status === "running"
                          ? "Cancel scan"
                          : "Delete scan"
                      }
                      disabled={singleDelete.isPending}
                      onClick={() => setPendingSingle(s)}
                      className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:opacity-50"
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

      {pendingSingle && (
        <ConfirmDeleteScanModal
          scan={pendingSingle}
          pending={singleDelete.isPending}
          onConfirm={() => singleDelete.mutate(pendingSingle.id)}
          onClose={() => setPendingSingle(null)}
        />
      )}
      {pendingBulk && (
        <ConfirmBulkDeleteModal
          scans={pendingBulk}
          pending={bulkDelete.isPending}
          onConfirm={() => bulkDelete.mutate(pendingBulk.map((s) => s.id))}
          onClose={() => setPendingBulk(null)}
        />
      )}
    </div>
  );
}

function ConfirmBulkDeleteModal({
  scans,
  pending,
  onConfirm,
  onClose,
}: {
  scans: NmapScanRead[];
  pending: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const inFlight = scans.filter(
    (s) => s.status === "queued" || s.status === "running",
  ).length;
  const terminal = scans.length - inFlight;
  const { dialogProps, titleProps } = useModalDialog(onClose);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
      <div
        {...dialogProps}
        className="w-full max-w-md rounded-lg border bg-card p-5 shadow-xl focus:outline-none"
      >
        <h3 {...titleProps} className="text-base font-semibold">
          Delete {scans.length} scan{scans.length === 1 ? "" : "s"}?
        </h3>
        <p className="mt-2 text-sm text-muted-foreground">
          {terminal > 0 && (
            <>
              {terminal} finished scan
              {terminal === 1 ? " will be" : "s will be"} permanently removed.
            </>
          )}
          {terminal > 0 && inFlight > 0 && " "}
          {inFlight > 0 && (
            <>
              {inFlight} running scan{inFlight === 1 ? "" : "s"} will be
              cancelled.
            </>
          )}
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={pending}
            className="inline-flex items-center gap-1.5 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-1.5 text-sm text-destructive hover:bg-destructive/20 disabled:opacity-50"
          >
            {pending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Trash2 className="h-3.5 w-3.5" />
            )}
            Delete {scans.length}
          </button>
        </div>
      </div>
    </div>
  );
}
