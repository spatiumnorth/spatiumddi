import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Download, Loader2, Trash2 } from "lucide-react";
import {
  applianceApprovalApi,
  type PcapCaptureCreate,
  type PcapCaptureRead,
  pcapApi,
} from "@/lib/api";
import { useModalDialog } from "@/components/ui/use-draggable-modal";
import { cn } from "@/lib/utils";
import { humanTime } from "@/pages/network/_shared";

type RightTab = "live" | "history" | "result";

// Curated BPF presets — DDI-relevant first. Clicking one fills the
// advanced filter field. (A larger library can follow; these cover the
// overwhelming majority of appliance troubleshooting.)
const BPF_PRESETS: { label: string; filter: string }[] = [
  { label: "DNS (53)", filter: "port 53" },
  { label: "DHCP (67/68)", filter: "port 67 or port 68" },
  { label: "DNS + DHCP", filter: "port 53 or port 67 or port 68" },
  { label: "ARP", filter: "arp" },
  { label: "ICMP", filter: "icmp or icmp6" },
  { label: "HTTP/HTTPS", filter: "port 80 or port 443" },
  { label: "TCP SYN only", filter: "tcp[tcpflags] & tcp-syn != 0" },
  { label: "NTP (123)", filter: "udp port 123" },
  { label: "VRRP", filter: "proto 112" },
  { label: "Exclude SSH", filter: "not port 22" },
];

function fmtBytes(n: number | null | undefined): string {
  if (!n) return "0 B";
  const u = ["B", "KiB", "MiB", "GiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

function isTerminal(s: PcapCaptureRead): boolean {
  return (
    s.status === "completed" ||
    s.status === "failed" ||
    s.status === "cancelled"
  );
}

// "Settled" = terminal AND the artifact question is resolved. A Stop
// flips status to `cancelled` immediately, but the partial .pcap lands a
// moment later (the server vantage finalizes after SIGTERM; the appliance
// vantage relays the upload through the supervisor). So for a cancel we
// keep waiting until has_artifact is true OR a grace window passes — that
// way the Download button appears right at Stop instead of looking absent.
const CANCEL_ARTIFACT_GRACE_MS = 20000;

function isSettled(s: PcapCaptureRead): boolean {
  if (!isTerminal(s)) return false; // queued / running
  // Terminal: a Stopped capture with no artifact yet is still finalizing —
  // wait out the grace window for the partial to land. Everything else
  // (completed, failed, cancelled-with-artifact) is fully settled.
  if (s.status === "cancelled" && !s.has_artifact) {
    const fin = s.finished_at ? Date.parse(s.finished_at) : 0;
    return fin > 0 && Date.now() - fin > CANCEL_ARTIFACT_GRACE_MS;
  }
  return true;
}

export function PacketCapturePage() {
  const [activeId, setActiveId] = useState<string | null>(null);
  const [displayId, setDisplayId] = useState<string | null>(null);
  const [tab, setTab] = useState<RightTab>("history");

  // Deep-link from the Fleet drilldown: /tools/pcap?vantage=appliance&appliance=<id>
  // prefills the form to capture on that appliance host.
  const [params] = useSearchParams();
  const initialVantage =
    params.get("vantage") === "appliance" && params.get("appliance")
      ? (params.get("appliance") as string)
      : "server";

  const onStarted = (c: PcapCaptureRead) => {
    setActiveId(c.id);
    setTab("live");
  };

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold">Packet capture</h1>
        </div>
        <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
          Run tcpdump on the control plane or an appliance host, watch live
          progress, and download the .pcap for Wireshark. Captures raw traffic
          (may include sensitive payloads) — every start and download is
          audited.
        </p>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-lg border bg-card p-4">
            <h2 className="mb-3 text-sm font-medium">New capture</h2>
            <CaptureForm
              onStarted={onStarted}
              initialVantage={initialVantage}
            />
          </div>

          <div className="flex flex-col rounded-lg border bg-card">
            <div className="flex items-center gap-1 border-b px-2">
              <TabButton
                active={tab === "live"}
                onClick={() => setTab("live")}
                live={!!activeId}
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
                disabled={!displayId}
              >
                Last result
              </TabButton>
            </div>
            <div className="p-4">
              {tab === "live" && (
                <LiveTab
                  captureId={activeId}
                  onComplete={(id) => {
                    setDisplayId(id);
                    setActiveId(null);
                    setTab("result");
                  }}
                />
              )}
              {tab === "history" && (
                <HistoryTab
                  onSelect={(c) => {
                    setDisplayId(c.id);
                    setTab("result");
                  }}
                />
              )}
              {tab === "result" && <ResultTab captureId={displayId} />}
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
  live,
  onClick,
  children,
}: {
  active: boolean;
  disabled?: boolean;
  live?: boolean;
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
      {live && (
        <span className="ml-1 inline-flex h-1.5 w-1.5 rounded-full bg-blue-500 align-middle" />
      )}
    </button>
  );
}

function CaptureForm({
  onStarted,
  initialVantage = "server",
}: {
  onStarted: (c: PcapCaptureRead) => void;
  initialVantage?: string;
}) {
  // vantage select value: "server" or an appliance UUID.
  const [vantage, setVantage] = useState<string>(initialVantage);
  const [iface, setIface] = useState<string>("any");
  // When the operator picks "Other…" in the interface dropdown, fall back to
  // a free-text field — udev doesn't name every host NIC (bridges, overlay /
  // VPN interfaces), and the host runner validates whatever name is typed.
  const [customIface, setCustomIface] = useState(false);
  const [filter, setFilter] = useState("");
  const [durationS, setDurationS] = useState<number | "">(60);
  const [maxPackets, setMaxPackets] = useState<number | "">(10000);
  const [maxMiB, setMaxMiB] = useState<number | "">(50);
  const [snaplen, setSnaplen] = useState<number | "">(256);
  const [promiscuous, setPromiscuous] = useState(false);

  const isAppliance = vantage !== "server";

  const { data: appliances } = useQuery({
    queryKey: ["pcap-appliances"],
    queryFn: () => applianceApprovalApi.list(),
  });
  const approved = (appliances ?? []).filter((a) => a.state === "approved");

  // Both vantages enumerate NICs now: server lists the worker's own
  // container NICs; appliance lists the host's real NICs (ens18, …) that
  // the supervisor reported via heartbeat. Re-runs when the picked
  // appliance changes so the dropdown matches that host.
  const { data: ifaces } = useQuery({
    queryKey: [
      "pcap-interfaces",
      isAppliance ? `appliance:${vantage}` : "server",
    ],
    queryFn: () =>
      pcapApi.listInterfaces(
        isAppliance ? "appliance" : "server",
        isAppliance ? vantage : undefined,
      ),
  });
  const ifaceList = ifaces?.interfaces ?? [];

  const start = useMutation({
    mutationFn: (body: PcapCaptureCreate) => pcapApi.createCapture(body),
    onSuccess: onStarted,
  });

  const hasStop = durationS !== "" || maxPackets !== "" || maxMiB !== "";

  const commandPreview = useMemo(() => {
    const parts = [
      "tcpdump",
      "-n",
      "-U",
      "-i",
      iface,
      "-s",
      String(snaplen || 0),
    ];
    if (!promiscuous) parts.push("-p");
    if (maxPackets !== "") parts.push("-c", String(maxPackets));
    parts.push("-w", "<file>");
    if (filter.trim()) parts.push(filter.trim());
    return parts.join(" ");
  }, [iface, snaplen, promiscuous, maxPackets, filter]);

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (!hasStop) return;
        start.mutate({
          vantage_kind: isAppliance ? "appliance" : "server",
          appliance_id: isAppliance ? vantage : null,
          interface: iface,
          bpf_filter: filter.trim() || null,
          snaplen: snaplen === "" ? 256 : Number(snaplen),
          promiscuous,
          max_duration_s: durationS === "" ? null : Number(durationS),
          max_packets: maxPackets === "" ? null : Number(maxPackets),
          max_bytes: maxMiB === "" ? null : Number(maxMiB) * 1024 * 1024,
        });
      }}
    >
      <div>
        <label className="mb-1 block text-xs font-medium">Vantage</label>
        <select
          value={vantage}
          onChange={(e) => {
            setVantage(e.target.value);
            setIface("any"); // reset — interface list is per-vantage
            setCustomIface(false);
          }}
          className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
        >
          <option value="server">Control plane (container network)</option>
          {approved.map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname} (appliance host)
            </option>
          ))}
        </select>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium">Interface</label>
        {ifaceList.length > 0 && (
          <select
            value={customIface ? "__other__" : iface}
            onChange={(e) => {
              if (e.target.value === "__other__") {
                setCustomIface(true);
              } else {
                setCustomIface(false);
                setIface(e.target.value);
              }
            }}
            className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
          >
            {(customIface || ifaceList.includes(iface)
              ? ifaceList
              : [iface, ...ifaceList]
            ).map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
            <option value="__other__">Other — type a NIC name…</option>
          </select>
        )}
        {(customIface || ifaceList.length === 0) && (
          // "Other…" picked, or the appliance hasn't reported NICs yet — let
          // the operator type any NIC (bridges / overlay / VPN that udev
          // didn't name). The host runner validates it against /sys/class/net.
          <input
            type="text"
            value={iface}
            onChange={(e) => setIface(e.target.value)}
            placeholder="e.g. br0, vmbr0, tailscale0, any"
            className={cn(
              "w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm",
              ifaceList.length > 0 && "mt-1",
            )}
            autoFocus={customIface}
          />
        )}
        {ifaces?.note && (
          <p className="mt-1 text-[11px] text-muted-foreground">
            {ifaces.note}
          </p>
        )}
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium">BPF filter</label>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="e.g. port 53 or host 10.0.0.1 (empty = all traffic)"
          className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm"
        />
        <div className="mt-1.5 flex flex-wrap gap-1">
          {BPF_PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              onClick={() => setFilter(p.filter)}
              className="rounded border px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground"
              title={p.filter}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <NumField
          label="Max seconds"
          value={durationS}
          onChange={setDurationS}
          max={1800}
        />
        <NumField
          label="Max packets"
          value={maxPackets}
          onChange={setMaxPackets}
          max={1000000}
        />
        <NumField
          label="Max MiB"
          value={maxMiB}
          onChange={setMaxMiB}
          max={100}
        />
      </div>

      <div className="grid grid-cols-2 items-end gap-2">
        <NumField
          label="Snaplen (bytes/pkt)"
          value={snaplen}
          onChange={setSnaplen}
          max={65535}
        />
        <label className="flex items-center gap-2 pb-1.5 text-xs">
          <input
            type="checkbox"
            checked={promiscuous}
            onChange={(e) => setPromiscuous(e.target.checked)}
          />
          Promiscuous mode
        </label>
      </div>

      <div className="rounded-md border bg-muted/30 px-2 py-1.5">
        <p className="break-all font-mono text-[11px] text-muted-foreground">
          {commandPreview}
        </p>
      </div>

      {!hasStop && (
        <p className="text-[11px] text-amber-600">
          Set at least one stop condition (seconds, packets, or MiB).
        </p>
      )}
      {start.isError && (
        <p className="text-[11px] text-destructive">
          {(start.error as { response?: { data?: { detail?: string } } })
            ?.response?.data?.detail ?? "Failed to start capture."}
        </p>
      )}

      <button
        type="submit"
        disabled={!hasStop || start.isPending}
        className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
      >
        {start.isPending ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Activity className="h-3.5 w-3.5" />
        )}
        Start capture
      </button>
    </form>
  );
}

function NumField({
  label,
  value,
  onChange,
  max,
}: {
  label: string;
  value: number | "";
  onChange: (v: number | "") => void;
  max: number;
}) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium">{label}</label>
      <input
        type="number"
        min={1}
        max={max}
        value={value}
        onChange={(e) =>
          onChange(e.target.value === "" ? "" : Number(e.target.value))
        }
        className="w-full rounded-md border bg-background px-2 py-1.5 text-sm tabular-nums"
      />
    </div>
  );
}

function StatusPill({ status }: { status: PcapCaptureRead["status"] }) {
  const map: Record<string, string> = {
    queued: "bg-zinc-500/15 text-zinc-600",
    running: "bg-blue-500/15 text-blue-600",
    completed: "bg-emerald-500/15 text-emerald-600",
    failed: "bg-rose-500/15 text-rose-600",
    cancelled: "bg-amber-500/15 text-amber-600",
  };
  return (
    <span
      className={cn(
        "rounded px-1.5 py-0.5 text-[11px] font-medium",
        map[status],
      )}
    >
      {status}
    </span>
  );
}

function LiveTab({
  captureId,
  onComplete,
}: {
  captureId: string | null;
  onComplete: (id: string) => void;
}) {
  const qc = useQueryClient();
  const { data } = useQuery({
    enabled: !!captureId,
    queryKey: ["pcap-capture", captureId],
    queryFn: () => pcapApi.getCapture(captureId!),
    // Keep polling until the artifact question is settled — not just
    // until terminal — so a Stopped capture's partial .pcap shows up.
    refetchInterval: (q) =>
      q.state.data && isSettled(q.state.data) ? false : 1500,
  });

  useEffect(() => {
    // Only hand off to the Result tab once settled, so we never switch to
    // a "no artifact" view a beat before the partial .pcap lands.
    if (data && isSettled(data)) {
      qc.invalidateQueries({ queryKey: ["pcap-captures"] });
      onComplete(data.id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.status, data?.has_artifact]);

  const cancel = useMutation({
    mutationFn: (id: string) => pcapApi.cancelCapture(id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["pcap-capture", captureId] }),
  });

  if (!captureId || !data) {
    return (
      <p className="text-xs text-muted-foreground">
        No capture running — start one on the left. Live progress shows here.
      </p>
    );
  }
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs">{data.interface}</span>
        <StatusPill status={data.status} />
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <Stat label="Captured" value={fmtBytes(data.bytes_captured)} />
        <Stat
          label="Elapsed"
          value={`${Math.round(data.duration_seconds ?? 0)}s`}
        />
      </div>
      {data.bpf_filter && (
        <p className="font-mono text-[11px] text-muted-foreground">
          filter: {data.bpf_filter}
        </p>
      )}
      {data.status === "running" && (
        <button
          type="button"
          onClick={() => cancel.mutate(data.id)}
          disabled={cancel.isPending}
          className="inline-flex items-center gap-1 rounded border border-destructive/40 px-2 py-1 text-xs text-destructive hover:bg-destructive/10 disabled:opacity-50"
        >
          <Trash2 className="h-3 w-3" /> Stop capture
        </button>
      )}
      {/* After Stop, the partial .pcap lands a beat later (server finalizes
          post-SIGTERM; appliance relays via the supervisor). Show a spinner
          until it settles, then onComplete hands off to the Result tab which
          owns the Download button + the no-artifact message. */}
      {data.status === "cancelled" &&
        !data.has_artifact &&
        !isSettled(data) && (
          <p className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" />
            Finalizing the captured packets…
          </p>
        )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border bg-muted/20 px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="font-mono text-sm tabular-nums">{value}</div>
    </div>
  );
}

function ResultTab({ captureId }: { captureId: string | null }) {
  const { data } = useQuery({
    enabled: !!captureId,
    queryKey: ["pcap-capture", captureId],
    queryFn: () => pcapApi.getCapture(captureId!),
    // Keep refreshing until the artifact settles so a just-stopped
    // capture's Download button appears without a manual refresh.
    refetchInterval: (q) =>
      q.state.data && isSettled(q.state.data) ? false : 2000,
  });
  const download = useMutation({
    mutationFn: (id: string) => pcapApi.downloadCapture(id),
  });

  if (!data) {
    return (
      <p className="text-xs text-muted-foreground">
        Nothing to show yet. Click a row in History or run a capture.
      </p>
    );
  }
  const meta = data.metadata_json as { stop_reason?: string } | null;
  return (
    <div className="space-y-2 text-xs">
      <div className="flex items-center justify-between">
        <span className="text-muted-foreground">
          {humanTime(data.created_at)} ·{" "}
          <span className="font-mono">{data.interface}</span>
        </span>
        <StatusPill status={data.status} />
      </div>
      {data.bpf_filter && (
        <p className="font-mono text-[11px] text-muted-foreground">
          filter: {data.bpf_filter}
        </p>
      )}
      {data.error_message && (
        <p className="rounded-md border border-destructive/40 bg-destructive/5 p-2 text-destructive">
          {data.error_message}
        </p>
      )}
      <div className="grid grid-cols-2 gap-2">
        <Stat label="Packets" value={String(data.packets_captured)} />
        <Stat label="Size" value={fmtBytes(data.pcap_size_bytes)} />
      </div>
      {meta?.stop_reason && (
        <p className="text-[11px] text-muted-foreground">
          stopped: {meta.stop_reason}
        </p>
      )}
      {data.has_artifact ? (
        <button
          type="button"
          onClick={() => download.mutate(data.id)}
          disabled={download.isPending}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {download.isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Download className="h-3.5 w-3.5" />
          )}
          Download .pcap
        </button>
      ) : (
        <p className="text-[11px] italic text-muted-foreground">
          No downloadable artifact (capture produced no bytes, failed, or was
          pruned). A stopped capture still downloads whatever was captured
          before Stop.
        </p>
      )}
    </div>
  );
}

function HistoryTab({ onSelect }: { onSelect: (c: PcapCaptureRead) => void }) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [pendingBulk, setPendingBulk] = useState<PcapCaptureRead[] | null>(
    null,
  );

  const { data, isLoading, isError } = useQuery({
    queryKey: ["pcap-captures", "recent"],
    queryFn: () => pcapApi.listCaptures({ page_size: 50 }),
    refetchInterval: 5000,
  });
  const items = data?.items ?? [];

  useEffect(() => {
    if (selected.size === 0) return;
    const ids = new Set(items.map((s) => s.id));
    const next = new Set<string>();
    let changed = false;
    for (const id of selected) {
      if (ids.has(id)) next.add(id);
      else changed = true;
    }
    if (changed) setSelected(next);
  }, [items, selected]);

  const download = useMutation({
    mutationFn: (id: string) => pcapApi.downloadCapture(id),
  });
  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => pcapApi.bulkDeleteCaptures(ids),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["pcap-captures"] });
      setSelected(new Set());
      setPendingBulk(null);
    },
  });

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const allChecked = items.length > 0 && selected.size === items.length;
  const someChecked = selected.size > 0 && !allChecked;

  if (isLoading) {
    return (
      <p className="inline-flex items-center gap-2 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" /> Loading captures…
      </p>
    );
  }
  if (isError) {
    return <p className="text-xs text-destructive">Failed to load captures.</p>;
  }
  if (items.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        No captures yet — start one on the left.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {selected.size > 0 && (
        <div className="flex items-center justify-between rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs">
          <span>{selected.size} selected</span>
          <button
            type="button"
            onClick={() =>
              setPendingBulk(items.filter((s) => selected.has(s.id)))
            }
            disabled={bulkDelete.isPending}
            className="inline-flex items-center gap-1 rounded border border-destructive/40 px-2 py-0.5 text-[11px] text-destructive hover:bg-destructive/10 disabled:opacity-60"
          >
            <Trash2 className="h-3 w-3" /> Delete {selected.size}
          </button>
        </div>
      )}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[560px] text-xs">
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
                  onChange={() =>
                    setSelected(
                      allChecked ? new Set() : new Set(items.map((s) => s.id)),
                    )
                  }
                />
              </th>
              <th className="px-2 py-1.5 text-left">When</th>
              <th className="px-2 py-1.5 text-left">Interface</th>
              <th className="px-2 py-1.5 text-left">Filter</th>
              <th className="px-2 py-1.5 text-left">Status</th>
              <th className="px-2 py-1.5 text-left">Size</th>
              <th className="px-2 py-1.5"></th>
            </tr>
          </thead>
          <tbody>
            {items.map((s) => (
              <tr
                key={s.id}
                onClick={() => onSelect(s)}
                className={cn(
                  "cursor-pointer border-b last:border-0 hover:bg-muted/20",
                  selected.has(s.id) && "bg-amber-500/5",
                )}
              >
                <td className="px-2 py-1" onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    aria-label={`Select capture ${s.id}`}
                    checked={selected.has(s.id)}
                    onChange={() => toggle(s.id)}
                  />
                </td>
                <td className="px-2 py-1 text-muted-foreground">
                  {humanTime(s.created_at)}
                </td>
                <td className="px-2 py-1 font-mono">{s.interface}</td>
                <td className="max-w-[160px] truncate px-2 py-1 font-mono text-muted-foreground">
                  {s.bpf_filter || "—"}
                </td>
                <td className="px-2 py-1">
                  <StatusPill status={s.status} />
                </td>
                <td className="px-2 py-1 tabular-nums">
                  {fmtBytes(s.pcap_size_bytes)}
                </td>
                <td
                  className="px-2 py-1 text-right"
                  onClick={(e) => e.stopPropagation()}
                >
                  {s.has_artifact && (
                    <button
                      type="button"
                      title="Download .pcap"
                      onClick={() => download.mutate(s.id)}
                      className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                    >
                      <Download className="h-3.5 w-3.5" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pendingBulk && (
        <ConfirmBulkDeleteModal
          captures={pendingBulk}
          pending={bulkDelete.isPending}
          onConfirm={() => bulkDelete.mutate(pendingBulk.map((s) => s.id))}
          onClose={() => setPendingBulk(null)}
        />
      )}
    </div>
  );
}

function ConfirmBulkDeleteModal({
  captures,
  pending,
  onConfirm,
  onClose,
}: {
  captures: PcapCaptureRead[];
  pending: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const inFlight = captures.filter(
    (s) => s.status === "queued" || s.status === "running",
  ).length;
  const terminal = captures.length - inFlight;
  const { dialogProps, titleProps } = useModalDialog(onClose);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
      <div
        {...dialogProps}
        className="w-full max-w-md rounded-lg border bg-card p-5 shadow-xl focus:outline-none"
      >
        <h3 {...titleProps} className="text-base font-semibold">
          Delete {captures.length} capture{captures.length === 1 ? "" : "s"}?
        </h3>
        <p className="mt-2 text-sm text-muted-foreground">
          {terminal > 0 && (
            <>
              {terminal} finished capture
              {terminal === 1
                ? " (and its .pcap) will be"
                : "s (and their .pcaps) will be"}{" "}
              permanently removed.
            </>
          )}
          {terminal > 0 && inFlight > 0 && " "}
          {inFlight > 0 && (
            <>
              {inFlight} running capture{inFlight === 1 ? "" : "s"} will be
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
            Delete {captures.length}
          </button>
        </div>
      </div>
    </div>
  );
}
