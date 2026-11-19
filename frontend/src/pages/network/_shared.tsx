import { Field } from "@/components/ui/field";
import { cn } from "@/lib/utils";
import type {
  NetworkArpEntryRead,
  NetworkDeviceType,
  NetworkFdbEntryRead,
  NetworkInterfaceRead,
  NetworkPollStatus,
  NetworkSnmpVersion,
} from "@/lib/api";

// Compact text-input style used everywhere in the Network forms +
// filter rows.
export const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// Standard form-field wrapper: the shared labelled Field (#4371).
// eslint-disable-next-line react-refresh/only-export-components
export { Field };

// Lift detail off the FastAPI 422 envelope so users don't see the raw
// pydantic error array.
// eslint-disable-next-line react-refresh/only-export-components
export function errMsg(e: unknown, fallback: string): string {
  const ae = e as {
    response?: { data?: { detail?: unknown } };
    message?: string;
  };
  const d = ae?.response?.data?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    return (
      (d as Array<{ loc?: (string | number)[]; msg?: string }>)
        .map((err) => {
          const field = (err.loc ?? []).filter((p) => p !== "body").join(".");
          return field ? `${field}: ${err.msg}` : err.msg;
        })
        .filter(Boolean)
        .join("; ") || fallback
    );
  }
  return ae?.message || fallback;
}

// Relative-time formatter used in tables. Mirrors the helper in
// DashboardPage.tsx — kept local so this feature pulls cleanly even
// if the dashboard helper moves.
// eslint-disable-next-line react-refresh/only-export-components
export function humanTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 0) return d.toLocaleString();
  if (diff < 10) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  return d.toLocaleDateString();
}

// Humanise sysUpTime / lastChange (which arrive as integer seconds).
// SNMP semantics: 0 means "no information" — surface that as a dash.
// eslint-disable-next-line react-refresh/only-export-components
export function humanDuration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  if (seconds < 86400) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${h}h ${m}m`;
  }
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  return `${d}d ${h}h`;
}

// Speed humaniser (bps → "1 Gbps" etc).
// eslint-disable-next-line react-refresh/only-export-components
export function humanSpeed(bps: number | null | undefined): string {
  if (bps == null || bps <= 0) return "—";
  if (bps >= 1_000_000_000) {
    const v = bps / 1_000_000_000;
    return `${v % 1 === 0 ? v.toFixed(0) : v.toFixed(1)} Gbps`;
  }
  if (bps >= 1_000_000) {
    const v = bps / 1_000_000;
    return `${v % 1 === 0 ? v.toFixed(0) : v.toFixed(1)} Mbps`;
  }
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} kbps`;
  return `${bps} bps`;
}

// ── Pills ────────────────────────────────────────────────────────────

const PILL_BASE =
  "inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium";

const DEVICE_TYPE_LABELS: Record<NetworkDeviceType, string> = {
  router: "Router",
  switch: "Switch",
  ap: "AP",
  firewall: "Firewall",
  l3_switch: "L3 Switch",
  other: "Other",
};

const DEVICE_TYPE_COLORS: Record<NetworkDeviceType, string> = {
  router: "bg-sky-50 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300",
  switch:
    "bg-violet-50 text-violet-700 dark:bg-violet-500/10 dark:text-violet-300",
  ap: "bg-cyan-50 text-cyan-700 dark:bg-cyan-500/10 dark:text-cyan-300",
  firewall: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300",
  l3_switch:
    "bg-indigo-50 text-indigo-700 dark:bg-indigo-500/10 dark:text-indigo-300",
  other: "bg-zinc-100 text-zinc-700 dark:bg-zinc-500/15 dark:text-zinc-300",
};

export function DeviceTypePill({ type }: { type: NetworkDeviceType }) {
  return (
    <span className={cn(PILL_BASE, DEVICE_TYPE_COLORS[type])}>
      {DEVICE_TYPE_LABELS[type]}
    </span>
  );
}

const SNMP_VERSION_COLORS: Record<NetworkSnmpVersion, string> = {
  v1: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300",
  v2c: "bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300",
  v3: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300",
};

export function SnmpVersionPill({ version }: { version: NetworkSnmpVersion }) {
  return (
    <span className={cn(PILL_BASE, SNMP_VERSION_COLORS[version], "uppercase")}>
      SNMP {version}
    </span>
  );
}

const POLL_STATUS_LABELS: Record<NetworkPollStatus, string> = {
  pending: "Pending",
  success: "Success",
  partial: "Partial",
  failed: "Failed",
  timeout: "Timeout",
};

const POLL_STATUS_COLORS: Record<NetworkPollStatus, string> = {
  pending: "bg-zinc-100 text-zinc-700 dark:bg-zinc-500/15 dark:text-zinc-300",
  success:
    "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300",
  partial:
    "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300",
  failed: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300",
  timeout: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300",
};

export function PollStatusPill({ status }: { status: NetworkPollStatus }) {
  return (
    <span className={cn(PILL_BASE, POLL_STATUS_COLORS[status])}>
      {POLL_STATUS_LABELS[status]}
    </span>
  );
}

const ARP_STATE_COLORS: Record<NetworkArpEntryRead["state"], string> = {
  reachable:
    "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300",
  stale: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300",
  delay: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300",
  probe: "bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300",
  invalid: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300",
  unknown: "bg-zinc-100 text-zinc-700 dark:bg-zinc-500/15 dark:text-zinc-300",
};

export function ArpStatePill({
  state,
}: {
  state: NetworkArpEntryRead["state"];
}) {
  return (
    <span className={cn(PILL_BASE, ARP_STATE_COLORS[state], "capitalize")}>
      {state}
    </span>
  );
}

const FDB_TYPE_COLORS: Record<NetworkFdbEntryRead["fdb_type"], string> = {
  learned:
    "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300",
  static: "bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300",
  mgmt: "bg-violet-50 text-violet-700 dark:bg-violet-500/10 dark:text-violet-300",
  other: "bg-zinc-100 text-zinc-700 dark:bg-zinc-500/15 dark:text-zinc-300",
};

export function FdbTypePill({
  type,
}: {
  type: NetworkFdbEntryRead["fdb_type"];
}) {
  return (
    <span className={cn(PILL_BASE, FDB_TYPE_COLORS[type], "capitalize")}>
      {type}
    </span>
  );
}

// Admin/Oper status colouring shared between the Interfaces tab and any
// future place that surfaces interface state.
export function InterfaceStatusPill({
  status,
}: {
  status:
    | NetworkInterfaceRead["admin_status"]
    | NetworkInterfaceRead["oper_status"];
}) {
  if (!status) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  let color =
    "bg-zinc-100 text-zinc-700 dark:bg-zinc-500/15 dark:text-zinc-300";
  if (status === "up")
    color =
      "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300";
  else if (status === "down" || status === "lowerLayerDown")
    color = "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300";
  else if (status === "testing" || status === "dormant")
    color =
      "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300";
  return <span className={cn(PILL_BASE, color)}>{status}</span>;
}

// eslint-disable-next-line react-refresh/only-export-components
export const DEVICE_TYPE_OPTIONS: NetworkDeviceType[] = [
  "router",
  "switch",
  "ap",
  "firewall",
  "l3_switch",
  "other",
];
