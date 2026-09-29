import { useState } from "react";
import {
  type NmapPreset,
  type NmapScanCreate,
  type NmapScanRead,
  nmapApi,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { cn } from "@/lib/utils";
import { Loader2, Play } from "lucide-react";

const PRESETS: { id: NmapPreset; label: string; hint: string }[] = [
  {
    id: "quick",
    label: "Quick",
    hint: "Top 100 ports — fastest sanity check (-T4 -F).",
  },
  {
    id: "service_version",
    label: "Service + Version",
    hint: "Probe each open port for service banners (-sV --version-light).",
  },
  {
    id: "os_fingerprint",
    label: "OS Fingerprint",
    hint: "TCP/IP stack fingerprinting (-O). Needs CAP_NET_RAW (granted by default in our images).",
  },
  {
    id: "service_and_os",
    label: "Services + OS",
    hint: "Service detection + OS fingerprint in one pass (-sV -O --version-light). The right default for device profiling.",
  },
  {
    id: "subnet_sweep",
    label: "Subnet Sweep",
    hint: "Ping-scan a CIDR (-sn). Returns alive hosts only — no port scan. Cap is /16 worth of hosts.",
  },
  {
    id: "default_scripts",
    label: "Default Scripts",
    hint: "Run NSE 'default' category (-sC) — auth, broadcast, discovery scripts.",
  },
  {
    id: "udp_top1000",
    label: "UDP Top 1000",
    hint: "UDP sweep of the 1000 most common ports (-sU --top-ports 1000). Slow.",
  },
  {
    id: "aggressive",
    label: "Aggressive",
    hint: "OS + version + scripts + traceroute (-A). Noisy.",
  },
  {
    id: "custom",
    label: "Custom",
    hint: "Use only the flags you supply in 'Extra args'.",
  },
];

const inputCls =
  "block w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring";

export interface NmapScanFormProps {
  defaultTargetIp?: string;
  /** Pre-selects a specific preset radio. Used when callers want to
   *  push the operator toward the right default — e.g. the subnet
   *  Tools menu opens the modal with ``subnet_sweep`` because the
   *  target is a CIDR. */
  defaultPreset?: NmapPreset;
  ipAddressId?: string;
  /** Disables the target_ip input — used when launching from the IPAM
   *  detail modal where the IP is fixed. */
  lockTarget?: boolean;
  onScanStarted: (scan: NmapScanRead) => void;
}

export function NmapScanForm({
  defaultTargetIp = "",
  defaultPreset = "quick",
  ipAddressId,
  lockTarget,
  onScanStarted,
}: NmapScanFormProps) {
  const [targetIp, setTargetIp] = useState(defaultTargetIp);
  const [preset, setPreset] = useState<NmapPreset>(defaultPreset);
  const [portSpec, setPortSpec] = useState("");
  const [extraArgs, setExtraArgs] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = async () => {
    setError(null);
    if (!targetIp.trim()) {
      setError("Target IP is required");
      return;
    }
    setSubmitting(true);
    const body: NmapScanCreate = {
      target_ip: targetIp.trim(),
      preset,
      port_spec: portSpec.trim() || undefined,
      extra_args: extraArgs.trim() || undefined,
      ip_address_id: ipAddressId,
    };
    try {
      const scan = await nmapApi.createScan(body);
      onScanStarted(scan);
    } catch (e: unknown) {
      const detail = (e as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Failed to start scan");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-3">
      <div>
        <label className="mb-1 block text-xs font-medium text-muted-foreground">
          Target
        </label>
        <input
          className={cn(inputCls, "font-mono")}
          value={targetIp}
          onChange={(e) => setTargetIp(e.target.value)}
          disabled={!!lockTarget}
          placeholder="IP, CIDR, or hostname — e.g. 192.0.2.10, 192.0.2.0/24, 2001:db8::1, router1.lan"
          autoFocus={!lockTarget}
        />
        <p className="mt-1 text-[11px] text-muted-foreground/70">
          Hostnames are resolved by nmap at scan time. CIDRs expand to a list of
          alive hosts with the chosen preset (capped at /16 worth of addresses).
        </p>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-muted-foreground">
          Preset
        </label>
        <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
          {PRESETS.map((p) => (
            <label
              key={p.id}
              className={cn(
                "flex cursor-pointer items-start gap-2 rounded-md border p-2 text-xs",
                preset === p.id
                  ? "border-primary bg-primary/5"
                  : "border-border hover:bg-muted/40",
              )}
            >
              <input
                type="radio"
                name="nmap-preset"
                checked={preset === p.id}
                onChange={() => setPreset(p.id)}
                className="mt-0.5"
              />
              <span className="flex-1">
                <span className="block font-medium">{p.label}</span>
                <span className="block text-[11px] text-muted-foreground">
                  {p.hint}
                </span>
              </span>
            </label>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Port spec (optional)
          </label>
          <input
            className={cn(inputCls, "font-mono")}
            value={portSpec}
            onChange={(e) => setPortSpec(e.target.value)}
            placeholder='e.g. "22,80,443" or "1-1000" or "U:53,T:80"'
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Extra args (optional)
          </label>
          <input
            className={cn(inputCls, "font-mono")}
            value={extraArgs}
            onChange={(e) => setExtraArgs(e.target.value)}
            placeholder="e.g. --reason -Pn"
          />
          <p className="mt-1 text-[11px] text-muted-foreground">
            Scan type, host discovery, ports, timing, service / OS detection,
            and <span className="font-mono">--script</span> with named
            non-intrusive scripts. File, target and spoofing options are
            refused.
          </p>
        </div>
      </div>

      {error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
          {error}
        </p>
      )}

      <div className="flex justify-end">
        <HeaderButton variant="primary" onClick={submit} disabled={submitting}>
          {submitting ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5" />
          )}
          {targetIp ? `Scan ${targetIp}` : "Start scan"}
        </HeaderButton>
      </div>
    </div>
  );
}
