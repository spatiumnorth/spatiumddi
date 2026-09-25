import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Copy, Loader2, MapPin } from "lucide-react";
import {
  nmapApi,
  type NmapHostResult,
  type NmapPortResult,
  type NmapScanRead,
} from "@/lib/api";
import { useModalDialog } from "@/components/ui/use-draggable-modal";
import { cn } from "@/lib/utils";

/**
 * Parsed-summary panel for a finished nmap scan.
 *
 * Renders one of two shapes depending on whether the scan was a
 * single-host run or a multi-host CIDR / sweep run:
 *
 *   - Single-host: host_state header + port table + OS guess (the
 *     legacy SummaryPanel that lived inline in NmapScanLiveViewer).
 *   - Multi-host (``summary.hosts != null``): a counter strip + a
 *     collapsible alive-hosts list. Each host renders the same
 *     port/OS detail when expanded.
 */
export function NmapResultPanel({ scan }: { scan: NmapScanRead }) {
  const summary = scan.summary;
  if (!summary) return null;

  if (summary.hosts && summary.hosts.length > 0) {
    return <MultiHostResult scan={scan} hosts={summary.hosts} />;
  }
  return <SingleHostResult scan={scan} />;
}

function SingleHostResult({ scan }: { scan: NmapScanRead }) {
  const summary = scan.summary;
  if (!summary) return null;
  const openPorts = summary.ports.filter((p) => p.state === "open");
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3">
      <ResultHeader scan={scan} />
      <PortsTable ports={openPorts} />
    </div>
  );
}

function MultiHostResult({
  scan,
  hosts,
}: {
  scan: NmapScanRead;
  hosts: NmapHostResult[];
}) {
  const alive = hosts.filter((h) => h.host_state === "up");
  const aliveAddrs = alive
    .map((h) => h.address)
    .filter((a): a is string => !!a);
  const copyAlive = () => {
    if (aliveAddrs.length > 0) {
      void navigator.clipboard.writeText(aliveAddrs.join("\n"));
    }
  };
  const [confirmStamp, setConfirmStamp] = useState(false);
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span>
          Hosts probed: <strong>{hosts.length}</strong>
        </span>
        <span>
          Alive:{" "}
          <strong className="text-emerald-700 dark:text-emerald-400">
            {alive.length}
          </strong>
        </span>
        <span>
          Down: <strong>{hosts.length - alive.length}</strong>
        </span>
        {scan.duration_seconds !== null && (
          <span>Duration: {scan.duration_seconds.toFixed(1)}s</span>
        )}
        <div className="ml-auto flex flex-wrap gap-1">
          {alive.length > 0 && (
            <button
              type="button"
              onClick={copyAlive}
              className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent"
              title="Copy alive IPs (newline-separated) to clipboard"
            >
              <Copy className="h-3 w-3" />
              Copy alive IPs
            </button>
          )}
          {alive.length > 0 && (
            <button
              type="button"
              onClick={() => setConfirmStamp(true)}
              className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/5 px-2 py-0.5 text-[11px] text-emerald-700 hover:bg-emerald-500/10 dark:text-emerald-400"
              title="Create / refresh IPAM rows for the alive hosts"
            >
              <MapPin className="h-3 w-3" />
              Stamp alive hosts → IPAM
            </button>
          )}
        </div>
      </div>

      {alive.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No alive hosts in the swept range.
        </p>
      ) : (
        <div className="overflow-hidden rounded-md border bg-background">
          <ul>
            {alive.map((h) => (
              <HostRow key={h.address ?? Math.random()} host={h} />
            ))}
          </ul>
        </div>
      )}

      {confirmStamp && (
        <StampDiscoveredModal
          scanId={scan.id}
          aliveCount={alive.length}
          onClose={() => setConfirmStamp(false)}
        />
      )}
    </div>
  );
}

function StampDiscoveredModal({
  scanId,
  aliveCount,
  onClose,
}: {
  scanId: string;
  aliveCount: number;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const stamp = useMutation({
    mutationFn: () => nmapApi.stampDiscovered(scanId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["addresses"] });
      qc.invalidateQueries({ queryKey: ["subnets"] });
    },
  });
  const result = stamp.data;
  const errMsg =
    stamp.isError &&
    ((stamp.error as { response?: { data?: { detail?: string } } })?.response
      ?.data?.detail ??
      "Failed to stamp hosts");
  const { dialogProps, titleProps } = useModalDialog(onClose);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
      <div
        {...dialogProps}
        className="w-full max-w-md rounded-lg border bg-card p-5 shadow-xl focus:outline-none"
      >
        <h3 {...titleProps} className="text-base font-semibold">
          Stamp alive hosts into IPAM
        </h3>
        {!result && !stamp.isPending && (
          <p className="mt-2 text-sm text-muted-foreground">
            For each of the {aliveCount} alive host{aliveCount === 1 ? "" : "s"}
            : create a new IPAM row with status{" "}
            <code className="rounded bg-muted px-1">discovered</code> if none
            exists, or stamp{" "}
            <code className="rounded bg-muted px-1">last_seen</code> on the
            existing row. Operator- or integration-owned rows keep their current
            status (just the timestamp moves). Hosts that don't fall in a known
            subnet are skipped.
          </p>
        )}
        {stamp.isPending && (
          <p className="mt-2 inline-flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Stamping…
          </p>
        )}
        {errMsg && (
          <p className="mt-2 rounded-md border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
            {String(errMsg)}
          </p>
        )}
        {result && (
          <div className="mt-2 space-y-1 rounded-md border bg-muted/30 p-3 text-sm">
            <div>
              Created:{" "}
              <strong className="text-emerald-700 dark:text-emerald-400">
                {result.created}
              </strong>
            </div>
            <div>
              Bumped to discovered: <strong>{result.bumped}</strong>
            </div>
            <div>
              Refreshed (status preserved): <strong>{result.refreshed}</strong>
            </div>
            {result.skipped_no_subnet > 0 && (
              <div className="text-muted-foreground">
                Skipped (not in any subnet):{" "}
                <strong>{result.skipped_no_subnet}</strong>
              </div>
            )}
            {result.skipped_addresses.length > 0 && (
              <details className="text-[11px] text-muted-foreground">
                <summary className="cursor-pointer">
                  Skipped non-IP entries ({result.skipped_addresses.length})
                </summary>
                <ul className="mt-1 list-disc pl-4 font-mono">
                  {result.skipped_addresses.slice(0, 50).map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            {result ? "Close" : "Cancel"}
          </button>
          {!result && (
            <button
              type="button"
              onClick={() => stamp.mutate()}
              disabled={stamp.isPending}
              className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-sm text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-50 dark:text-emerald-400"
            >
              {stamp.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <MapPin className="h-3.5 w-3.5" />
              )}
              Stamp {aliveCount}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function HostRow({ host }: { host: NmapHostResult }) {
  const [open, setOpen] = useState(false);
  const openPorts = host.ports.filter((p) => p.state === "open");
  const hasDetail = openPorts.length > 0 || !!host.os?.name;
  return (
    <li className="border-b last:border-0">
      <button
        type="button"
        onClick={() => hasDetail && setOpen((v) => !v)}
        disabled={!hasDetail}
        className={cn(
          "flex w-full items-center gap-2 px-2 py-1.5 text-left text-xs",
          hasDetail && "cursor-pointer hover:bg-muted/30",
          !hasDetail && "cursor-default",
        )}
      >
        {hasDetail ? (
          open ? (
            <ChevronDown className="h-3 w-3 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
          )
        ) : (
          <span className="h-3 w-3" />
        )}
        <span className="font-mono">{host.address ?? "—"}</span>
        {host.hostname && (
          <span className="text-muted-foreground">{host.hostname}</span>
        )}
        <span className="ml-auto text-[11px] text-muted-foreground">
          {openPorts.length > 0 && `${openPorts.length} open`}
          {host.os?.name && ` · ${host.os.name}`}
        </span>
      </button>
      {open && hasDetail && (
        <div className="border-t bg-muted/20 px-2 py-2">
          {host.os?.name && (
            <p className="mb-1 text-[11px]">
              OS: <strong>{host.os.name}</strong>
              {host.os.accuracy ? ` (${host.os.accuracy}%)` : ""}
            </p>
          )}
          <PortsTable ports={openPorts} compact />
        </div>
      )}
    </li>
  );
}

function ResultHeader({ scan }: { scan: NmapScanRead }) {
  const summary = scan.summary;
  if (!summary) return null;
  return (
    <div className="flex flex-wrap gap-3 text-xs">
      <span>
        Host state: <strong>{summary.host_state}</strong>
      </span>
      {scan.exit_code !== null && (
        <span>
          Exit: <strong>{scan.exit_code}</strong>
        </span>
      )}
      {scan.duration_seconds !== null && (
        <span>Duration: {scan.duration_seconds.toFixed(1)}s</span>
      )}
      {summary.os?.name && (
        <span>
          OS guess: <strong>{summary.os.name}</strong>
          {summary.os.accuracy ? ` (${summary.os.accuracy}%)` : ""}
        </span>
      )}
    </div>
  );
}

function PortsTable({
  ports,
  compact,
}: {
  ports: NmapPortResult[];
  compact?: boolean;
}) {
  if (ports.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">No open ports detected.</p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-md border bg-background">
      <table className={cn("w-full text-xs", !compact && "min-w-[480px]")}>
        <thead>
          <tr className="border-b bg-muted/30">
            <th className="px-2 py-1.5 text-left">Port</th>
            <th className="px-2 py-1.5 text-left">Proto</th>
            <th className="px-2 py-1.5 text-left">State</th>
            <th className="px-2 py-1.5 text-left">Service</th>
            <th className="px-2 py-1.5 text-left">Version</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((p) => (
            <tr key={`${p.proto}-${p.port}`} className="border-b last:border-0">
              <td className="px-2 py-1 font-mono">{p.port}</td>
              <td className="px-2 py-1">{p.proto}</td>
              <td className="px-2 py-1">{p.state}</td>
              <td className="px-2 py-1">
                {p.service ?? <span className="text-muted-foreground">—</span>}
              </td>
              <td className="px-2 py-1 text-muted-foreground">
                {[p.product, p.version, p.extrainfo]
                  .filter(Boolean)
                  .join(" ") || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
