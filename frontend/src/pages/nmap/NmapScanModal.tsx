import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Modal } from "@/components/ui/modal";
import { type NmapPreset, type NmapScanRead, nmapApi } from "@/lib/api";
import { NmapScanForm } from "./NmapScanForm";
import { NmapScanLiveViewer } from "./NmapScanLiveViewer";
import { ConfirmDeleteScanModal } from "./ConfirmDeleteScanModal";
import { humanTime } from "@/pages/network/_shared";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { History, Trash2 } from "lucide-react";

export interface NmapScanModalProps {
  ip: string;
  ipAddressId?: string;
  /** Pre-selects a preset radio in the form — caller can push the
   *  operator toward the right default (e.g. ``subnet_sweep`` when
   *  the modal opens from a subnet header). */
  defaultPreset?: NmapPreset;
  /** Override the modal title (default: ``Nmap scan — {ip}``). The
   *  subnet header path uses this to read ``Nmap scan — 10.0.0.0/24``
   *  instead of repeating the noun. */
  title?: string;
  onClose: () => void;
}

/**
 * Per-IP "Scan with Nmap" modal.
 *
 * Opens on the form view; once the operator hits "Scan" we flip to
 * the live viewer. A "View past scans" toggle at the bottom lazily
 * loads the last few scans against this IP from
 * ``GET /nmap/scans?ip_address_id=<id>``.
 */
export function NmapScanModal({
  ip,
  ipAddressId,
  defaultPreset,
  title,
  onClose,
}: NmapScanModalProps) {
  const [activeScan, setActiveScan] = useState<NmapScanRead | null>(null);
  const [showHistory, setShowHistory] = useState(false);

  return (
    <Modal title={title ?? `Nmap scan — ${ip}`} onClose={onClose} wide>
      {activeScan ? (
        <NmapScanLiveViewer
          scanId={activeScan.id}
          onClose={() => setActiveScan(null)}
        />
      ) : (
        <div className="space-y-3">
          <NmapScanForm
            defaultTargetIp={ip}
            defaultPreset={defaultPreset}
            ipAddressId={ipAddressId}
            lockTarget
            onScanStarted={setActiveScan}
          />
          <button
            type="button"
            onClick={() => setShowHistory((v) => !v)}
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <History className="h-3 w-3" />
            {showHistory ? "Hide past scans" : "View past scans"}
          </button>
          {showHistory && (
            <PastScans
              ipAddressId={ipAddressId}
              targetIp={ip}
              onSelect={setActiveScan}
            />
          )}
        </div>
      )}
    </Modal>
  );
}

function PastScans({
  ipAddressId,
  targetIp,
  onSelect,
}: {
  ipAddressId?: string;
  targetIp: string;
  onSelect: (s: NmapScanRead) => void;
}) {
  const qc = useQueryClient();
  // Cancel and delete take delete on 'manage_nmap_scans' (nmap/router.py).
  const deleteGate = permissionGate(
    usePermissions().can("delete", "manage_nmap_scans"),
    "Requires delete permission on nmap scans",
  );
  const [pendingDelete, setPendingDelete] = useState<NmapScanRead | null>(null);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["nmap-scans", { ipAddressId, targetIp }],
    queryFn: () =>
      nmapApi.listScans(
        ipAddressId
          ? { ip_address_id: ipAddressId, page_size: 25 }
          : { target_ip: targetIp, page_size: 25 },
      ),
  });
  const deleteMut = useMutation({
    mutationFn: (id: string) => nmapApi.cancelScan(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["nmap-scans"] });
      setPendingDelete(null);
    },
  });

  if (isLoading) {
    return <p className="text-xs text-muted-foreground">Loading…</p>;
  }
  if (isError) {
    return (
      <p className="text-xs text-destructive">Failed to load past scans.</p>
    );
  }
  const items = data?.items ?? [];
  if (items.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        No previous scans recorded for this IP.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full min-w-[460px] text-xs">
        <thead>
          <tr className="border-b bg-muted/30">
            <th className="px-2 py-1.5 text-left">When</th>
            <th className="px-2 py-1.5 text-left">Preset</th>
            <th className="px-2 py-1.5 text-left">Status</th>
            <th className="px-2 py-1.5 text-left">Open</th>
            <th className="px-2 py-1.5 text-left">Duration</th>
            <th className="px-2 py-1.5"></th>
          </tr>
        </thead>
        <tbody>
          {items.map((s) => {
            const open =
              s.summary?.ports.filter((p) => p.state === "open").length ?? 0;
            return (
              <tr
                key={s.id}
                onClick={() => onSelect(s)}
                className="cursor-pointer border-b last:border-0 hover:bg-muted/20"
              >
                <td className="px-2 py-1 text-muted-foreground">
                  {humanTime(s.created_at)}
                </td>
                <td className="px-2 py-1">{s.preset}</td>
                <td className="px-2 py-1">{s.status}</td>
                <td className="px-2 py-1 tabular-nums">{open}</td>
                <td className="px-2 py-1 text-muted-foreground tabular-nums">
                  {s.duration_seconds !== null
                    ? `${s.duration_seconds.toFixed(1)}s`
                    : "—"}
                </td>
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
                    disabled={deleteMut.isPending}
                    onClick={() => setPendingDelete(s)}
                    className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:opacity-50"
                    {...deleteGate}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {pendingDelete && (
        <ConfirmDeleteScanModal
          scan={pendingDelete}
          pending={deleteMut.isPending}
          onConfirm={() => deleteMut.mutate(pendingDelete.id)}
          onClose={() => setPendingDelete(null)}
        />
      )}
    </div>
  );
}
