import { useEffect, useState } from "react";
import { Modal } from "./modal";

/**
 * Per-server maintenance-mode pause flow (issue #182). Shared between
 * the DNS ServerDetailModal and the DHCP ServerDetailModal because
 * both have identical shape: free-text reason capture, confirm,
 * cancel. The caller does the actual API mutation in ``onConfirm``;
 * this component just owns the input field + validation.
 *
 * The reason is optional but strongly encouraged. We surface a faint
 * hint about that in the placeholder but don't enforce — operator
 * judgment wins.
 *
 * ``error`` is the caller's failed pause, shown in the dialog (#1344): a
 * refused or failed pause leaves the dialog open, and without it the
 * operator was told nothing at all.
 */
export function PauseServerModal({
  serverName,
  serverKind,
  onConfirm,
  onCancel,
  isPending = false,
  error,
}: {
  serverName: string;
  serverKind: "DNS" | "DHCP";
  onConfirm: (reason: string) => void;
  onCancel: () => void;
  isPending?: boolean;
  error?: string | null;
}) {
  const [reason, setReason] = useState("");

  // Reset on remount so a previous pause cycle's text doesn't leak.
  useEffect(() => {
    setReason("");
  }, [serverName]);

  return (
    <Modal title={`Pause ${serverKind} server`} onClose={onCancel}>
      <div className="space-y-4">
        <div className="text-sm text-muted-foreground">
          Put <span className="font-medium text-foreground">{serverName}</span>{" "}
          in maintenance mode. The control plane will stop shipping pending
          updates and silence the heartbeat-stale alert. You should stop the
          container separately if that's part of the maintenance window — the
          flag itself doesn't dispatch a container stop.
        </div>
        <div className="space-y-1">
          <label className="block text-sm font-medium">
            Reason{" "}
            <span className="text-xs font-normal text-muted-foreground">
              (optional, but helpful for the audit trail)
            </span>
          </label>
          <textarea
            autoFocus
            rows={3}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
            placeholder="e.g. kernel patching, hardware swap, debugging upstream connectivity…"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={isPending}
          />
        </div>
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={isPending}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onConfirm(reason.trim())}
            disabled={isPending}
            className="rounded-md bg-amber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-amber-700 disabled:opacity-50"
          >
            {isPending ? "Pausing…" : "Pause"}
          </button>
        </div>
      </div>
    </Modal>
  );
}
