import type { ReactNode } from "react";
import { Modal } from "@/components/ui/modal";

/**
 * Two-choice delete modal shared by IPAM and DNS (#4078): a reversible
 * choice (amber — Move to Trash / Mark as Orphan) and an irreversible one
 * (red — Delete Permanently), in one draggable modal. The permanent choice is
 * only rendered when `allowPermanent` is true, so callers the API refuses on
 * the permanent path see the reversible choice alone.
 */
export function DeleteChoiceModal({
  title,
  intro,
  softHeading,
  softBody,
  softExtra,
  softButtonLabel,
  permanentHeading = "Delete Permanently (irreversible)",
  permanentBody,
  permanentExtra,
  permanentButtonLabel = "Delete Permanently",
  allowPermanent = true,
  onSoft,
  onPermanent,
  onClose,
  isSoftPending,
  isPermanentPending,
  error,
}: {
  title: string;
  intro: ReactNode;
  softHeading: string;
  softBody: ReactNode;
  softExtra?: ReactNode;
  softButtonLabel: string;
  permanentHeading?: string;
  permanentBody: ReactNode;
  permanentExtra?: ReactNode;
  permanentButtonLabel?: string;
  allowPermanent?: boolean;
  onSoft: () => void;
  onPermanent: () => void;
  onClose: () => void;
  isSoftPending?: boolean;
  isPermanentPending?: boolean;
  error?: string | null;
}) {
  const busy = isSoftPending || isPermanentPending;
  return (
    <Modal title={title} onClose={onClose}>
      <div className="space-y-4">
        <p className="break-words text-sm text-muted-foreground">{intro}</p>
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
          <div className="text-xs font-medium text-amber-700 dark:text-amber-400">
            {softHeading}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{softBody}</p>
          {softExtra}
        </div>
        {allowPermanent && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3">
            <div className="text-xs font-medium text-destructive">
              {permanentHeading}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {permanentBody}
            </p>
            {permanentExtra}
          </div>
        )}
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <div className="flex flex-wrap justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          {allowPermanent && (
            <button
              onClick={onPermanent}
              disabled={busy}
              className="rounded-md bg-destructive px-3 py-1.5 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
            >
              {isPermanentPending ? "…" : permanentButtonLabel}
            </button>
          )}
          <button
            onClick={onSoft}
            disabled={busy}
            className="rounded-md bg-amber-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-amber-600 disabled:opacity-50 dark:bg-amber-600 dark:hover:bg-amber-700"
          >
            {isSoftPending ? "…" : softButtonLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
