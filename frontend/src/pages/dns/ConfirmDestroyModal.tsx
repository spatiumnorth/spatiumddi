import { useState } from "react";
import { Modal } from "@/components/ui/modal";

/**
 * Double-confirm destroy modal (matches IPAM pattern).
 *
 * The step-2 heading, warning line and button default to the permanent-delete
 * wording, which is right for the paths that really are permanent (group,
 * TSIG key, blocking list). A caller whose delete is a soft delete into Trash
 * (zones, #1880) passes `confirmTitle` / `warning` / `confirmButtonLabel` so
 * the dialog does not claim an irreversible action it is not taking.
 */
export function ConfirmDestroyModal({
  title,
  description,
  checkLabel,
  onConfirm,
  onClose,
  isPending,
  error,
  notice,
  confirmTitle = "Confirm Permanent Deletion",
  warning = "This action cannot be undone.",
  confirmButtonLabel = "Delete",
}: {
  title: string;
  description: React.ReactNode;
  checkLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  isPending?: boolean;
  error?: string | null;
  // Non-error feedback shown in a neutral box — used for the #62
  // two-person approval queue "Submitted for approval" message, where
  // the delete returned 202 instead of executing.
  notice?: string | null;
  confirmTitle?: string;
  warning?: string;
  confirmButtonLabel?: string;
}) {
  const [step, setStep] = useState<1 | 2>(1);
  const [checked, setChecked] = useState(false);

  if (step === 1) {
    return (
      <Modal title={title} onClose={onClose}>
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">{description}</p>
          {error && (
            <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {error}
            </div>
          )}
          {notice && (
            <div className="rounded-md border border-blue-500/40 bg-blue-500/5 px-3 py-2 text-xs text-blue-600 dark:text-blue-400">
              {notice}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <button
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            >
              Cancel
            </button>
            <button
              onClick={() => setStep(2)}
              className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90"
            >
              Continue
            </button>
          </div>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title={confirmTitle} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm font-medium text-destructive">{warning}</p>
        <p className="text-sm text-muted-foreground">{description}</p>
        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={checked}
            onChange={(e) => setChecked(e.target.checked)}
          />
          {checkLabel}
        </label>
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}
        {notice && (
          <div className="rounded-md border border-blue-500/40 bg-blue-500/5 px-3 py-2 text-xs text-blue-600 dark:text-blue-400">
            {notice}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={!checked || isPending}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {isPending ? "Deleting…" : confirmButtonLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
