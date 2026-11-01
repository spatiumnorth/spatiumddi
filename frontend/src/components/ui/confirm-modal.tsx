import { useEffect, useState, type ReactNode } from "react";

import { cn } from "@/lib/utils";

import { Modal } from "./modal";

// Lightweight Cancel / Confirm dialog. Replaces `window.confirm` so
// every confirmation across the app gets the shared draggable modal
// shell + theme-aware styling. For destructive ops that need an
// extra "I understand this can't be undone" checkbox plus a list of
// referenced rows, use ``pages/dhcp/_shared.tsx``'s
// ``DeleteConfirmModal`` instead — this one is the routine yes/no.
//
// Pass ``requireCheckboxLabel`` to require an explicit "yes I mean
// it" checkbox before the Confirm button enables. Used for actions
// that are non-destructive but operationally heavy (e.g. fleet
// reboot — won't lose data but will take an agent offline for
// 30-60 s).
//
// Pass ``requirePassword`` for destructive actions that need re-auth
// (e.g. fleet appliance delete). The current operator types their
// password; ``onConfirm`` receives it and the caller posts it to the
// server-side endpoint, which verifies + audits. The button stays
// disabled until the password field is non-empty (the server's
// ``verify_password`` does the real check).
export function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "default",
  loading = false,
  requireCheckboxLabel,
  requirePassword = false,
  autoFocusCancel = false,
  passwordError,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "default" | "destructive";
  loading?: boolean;
  requireCheckboxLabel?: string;
  requirePassword?: boolean;
  // Focus Cancel on open, so Enter backs out instead of confirming. For
  // destructive confirmations where the safe answer must be the default.
  autoFocusCancel?: boolean;
  // Surfaced to the password input as inline error text — used by
  // callers to render the server's 403 "Current password incorrect."
  // body without bouncing the operator out of the modal.
  passwordError?: string | null;
  onConfirm: (password?: string) => void;
  onClose: () => void;
}) {
  const [checked, setChecked] = useState(false);
  const [password, setPassword] = useState("");

  // Reset the checkbox + password when the modal opens — otherwise
  // they stay populated across re-opens, which is the opposite of
  // the safety valve we want it to be.
  useEffect(() => {
    if (open) {
      setChecked(false);
      setPassword("");
    }
  }, [open]);

  if (!open) return null;
  const disabled =
    loading ||
    (!!requireCheckboxLabel && !checked) ||
    (requirePassword && password.trim() === "");
  return (
    <Modal title={title} onClose={onClose}>
      <div className="space-y-4">
        <div className="text-sm text-muted-foreground">{message}</div>
        {requireCheckboxLabel && (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5 cursor-pointer"
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
              disabled={loading}
            />
            <span>{requireCheckboxLabel}</span>
          </label>
        )}
        {requirePassword && (
          <div className="space-y-1">
            <label className="block text-sm font-medium">
              Confirm with your password
            </label>
            <input
              type="password"
              autoComplete="current-password"
              autoFocus
              className={cn(
                "w-full rounded-md border bg-background px-3 py-1.5 text-sm",
                passwordError
                  ? "border-destructive focus:outline-none focus:ring-1 focus:ring-destructive"
                  : "focus:outline-none focus:ring-1 focus:ring-ring",
              )}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !disabled) {
                  onConfirm(password);
                }
              }}
              disabled={loading}
            />
            {passwordError && (
              <p className="text-xs text-destructive">{passwordError}</p>
            )}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            autoFocus={autoFocusCancel}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            disabled={disabled}
            onClick={() => onConfirm(requirePassword ? password : undefined)}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm disabled:opacity-50",
              tone === "destructive"
                ? "bg-destructive text-destructive-foreground hover:bg-destructive/90"
                : "bg-primary text-primary-foreground hover:bg-primary/90",
            )}
          >
            {loading ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
