import { useState } from "react";
import { Modal } from "@/components/ui/modal";
import { v6ScopeNoHaNote } from "@/lib/dhcpHa";

export { Modal };

export const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground/70">{hint}</p>}
    </div>
  );
}

export function Btns({
  onClose,
  pending,
  label,
  disabled,
}: {
  onClose: () => void;
  pending: boolean;
  label?: string;
  disabled?: boolean;
}) {
  return (
    <div className="flex justify-end gap-2 pt-2">
      <button
        type="button"
        onClick={onClose}
        className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
      >
        Cancel
      </button>
      <button
        type="submit"
        disabled={pending || disabled}
        className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
      >
        {pending ? "Saving…" : (label ?? "Save")}
      </button>
    </div>
  );
}

export type ApiError = { response?: { data?: { detail?: unknown } } };

// eslint-disable-next-line react-refresh/only-export-components
export function errMsg(e: unknown, fallback = "Request failed"): string {
  const ae = e as ApiError;
  const d = ae?.response?.data?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    // Pydantic 422 — array of { type, loc, msg, input }.
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
  return fallback;
}

// True when the error is the cloud-driver adoption conflict (#865): a push
// would overwrite a provider DHCP object SpatiumDDI never created. The
// backend marks these 409s with X-Adoption-Required so they're
// distinguishable from other conflicts (e.g. duplicate group+subnet) where
// an adopt-retry would be wrong. Axios lower-cases response header names.
// eslint-disable-next-line react-refresh/only-export-components
export function isAdoptionRequired(e: unknown): boolean {
  const ae = e as {
    response?: { status?: number; headers?: Record<string, unknown> };
  };
  return (
    ae?.response?.status === 409 &&
    String(ae.response.headers?.["x-adoption-required"] ?? "") === "true"
  );
}

/** Shared destructive-confirm modal (single-step with optional references block). */
export function DeleteConfirmModal({
  title,
  description,
  referencesTitle,
  references,
  onConfirm,
  onClose,
  isPending,
  error,
  notice,
}: {
  title: string;
  description: string;
  referencesTitle?: string;
  references?: string[];
  onConfirm: () => void;
  onClose: () => void;
  isPending?: boolean;
  error?: string | null;
  // Non-error feedback shown in a neutral box — used for the #62
  // two-person approval queue "Submitted for approval" message, where
  // the delete returned 202 instead of executing.
  notice?: string | null;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title={title} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">{description}</p>
        {references && references.length > 0 && (
          <div className="rounded-md border bg-muted/40 p-3">
            <p className="text-xs font-medium mb-1.5">
              {referencesTitle ?? "Referenced objects:"}
            </p>
            <ul className="text-xs text-muted-foreground list-disc pl-5 space-y-0.5">
              {references.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        )}
        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => setChecked(e.target.checked)}
            className="mt-0.5"
          />
          <span>I understand this action cannot be undone.</span>
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
            disabled={!checked || isPending}
            onClick={onConfirm}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {isPending ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

/** Status dot shared across DHCP UI (matches DNS color scheme). */
export function StatusDot({
  status,
  className = "",
}: {
  status: string;
  className?: string;
}) {
  const cls =
    {
      active: "bg-emerald-500",
      syncing: "bg-blue-500",
      unreachable: "bg-red-500",
      error: "bg-red-500",
      pending: "bg-amber-500",
    }[status] ?? "bg-muted";
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full flex-shrink-0 ${cls} ${className}`}
      title={status}
    />
  );
}

/** #1238 — marks a DHCPv6 scope on a group with two or more Kea members,
 * which HA does not coordinate. Callers decide with `v6ScopeLacksHa`. */
export function V6NoHaTag({ keaMemberCount }: { keaMemberCount: number }) {
  return (
    <span
      className="inline-flex items-center rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400"
      title={v6ScopeNoHaNote(keaMemberCount)}
    >
      v6: no HA
    </span>
  );
}
