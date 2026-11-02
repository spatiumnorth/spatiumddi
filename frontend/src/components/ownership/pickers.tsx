import { useQuery } from "@tanstack/react-query";

import {
  customersApi,
  providersApi,
  sitesApi,
  type CustomerListResponse,
} from "@/lib/api";
import { cn } from "@/lib/utils";

interface PickerProps {
  value: string | null;
  onChange: (id: string | null) => void;
  className?: string;
  disabled?: boolean;
  /** When set, only providers of this kind are listed (e.g. "registrar"). */
  kind?: string;
}

// All three pickers use a 60s staleTime + a shared query key so multiple
// modals on the same page share one underlying fetch instead of each
// modal triggering its own list call.

/**
 * The `<option>` an edit form shows for a stored customer the live list does
 * not hold (#3192). A customer in the Trash keeps every row that names it
 * pointing at it, and the update saves while the reference is unchanged, so
 * the form must keep that id selected rather than fall back to its
 * placeholder. Nothing is shown until the list has loaded: a list that failed
 * says nothing about the customer. When the list is truncated (more customers
 * than one page) the id may simply be on a later page, so it is named as the
 * current customer, not as one in the Trash.
 */
export function MissingCustomerOption({
  customerId,
  list,
}: {
  customerId: string | null | undefined;
  list: { isSuccess: boolean; data?: CustomerListResponse };
}) {
  if (!customerId || !list.isSuccess || !list.data) return null;
  const { items, total } = list.data;
  if (items.some((c) => c.id === customerId)) return null;
  return (
    <option value={customerId}>
      {total > items.length ? "(current customer)" : "(customer in Trash)"}
    </option>
  );
}

export function CustomerPicker({
  value,
  onChange,
  className,
  disabled,
}: PickerProps) {
  const { data } = useQuery({
    queryKey: ["customers-picker"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const items = data?.items ?? [];
  return (
    <select
      className={className}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value || null)}
      disabled={disabled}
    >
      <option value="">— None —</option>
      {items.map((c) => (
        <option key={c.id} value={c.id}>
          {c.name}
          {c.account_number ? ` · ${c.account_number}` : ""}
        </option>
      ))}
    </select>
  );
}

export function SitePicker({
  value,
  onChange,
  className,
  disabled,
}: PickerProps) {
  const { data } = useQuery({
    queryKey: ["sites-picker"],
    queryFn: () => sitesApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const items = data?.items ?? [];
  return (
    <select
      className={className}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value || null)}
      disabled={disabled}
    >
      <option value="">— None —</option>
      {items.map((s) => (
        <option key={s.id} value={s.id}>
          {s.name}
          {s.code ? ` (${s.code})` : ""}
        </option>
      ))}
    </select>
  );
}

export function ProviderPicker({
  value,
  onChange,
  className,
  disabled,
  kind,
}: PickerProps) {
  const { data } = useQuery({
    queryKey: ["providers-picker"],
    queryFn: () => providersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const items = (data?.items ?? []).filter((p) => !kind || p.kind === kind);
  return (
    <select
      className={className}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value || null)}
      disabled={disabled}
    >
      <option value="">— None —</option>
      {items.map((p) => (
        <option key={p.id} value={p.id}>
          {p.name}
          {!kind ? ` · ${p.kind}` : ""}
        </option>
      ))}
    </select>
  );
}

// ── Chips ────────────────────────────────────────────────────────────
//
// Tiny inline badges rendered alongside resource names in list / tree
// views. Each takes the FK id and resolves to the row's display name
// via the same shared queries the pickers use, so multiple chips on
// one page share one fetch.
//
// Returns null when the id is null OR when the lookup hasn't loaded
// yet — saves a render-flash and keeps row heights stable.

const chipBaseCls =
  "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium";

export function CustomerChip({
  customerId,
  className,
}: {
  customerId: string | null | undefined;
  className?: string;
}) {
  const { data } = useQuery({
    queryKey: ["customers-picker"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
    enabled: !!customerId,
  });
  if (!customerId) return null;
  const c = (data?.items ?? []).find((x) => x.id === customerId);
  if (!c) return null;
  return (
    <span
      className={cn(
        chipBaseCls,
        "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
        className,
      )}
      title={`Customer: ${c.name}`}
    >
      {c.name}
    </span>
  );
}

export function SiteChip({
  siteId,
  className,
}: {
  siteId: string | null | undefined;
  className?: string;
}) {
  const { data } = useQuery({
    queryKey: ["sites-picker"],
    queryFn: () => sitesApi.list({ limit: 500 }),
    staleTime: 60_000,
    enabled: !!siteId,
  });
  if (!siteId) return null;
  const s = (data?.items ?? []).find((x) => x.id === siteId);
  if (!s) return null;
  const label = s.code || s.name;
  return (
    <span
      className={cn(
        chipBaseCls,
        "border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300",
        className,
      )}
      title={`Site: ${s.name}${s.code ? ` (${s.code})` : ""}`}
    >
      {label}
    </span>
  );
}

export function ProviderChip({
  providerId,
  className,
}: {
  providerId: string | null | undefined;
  className?: string;
}) {
  const { data } = useQuery({
    queryKey: ["providers-picker"],
    queryFn: () => providersApi.list({ limit: 500 }),
    staleTime: 60_000,
    enabled: !!providerId,
  });
  if (!providerId) return null;
  const p = (data?.items ?? []).find((x) => x.id === providerId);
  if (!p) return null;
  return (
    <span
      className={cn(
        chipBaseCls,
        "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
        className,
      )}
      title={`Provider: ${p.name} (${p.kind})`}
    >
      {p.name}
    </span>
  );
}
