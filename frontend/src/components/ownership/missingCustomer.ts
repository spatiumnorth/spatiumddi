import { usePermissions } from "@/hooks/usePermissions";
import type { CustomerListResponse } from "@/lib/api";

/**
 * What to call a stored customer id the live list does not hold, or null when
 * nothing needs saying (no id, the list not loaded or failed, or the id is in
 * the list). "(customer in Trash)" only when the list is every live customer:
 * complete (not truncated) AND read by a caller who may read every customer.
 * A caller admitted by grants scoped to single customers (#3039) gets a list
 * narrowed to those rows, so an id missing from it is one they may not read,
 * not one in the Trash; that, and a truncated list, is "(current customer)".
 * Shared by the edit forms' option, the picker and the lists' chip (#3506).
 */
export function missingCustomerLabel(
  customerId: string | null | undefined,
  list: { isSuccess: boolean; data?: CustomerListResponse },
  readsEveryCustomer: boolean,
): string | null {
  if (!customerId || !list.isSuccess || !list.data) return null;
  const { items, total } = list.data;
  if (items.some((c) => c.id === customerId)) return null;
  return total > items.length || !readsEveryCustomer
    ? "(current customer)"
    : "(customer in Trash)";
}

/** Whether the caller's customer list is unnarrowed: the type-wide read the
 *  list handler tests before it narrows to per-row grants. False while the
 *  permissions load, so nothing is called "in Trash" on a guess. */
export function useReadsEveryCustomer(): boolean {
  return usePermissions().can("read", "customer");
}
