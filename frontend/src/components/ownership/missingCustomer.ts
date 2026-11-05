import type { CustomerListResponse } from "@/lib/api";

/**
 * What to call a stored customer id the live list does not hold, or null when
 * nothing needs saying (no id, the list not loaded or failed, or the id is in
 * the list). "(customer in Trash)" only when the list is complete; a truncated
 * list may simply not have reached the id, so that is "(current customer)".
 * Shared by the edit forms' option, the picker and the lists' chip (#3506).
 */
export function missingCustomerLabel(
  customerId: string | null | undefined,
  list: { isSuccess: boolean; data?: CustomerListResponse },
): string | null {
  if (!customerId || !list.isSuccess || !list.data) return null;
  const { items, total } = list.data;
  if (items.some((c) => c.id === customerId)) return null;
  return total > items.length ? "(current customer)" : "(customer in Trash)";
}
