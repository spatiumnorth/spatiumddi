import type { ERLBinding } from "@/lib/api";

/** What the Bindings table shows for a rule's target (#4060): the
 *  server-resolved label, the raw id marked "deleted" when the row it
 *  names is gone, else the raw value (a MAC or BSSID reads fine as is). */
export function bindingTargetText(b: ERLBinding): string {
  if (b.target_label) return b.target_label;
  const raw =
    b.mac_address ??
    b.bssid ??
    b.network_interface_id ??
    b.subnet_id ??
    b.vlan_ref_id ??
    b.ip_address_id ??
    b.site_id ??
    "—";
  return b.target_missing ? `${raw} (target deleted)` : raw;
}
