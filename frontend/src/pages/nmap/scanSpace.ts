import type { NmapScanRead } from "@/lib/api";

/** The name of the space a pinned scan stamps into by default; "" when the
 *  scan is pinned to an IPAM row but the space has not been read yet; null
 *  only for a scan with no IPAM row. Pinning is read off `ip_address_id`, not
 *  `ip_space_id`: a scan copy that omits the space (an older list response,
 *  #2577) must not be worded as an unpinned sweep. */
export function pinnedScanSpaceName(
  scan: Pick<NmapScanRead, "ip_address_id" | "ip_space_id" | "ip_space_name">,
): string | null {
  if (scan.ip_space_id) return scan.ip_space_name ?? "";
  return scan.ip_address_id ? "" : null;
}

/** The "Automatic" option says what the server will do without a space. */
export function automaticSpaceLabel(scanSpaceName: string | null): string {
  if (scanSpaceName === null) {
    return "Automatic — skip addresses found in more than one space";
  }
  return scanSpaceName
    ? `Automatic — the scan's own space (${scanSpaceName})`
    : "Automatic — the scan's own space";
}
