import { GATEWAY_FORWARD_SKIPPED_NOTE } from "@/lib/gatewayDns";

/** Advisory note (not an error) shown when a hostname is exactly "gateway"
 * and the subnet has a forward zone (#2101). Saving is still allowed. */
export function GatewayHostnameNote() {
  return (
    <p
      role="note"
      data-testid="gateway-hostname-note"
      className="mt-1 text-xs text-amber-700 dark:text-amber-400"
    >
      {GATEWAY_FORWARD_SKIPPED_NOTE}
    </p>
  );
}
