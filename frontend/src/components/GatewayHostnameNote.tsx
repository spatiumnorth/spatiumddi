import { gatewayForwardSkippedNote } from "@/lib/gatewayDns";

/** Advisory note (not an error) shown when a hostname is exactly "gateway"
 * and the subnet has a forward zone (#2101). Saving is still allowed. */
export function GatewayHostnameNote({
  canEdit = true,
}: {
  /** False on a read-only surface: the note drops its rename advice. */
  canEdit?: boolean;
}) {
  return (
    <p
      role="note"
      data-testid="gateway-hostname-note"
      className="mt-1 text-xs text-amber-700 dark:text-amber-400"
    >
      {gatewayForwardSkippedNote(canEdit)}
    </p>
  );
}
