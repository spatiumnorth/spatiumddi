import { useQuery } from "@tanstack/react-query";
import { dnsApi } from "@/lib/api";
import { memoryBannerLines } from "@/lib/dns-memory";

/** #3551 — warns on a BIND9 group's Views and Blocklists tabs when its
 *  estimated named memory reaches 80 % of the agents' limit. `refreshKey`
 *  changes whenever the views or list assignments do, so the estimate is
 *  re-read after an edit on the same tab. */
export function DnsMemoryBanner({
  groupId,
  refreshKey = "",
}: {
  groupId: string;
  refreshKey?: string;
}) {
  const { data } = useQuery({
    queryKey: ["dns-memory-estimate", groupId, refreshKey],
    queryFn: () => dnsApi.getMemoryEstimate(groupId),
  });
  const lines = memoryBannerLines(data);
  if (!lines) return null;
  return (
    <div
      className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/5 p-2 text-xs text-amber-700 dark:text-amber-400"
      role="alert"
    >
      <p>
        <strong>This group is close to its memory limit.</strong>{" "}
        {lines.headline}
      </p>
      {lines.detail && <p className="mt-1">{lines.detail}</p>}
      <p className="mt-1">{lines.fix}</p>
    </div>
  );
}
