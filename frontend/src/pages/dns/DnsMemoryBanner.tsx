import { useQuery } from "@tanstack/react-query";
import { dnsApi } from "@/lib/api";
import {
  fmtBytes as fmtMemory,
  memoryBannerLines,
  observedMemoryRows,
} from "@/lib/dns-memory";

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
  const observed = observedMemoryRows(data);
  if (!lines && !observed) return null;
  return (
    <>
      {lines && (
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
      )}
      {observed && (
        <div
          className="mb-3 rounded-md border bg-muted/30 p-2 text-xs text-muted-foreground"
          data-testid="dns-memory-observed"
        >
          <p className="mb-1 font-medium text-foreground">
            Actual memory, as each server reports it
            {data
              ? ` (the estimate is about ${fmtMemory(data.estimated_bytes)})`
              : ""}
          </p>
          <ul className="space-y-0.5">
            {observed.map((r) => (
              <li key={r.name}>
                <span className="font-mono">{r.name}</span>: named{" "}
                {r.daemon ?? "—"}, container {r.container ?? "—"}
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}
