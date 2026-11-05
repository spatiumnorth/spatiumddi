/** #3551 — the text of the DNS group memory banner, apart from the
 *  component so it can be tested on its own. */
import type { DNSMemoryEstimate } from "@/lib/api";

function fmtBytes(n: number): string {
  const mib = n / (1024 * 1024);
  return mib >= 1024
    ? `${(mib / 1024).toFixed(1)} GiB`
    : `${Math.round(mib)} MiB`;
}

/** The banner's text, kept apart from the query so it can be tested on its
 *  own. Null when the estimate does not warn. */
export function memoryBannerLines(est: DNSMemoryEstimate | null | undefined) {
  if (!est || !est.warn) return null;
  const limit =
    est.limit_source === "agent"
      ? `the ${fmtBytes(est.limit_bytes)} limit${est.limit_server ? ` ${est.limit_server} reports` : ""}`
      : `the default ${fmtBytes(est.limit_bytes)} DNS pod limit (no agent of this group has reported its own)`;
  const perView = new Map<string, number>();
  for (const r of est.rpz) {
    for (const v of r.views) perView.set(v, (perView.get(v) ?? 0) + r.entries);
  }
  return {
    headline: `named is estimated to need about ${fmtBytes(est.estimated_bytes)}, ${Math.round(est.percent)}% of ${limit}.`,
    detail:
      perView.size > 1
        ? `Blocklists take about ${fmtBytes(est.rpz_bytes)} of that: each view loads its own copy of the lists it applies (${Array.from(
            perView,
            ([v, n]) => `${v}: ${n.toLocaleString()} entries`,
          ).join(", ")}), and BIND cannot share a blocklist between views.`
        : null,
    fix: "Have fewer views draw on the same lists, or raise the DNS pod's memory limit, before named is OOM-killed.",
  };
}
