export interface AnalyticsFilterValues {
  q: string;
  qtype: string;
  client_ip: string;
  view: string;
  rcode: string;
}

/** The filters the analytics request carries: none unless the toggle is on
 *  (#4072). Blank fields are dropped, so "on" with nothing typed is the
 *  whole window. */
export function analyticsFilterParams(
  follow: boolean,
  f: AnalyticsFilterValues,
): Partial<Record<keyof AnalyticsFilterValues, string>> {
  if (!follow) return {};
  const out: Partial<Record<keyof AnalyticsFilterValues, string>> = {};
  for (const k of ["q", "qtype", "client_ip", "view", "rcode"] as const) {
    const v = f[k].trim();
    if (v) out[k] = v;
  }
  return out;
}

/** "192.0.2.0/24 · AAAA" — what a narrowed strip is showing. */
export function describeAnalyticsFilters(
  p: Partial<Record<keyof AnalyticsFilterValues, string>>,
): string {
  return [
    p.client_ip,
    p.q && `"${p.q}"`,
    p.qtype,
    p.view && `view ${p.view}`,
    p.rcode,
  ]
    .filter(Boolean)
    .join(" · ");
}
