import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ExternalLink,
  Globe2,
  Loader2,
  Network,
  Search,
  ServerCog,
} from "lucide-react";

import { bgpApi } from "@/lib/api";
import { safeExternalHref } from "@/lib/safeUrl";
import { cn } from "@/lib/utils";

/**
 * BGP Footprint tab on the ASN detail page (issue #122 frontend
 * follow-up).
 *
 * Renders three stacked sections backed by the BGP enrichment API:
 *
 * 1. **Announced prefixes** — RIPEstat ``announced-prefixes``.
 *    Filterable, with a v4 / v6 split count header.
 * 2. **Peering profile** — PeeringDB ``net`` record. Read-only
 *    organisation metadata + peering policy (Open / Selective /
 *    Restrictive) + IRR AS-set + looking-glass URL.
 * 3. **IXP presence** — PeeringDB ``netixlan``. Each row is one
 *    peering port at one IX, grouped by city for readability.
 *
 * Private ASNs (``kind === "private"``) skip these queries entirely
 * — they're not registered in any public registry by definition,
 * so hitting RIPEstat / PeeringDB just wastes round-trips. We
 * render a friendly empty state instead.
 *
 * Each section handles its own loading / error / unavailable state
 * so a slow upstream doesn't block the others.
 */
export function BgpFootprintTab({
  asnNumber,
  kind,
}: {
  asnNumber: number;
  kind: string;
}) {
  if (kind === "private") {
    return (
      <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-4 py-3 text-sm text-amber-700 dark:text-amber-300">
        <div className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <div>
            Private ASN — no public BGP footprint. RIPEstat / PeeringDB
            don&rsquo;t track private-range ASNs (RFC 6996 / 7300).
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <AnnouncedPrefixesSection asn={asnNumber} />
      <PeeringProfileSection asn={asnNumber} />
      <IxpPresenceSection asn={asnNumber} />
      <SourceFooter />
    </div>
  );
}

// ── Section: announced prefixes ────────────────────────────────────────

function AnnouncedPrefixesSection({ asn }: { asn: number }) {
  const [filter, setFilter] = useState("");
  const q = useQuery({
    queryKey: ["bgp-announced-prefixes", asn],
    queryFn: () => bgpApi.announcedPrefixes(asn),
    // See note on the PeeringDB queries below — backend cache (6h
    // here) is the source of truth; the frontend keeps a small
    // window so tab-switching doesn't refetch needlessly.
    staleTime: 60 * 1000,
  });

  const filtered = useMemo(() => {
    if (!q.data?.prefixes) return [];
    const needle = filter.trim().toLowerCase();
    if (!needle) return q.data.prefixes;
    return q.data.prefixes.filter((p) =>
      p.prefix.toLowerCase().includes(needle),
    );
  }, [q.data, filter]);

  return (
    <section>
      <SectionHeader
        icon={Network}
        title="Announced prefixes"
        subtitle={
          q.data?.available
            ? `${q.data.ipv4_count ?? 0} IPv4 · ${q.data.ipv6_count ?? 0} IPv6 — currently advertised in the global BGP table`
            : "Currently advertised in the global BGP table"
        }
      />
      {q.isLoading ? (
        <SectionLoading />
      ) : q.isError ? (
        <SectionError msg="Failed to fetch announced prefixes." />
      ) : !q.data?.available ? (
        <SectionUnavailable error={q.data?.error} source="RIPEstat" />
      ) : (q.data.prefixes ?? []).length === 0 ? (
        <SectionEmpty msg="This ASN doesn't appear in any public BGP feed right now." />
      ) : (
        <>
          <div className="mb-2 flex items-center gap-2">
            <Search className="h-3.5 w-3.5 text-muted-foreground" />
            <input
              type="search"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter prefixes…"
              className="w-64 rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <span className="ml-auto text-[11px] text-muted-foreground">
              {filtered.length} of {q.data.prefixes!.length}
            </span>
          </div>
          <div className="rounded-lg border">
            <div className="max-h-96 overflow-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-card text-left">
                  <tr className="border-b">
                    <th className="px-3 py-2 font-medium">Prefix</th>
                    <th className="px-3 py-2 font-medium">Family</th>
                    <th className="px-3 py-2 font-medium">First seen</th>
                    <th className="px-3 py-2 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.slice(0, 1000).map((p) => (
                    <tr key={p.prefix} className="border-b last:border-b-0">
                      <td className="px-3 py-1.5 font-mono">{p.prefix}</td>
                      <td className="px-3 py-1.5 text-muted-foreground">
                        {p.prefix.includes(":") ? "IPv6" : "IPv4"}
                      </td>
                      <td className="px-3 py-1.5 text-muted-foreground">
                        {fmtDate(p.first_seen)}
                      </td>
                      <td className="px-3 py-1.5 text-muted-foreground">
                        {fmtDate(p.last_seen)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filtered.length > 1000 && (
              <div className="border-t px-3 py-1.5 text-[11px] text-muted-foreground">
                Showing first 1000 — refine the filter to see the rest.
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}

// ── Section: peering profile ───────────────────────────────────────────

function PeeringProfileSection({ asn }: { asn: number }) {
  const q = useQuery({
    queryKey: ["bgp-peering-profile", asn],
    queryFn: () => bgpApi.asnNetwork(asn),
    // Backend caches the upstream response for 24h already; keeping
    // a small frontend staleTime means an operator who reopens the
    // tab gets the latest backend snapshot, not a possibly-stale
    // browser-side copy. 60 s is enough to absorb tab-switching
    // bounces without doubling up the long upstream cache.
    staleTime: 60 * 1000,
  });

  return (
    <section>
      <SectionHeader
        icon={ServerCog}
        title="Peering profile"
        subtitle="Registered org metadata + peering policy from PeeringDB"
      />
      {q.isLoading ? (
        <SectionLoading />
      ) : q.isError ? (
        <SectionError msg="Failed to fetch peering profile." />
      ) : !q.data?.available ? (
        <SectionUnavailable error={q.data?.error} source="PeeringDB" />
      ) : !q.data.found ? (
        <SectionEmpty msg="This ASN isn't registered in PeeringDB." />
      ) : (
        <div className="rounded-lg border p-4 text-sm">
          <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2">
            <Field label="Name" value={q.data.name} />
            <Field label="Aka" value={q.data.aka} />
            <Field label="Type" value={q.data.info_type} />
            <Field label="Traffic" value={q.data.info_traffic} />
            <Field label="Scope" value={q.data.info_scope} />
            <Field
              label="Policy"
              value={
                q.data.policy_general && (
                  <PolicyBadge policy={q.data.policy_general} />
                )
              }
            />
            <Field
              label="Locations preference"
              value={q.data.policy_locations}
            />
            <Field
              label="IRR AS-set"
              value={
                q.data.irr_as_set ? (
                  <code className="font-mono text-xs">{q.data.irr_as_set}</code>
                ) : null
              }
            />
            <Field
              label="Looking glass"
              value={q.data.looking_glass && externalLink(q.data.looking_glass)}
            />
            <Field
              label="Website"
              value={q.data.website && externalLink(q.data.website)}
            />
          </dl>
        </div>
      )}
    </section>
  );
}

const POLICY_COLORS: Record<string, string> = {
  Open: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  Selective: "bg-amber-500/15 text-amber-700 dark:text-amber-300",
  Restrictive: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
  No: "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400",
};

function PolicyBadge({ policy }: { policy: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium",
        POLICY_COLORS[policy] ?? "bg-muted text-muted-foreground",
      )}
    >
      {policy}
    </span>
  );
}

// ── Section: IXP presence ──────────────────────────────────────────────

function IxpPresenceSection({ asn }: { asn: number }) {
  const q = useQuery({
    queryKey: ["bgp-ixps", asn],
    queryFn: () => bgpApi.asnIxps(asn),
    // Backend caches the upstream response for 24h already; keeping
    // a small frontend staleTime means an operator who reopens the
    // tab gets the latest backend snapshot, not a possibly-stale
    // browser-side copy. 60 s is enough to absorb tab-switching
    // bounces without doubling up the long upstream cache.
    staleTime: 60 * 1000,
  });

  // Group by IX name + city for readability — operators with multiple
  // ports at the same IX (a 100G + 400G upgrade in flight, e.g.) want
  // them stacked, not interleaved with other IXes.
  const grouped = useMemo(() => {
    const ixps = q.data?.ixps ?? [];
    const groups = new Map<string, typeof ixps>();
    for (const row of ixps) {
      const key = `${row.ix_name ?? "—"} · ${row.city ?? ""}`;
      const existing = groups.get(key);
      if (existing) {
        existing.push(row);
      } else {
        groups.set(key, [row]);
      }
    }
    return Array.from(groups.entries()).sort((a, b) =>
      a[0].localeCompare(b[0]),
    );
  }, [q.data]);

  return (
    <section>
      <SectionHeader
        icon={Globe2}
        title="IXP presence"
        subtitle={
          q.data?.available
            ? `${q.data.ixp_count ?? 0} peering ports at ${grouped.length} IXes`
            : "IXP membership from PeeringDB"
        }
      />
      {q.isLoading ? (
        <SectionLoading />
      ) : q.isError ? (
        <SectionError msg="Failed to fetch IXP presence." />
      ) : !q.data?.available ? (
        <SectionUnavailable error={q.data?.error} source="PeeringDB" />
      ) : grouped.length === 0 ? (
        <SectionEmpty msg="This ASN doesn't appear at any IX in PeeringDB." />
      ) : (
        <div className="rounded-lg border">
          <div className="max-h-96 overflow-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-muted/30 text-left">
                <tr className="border-b">
                  <th className="px-3 py-2 font-medium">IX</th>
                  <th className="px-3 py-2 font-medium">City</th>
                  <th className="px-3 py-2 font-medium">Speed</th>
                  <th className="px-3 py-2 font-medium">IPv4</th>
                  <th className="px-3 py-2 font-medium">IPv6</th>
                  <th className="px-3 py-2 font-medium">Notes</th>
                </tr>
              </thead>
              <tbody>
                {grouped.flatMap(([_key, rows]) =>
                  rows.map((r, idx) => (
                    <tr
                      key={`${r.ix_name}-${idx}-${r.ipv4 ?? r.ipv6 ?? idx}`}
                      className="border-b last:border-b-0"
                    >
                      <td className="px-3 py-1.5 font-medium">
                        {r.ix_name ?? "—"}
                      </td>
                      <td className="px-3 py-1.5 text-muted-foreground">
                        {r.city ?? "—"}
                      </td>
                      <td className="px-3 py-1.5 font-mono">
                        {fmtSpeed(r.speed_mbit)}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-muted-foreground">
                        {r.ipv4 ?? "—"}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-muted-foreground">
                        {r.ipv6 ?? "—"}
                      </td>
                      <td className="px-3 py-1.5 text-[11px]">
                        <div className="flex gap-1">
                          {r.is_rs_peer && (
                            <span className="rounded bg-sky-500/15 px-1.5 py-0.5 text-sky-700 dark:text-sky-400">
                              RS peer
                            </span>
                          )}
                          {!r.operational && (
                            <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-amber-700 dark:text-amber-400">
                              Down
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}

// ── Building blocks ────────────────────────────────────────────────────

function SectionHeader({
  icon: Icon,
  title,
  subtitle,
}: {
  icon: typeof Network;
  title: string;
  subtitle: string;
}) {
  return (
    <div className="mb-3 flex items-baseline gap-2">
      <Icon className="h-4 w-4 self-center text-muted-foreground" />
      <h2 className="text-sm font-semibold">{title}</h2>
      <span className="text-xs text-muted-foreground">{subtitle}</span>
    </div>
  );
}

function SectionLoading() {
  return (
    <div className="rounded-lg border border-dashed px-4 py-6 text-center text-xs text-muted-foreground">
      <Loader2 className="mx-auto mb-1 h-4 w-4 animate-spin" />
      Loading…
    </div>
  );
}

function SectionError({ msg }: { msg: string }) {
  return (
    <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-xs text-destructive">
      {msg}
    </div>
  );
}

function SectionUnavailable({
  error,
  source,
}: {
  error?: string | null;
  source: string;
}) {
  return (
    <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 px-4 py-3 text-xs text-amber-700 dark:text-amber-300">
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
        <div>
          <span className="font-medium">{source} unreachable</span>
          {error ? `: ${error}` : ""}. Cached data will serve while the upstream
          recovers.
        </div>
      </div>
    </div>
  );
}

function SectionEmpty({ msg }: { msg: string }) {
  return (
    <div className="rounded-lg border border-dashed px-4 py-3 text-xs text-muted-foreground">
      {msg}
    </div>
  );
}

function Field({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode | null | undefined;
}) {
  if (value == null || value === "") {
    return null;
  }
  return (
    <div className="flex items-baseline gap-2">
      <dt className="w-32 flex-shrink-0 text-xs text-muted-foreground">
        {label}
      </dt>
      <dd className="break-words text-sm">{value}</dd>
    </div>
  );
}

// PeeringDB values: only http(s) becomes a link. Anything else, including
// a telnet: or ssh: looking glass, is shown as plain text (#1361). A link
// shows its parsed href, so the text names the host it actually opens.
function externalLink(value: string) {
  const href = safeExternalHref(value);
  if (!href) {
    return <span className="break-all">{value}</span>;
  }
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className="inline-flex items-center gap-1 text-primary hover:underline"
    >
      <span className="break-all">{href}</span>
      <ExternalLink className="h-3 w-3 flex-shrink-0" />
    </a>
  );
}

function fmtDate(iso: string | null | undefined) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString();
  } catch {
    return iso;
  }
}

function fmtSpeed(mbit: number | null | undefined) {
  if (mbit == null) return "—";
  if (mbit >= 1000) {
    const gbps = mbit / 1000;
    return `${gbps.toFixed(gbps >= 100 ? 0 : 1)} Gbps`;
  }
  return `${mbit} Mbps`;
}

function SourceFooter() {
  return (
    <p className="border-t pt-3 text-[11px] text-muted-foreground">
      Data: <strong>RIPEstat</strong> (announced prefixes) + ·{" "}
      <strong>PeeringDB</strong> (peering profile + IXPs). Cached 6&nbsp;h /
      24&nbsp;h respectively.
    </p>
  );
}
