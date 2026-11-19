import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Loader2,
  RefreshCw,
} from "lucide-react";

import {
  alertsApi,
  dnsApi,
  domainsApi,
  formatApiError,
  tlsCertsApi,
  type AlertSeverity,
  type Domain,
  type DomainWhoisState,
} from "@/lib/api";
import { RdapPanel } from "@/components/network/rdap-panel";
import { CertsCompactTable } from "@/pages/network/CertificatesPage";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { useModuleOn } from "@/hooks/useModuleOn";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { cn, zebraBodyCls } from "@/lib/utils";

// ── helpers ─────────────────────────────────────────────────────────────────

function daysUntil(iso: string | null): number | null {
  if (!iso) return null;
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms)) return null;
  return Math.floor(ms / (24 * 3600 * 1000));
}

function fmt(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// ── Expiry badge ─────────────────────────────────────────────────────────────

function ExpiryBadge({ expiresAt }: { expiresAt: string | null }) {
  const days = daysUntil(expiresAt);
  if (expiresAt === null || days === null) {
    return <span className="text-muted-foreground">—</span>;
  }
  let cls: string;
  let label: string;
  if (days < 0) {
    cls =
      "bg-red-100 text-red-700 dark:bg-red-950/40 dark:text-red-300 border border-red-300 dark:border-red-800";
    label = `Expired ${Math.abs(days)}d ago`;
  } else if (days < 14) {
    cls =
      "bg-red-100 text-red-700 dark:bg-red-950/40 dark:text-red-300 border border-red-300 dark:border-red-800";
    label = `Expires in ${days}d`;
  } else if (days < 30) {
    cls =
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400 border border-amber-300 dark:border-amber-800";
    label = `Expires in ${days}d`;
  } else {
    cls =
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800";
    label = `Expires in ${days}d`;
  }
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium",
        cls,
      )}
    >
      {label}
    </span>
  );
}

// ── WHOIS state badge ────────────────────────────────────────────────────────

function WhoisStateBadge({ state }: { state: DomainWhoisState }) {
  const styles: Record<DomainWhoisState, string> = {
    ok: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    drift:
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400",
    expiring:
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400",
    expired: "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400",
    unreachable: "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400",
    unknown: "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
    // #986 — the name is not under a delegated TLD, so there is no registry
    // to query. Neutral, not red: nothing is wrong, the lookup is simply
    // not applicable.
    "n/a": "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        styles[state],
      )}
    >
      {state}
    </span>
  );
}

// ── Alert severity badge ─────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  const cls: Record<AlertSeverity, string> = {
    info: "bg-blue-100 text-blue-700 dark:bg-blue-950/30 dark:text-blue-400",
    warning:
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400",
    critical: "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        cls[severity],
      )}
    >
      {severity}
    </span>
  );
}

// ── Tab button ───────────────────────────────────────────────────────────────

type Tab = "whois" | "zones" | "certs" | "alerts";

function TabButton({
  active,
  onClick,
  label,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "border-b-2 px-4 pb-2.5 pt-2 text-sm font-medium transition-colors",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground",
      )}
    >
      {label}
    </button>
  );
}

// ── Nameserver diff panel ────────────────────────────────────────────────────

function NameserverDiffPanel({ domain }: { domain: Domain }) {
  if ((domain.expected_nameservers ?? []).length === 0) return null;

  const expected = new Set(
    domain.expected_nameservers.map((ns) => ns.toLowerCase()),
  );
  const actual = domain.actual_nameservers ?? [];

  return (
    <div className="rounded-lg border bg-card p-5">
      <div className="mb-4 flex items-center gap-2">
        <h2 className="text-sm font-semibold">Nameserver Configuration</h2>
        {domain.nameserver_drift ? (
          <span className="inline-flex items-center gap-1 rounded bg-red-100 px-2 py-0.5 text-[11px] font-medium text-red-700 dark:bg-red-950/30 dark:text-red-400">
            <AlertTriangle className="h-3 w-3" />
            Drift detected
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded bg-emerald-100 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400">
            <CheckCircle2 className="h-3 w-3" />
            In sync
          </span>
        )}
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <p className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Expected
          </p>
          <div className="flex flex-wrap gap-1.5">
            {domain.expected_nameservers.map((ns) => (
              <span
                key={ns}
                className="rounded border bg-muted px-2 py-1 font-mono text-xs"
              >
                {ns}
              </span>
            ))}
          </div>
        </div>
        <div>
          <p className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Actual (from RDAP)
          </p>
          {actual.length === 0 ? (
            <p className="text-xs text-muted-foreground/70">
              Not yet observed — refresh WHOIS to populate.
            </p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {actual.map((ns) => {
                const inExpected = expected.has(ns.toLowerCase());
                return (
                  <span
                    key={ns}
                    className={cn(
                      "rounded border px-2 py-1 font-mono text-xs",
                      inExpected
                        ? "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/20 dark:text-emerald-300"
                        : "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/20 dark:text-amber-300",
                    )}
                  >
                    {ns}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── WHOIS tab ────────────────────────────────────────────────────────────────

function WhoisTab({ domain }: { domain: Domain }) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <RdapPanel
        payload={domain.whois_data as Record<string, unknown> | null}
        kind="domain"
        emptyMessage="No WHOIS data available — try Refresh WHOIS"
      />
    </div>
  );
}

// ── Zones tab ────────────────────────────────────────────────────────────────

function LinkedZonesTab({ domain }: { domain: Domain }) {
  // Fetch all groups, then all zones per group, filter by domain name match.
  const { data: groups = [], isLoading: loadingGroups } = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });

  // Fan out one query per group; combined into a single derived
  // query that depends on groups being loaded.
  const { data: allZonesWithGroup = [], isLoading: loadingZones } = useQuery({
    queryKey: ["domain-linked-zones", domain.id, groups.map((g) => g.id)],
    enabled: groups.length > 0,
    queryFn: async () => {
      const results = await Promise.all(
        groups.map(async (g) => {
          const zones = await dnsApi.listZones(g.id);
          return zones.map((z) => ({ zone: z, group: g }));
        }),
      );
      return results.flat();
    },
  });

  const isLoading = loadingGroups || loadingZones;

  // Prefer the explicit ``domain_id`` FK; fall back to a case-insensitive
  // name-match for zones that haven't been pinned yet (backward-compat).
  const linkedZones = allZonesWithGroup.filter(({ zone }) => {
    if (zone.domain_id) {
      return zone.domain_id === domain.id;
    }
    // Suffix match — ``test.example.com`` belongs to the ``example.com``
    // domain unless an explicit ``domain_id`` overrides it. We accept
    // either the exact match or a left-side label tree (``.<domain>``)
    // to avoid false positives like ``example.com.au`` matching
    // ``example.com``.
    const zoneName = zone.name.replace(/\.$/, "").toLowerCase();
    const domainName = domain.name.replace(/\.$/, "").toLowerCase();
    return zoneName === domainName || zoneName.endsWith("." + domainName);
  });

  return (
    <div className="rounded-lg border bg-card">
      <table className="w-full text-sm">
        <thead className="border-b bg-card text-xs uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-4 py-2.5 text-left">Zone Name</th>
            <th className="px-4 py-2.5 text-left">Type</th>
            <th className="px-4 py-2.5 text-left">Kind</th>
            <th className="px-4 py-2.5 text-left">Server Group</th>
          </tr>
        </thead>
        <tbody className={zebraBodyCls}>
          {isLoading && (
            <tr>
              <td
                colSpan={4}
                className="px-4 py-8 text-center text-xs text-muted-foreground"
              >
                <Loader2 className="mx-auto h-4 w-4 animate-spin" />
              </td>
            </tr>
          )}
          {!isLoading && linkedZones.length === 0 && (
            <tr>
              <td
                colSpan={4}
                className="px-4 py-8 text-center text-xs text-muted-foreground"
              >
                No linked DNS zones
              </td>
            </tr>
          )}
          {linkedZones.map(({ zone, group }) => {
            const zoneClean = zone.name.replace(/\.$/, "").toLowerCase();
            const domainClean = domain.name.replace(/\.$/, "").toLowerCase();
            const isSubzone = zoneClean !== domainClean;
            return (
              <tr key={zone.id} className="border-b">
                <td className="px-4 py-2.5 font-medium font-mono text-xs">
                  <Link
                    to={`/dns`}
                    className="hover:underline hover:text-primary"
                  >
                    {zone.name}
                  </Link>
                  {isSubzone && (
                    <span
                      className="ml-2 rounded bg-muted px-1.5 py-0.5 font-sans text-[10px] uppercase tracking-wider text-muted-foreground"
                      title={`Sub-zone of ${domainClean}`}
                    >
                      sub-zone
                    </span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-muted-foreground capitalize">
                  {zone.zone_type}
                </td>
                <td className="px-4 py-2.5 text-muted-foreground capitalize">
                  {zone.kind}
                </td>
                <td className="px-4 py-2.5 text-muted-foreground">
                  {group.name}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Certificates tab ──────────────────────────────────────────────────────────

function CertificatesTab({ domainId }: { domainId: string }) {
  const { enabled, ready } = useFeatureModules();
  const moduleOn = enabled("security.tls_certs");

  const { data, isLoading } = useQuery({
    queryKey: ["tls-certs", "domain", domainId],
    queryFn: () => tlsCertsApi.list({ domain_id: domainId, limit: 200 }),
    enabled: ready && moduleOn,
  });

  if (ready && !moduleOn) {
    return (
      <p className="rounded-lg border bg-card px-4 py-8 text-center text-xs text-muted-foreground">
        TLS certificate monitoring is disabled.
      </p>
    );
  }

  return (
    <CertsCompactTable
      targets={data?.items ?? []}
      isLoading={isLoading}
      emptyLabel="No TLS certificates linked to this domain."
    />
  );
}

// ── Alert history tab ────────────────────────────────────────────────────────

function AlertHistoryTab({ domainId }: { domainId: string }) {
  const { data: allEvents = [], isLoading } = useQuery({
    queryKey: ["alert-events-all"],
    queryFn: () => alertsApi.listEvents({ limit: 500 }),
  });

  // Filter client-side to events for this domain.
  const events = allEvents.filter(
    (e) => e.subject_type === "domain" && e.subject_id === domainId,
  );

  return (
    <div className="rounded-lg border bg-card">
      <table className="w-full text-sm">
        <thead className="border-b bg-card text-xs uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-4 py-2.5 text-left">Message</th>
            <th className="px-4 py-2.5 text-left">Severity</th>
            <th className="px-4 py-2.5 text-left">State</th>
            <th className="px-4 py-2.5 text-left">Fired At</th>
            <th className="px-4 py-2.5 text-left">Resolved At</th>
          </tr>
        </thead>
        <tbody className={zebraBodyCls}>
          {isLoading && (
            <tr>
              <td
                colSpan={5}
                className="px-4 py-8 text-center text-xs text-muted-foreground"
              >
                <Loader2 className="mx-auto h-4 w-4 animate-spin" />
              </td>
            </tr>
          )}
          {!isLoading && events.length === 0 && (
            <tr>
              <td
                colSpan={5}
                className="px-4 py-8 text-center text-xs text-muted-foreground"
              >
                No alert events for this domain
              </td>
            </tr>
          )}
          {events.map((e) => (
            <tr key={e.id} className="border-b">
              <td
                className="px-4 py-2.5 text-xs max-w-xs truncate"
                title={e.message}
              >
                {e.message}
              </td>
              <td className="px-4 py-2.5">
                <SeverityBadge severity={e.severity} />
              </td>
              <td className="px-4 py-2.5">
                {e.resolved_at ? (
                  <span className="text-xs text-muted-foreground">
                    resolved
                  </span>
                ) : (
                  <span className="inline-flex items-center rounded bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:bg-amber-950/30 dark:text-amber-400">
                    open
                  </span>
                )}
              </td>
              <td className="px-4 py-2.5 text-xs text-muted-foreground tabular-nums whitespace-nowrap">
                {fmt(e.fired_at)}
              </td>
              <td className="px-4 py-2.5 text-xs text-muted-foreground tabular-nums whitespace-nowrap">
                {e.resolved_at ? fmt(e.resolved_at) : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export function DomainDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("whois");
  // #2135 — a Domain does not need DNS, but its Linked DNS Zones tab reads
  // /dns/*, so it exists only while core.dns is on.
  const dnsOn = useModuleOn("core.dns");

  const {
    data: domain,
    isLoading,
    isError,
  } = useQuery({
    queryKey: ["domain", id],
    queryFn: () => domainsApi.get(id),
    enabled: !!id,
  });

  // #2519 — the router asks write on 'manage_domains', as the list does.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_domains"),
    "Requires write permission on domains",
  );

  const refreshMut = useMutation({
    mutationFn: () => domainsApi.refreshWhois(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["domain", id] });
      qc.invalidateQueries({ queryKey: ["domains"] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (isError || !domain) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-muted-foreground">
        <AlertTriangle className="h-8 w-8" />
        <p className="text-sm">Domain not found.</p>
        <Link
          to="/admin/domains"
          className="text-sm text-primary hover:underline"
        >
          Back to Domains
        </Link>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-[1200px] space-y-5">
        {/* Header */}
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <Link
              to="/admin/domains"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Back to Domains
            </Link>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight font-mono">
                {domain.name}
              </h1>
              {domain.registrar && (
                <span className="rounded border bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
                  {domain.registrar}
                </span>
              )}
              <ExpiryBadge expiresAt={domain.expires_at} />
            </div>
          </div>
          <button
            onClick={() => refreshMut.mutate()}
            disabled={refreshMut.isPending}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
            {...writeGate}
          >
            <RefreshCw
              className={cn(
                "h-3.5 w-3.5",
                refreshMut.isPending && "animate-spin",
              )}
            />
            {refreshMut.isPending ? "Refreshing…" : "Refresh WHOIS"}
          </button>
          {refreshMut.isError && (
            <p role="alert" className="basis-full text-sm text-destructive">
              {formatApiError(refreshMut.error, "WHOIS refresh failed")}
            </p>
          )}
        </div>

        {/* Info card */}
        <div className="rounded-lg border bg-card p-5">
          <h2 className="mb-4 text-sm font-semibold">Registration Details</h2>
          <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
            <InfoRow label="Registrar" value={domain.registrar ?? "—"} />
            <InfoRow
              label="Registrant Org"
              value={domain.registrant_org ?? "—"}
            />
            <InfoRow
              label="Registered"
              value={
                domain.registered_at
                  ? new Date(domain.registered_at).toLocaleString()
                  : "—"
              }
            />
            <InfoRow
              label="Expires"
              value={
                domain.expires_at
                  ? new Date(domain.expires_at).toLocaleString()
                  : "—"
              }
            />
            <InfoRow
              label="DNSSEC"
              value={
                domain.dnssec_signed ? (
                  <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Signed
                  </span>
                ) : (
                  <span className="text-muted-foreground">Unsigned</span>
                )
              }
            />
            <InfoRow
              label="WHOIS State"
              value={
                <span className="inline-flex flex-wrap items-center gap-2">
                  <WhoisStateBadge state={domain.whois_state} />
                  {/* #986 — "n/a" is not a failed lookup, it is a name with
                      no registry to look up. Say so, or it reads as an
                      error the operator is expected to fix — and say WHICH
                      reason: "not under a delegated TLD" is true of .lan and
                      flatly false of example.com (under .com) and of a
                      reverse zone (under .arpa). Both of those are skipped
                      because nothing registers them, not because their TLD
                      is undelegated. */}
                  {domain.whois_state === "n/a" && (
                    <span className="text-[11px] text-muted-foreground">
                      {domain.name_scope === "reserved"
                        ? "Reserved special-use name — those are not registered with anyone, so RDAP is skipped."
                        : domain.name_scope === "reverse"
                          ? "Reverse-lookup name — delegated with an address block rather than registered as a domain, so RDAP is skipped."
                          : "Not under a delegated top-level domain — there is no registry to query, so RDAP is skipped."}
                    </span>
                  )}
                </span>
              }
            />
            <InfoRow
              label="Last Checked"
              value={
                domain.whois_last_checked_at
                  ? new Date(domain.whois_last_checked_at).toLocaleString()
                  : "Never"
              }
            />
            <InfoRow
              label="Next Check"
              value={
                domain.next_check_at
                  ? new Date(domain.next_check_at).toLocaleString()
                  : "—"
              }
            />
          </dl>
        </div>

        {/* Nameserver diff panel */}
        <NameserverDiffPanel domain={domain} />

        {/* Tabs */}
        <div>
          <div className="flex gap-1 border-b">
            <TabButton
              active={tab === "whois"}
              onClick={() => setTab("whois")}
              label="WHOIS"
            />
            {dnsOn && (
              <TabButton
                active={tab === "zones"}
                onClick={() => setTab("zones")}
                label="Linked DNS Zones"
              />
            )}
            <TabButton
              active={tab === "certs"}
              onClick={() => setTab("certs")}
              label="Certificates"
            />
            <TabButton
              active={tab === "alerts"}
              onClick={() => setTab("alerts")}
              label="Alert History"
            />
          </div>
          <div className="mt-4">
            {tab === "whois" && <WhoisTab domain={domain} />}
            {tab === "zones" && dnsOn && <LinkedZonesTab domain={domain} />}
            {tab === "certs" && <CertificatesTab domainId={domain.id} />}
            {tab === "alerts" && <AlertHistoryTab domainId={domain.id} />}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── InfoRow helper ───────────────────────────────────────────────────────────

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="text-sm">{value}</dd>
    </div>
  );
}
