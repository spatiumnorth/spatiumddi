import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  Building2,
  Loader2,
  RefreshCw,
} from "lucide-react";

import {
  alertsApi,
  asnsApi,
  ipamApi,
  type ASNRpkiRoaState,
  type AlertSeverity,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { RdapPanel } from "@/components/network/rdap-panel";
import { cn } from "@/lib/utils";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { CommunitiesTab } from "./CommunitiesTab";
import { PeeringsTab } from "./PeeringsTab";
import { BgpFootprintTab } from "./BgpFootprintTab";
import { BgpMonitorTab } from "./BgpMonitorTab";
import { LearnedRoutesTab } from "./LearnedRoutesTab";

import { errMsg, humanTime } from "./_shared";

type Tab =
  | "whois"
  | "rpki"
  | "footprint"
  | "monitor"
  | "learned"
  | "bgp"
  | "communities"
  | "ipam"
  | "alerts";

// ── Badges ───────────────────────────────────────────────────────────

const PILL_BASE =
  "inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium";

function KindBadge({ kind }: { kind: string }) {
  const cls =
    kind === "private"
      ? "bg-amber-500/15 text-amber-700 dark:text-amber-400"
      : "bg-sky-500/15 text-sky-700 dark:text-sky-400";
  return (
    <span
      className={cn(
        "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        cls,
      )}
    >
      {kind}
    </span>
  );
}

const WHOIS_COLOR: Record<string, string> = {
  ok: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  drift: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
  unreachable: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  "n/a": "bg-muted text-muted-foreground",
};
const WHOIS_LABEL: Record<string, string> = {
  ok: "OK",
  drift: "Drift",
  unreachable: "Unreachable",
  "n/a": "n/a",
};

function WhoisBadge({ state }: { state: string }) {
  return (
    <span
      className={cn(
        PILL_BASE,
        WHOIS_COLOR[state] ?? "bg-muted text-muted-foreground",
      )}
    >
      {WHOIS_LABEL[state] ?? state}
    </span>
  );
}

const ROA_STATE_COLOR: Record<ASNRpkiRoaState, string> = {
  valid:
    "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300",
  expiring_soon:
    "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300",
  expired: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300",
  not_found: "bg-zinc-100 text-zinc-700 dark:bg-zinc-500/15 dark:text-zinc-300",
};

const ROA_STATE_LABEL: Record<ASNRpkiRoaState, string> = {
  valid: "Valid",
  expiring_soon: "Expiring",
  expired: "Expired",
  not_found: "Not found",
};

function RoaStateBadge({ state }: { state: ASNRpkiRoaState }) {
  return (
    <span className={cn(PILL_BASE, ROA_STATE_COLOR[state])}>
      {ROA_STATE_LABEL[state] ?? state}
    </span>
  );
}

const SEVERITY_COLOR: Record<AlertSeverity, string> = {
  info: "bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300",
  warning:
    "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300",
  critical: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300",
};

function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return (
    <span className={cn(PILL_BASE, SEVERITY_COLOR[severity], "capitalize")}>
      {severity}
    </span>
  );
}

// ── Page ─────────────────────────────────────────────────────────────

export function AsnDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("whois");
  const { enabled: featureEnabled } = useFeatureModules();
  // #2518 — the refreshes are POSTs under the router's write gate on
  // 'manage_asns', as the ASN list's buttons are.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_asns"),
    "Requires write permission on ASNs",
  );

  const {
    data: asn,
    isFetching,
    isError,
  } = useQuery({
    queryKey: ["asn", id],
    queryFn: () => asnsApi.get(id),
    enabled: !!id,
  });

  const refreshMut = useMutation({
    mutationFn: () => asnsApi.refreshWhois(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asn", id] });
      qc.invalidateQueries({ queryKey: ["asns"] });
    },
  });

  const refreshRpkiMut = useMutation({
    mutationFn: () => asnsApi.refreshRpki(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asn-rpki-roas", id] });
    },
  });

  const { data: roas } = useQuery({
    queryKey: ["asn-rpki-roas", id],
    queryFn: () => asnsApi.getRpkiRoas(id),
    enabled: !!id && tab === "rpki",
  });

  const { data: spaces } = useQuery({
    queryKey: ["ipam-spaces"],
    queryFn: () => ipamApi.listSpaces(),
    enabled: !!id && tab === "ipam",
  });

  const { data: blocks } = useQuery({
    queryKey: ["ipam-blocks"],
    queryFn: () => ipamApi.listBlocks(),
    enabled: !!id && tab === "ipam",
  });

  const { data: alertEvents } = useQuery({
    queryKey: ["alert-events"],
    queryFn: () => alertsApi.listEvents({ limit: 500 }),
    enabled: !!id && tab === "alerts",
  });

  if (isError) {
    return (
      <div className="p-6">
        <p className="text-sm text-destructive">ASN not found.</p>
        <Link
          to="/network/asns"
          className="mt-2 inline-flex items-center gap-1 text-sm text-primary hover:underline"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to ASNs
        </Link>
      </div>
    );
  }

  if (!asn) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  // ``whois_data.raw`` is the full RDAP response payload. The RIRs
  // serve JSON, so this is normally a nested object that the
  // ``RdapPanel`` component below pulls into structured UI. Older
  // snapshots may have stored a plain string — render those as a
  // pre-formatted block.
  const rawValue = asn.whois_data?.raw;
  const rawString =
    typeof rawValue === "string" && rawValue.length > 0 ? rawValue : null;
  const rawObject =
    rawValue && typeof rawValue === "object" && !Array.isArray(rawValue)
      ? (rawValue as Record<string, unknown>)
      : null;
  const previousHolder =
    typeof asn.whois_data?.previous_holder === "string"
      ? (asn.whois_data.previous_holder as string)
      : null;
  const showHolderDriftDiff =
    asn.whois_state === "drift" &&
    !!previousHolder &&
    !!asn.holder_org &&
    previousHolder !== asn.holder_org;

  const sortedRoas = roas
    ? [...roas].sort((a, b) => {
        const stateOrder: Record<ASNRpkiRoaState, number> = {
          expired: 0,
          expiring_soon: 1,
          not_found: 2,
          valid: 3,
        };
        const so = (stateOrder[a.state] ?? 4) - (stateOrder[b.state] ?? 4);
        if (so !== 0) return so;
        if (!a.valid_to && !b.valid_to) return 0;
        if (!a.valid_to) return 1;
        if (!b.valid_to) return -1;
        return new Date(a.valid_to).getTime() - new Date(b.valid_to).getTime();
      })
    : [];

  const linkedSpaces = (spaces ?? []).filter(
    (s) => (s as { asn_id?: string | null }).asn_id === id,
  );
  const linkedBlocks = (blocks ?? []).filter(
    (b) => (b as { asn_id?: string | null }).asn_id === id,
  );

  const asnAlerts = (alertEvents ?? []).filter(
    (e) => e.subject_type === "asn" && e.subject_id === id,
  );

  const TABS: Array<[Tab, string]> = [
    ["whois", "WHOIS"],
    ["rpki", "RPKI ROAs"],
    ["footprint", "BGP Footprint"],
    ["monitor", "BGP Monitoring"],
    // Learned Routes (issue #566 Phase 3) — the internal Looking Glass
    // RIB view, next to BGP Monitoring's external hijack-detection view.
    // Hidden when network.looking_glass is off, unlike the tabs above
    // which all sit behind this page's own network.asn module.
    ...(featureEnabled("network.looking_glass")
      ? ([["learned", "Learned Routes"]] as Array<[Tab, string]>)
      : []),
    ["bgp", "BGP Peering"],
    ["communities", "Communities"],
    ["ipam", "IP Spaces / Blocks"],
    ["alerts", "Alert History"],
  ];

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <Link
              to="/network/asns"
              className="mb-1 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3 w-3" /> Back to ASNs
            </Link>
            <div className="flex flex-wrap items-center gap-2">
              <Building2 className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold font-mono">
                AS{asn.number}
              </h1>
              {asn.name && (
                <span className="text-base text-muted-foreground">
                  {asn.name}
                </span>
              )}
              <KindBadge kind={asn.kind} />
              {asn.holder_org && (
                <span className="text-xs text-muted-foreground">
                  {asn.holder_org}
                </span>
              )}
            </div>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={isFetching ? Loader2 : RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() => qc.invalidateQueries({ queryKey: ["asn", id] })}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              icon={refreshMut.isPending ? Loader2 : RefreshCw}
              iconClassName={refreshMut.isPending ? "animate-spin" : ""}
              disabled={refreshMut.isPending || asn.kind === "private"}
              onClick={() => refreshMut.mutate()}
              title={
                asn.kind === "private"
                  ? "Private ASN — no public WHOIS"
                  : undefined
              }
              {...writeGate}
            >
              Refresh WHOIS
            </HeaderButton>
            <HeaderButton
              icon={refreshRpkiMut.isPending ? Loader2 : RefreshCw}
              iconClassName={refreshRpkiMut.isPending ? "animate-spin" : ""}
              disabled={refreshRpkiMut.isPending || asn.kind === "private"}
              onClick={() => refreshRpkiMut.mutate()}
              title={
                asn.kind === "private"
                  ? "Private ASN — no RPKI ROAs issued"
                  : "Pull the global ROA dump and reconcile this ASN's ROAs"
              }
              {...writeGate}
            >
              Refresh RPKI
            </HeaderButton>
          </div>
        </div>

        {refreshMut.isError && (
          <div className="mt-2 text-xs text-destructive">
            {errMsg(refreshMut.error, "WHOIS refresh failed")}
          </div>
        )}
        {refreshRpkiMut.isError && (
          <div className="mt-2 text-xs text-destructive">
            {errMsg(refreshRpkiMut.error, "RPKI refresh failed")}
          </div>
        )}
        {refreshRpkiMut.isSuccess && refreshRpkiMut.data && (
          <div className="mt-2 text-xs text-muted-foreground">
            RPKI sync: +{refreshRpkiMut.data.added} added,{" "}
            {refreshRpkiMut.data.updated} updated, {refreshRpkiMut.data.removed}{" "}
            removed
          </div>
        )}

        <div className="mt-4 -mb-px flex gap-1 border-b">
          {TABS.map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${
                tab === key
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        {tab === "whois" && (
          <div className="space-y-4">
            {asn.whois_state === "unreachable" && (
              <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-700 dark:text-amber-300">
                <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                RDAP lookup failed — check connectivity
              </div>
            )}

            {showHolderDriftDiff && (
              <div className="rounded-md border border-rose-500/40 bg-rose-500/5 p-4">
                <div className="mb-3 flex items-center gap-2 text-sm font-medium text-rose-700 dark:text-rose-300">
                  <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                  Holder drift detected
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <p className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                      Previous holder
                    </p>
                    <p className="rounded border bg-muted/30 px-3 py-2 text-sm font-mono">
                      {previousHolder}
                    </p>
                  </div>
                  <div>
                    <p className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                      Current holder
                    </p>
                    <p className="rounded border border-rose-300 bg-rose-50/50 px-3 py-2 text-sm font-mono dark:border-rose-800 dark:bg-rose-950/20">
                      {asn.holder_org}
                    </p>
                  </div>
                </div>
                {asn.whois_last_checked_at && (
                  <p className="mt-3 text-[11px] text-muted-foreground">
                    Detected at{" "}
                    {new Date(asn.whois_last_checked_at).toLocaleString()}
                  </p>
                )}
              </div>
            )}

            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <InfoRow label="Holder Org" value={asn.holder_org ?? "—"} />
              <InfoRow label="Registry" value={asn.registry.toUpperCase()} />
              <InfoRow
                label="WHOIS State"
                value={<WhoisBadge state={asn.whois_state} />}
              />
              <InfoRow
                label="Last Checked"
                value={
                  asn.whois_last_checked_at
                    ? new Date(asn.whois_last_checked_at).toLocaleString()
                    : "—"
                }
              />
            </div>

            {rawObject ? (
              <RdapPanel payload={rawObject} kind="asn" />
            ) : rawString ? (
              <pre className="rounded-md border bg-muted/30 p-3 text-xs font-mono overflow-auto max-h-96 whitespace-pre-wrap">
                {rawString}
              </pre>
            ) : (
              <p className="text-xs text-muted-foreground">
                {asn.kind === "private"
                  ? "No raw WHOIS data — a private ASN has no public WHOIS."
                  : "No raw WHOIS data — run Refresh WHOIS to populate."}
              </p>
            )}
          </div>
        )}

        {tab === "rpki" && (
          <div className="rounded-lg border">
            {sortedRoas.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                No ROAs found for this ASN
              </div>
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-card shadow-[inset_0_-1px_0] shadow-border">
                  <tr>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Prefix
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Max Length
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Valid From
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Valid To
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Trust Anchor
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      State
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sortedRoas.map((roa) => (
                    <tr
                      key={roa.id}
                      className="border-b last:border-0 hover:bg-muted/20"
                    >
                      <td className="whitespace-nowrap px-3 py-2 font-mono">
                        {roa.prefix}
                      </td>
                      <td className="px-3 py-2">/{roa.max_length}</td>
                      <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                        {roa.valid_from
                          ? new Date(roa.valid_from).toLocaleString()
                          : "—"}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                        {roa.valid_to
                          ? new Date(roa.valid_to).toLocaleString()
                          : "—"}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 uppercase">
                        {roa.trust_anchor}
                      </td>
                      <td className="px-3 py-2">
                        <RoaStateBadge state={roa.state} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === "footprint" && (
          <BgpFootprintTab asnNumber={asn.number} kind={asn.kind} />
        )}

        {tab === "monitor" && <BgpMonitorTab asnId={id} asnKind={asn.kind} />}

        {tab === "learned" && (
          <LearnedRoutesTab asnNumber={asn.number} asnId={id} />
        )}

        {tab === "bgp" && <PeeringsTab asnId={id} />}

        {tab === "communities" && <CommunitiesTab asnId={id} />}

        {tab === "ipam" && (
          <div className="space-y-6">
            <section>
              <h2 className="mb-2 text-sm font-semibold">IP Spaces</h2>
              {linkedSpaces.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No linked spaces/blocks
                </p>
              ) : (
                <div className="rounded-lg border">
                  <table className="w-full text-xs">
                    <thead className="bg-muted/30">
                      <tr className="border-b">
                        <th className="px-3 py-2 text-left font-medium">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium">
                          Description
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {linkedSpaces.map((s) => (
                        <tr
                          key={s.id}
                          className="border-b last:border-0 hover:bg-muted/20"
                        >
                          <td className="px-3 py-2 font-medium">{s.name}</td>
                          <td className="px-3 py-2 text-muted-foreground">
                            {s.description || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <section>
              <h2 className="mb-2 text-sm font-semibold">IP Blocks</h2>
              {linkedBlocks.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No linked spaces/blocks
                </p>
              ) : (
                <div className="rounded-lg border">
                  <table className="w-full text-xs">
                    <thead className="bg-muted/30">
                      <tr className="border-b">
                        <th className="px-3 py-2 text-left font-medium">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium">
                          CIDR
                        </th>
                        <th className="px-3 py-2 text-left font-medium">
                          Description
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {linkedBlocks.map((b) => (
                        <tr
                          key={b.id}
                          className="border-b last:border-0 hover:bg-muted/20"
                        >
                          <td className="px-3 py-2 font-medium">{b.name}</td>
                          <td className="px-3 py-2 font-mono">{b.network}</td>
                          <td className="px-3 py-2 text-muted-foreground">
                            {b.description || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
        )}

        {tab === "alerts" && (
          <div className="rounded-lg border">
            {asnAlerts.length === 0 ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                No alert events for this ASN
              </div>
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-muted/30">
                  <tr className="border-b">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Rule Type
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Severity
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      State
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Fired At
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Resolved At
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {asnAlerts.map((e) => (
                    <tr
                      key={e.id}
                      className="border-b last:border-0 hover:bg-muted/20"
                    >
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                        {e.subject_display || e.subject_type}
                      </td>
                      <td className="px-3 py-2">
                        <SeverityBadge severity={e.severity} />
                      </td>
                      <td className="px-3 py-2">
                        {e.resolved_at ? (
                          <span className="text-muted-foreground">
                            resolved
                          </span>
                        ) : (
                          <span className="text-amber-600 dark:text-amber-400">
                            open
                          </span>
                        )}
                      </td>
                      <td
                        className="whitespace-nowrap px-3 py-2 text-muted-foreground"
                        title={e.fired_at}
                      >
                        {humanTime(e.fired_at)}
                      </td>
                      <td
                        className="whitespace-nowrap px-3 py-2 text-muted-foreground"
                        title={e.resolved_at ?? ""}
                      >
                        {e.resolved_at ? humanTime(e.resolved_at) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </dt>
      <dd className="mt-0.5 text-sm">{value}</dd>
    </div>
  );
}
