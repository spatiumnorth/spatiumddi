import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Loader2,
  RefreshCw,
  BellOff,
  Search,
  ShieldCheck,
  ShieldQuestion,
  Ban,
} from "lucide-react";

import { Modal } from "@/components/ui/modal";
import { cn } from "@/lib/utils";
import {
  authApi,
  dnsThreatApi,
  type DNSClientWindow,
  type DNSTunnelSignal,
} from "@/lib/api";

/**
 * Logs → DNS Threat (issue #699).
 *
 * Scored per-client windows, worst first. DNS tunneling hides payload
 * in the names a host looks up, under a domain the attacker's own
 * server answers for — it is the exfiltration path a firewall never
 * inspects.
 *
 * Two framing decisions worth keeping:
 *
 * 1. **An empty list is not an all-clear.** The rollup only has rows
 *    when the default-off module is on AND a DNS group has query
 *    logging enabled, so "nothing here" has two very different
 *    meanings. The empty state says which one it is rather than
 *    rendering a reassuring blank.
 * 2. **The score always shows its working.** Every signal is listed
 *    with its contribution, including the ones that scored zero, so an
 *    operator can see what was considered — "your entropy is fine,
 *    it's the fan-out that's odd" beats a bare 62.
 *
 * #699 asks for a deep link from a finding to the IP detail modal.
 * Not wired yet: the IPAM page accepts ``?subnet=`` / ``?block=`` /
 * ``?space=`` but has no parameter that opens a specific address, and
 * a button that silently does nothing is worse than no button. Needs
 * an ``?ip=`` entry point on IPAMPage first.
 */

type Detection = "tunnel" | "beacon" | "dga";

/**
 * One table driving every per-detection difference: which score the row
 * shows, which signals its evidence panel renders, and — critically —
 * what the score is CALLED. The top band used to be hard-coded "Likely
 * tunnel" for all three, so a DGA finding rendered as the one structural
 * conclusion it is not (a tunnel concentrates under one parent, a DGA
 * sprays across many).
 */
const DETECTIONS: Record<
  Detection,
  {
    label: string;
    topBand: string;
    score: (w: DNSClientWindow) => number;
    signals: (w: DNSClientWindow) => DNSTunnelSignal[];
  }
> = {
  tunnel: {
    label: "Tunneling (content)",
    topBand: "Likely tunnel",
    score: (w) => w.tunnel_score,
    signals: (w) => w.tunnel_signals,
  },
  beacon: {
    label: "Beaconing (timing)",
    topBand: "Likely beacon",
    score: (w) => w.beacon_score,
    // Beaconing reports per-name candidates rather than weighted
    // signals, so its panel renders those instead; showing the tunnel
    // signals here (the previous fallthrough) was actively misleading.
    signals: () => [],
  },
  dga: {
    label: "DGA (name plausibility)",
    topBand: "Likely DGA",
    score: (w) => w.dga_score,
    signals: (w) => w.dga_signals,
  },
};

const SCORE_BANDS = [
  { min: 60, label: null, cls: "text-rose-600 dark:text-rose-400" },
  { min: 40, label: "Suspicious", cls: "text-amber-600 dark:text-amber-400" },
  {
    min: 20,
    label: "Worth a look",
    cls: "text-yellow-600 dark:text-yellow-500",
  },
] as const;

function band(score: number, detection: Detection) {
  const b = SCORE_BANDS.find((x) => score >= x.min);
  if (!b) return { label: "Low", cls: "text-muted-foreground" };
  // `label: null` on the top band means "name the detection" — that is
  // the only band whose wording is detection-specific.
  return { label: b.label ?? DETECTIONS[detection].topBand, cls: b.cls };
}

function ScoreCell({
  score,
  detection = "tunnel",
}: {
  score: number;
  detection?: Detection;
}) {
  const b = band(score, detection);
  return (
    <div className="flex items-center gap-2">
      <span className={`font-mono text-sm font-semibold ${b.cls}`}>
        {score.toFixed(0)}
      </span>
      <span className={`text-xs ${b.cls}`}>{b.label}</span>
    </div>
  );
}

function SignalBar({ signal }: { signal: DNSTunnelSignal }) {
  // Against the signal's OWN ceiling, which the backend reports:
  // weights differ (30/25/30/15), so scaling every bar by the same
  // factor made a fully-saturated payload-qtype signal render at 45%
  // and nothing ever reach 100%.
  const ceiling = signal.max_contribution || 0;
  const pct = ceiling
    ? Math.max(0, Math.min(100, (signal.contribution / ceiling) * 100))
    : 0;
  return (
    <li className="py-1">
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-xs">{signal.name}</span>
        <span className="shrink-0 text-xs text-muted-foreground">
          +{signal.contribution.toFixed(1)}
        </span>
      </div>
      <div className="mt-0.5 h-1 w-full overflow-hidden rounded bg-muted">
        <div
          className={
            signal.contribution > 0 ? "h-full bg-amber-500" : "h-full bg-muted"
          }
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="mt-0.5 break-words text-xs text-muted-foreground">
        {signal.detail}
      </p>
    </li>
  );
}

export function DNSThreatTab() {
  const [hours, setHours] = useState(24);
  const [minScore, setMinScore] = useState(20);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // Allowlisted windows are hidden by default but reachable: the
  // rollup keeps them so an operator can confirm "we looked at this
  // client and cleared it" rather than wondering why a chatty host
  // never appears at all.
  const [showAllowlisted, setShowAllowlisted] = useState(false);
  const [showMutes, setShowMutes] = useState(false);
  // Which detection to rank by. Explicit rather than a combined score:
  // tunneling and beaconing answer different questions, and an
  // operator hunting exfil shouldn't have their list reordered by a
  // chatty monitoring agent.
  const [detection, setDetection] = useState<Detection>("tunnel");
  const [inspecting, setInspecting] = useState<string | null>(null);
  const [muting, setMuting] = useState<string | null>(null);
  const qc = useQueryClient();
  // Only a superadmin can change feature modules, so only they get the link.
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: authApi.me,
    staleTime: 60_000,
  });
  const isSuperadmin = me?.is_superadmin ?? false;
  const refreshAll = () => {
    void qc.invalidateQueries({ queryKey: ["dns-threat-windows"] });
    void qc.invalidateQueries({ queryKey: ["dns-threat-summary"] });
    void qc.invalidateQueries({ queryKey: ["dns-threat-mutes"] });
  };
  const unmute = useMutation({
    mutationFn: (ip: string) => dnsThreatApi.unmute(ip),
    onSuccess: () => {
      refreshAll();
      void qc.invalidateQueries({ queryKey: ["dns-threat-mutes"] });
    },
  });

  const q = useQuery({
    queryKey: [
      "dns-threat-windows",
      hours,
      minScore,
      showAllowlisted,
      detection,
    ],
    queryFn: () =>
      dnsThreatApi.listWindows({
        hours,
        min_score: minScore,
        detection,
        include_allowlisted: showAllowlisted,
        limit: 200,
      }),
    retry: false,
  });
  const summaryQ = useQuery({
    queryKey: ["dns-threat-summary", hours],
    queryFn: () => dnsThreatApi.summary({ hours }),
    retry: false,
  });

  // A 404 here means the feature module is off, not that something
  // broke — the router include is module-gated.
  const moduleOff =
    (q.error as { response?: { status?: number } } | null)?.response?.status ===
    404;

  const rows = q.data ?? [];
  const summary = summaryQ.data;

  if (moduleOff) {
    return (
      <div className="rounded-lg border bg-card p-6">
        <div className="flex items-start gap-3">
          <ShieldQuestion className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" />
          <div>
            <h3 className="text-sm font-semibold">
              DNS threat analytics is off
            </h3>
            <p className="mt-1 max-w-2xl text-xs text-muted-foreground">
              Scoring reads the <strong>names your clients look up</strong>, so
              it is disabled by default rather than switched on by an upgrade.
              {isSuperadmin ? (
                <>
                  Enable <strong>DNS threat analytics</strong> (Security) on the{" "}
                  <Link
                    to="/admin/features"
                    className="text-primary underline underline-offset-2"
                  >
                    Features &amp; Integrations
                  </Link>{" "}
                  page to turn it on.
                </>
              ) : (
                <>
                  Ask an administrator to enable{" "}
                  <strong>DNS threat analytics</strong> (Security) on the
                  Features &amp; Integrations page.
                </>
              )}{" "}
              It also needs query logging enabled on at least one DNS server
              group (DNS → Server Groups → the group → Options) before there is
              anything to score.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3 rounded-lg border bg-card px-4 py-3">
        <div>
          <label className="mb-1 block text-xs font-medium">Detection</label>
          <select
            value={detection}
            onChange={(e) => setDetection(e.target.value as Detection)}
            className="rounded-md border bg-background px-2 py-1.5 text-sm"
          >
            <option value="tunnel">Tunneling (name content)</option>
            <option value="beacon">Beaconing (timing)</option>
            <option value="dga">DGA (name plausibility)</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium">Window</label>
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="rounded-md border bg-background px-2 py-1.5 text-sm"
          >
            <option value={6}>Last 6 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={72}>Last 3 days</option>
            <option value={168}>Last 7 days</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium">
            Minimum score
          </label>
          <select
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
            className="rounded-md border bg-background px-2 py-1.5 text-sm"
          >
            <option value={0}>Everything (noisy)</option>
            <option value={20}>20 — worth a look</option>
            <option value={40}>40 — suspicious</option>
            <option value={60}>60 — likely tunnel</option>
          </select>
        </div>
        <button
          type="button"
          onClick={() => setShowMutes((v) => !v)}
          className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
        >
          <BellOff className="h-4 w-4" />
          Muted clients
        </button>
        <label className="flex items-center gap-1.5 text-xs">
          <input
            type="checkbox"
            checked={showAllowlisted}
            onChange={(e) => setShowAllowlisted(e.target.checked)}
          />
          Show cleared (allowlisted)
        </label>
        <button
          type="button"
          onClick={() => {
            void q.refetch();
            void summaryQ.refetch();
          }}
          className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>

        {summary && (
          <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
            {summary.has_data ? (
              <>
                <ShieldCheck className="h-4 w-4" />
                {summary.windows_scored} windows · {summary.clients_seen}{" "}
                clients scored
              </>
            ) : (
              <>
                <AlertTriangle className="h-4 w-4 text-amber-500" />
                No windows scored yet
              </>
            )}
          </div>
        )}
      </div>

      {q.isLoading ? (
        <div className="flex items-center gap-2 rounded-lg border bg-card px-4 py-6 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Scoring&hellip;
        </div>
      ) : rows.length === 0 ? (
        <div className="rounded-lg border bg-card p-6">
          <div className="flex items-start gap-3">
            {summary?.has_data ? (
              <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <ShieldQuestion className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
            )}
            <div>
              <h3 className="text-sm font-semibold">
                {summary?.has_data
                  ? "Nothing scoring above the threshold"
                  : "No data to score yet"}
              </h3>
              <p className="mt-1 max-w-2xl text-xs text-muted-foreground">
                {summary?.has_data ? (
                  <>
                    {summary.clients_seen} client(s) were scored over this
                    window and none crossed {minScore}. Lower the minimum score
                    to see the full picture.
                  </>
                ) : (
                  <>
                    The rollup has scored nothing in this period, which is{" "}
                    <strong>not the same as an all-clear</strong>. Check that a
                    DNS server group has query logging enabled — without it
                    there are no queries to analyse.
                  </>
                )}
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full min-w-[820px] text-sm">
            <thead>
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="px-4 py-2 font-medium">Score</th>
                <th className="px-4 py-2 font-medium">Client</th>
                <th className="px-4 py-2 font-medium">Window</th>
                <th className="px-4 py-2 font-medium">Queries</th>
                <th className="px-4 py-2 font-medium">Concentrated on</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {rows.map((w) => (
                <Row
                  key={w.id}
                  w={w}
                  open={expanded.has(w.id)}
                  onToggle={() =>
                    setExpanded((prev) => {
                      const next = new Set(prev);
                      if (next.has(w.id)) next.delete(w.id);
                      else next.add(w.id);
                      return next;
                    })
                  }
                  onInspect={() => setInspecting(w.client_ip)}
                  detection={detection}
                  onMute={() => setMuting(w.client_ip)}
                  onUnmute={() => unmute.mutate(w.client_ip)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showMutes && (
        <MutedClientsPanel
          onUnmute={(ip) => unmute.mutate(ip)}
          error={unmute.error as Error | null}
        />
      )}

      {muting && (
        <MuteModal
          clientIp={muting}
          onClose={() => setMuting(null)}
          onDone={refreshAll}
        />
      )}

      {inspecting && (
        <ClientDetailModal
          detection={detection}
          clientIp={inspecting}
          hours={hours}
          onClose={() => setInspecting(null)}
        />
      )}

      {/* Blocklist attribution. Rendered as its own section rather than a
          fourth detection mode because it is ground truth, not a score:
          named matched a policy and logged it, so there is nothing to
          threshold and nothing to rank by confidence.

          Carries the same card treatment as every sibling above — the
          root is a bare `flex flex-col gap-4`, so the horizontal inset
          comes from each child's own `px-4`, not from the container. A
          bare <section> here rendered flush against the left edge and
          visibly out of line with the rest of the tab. */}
      {!moduleOff && (
        <section className="rounded-lg border bg-card px-4 py-3">
          <h3 className="mb-1 text-sm font-semibold">Blocklist hits (RPZ)</h3>
          <p className="mb-3 text-xs text-muted-foreground">
            Which machines keep reaching for domains the blocklists block.
            Unlike the scores above this is not a heuristic — every row is a
            policy that actually fired.
          </p>
          <RPZPanel hours={hours} />
        </section>
      )}
    </div>
  );
}

function Row({
  w,
  open,
  onToggle,
  onInspect,
  onMute,
  onUnmute,
  detection,
}: {
  w: DNSClientWindow;
  open: boolean;
  detection: Detection;
  onToggle: () => void;
  onInspect: () => void;
  onMute: () => void;
  onUnmute: () => void;
}) {
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <>
      {/* The whole row toggles the evidence panel — scanning a list of
          findings means opening and closing several in a row, and
          hunting for a small button each time is friction. The button
          stays as the visible affordance that the row does something. */}
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-b last:border-0 hover:bg-accent/40 ${
          w.muted ? "opacity-50" : ""
        }`}
      >
        <td className="px-4 py-2">
          <ScoreCell
            score={DETECTIONS[detection].score(w)}
            detection={detection}
          />
        </td>
        <td className="px-4 py-2 font-mono text-xs">
          {w.client_ip}
          {w.muted && (
            <span
              className="ml-1.5 inline-flex items-center gap-1 rounded bg-muted px-1 py-0.5 font-sans text-[10px] text-muted-foreground"
              title={w.mute_reason ?? undefined}
            >
              <BellOff className="h-2.5 w-2.5" />
              muted
            </span>
          )}
        </td>
        <td className="px-4 py-2 text-xs text-muted-foreground">
          {new Date(w.window_start).toLocaleString()}
        </td>
        <td className="px-4 py-2 text-xs">
          {w.query_count.toLocaleString()}
          <span className="ml-1 text-muted-foreground">
            ({w.distinct_qnames.toLocaleString()} unique)
          </span>
        </td>
        <td className="px-4 py-2 text-xs">
          {w.top_parent ? (
            <>
              <span className="font-mono">{w.top_parent}</span>
              <span className="ml-1 text-muted-foreground">
                ({w.top_parent_subdomains} subdomains)
              </span>
            </>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </td>
        {/* Clicks inside the action cell must not also fire the row's
            toggle, or opening the modal would leave the panel flapping. */}
        <td className="px-4 py-2" onClick={(e) => e.stopPropagation()}>
          <div className="flex justify-end gap-1.5">
            {w.muted ? (
              <button
                type="button"
                onClick={onUnmute}
                className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:bg-accent"
              >
                Unmute
              </button>
            ) : (
              <button
                type="button"
                onClick={onMute}
                className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:bg-accent"
              >
                <BellOff className="h-3 w-3" />
                Mute
              </button>
            )}
            <button
              type="button"
              onClick={onInspect}
              className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:bg-accent"
            >
              <Search className="h-3 w-3" />
              Details
            </button>
            <button
              type="button"
              onClick={onToggle}
              className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs hover:bg-accent"
            >
              <Chevron className="h-3 w-3" />
              Why
            </button>
          </div>
        </td>
      </tr>
      {open && (
        <tr className="border-b last:border-0">
          <td colSpan={6} className="bg-muted/30 px-4 py-3">
            {w.muted && w.mute_reason && (
              <p className="mb-2 rounded border border-dashed px-2 py-1 text-xs text-muted-foreground">
                <strong>Muted:</strong> {w.mute_reason}
                {w.mute_until &&
                  ` (until ${new Date(w.mute_until).toLocaleDateString()})`}
              </p>
            )}
            {detection === "beacon" ? (
              <>
                <p className="mb-2 text-xs text-muted-foreground">
                  {w.beacon_detail ||
                    "No name repeated on a regular cadence in this window."}
                </p>
                {w.beacon_candidates.length > 0 && (
                  <ul className="mb-2">
                    {w.beacon_candidates.map((c) => (
                      <li key={c.qname} className="py-0.5 text-xs">
                        <span className="font-mono">{c.qname}</span>
                        <span className="ml-2 text-muted-foreground">
                          every {c.period_seconds}s · {c.samples} samples ·
                          variation {(c.cv * 100).toFixed(0)}% · scored{" "}
                          {c.score.toFixed(0)}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="mb-2 text-xs text-amber-600 dark:text-amber-400">
                  Periodic lookups are frequently benign — monitoring agents,
                  health checks and update checkers all look like this. Check
                  the name against what the host runs before treating it as a
                  callback.
                </p>
              </>
            ) : detection === "dga" ? (
              <>
                <p className="mb-2 text-xs text-muted-foreground">
                  {w.dga_detail ||
                    "No crop of generated-looking domains in this window."}
                </p>
                {w.dga_candidates.length > 0 && (
                  <ul className="mb-2">
                    {w.dga_candidates.map((c) => (
                      <li key={c.parent} className="py-0.5 text-xs">
                        <span className="font-mono">{c.parent}</span>
                        <span className="ml-2 text-muted-foreground">
                          {(c.implausibility * 100).toFixed(0)}% implausible
                          bigrams · {(c.vowel_ratio * 100).toFixed(0)}% vowels
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="mb-2 text-xs text-amber-600 dark:text-amber-400">
                  Scored on name plausibility alone — the BIND9 query log
                  carries no rcode, so there is no NXDOMAIN prior to corroborate
                  it. Hashed-CDN buckets, shortlink services and odd brand names
                  share the shape, so confirm the domains above before treating
                  this as an infection.
                </p>
              </>
            ) : (
              <p className="mb-2 text-xs text-muted-foreground">
                Every signal is listed, including those contributing nothing —
                what was <em>ruled out</em> matters as much as what fired.
              </p>
            )}
            <ul className="max-w-3xl">
              {DETECTIONS[detection].signals(w).map((s) => (
                <SignalBar key={s.name} signal={s} />
              ))}
            </ul>
            <p className="mt-2 text-xs text-muted-foreground">
              Longest label {w.max_label_length} chars · mean entropy{" "}
              {w.mean_label_entropy.toFixed(2)} bits/char ·{" "}
              {w.payload_qtype_count} payload-bearing qtypes · seen by{" "}
              {w.server_count} server(s)
            </p>
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * Per-client deep dive.
 *
 * Exists for the one question the inline evidence panel structurally
 * cannot answer: **is this sustained?** A single hour at 70 is a
 * curiosity; six consecutive hours at 70 is someone's data leaving the
 * building. The row shows one window; this shows the client's whole
 * retained history, newest first, so the shape is visible at a glance.
 */
function ClientDetailModal({
  detection,
  clientIp,
  hours,
  onClose,
}: {
  detection: Detection;
  clientIp: string;
  hours: number;
  onClose: () => void;
}) {
  const scoreOf = DETECTIONS[detection].score;
  const q = useQuery({
    queryKey: ["dns-threat-client", clientIp],
    // Per-client fetch returns that client's full history regardless of
    // score — a window that dropped back to 0 is part of the story.
    queryFn: () =>
      dnsThreatApi.listWindows({
        client_ip: clientIp,
        hours: Math.max(hours, 24 * 7),
        include_allowlisted: true,
        limit: 200,
      }),
  });
  const rows = q.data ?? [];
  const peak = rows.reduce((m, r) => Math.max(m, scoreOf(r)), 0);
  const totalQueries = rows.reduce((n, r) => n + r.query_count, 0);
  const scored = rows.filter((r) => scoreOf(r) > 0);

  return (
    <Modal title={`DNS behaviour — ${clientIp}`} onClose={onClose} wide>
      {q.isLoading ? (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading history&hellip;
        </div>
      ) : rows.length === 0 ? (
        <p className="py-6 text-sm text-muted-foreground">
          No retained windows for this client.
        </p>
      ) : (
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat
              label={`Peak ${DETECTIONS[detection].label.split(" ")[0].toLowerCase()} score`}
              value={peak.toFixed(0)}
            />
            <Stat label="Windows retained" value={String(rows.length)} />
            <Stat label="Windows scoring" value={String(scored.length)} />
            <Stat label="Queries seen" value={totalQueries.toLocaleString()} />
          </div>

          <div>
            <h4 className="mb-1 text-xs font-semibold">Score over time</h4>
            <p className="mb-2 text-xs text-muted-foreground">
              Newest first. A run of consecutive scoring hours is the signal
              that matters — one-off spikes are usually noise.
            </p>
            <ul className="max-h-52 overflow-y-auto rounded border">
              {rows.map((r) => (
                <li
                  key={r.id}
                  className="flex items-center gap-2 border-b px-2 py-1 text-xs last:border-0"
                >
                  <span className="w-32 shrink-0 text-muted-foreground">
                    {new Date(r.window_start).toLocaleString()}
                  </span>
                  <span className="h-1.5 flex-1 overflow-hidden rounded bg-muted">
                    <span
                      className={
                        scoreOf(r) >= 60
                          ? "block h-full bg-rose-500"
                          : scoreOf(r) >= 20
                            ? "block h-full bg-amber-500"
                            : "block h-full bg-emerald-500/50"
                      }
                      style={{ width: `${Math.max(2, scoreOf(r))}%` }}
                    />
                  </span>
                  <span className="w-8 shrink-0 text-right font-mono">
                    {scoreOf(r).toFixed(0)}
                  </span>
                  <span className="w-40 shrink-0 truncate text-muted-foreground">
                    {r.allowlisted ? "cleared (allowlisted)" : r.top_parent}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="mb-1 text-xs font-semibold">
              Signals — most recent window
            </h4>
            <ul>
              {(rows[0]?.tunnel_signals ?? []).map((sig) => (
                <SignalBar key={sig.name} signal={sig} />
              ))}
            </ul>
          </div>

          <p className="text-xs text-muted-foreground">
            To see the actual names this client asked for, open the{" "}
            <strong>DNS Queries</strong> tab and filter on{" "}
            <span className="font-mono">{clientIp}</span>.
          </p>
        </div>
      )}
    </Modal>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border px-2 py-1.5">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}

/**
 * Clear a reviewed finding.
 *
 * A mute on the CLIENT, not a delete of the rows — deleting wouldn't
 * stick (the aggregator recomputes recent hours and upserts) and would
 * destroy evidence of what may be an exfiltration event. The reason is
 * required, because an unexplained mute is how a real incident gets
 * buried by someone tidying a dashboard.
 */
function MuteModal({
  clientIp,
  onClose,
  onDone,
}: {
  clientIp: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  // Default to an expiring mute: a snap "this is fine" should age out
  // and get re-examined rather than silently outlive whoever made it.
  const [days, setDays] = useState<number | "forever">(30);

  const save = useMutation({
    mutationFn: () =>
      dnsThreatApi.mute({
        client_ip: clientIp,
        reason,
        muted_until:
          days === "forever"
            ? null
            : new Date(Date.now() + days * 86400_000).toISOString(),
      }),
    onSuccess: () => {
      onDone();
      onClose();
    },
  });

  return (
    <Modal title={`Mute findings for ${clientIp}`} onClose={onClose}>
      <div className="flex flex-col gap-3">
        <p className="text-xs text-muted-foreground">
          Hides this client from the Threat tab and stops the{" "}
          <strong>DNS tunneling suspected</strong> alert firing for it. The
          scored windows and their evidence are kept — muting records a
          decision, it doesn&rsquo;t delete anything.
        </p>

        <div>
          <label className="mb-1 block text-xs font-medium">
            Why is this expected? <span className="text-rose-500">*</span>
          </label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            placeholder="e.g. Veeam backup agent — chunks payload into subdomains by design"
            className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
          />
          <p className="mt-1 text-xs text-muted-foreground">
            Required. The next person to look at this host reads this instead of
            re-investigating it.
          </p>
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium">Mute for</label>
          <select
            value={String(days)}
            onChange={(e) =>
              setDays(
                e.target.value === "forever"
                  ? "forever"
                  : Number(e.target.value),
              )
            }
            className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
          >
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
            <option value="forever">Indefinitely</option>
          </select>
        </div>

        {save.isError && (
          <p className="text-xs text-rose-600 dark:text-rose-400">
            {(save.error as Error).message}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={reason.trim().length < 3 || save.isPending}
            onClick={() => save.mutate()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Mute client
          </button>
        </div>
      </div>
    </Modal>
  );
}

/**
 * The muted-clients list.
 *
 * Without it, the only Unmute affordance was a button on a listed
 * window row — so an indefinite mute became unreachable the moment the
 * client stopped scoring (or its windows aged past the 30-day prune),
 * permanently suppressing a critical alert with no way to discover or
 * revoke it short of a psql session.
 */
function MutedClientsPanel({
  onUnmute,
  error,
}: {
  onUnmute: (ip: string) => void;
  error: Error | null;
}) {
  const q = useQuery({
    queryKey: ["dns-threat-mutes"],
    queryFn: () => dnsThreatApi.listMutes(),
    retry: false,
  });
  const rows = q.data ?? [];

  return (
    <section className="rounded-lg border bg-card">
      <div className="border-b px-4 py-3">
        <h3 className="text-sm font-semibold">Muted clients</h3>
        <p className="mt-0.5 text-xs text-muted-foreground">
          Reviewed and cleared. These do not appear in the findings list and do
          not fire the tunneling alert. Expired mutes are kept — they explain
          why a client started appearing again.
        </p>
      </div>
      {error && (
        <p className="border-b px-4 py-2 text-xs text-rose-600 dark:text-rose-400">
          Could not un-mute: {error.message}
        </p>
      )}
      {q.isLoading ? (
        <p className="px-4 py-4 text-sm text-muted-foreground">
          Loading&hellip;
        </p>
      ) : rows.length === 0 ? (
        <p className="px-4 py-4 text-sm text-muted-foreground">
          No clients are muted.
        </p>
      ) : (
        <ul className="divide-y">
          {rows.map((m) => (
            <li
              key={m.id}
              className="flex flex-wrap items-center gap-2 px-4 py-2 text-xs"
            >
              <span className="font-mono">{m.client_ip}</span>
              {!m.active && (
                <span className="rounded bg-muted px-1 py-0.5 text-[10px] text-muted-foreground">
                  expired
                </span>
              )}
              <span className="min-w-0 flex-1 break-words text-muted-foreground">
                {m.reason}
              </span>
              <span className="shrink-0 text-muted-foreground">
                {m.muted_until
                  ? `until ${new Date(m.muted_until).toLocaleDateString()}`
                  : "indefinite"}
                {m.muted_by_display && ` · ${m.muted_by_display}`}
              </span>
              {m.active && (
                <button
                  type="button"
                  onClick={() => onUnmute(m.client_ip)}
                  className="shrink-0 rounded-md border px-2.5 py-1 hover:bg-accent"
                >
                  Unmute
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * RPZ hit attribution (#699).
 *
 * The other three surfaces on this tab are heuristics with a score. This
 * one is ground truth: named matched a response-policy rule and logged
 * it, so there is nothing to infer and nothing to threshold — only to
 * attribute and rank. That difference is why it renders as its own
 * panel rather than a fourth entry in the detection dropdown.
 *
 * PASSTHRU is reported separately, never inside the blocked count: it is
 * an explicit ALLOW (a blocklist exception firing), and folding it in
 * would make a correctly-tuned allowlist read as an infection.
 */
function RPZPanel({ hours }: { hours: number }) {
  const summary = useQuery({
    queryKey: ["dns-threat-rpz-summary", hours],
    queryFn: () => dnsThreatApi.rpzSummary({ hours }),
  });
  const clients = useQuery({
    queryKey: ["dns-threat-rpz-clients", hours],
    queryFn: () => dnsThreatApi.rpzClients({ hours, limit: 20 }),
  });
  // Clicking a client narrows the per-hit list below (#914). The rollup
  // says a host has 412 blocked lookups; closing out "the user says this
  // site does not work" needs the names themselves.
  const [focusClient, setFocusClient] = useState<string | null>(null);
  const hits = useQuery({
    queryKey: ["dns-threat-rpz-hits", hours, focusClient],
    queryFn: () =>
      dnsThreatApi.rpzHits({
        hours,
        limit: 100,
        ...(focusClient ? { client_ip: focusClient } : {}),
      }),
  });

  if (summary.isLoading) {
    return (
      <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading blocklist activity&hellip;
      </div>
    );
  }
  const s = summary.data;
  // "Nothing was blocked" and "this never ran" must stay distinguishable
  // — zero blocks is a plausible real answer on a quiet network, so the
  // UI must not have to guess. Same contract the threat summary carries.
  if (!s?.has_data) {
    return (
      <div className="text-sm text-muted-foreground">
        <p className="mb-1 font-medium text-foreground">
          No blocklist activity recorded yet
        </p>
        <p>
          RPZ attribution needs a BIND9 group with query logging enabled and at
          least one blocklist assigned. This reads &quot;not running yet&quot;
          rather than &quot;nothing was blocked&quot; — once the pipeline is
          live, a genuinely quiet network shows zeroes here instead of this
          message.
        </p>
      </div>
    );
  }

  const rows = clients.data ?? [];
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Blocked lookups" value={s.blocked_hits.toLocaleString()} />
        <Stat label="Clients blocked" value={String(s.clients_blocked)} />
        <Stat label="Distinct names" value={String(s.distinct_names)} />
        <Stat
          label="Allowed (passthru)"
          value={s.passthru_hits.toLocaleString()}
        />
      </div>

      <div>
        <h4 className="mb-1 text-xs font-semibold">
          Clients reaching for blocked domains
        </h4>
        <p className="mb-2 text-xs text-muted-foreground">
          A single blocked lookup is an ad on a web page. Hundreds from one host
          is a machine with something running on it — which is the question the
          blocklists could always answer and never did.
        </p>
        {rows.length === 0 ? (
          <p className="py-3 text-sm text-muted-foreground">
            Nothing was blocked in this window.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[40rem] text-sm">
              <thead className="border-b text-left text-xs text-muted-foreground">
                <tr>
                  <th className="py-1.5 pr-3 font-medium">Client</th>
                  <th className="py-1.5 pr-3 font-medium">Blocked</th>
                  <th className="py-1.5 pr-3 font-medium">Names</th>
                  <th className="py-1.5 pr-3 font-medium">Most blocked</th>
                  <th className="py-1.5 font-medium">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.client_ip}
                    onClick={() =>
                      setFocusClient(
                        focusClient === r.client_ip ? null : r.client_ip,
                      )
                    }
                    className={cn(
                      "cursor-pointer border-b last:border-0 hover:bg-muted/40",
                      focusClient === r.client_ip && "bg-muted/60",
                    )}
                    title="Show this client's individual blocked lookups"
                  >
                    <td className="py-1.5 pr-3 font-mono text-xs">
                      <span className="inline-flex items-center gap-1.5">
                        {r.noisy && (
                          <Ban className="h-3.5 w-3.5 text-rose-500" />
                        )}
                        {r.client_ip}
                      </span>
                    </td>
                    <td
                      className={`py-1.5 pr-3 font-mono ${
                        r.noisy ? "font-semibold text-rose-600" : ""
                      }`}
                    >
                      {r.hits.toLocaleString()}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs">
                      {r.distinct_names}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs break-all">
                      {r.top_qname ?? "—"}
                    </td>
                    <td className="py-1.5 text-xs text-muted-foreground">
                      {new Date(r.last_seen).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div>
        <div className="mb-1 flex flex-wrap items-center gap-2">
          <h4 className="text-xs font-semibold">Recent blocked lookups</h4>
          {focusClient && (
            <button
              type="button"
              onClick={() => setFocusClient(null)}
              className="rounded-md border px-2 py-0.5 text-[11px] hover:bg-accent"
            >
              {focusClient} &times;
            </button>
          )}
        </div>
        <p className="mb-2 text-xs text-muted-foreground">
          The individual hits, newest first — what the counts above cannot tell
          you. Click a client to narrow. PASSTHRU rows are excluded: an
          exception firing is an explicit allow, not a block.
        </p>
        {hits.isLoading ? (
          <div className="flex items-center gap-2 py-3 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading&hellip;
          </div>
        ) : (hits.data ?? []).length === 0 ? (
          <p className="py-3 text-sm text-muted-foreground">
            No blocked lookups in this window.
          </p>
        ) : (
          <div className="max-h-96 overflow-auto">
            <table className="w-full min-w-[40rem] text-sm">
              <thead className="sticky top-0 border-b bg-card text-left text-xs text-muted-foreground">
                <tr>
                  <th className="py-1.5 pr-3 font-medium">Time</th>
                  <th className="py-1.5 pr-3 font-medium">Client</th>
                  <th className="py-1.5 pr-3 font-medium">Name</th>
                  <th className="py-1.5 pr-3 font-medium">Policy</th>
                  <th className="py-1.5 font-medium">Feed</th>
                </tr>
              </thead>
              <tbody>
                {(hits.data ?? []).map((h) => (
                  <tr key={h.id} className="border-b last:border-0">
                    <td className="py-1.5 pr-3 text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(h.ts).toLocaleString()}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs">
                      {h.client_ip ?? "—"}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs break-all">
                      {h.qname ?? "—"}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs">
                      {h.trigger} {h.policy}
                    </td>
                    <td className="py-1.5 font-mono text-xs break-all text-muted-foreground">
                      {h.rpz_zone ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
