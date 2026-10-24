import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import { useSearchParams } from "react-router-dom";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import {
  Activity,
  AlertTriangle,
  Ban,
  Calendar,
  ChevronDown,
  ChevronRight,
  Copy,
  FileClock,
  Info,
  Maximize2,
  RefreshCw,
  Search,
  ScrollText,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import {
  logsApi,
  type AgentLogSource,
  type DhcpAuditDay,
  type DhcpAuditRow,
  type DHCPActivityLogRow,
  type DNSQueryLogRow,
  type LogEventRow,
  type LogSource,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { AgentLogScopePicker } from "@/components/AgentLogScopePicker";
import {
  type AgentLogSelection,
  defaultSelection,
  selectionHost,
  selectionIsValid,
  selectionToScope,
} from "@/lib/agent-log-scope";
import { copyToClipboard } from "@/lib/clipboard";
import { cn } from "@/lib/utils";
import { DNSThreatTab } from "./logs/DNSThreatTab";

/**
 * Logs page — central log viewer.
 *
 * Four tabs, two transports. Agent-driven (open-source) tabs ship
 * first because that's what most operators run; Windows-only tabs
 * are last so an all-Linux deployment doesn't open the page on a
 * blank Windows-only surface.
 *
 *   • **DNS Queries** — BIND9 / PowerDNS query log (client → qname
 *     → qtype). Pushed by the agent's QueryLogShipper after the
 *     daemon writes its query-log file (BIND9 ``logging { ... }``
 *     channel; PowerDNS ``log-dns-queries=yes``). Requires
 *     ``query_log_enabled`` on the DNS server group.
 *
 *   • **DHCP Activity** — Kea DHCPv4 activity (DISCOVER / OFFER /
 *     REQUEST / ACK, lease alloc, declines). Pushed by the Kea
 *     agent's LogShipper from the file output_options channel.
 *
 *   • **Event Log** — Windows Event Log (admin / operational events
 *     from DNS + DHCP server roles). Pulled via
 *     ``Get-WinEvent -FilterHashtable`` over WinRM. Applies to both
 *     DNS and DHCP servers.
 *
 *   • **DHCP Audit** — per-lease events (grants, renewals, releases,
 *     conflicts, DNS update results) parsed from
 *     ``C:\Windows\System32\dhcp\DhcpSrvLog-<Day>.log``. DHCP only.
 *     This is the actual "DHCP client requests" view for Windows;
 *     the Event Log tab covers service-level events like scope
 *     activation.
 *
 * All tabs auto-fetch on mount and on filter change; staleTime is
 * Infinity for the WinRM tabs so tab-switching doesn't re-hit the
 * DC, 5 s for the agent tabs since their backing rows update live.
 */

type Tab = "dns-queries" | "dns-threat" | "dhcp-activity" | "events" | "audit";

const TABS: readonly Tab[] = [
  "dns-queries",
  "dns-threat",
  "dhcp-activity",
  "events",
  "audit",
] as const;

const DHCP_TABS: ReadonlySet<Tab> = new Set<Tab>(["dhcp-activity", "audit"]);
// The DNS tabs read the DNS query log / threat scores, so they exist only
// while core.dns is on (#2135).
const DNS_TABS: ReadonlySet<Tab> = new Set<Tab>(["dns-queries", "dns-threat"]);

export function LogsPage() {
  // ``?tab=`` entry point so other surfaces can deep-link a specific
  // tab — the Security dashboard's DNS-tunneling card needs to land on
  // DNS Threat, and without this it silently opened DNS Queries
  // instead. Kept in the URL (not just state) so the link is
  // shareable and survives a refresh.
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("tab") as Tab | null;
  // #2130 — the DHCP tabs read DHCP logs, so they exist only while core.dhcp
  // is on. A deep link to one with it off (or before the module set has
  // loaded) lands on DNS Queries, not on a tab that is not there.
  const { enabled: moduleEnabled, ready: modulesReady } = useFeatureModules();
  const dhcpOn = modulesReady && moduleEnabled("core.dhcp");
  const dnsOn = modulesReady && moduleEnabled("core.dns");
  // #2135 — the same for the DNS tabs. Their buttons stay up until the module
  // set has loaded (DNS Queries is the default and a bar with no tabs in it
  // blinks); only the tab BODIES, which fire the queries, wait.
  const dnsTabsShown = !modulesReady || dnsOn;
  const wanted: Tab | null =
    requested && TABS.includes(requested) ? requested : null;
  // Only the Event Log tab is valid with neither module on, so every other
  // landing (a deep link, or none) waits for the module set rather than
  // mounting a tab, and firing its query, for a moment first.
  const awaitingModules = !modulesReady && wanted !== "events";
  const tabAllowed = (t: Tab) =>
    (dnsOn || !DNS_TABS.has(t)) && (dhcpOn || !DHCP_TABS.has(t));
  // With DNS off the default is the first tab that still exists, and with
  // both off that is the Event Log: a valid tab, never a blank page.
  const fallbackTab: Tab = dnsOn
    ? "dns-queries"
    : dhcpOn
      ? "dhcp-activity"
      : "events";
  // Until the module set has loaded nothing is known to be off, so the tab
  // the URL asks for (or DNS Queries, the usual default) stays highlighted
  // rather than flicking to the Event Log for a moment; the bodies below
  // still wait, so nothing is read before the answer is in.
  const tab: Tab = !modulesReady
    ? (wanted ?? "dns-queries")
    : wanted && tabAllowed(wanted)
      ? wanted
      : fallbackTab;
  const setTab = (next: Tab) => {
    const params = new URLSearchParams(searchParams);
    params.set("tab", next);
    setSearchParams(params, { replace: true });
  };

  // Two source lists: Windows servers (Event Log + DHCP Audit) and
  // agent-driven servers (DNS Queries + DHCP Activity). They're
  // populated by separate endpoints because the underlying
  // transports are different (WinRM pull vs. agent push).
  const {
    data: sources,
    isLoading: sourcesLoading,
    error: sourcesError,
    refetch: refetchSources,
  } = useQuery({
    queryKey: ["logs-sources"],
    queryFn: logsApi.listSources,
    staleTime: 60_000,
  });

  const {
    data: agentSources,
    isLoading: agentSourcesLoading,
    error: agentSourcesError,
    refetch: refetchAgentSources,
  } = useQuery({
    queryKey: ["logs-agent-sources"],
    queryFn: logsApi.listAgentSources,
    staleTime: 60_000,
  });

  // Filter by tab — audit tab is DHCP-only. The agent tabs filter
  // their own list on `server_kind` directly.
  const tabSources = useMemo(() => {
    if (!sources) return [];
    if (tab === "audit") return sources.filter((s) => s.server_kind === "dhcp");
    return sources;
  }, [sources, tab]);

  const dnsAgentSources = useMemo(
    () => (agentSources ?? []).filter((s) => s.server_kind === "dns"),
    [agentSources],
  );
  const dhcpAgentSources = useMemo(
    () => (agentSources ?? []).filter((s) => s.server_kind === "dhcp"),
    [agentSources],
  );

  if (sourcesLoading || agentSourcesLoading) {
    return (
      <div className="p-6 text-sm text-muted-foreground">Loading sources…</div>
    );
  }

  const hasWindows = !!sources && sources.length > 0;
  const hasAgents = !!agentSources && agentSources.length > 0;

  if (!hasWindows && !hasAgents) {
    return <EmptyLogsState error={sourcesError ?? agentSourcesError} />;
  }

  function refreshAll() {
    refetchSources();
    refetchAgentSources();
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header + tab switcher */}
      <div className="border-b px-6 py-4">
        <div className="flex items-end justify-between gap-4">
          <div>
            <h1 className="flex items-center gap-2 text-xl font-bold tracking-tight">
              <ScrollText className="h-5 w-5" />
              Logs
            </h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Read-only. BIND9 / PowerDNS / Kea via agent push, Windows DNS /
              DHCP via WinRM.
            </p>
          </div>
          <button
            onClick={refreshAll}
            title="Refresh source list"
            className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-accent"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Sources
          </button>
        </div>
        <div className="mt-3 flex flex-wrap gap-1 border-b -mb-4">
          {dnsTabsShown && (
            <TabButton
              active={tab === "dns-queries"}
              onClick={() => setTab("dns-queries")}
              icon={Search}
              label="DNS Queries"
              hint="BIND9 / PowerDNS query log (client → name → qtype). Requires query_log_enabled on the server group."
              count={dnsAgentSources.length || undefined}
            />
          )}
          {dnsTabsShown && (
            <TabButton
              active={tab === "dns-threat"}
              onClick={() => setTab("dns-threat")}
              icon={ShieldAlert}
              label="DNS Threat"
              hint="Per-client tunneling / exfiltration scoring over the query log. Requires the security.dns_threat module (default off — it reads query content)."
            />
          )}
          {dhcpOn && (
            <TabButton
              active={tab === "dhcp-activity"}
              onClick={() => setTab("dhcp-activity")}
              icon={Activity}
              label="DHCP Activity"
              hint="Kea DHCPv4 activity (DISCOVER / OFFER / REQUEST / ACK, lease alloc, declines)"
              count={dhcpAgentSources.length || undefined}
            />
          )}
          <TabButton
            active={tab === "events"}
            onClick={() => setTab("events")}
            icon={ScrollText}
            label="Event Log"
            hint="Windows DNS/DHCP service events (scope load, zone transfer, auth)"
            count={hasWindows ? sources?.length : undefined}
          />
          {dhcpOn && (
            <TabButton
              active={tab === "audit"}
              onClick={() => setTab("audit")}
              icon={FileClock}
              label="DHCP Audit"
              hint="Windows DHCP per-lease events (grants, renewals, releases)"
              count={
                sources?.filter((s) => s.server_kind === "dhcp").length ||
                undefined
              }
            />
          )}
        </div>
      </div>

      {tab === "dns-queries" && dnsOn && !awaitingModules && (
        <DNSQueriesTab sources={dnsAgentSources} />
      )}
      {tab === "dns-threat" && dnsOn && !awaitingModules && <DNSThreatTab />}
      {tab === "dhcp-activity" && dhcpOn && !awaitingModules && (
        <DHCPActivityTab sources={dhcpAgentSources} />
      )}
      {tab === "events" && !awaitingModules && (
        <EventLogTab sources={tabSources} />
      )}
      {tab === "audit" && dhcpOn && !awaitingModules && (
        <DhcpAuditTab sources={tabSources} />
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon: Icon,
  label,
  hint,
  count,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ElementType;
  label: string;
  hint?: string;
  count?: number;
}) {
  return (
    <button
      onClick={onClick}
      title={hint}
      className={cn(
        "flex items-center gap-1.5 border-b-2 px-3 pb-2 pt-1.5 text-xs font-medium transition-colors",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground",
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
      {count !== undefined && (
        <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] tabular-nums">
          {count}
        </span>
      )}
    </button>
  );
}

function EmptyLogsState({ error }: { error?: unknown }) {
  return (
    <div className="flex h-full flex-col">
      <div className="border-b px-6 py-4">
        <h1 className="flex items-center gap-2 text-xl font-bold tracking-tight">
          <ScrollText className="h-5 w-5" />
          Logs
        </h1>
      </div>
      <div className="flex flex-1 items-center justify-center p-10">
        <div className="max-w-md rounded-lg border border-dashed p-10 text-center">
          <ScrollText className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
          {error ? (
            <p className="text-sm">
              <ListEmpty error={error} what="log sources">
                No log sources yet
              </ListEmpty>
            </p>
          ) : (
            <>
              <p className="text-sm font-medium">No log sources yet</p>
              <p className="mt-2 text-xs text-muted-foreground">
                Register a Windows DNS or DHCP server with WinRM credentials
                configured and its logs will appear here.
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Event Log tab ───────────────────────────────────────────────────────────

function EventLogTab({ sources }: { sources: LogSource[] }) {
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [logName, setLogName] = useState<string | null>(null);
  const [maxEvents, setMaxEvents] = useState(100);
  const [level, setLevel] = useState<number | "">("");
  const [since, setSince] = useState<string>("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (sources.length === 0) {
      setSelectedKey(null);
      setLogName(null);
      return;
    }
    if (selectedKey) return;
    const first = sources[0];
    setSelectedKey(`${first.server_kind}:${first.server_id}`);
    if (first.logs.length > 0) setLogName(first.logs[0].name);
  }, [sources, selectedKey]);

  const selected = useMemo(
    () =>
      sources.find((s) => `${s.server_kind}:${s.server_id}` === selectedKey),
    [selectedKey, sources],
  );

  useEffect(() => {
    if (!selected) return;
    if (!logName || !selected.logs.some((l) => l.name === logName)) {
      setLogName(selected.logs[0]?.name ?? null);
    }
  }, [selected, logName]);

  const sinceIso = since ? new Date(since).toISOString() : null;
  const enabled = !!selected && !!logName;

  const eventsQuery = useQuery({
    queryKey: [
      "logs-query",
      selected?.server_id,
      selected?.server_kind,
      logName,
      level,
      maxEvents,
      sinceIso,
    ],
    queryFn: () =>
      logsApi.query({
        server_id: selected!.server_id,
        server_kind: selected!.server_kind,
        log_name: logName!,
        max_events: maxEvents,
        level: level === "" ? null : level,
        since: sinceIso,
        event_id: null,
      }),
    enabled,
    staleTime: Infinity,
    gcTime: 5 * 60_000,
    retry: false,
  });

  const events = eventsQuery.data?.events ?? [];
  const filteredEvents = useMemo(() => {
    if (!search.trim()) return events;
    const q = search.trim().toLowerCase();
    return events.filter(
      (e) =>
        e.message.toLowerCase().includes(q) ||
        e.provider.toLowerCase().includes(q) ||
        String(e.id).includes(q),
    );
  }, [events, search]);

  // Empty state — checked after every hook so React's hook-count
  // stays stable across renders. Mirrors the DHCP Audit tab pattern.
  if (sources.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center p-10">
        <div className="max-w-md rounded-lg border border-dashed p-10 text-center">
          <ScrollText className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
          <p className="text-sm font-medium">No Windows servers configured</p>
          <p className="mt-2 text-xs text-muted-foreground">
            The Event Log tab is the Windows Event Viewer surface for the DNS
            Server / DHCP Server roles — admin + operational events like zone
            load, scope activation, and AD integration warnings. It requires a
            Windows DNS or DHCP server registered with WinRM credentials. For
            BIND9 / PowerDNS / Kea use the <strong>DNS Queries</strong> or{" "}
            <strong>DHCP Activity</strong> tab instead.
          </p>
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3 border-b bg-muted/20 px-6 py-3">
        <ServerPicker
          sources={sources}
          value={selectedKey}
          onChange={(key) => {
            setSelectedKey(key);
            const s = sources.find(
              (src) => `${src.server_kind}:${src.server_id}` === key,
            );
            setLogName(s?.logs?.[0]?.name ?? null);
          }}
        />
        {selected && (
          <label className="flex items-center gap-1.5 text-xs">
            <span className="text-muted-foreground">Log</span>
            <select
              value={logName ?? ""}
              onChange={(e) => setLogName(e.target.value)}
              className="min-w-[240px] rounded-md border bg-background px-2 py-1 text-sm"
            >
              {selected.logs.map((l) => (
                <option key={l.name} value={l.name}>
                  {l.display}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">Level</span>
          <select
            value={level}
            onChange={(e) =>
              setLevel(
                e.target.value === "" ? "" : parseInt(e.target.value, 10),
              )
            }
            className="rounded-md border bg-background px-2 py-1 text-sm"
          >
            <option value="">All</option>
            <option value="1">Critical</option>
            <option value="2">Error</option>
            <option value="3">Warning</option>
            <option value="4">Information</option>
            <option value="5">Verbose</option>
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-xs">
          <span className="inline-flex items-center gap-1 text-muted-foreground">
            <Calendar className="h-3 w-3" />
            Since
          </span>
          <input
            type="datetime-local"
            value={since}
            onChange={(e) => setSince(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 text-sm"
          />
          {since && (
            <button
              type="button"
              onClick={() => setSince("")}
              title="Clear since filter"
              className="rounded text-[11px] text-muted-foreground hover:text-foreground"
            >
              ✕
            </button>
          )}
        </label>
        <MaxEventsPicker value={maxEvents} onChange={setMaxEvents} />
        <FilterSearch value={search} onChange={setSearch} />
        <RefreshButton query={eventsQuery} enabled={enabled} />
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto">
        {eventsQuery.isError && <QueryErrorBanner query={eventsQuery} />}
        {enabled && eventsQuery.isLoading && (
          <QueryingIndicator host={selected?.host} />
        )}
        {eventsQuery.data && events.length === 0 && !eventsQuery.isError && (
          <EmptyResults hasSince={!!since} />
        )}
        {events.length > 0 && (
          <div className="divide-y">
            <div className="sticky top-0 z-10 grid grid-cols-[140px_52px_60px_140px_1fr] gap-3 border-b bg-muted/40 px-6 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              <span>Time</span>
              <span>Level</span>
              <span className="text-right">Event</span>
              <span>Provider</span>
              <span>Message</span>
            </div>
            {filteredEvents.map((ev, idx) => (
              <EventRow key={`${ev.time}-${ev.id}-${idx}`} ev={ev} />
            ))}
            {eventsQuery.data?.truncated && <TruncatedNotice max={maxEvents} />}
          </div>
        )}
      </div>
    </>
  );
}

// ── DHCP Audit tab ──────────────────────────────────────────────────────────

const WEEKDAYS: DhcpAuditDay[] = [
  "Mon",
  "Tue",
  "Wed",
  "Thu",
  "Fri",
  "Sat",
  "Sun",
];

function DhcpAuditTab({ sources }: { sources: LogSource[] }) {
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [day, setDay] = useState<DhcpAuditDay | "today">("today");
  const [maxEvents, setMaxEvents] = useState(500);
  const [codeFilter, setCodeFilter] = useState<number | "">("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (sources.length === 0) {
      setSelectedKey(null);
      return;
    }
    if (selectedKey) return;
    const first = sources[0];
    setSelectedKey(`${first.server_kind}:${first.server_id}`);
  }, [sources, selectedKey]);

  const selected = useMemo(
    () =>
      sources.find((s) => `${s.server_kind}:${s.server_id}` === selectedKey),
    [selectedKey, sources],
  );

  const enabled = !!selected;
  const auditQuery = useQuery({
    queryKey: ["dhcp-audit", selected?.server_id, day, maxEvents],
    queryFn: () =>
      logsApi.dhcpAudit({
        server_id: selected!.server_id,
        day: day === "today" ? null : day,
        max_events: maxEvents,
      }),
    enabled,
    staleTime: Infinity,
    gcTime: 5 * 60_000,
    retry: false,
  });

  const allRows = auditQuery.data?.events ?? [];
  // Newest first for display — the file is oldest → newest.
  const rows = useMemo(() => [...allRows].reverse(), [allRows]);
  const filtered = useMemo(() => {
    let out = rows;
    if (codeFilter !== "") {
      out = out.filter((r) => r.event_code === codeFilter);
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      out = out.filter(
        (r) =>
          r.ip_address.toLowerCase().includes(q) ||
          r.hostname.toLowerCase().includes(q) ||
          r.mac_address.toLowerCase().includes(q) ||
          r.description.toLowerCase().includes(q) ||
          r.event_label.toLowerCase().includes(q),
      );
    }
    return out;
  }, [rows, codeFilter, search]);

  // Build a code → count map for the picker, so it shows event-code
  // distribution for the current day without needing a second query.
  const codeCounts = useMemo(() => {
    const m = new Map<number, number>();
    for (const r of allRows)
      m.set(r.event_code, (m.get(r.event_code) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [allRows]);

  if (sources.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center p-10">
        <div className="max-w-md rounded-lg border border-dashed p-10 text-center">
          <FileClock className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
          <p className="text-sm font-medium">No DHCP servers configured</p>
          <p className="mt-2 text-xs text-muted-foreground">
            DHCP audit logs require a Windows DHCP server with WinRM
            credentials. Register one under DHCP → Server Groups first.
          </p>
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b bg-muted/20 px-6 py-3">
        <ServerPicker
          sources={sources}
          value={selectedKey}
          onChange={setSelectedKey}
        />
        <label className="flex items-center gap-1.5 text-xs">
          <span className="inline-flex items-center gap-1 text-muted-foreground">
            <Calendar className="h-3 w-3" />
            Day
          </span>
          <select
            value={day}
            onChange={(e) => setDay(e.target.value as DhcpAuditDay | "today")}
            className="rounded-md border bg-background px-2 py-1 text-sm"
          >
            <option value="today">Today</option>
            {WEEKDAYS.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
          <span className="text-[10px] text-muted-foreground/70">
            // Windows keeps 7 daily logs
          </span>
        </label>
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">Event</span>
          <select
            value={codeFilter}
            onChange={(e) =>
              setCodeFilter(
                e.target.value === "" ? "" : parseInt(e.target.value, 10),
              )
            }
            className="min-w-[220px] rounded-md border bg-background px-2 py-1 text-sm"
          >
            <option value="">All ({allRows.length})</option>
            {codeCounts.map(([code, count]) => {
              const label = allRows.find(
                (r) => r.event_code === code,
              )?.event_label;
              return (
                <option key={code} value={code}>
                  {code} — {label} ({count})
                </option>
              );
            })}
          </select>
        </label>
        <MaxEventsPicker
          value={maxEvents}
          onChange={setMaxEvents}
          options={[100, 250, 500, 1000, 2000]}
        />
        <FilterSearch value={search} onChange={setSearch} />
        <RefreshButton query={auditQuery} enabled={enabled} />
      </div>

      <div className="flex-1 overflow-auto">
        {auditQuery.isError && <QueryErrorBanner query={auditQuery} />}
        {enabled && auditQuery.isLoading && (
          <QueryingIndicator host={selected?.host} />
        )}
        {auditQuery.data && allRows.length === 0 && !auditQuery.isError && (
          <EmptyAuditResults day={day === "today" ? "today" : day} />
        )}
        {filtered.length > 0 && (
          <div className="divide-y">
            <div className="sticky top-0 z-10 grid grid-cols-[140px_180px_120px_160px_140px_1fr] gap-3 border-b bg-muted/40 px-6 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              <span>Time</span>
              <span>Event</span>
              <span>IP</span>
              <span>Hostname</span>
              <span>MAC</span>
              <span>Description</span>
            </div>
            {filtered.map((r, idx) => (
              <AuditRow key={`${r.time}-${r.transaction_id}-${idx}`} row={r} />
            ))}
            {auditQuery.data?.truncated && <TruncatedNotice max={maxEvents} />}
          </div>
        )}
      </div>
    </>
  );
}

// ── Shared filter-bar + result chrome ───────────────────────────────────────

function ServerPicker({
  sources,
  value,
  onChange,
}: {
  sources: LogSource[];
  value: string | null;
  onChange: (v: string) => void;
}) {
  return (
    <label className="flex items-center gap-1.5 text-xs">
      <span className="text-muted-foreground">Server</span>
      <select
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border bg-background px-2 py-1 text-sm"
      >
        {sources.map((s) => (
          <option
            key={`${s.server_kind}:${s.server_id}`}
            value={`${s.server_kind}:${s.server_id}`}
          >
            {s.server_kind.toUpperCase()} · {s.server_name} ({s.host})
          </option>
        ))}
      </select>
    </label>
  );
}

function MaxEventsPicker({
  value,
  onChange,
  options = [50, 100, 200, 500],
}: {
  value: number;
  onChange: (v: number) => void;
  options?: number[];
}) {
  return (
    <label className="flex items-center gap-1.5 text-xs">
      <span className="text-muted-foreground">Max</span>
      <select
        value={value}
        onChange={(e) => onChange(parseInt(e.target.value, 10))}
        className="rounded-md border bg-background px-2 py-1 text-sm"
      >
        {options.map((n) => (
          <option key={n} value={n}>
            {n}
          </option>
        ))}
      </select>
    </label>
  );
}

function FilterSearch({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="relative flex-1 min-w-[180px] max-w-[320px]">
      <Search className="absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Filter rendered events…"
        className="w-full rounded-md border bg-background pl-7 pr-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
      />
    </div>
  );
}

function RefreshButton({
  query,
  enabled,
}: {
  query: { isFetching: boolean; refetch: () => unknown };
  enabled: boolean;
}) {
  return (
    <button
      onClick={() => query.refetch()}
      disabled={!enabled || query.isFetching}
      title="Re-run the query (bypasses cache)"
      className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
    >
      <RefreshCw
        className={cn("h-3.5 w-3.5", query.isFetching && "animate-spin")}
      />
      {query.isFetching ? "Querying…" : "Refresh"}
    </button>
  );
}

function QueryErrorBanner({ query }: { query: { error: unknown } }) {
  const detail =
    (
      query.error as
        | {
            response?: { data?: { detail?: string } };
          }
        | undefined
    )?.response?.data?.detail ?? String(query.error);
  return (
    <div className="m-6 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
      <p className="font-medium">Query failed</p>
      <p className="mt-1 whitespace-pre-wrap break-words text-xs">{detail}</p>
    </div>
  );
}

function QueryingIndicator({ host }: { host: string | undefined }) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <RefreshCw className="h-4 w-4 animate-spin" />
        Querying {host ?? "servers"}…
      </div>
    </div>
  );
}

function EmptyResults({ hasSince }: { hasSince: boolean }) {
  return (
    <div className="m-6 rounded-lg border border-dashed p-8 text-center">
      <p className="text-sm font-medium">No events match your filter.</p>
      <p className="mt-1 text-xs text-muted-foreground">
        {hasSince
          ? "Try widening the time window or raising Max."
          : "Try widening the level filter or raising Max."}
      </p>
    </div>
  );
}

function EmptyAuditResults({ day }: { day: string }) {
  return (
    <div className="m-6 rounded-lg border border-dashed p-8 text-center">
      <p className="text-sm font-medium">
        No DHCP audit events for {day === "today" ? "today" : `the ${day} log`}.
      </p>
      <p className="mt-1 text-xs text-muted-foreground">
        The log file may be empty, absent (DHCP service inactive on this
        weekday), or the DHCP role may not be enabled on this host. Windows
        keeps one rotating file per weekday in{" "}
        <code className="rounded bg-muted px-1">C:\Windows\System32\dhcp</code>.
      </p>
    </div>
  );
}

function TruncatedNotice({ max }: { max: number }) {
  return (
    <div className="bg-amber-50/40 px-6 py-2 text-xs text-amber-700 dark:bg-amber-950/20 dark:text-amber-400">
      Result limit reached ({max}). Raise Max or narrow the filters to see older
      events.
    </div>
  );
}

// ── Row renderers ───────────────────────────────────────────────────────────

function levelStyling(level: string): {
  icon: React.ElementType;
  color: string;
  bg: string;
} {
  const l = level.toLowerCase();
  if (l.startsWith("crit") || l === "critical") {
    return {
      icon: XCircle,
      color: "text-red-600 dark:text-red-400",
      bg: "bg-red-500",
    };
  }
  if (l === "error") {
    return {
      icon: Ban,
      color: "text-red-600 dark:text-red-400",
      bg: "bg-red-500",
    };
  }
  if (l === "warning") {
    return {
      icon: AlertTriangle,
      color: "text-amber-600 dark:text-amber-400",
      bg: "bg-amber-500",
    };
  }
  if (l === "verbose") {
    return {
      icon: Info,
      color: "text-muted-foreground",
      bg: "bg-muted-foreground/50",
    };
  }
  return {
    icon: Info,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500",
  };
}

function EventRow({ ev }: { ev: LogEventRow }) {
  const [expanded, setExpanded] = useState(false);
  const { icon: LevelIcon, color, bg } = levelStyling(ev.level);
  const firstLine = ev.message.split("\n")[0];
  const hasMore = ev.message.includes("\n") || ev.message.length > 120;
  return (
    <div className="grid grid-cols-[140px_52px_60px_140px_1fr] items-start gap-3 px-6 py-2 text-xs even:bg-muted/40 hover:bg-muted/70 even:hover:bg-muted/70">
      <span className="font-mono text-muted-foreground">
        {formatTime(ev.time)}
      </span>
      <span className="flex items-center gap-1.5">
        <span className={cn("inline-block h-1.5 w-1.5 rounded-full", bg)} />
        <LevelIcon className={cn("h-3 w-3", color)} />
      </span>
      <span className="text-right tabular-nums text-muted-foreground">
        {ev.id}
      </span>
      <span className="truncate text-muted-foreground" title={ev.provider}>
        {ev.provider.replace(/^Microsoft-Windows-/, "")}
      </span>
      <div className="min-w-0">
        <button
          onClick={() => hasMore && setExpanded((v) => !v)}
          className={cn(
            "flex w-full items-start gap-1.5 text-left",
            hasMore ? "cursor-pointer hover:text-foreground" : "cursor-default",
          )}
        >
          {hasMore &&
            (expanded ? (
              <ChevronDown className="mt-0.5 h-3 w-3 flex-shrink-0 text-muted-foreground" />
            ) : (
              <ChevronRight className="mt-0.5 h-3 w-3 flex-shrink-0 text-muted-foreground" />
            ))}
          <span
            className={cn(
              "block",
              expanded ? "whitespace-pre-wrap" : "truncate",
            )}
          >
            {expanded ? ev.message : firstLine}
          </span>
        </button>
      </div>
    </div>
  );
}

/** Colour family per DHCP audit event code — roughly mirrors the
 *  Windows Event Log level semantics applied to the DHCP audit code
 *  ranges. 10/11/20 (grants/renew) = green; 12/16/17 (release /
 *  expire) = muted; 13/14/15/18/31/33/34 (failures) = red;
 *  51-57 (auth-related) = blue. */
function auditCodeColor(code: number): string {
  if ([10, 11, 20, 32, 51, 55, 57, 61, 64].includes(code))
    return "bg-emerald-500";
  if ([12, 16, 17, 23, 24].includes(code)) return "bg-muted-foreground/50";
  if (
    [13, 14, 15, 18, 25, 31, 33, 34, 35, 50, 52, 54, 56, 58, 59, 60].includes(
      code,
    )
  )
    return "bg-red-500";
  if ([30, 53, 62, 63].includes(code)) return "bg-blue-500";
  return "bg-muted-foreground/40";
}

function AuditRow({ row }: { row: DhcpAuditRow }) {
  const dot = auditCodeColor(row.event_code);
  return (
    <div className="grid grid-cols-[140px_180px_120px_160px_140px_1fr] items-center gap-3 px-6 py-1.5 text-xs even:bg-muted/40 hover:bg-muted/70 even:hover:bg-muted/70">
      <span className="font-mono text-muted-foreground">
        {formatTime(row.time)}
      </span>
      <span className="flex items-center gap-1.5 truncate">
        <span className={cn("inline-block h-1.5 w-1.5 rounded-full", dot)} />
        <span
          className="tabular-nums text-muted-foreground"
          title={`Event code ${row.event_code}`}
        >
          {row.event_code}
        </span>
        <span className="truncate font-medium" title={row.event_label}>
          {row.event_label}
        </span>
      </span>
      <span className="truncate font-mono" title={row.ip_address}>
        {row.ip_address || <span className="text-muted-foreground/40">—</span>}
      </span>
      <span className="truncate" title={row.hostname}>
        {row.hostname || <span className="text-muted-foreground/40">—</span>}
      </span>
      <span
        className="truncate font-mono text-muted-foreground"
        title={row.mac_address}
      >
        {row.mac_address || <span className="text-muted-foreground/40">—</span>}
      </span>
      <span className="truncate text-muted-foreground" title={row.description}>
        {row.description || <span className="text-muted-foreground/40">—</span>}
      </span>
    </div>
  );
}

function formatTime(iso: string): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return (
      d.toLocaleDateString(undefined, { month: "short", day: "2-digit" }) +
      " " +
      d.toLocaleTimeString(undefined, { hour12: false })
    );
  } catch {
    return iso;
  }
}

// ── Agent server picker ───────────────────────────────────────────

function EmptyAgentTab({
  kind,
  drivers,
}: {
  kind: "DNS" | "DHCP";
  drivers: string;
}) {
  return (
    <div className="m-6 rounded-lg border border-dashed p-8 text-center">
      <p className="text-sm font-medium">
        No {kind} servers using a SpatiumDDI agent.
      </p>
      <p className="mt-2 text-xs text-muted-foreground">
        Register a {kind} server with driver <code>{drivers}</code> and the
        agent will start shipping log lines once activity flows through it.
      </p>
    </div>
  );
}

// ── DNS Queries tab (BIND9 query log) ────────────────────────────

// Grid templates as whole literals so Tailwind sees them. The `_server`
// variant adds a Server column after Time, shown whenever the read covers
// more than one server (a group or "All servers", #2120).
const DNS_COLS = "grid-cols-[20px_160px_140px_60px_70px_120px_95px_80px_1fr]";
const DNS_COLS_SERVER =
  "grid-cols-[20px_160px_130px_140px_60px_70px_120px_95px_80px_1fr]";
const DHCP_COLS = "grid-cols-[20px_160px_70px_180px_140px_120px_1fr]";
const DHCP_COLS_SERVER =
  "grid-cols-[20px_160px_130px_70px_180px_140px_120px_1fr]";

/** Whether a response merged more than one server. */
function coversManyServers(data: { server_ids?: string[] } | undefined) {
  return (data?.server_ids?.length ?? 0) > 1;
}

function ServerCell({ name }: { name: string }) {
  return (
    <span className="truncate font-mono text-[11px]" title={name}>
      {name}
    </span>
  );
}

function DNSQueriesTab({ sources }: { sources: AgentLogSource[] }) {
  const [selection, setSelection] = useState<AgentLogSelection | null>(() =>
    defaultSelection(sources),
  );
  const [maxEvents, setMaxEvents] = useState(200);
  const [since, setSince] = useState<string>("");
  const [q, setQ] = useState("");
  const [qtype, setQtype] = useState<string>("");
  const [clientIp, setClientIp] = useState<string>("");
  const [view, setView] = useState<string>("");
  const [rcode, setRcode] = useState<string>("");

  useEffect(() => {
    if (sources.length === 0) {
      setSelection(null);
      return;
    }
    if (!selectionIsValid(selection, sources)) {
      setSelection(defaultSelection(sources));
    }
  }, [sources, selection]);
  const scope = selection ? selectionToScope(selection) : {};

  const sinceIso = since ? new Date(since).toISOString() : null;
  const enabled = !!selection;

  const dnsQueriesQuery = useQuery({
    queryKey: [
      "logs-dns-queries",
      selection,
      maxEvents,
      sinceIso,
      q,
      qtype,
      clientIp,
      view,
      rcode,
    ],
    queryFn: () =>
      logsApi.dnsQueries({
        ...scope,
        max_events: maxEvents,
        since: sinceIso,
        q: q.trim() || null,
        qtype: qtype.trim() || null,
        client_ip: clientIp.trim() || null,
        view: view.trim() || null,
        rcode: rcode.trim() || null,
      }),
    enabled,
    staleTime: 5_000,
    gcTime: 60_000,
    retry: false,
  });

  // Analytics rollups — keyed off (server_id, since) only so per-keystroke
  // filter changes (qtype / client_ip / q) don't refetch the entire summary.
  const analyticsQuery = useQuery({
    queryKey: ["logs-dns-queries-analytics", selection, sinceIso],
    queryFn: () =>
      logsApi.dnsQueryAnalytics({
        ...scope,
        since: sinceIso,
        limit: 10,
      }),
    enabled,
    staleTime: 30_000,
    gcTime: 60_000,
    retry: false,
  });

  const events = dnsQueriesQuery.data?.events ?? [];
  const showServer = coversManyServers(dnsQueriesQuery.data);
  const selectedHost = useMemo(
    () => selectionHost(selection, sources),
    [selection, sources],
  );

  if (sources.length === 0) {
    return <EmptyAgentTab kind="DNS" drivers="bind9 / powerdns" />;
  }

  return (
    <>
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3 border-b bg-muted/20 px-6 py-3">
        <AgentLogScopePicker
          sources={sources}
          value={selection}
          onChange={setSelection}
        />
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">QType</span>
          <input
            value={qtype}
            onChange={(e) => setQtype(e.target.value.toUpperCase())}
            placeholder="A / AAAA / MX…"
            className="w-24 rounded-md border bg-background px-2 py-1 text-sm"
          />
        </label>
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">Client IP</span>
          <input
            value={clientIp}
            onChange={(e) => setClientIp(e.target.value)}
            placeholder="192.0.2.5"
            className="w-32 rounded-md border bg-background px-2 py-1 text-sm font-mono text-[11px]"
          />
        </label>
        {/* Outcome filter (#914). "Unrecorded" is a real question an
            operator asks — it is how you find out whether response
            logging is actually on — so it is a selectable value rather
            than an absence. */}
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">Result</span>
          <select
            value={rcode}
            onChange={(e) => setRcode(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 text-sm"
          >
            <option value="">Any</option>
            <option value="NOERROR">NOERROR</option>
            <option value="NXDOMAIN">NXDOMAIN</option>
            <option value="REFUSED">REFUSED</option>
            <option value="SERVFAIL">SERVFAIL</option>
            <option value="UNKNOWN">Unrecorded</option>
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-xs">
          <span className="inline-flex items-center gap-1 text-muted-foreground">
            <Calendar className="h-3 w-3" />
            Since
          </span>
          <input
            type="datetime-local"
            value={since}
            onChange={(e) => setSince(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 text-sm"
          />
          {since && (
            <button
              type="button"
              onClick={() => setSince("")}
              title="Clear"
              className="rounded p-0.5 text-muted-foreground hover:text-foreground"
            >
              <XCircle className="h-3.5 w-3.5" />
            </button>
          )}
        </label>
        <MaxEventsPicker value={maxEvents} onChange={setMaxEvents} />
        <FilterSearch value={q} onChange={setQ} />
        <div className="ml-auto flex items-center gap-2">
          {(q || qtype || clientIp || view || rcode || since) && (
            <button
              type="button"
              onClick={() => {
                setQ("");
                setQtype("");
                setClientIp("");
                setView("");
                setRcode("");
                setSince("");
              }}
              title="Clear all filters"
              className="flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-accent/50"
            >
              <XCircle className="h-3.5 w-3.5" />
              Clear
            </button>
          )}
          <RefreshButton query={dnsQueriesQuery} enabled={enabled} />
        </div>
      </div>

      {/* On-demand analytics rollups over the same time window — top
          qnames / clients + qtype distribution. Click a row to seed the
          filter bar above and narrow the events grid. */}
      <DNSQueryAnalyticsStrip
        analytics={analyticsQuery.data ?? null}
        loading={analyticsQuery.isFetching}
        onPickQname={(name) => setQ(name)}
        onPickClient={(ip) => setClientIp(ip)}
        onPickQtype={(t) => setQtype(t)}
        onPickView={(v) => setView(v)}
        onPickRcode={(r) => setRcode(r)}
      />

      {dnsQueriesQuery.isError && <QueryErrorBanner query={dnsQueriesQuery} />}
      {dnsQueriesQuery.isFetching && events.length === 0 && (
        <QueryingIndicator host={selectedHost} />
      )}
      {!dnsQueriesQuery.isError &&
        !dnsQueriesQuery.isFetching &&
        events.length === 0 && <EmptyResults hasSince={!!sinceIso} />}

      {events.length > 0 && (
        <div className="flex-1 overflow-auto">
          <div
            className={cn(
              "grid gap-x-3 border-b bg-muted/30 px-6 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground",
              showServer ? DNS_COLS_SERVER : DNS_COLS,
            )}
          >
            <span className="sr-only">Details</span>
            <span>Time</span>
            {showServer && <span>Server</span>}
            <span>Client</span>
            <span>QType</span>
            <span>QClass</span>
            <span>QName</span>
            <span>Result</span>
            <span>Flags</span>
            <span>Raw</span>
          </div>
          <div className="divide-y text-xs">
            {events.map((row) => (
              <DNSQueryRow
                key={row.id}
                row={row}
                showServer={showServer}
                onFilterClient={(ip) => setClientIp(ip)}
                onFilterQname={(name) => setQ(name)}
              />
            ))}
          </div>
          {dnsQueriesQuery.data?.truncated && (
            <div className="px-6 py-2 text-[11px] text-amber-600">
              Showing newest {events.length} — older entries exist; raise Max or
              narrow the time window.
            </div>
          )}
        </div>
      )}
    </>
  );
}

function DNSQueryAnalyticsStrip({
  analytics,
  loading,
  onPickQname,
  onPickClient,
  onPickQtype,
  onPickView,
  onPickRcode,
}: {
  analytics: import("@/lib/api").DNSQueryAnalyticsResponse | null;
  loading: boolean;
  onPickQname: (name: string) => void;
  onPickClient: (ip: string) => void;
  onPickQtype: (t: string) => void;
  onPickView: (v: string) => void;
  onPickRcode: (r: string) => void;
}) {
  if (!analytics && !loading) return null;
  const total = analytics?.total_queries ?? 0;
  // Per-view card only renders for split-horizon servers (≥1 view seen) so
  // single-view setups keep the tidy 3-card strip (#371).
  const views = analytics?.top_views ?? [];
  // Outcome breakdown (#914). Present on every server once the backend
  // ships it — a group with response logging off still gets one bar
  // ("UNKNOWN"), which is the honest rendering and also the fastest way
  // to notice the toggle is off.
  const rcodes = analytics?.rcode_distribution ?? [];
  const cardCount =
    3 + (views.length > 0 ? 1 : 0) + (rcodes.length > 0 ? 1 : 0);
  const cols =
    cardCount >= 5
      ? "md:grid-cols-3 lg:grid-cols-5"
      : cardCount === 4
        ? "md:grid-cols-2 lg:grid-cols-4"
        : "md:grid-cols-3";

  return (
    <div className="border-b bg-muted/10 px-6 py-2">
      <div className="mb-1 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        <span>Analytics</span>
        <span className="text-muted-foreground/70">
          {loading
            ? "computing…"
            : `${total.toLocaleString()} queries in window`}
        </span>
      </div>
      <div className={cn("grid grid-cols-1 gap-3", cols)}>
        <AnalyticsCard
          title="Top names"
          rows={analytics?.top_qnames ?? []}
          total={total}
          onPick={onPickQname}
          emptyHint="No queries in window."
        />
        <AnalyticsCard
          title="Top clients"
          rows={analytics?.top_clients ?? []}
          total={total}
          onPick={onPickClient}
          emptyHint="No clients in window."
        />
        <AnalyticsCard
          title="QType breakdown"
          rows={analytics?.qtype_distribution ?? []}
          total={total}
          onPick={onPickQtype}
          emptyHint="No qtype data."
        />
        {views.length > 0 && (
          <AnalyticsCard
            title="By view"
            rows={views}
            total={total}
            onPick={onPickView}
            emptyHint="No view data."
          />
        )}
        {rcodes.length > 0 && (
          <AnalyticsCard
            title="Outcome"
            rows={rcodes}
            total={total}
            onPick={onPickRcode}
            emptyHint="No outcome data."
          />
        )}
      </div>
    </div>
  );
}

function AnalyticsCard({
  title,
  rows,
  total,
  onPick,
  emptyHint,
}: {
  title: string;
  rows: import("@/lib/api").DNSQueryAnalyticsRow[];
  total: number;
  onPick: (key: string) => void;
  emptyHint: string;
}) {
  return (
    <div className="rounded border bg-card p-2">
      <div className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {title}
      </div>
      {rows.length === 0 ? (
        <p className="px-1 py-1 text-[11px] italic text-muted-foreground">
          {emptyHint}
        </p>
      ) : (
        <ul className="space-y-0.5 text-[11px]">
          {rows.map((r) => {
            const pct = total > 0 ? (100 * r.count) / total : 0;
            return (
              <li key={r.key}>
                <button
                  type="button"
                  onClick={() => onPick(r.key)}
                  className="group flex w-full items-center gap-2 rounded px-1 py-0.5 text-left hover:bg-muted/40"
                  title={`Filter the events grid below by "${r.key}"`}
                >
                  <span className="flex-1 truncate font-mono">{r.key}</span>
                  <span className="tabular-nums text-muted-foreground">
                    {r.count}
                  </span>
                  <span className="w-12 text-right tabular-nums text-muted-foreground/70">
                    {pct.toFixed(1)}%
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/**
 * The answer half of a query (#914).
 *
 * A missing rcode is rendered as an explicit "not recorded", never as a
 * dash that sits in the same column as a successful NOERROR — reading an
 * unrecorded outcome as "fine" is the one mistake the field exists to
 * prevent, and a blank cell invites exactly that. A NOERROR carrying no
 * answer records is labelled NODATA, because "the name exists but has no
 * record of that type" is a different fault from NXDOMAIN and looks
 * identical without it.
 */
function RcodeCell({
  rcode,
  answers,
}: {
  rcode: string | null;
  answers: number | null;
}) {
  if (!rcode) {
    return (
      <span
        className="truncate text-[10px] italic text-muted-foreground/50"
        title="Response logging is off for this server group, so the outcome was never recorded. This does NOT mean the query succeeded."
      >
        not recorded
      </span>
    );
  }
  const nodata = rcode === "NOERROR" && answers === 0;
  const label = nodata ? "NODATA" : rcode;
  const tone =
    rcode === "NOERROR"
      ? nodata
        ? "text-amber-600"
        : "text-emerald-600"
      : rcode === "NXDOMAIN"
        ? "text-amber-600"
        : "text-rose-600";
  return (
    <span
      className={cn("truncate font-mono text-[11px] font-medium", tone)}
      title={
        nodata
          ? "NOERROR with no answer records — the name exists but has no record of this type"
          : `${rcode}${answers !== null ? ` — ${answers} answer record(s)` : ""}`
      }
    >
      {label}
    </span>
  );
}

export function DNSQueryRow({
  row,
  showServer = false,
  onFilterClient,
  onFilterQname,
}: {
  row: DNSQueryLogRow;
  /** Render the Server column (#2120) — the read merged several servers. */
  showServer?: boolean;
  onFilterClient?: (ip: string) => void;
  onFilterQname?: (qname: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className={cn(
        "grid items-baseline gap-x-3 px-6 py-1 hover:bg-muted/40",
        showServer ? DNS_COLS_SERVER : DNS_COLS,
      )}
    >
      <RowDetailsButton onClick={() => setOpen(true)} />
      {open && (
        <DNSQueryDetailModal
          row={row}
          onClose={() => setOpen(false)}
          onFilterClient={onFilterClient}
          onFilterQname={onFilterQname}
        />
      )}
      <span
        className="font-mono tabular-nums text-muted-foreground"
        title={row.ts}
      >
        {formatTime(row.ts)}
      </span>
      {showServer && <ServerCell name={row.server_name} />}
      <span
        className="truncate font-mono text-[11px]"
        title={
          row.client_ip
            ? `${row.client_ip}${row.client_port ? `#${row.client_port}` : ""}`
            : ""
        }
      >
        {row.client_ip ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <span className="font-mono">
        {row.qtype ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <span className="font-mono text-muted-foreground">
        {row.qclass ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <span className="truncate" title={row.qname ?? ""}>
        {row.qname ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <RcodeCell rcode={row.rcode ?? null} answers={row.answer_count ?? null} />
      <span className="font-mono text-muted-foreground">
        {row.flags ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <span
        className="truncate font-mono text-[10px] text-muted-foreground/70"
        title={row.raw}
      >
        {row.raw}
      </span>
    </div>
  );
}

// ── DHCP Activity tab (Kea log) ───────────────────────────────────

function DHCPActivityTab({ sources }: { sources: AgentLogSource[] }) {
  const [selection, setSelection] = useState<AgentLogSelection | null>(() =>
    defaultSelection(sources),
  );
  const [maxEvents, setMaxEvents] = useState(200);
  const [since, setSince] = useState<string>("");
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState<string>("");
  const [code, setCode] = useState<string>("");
  const [mac, setMac] = useState<string>("");
  const [ip, setIp] = useState<string>("");

  useEffect(() => {
    if (sources.length === 0) {
      setSelection(null);
      return;
    }
    if (!selectionIsValid(selection, sources)) {
      setSelection(defaultSelection(sources));
    }
  }, [sources, selection]);
  const scope = selection ? selectionToScope(selection) : {};

  const sinceIso = since ? new Date(since).toISOString() : null;
  const enabled = !!selection;

  const activityQuery = useQuery({
    queryKey: [
      "logs-dhcp-activity",
      selection,
      maxEvents,
      sinceIso,
      q,
      severity,
      code,
      mac,
      ip,
    ],
    queryFn: () =>
      logsApi.dhcpActivity({
        ...scope,
        max_events: maxEvents,
        since: sinceIso,
        q: q.trim() || null,
        severity: severity.trim() || null,
        code: code.trim() || null,
        mac_address: mac.trim() || null,
        ip_address: ip.trim() || null,
      }),
    enabled,
    staleTime: 5_000,
    gcTime: 60_000,
    retry: false,
  });

  const events = activityQuery.data?.events ?? [];
  const showServer = coversManyServers(activityQuery.data);
  const selectedHost = useMemo(
    () => selectionHost(selection, sources),
    [selection, sources],
  );

  if (sources.length === 0) {
    return <EmptyAgentTab kind="DHCP" drivers="kea" />;
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b bg-muted/20 px-6 py-3">
        <AgentLogScopePicker
          sources={sources}
          value={selection}
          onChange={setSelection}
        />
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">Severity</span>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 text-sm"
          >
            <option value="">All</option>
            <option value="DEBUG">Debug</option>
            <option value="INFO">Info</option>
            <option value="WARN">Warn</option>
            <option value="ERROR">Error</option>
            <option value="FATAL">Fatal</option>
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">Code</span>
          <input
            value={code}
            onChange={(e) => setCode(e.target.value.toUpperCase())}
            placeholder="DHCP4_LEASE_ALLOC"
            className="w-44 rounded-md border bg-background px-2 py-1 font-mono text-[11px]"
          />
        </label>
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">MAC</span>
          <input
            value={mac}
            onChange={(e) => setMac(e.target.value.toLowerCase())}
            placeholder="aa:bb:cc:dd:ee:ff"
            className="w-40 rounded-md border bg-background px-2 py-1 font-mono text-[11px]"
          />
        </label>
        <label className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">IP</span>
          <input
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="192.0.2.10"
            className="w-32 rounded-md border bg-background px-2 py-1 font-mono text-[11px]"
          />
        </label>
        <label className="flex items-center gap-1.5 text-xs">
          <span className="inline-flex items-center gap-1 text-muted-foreground">
            <Calendar className="h-3 w-3" />
            Since
          </span>
          <input
            type="datetime-local"
            value={since}
            onChange={(e) => setSince(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 text-sm"
          />
          {since && (
            <button
              type="button"
              onClick={() => setSince("")}
              title="Clear"
              className="rounded p-0.5 text-muted-foreground hover:text-foreground"
            >
              <XCircle className="h-3.5 w-3.5" />
            </button>
          )}
        </label>
        <MaxEventsPicker value={maxEvents} onChange={setMaxEvents} />
        <FilterSearch value={q} onChange={setQ} />
        <div className="ml-auto">
          <RefreshButton query={activityQuery} enabled={enabled} />
        </div>
      </div>

      {activityQuery.isError && <QueryErrorBanner query={activityQuery} />}
      {activityQuery.isFetching && events.length === 0 && (
        <QueryingIndicator host={selectedHost} />
      )}
      {!activityQuery.isError &&
        !activityQuery.isFetching &&
        events.length === 0 && <EmptyResults hasSince={!!sinceIso} />}

      {events.length > 0 && (
        <div className="flex-1 overflow-auto">
          <div
            className={cn(
              "grid gap-x-3 border-b bg-muted/30 px-6 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground",
              showServer ? DHCP_COLS_SERVER : DHCP_COLS,
            )}
          >
            <span className="sr-only">Details</span>
            <span>Time</span>
            {showServer && <span>Server</span>}
            <span>Severity</span>
            <span>Code</span>
            <span>MAC</span>
            <span>IP</span>
            <span>Raw</span>
          </div>
          <div className="divide-y text-xs">
            {events.map((row) => (
              <DHCPActivityRow key={row.id} row={row} showServer={showServer} />
            ))}
          </div>
          {activityQuery.data?.truncated && (
            <div className="px-6 py-2 text-[11px] text-amber-600">
              Showing newest {events.length} — older entries exist; raise Max or
              narrow the time window.
            </div>
          )}
        </div>
      )}
    </>
  );
}

export function DHCPActivityRow({
  row,
  showServer = false,
}: {
  row: DHCPActivityLogRow;
  /** Render the Server column (#2120) — the read merged several servers. */
  showServer?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const sevCls =
    row.severity === "ERROR" || row.severity === "FATAL"
      ? "text-destructive"
      : row.severity === "WARN"
        ? "text-amber-600 dark:text-amber-400"
        : row.severity === "DEBUG"
          ? "text-muted-foreground/60"
          : "text-foreground";
  return (
    <div
      className={cn(
        "grid items-baseline gap-x-3 px-6 py-1 hover:bg-muted/40",
        showServer ? DHCP_COLS_SERVER : DHCP_COLS,
      )}
    >
      <RowDetailsButton onClick={() => setOpen(true)} />
      {open && (
        <DHCPActivityDetailModal row={row} onClose={() => setOpen(false)} />
      )}
      <span
        className="font-mono tabular-nums text-muted-foreground"
        title={row.ts}
      >
        {formatTime(row.ts)}
      </span>
      {showServer && <ServerCell name={row.server_name} />}
      <span className={cn("font-mono text-[11px]", sevCls)}>
        {row.severity ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <span className="truncate font-mono text-[11px]" title={row.code ?? ""}>
        {row.code ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <span
        className="truncate font-mono text-muted-foreground"
        title={row.mac_address ?? ""}
      >
        {row.mac_address ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <span
        className="truncate font-mono text-muted-foreground"
        title={row.ip_address ?? ""}
      >
        {row.ip_address ?? <span className="text-muted-foreground/40">—</span>}
      </span>
      <span
        className="truncate font-mono text-[10px] text-muted-foreground/70"
        title={row.raw}
      >
        {row.raw}
      </span>
    </div>
  );
}

// ── Row detail modals (#2246) ─────────────────────────────────────
//
// The grid rows truncate client / qname / raw to keep one line per
// event, and a hover ``title`` is not selectable, not usable on touch
// and clipped by the browser for long lines. The details button opens
// every field of the row untruncated, with the raw line copyable.

function RowDetailsButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="Show row details"
      title="Show row details"
      className="self-center rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
    >
      <Maximize2 className="h-3 w-3" />
    </button>
  );
}

function formatFullTimestamp(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${iso} (local: ${d.toLocaleString(undefined, { hour12: false })})`;
}

function Missing() {
  return <span className="text-muted-foreground/50">—</span>;
}

function DetailField({
  label,
  children,
  mono,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <>
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className={cn("min-w-0 break-all text-sm", mono && "font-mono")}>
        {children}
      </dd>
    </>
  );
}

function RawLineBlock({ raw }: { raw: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-4">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">
          Raw line
        </span>
        <button
          type="button"
          onClick={() => {
            // Shared helper: falls back to execCommand on plain-http
            // origins, where navigator.clipboard is undefined. On
            // failure the line stays selectable in the block below.
            void copyToClipboard(raw).then((ok) => {
              if (!ok) return;
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1500);
            });
          }}
          className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent"
        >
          <Copy className="h-3 w-3" />
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre
        data-testid="raw-line"
        className="whitespace-pre-wrap break-all rounded-md border bg-muted/40 p-2 font-mono text-[11px]"
      >
        {raw}
      </pre>
    </div>
  );
}

/** Same wording as ``RcodeCell``, spelled out for the detail view. */
function describeRcode(
  rcode: string | null,
  answers: number | null,
): { label: string; note: string } {
  if (!rcode) {
    return {
      label: "not recorded",
      note: "Response logging is off for this server group, so the outcome was never recorded. This does NOT mean the query succeeded.",
    };
  }
  if (rcode === "NOERROR" && answers === 0) {
    return {
      label: "NODATA",
      note: "NOERROR with no answer records — the name exists but has no record of this type.",
    };
  }
  return { label: rcode, note: "" };
}

function DNSQueryDetailModal({
  row,
  onClose,
  onFilterClient,
  onFilterQname,
}: {
  row: DNSQueryLogRow;
  onClose: () => void;
  onFilterClient?: (ip: string) => void;
  onFilterQname?: (qname: string) => void;
}) {
  const rcode = row.rcode ?? null;
  const answers = row.answer_count ?? null;
  const result = describeRcode(rcode, answers);
  const client = row.client_ip
    ? `${row.client_ip}${row.client_port ? `#${row.client_port}` : ""}`
    : null;
  return (
    <Modal title="DNS query details" onClose={onClose} wide>
      <dl className="grid grid-cols-[110px_1fr] gap-x-4 gap-y-2">
        <DetailField label="Timestamp" mono>
          {formatFullTimestamp(row.ts)}
        </DetailField>
        <DetailField label="Server" mono>
          {row.server_name || <Missing />}
        </DetailField>
        <DetailField label="Client" mono>
          {client ?? <Missing />}
        </DetailField>
        <DetailField label="View" mono>
          {row.view ?? <Missing />}
        </DetailField>
        <DetailField label="QName" mono>
          {row.qname ?? <Missing />}
        </DetailField>
        <DetailField label="QType" mono>
          {row.qtype ?? <Missing />}
        </DetailField>
        <DetailField label="QClass" mono>
          {row.qclass ?? <Missing />}
        </DetailField>
        <DetailField label="Result">
          <span
            data-testid="dns-result"
            className={cn(
              rcode ? "font-mono font-medium" : "italic text-muted-foreground",
            )}
          >
            {result.label}
          </span>
          {result.note && (
            <span className="mt-0.5 block text-xs text-muted-foreground">
              {result.note}
            </span>
          )}
        </DetailField>
        <DetailField label="Answers" mono>
          {answers ?? <Missing />}
        </DetailField>
        <DetailField label="Flags" mono>
          {row.flags ?? <Missing />}
        </DetailField>
      </dl>
      <RawLineBlock raw={row.raw} />
      {((onFilterClient && row.client_ip) || (onFilterQname && row.qname)) && (
        <div className="mt-4 flex flex-wrap justify-end gap-2">
          {onFilterClient && row.client_ip && (
            <button
              type="button"
              onClick={() => {
                onFilterClient(row.client_ip!);
                onClose();
              }}
              className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-accent/50"
            >
              <Search className="h-3.5 w-3.5" />
              Filter by client
            </button>
          )}
          {onFilterQname && row.qname && (
            <button
              type="button"
              onClick={() => {
                onFilterQname(row.qname!);
                onClose();
              }}
              className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-accent/50"
            >
              <Search className="h-3.5 w-3.5" />
              Filter by qname
            </button>
          )}
        </div>
      )}
    </Modal>
  );
}

function DHCPActivityDetailModal({
  row,
  onClose,
}: {
  row: DHCPActivityLogRow;
  onClose: () => void;
}) {
  return (
    <Modal title="DHCP activity details" onClose={onClose} wide>
      <dl className="grid grid-cols-[110px_1fr] gap-x-4 gap-y-2">
        <DetailField label="Timestamp" mono>
          {formatFullTimestamp(row.ts)}
        </DetailField>
        <DetailField label="Server" mono>
          {row.server_name || <Missing />}
        </DetailField>
        <DetailField label="Severity" mono>
          {row.severity ?? <Missing />}
        </DetailField>
        <DetailField label="Log code" mono>
          {row.code ?? <Missing />}
        </DetailField>
        <DetailField label="MAC" mono>
          {row.mac_address ?? <Missing />}
        </DetailField>
        <DetailField label="IP" mono>
          {row.ip_address ?? <Missing />}
        </DetailField>
        <DetailField label="Transaction ID" mono>
          {row.transaction_id ?? <Missing />}
        </DetailField>
      </dl>
      <RawLineBlock raw={row.raw} />
    </Modal>
  );
}
