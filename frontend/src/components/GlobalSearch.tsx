import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  Network,
  Layers,
  Globe,
  MapPin,
  Sparkles,
  X,
  Server,
  FileText,
  Boxes,
  Cable,
  CornerDownLeft,
  Clock,
  HardDrive,
  Router as RouterIcon,
  ShieldAlert,
  Users,
  UsersRound,
  Waypoints,
  Eye,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import {
  searchApi,
  type SearchResult,
  type SearchResultType,
  type SearchTypeInfo,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  formatCombo,
  matchesShortcut,
  OPEN_GLOBAL_SEARCH,
} from "@/lib/shortcuts";
import { askAI } from "@/components/copilot/askAI";
import { useAiAvailable } from "@/components/copilot/useAiAvailable";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { useSessionState } from "@/lib/useSessionState";
import {
  ALL_NAV_DESTINATIONS,
  navEntryVisible,
  type NavDestination,
} from "@/lib/navigation";

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

const TYPE_LABELS: Record<SearchResultType, string> = {
  ip_address: "IP Address",
  subnet: "Subnet",
  block: "Block",
  space: "Space",
  dns_group: "DNS Group",
  dns_zone: "DNS Zone",
  dns_record: "DNS Record",
  dns_server: "DNS Server",
  dns_view: "DNS View",
  dns_blocklist: "Blocklist",
  dhcp_scope: "DHCP Scope",
  dhcp_reservation: "Reservation",
  dhcp_server: "DHCP Server",
  vlan: "VLAN",
  device: "Device",
  site: "Site",
  circuit: "Circuit",
  user: "User",
  group: "Group",
  appliance: "Appliance",
};

const TYPE_ICONS: Record<SearchResultType, React.ElementType> = {
  ip_address: MapPin,
  subnet: Network,
  block: Layers,
  space: Globe,
  dns_group: Server,
  dns_zone: Globe,
  dns_record: FileText,
  dns_server: Server,
  dns_view: Eye,
  dns_blocklist: ShieldAlert,
  dhcp_scope: Boxes,
  dhcp_reservation: MapPin,
  dhcp_server: Server,
  vlan: RouterIcon,
  device: Cable,
  site: MapPin,
  circuit: Waypoints,
  user: Users,
  group: UsersRound,
  appliance: HardDrive,
};

const TYPE_COLORS: Record<SearchResultType, string> = {
  ip_address: "text-emerald-500",
  subnet: "text-blue-500",
  block: "text-violet-500",
  space: "text-orange-500",
  dns_group: "text-sky-500",
  dns_zone: "text-cyan-500",
  dns_record: "text-teal-500",
  dns_server: "text-sky-500",
  dns_view: "text-cyan-500",
  dns_blocklist: "text-rose-500",
  dhcp_scope: "text-indigo-500",
  dhcp_reservation: "text-indigo-400",
  dhcp_server: "text-indigo-500",
  vlan: "text-amber-500",
  device: "text-lime-500",
  site: "text-pink-500",
  circuit: "text-fuchsia-500",
  user: "text-slate-500",
  group: "text-slate-500",
  appliance: "text-stone-500",
};

/** Scope chips, in display order. Only groups the server actually returned
 *  a type for are rendered, so an operator without DHCP permission never
 *  sees a DHCP filter that can only come back empty. */
const SCOPE_ORDER: { id: string; label: string }[] = [
  { id: "ipam", label: "IPAM" },
  { id: "dns", label: "DNS" },
  { id: "dhcp", label: "DHCP" },
  { id: "network", label: "Network" },
  { id: "admin", label: "Admin" },
];

const RECENTS_KEY = "global-search-recents";
const MAX_RECENTS = 6;
const MAX_COMMANDS = 5;

/** Rank a navigation destination against the typed query.
 *
 *  Deliberately the same exact > prefix > substring ladder the backend
 *  ranks records with (`app/services/search/ranking.py`), so the two halves
 *  of one result list don't order themselves by different rules. */
function commandScore(query: string, dest: NavDestination): number {
  const q = query.toLowerCase();
  const label = dest.label.toLowerCase();
  if (label === q) return 100;
  if (label.startsWith(q)) return 60;
  if (label.includes(q)) return 25;
  // Section match ranks last: typing "network" should surface the pages in
  // that section, but below anything whose own name matched.
  if (dest.section.toLowerCase().includes(q)) return 10;
  return 0;
}

type Row =
  | { kind: "recent"; key: string; query: string }
  | { kind: "result"; key: string; result: SearchResult }
  | { kind: "command"; key: string; dest: NavDestination }
  | { kind: "ai"; key: string };

function ResultRow({
  result,
  isActive,
  onSelect,
}: {
  result: SearchResult;
  isActive: boolean;
  onSelect: (r: SearchResult) => void;
}) {
  const Icon = TYPE_ICONS[result.type] ?? FileText;
  return (
    <button
      className={cn(
        "flex w-full items-start gap-3 px-4 py-2.5 text-left transition-colors",
        isActive ? "bg-accent" : "hover:bg-accent/50",
      )}
      onMouseDown={(e) => {
        e.preventDefault();
        onSelect(result);
      }}
    >
      <Icon
        className={cn(
          "mt-0.5 h-4 w-4 flex-shrink-0",
          TYPE_COLORS[result.type] ?? "text-muted-foreground",
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="font-mono text-sm font-medium">
            {result.display}
          </span>
          {result.name && result.name !== result.display && (
            <span className="truncate text-xs text-muted-foreground">
              {result.name}
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span className="rounded bg-muted px-1 py-0.5 text-[10px] font-medium">
            {TYPE_LABELS[result.type] ?? result.type}
          </span>
          {/* IPAM context */}
          {result.space_name &&
            !result.type.startsWith("dns_") &&
            result.type !== "dhcp_scope" && <span>{result.space_name}</span>}
          {result.subnet_network && result.type === "ip_address" && (
            <span>{result.subnet_network}</span>
          )}
          {result.hostname &&
            result.type === "ip_address" &&
            result.hostname !== result.display && (
              <span>{result.hostname}</span>
            )}
          {result.mac_address && (
            <span className="font-mono">{result.mac_address}</span>
          )}
          {/* Generic breadcrumb for the types added in #879 */}
          {result.context && <span className="truncate">{result.context}</span>}
          {result.status &&
            result.type !== "dns_zone" &&
            result.type !== "dns_record" && (
              <span
                className={cn(
                  "rounded px-1 py-0.5 text-[10px] font-medium",
                  result.status === "allocated" &&
                    "bg-green-500/10 text-green-600",
                  result.status === "reserved" &&
                    "bg-yellow-500/10 text-yellow-600",
                  result.status === "orphan" && "bg-red-500/10 text-red-600",
                )}
              >
                {result.status}
              </span>
            )}
          {/* DNS context */}
          {result.dns_group_name && result.type !== "dns_group" && (
            <span>{result.dns_group_name}</span>
          )}
          {result.dns_zone_name && result.type === "dns_record" && (
            <span>{result.dns_zone_name}</span>
          )}
          {result.dns_record_type && (
            <span className="rounded bg-sky-500/10 px-1 py-0.5 text-[10px] font-medium text-sky-600">
              {result.dns_record_type}
            </span>
          )}
          {result.dns_record_value && (
            <span className="truncate font-mono">
              {result.dns_record_value}
            </span>
          )}
          {result.type === "dns_zone" && result.status && (
            <span className="rounded bg-cyan-500/10 px-1 py-0.5 text-[10px] font-medium text-cyan-600">
              {result.status}
            </span>
          )}
          {result.matched_field && (
            <span
              className="truncate rounded bg-amber-500/10 px-1 py-0.5 text-[10px] font-medium text-amber-600"
              title="Matched field"
            >
              {result.matched_field}
            </span>
          )}
        </div>
      </div>
    </button>
  );
}

export function GlobalSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState<string>("all");
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const { enabled: moduleEnabled } = useFeatureModules();

  const [recents, setRecents] = useSessionState<string[]>(RECENTS_KEY, []);

  const debouncedQuery = useDebounce(query.trim(), 250);

  // Which types this caller may search — drives the scope chips. Fetched
  // once when the palette first opens rather than on mount, so the request
  // never fires for an operator who doesn't use search.
  const { data: availableTypes } = useQuery({
    queryKey: ["search", "types"],
    queryFn: searchApi.types,
    enabled: open,
    staleTime: 5 * 60 * 1000,
  });

  const scopes = useMemo(() => {
    const present = new Set((availableTypes ?? []).map((t) => t.group));
    return SCOPE_ORDER.filter((s) => present.has(s.id));
  }, [availableTypes]);

  const typesParam = useMemo(() => {
    if (scope === "all" || !availableTypes) return undefined;
    const inScope = availableTypes
      .filter((t: SearchTypeInfo) => t.group === scope)
      .map((t) => t.type);
    return inScope.length ? inScope.join(",") : undefined;
  }, [scope, availableTypes]);

  const { data, isFetching } = useQuery({
    queryKey: ["search", debouncedQuery, typesParam],
    queryFn: () => searchApi.search(debouncedQuery, typesParam, 20),
    enabled: debouncedQuery.length >= 1,
    staleTime: 10_000,
  });

  const results = useMemo(() => data?.results ?? [], [data]);

  // Command-palette entries: the sidebar's own destinations, filtered by
  // the enabled feature modules exactly as the sidebar filters them. Only
  // shown in the "all" scope — a DHCP-scoped search asking for DHCP rows
  // shouldn't answer with a link to the Alerts page.
  const commands = useMemo(() => {
    if (!debouncedQuery || scope !== "all") return [];
    return ALL_NAV_DESTINATIONS.filter((d) => navEntryVisible(d, moduleEnabled))
      .map((d) => ({ dest: d, score: commandScore(debouncedQuery, d) }))
      .filter((c) => c.score > 0)
      .sort(
        (a, b) => b.score - a.score || a.dest.label.localeCompare(b.dest.label),
      )
      .slice(0, MAX_COMMANDS)
      .map((c) => c.dest);
  }, [debouncedQuery, scope, moduleEnabled]);

  const aiAvailable = useAiAvailable();
  const askAIVisible = aiAvailable && debouncedQuery.length > 0;

  // One flat row list. Keyboard navigation used to do index arithmetic
  // across two separate lists ("the AI row sits at index results.length"),
  // which only stayed correct while there were exactly two kinds of row.
  const rows: Row[] = useMemo(() => {
    const out: Row[] = [];
    if (!query) {
      for (const r of recents)
        out.push({ kind: "recent", key: `r:${r}`, query: r });
      return out;
    }
    for (const r of results)
      out.push({ kind: "result", key: `${r.type}:${r.id}`, result: r });
    for (const d of commands)
      out.push({ kind: "command", key: `c:${d.to}`, dest: d });
    if (askAIVisible) out.push({ kind: "ai", key: "ai" });
    return out;
  }, [query, recents, results, commands, askAIVisible]);

  useEffect(() => {
    setActiveIdx(0);
  }, [debouncedQuery, scope]);

  // Keep the highlighted row in view when arrowing past the fold.
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(
      '[data-active="true"]',
    );
    el?.scrollIntoView({ block: "nearest" });
  }, [activeIdx]);

  useEffect(() => {
    function handler(e: KeyboardEvent) {
      if (matchesShortcut(e, OPEN_GLOBAL_SEARCH)) {
        e.preventDefault();
        setOpen((v) => !v);
      }
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery("");
      setScope("all");
    }
  }, [open]);

  const remember = useCallback(
    (q: string) => {
      const trimmed = q.trim();
      if (trimmed.length < 2) return;
      setRecents((prev) =>
        [trimmed, ...prev.filter((p) => p !== trimmed)].slice(0, MAX_RECENTS),
      );
    },
    [setRecents],
  );

  const handleSelect = useCallback(
    (result: SearchResult) => {
      setOpen(false);
      remember(query);
      // The original seven types pass react-router *state* (which subnet to
      // expand, which row to highlight), which a path can't express. Newer
      // types carry their own `route` from the server instead of extending
      // this switch once per type.
      if (result.type === "ip_address") {
        navigate("/ipam", {
          state: {
            selectSubnet: result.subnet_id,
            highlightAddress: result.id,
          },
        });
      } else if (result.type === "subnet") {
        navigate("/ipam", { state: { selectSubnet: result.id } });
      } else if (result.type === "block") {
        navigate("/ipam", { state: { selectBlock: result.id } });
      } else if (result.type === "space") {
        navigate("/ipam", { state: { selectSpace: result.id } });
      } else if (result.type === "dns_group") {
        navigate("/dns", { state: { selectGroup: result.dns_group_id } });
      } else if (result.type === "dns_zone") {
        navigate("/dns", {
          state: {
            selectGroup: result.dns_group_id,
            selectZone: result.dns_zone_id,
          },
        });
      } else if (result.type === "dns_record") {
        navigate("/dns", {
          state: {
            selectGroup: result.dns_group_id,
            selectZone: result.dns_zone_id,
            highlightRecord: result.id,
          },
        });
      } else if (result.route) {
        navigate(result.route);
      }
    },
    [navigate, query, remember],
  );

  const handleAskAI = useCallback(() => {
    setOpen(false);
    remember(query);
    askAI({ prompt: query.trim() });
  }, [query, remember]);

  const activate = useCallback(
    (row: Row) => {
      if (row.kind === "result") handleSelect(row.result);
      else if (row.kind === "command") {
        setOpen(false);
        remember(query);
        navigate(row.dest.to);
      } else if (row.kind === "recent") {
        setQuery(row.query);
        inputRef.current?.focus();
      } else handleAskAI();
    },
    [handleSelect, handleAskAI, navigate, query, remember],
  );

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIdx((i) => Math.min(i + 1, rows.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      const row = rows[activeIdx];
      if (row) activate(row);
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  }

  const firstCommandIdx = rows.findIndex((r) => r.kind === "command");

  return (
    <>
      {/* Trigger button */}
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 rounded-md border border-border/50 bg-muted/30 px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground w-80"
      >
        <Search className="h-3.5 w-3.5 flex-shrink-0" />
        <span className="flex-1 text-left">Search or jump to…</span>
        {/* Rendered from the shortcut definition, not hardcoded — this
            used to read "⌘K" on every platform, so Linux / Windows
            operators were shown a key their keyboard doesn't have. */}
        <kbd className="hidden rounded bg-muted px-1 py-0.5 text-[10px] font-mono sm:inline-block flex-shrink-0">
          {formatCombo(OPEN_GLOBAL_SEARCH.combos[0])}
        </kbd>
      </button>

      {/* Modal overlay */}
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
          onClick={() => setOpen(false)}
        >
          <div className="absolute inset-0 bg-black/50" />

          <div
            className="relative z-10 w-full max-w-xl rounded-xl border bg-card shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Input */}
            <div className="flex items-center gap-3 border-b px-4 py-3">
              <Search className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search IP, hostname, MAC, subnet, zone, record, page…"
                className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
              />
              {query && (
                <button
                  onClick={() => setQuery("")}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
              <kbd className="rounded border bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                ESC
              </kbd>
            </div>

            {/* Scope chips */}
            {scopes.length > 1 && (
              <div className="flex flex-wrap items-center gap-1 border-b px-3 py-2">
                {[{ id: "all", label: "All" }, ...scopes].map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    onClick={() => setScope(s.id)}
                    className={cn(
                      "rounded-full px-2.5 py-0.5 text-[11px] font-medium transition-colors",
                      scope === s.id
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted/60 text-muted-foreground hover:bg-muted",
                    )}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            )}

            {/* Results */}
            <div ref={listRef} className="max-h-96 overflow-y-auto">
              {!query && recents.length === 0 && (
                <p className="px-4 py-6 text-center text-sm text-muted-foreground">
                  Search IP addresses, subnets, zones, records, scopes, VLANs
                  and more — or type a page name to jump straight to it.
                </p>
              )}
              {!query && recents.length > 0 && (
                <div className="px-4 pt-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                  Recent searches
                </div>
              )}
              {query && isFetching && results.length === 0 && (
                <p className="px-4 py-6 text-center text-sm text-muted-foreground">
                  Searching…
                </p>
              )}
              {query &&
                !isFetching &&
                rows.length === 0 &&
                debouncedQuery.length > 0 && (
                  <p className="px-4 py-6 text-center text-sm text-muted-foreground">
                    No results for{" "}
                    <span className="font-mono font-medium">
                      "{debouncedQuery}"
                    </span>
                    {scope !== "all" && " in this scope"}
                  </p>
                )}

              {rows.map((row, i) => {
                const isActive = i === activeIdx;
                if (row.kind === "result") {
                  return (
                    <div key={row.key} data-active={isActive}>
                      <ResultRow
                        result={row.result}
                        isActive={isActive}
                        onSelect={handleSelect}
                      />
                    </div>
                  );
                }
                if (row.kind === "recent") {
                  return (
                    <button
                      key={row.key}
                      type="button"
                      data-active={isActive}
                      onMouseDown={(e) => {
                        e.preventDefault();
                        activate(row);
                      }}
                      className={cn(
                        "flex w-full items-center gap-3 px-4 py-2 text-left text-sm transition-colors",
                        isActive ? "bg-accent" : "hover:bg-accent/50",
                      )}
                    >
                      <Clock className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
                      <span className="truncate font-mono">{row.query}</span>
                    </button>
                  );
                }
                if (row.kind === "command") {
                  const Icon = row.dest.icon;
                  return (
                    <div key={row.key}>
                      {i === firstCommandIdx && (
                        <div className="border-t px-4 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                          Go to
                        </div>
                      )}
                      <button
                        type="button"
                        data-active={isActive}
                        onMouseDown={(e) => {
                          e.preventDefault();
                          activate(row);
                        }}
                        className={cn(
                          "flex w-full items-center gap-3 px-4 py-2 text-left text-sm transition-colors",
                          isActive ? "bg-accent" : "hover:bg-accent/50",
                        )}
                      >
                        <Icon className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
                        <span className="flex-1 truncate">
                          {row.dest.label}
                        </span>
                        <span className="text-[11px] text-muted-foreground">
                          {row.dest.section}
                        </span>
                        <CornerDownLeft className="h-3 w-3 flex-shrink-0 text-muted-foreground/60" />
                      </button>
                    </div>
                  );
                }
                return (
                  <button
                    key={row.key}
                    type="button"
                    data-active={isActive}
                    onMouseDown={(e) => {
                      e.preventDefault();
                      activate(row);
                    }}
                    className={cn(
                      "flex w-full items-center gap-3 border-t px-4 py-2.5 text-left text-sm transition-colors",
                      isActive ? "bg-primary/5" : "hover:bg-accent/50",
                    )}
                  >
                    <Sparkles className="h-4 w-4 flex-shrink-0 text-primary" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate">
                        Ask AI:{" "}
                        <span className="font-medium">"{debouncedQuery}"</span>
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        Open Copilot with this query pre-filled
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            {results.length > 0 && (
              <div className="flex items-center justify-between border-t px-4 py-2 text-xs text-muted-foreground">
                <span>
                  {data?.total ?? 0} result{(data?.total ?? 0) !== 1 ? "s" : ""}
                  {(data?.total ?? 0) > results.length &&
                    ` · showing top ${results.length}`}
                </span>
                <span className="flex items-center gap-2">
                  <span>↑↓ navigate</span>
                  <span>↵ select</span>
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
