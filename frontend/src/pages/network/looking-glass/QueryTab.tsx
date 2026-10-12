import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Terminal } from "lucide-react";

import {
  asnsApi,
  lookingGlassApi,
  type BGPLGCollector,
  type BGPLGRoute,
  type NetToolTarget,
} from "@/lib/api";
import { BgpRouteMiniTable } from "@/components/network/bgp-route-table";
import { CommandTool } from "@/pages/tools/NetworkToolsPage";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { useSessionState } from "@/lib/useSessionState";
import { cn } from "@/lib/utils";
import { Field, errMsg, inputCls } from "../_shared";

// ── command grammar (#566 Phase 4) ───────────────────────────────────
//
//   show route <prefix-or-ip> [exact]
//   show route regexp <as-path-regex>
//   show route community <value>
//
// A bare prefix/IP with no "show route" prefix is accepted too, as a
// convenience (treated as `show route <input>`).

type ParsedQuery =
  | { kind: "prefix"; value: string; exact: boolean }
  | { kind: "regexp"; value: string }
  | { kind: "community"; value: string }
  | { kind: "error"; message: string };

function parseLgCommand(raw: string): ParsedQuery {
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      kind: "error",
      message: "Type a command, e.g. show route 10.0.0.0/24",
    };
  }
  const tokens = trimmed.split(/\s+/);
  const lower = tokens.map((t) => t.toLowerCase());
  if (lower[0] !== "show" || lower[1] !== "route") {
    return { kind: "prefix", value: trimmed, exact: false };
  }
  const rest = tokens.slice(2);
  if (rest.length === 0) {
    return {
      kind: "error",
      message:
        "Expected a prefix, 'regexp <pattern>', or 'community <value>' after 'show route'.",
    };
  }
  if (rest[0].toLowerCase() === "regexp") {
    const pattern = rest.slice(1).join(" ").trim();
    if (!pattern) {
      return {
        kind: "error",
        message: "Expected an AS-path regex after 'regexp'.",
      };
    }
    return { kind: "regexp", value: pattern };
  }
  if (rest[0].toLowerCase() === "community") {
    const value = rest.slice(1).join(" ").trim();
    if (!value) {
      return {
        kind: "error",
        message: "Expected a community value after 'community'.",
      };
    }
    return { kind: "community", value };
  }
  const exact = rest[rest.length - 1].toLowerCase() === "exact";
  const value = (exact ? rest.slice(0, -1) : rest).join("");
  return { kind: "prefix", value, exact };
}

const HISTORY_KEY = "bgp-lg-query-history";
const HISTORY_CAP = 20;

export function QueryTab({ collectors }: { collectors: BGPLGCollector[] }) {
  const [draft, setDraft] = useState("");
  const [submitted, setSubmitted] = useState<ParsedQuery | null>(null);
  const [history, setHistory] = useSessionState<string[]>(HISTORY_KEY, []);

  const communitiesQ = useQuery({
    queryKey: ["bgp-communities-standard"],
    queryFn: () => asnsApi.listStandardCommunities(),
    staleTime: 5 * 60_000,
  });

  function submit(raw: string) {
    const parsed = parseLgCommand(raw);
    setSubmitted(parsed);
    if (parsed.kind !== "error") {
      const trimmed = raw.trim();
      setHistory((prev) =>
        [trimmed, ...prev.filter((h) => h !== trimmed)].slice(0, HISTORY_CAP),
      );
    }
  }

  function run() {
    submit(draft);
  }

  function runFromHistory(h: string) {
    setDraft(h);
    setSubmitted(parseLgCommand(h));
  }

  const queryQ = useQuery({
    queryKey: ["bgp-lg-query", submitted],
    queryFn: async (): Promise<{ items: BGPLGRoute[]; total?: number }> => {
      if (!submitted || submitted.kind === "error") return { items: [] };
      if (submitted.kind === "prefix") {
        if (submitted.exact) {
          const items = await lookingGlassApi.getRoute(submitted.value);
          return { items };
        }
        const res = await lookingGlassApi.searchRoutes({
          prefix: submitted.value,
          limit: 200,
        });
        return { items: res.items, total: res.total };
      }
      if (submitted.kind === "regexp") {
        const res = await lookingGlassApi.searchRoutes({
          as_path_regexp: submitted.value,
          limit: 200,
        });
        return { items: res.items, total: res.total };
      }
      // community — accept either the raw wire value or a friendly catalog
      // name (resolve name -> value against the same catalog RoutesTab
      // uses).
      const byName = (communitiesQ.data ?? []).find(
        (c) => c.name === submitted.value,
      );
      const res = await lookingGlassApi.searchRoutes({
        community: byName?.value ?? submitted.value,
        limit: 200,
      });
      return { items: res.items, total: res.total };
    },
    enabled: submitted !== null && submitted.kind !== "error",
  });

  // ── vantage tools (ping / traceroute from a collector) ─────────────
  const { enabled: moduleEnabled } = useFeatureModules();
  const netToolsEnabled = moduleEnabled("tools.network");

  const [runFrom, setRunFrom] = useState("server");
  const [vantageTool, setVantageTool] = useState<"ping" | "traceroute">("ping");
  const selectedCollector = collectors.find((c) => c.id === runFrom);
  const target: NetToolTarget | undefined =
    runFrom === "server" || !selectedCollector?.appliance_id
      ? undefined
      : { kind: "bgp_lg_collector", id: runFrom };

  const items = queryQ.data?.items ?? [];
  const total = queryQ.data?.total;

  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-card p-3">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 shrink-0 text-muted-foreground" />
          <input
            className={cn(inputCls, "font-mono")}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            placeholder="show route 10.0.0.0/24 · show route regexp _65001_ · show route community 65535:666"
          />
          <button
            type="button"
            onClick={run}
            className="shrink-0 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            Run
          </button>
        </div>
        <p className="mt-1.5 text-[11px] text-muted-foreground/70">
          AS-path regex uses the Cisco/Juniper "_" boundary convention (a space,
          start, or end of path) — e.g. "_65001_" matches AS65001 anywhere in
          the path, "_65001$"-style trailing forms match it as the origin (the
          last hop in the stored path). Plain POSIX regex is otherwise
          supported.
        </p>
        {history.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {history.map((h) => (
              <button
                key={h}
                type="button"
                onClick={() => runFromHistory(h)}
                className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground"
              >
                {h}
              </button>
            ))}
          </div>
        )}
      </div>

      {submitted?.kind === "error" && (
        <p className="text-sm text-destructive">{submitted.message}</p>
      )}
      {queryQ.error && (
        <p className="text-sm text-destructive">
          {errMsg(queryQ.error, "Query failed.")}
        </p>
      )}

      {submitted && submitted.kind !== "error" && (
        <div className="space-y-2">
          {!queryQ.isFetching && (
            <p className="text-xs text-muted-foreground">
              {items.length === 0
                ? "No routes match."
                : total !== undefined && total > items.length
                  ? `Showing ${items.length.toLocaleString()} of ${total.toLocaleString()} matching routes (narrow the query to see more).`
                  : `${items.length.toLocaleString()} matching route${items.length === 1 ? "" : "s"}.`}
            </p>
          )}
          <BgpRouteMiniTable items={items} />
        </div>
      )}

      {/* Vantage tools — ping / traceroute FROM a collector's network
          position (or the control-plane server). Only appliance-managed
          collectors (appliance_id set) have a dispatchable command
          channel — see #566 Phase 4 spec Part A3. */}
      <div className="rounded-md border bg-card p-3">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Vantage tools
        </h3>
        {netToolsEnabled ? (
          <>
            <p className="mb-3 text-[11px] text-muted-foreground/70">
              Run ping / traceroute from a collector's own network position.
              Standalone (non-appliance) collectors have no command channel and
              aren't selectable — run from Server instead.
            </p>
            <div className="mb-3 flex flex-wrap items-end gap-3">
              <Field label="Run from">
                <select
                  className={inputCls}
                  value={runFrom}
                  onChange={(e) => setRunFrom(e.target.value)}
                >
                  <option value="server">Server (control plane)</option>
                  {collectors.map((c) => (
                    <option key={c.id} value={c.id} disabled={!c.appliance_id}>
                      {c.name}
                      {!c.appliance_id ? " — not appliance-managed" : ""}
                    </option>
                  ))}
                </select>
              </Field>
              <div className="flex gap-1 pb-1.5">
                {(["ping", "traceroute"] as const).map((k) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setVantageTool(k)}
                    className={cn(
                      "rounded-md px-2.5 py-1 text-xs capitalize",
                      vantageTool === k
                        ? "bg-primary/10 text-primary"
                        : "text-muted-foreground hover:bg-muted",
                    )}
                  >
                    {k}
                  </button>
                ))}
              </div>
            </div>
            <CommandTool kind={vantageTool} target={target} />
          </>
        ) : (
          <p className="text-xs text-muted-foreground">
            Vantage tools need the "tools.network" feature module, which is
            disabled. An administrator can enable it on the Features &
            Integrations page.
          </p>
        )}
      </div>
    </div>
  );
}
