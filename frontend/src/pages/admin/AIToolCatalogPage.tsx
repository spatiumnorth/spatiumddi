import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Boxes,
  RefreshCcw,
  RotateCcw,
  Sparkles,
} from "lucide-react";
import {
  aiToolCatalogApi,
  type AIToolCatalog,
  type AIToolCatalogEntry,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { Toggle } from "@/components/ui/toggle";
import { ListReadError } from "@/components/ui/list-read-error";
import { cn } from "@/lib/utils";

// Tools whose name starts with this prefix stage write proposals
// — operators see an Approve / Reject card in the chat drawer
// after the LLM calls one. Enabling such a tool means the AI can
// PREPARE a write; the human still has to click Approve. We gate
// enable with a confirm modal so it's a deliberate two-step act.
const WRITE_PROPOSAL_PREFIX = "propose_";

function isWriteProposal(t: AIToolCatalogEntry): boolean {
  return t.writes || t.name.startsWith(WRITE_PROPOSAL_PREFIX);
}

const headerCls =
  "flex shrink-0 items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50";

// Display-friendly names for the registry's `category` field (which
// is a short lowercase string declared on each `register_tool(...)`
// call in the backend tool registry). Anything not in this map falls
// back to the raw category id, capitalised by group rendering.
const CATEGORY_LABELS: Record<string, string> = {
  ipam: "IPAM",
  dns: "DNS",
  dhcp: "DHCP",
  network: "Network",
  ops: "Operations",
};

const CATALOG_QUERY_KEY = ["ai-tool-catalog-admin"];

/** Settings → AI Tool Catalog.
 *
 * Layout mirrors the Features page: 3-col adaptive grid for wide
 * groups, narrow groups (≤2 tools) cluster into shared 3-up rows,
 * pill toggle on each row that auto-saves on flip via an optimistic
 * React Query mutation. No batch Save button — every click hits
 * `PUT /ai/tools/catalog` immediately so the change takes effect on
 * the next chat turn without operator effort.
 *
 * Per-tool toggling computes the new explicit list from current
 * `enabled` flags ± the toggled tool, then PUTs that list. This
 * implicitly converts a NULL platform override into an explicit one
 * — operators can revert via the "Reset to defaults" button which
 * sends NULL back. Optimistic update prevents the toggle from
 * snapping back during the round-trip.
 */
export function AIToolCatalogPage() {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: CATALOG_QUERY_KEY,
    queryFn: () => aiToolCatalogApi.list(),
  });

  const updateMutation = useMutation({
    mutationFn: (enabledNames: string[] | null) =>
      aiToolCatalogApi.update(enabledNames),
    onMutate: async (enabledNames) => {
      // Cancel any in-flight refetch so it doesn't clobber the
      // optimistic state, then patch the cache so the row toggles
      // visually before the server round-trip lands.
      await qc.cancelQueries({ queryKey: CATALOG_QUERY_KEY });
      const prev = qc.getQueryData<AIToolCatalog>(CATALOG_QUERY_KEY);
      if (prev) {
        const explicit = enabledNames !== null;
        const enabledSet = explicit
          ? new Set(enabledNames)
          : // Null means "revert to registry defaults" — recompute
            // each row's `enabled` from `default_enabled`.
            null;
        qc.setQueryData<AIToolCatalog>(CATALOG_QUERY_KEY, {
          ...prev,
          platform_override: enabledNames,
          tools: prev.tools.map((t) => ({
            ...t,
            enabled: enabledSet ? enabledSet.has(t.name) : t.default_enabled,
          })),
        });
      }
      return { prev };
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(CATALOG_QUERY_KEY, ctx.prev);
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: CATALOG_QUERY_KEY });
    },
  });

  // When the operator flips on a write-proposal tool we show a
  // confirm modal first (per-issue-#101 "double validation to enable
  // them"). Stash the pending toggle in state until the operator
  // confirms; bulk "Enable all" on a category that contains write
  // proposals also routes through the modal so it can't sneak by.
  const [pendingEnable, setPendingEnable] = useState<{
    label: string;
    names: string[];
  } | null>(null);

  function currentEnabledNames(): string[] {
    return (data?.tools ?? []).filter((t) => t.enabled).map((t) => t.name);
  }

  function commitToggle(toAdd: string[], toRemove: string[]) {
    const current = new Set(currentEnabledNames());
    for (const n of toAdd) current.add(n);
    for (const n of toRemove) current.delete(n);
    updateMutation.mutate([...current].sort());
  }

  function toggleOne(t: AIToolCatalogEntry, next: boolean) {
    if (next && isWriteProposal(t)) {
      setPendingEnable({ label: t.name, names: [t.name] });
      return;
    }
    commitToggle(next ? [t.name] : [], next ? [] : [t.name]);
  }

  function setGroup(tools: AIToolCatalogEntry[], next: boolean) {
    if (next) {
      const writeProposals = tools.filter(isWriteProposal).map((t) => t.name);
      const safe = tools.filter((t) => !isWriteProposal(t)).map((t) => t.name);
      // Apply the safe ones immediately; gate the write proposals
      // behind the confirm modal so a single "Enable all" click can't
      // silently arm the LLM with write capability.
      if (safe.length) {
        commitToggle(safe, []);
      }
      if (writeProposals.length) {
        setPendingEnable({
          label: `${writeProposals.length} write-proposal tool(s)`,
          names: writeProposals,
        });
      }
      return;
    }
    commitToggle(
      [],
      tools.map((t) => t.name),
    );
  }

  const grouped = useMemo(() => {
    if (!data) return [] as [string, AIToolCatalogEntry[]][];
    const haystack = search.trim().toLowerCase();
    const filtered = haystack
      ? data.tools.filter(
          (t) =>
            t.name.toLowerCase().includes(haystack) ||
            t.description.toLowerCase().includes(haystack) ||
            t.category.toLowerCase().includes(haystack),
        )
      : data.tools;
    const buckets: Record<string, AIToolCatalogEntry[]> = {};
    for (const t of filtered) {
      const key = t.category || "other";
      (buckets[key] ??= []).push(t);
    }
    return Object.entries(buckets).sort((a, b) => a[0].localeCompare(b[0]));
  }, [data, search]);

  const totalEnabled = data?.tools.filter((t) => t.enabled).length ?? 0;
  const totalKnown = data?.total ?? 0;
  const usingDefaults = data?.platform_override === null;

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b p-4">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Sparkles className="h-5 w-5 flex-shrink-0 text-primary" />
          <div className="min-w-0">
            <h1 className="text-lg font-semibold">Tool Catalog</h1>
            <p className="text-xs text-muted-foreground">
              Each tool here is something the Operator Copilot can call on your
              behalf. Disabled tools stay listed for the model so it can tell
              users "ask your admin to enable X" instead of giving up. A
              provider can narrow this further with its own tool allowlist,
              which is set through the API (the provider's{" "}
              <code>enabled_tools</code>); the AI Providers page has no control
              for it.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
          <Boxes className="h-3.5 w-3.5" />
          <span>
            {totalEnabled} of {totalKnown} enabled
          </span>
          {usingDefaults && (
            <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400">
              registry defaults
            </span>
          )}
        </div>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search…"
          className="w-44 rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
        <button
          type="button"
          onClick={() => refetch()}
          disabled={isFetching}
          className={headerCls}
          title="Reload from server"
        >
          <RefreshCcw
            className={cn("h-3.5 w-3.5", isFetching && "animate-spin")}
          />
          Refresh
        </button>
        <button
          type="button"
          onClick={() => updateMutation.mutate(null)}
          disabled={updateMutation.isPending || usingDefaults}
          className={headerCls}
          title="Discard the explicit list and use each tool's registry default."
        >
          <RotateCcw className="h-3.5 w-3.5" />
          Reset to defaults
        </button>
      </div>

      {isLoading && (
        <div className="p-4 text-sm text-muted-foreground">Loading…</div>
      )}

      {/* Same adaptive layout as Settings → Features:
       *   - Wide groups (≥3 tools) lay out in a 3-col internal grid
       *   - Narrow groups (≤2 tools) cluster into shared 3-up rows so
       *     small categories don't strand toggles mid-page
       *   - Trailing fillers keep the gap-px divider grid from
       *     leaking stray bands. pb-24 reserves room for the floating
       *     Copilot button. */}
      <div className="flex-1 space-y-3 overflow-auto p-4 pb-24">
        {(() => {
          type Block =
            | {
                kind: "wide";
                category: string;
                tools: AIToolCatalogEntry[];
              }
            | {
                kind: "cluster";
                items: { category: string; tools: AIToolCatalogEntry[] }[];
              };
          const blocks: Block[] = [];
          let buffer: { category: string; tools: AIToolCatalogEntry[] }[] = [];
          const flush = () => {
            if (buffer.length) {
              blocks.push({ kind: "cluster", items: buffer });
              buffer = [];
            }
          };
          for (const [category, tools] of grouped) {
            if (tools.length >= 3) {
              flush();
              blocks.push({ kind: "wide", category, tools });
            } else {
              buffer.push({ category, tools });
            }
          }
          flush();

          const renderSection = (
            category: string,
            tools: AIToolCatalogEntry[],
            clustered: boolean,
          ) => {
            const cols = clustered ? 1 : Math.min(3, tools.length);
            const fillerCount =
              cols > 0 ? (cols - (tools.length % cols)) % cols : 0;
            const colsClass =
              cols === 3
                ? "md:grid-cols-3"
                : cols === 2
                  ? "md:grid-cols-2"
                  : "";
            const allOn = tools.every((t) => t.enabled);
            return (
              <section
                key={category}
                className="overflow-hidden rounded-md border bg-background"
              >
                <header className="flex items-center justify-between gap-2 border-b bg-muted/30 px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <span>
                    {CATEGORY_LABELS[category] ?? category} ({tools.length})
                  </span>
                  <button
                    type="button"
                    onClick={() => setGroup(tools, !allOn)}
                    disabled={updateMutation.isPending}
                    className="text-[10px] font-normal normal-case tracking-normal text-muted-foreground hover:text-foreground disabled:opacity-50"
                  >
                    {allOn ? "Disable all" : "Enable all"}
                  </button>
                </header>
                <div
                  className={cn(
                    "grid grid-cols-1 gap-px bg-border/40",
                    colsClass,
                  )}
                >
                  {tools.map((t) => {
                    const overridden = t.enabled !== t.default_enabled;
                    return (
                      <div
                        key={t.name}
                        className="flex items-start gap-3 bg-background px-3 py-2 hover:bg-muted/40"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-baseline gap-x-2">
                            <code className="font-mono text-xs font-medium">
                              {t.name}
                            </code>
                            {t.writes && (
                              <span className="rounded bg-red-500/15 px-1 py-px text-[9px] font-medium text-red-700 dark:text-red-400">
                                writes
                              </span>
                            )}
                            {!t.writes &&
                              t.name.startsWith(WRITE_PROPOSAL_PREFIX) && (
                                <span
                                  className="rounded bg-amber-500/15 px-1 py-px text-[9px] font-medium text-amber-700 dark:text-amber-400"
                                  title="Stages a write proposal — operator must Approve in the chat drawer for the change to land"
                                >
                                  proposal
                                </span>
                              )}
                            {overridden && (
                              <span
                                className="rounded bg-amber-500/15 px-1 py-px text-[9px] font-medium text-amber-700 dark:text-amber-400"
                                title={`Default: ${t.default_enabled ? "on" : "off"}`}
                              >
                                overridden
                              </span>
                            )}
                          </div>
                          <p className="mt-0.5 text-xs leading-snug text-muted-foreground">
                            {t.description.split("\n")[0]}
                          </p>
                        </div>
                        <div className="mt-0.5">
                          <Toggle
                            label={`${t.enabled ? "Disable" : "Enable"} ${t.name}`}
                            checked={t.enabled}
                            disabled={updateMutation.isPending}
                            onChange={(v) => toggleOne(t, v)}
                          />
                        </div>
                      </div>
                    );
                  })}
                  {Array.from({ length: fillerCount }).map((_, idx) => (
                    <div
                      key={`filler-${idx}`}
                      className="hidden bg-background md:block"
                      aria-hidden
                    />
                  ))}
                </div>
              </section>
            );
          };

          return blocks.map((block, idx) => {
            if (block.kind === "wide") {
              return renderSection(block.category, block.tools, false);
            }
            return (
              <div
                key={`cluster-${idx}`}
                className="grid grid-cols-1 gap-3 md:grid-cols-3"
              >
                {block.items.map(({ category, tools }) =>
                  renderSection(category, tools, true),
                )}
              </div>
            );
          });
        })()}
        {!isLoading && grouped.length === 0 && (
          <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
            {/* A refused or failed read is not an empty registry (#1343). */}
            {isError && !data ? (
              <ListReadError error={error} what="the AI tool catalog" />
            ) : search ? (
              "No tools match this search."
            ) : (
              "No tools registered."
            )}
          </div>
        )}
      </div>
      {pendingEnable && (
        <Modal
          title="Enable write-proposal tool?"
          onClose={() => setPendingEnable(null)}
        >
          <div className="space-y-3 text-sm">
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-amber-900 dark:text-amber-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
              <div className="space-y-2">
                <p className="font-medium">
                  About to enable: {pendingEnable.label}
                </p>
                <p className="text-xs leading-snug">
                  Tools whose name starts with <code>propose_</code> let the
                  Operator Copilot <em>stage</em> write actions — DNS records,
                  DHCP statics, alert rules, and so on. The actual change never
                  runs until you click Approve on the proposal card in the chat
                  drawer, but enabling these tools means the AI can prepare
                  write payloads on your behalf.
                </p>
                <p className="text-xs leading-snug">
                  If you're not sure, leave them disabled — the read-only tools
                  above answer most operator questions without write access.
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setPendingEnable(null)}
                className="rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  commitToggle(pendingEnable.names, []);
                  setPendingEnable(null);
                }}
                className="rounded-md bg-amber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-amber-700"
              >
                Enable {pendingEnable.names.length === 1 ? "tool" : "tools"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
