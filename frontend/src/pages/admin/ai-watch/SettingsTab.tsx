import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import {
  aiWatchApi,
  formatApiError,
  type AIWatchConfig,
  type AIWatchConfigUpdate,
} from "@/lib/api";
import { ListReadError } from "@/components/ui/list-read-error";
import { fmtWhen, skipReason } from "./shared";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";
const labelCls = "mb-1 block text-xs font-medium text-muted-foreground";
const sectionCls = "space-y-3 rounded-md border bg-background p-4";
const h2Cls = "text-sm font-semibold";

interface Draft {
  enabled: boolean;
  provider_id: string;
  allow_hosted_provider: boolean;
  sweep_interval_hours: string;
  event_trigger_enabled: boolean;
  event_debounce_seconds: string;
  enabled_tools: string[] | null;
  daily_token_budget: string;
  daily_cost_budget_usd: string;
  max_runs_per_hour: string;
  max_rounds: string;
  max_tokens_per_run: string;
}

function toDraft(c: AIWatchConfig): Draft {
  return {
    enabled: c.enabled,
    provider_id: c.provider_id ?? "",
    allow_hosted_provider: c.allow_hosted_provider,
    sweep_interval_hours: String(c.sweep_interval_hours),
    event_trigger_enabled: c.event_trigger_enabled,
    event_debounce_seconds: String(c.event_debounce_seconds),
    enabled_tools: c.enabled_tools,
    daily_token_budget: String(c.daily_token_budget),
    daily_cost_budget_usd: c.daily_cost_budget_usd,
    max_runs_per_hour: String(c.max_runs_per_hour),
    max_rounds: String(c.max_rounds),
    max_tokens_per_run: String(c.max_tokens_per_run),
  };
}

const INT_FIELDS = [
  "sweep_interval_hours",
  "event_debounce_seconds",
  "daily_token_budget",
  "max_runs_per_hour",
  "max_rounds",
  "max_tokens_per_run",
] as const;

/** The fields that differ from what is stored, as the API wants them.
 *  Throws with a sentence for a value that is not a number. */
function changes(draft: Draft, stored: AIWatchConfig): AIWatchConfigUpdate {
  const out: AIWatchConfigUpdate = {};
  if (draft.enabled !== stored.enabled) out.enabled = draft.enabled;
  if (draft.allow_hosted_provider !== stored.allow_hosted_provider)
    out.allow_hosted_provider = draft.allow_hosted_provider;
  if (draft.event_trigger_enabled !== stored.event_trigger_enabled)
    out.event_trigger_enabled = draft.event_trigger_enabled;
  if ((draft.provider_id || null) !== stored.provider_id)
    out.provider_id = draft.provider_id || null;
  for (const key of INT_FIELDS) {
    const n = Number(draft[key]);
    if (!Number.isInteger(n) || draft[key].trim() === "")
      throw new Error(`${key.replace(/_/g, " ")} must be a whole number.`);
    if (n !== stored[key]) out[key] = n;
  }
  const cost = Number(draft.daily_cost_budget_usd);
  if (!Number.isFinite(cost) || cost <= 0)
    throw new Error("The daily cost budget must be more than 0.");
  if (cost !== Number(stored.daily_cost_budget_usd))
    out.daily_cost_budget_usd = draft.daily_cost_budget_usd.trim();
  const a = draft.enabled_tools;
  const b = stored.enabled_tools;
  const sameTools =
    a === b ||
    (a !== null &&
      b !== null &&
      a.length === b.length &&
      [...a].sort().join() === [...b].sort().join());
  if (!sameTools) out.enabled_tools = a;
  return out;
}

const BLOCKED: Record<string, string> = {
  no_provider:
    "No enabled AI provider is available. Add and enable one under AI Providers.",
  hosted_not_allowed:
    "No enabled AI provider is marked on-prem. Mark one on-prem under AI Providers, or allow a hosted provider below.",
};

export function SettingsTab() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["ai-watch", "config"],
    queryFn: aiWatchApi.getConfig,
    retry: false,
  });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  // Load the stored settings into the form once, and again after a save.
  useEffect(() => {
    if (data) setDraft(toDraft(data));
  }, [data]);

  const save = useMutation({
    mutationFn: (body: AIWatchConfigUpdate) => aiWatchApi.updateConfig(body),
    onSuccess: (fresh) => {
      qc.setQueryData(["ai-watch", "config"], fresh);
      qc.invalidateQueries({ queryKey: ["ai-watch"] });
    },
  });

  const dirty = useMemo(() => {
    if (!draft || !data) return false;
    try {
      return Object.keys(changes(draft, data)).length > 0;
    } catch {
      return true;
    }
  }, [draft, data]);

  if (isLoading)
    return <div className="text-sm text-muted-foreground">Loading…</div>;
  if (isError || !data || !draft)
    return (
      <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
        <ListReadError error={error} what="the Copilot Watch settings" />
      </div>
    );

  function set<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft((d) => (d ? { ...d, [key]: value } : d));
  }

  function submit() {
    if (!draft || !data) return;
    setFormError(null);
    let body: AIWatchConfigUpdate;
    try {
      body = changes(draft, data);
    } catch (e) {
      setFormError((e as Error).message);
      return;
    }
    save.mutate(body);
  }

  const toolNames = draft.enabled_tools;
  const selected = new Set(
    toolNames ?? data.tools.filter((t) => t.default).map((t) => t.name),
  );
  function toggleTool(name: string, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(name);
    else next.delete(name);
    set("enabled_tools", [...next].sort());
  }

  const usage = data.usage_today;
  const blocked = data.blocked_reason;

  return (
    <div className="space-y-4">
      <section className={sectionCls}>
        <h2 className={h2Cls}>Status</h2>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={draft.enabled}
            onChange={(e) => set("enabled", e.target.checked)}
          />
          <span>
            Enable Copilot Watch
            <span className="block text-xs text-muted-foreground">
              Once enabled it sends alert, conformity and server-health data to
              the AI provider below without anyone asking, on the schedule and
              budget set here. It only files findings: it cannot change
              anything.
            </span>
          </span>
        </label>
        {blocked && (
          <p className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-900 dark:text-amber-200">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>
              A run could not start right now:{" "}
              {BLOCKED[blocked] ?? skipReason(blocked)}
            </span>
          </p>
        )}
      </section>

      <section className={sectionCls}>
        <h2 className={h2Cls}>AI provider</h2>
        <div>
          <label htmlFor="watch-provider" className={labelCls}>
            Provider
          </label>
          <select
            id="watch-provider"
            value={draft.provider_id}
            onChange={(e) => set("provider_id", e.target.value)}
            className={inputCls}
          >
            <option value="">
              Highest-priority provider Copilot Watch may use
            </option>
            {data.providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.default_model || "no default model"})
                {p.is_on_prem ? " · on-prem" : " · hosted"}
                {p.is_enabled ? "" : " · disabled"}
              </option>
            ))}
          </select>
          <p className="mt-1 text-xs text-muted-foreground">
            Only providers marked on-prem on the{" "}
            <Link
              to="/admin/ai/providers"
              className="text-primary hover:underline"
            >
              AI Providers
            </Link>{" "}
            page are used, unless the box below is ticked. A run never falls
            back to a provider it could not have started on.
          </p>
        </div>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={draft.allow_hosted_provider}
            onChange={(e) => set("allow_hosted_provider", e.target.checked)}
          />
          <span>
            Allow a hosted provider
            <span className="block text-xs text-muted-foreground">
              Lets Copilot Watch send data to a provider that is not marked
              on-prem. Alert text, server names, DNS names and client
              hostnames then leave your network unattended, every run.
            </span>
          </span>
        </label>
      </section>

      <section className={sectionCls}>
        <h2 className={h2Cls}>When it runs</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="watch-sweep" className={labelCls}>
              Scheduled sweep every (hours, 0 = off)
            </label>
            <input
              id="watch-sweep"
              inputMode="numeric"
              value={draft.sweep_interval_hours}
              onChange={(e) => set("sweep_interval_hours", e.target.value)}
              className={inputCls}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              Last sweep: {fmtWhen(data.last_sweep_at)}
            </p>
          </div>
          <div>
            <label htmlFor="watch-debounce" className={labelCls}>
              Wait after an alert change (seconds, 60 to 3600)
            </label>
            <input
              id="watch-debounce"
              inputMode="numeric"
              value={draft.event_debounce_seconds}
              onChange={(e) => set("event_debounce_seconds", e.target.value)}
              className={inputCls}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              One outage that opens many alerts is reviewed once, this long
              after the first.
            </p>
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.event_trigger_enabled}
            onChange={(e) => set("event_trigger_enabled", e.target.checked)}
          />
          Run when an alert opens or gets worse
        </label>
      </section>

      <section className={sectionCls}>
        <h2 className={h2Cls}>Budget and limits</h2>
        <p className="text-xs text-muted-foreground">
          Used today: {usage.tokens.toLocaleString()} of{" "}
          {usage.token_budget.toLocaleString()} tokens, $
          {Number(usage.cost_usd).toFixed(4)} of $
          {Number(usage.cost_budget_usd).toFixed(2)}, in {usage.runs} run
          {usage.runs === 1 ? "" : "s"}. Both budgets are required. When
          either is reached Copilot Watch pauses until 00:00 UTC and says so on
          this page. A model that is not on the rate sheet (most local models)
          has no known cost, so the token budget is what limits it.
        </p>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <label htmlFor="watch-tokens" className={labelCls}>
              Daily token budget
            </label>
            <input
              id="watch-tokens"
              inputMode="numeric"
              value={draft.daily_token_budget}
              onChange={(e) => set("daily_token_budget", e.target.value)}
              className={inputCls}
            />
          </div>
          <div>
            <label htmlFor="watch-cost" className={labelCls}>
              Daily cost budget (USD)
            </label>
            <input
              id="watch-cost"
              inputMode="decimal"
              value={draft.daily_cost_budget_usd}
              onChange={(e) => set("daily_cost_budget_usd", e.target.value)}
              className={inputCls}
            />
          </div>
          <div>
            <label htmlFor="watch-per-hour" className={labelCls}>
              Runs per hour, at most
            </label>
            <input
              id="watch-per-hour"
              inputMode="numeric"
              value={draft.max_runs_per_hour}
              onChange={(e) => set("max_runs_per_hour", e.target.value)}
              className={inputCls}
            />
          </div>
          <div>
            <label htmlFor="watch-rounds" className={labelCls}>
              Model rounds per run, at most
            </label>
            <input
              id="watch-rounds"
              inputMode="numeric"
              value={draft.max_rounds}
              onChange={(e) => set("max_rounds", e.target.value)}
              className={inputCls}
            />
          </div>
          <div>
            <label htmlFor="watch-run-tokens" className={labelCls}>
              Tokens per run, at most
            </label>
            <input
              id="watch-run-tokens"
              inputMode="numeric"
              value={draft.max_tokens_per_run}
              onChange={(e) => set("max_tokens_per_run", e.target.value)}
              className={inputCls}
            />
          </div>
        </div>
      </section>

      <section className={sectionCls}>
        <h2 className={h2Cls}>Identity</h2>
        <p className="text-xs text-muted-foreground">
          Copilot Watch runs as the built-in service identity{" "}
          <code>{data.principal.username}</code>, which cannot sign in. It
          reads what the roles of the <strong>{data.principal.group}</strong>{" "}
          group allow, currently:{" "}
          {data.principal.roles.length
            ? data.principal.roles.join(", ")
            : "no roles, so nothing"}
          . To narrow what it can see, give that group narrower read-only
          roles under{" "}
          <Link to="/admin/groups" className="text-primary hover:underline">
            Groups
          </Link>
          . Every tool call it makes is in the audit log under this identity.
        </p>
        {data.principal.problem && (
          <p
            role="alert"
            className="rounded-md border border-destructive/30 bg-destructive/10 p-2 text-xs text-destructive"
          >
            {skipReason(data.principal.problem)}. Copilot Watch will not run
            until this is fixed.
          </p>
        )}
      </section>

      <section className={sectionCls}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className={h2Cls}>
            Tools it may call ({selected.size} of {data.tools.length})
          </h2>
          <button
            type="button"
            onClick={() => set("enabled_tools", null)}
            disabled={draft.enabled_tools === null}
            className="rounded-md border bg-background px-2.5 py-1 text-xs hover:bg-muted disabled:opacity-50"
          >
            Use the default list
          </button>
        </div>
        <p className="text-xs text-muted-foreground">
          Read-only tools the model may use to look closer at what the
          evidence names. Tools that change anything, stage a change or send
          traffic outward are never offered and are not listed. The identity's
          roles and the platform Tool Catalog narrow this further.
        </p>
        <div className="grid max-h-72 gap-x-4 gap-y-1 overflow-auto sm:grid-cols-2 lg:grid-cols-3">
          {data.tools.map((t) => (
            <label
              key={t.name}
              className="flex items-start gap-2 text-xs"
              title={t.description}
            >
              <input
                type="checkbox"
                className="mt-0.5"
                checked={selected.has(t.name)}
                onChange={(e) => toggleTool(t.name, e.target.checked)}
              />
              <code className="break-all">{t.name}</code>
            </label>
          ))}
        </div>
      </section>

      {(formError || save.isError) && (
        <div role="alert" className="text-sm text-destructive">
          {formError ??
            formatApiError(save.error, "Could not save the settings")}
        </div>
      )}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={submit}
          disabled={!dirty || save.isPending}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          Save settings
        </button>
        {save.isSuccess && !dirty && (
          <span role="status" className="text-xs text-muted-foreground">
            Saved.
          </span>
        )}
      </div>

      <MutesSection />
      <FeedbackSection />
    </div>
  );
}

function MutesSection() {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["ai-watch", "mutes"],
    queryFn: aiWatchApi.listMutes,
    retry: false,
  });
  const remove = useMutation({
    mutationFn: (id: string) => aiWatchApi.deleteMute(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-watch", "mutes"] }),
  });
  if (!data || data.length === 0) return null;
  return (
    <section className={sectionCls}>
      <h2 className={h2Cls}>Muted findings</h2>
      <p className="text-xs text-muted-foreground">
        Findings dismissed with a mute. Copilot Watch does not file these
        again while the mute holds.
      </p>
      {remove.isError && (
        <div role="alert" className="text-sm text-destructive">
          {formatApiError(remove.error, "Could not remove the mute")}
        </div>
      )}
      <ul className="divide-y text-sm">
        {data.map((m) => (
          <li key={m.id} className="flex flex-wrap items-center gap-2 py-1.5">
            <span className="min-w-0 flex-1 break-words">
              {m.title || m.fingerprint.slice(0, 12)}
              <span className="block text-xs text-muted-foreground">
                {m.until ? `until ${fmtWhen(m.until)}` : "until removed"}
                {m.reason ? ` · ${m.reason}` : ""}
              </span>
            </span>
            <button
              type="button"
              onClick={() => remove.mutate(m.id)}
              disabled={remove.isPending}
              className="rounded-md border bg-background px-2.5 py-1 text-xs hover:bg-muted disabled:opacity-50"
            >
              Remove mute
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function FeedbackSection() {
  const { data } = useQuery({
    queryKey: ["ai-watch", "feedback-stats"],
    queryFn: aiWatchApi.feedbackStats,
    retry: false,
  });
  if (!data || data.length === 0) return null;
  return (
    <section className={sectionCls}>
      <h2 className={h2Cls}>How useful the findings were</h2>
      <p className="text-xs text-muted-foreground">
        Verdicts people left on findings, by finding kind and by the model
        that wrote them. A kind or a model that keeps being marked wrong is
        one to mute, narrow or replace.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[420px] text-left text-sm">
          <thead className="text-xs text-muted-foreground">
            <tr>
              <th className="py-1 pr-3 font-medium">Kind or model</th>
              <th className="py-1 pr-3 text-right font-medium">Useful</th>
              <th className="py-1 pr-3 text-right font-medium">Not useful</th>
              <th className="py-1 text-right font-medium">Wrong</th>
            </tr>
          </thead>
          <tbody>
            {data.map((s) => (
              <tr key={`${s.dimension}:${s.value}`} className="border-t">
                <td className="py-1 pr-3">
                  <span className="text-xs text-muted-foreground">
                    {s.dimension}
                  </span>{" "}
                  {s.value || "unknown"}
                </td>
                <td className="py-1 pr-3 text-right tabular-nums">
                  {s.useful}
                </td>
                <td className="py-1 pr-3 text-right tabular-nums">
                  {s.not_useful}
                </td>
                <td className="py-1 text-right tabular-nums">{s.wrong}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
