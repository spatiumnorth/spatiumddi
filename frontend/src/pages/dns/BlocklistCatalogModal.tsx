import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  Loader2,
  Search,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Modal } from "@/components/ui/modal";
import {
  dnsBlocklistApi,
  type BlocklistApplyProfileResponse,
  type BlocklistCatalogSource,
  type BlocklistProfile,
  type BlocklistTemplate,
  type DNSBlockList,
  formatApiError,
} from "@/lib/api";
import { FormError } from "@/components/ui/form-error";

type Tab = "profiles" | "feeds" | "templates";

/**
 * Curated catalog browser. Three tabs, all ending in the same place —
 * a `DNSBlockList` row the operator then scopes to a group or view:
 *
 *  - Profiles  — several feeds + templates applied in one action.
 *  - Feeds     — a remote URL the refresh task fetches on a cadence.
 *  - Templates — entries shipped inline (SafeSearch rewrites), no feed.
 *
 * Already-applied entries are flagged so operators don't double-add.
 */
export function BlocklistCatalogModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("profiles");
  const [filter, setFilter] = useState("");
  const [category, setCategory] = useState<string>("all");

  const { data: catalog } = useQuery({
    queryKey: ["dns", "blocklist-catalog"],
    queryFn: () => dnsBlocklistApi.catalog(),
    staleTime: 60 * 60 * 1000,
  });

  const { data: existing = [] } = useQuery<DNSBlockList[]>({
    queryKey: ["dns-blocklists"],
    queryFn: () => dnsBlocklistApi.list(),
  });

  const subscribedUrls = useMemo(
    () => new Set(existing.map((b) => b.feed_url ?? "")),
    [existing],
  );

  // Applied templates are matched by NAME, not by feed_url: a template
  // list has no URL to compare, and the create path already refuses a
  // duplicate name — so name is exactly the key the backend uses too.
  const existingNames = useMemo(
    () => new Set(existing.map((b) => b.name)),
    [existing],
  );

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
  };

  const subscribeMut = useMutation({
    mutationFn: (sourceId: string) =>
      dnsBlocklistApi.subscribeFromCatalog({ source_id: sourceId }),
    onSuccess: invalidate,
  });

  const templateMut = useMutation({
    mutationFn: (v: { templateId: string; groupIds: string[] }) =>
      dnsBlocklistApi.createFromTemplate({
        template_id: v.templateId,
        group_ids: v.groupIds,
      }),
    onSuccess: invalidate,
  });

  const profileMut = useMutation<
    BlocklistApplyProfileResponse,
    unknown,
    string
  >({
    mutationFn: (profileId: string) =>
      dnsBlocklistApi.applyProfile({ profile_id: profileId }),
    onSuccess: invalidate,
  });

  const sources = catalog?.sources ?? [];
  const templates = catalog?.templates ?? [];
  const profiles = catalog?.profiles ?? [];
  const categories = useMemo(() => {
    const set = new Set(sources.map((s) => s.category));
    return ["all", ...Array.from(set).sort()];
  }, [sources]);

  const filtered = useMemo(() => {
    const f = filter.toLowerCase();
    return sources.filter((s) => {
      if (category !== "all" && s.category !== category) return false;
      if (!f) return true;
      return (
        s.name.toLowerCase().includes(f) ||
        s.description.toLowerCase().includes(f) ||
        s.id.toLowerCase().includes(f)
      );
    });
  }, [sources, filter, category]);

  const error =
    (subscribeMut.isError && formatApiError(subscribeMut.error)) ||
    (templateMut.isError && formatApiError(templateMut.error)) ||
    (profileMut.isError && formatApiError(profileMut.error)) ||
    null;

  const TABS: { id: Tab; label: string; count: number }[] = [
    { id: "profiles", label: "Profiles", count: profiles.length },
    { id: "feeds", label: "Feeds", count: sources.length },
    { id: "templates", label: "Templates", count: templates.length },
  ];

  return (
    <Modal title="Add a curated blocklist" onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap items-center gap-1 border-b">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`-mb-px border-b-2 px-3 py-1.5 text-xs ${
                tab === t.id
                  ? "border-primary font-medium text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {t.label}
              <span className="ml-1.5 text-[10px] text-muted-foreground">
                {t.count}
              </span>
            </button>
          ))}
          {catalog && (
            <span className="ml-auto pb-1 text-[11px] text-muted-foreground">
              Catalog version {catalog.version}
            </span>
          )}
        </div>

        {tab === "profiles" && (
          <>
            <p className="text-xs text-muted-foreground">
              A profile applies several feeds and templates at once. It creates
              the lists but assigns them to nothing — scope them to the views or
              server groups serving the networks you want filtered, or they
              filter nobody. Applied everywhere, they filter your servers too.
            </p>
            <div className="max-h-[60vh] space-y-2 overflow-y-auto">
              {profiles.map((p) => (
                <ProfileRow
                  key={p.id}
                  profile={p}
                  result={
                    profileMut.data?.profile_id === p.id
                      ? profileMut.data
                      : undefined
                  }
                  onApply={() => profileMut.mutate(p.id)}
                  isPending={
                    profileMut.isPending && profileMut.variables === p.id
                  }
                />
              ))}
              {profiles.length === 0 && (
                <p className="text-xs text-muted-foreground">
                  No profiles in this catalog version.
                </p>
              )}
            </div>
          </>
        )}

        {tab === "feeds" && (
          <>
            <p className="text-xs text-muted-foreground">
              Public DNS blocklist sources curated from AdGuard's
              HostlistsRegistry, Pi-hole defaults, and Hagezi / OISD.
              Subscribing creates a <code>url</code>-sourced blocklist with the
              entry's URL prefilled — the refresh pipeline parses and ingests
              entries on the configured cadence.
            </p>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-[200px] flex-1">
                <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Filter by name or description…"
                  className="w-full rounded border bg-background pl-7 pr-2 py-1 text-xs"
                />
              </div>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="rounded border bg-background px-2 py-1 text-xs"
              >
                {categories.map((c) => (
                  <option key={c} value={c}>
                    {c === "all" ? "All categories" : c}
                  </option>
                ))}
              </select>
            </div>

            <div className="max-h-[55vh] space-y-2 overflow-y-auto">
              {filtered.map((s) => (
                <CatalogRow
                  key={s.id}
                  source={s}
                  alreadySubscribed={subscribedUrls.has(s.feed_url)}
                  onSubscribe={() => subscribeMut.mutate(s.id)}
                  isPending={
                    subscribeMut.isPending && subscribeMut.variables === s.id
                  }
                />
              ))}
              {filtered.length === 0 && (
                <p className="text-xs text-muted-foreground">
                  No matching sources.
                </p>
              )}
            </div>
          </>
        )}

        {tab === "templates" && (
          <>
            <p className="text-xs text-muted-foreground">
              Entry sets shipped with the release instead of fetched — for rules
              that have no upstream feed. SafeSearch enforcement is a set of
              rewrites, not blocks: each engine still answers, from its own
              filtered endpoint. Requires a BIND9 server group; Windows,
              PowerDNS and the cloud DNS drivers do not enforce RPZ rewrites.
            </p>
            <div className="max-h-[55vh] space-y-2 overflow-y-auto">
              {templates.map((t) => (
                <TemplateRow
                  key={t.id}
                  template={t}
                  alreadyApplied={existingNames.has(t.name)}
                  onApply={(groupIds) =>
                    templateMut.mutate({ templateId: t.id, groupIds })
                  }
                  isPending={
                    templateMut.isPending &&
                    templateMut.variables?.templateId === t.id
                  }
                />
              ))}
              {templates.length === 0 && (
                <p className="text-xs text-muted-foreground">
                  No templates in this catalog version.
                </p>
              )}
            </div>
          </>
        )}

        {error && (
          <FormError className="text-xs text-destructive">{error}</FormError>
        )}

        <div className="flex justify-end pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted/50"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

function ProfileRow({
  profile,
  result,
  onApply,
  isPending,
}: {
  profile: BlocklistProfile;
  result?: BlocklistApplyProfileResponse;
  onApply: () => void;
  isPending: boolean;
}) {
  const total = profile.source_ids.length + profile.template_ids.length;
  return (
    <div className="rounded border bg-card p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 text-sm font-medium">
            <ShieldCheck className="h-3.5 w-3.5 text-primary" />
            {profile.name}
            <span className="rounded bg-muted px-1 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
              {total} lists
            </span>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {profile.description}
          </p>
          {profile.note && (
            <p className="mt-1 text-[11px] italic text-muted-foreground">
              {profile.note}
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={onApply}
          disabled={isPending}
          className="inline-flex flex-shrink-0 items-center gap-1 rounded bg-primary px-2 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {isPending && <Loader2 className="h-3 w-3 animate-spin" />}
          Apply
        </button>
      </div>
      {result && (
        <ul className="mt-2 space-y-0.5 border-t pt-2 text-[11px]">
          {result.items.map((i) => (
            <li key={`${i.kind}:${i.catalog_id}`} className="flex gap-1.5">
              <span
                className={
                  i.status === "created"
                    ? "text-emerald-600 dark:text-emerald-400"
                    : "text-muted-foreground"
                }
              >
                {i.status === "created"
                  ? "created"
                  : i.status === "skipped_existing"
                    ? "already present"
                    : "unavailable"}
              </span>
              <span className="text-muted-foreground">{i.name}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function TemplateRow({
  template,
  alreadyApplied,
  onApply,
  isPending,
}: {
  template: BlocklistTemplate;
  alreadyApplied: boolean;
  onApply: (groupIds: string[]) => void;
  isPending: boolean;
}) {
  const [selected, setSelected] = useState<string[]>(() =>
    template.groups.filter((g) => g.default).map((g) => g.id),
  );

  const toggle = (id: string) =>
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );

  // Two groups covering the same domain with different targets is a
  // configuration the API refuses (the YouTube Strict / Moderate pair).
  // The catalog declares each such pair, so this reads the declaration
  // rather than re-deriving it — the group's domain list isn't sent to
  // the client, and inferring it from names would be guesswork.
  const conflict = useMemo(() => {
    const chosen = template.groups.filter((g) => selected.includes(g.id));
    for (const g of chosen) {
      const clash = chosen.find((o) => g.conflicts_with.includes(o.id));
      if (clash) {
        return `"${g.name}" and "${clash.name}" rewrite the same domains to different targets — pick one.`;
      }
    }
    return null;
  }, [template.groups, selected]);

  const domainCount = template.groups
    .filter((g) => selected.includes(g.id))
    .reduce((n, g) => n + g.domain_count, 0);

  return (
    <div className="rounded border bg-card p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 text-sm font-medium">
            {template.name}
            <span className="rounded bg-muted px-1 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
              {template.category}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {template.description}
          </p>
        </div>
        <div className="flex flex-shrink-0 flex-col items-end gap-1">
          {alreadyApplied ? (
            <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-2 py-1 text-xs text-emerald-700 dark:text-emerald-400">
              <CheckCircle2 className="h-3 w-3" />
              Added
            </span>
          ) : (
            <button
              type="button"
              onClick={() => onApply(selected)}
              disabled={isPending || selected.length === 0 || conflict !== null}
              className="inline-flex items-center gap-1 rounded bg-primary px-2 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {isPending && <Loader2 className="h-3 w-3 animate-spin" />}
              Add {domainCount > 0 && `(${domainCount})`}
            </button>
          )}
        </div>
      </div>

      <div className="mt-2 space-y-1 border-t pt-2">
        {template.groups.map((g) => (
          <label
            key={g.id}
            className="flex cursor-pointer items-start gap-2 text-xs"
          >
            <input
              type="checkbox"
              checked={selected.includes(g.id)}
              onChange={() => toggle(g.id)}
              disabled={alreadyApplied}
              className="mt-0.5"
            />
            <span className="min-w-0 flex-1">
              <span className="font-medium">{g.name}</span>
              <span className="ml-1.5 text-muted-foreground">
                {g.domain_count} {g.domain_count === 1 ? "domain" : "domains"} →{" "}
                <code className="break-all">{g.target}</code>
              </span>
              {g.note && (
                <span className="mt-0.5 block text-[11px] italic text-muted-foreground">
                  {g.note}
                </span>
              )}
            </span>
          </label>
        ))}
      </div>

      {conflict && (
        <p className="mt-1.5 text-[11px] text-amber-600 dark:text-amber-400">
          {conflict}
        </p>
      )}
    </div>
  );
}

function CatalogRow({
  source,
  alreadySubscribed,
  onSubscribe,
  isPending,
}: {
  source: BlocklistCatalogSource;
  alreadySubscribed: boolean;
  onSubscribe: () => void;
  isPending: boolean;
}) {
  return (
    <div className="rounded border bg-card p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 text-sm font-medium">
            {source.name}
            {source.recommended && (
              <span
                className="inline-flex items-center gap-0.5 rounded bg-amber-500/15 px-1 py-0.5 text-[10px] text-amber-700 dark:text-amber-400"
                title="Recommended starting point"
              >
                <Sparkles className="h-2.5 w-2.5" />
                Recommended
              </span>
            )}
            <span className="rounded bg-muted px-1 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
              {source.category}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {source.description}
          </p>
          <div className="mt-1 flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
            <span className="font-mono">{source.feed_format}</span>
            <span>License: {source.license}</span>
            {source.homepage && (
              <a
                href={source.homepage}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-0.5 hover:text-foreground"
              >
                Homepage
                <ExternalLink className="h-2.5 w-2.5" />
              </a>
            )}
          </div>
        </div>
        <div className="flex flex-shrink-0 flex-col items-end gap-1">
          {alreadySubscribed ? (
            <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-2 py-1 text-xs text-emerald-700 dark:text-emerald-400">
              <CheckCircle2 className="h-3 w-3" />
              Subscribed
            </span>
          ) : (
            <button
              type="button"
              onClick={onSubscribe}
              disabled={isPending}
              className="inline-flex items-center gap-1 rounded bg-primary px-2 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {isPending ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <AlertCircle className="h-3 w-3" />
              )}
              Subscribe
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
