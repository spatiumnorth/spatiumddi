import { ListEmpty } from "@/components/ui/list-read-error";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  domainsApi,
  type Domain,
  type DomainCreate,
  type DomainUpdate,
  type DomainWhoisState,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { TagFilterChips } from "@/components/TagFilterChips";
import { CustomerPicker, ProviderPicker } from "@/components/ownership/pickers";
import { ZoneScopePill } from "@/components/ZoneScopePill";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// ── helpers ─────────────────────────────────────────────────────────────────

function daysUntil(iso: string | null): number | null {
  if (!iso) return null;
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms)) return null;
  return Math.floor(ms / (24 * 3600 * 1000));
}

function relativeFromNow(iso: string | null): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return "—";
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function parseTextareaList(raw: string): string[] {
  // Split on newlines / commas / spaces, drop blanks. Operator-ergonomic
  // — they can paste a registrar's "ns1.example.com, ns2.example.com"
  // as-is or one-per-line.
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function ExpiryBadge({ expiresAt }: { expiresAt: string | null }) {
  const days = daysUntil(expiresAt);
  if (expiresAt === null || days === null) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  let cls =
    "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400";
  let label = `${days}d`;
  if (days < 0) {
    cls = "bg-red-200 text-red-900 dark:bg-red-950/50 dark:text-red-300";
    label = `expired ${Math.abs(days)}d ago`;
  } else if (days < 30) {
    cls = "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400";
  } else if (days <= 90) {
    cls =
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400";
  }
  const date = new Date(expiresAt).toLocaleDateString();
  return (
    <span className="inline-flex items-center gap-2">
      <span className="text-xs tabular-nums text-muted-foreground">{date}</span>
      <span
        className={cn(
          "rounded px-2 py-0.5 text-[11px] font-medium tabular-nums",
          cls,
        )}
        title={`Expires in ${days} days`}
      >
        {label}
      </span>
    </span>
  );
}

function StateBadge({ state }: { state: DomainWhoisState }) {
  const styles: Record<DomainWhoisState, string> = {
    ok: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    drift:
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400",
    expiring:
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400",
    expired: "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400",
    unreachable:
      "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
    unknown: "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
    // #986 — the name is not under a delegated TLD, so RDAP is skipped
    // rather than attempted and reported as an outage.
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

// ── Editor modal ────────────────────────────────────────────────────────────

function DomainEditorModal({
  existing,
  onClose,
}: {
  existing: Domain | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [expectedNs, setExpectedNs] = useState(
    (existing?.expected_nameservers ?? []).join("\n"),
  );
  const [customerId, setCustomerId] = useState<string | null>(
    existing?.customer_id ?? null,
  );
  const [registrarProviderId, setRegistrarProviderId] = useState<string | null>(
    existing?.registrar_provider_id ?? null,
  );
  const [tagsRaw, setTagsRaw] = useState(
    JSON.stringify(existing?.tags ?? {}, null, 2),
  );
  const [cfRaw, setCfRaw] = useState(
    JSON.stringify(existing?.custom_fields ?? {}, null, 2),
  );
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: async () => {
      let tags: Record<string, unknown> = {};
      let custom_fields: Record<string, unknown> = {};
      try {
        tags = tagsRaw.trim() ? JSON.parse(tagsRaw) : {};
      } catch {
        throw new Error("Tags must be valid JSON");
      }
      try {
        custom_fields = cfRaw.trim() ? JSON.parse(cfRaw) : {};
      } catch {
        throw new Error("Custom fields must be valid JSON");
      }
      const expected_nameservers = parseTextareaList(expectedNs);
      if (existing) {
        const body: DomainUpdate = {
          name,
          expected_nameservers,
          tags,
          custom_fields,
          customer_id: customerId,
          registrar_provider_id: registrarProviderId,
        };
        return domainsApi.update(existing.id, body);
      }
      const body: DomainCreate = {
        name,
        expected_nameservers,
        tags,
        custom_fields,
        customer_id: customerId,
        registrar_provider_id: registrarProviderId,
      };
      return domainsApi.create(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["domains"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string } };
      };
      setError(err?.response?.data?.detail ?? err?.message ?? "Save failed");
    },
  });

  return (
    <Modal
      onClose={onClose}
      title={existing ? "Edit domain" : "New domain"}
      wide
    >
      <div className="space-y-4">
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Apex domain
          </label>
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="example.com"
            autoFocus={!existing}
          />
          <p className="text-[11px] text-muted-foreground/80">
            Lowercased + trailing dot stripped on save.
          </p>
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Expected nameservers
          </label>
          <textarea
            className={cn(inputCls, "min-h-[90px] font-mono text-xs")}
            value={expectedNs}
            onChange={(e) => setExpectedNs(e.target.value)}
            placeholder={"ns1.example.com\nns2.example.com"}
          />
          <p className="text-[11px] text-muted-foreground/80">
            One per line (or comma / space separated). Drift is computed against
            the registry-reported list on the next refresh.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Customer
            </label>
            <CustomerPicker
              className={inputCls}
              value={customerId}
              onChange={setCustomerId}
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Registrar (Provider)
            </label>
            <ProviderPicker
              className={inputCls}
              value={registrarProviderId}
              onChange={setRegistrarProviderId}
              kind="registrar"
            />
            <p className="text-[11px] text-muted-foreground/80">
              FK successor to the freeform registrar text. Pick a Provider of
              kind "registrar".
            </p>
          </div>
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Tags (JSON object)
          </label>
          <textarea
            className={cn(inputCls, "min-h-[60px] font-mono text-xs")}
            value={tagsRaw}
            onChange={(e) => setTagsRaw(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Custom fields (JSON object)
          </label>
          <textarea
            className={cn(inputCls, "min-h-[60px] font-mono text-xs")}
            value={cfRaw}
            onChange={(e) => setCfRaw(e.target.value)}
          />
        </div>
        {error && <p className="text-xs text-red-600">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!name.trim() || mut.isPending}
            onClick={() => {
              setError(null);
              mut.mutate();
            }}
            className={cn(
              "rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground",
              "hover:bg-primary/90 disabled:opacity-50",
            )}
          >
            {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Page ────────────────────────────────────────────────────────────────────

export function DomainsPage() {
  // #1341 — a read-only user is offered no write it would be refused:
  // the router asks write on 'manage_domains'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_domains"),
    "Requires write permission on domains",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "manage_domains"),
    "Requires delete permission on domains",
  );
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Domain | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [stateFilter, setStateFilter] = useState<DomainWhoisState | "">("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [refreshingId, setRefreshingId] = useState<string | null>(null);
  const [tagFilters, setTagFilters] = useState<string[]>([]);

  const listParams = {
    ...(stateFilter ? { whois_state: stateFilter } : {}),
    ...(search.trim() ? { search: search.trim() } : {}),
    ...(tagFilters.length > 0 ? { tag: tagFilters } : {}),
    page_size: 200,
  };

  const {
    data,
    isLoading,
    refetch,
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["domains", listParams],
    queryFn: () => domainsApi.list(listParams),
    // #278 — a freshly-created domain's RDAP data lands a few seconds
    // later via the one-shot worker task. ``whois_last_checked_at`` is
    // null until that first lookup records an attempt (success OR
    // unreachable), so poll while any row is still un-checked and stop
    // once they've all reported — no manual Refresh needed.
    refetchInterval: (query) => {
      const rows = query.state.data?.items ?? [];
      return rows.some((d) => d.whois_last_checked_at == null) ? 3000 : false;
    },
  });

  const items = useMemo(() => data?.items ?? [], [data]);

  const refresh = useMutation({
    mutationFn: async (id: string) => {
      setRefreshingId(id);
      try {
        return await domainsApi.refreshWhois(id);
      } finally {
        setRefreshingId(null);
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["domains"] }),
  });

  const del = useMutation({
    mutationFn: (id: string) => domainsApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["domains"] }),
  });

  const bulkDel = useMutation({
    mutationFn: (ids: string[]) => domainsApi.bulkDelete(ids),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["domains"] });
      setSelected(new Set());
    },
  });

  // Bulk-refresh fans out individual refresh calls so each row's
  // ``whois_data`` updates independently. Sequential keeps us
  // gentle on the upstream RDAP service; the deferred scheduled
  // task will own real rate-limiting.
  const bulkRefresh = useMutation({
    mutationFn: async (ids: string[]) => {
      for (const id of ids) {
        try {
          await domainsApi.refreshWhois(id);
        } catch {
          // Swallow per-row errors so one slow / dead RDAP server
          // doesn't abort the whole batch.
        }
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["domains"] }),
  });

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (selected.size === items.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(items.map((d) => d.id)));
    }
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-[1400px] space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-bold tracking-tight">Domains</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Track registered domains via RDAP — registrar, expiry, nameserver
              drift, DNSSEC. Distinct from DNS zones (which SpatiumDDI serves
              authoritatively).
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              onClick={() => refetch()}
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
              disabled={isFetching}
            >
              <RefreshCw
                className={cn("h-3.5 w-3.5", isFetching && "animate-spin")}
              />
              Refresh
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground",
                "hover:bg-primary/90",
              )}
              {...writeGate}
            >
              <Plus className="h-3.5 w-3.5" />
              New domain
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-card p-3">
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search name or registrar…"
            className={cn(inputCls, "max-w-xs")}
          />
          <select
            className={cn(inputCls, "max-w-[200px]")}
            value={stateFilter}
            onChange={(e) =>
              setStateFilter(e.target.value as DomainWhoisState | "")
            }
          >
            <option value="">All states</option>
            <option value="ok">ok</option>
            <option value="drift">drift</option>
            <option value="expiring">expiring</option>
            <option value="expired">expired</option>
            <option value="unreachable">unreachable</option>
            <option value="n/a">n/a (no registry)</option>
            <option value="unknown">unknown</option>
          </select>
          <span className="ml-auto text-xs text-muted-foreground">
            {items.length} of {data?.total ?? 0}
          </span>
          <div className="basis-full">
            <TagFilterChips
              value={tagFilters}
              onChange={setTagFilters}
              placeholder="Filter by tag — try env or env:prod…"
            />
          </div>
        </div>

        {/* Bulk toolbar */}
        {selected.size > 0 && (
          <div className="flex items-center justify-between rounded-lg border border-primary/30 bg-primary/5 px-4 py-2">
            <span className="text-sm">{selected.size} selected</span>
            <div className="flex gap-2">
              <button
                onClick={() => bulkRefresh.mutate(Array.from(selected))}
                disabled={bulkRefresh.isPending}
                className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...writeGate}
              >
                <RefreshCw
                  className={cn(
                    "h-3.5 w-3.5",
                    bulkRefresh.isPending && "animate-spin",
                  )}
                />
                {bulkRefresh.isPending ? "Refreshing…" : "Bulk refresh WHOIS"}
              </button>
              <button
                onClick={() => {
                  if (
                    confirm(
                      `Delete ${selected.size} selected domain(s)? This cannot be undone.`,
                    )
                  ) {
                    bulkDel.mutate(Array.from(selected));
                  }
                }}
                disabled={bulkDel.isPending}
                className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:hover:bg-red-950/30"
                {...deleteGate}
              >
                <Trash2 className="h-3.5 w-3.5" />
                Bulk delete
              </button>
            </div>
          </div>
        )}

        {/* Table */}
        <div className="rounded-lg border bg-card">
          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10 bg-card text-xs uppercase tracking-wider text-muted-foreground">
              <tr className="border-b">
                <th className="px-3 py-2 text-left">
                  <input
                    type="checkbox"
                    aria-label="Select all"
                    checked={items.length > 0 && selected.size === items.length}
                    onChange={toggleSelectAll}
                  />
                </th>
                <th className="px-3 py-2 text-left">Name</th>
                <th className="px-3 py-2 text-left">Registrar</th>
                <th className="px-3 py-2 text-left">Expires</th>
                <th className="px-3 py-2 text-left">State</th>
                <th className="px-3 py-2 text-left">NS drift</th>
                <th className="px-3 py-2 text-left">DNSSEC</th>
                <th className="px-3 py-2 text-left">Last checked</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {isLoading && (
                <tr>
                  <td
                    colSpan={9}
                    className="px-4 py-8 text-center text-xs text-muted-foreground"
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!isLoading && items.length === 0 && (
                <tr>
                  <td
                    colSpan={9}
                    className="px-4 py-8 text-center text-xs text-muted-foreground"
                  >
                    <ListEmpty
                      error={listError}
                      what="domains"
                      filtered={
                        stateFilter !== "" ||
                        search.trim() !== "" ||
                        tagFilters.length > 0
                      }
                      onClearFilters={() => {
                        setStateFilter("");
                        setSearch("");
                        setTagFilters([]);
                      }}
                    >
                      No domains yet — click "New domain" to add the first one.
                    </ListEmpty>
                  </td>
                </tr>
              )}
              {items.map((d) => (
                <DomainRow
                  key={d.id}
                  domain={d}
                  selected={selected.has(d.id)}
                  onToggleSelect={() => toggleSelect(d.id)}
                  onEdit={() => setEditing(d)}
                  onDelete={() => {
                    if (
                      confirm(
                        `Delete domain "${d.name}"? This cannot be undone.`,
                      )
                    ) {
                      del.mutate(d.id);
                    }
                  }}
                  onRefresh={() => refresh.mutate(d.id)}
                  refreshing={refreshingId === d.id && refresh.isPending}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showCreate && (
        <DomainEditorModal
          existing={null}
          onClose={() => setShowCreate(false)}
        />
      )}
      {editing && (
        <DomainEditorModal
          existing={editing}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

function DomainRow({
  domain,
  selected,
  onToggleSelect,
  onEdit,
  onDelete,
  onRefresh,
  refreshing,
}: {
  domain: Domain;
  selected: boolean;
  onToggleSelect: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  // #1341 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'manage_domains'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_domains"),
    "Requires write permission on domains",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "manage_domains"),
    "Requires delete permission on domains",
  );
  return (
    <tr className={cn("border-b", selected && "bg-primary/5")}>
      <td className="px-3 py-2">
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggleSelect}
          aria-label={`Select ${domain.name}`}
        />
      </td>
      <td className="px-3 py-2 font-medium">
        <Link
          to={`/admin/domains/${domain.id}`}
          className="hover:text-primary hover:underline"
        >
          {domain.name}
        </Link>
        {/* #986 — a domain under a non-public TLD can never have RDAP
            data, which is why its state sits at "n/a". */}
        <ZoneScopePill scope={domain.name_scope} className="ml-2" />
      </td>
      <td className="px-3 py-2 text-muted-foreground">
        {domain.registrar ?? "—"}
      </td>
      <td className="px-3 py-2">
        <ExpiryBadge expiresAt={domain.expires_at} />
      </td>
      <td className="px-3 py-2">
        <StateBadge state={domain.whois_state} />
      </td>
      <td className="px-3 py-2">
        {domain.nameserver_drift ? (
          <span className="inline-flex items-center rounded bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:bg-amber-950/30 dark:text-amber-400">
            drift
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        )}
      </td>
      <td className="px-3 py-2">
        {domain.dnssec_signed ? (
          <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        )}
      </td>
      <td className="px-3 py-2 text-xs text-muted-foreground tabular-nums whitespace-nowrap">
        {relativeFromNow(domain.whois_last_checked_at)}
      </td>
      <td className="px-3 py-2">
        <div className="flex justify-end gap-1">
          <button
            onClick={onRefresh}
            disabled={refreshing}
            title="Refresh WHOIS"
            className="rounded p-1.5 hover:bg-accent disabled:opacity-50"
            {...writeGate}
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", refreshing && "animate-spin")}
            />
          </button>
          <button
            onClick={onEdit}
            title="Edit"
            className="rounded p-1.5 hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
            {...writeGate}
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={onDelete}
            title="Delete"
            className="rounded p-1.5 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30 disabled:cursor-not-allowed disabled:opacity-50"
            {...deleteGate}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </td>
    </tr>
  );
}
