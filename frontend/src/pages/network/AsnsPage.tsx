import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  Building2,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";

import {
  asnsApi,
  type ASNKind,
  type ASNListQuery,
  type ASNRead,
  type ASNRegistry,
  type ASNWhoisState,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { TagFilterChips } from "@/components/TagFilterChips";
import { cn } from "@/lib/utils";

import { errMsg, humanTime } from "./_shared";
import { AsnFormModal } from "./AsnFormModal";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

// ── Badges ──────────────────────────────────────────────────────────

const REGISTRY_LABEL: Record<ASNRegistry, string> = {
  arin: "ARIN",
  ripe: "RIPE",
  apnic: "APNIC",
  lacnic: "LACNIC",
  afrinic: "AFRINIC",
  unknown: "—",
};

const REGISTRY_COLOR: Record<ASNRegistry, string> = {
  arin: "bg-blue-500/15 text-blue-700 dark:text-blue-400",
  ripe: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  apnic: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  lacnic: "bg-purple-500/15 text-purple-700 dark:text-purple-400",
  afrinic: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
  unknown: "bg-muted text-muted-foreground",
};

function KindBadge({ kind }: { kind: ASNKind }) {
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

function RegistryBadge({ registry }: { registry: ASNRegistry }) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        REGISTRY_COLOR[registry],
      )}
    >
      {REGISTRY_LABEL[registry]}
    </span>
  );
}

const WHOIS_LABEL: Record<ASNWhoisState, string> = {
  ok: "OK",
  drift: "Drift",
  unreachable: "Unreachable",
  "n/a": "n/a",
};
const WHOIS_COLOR: Record<ASNWhoisState, string> = {
  ok: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  drift: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
  unreachable: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  "n/a": "bg-muted text-muted-foreground",
};

function WhoisBadge({ state }: { state: ASNWhoisState }) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium",
        WHOIS_COLOR[state],
      )}
    >
      {WHOIS_LABEL[state]}
    </span>
  );
}

// ── Filter chip helper (mirrors NetworkPage) ────────────────────────

function FilterChips<T extends string>({
  label,
  value,
  options,
  onChange,
  formatter,
}: {
  label: string;
  value: T | "all";
  options: T[];
  onChange: (v: T | "all") => void;
  formatter?: (v: T) => string;
}) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <button
        type="button"
        onClick={() => onChange("all")}
        className={`rounded-full px-2 py-0.5 text-[11px] ${
          value === "all"
            ? "bg-primary text-primary-foreground"
            : "border hover:bg-muted"
        }`}
      >
        All
      </button>
      {options.map((opt) => (
        <button
          key={opt}
          type="button"
          onClick={() => onChange(opt)}
          className={`rounded-full px-2 py-0.5 text-[11px] capitalize ${
            value === opt
              ? "bg-primary text-primary-foreground"
              : "border hover:bg-muted"
          }`}
        >
          {formatter ? formatter(opt) : opt}
        </button>
      ))}
    </div>
  );
}

// ── Bulk-delete confirmation ────────────────────────────────────────

function ConfirmBulkDeleteModal({
  count,
  onConfirm,
  onClose,
  pending,
}: {
  count: number;
  onConfirm: () => void;
  onClose: () => void;
  pending: boolean;
}) {
  return (
    <Modal title="Delete ASNs" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p>
          Delete <span className="font-semibold">{count}</span> ASN
          {count === 1 ? "" : "s"}? Linked RPKI ROA rows are removed (CASCADE).
          This won't touch IPAM rows or BGP-relationship FKs (those land in
          follow-up issues with their own delete policy).
        </p>
        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            disabled={pending}
            className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={pending}
            className="rounded-md bg-destructive px-3 py-1.5 text-xs text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {pending ? "Deleting…" : `Delete ${count}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Per-row component (owns the per-row refreshWhois mutation) ───────

function AsnRow({
  asn: a,
  selected: sel,
  onToggle,
  onEdit,
}: {
  asn: ASNRead;
  selected: boolean;
  onToggle: () => void;
  onEdit: () => void;
}) {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write on 'manage_asns'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_asns"),
    "Requires write permission on ASNs",
  );
  const qc = useQueryClient();
  const refreshMut = useMutation({
    mutationFn: () => asnsApi.refreshWhois(a.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asns"] });
    },
  });

  return (
    <tr
      className={`border-b last:border-0 hover:bg-muted/20 ${
        sel ? "bg-primary/5" : ""
      }`}
    >
      <td className="w-8 px-2 py-2">
        <input
          type="checkbox"
          checked={sel}
          onChange={onToggle}
          aria-label={`Select AS${a.number}`}
        />
      </td>
      <td className="whitespace-nowrap px-3 py-2 font-mono">
        <Link
          to={`/network/asns/${a.id}`}
          className="hover:text-primary hover:underline"
        >
          AS{a.number}
        </Link>
      </td>
      <td className="whitespace-nowrap px-3 py-2">
        <Link to={`/network/asns/${a.id}`} className="hover:text-primary">
          <div className="font-medium">
            {a.name || <span className="text-muted-foreground">—</span>}
          </div>
          {a.description && (
            <div className="text-[11px] text-muted-foreground">
              {a.description}
            </div>
          )}
        </Link>
      </td>
      <td className="px-3 py-2">
        <KindBadge kind={a.kind} />
      </td>
      <td className="whitespace-nowrap px-3 py-2">
        {a.holder_org ?? <span className="text-muted-foreground">—</span>}
      </td>
      <td className="px-3 py-2">
        <RegistryBadge registry={a.registry} />
      </td>
      <td className="px-3 py-2">
        <WhoisBadge state={a.whois_state} />
      </td>
      <td
        className="whitespace-nowrap px-3 py-2 text-muted-foreground"
        title={a.whois_last_checked_at ?? ""}
      >
        {humanTime(a.whois_last_checked_at)}
      </td>
      <td className="w-16 px-2 py-2 text-right">
        <div className="inline-flex items-center gap-0.5">
          <button
            onClick={() => refreshMut.mutate()}
            disabled={refreshMut.isPending || a.kind === "private"}
            title={
              a.kind === "private"
                ? "Private ASN — no public WHOIS"
                : "Refresh WHOIS"
            }
            className="inline-flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground disabled:pointer-events-none disabled:opacity-40"
            {...writeGate}
          >
            {refreshMut.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-[14px] w-[14px]" />
            )}
          </button>
          <button
            onClick={onEdit}
            title="Edit ASN"
            className="inline-flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
            {...writeGate}
          >
            <Pencil className="h-3 w-3" />
          </button>
        </div>
      </td>
    </tr>
  );
}

// ── Page ────────────────────────────────────────────────────────────

export function AsnsPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'manage_asns'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_asns"),
    "Requires write permission on ASNs",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "manage_asns"),
    "Requires delete permission on ASNs",
  );
  const qc = useQueryClient();

  const [kindFilter, setKindFilter] = useState<ASNKind | "all">("all");
  const [registryFilter, setRegistryFilter] = useState<ASNRegistry | "all">(
    "all",
  );
  const [whoisFilter, setWhoisFilter] = useState<ASNWhoisState | "all">("all");
  const [search, setSearch] = useState("");
  const [tagFilters, setTagFilters] = useState<string[]>([]);

  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<ASNRead | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [bulkError, setBulkError] = useState<string | null>(null);

  const queryParams = useMemo<ASNListQuery>(() => {
    const p: ASNListQuery = { limit: 200, offset: 0 };
    if (kindFilter !== "all") p.kind = kindFilter;
    if (registryFilter !== "all") p.registry = registryFilter;
    if (whoisFilter !== "all") p.whois_state = whoisFilter;
    if (search.trim()) p.search = search.trim();
    if (tagFilters.length > 0) p.tag = tagFilters;
    return p;
  }, [kindFilter, registryFilter, whoisFilter, search, tagFilters]);

  const {
    data,
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["asns", queryParams],
    queryFn: () => asnsApi.list(queryParams),
    // #278 follow-up — a freshly-created ASN's RDAP/RPKI data lands a few
    // seconds later via the one-shot worker task. ``whois_last_checked_at``
    // is null until that first lookup records an attempt (it's stamped for
    // private rows too), so poll while any row is still un-checked and stop
    // once they've all reported — no manual Refresh needed.
    refetchInterval: (query) => {
      const rows = query.state.data?.items ?? [];
      return rows.some((a) => a.whois_last_checked_at == null) ? 3000 : false;
    },
  });
  const asns = data?.items ?? [];
  const total = data?.total ?? 0;

  const allSelected = asns.length > 0 && asns.every((a) => selected.has(a.id));
  const someSelected = !allSelected && asns.some((a) => selected.has(a.id));

  function toggleAll() {
    if (allSelected) setSelected(new Set());
    else setSelected(new Set(asns.map((a) => a.id)));
  }
  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const bulkDelete = useMutation({
    mutationFn: () => asnsApi.bulkDelete(Array.from(selected)),
    onSuccess: () => {
      setBulkError(null);
      setSelected(new Set());
      setConfirmDelete(false);
      qc.invalidateQueries({ queryKey: ["asns"] });
    },
    onError: (e: unknown) => {
      setBulkError(errMsg(e, "Bulk delete failed"));
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Building2 className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">ASNs</h1>
              <span className="text-xs text-muted-foreground">
                {listError ? "—" : `${total} ASN${total === 1 ? "" : "s"}`}
                {selected.size > 0 && (
                  <span className="ml-2 text-primary">
                    {selected.size} selected
                  </span>
                )}
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              The autonomous systems carrying our IP space. Foundation for RDAP
              refresh, RPKI ROA tracking, and BGP-relationship FKs in follow-up
              phases.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() => qc.invalidateQueries({ queryKey: ["asns"] })}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowCreate(true)}
              {...writeGate}
            >
              New ASN
            </HeaderButton>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-3">
          <FilterChips
            label="Kind"
            value={kindFilter}
            options={["public", "private"] as ASNKind[]}
            onChange={setKindFilter}
          />
          <FilterChips
            label="Registry"
            value={registryFilter}
            options={
              [
                "arin",
                "ripe",
                "apnic",
                "lacnic",
                "afrinic",
                "unknown",
              ] as ASNRegistry[]
            }
            onChange={setRegistryFilter}
            formatter={(v) => REGISTRY_LABEL[v]}
          />
          <FilterChips
            label="WHOIS"
            value={whoisFilter}
            options={["ok", "drift", "unreachable", "n/a"] as ASNWhoisState[]}
            onChange={setWhoisFilter}
            formatter={(v) => WHOIS_LABEL[v]}
          />
          <input
            type="text"
            placeholder="Search number / name / holder…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="ml-auto rounded-md border bg-background px-3 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>

        <div className="mt-2">
          <TagFilterChips
            value={tagFilters}
            onChange={setTagFilters}
            placeholder="Filter by tag — try env or env:prod…"
          />
        </div>

        {selected.size > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md border bg-muted/20 px-3 py-2">
            <span className="text-xs font-medium">Bulk:</span>
            <button
              onClick={() => setConfirmDelete(true)}
              className="inline-flex items-center gap-1 rounded-md bg-destructive px-2 py-1 text-xs text-destructive-foreground hover:bg-destructive/90 disabled:cursor-not-allowed disabled:opacity-50"
              {...deleteGate}
            >
              <Trash2 className="h-3 w-3" /> Delete {selected.size}
            </button>
            <span className="h-4 w-px bg-border" />
            <button
              onClick={() => setSelected(new Set())}
              className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
            >
              Clear
            </button>
            {bulkError && (
              <span className="ml-2 text-xs text-red-600">{bulkError}</span>
            )}
          </div>
        )}
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {asns.length === 0 ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <Building2 className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                <ListEmpty
                  error={listError}
                  what="ASNs"
                  filtered={
                    kindFilter !== "all" ||
                    registryFilter !== "all" ||
                    whoisFilter !== "all" ||
                    search.trim() !== "" ||
                    tagFilters.length > 0
                  }
                  onClearFilters={() => {
                    setKindFilter("all");
                    setRegistryFilter("all");
                    setWhoisFilter("all");
                    setSearch("");
                    setTagFilters([]);
                  }}
                >
                  No ASNs tracked yet — add one to start the registry.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-1 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...writeGate}
              >
                <Plus className="h-3 w-3" /> New ASN
              </button>
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 z-10 bg-muted/30">
                <tr className="border-b">
                  <th className="w-8 px-2 py-2">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      ref={(el) => {
                        if (el) el.indeterminate = someSelected;
                      }}
                      onChange={toggleAll}
                      aria-label="Select all"
                    />
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Number
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Name
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Kind
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Holder Org
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Registry
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    WHOIS
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Last Checked
                  </th>
                  <th className="w-16 px-2 py-2" />
                </tr>
              </thead>
              <tbody>
                {asns.map((a) => (
                  <AsnRow
                    key={a.id}
                    asn={a}
                    selected={selected.has(a.id)}
                    onToggle={() => toggleOne(a.id)}
                    onEdit={() => setEditing(a)}
                  />
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {showCreate && <AsnFormModal onClose={() => setShowCreate(false)} />}
      {editing && (
        <AsnFormModal asn={editing} onClose={() => setEditing(null)} />
      )}
      {confirmDelete && (
        <ConfirmBulkDeleteModal
          count={selected.size}
          pending={bulkDelete.isPending}
          onConfirm={() => bulkDelete.mutate()}
          onClose={() => setConfirmDelete(false)}
        />
      )}
    </div>
  );
}
