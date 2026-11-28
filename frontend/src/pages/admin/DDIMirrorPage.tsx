import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Eye,
  Pencil,
  Plus,
  RefreshCw,
  RotateCw,
  TestTube2,
  Trash2,
} from "lucide-react";

import {
  ddiMirrorApi,
  formatDialogError,
  type DDIMirrorAction,
  type DDIMirrorKind,
  type DDIMirrorTarget,
  type DDIMirrorTargetCreate,
  type DDIMirrorTargetUpdate,
  type DDIMirrorTestResult,
} from "@/lib/api";
import { countNoun } from "@/lib/count-noun";
import { Field } from "@/components/ui/field";
import { FormError } from "@/components/ui/form-error";
import { FreshEdit } from "@/components/FreshEdit";
import { HeaderButton } from "@/components/ui/header-button";
import { ListEmpty } from "@/components/ui/list-read-error";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { changedFields } from "@/hooks/useFreshRow";
import { useCredentialReask } from "@/hooks/useCredentialReask";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import { secondsFieldError } from "@/lib/seconds";

/**
 * Configuration → Import → DDI mirror (#4729).
 *
 * A read-only live mirror of a commercial DDI estate (Infoblox today) kept in
 * its own store, never in live IPAM / DNS / DHCP. Targets are managed here;
 * selecting one opens the cutover rehearsal (what an import would create and
 * what differs), the mirrored objects, and the last sync's report. Writes are
 * superadmin-only, as the API enforces.
 */

const KINDS: { key: DDIMirrorKind; label: string }[] = [
  { key: "view", label: "Views" },
  { key: "container", label: "Containers" },
  { key: "network", label: "Networks" },
  { key: "range", label: "Ranges" },
  { key: "reservation", label: "Fixed addresses" },
  { key: "zone", label: "Zones" },
  { key: "host", label: "Host records" },
  { key: "a", label: "A records" },
  { key: "ptr", label: "PTR records" },
];

const ACTIONS: DDIMirrorAction[] = ["create", "exists", "differs"];
const ACTION_CLS: Record<DDIMirrorAction, string> = {
  create: "bg-sky-500/15 text-sky-700 dark:text-sky-400",
  exists: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  differs: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
};
const PAGE = 100;

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const errMsg = formatDialogError;

type DetailTab = "rehearsal" | "mirror" | "report";

export function DDIMirrorPage() {
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: targets = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["ddi-mirror-targets"],
    queryFn: ddiMirrorApi.list,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<DDIMirrorTarget | null>(null);
  const [del, setDel] = useState<DDIMirrorTarget | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, DDIMirrorTestResult | undefined>
  >({});
  const selected = targets.find((t) => t.id === selectedId) ?? null;

  const refresh = () =>
    qc.invalidateQueries({ queryKey: ["ddi-mirror-targets"] });

  const delMut = useMutation({
    mutationFn: (id: string) => ddiMirrorApi.remove(id),
    onSuccess: (_d, id) => {
      refresh();
      if (selectedId === id) setSelectedId(null);
      setDel(null);
    },
  });
  const testMut = useMutation({
    mutationFn: (id: string) => ddiMirrorApi.testConnection({ target_id: id }),
    onMutate: (id) => setInlineTest((p) => ({ ...p, [id]: undefined })),
    onSuccess: (result, id) => {
      setInlineTest((p) => ({ ...p, [id]: result }));
      refresh();
    },
    onError: (e, id) =>
      setInlineTest((p) => ({
        ...p,
        [id]: { ok: false, message: errMsg(e, "Test failed"), version: null },
      })),
  });
  const syncMut = useMutation({
    mutationFn: (id: string) => ddiMirrorApi.syncNow(id),
    onSuccess: () => {
      refresh();
      setTimeout(refresh, 5000);
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <h1 className="text-lg font-semibold">Commercial DDI mirror</h1>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              A read-only, continuously refreshed copy of an Infoblox estate
              (networks, ranges, fixed addresses, host / A / PTR records, zones,
              views), kept apart from live IPAM, DNS and DHCP. Nothing is
              written to the source, and nothing is written to live data: the
              rehearsal shows what an import would create and what differs.
              BlueCat and EfficientIP are not supported yet.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={refresh}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowCreate(true)}
              {...superadminGate}
            >
              Add source
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 space-y-4 overflow-auto p-6">
        <div className="rounded-lg border">
          {targets.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted-foreground">
              <ListEmpty error={listError} what="mirror sources">
                No commercial DDI source configured yet.
              </ListEmpty>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[960px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    {[
                      "Name",
                      "Endpoint",
                      "Objects",
                      "Last sync",
                      "Test",
                      "",
                    ].map((h) => (
                      <th
                        key={h}
                        className="whitespace-nowrap px-3 py-2 text-left font-medium"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {targets.map((t) => {
                    const tr = inlineTest[t.id];
                    return (
                      <tr
                        key={t.id}
                        className={`border-b last:border-0 ${
                          t.id === selectedId ? "bg-accent/40" : ""
                        }`}
                      >
                        <td className="px-3 py-2 font-medium">
                          {t.name}
                          <span className="ml-2 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">
                            {t.vendor}
                          </span>
                          {!t.enabled && (
                            <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                              disabled
                            </span>
                          )}
                          {t.description && (
                            <div className="max-w-md truncate text-[11px] text-muted-foreground">
                              {t.description}
                            </div>
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px]">
                          {t.base_url}
                          <div className="text-muted-foreground">
                            WAPI {t.api_version}
                            {!t.verify_tls && " · TLS not verified"}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {t.object_count != null
                            ? countNoun(t.object_count, "object")
                            : "—"}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {t.last_synced_at
                            ? new Date(t.last_synced_at).toLocaleString()
                            : "never"}
                          {t.last_sync_error && (
                            <div
                              className="max-w-xs truncate text-[11px] text-destructive"
                              title={t.last_sync_error}
                            >
                              {t.last_sync_error}
                            </div>
                          )}
                          {!t.last_sync_error && t.last_sync_warning && (
                            <div
                              className="max-w-xs truncate text-[11px] text-amber-600 dark:text-amber-500"
                              title={t.last_sync_warning}
                            >
                              {t.last_sync_warning}
                            </div>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <button
                            onClick={() => testMut.mutate(t.id)}
                            disabled={testMut.isPending}
                            className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
                            {...superadminGate}
                          >
                            <TestTube2 className="h-3 w-3" />
                            Test
                          </button>
                          {tr && (
                            <div
                              role={tr.ok ? undefined : "alert"}
                              className={`mt-1 max-w-xs truncate text-[11px] ${
                                tr.ok
                                  ? "text-emerald-600 dark:text-emerald-400"
                                  : "text-destructive"
                              }`}
                              title={tr.message}
                            >
                              {tr.ok ? "✓" : "✗"} {tr.message}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <button
                            onClick={() => setSelectedId(t.id)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground"
                            title="Open rehearsal"
                            aria-label={`Open ${t.name}`}
                          >
                            <Eye className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => syncMut.mutate(t.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === t.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
                            aria-label="Sync Now"
                            {...superadminGate}
                          >
                            <RotateCw
                              className={`h-3.5 w-3.5 ${
                                syncMut.isPending && syncMut.variables === t.id
                                  ? "animate-spin"
                                  : ""
                              }`}
                            />
                          </button>
                          <button
                            onClick={() => setEdit(t)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                            title="Edit"
                            aria-label="Edit"
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(t)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                            title="Delete"
                            aria-label="Delete"
                            {...superadminGate}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {selected && <TargetDetail key={selected.id} target={selected} />}
      </div>

      {showCreate && <TargetModal onClose={() => setShowCreate(false)} />}
      {edit && (
        <FreshEdit
          row={edit}
          queryKeys={[["ddi-mirror-targets"]]}
          title="Edit mirror source"
          onClose={() => setEdit(null)}
        >
          {(fresh) => (
            <TargetModal target={fresh} onClose={() => setEdit(null)} />
          )}
        </FreshEdit>
      )}
      <ConfirmModal
        open={!!del}
        title="Delete mirror source"
        message={
          <>
            Delete <strong>{del?.name}</strong> and its{" "}
            {countNoun(del?.object_count ?? 0, "mirrored object")}? Nothing in
            live IPAM, DNS or DHCP is touched, and nothing is changed on the
            source.
          </>
        }
        confirmLabel="Delete"
        tone="destructive"
        loading={delMut.isPending}
        error={delMut.isError ? errMsg(delMut.error, "Delete failed") : null}
        onConfirm={() => del && delMut.mutate(del.id)}
        onClose={() => {
          delMut.reset();
          setDel(null);
        }}
      />
    </div>
  );
}

// ── Detail: rehearsal / mirror / report ─────────────────────────────

function TargetDetail({ target }: { target: DDIMirrorTarget }) {
  const [tab, setTab] = useState<DetailTab>("rehearsal");
  const tabs: { key: DetailTab; label: string }[] = [
    { key: "rehearsal", label: "Cutover rehearsal" },
    { key: "mirror", label: "Mirrored objects" },
    { key: "report", label: "Last sync report" },
  ];
  return (
    <div className="rounded-lg border">
      <div className="flex items-center gap-1 border-b bg-muted/30 px-3 pt-2">
        <span className="mr-3 text-xs font-semibold">{target.name}</span>
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`rounded-t-md px-3 py-1.5 text-xs ${
              tab === t.key
                ? "border-x border-t bg-card font-medium"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="p-4">
        {tab === "rehearsal" && <RehearsalTab target={target} />}
        {tab === "mirror" && <MirrorTab target={target} />}
        {tab === "report" && <ReportTab target={target} />}
      </div>
    </div>
  );
}

function Pager({
  offset,
  total,
  onChange,
}: {
  offset: number;
  total: number;
  onChange: (o: number) => void;
}) {
  const last = Math.min(offset + PAGE, total);
  return (
    <div className="flex items-center justify-between pt-2 text-[11px] text-muted-foreground">
      <span>
        {total === 0 ? "0" : `${offset + 1}–${last}`} of {total}
      </span>
      <span className="flex gap-1">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - PAGE))}
          className="rounded border px-2 py-0.5 hover:bg-accent disabled:opacity-50"
        >
          Previous
        </button>
        <button
          type="button"
          disabled={offset + PAGE >= total}
          onClick={() => onChange(offset + PAGE)}
          className="rounded border px-2 py-0.5 hover:bg-accent disabled:opacity-50"
        >
          Next
        </button>
      </span>
    </div>
  );
}

function RehearsalTab({ target }: { target: DDIMirrorTarget }) {
  const [kind, setKind] = useState("");
  const [action, setAction] = useState("");
  const [offset, setOffset] = useState(0);
  const { data, isLoading, error } = useQuery({
    queryKey: ["ddi-mirror-rehearsal", target.id, kind, action, offset],
    queryFn: () =>
      ddiMirrorApi.rehearsal(target.id, {
        kind: kind || undefined,
        action: action || undefined,
        limit: PAGE,
        offset,
      }),
  });

  if (error)
    return (
      <FormError className="text-sm text-destructive">
        {errMsg(error, "Could not compute the rehearsal")}
      </FormError>
    );
  if (isLoading || !data)
    return <p className="text-xs text-muted-foreground">Computing…</p>;
  if (data.totals.total === 0)
    return (
      <p className="text-xs text-muted-foreground">
        Nothing is mirrored yet. Run a sync first.
      </p>
    );

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        What importing this mirror into live SpatiumDDI would do, compared with
        what is live right now
        {data.synced_at
          ? ` (mirror as of ${new Date(data.synced_at).toLocaleString()})`
          : ""}
        . Nothing is changed by looking.
      </p>
      <table className="w-full max-w-2xl text-xs">
        <thead>
          <tr className="border-b text-left text-muted-foreground">
            <th className="py-1 font-medium">Kind</th>
            <th className="py-1 text-right font-medium">Mirrored</th>
            <th className="py-1 text-right font-medium">Would create</th>
            <th className="py-1 text-right font-medium">Already live</th>
            <th className="py-1 text-right font-medium">Differs</th>
          </tr>
        </thead>
        <tbody>
          {KINDS.filter((k) => data.kinds[k.key]?.total).map((k) => {
            const c = data.kinds[k.key];
            return (
              <tr key={k.key} className="border-b last:border-0">
                <td className="py-1">{k.label}</td>
                <td className="py-1 text-right tabular-nums">{c.total}</td>
                <td className="py-1 text-right tabular-nums">{c.create}</td>
                <td className="py-1 text-right tabular-nums">{c.exists}</td>
                <td className="py-1 text-right tabular-nums">{c.differs}</td>
              </tr>
            );
          })}
          <tr className="font-medium">
            <td className="py-1">Total</td>
            <td className="py-1 text-right tabular-nums">
              {data.totals.total}
            </td>
            <td className="py-1 text-right tabular-nums">
              {data.totals.create}
            </td>
            <td className="py-1 text-right tabular-nums">
              {data.totals.exists}
            </td>
            <td className="py-1 text-right tabular-nums">
              {data.totals.differs}
            </td>
          </tr>
        </tbody>
      </table>

      <div className="flex flex-wrap gap-3">
        <Field label="Kind">
          <select
            className={inputCls}
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">All kinds</option>
            {KINDS.map((k) => (
              <option key={k.key} value={k.key}>
                {k.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Import would">
          <select
            className={inputCls}
            value={action}
            onChange={(e) => {
              setAction(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">Any</option>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </Field>
      </div>

      {data.items.length === 0 ? (
        <p className="text-xs text-muted-foreground">Nothing matches.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-xs">
            <thead>
              <tr className="border-b text-left text-muted-foreground">
                <th className="py-1 font-medium">Kind</th>
                <th className="py-1 font-medium">Name</th>
                <th className="py-1 font-medium">Value</th>
                <th className="py-1 font-medium">Result</th>
                <th className="py-1 font-medium">Differences</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((i, n) => (
                <tr
                  key={`${i.kind}-${i.name}-${i.value}-${n}`}
                  className="border-b last:border-0 align-top"
                >
                  <td className="py-1 text-muted-foreground">{i.kind}</td>
                  <td className="py-1 font-mono text-[11px]">
                    {i.name}
                    {i.view && (
                      <span className="ml-1 text-muted-foreground">
                        ({i.view})
                      </span>
                    )}
                  </td>
                  <td
                    className="max-w-xs truncate py-1 font-mono text-[11px]"
                    title={i.value}
                  >
                    {i.value}
                  </td>
                  <td className="py-1">
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] ${ACTION_CLS[i.action]}`}
                    >
                      {i.action}
                    </span>
                  </td>
                  <td className="py-1 text-muted-foreground">
                    {i.differences.join("; ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager offset={offset} total={data.total_items} onChange={setOffset} />
    </div>
  );
}

function MirrorTab({ target }: { target: DDIMirrorTarget }) {
  const [kind, setKind] = useState("");
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const { data, isLoading, error } = useQuery({
    queryKey: ["ddi-mirror-objects", target.id, kind, q, offset],
    queryFn: () =>
      ddiMirrorApi.objects(target.id, {
        kind: kind || undefined,
        q: q || undefined,
        limit: PAGE,
        offset,
      }),
  });
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3">
        <Field label="Kind">
          <select
            className={inputCls}
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">All kinds</option>
            {KINDS.map((k) => (
              <option key={k.key} value={k.key}>
                {k.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Search">
          <input
            className={inputCls}
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setOffset(0);
            }}
            placeholder="name, value or comment"
          />
        </Field>
      </div>
      {error ? (
        <FormError className="text-sm text-destructive">
          {errMsg(error, "Could not read the mirror")}
        </FormError>
      ) : isLoading || !data ? (
        <p className="text-xs text-muted-foreground">Loading…</p>
      ) : data.items.length === 0 ? (
        <p className="text-xs text-muted-foreground">No mirrored objects.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-xs">
            <thead>
              <tr className="border-b text-left text-muted-foreground">
                <th className="py-1 font-medium">Kind</th>
                <th className="py-1 font-medium">Name</th>
                <th className="py-1 font-medium">View</th>
                <th className="py-1 font-medium">Value</th>
                <th className="py-1 font-medium">Comment</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((o) => (
                <tr key={o.id} className="border-b last:border-0">
                  <td className="py-1 text-muted-foreground">{o.kind}</td>
                  <td className="py-1 font-mono text-[11px]">{o.name}</td>
                  <td className="py-1 text-muted-foreground">
                    {o.view || "—"}
                  </td>
                  <td
                    className="max-w-xs truncate py-1 font-mono text-[11px]"
                    title={o.value}
                  >
                    {o.value}
                  </td>
                  <td
                    className="max-w-xs truncate py-1 text-muted-foreground"
                    title={o.comment}
                  >
                    {o.comment}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager offset={offset} total={data?.total ?? 0} onChange={setOffset} />
    </div>
  );
}

function ReportTab({ target }: { target: DDIMirrorTarget }) {
  const r = target.last_report;
  if (!r)
    return (
      <p className="text-xs text-muted-foreground">
        No sync has completed yet.
      </p>
    );
  return (
    <div className="space-y-3">
      <table className="w-full max-w-3xl text-xs">
        <thead>
          <tr className="border-b text-left text-muted-foreground">
            <th className="py-1 font-medium">Kind</th>
            <th className="py-1 text-right font-medium">Fetched</th>
            <th className="py-1 text-right font-medium">New</th>
            <th className="py-1 text-right font-medium">Changed</th>
            <th className="py-1 text-right font-medium">Removed</th>
            <th className="py-1 text-right font-medium">Could not map</th>
            <th className="py-1 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {KINDS.filter((k) => r.kinds[k.key]).map((k) => {
            const c = r.kinds[k.key];
            return (
              <tr key={k.key} className="border-b last:border-0">
                <td className="py-1">{k.label}</td>
                <td className="py-1 text-right tabular-nums">{c.fetched}</td>
                <td className="py-1 text-right tabular-nums">{c.created}</td>
                <td className="py-1 text-right tabular-nums">{c.updated}</td>
                <td className="py-1 text-right tabular-nums">{c.deleted}</td>
                <td className="py-1 text-right tabular-nums">{c.unmapped}</td>
                <td className="py-1 text-[11px]">
                  {c.error ? (
                    <span className="text-destructive" title={c.error}>
                      not read: {c.error}
                    </span>
                  ) : !c.complete ? (
                    <span className="text-amber-600">stopped at the cap</span>
                  ) : (
                    <span className="text-muted-foreground">ok</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {r.unmapped_examples.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold">
            Objects that could not be mapped ({r.unmapped_total})
          </h3>
          <ul className="mt-1 list-disc pl-5 font-mono text-[11px] text-muted-foreground">
            {r.unmapped_examples.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ── Create / edit modal ─────────────────────────────────────────────

function TargetModal({
  target,
  onClose,
}: {
  target?: DDIMirrorTarget;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!target;
  const [name, setName] = useState(target?.name ?? "");
  const [description, setDescription] = useState(target?.description ?? "");
  const [enabled, setEnabled] = useState(target?.enabled ?? true);
  const [baseUrl, setBaseUrl] = useState(target?.base_url ?? "");
  const [apiVersion, setApiVersion] = useState(target?.api_version ?? "v2.12");
  const [verifyTls, setVerifyTls] = useState(target?.verify_tls ?? true);
  const [caBundlePem, setCaBundlePem] = useState("");
  const [username, setUsername] = useState(target?.username ?? "");
  const [password, setPassword] = useState("");
  const [networkView, setNetworkView] = useState(target?.network_view ?? "");
  const [dnsView, setDnsView] = useState(target?.dns_view ?? "");
  const [syncInterval, setSyncInterval] = useState(
    String(target?.sync_interval_seconds ?? 900),
  );
  const [error, setError] = useState("");
  const [testResult, setTestResult] = useState<DDIMirrorTestResult | null>(
    null,
  );

  // A moved address or user needs the stored password entered again.
  const reask = useCredentialReask(
    { baseUrl, username },
    target && { baseUrl: target.base_url, username: target.username },
    () => setPassword(""),
  );
  const mustEnter = reask.asks(target?.password_present);

  const testMut = useMutation({
    mutationFn: () =>
      ddiMirrorApi.testConnection({
        target_id: target?.id,
        base_url: baseUrl || undefined,
        api_version: apiVersion,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundlePem || undefined,
        username: username || undefined,
        password: password || undefined,
      }),
    onSuccess: setTestResult,
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        version: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      const interval = Number(syncInterval.trim());
      if (editing) {
        const update: DDIMirrorTargetUpdate = {
          name,
          description,
          enabled,
          base_url: baseUrl,
          api_version: apiVersion,
          verify_tls: verifyTls,
          username,
          network_view: networkView,
          dns_view: dnsView,
          sync_interval_seconds: interval,
        };
        if (caBundlePem) update.ca_bundle_pem = caBundlePem;
        if (password) update.password = password;
        const body = changedFields(target!, update);
        if (Object.keys(body).length === 0) return Promise.resolve(target!);
        return ddiMirrorApi.update(target!.id, body);
      }
      const create: DDIMirrorTargetCreate = {
        name,
        description,
        enabled,
        vendor: "infoblox",
        base_url: baseUrl,
        api_version: apiVersion,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundlePem,
        username,
        password,
        network_view: networkView,
        dns_view: dnsView,
        sync_interval_seconds: interval,
      };
      return ddiMirrorApi.create(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ddi-mirror-targets"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save the source")),
  });

  return (
    <Modal
      title={editing ? "Edit mirror source" : "Add mirror source"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const intervalError = secondsFieldError(
            "Sync interval",
            syncInterval,
            {
              min: 60,
            },
          );
          if (intervalError) {
            setError(intervalError);
            return;
          }
          setError("");
          saveMut.mutate();
        }}
        className="space-y-3"
      >
        <p className="rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
          Infoblox NIOS over its WAPI. Use a dedicated account with read-only
          permissions (the mirror only issues GET requests). Pulls are paged and
          sequential; the default interval is 15 minutes.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </Field>
          <label className="flex cursor-pointer items-center gap-2 pt-6 text-sm">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>Enabled</span>
          </label>
        </div>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <Field
              label="Grid master URL"
              hint="https:// and the host, plus a port if not 443. No path."
            >
              <input
                className={`${inputCls} font-mono text-[11px]`}
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://gm.your-domain"
                required
              />
            </Field>
          </div>
          <Field label="WAPI version">
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={apiVersion}
              onChange={(e) => setApiVersion(e.target.value)}
              required
            />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Username">
            <input
              className={inputCls}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </Field>
          <Field label="Password" hint={mustEnter ? reask.hint : undefined}>
            <input
              type="password"
              className={inputCls}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={
                mustEnter
                  ? reask.placeholder
                  : editing && target?.password_present
                    ? "••• stored — enter to replace"
                    : "password"
              }
              required={!editing || mustEnter}
            />
          </Field>
        </div>
        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={verifyTls}
            onChange={(e) => setVerifyTls(e.target.checked)}
            className="mt-0.5"
          />
          <div>
            <span>Verify TLS certificate</span>
            <p className="text-[11px] text-muted-foreground/70">
              On by default. Uncheck only for a self-signed lab grid, or paste
              the CA bundle below and leave this on.
            </p>
          </div>
        </label>
        <Field label="CA bundle (PEM, optional)">
          <textarea
            className={`${inputCls} font-mono text-[11px]`}
            rows={3}
            value={caBundlePem}
            onChange={(e) => setCaBundlePem(e.target.value)}
            placeholder={
              editing && target?.ca_bundle_present
                ? "••• stored — paste to replace"
                : "-----BEGIN CERTIFICATE-----"
            }
          />
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Network view" hint="Blank mirrors every view.">
            <input
              className={inputCls}
              value={networkView}
              onChange={(e) => setNetworkView(e.target.value)}
            />
          </Field>
          <Field label="DNS view" hint="Blank mirrors every view.">
            <input
              className={inputCls}
              value={dnsView}
              onChange={(e) => setDnsView(e.target.value)}
            />
          </Field>
          <Field label="Sync interval (s)">
            <input
              className={inputCls}
              value={syncInterval}
              onChange={(e) => setSyncInterval(e.target.value)}
              inputMode="numeric"
            />
          </Field>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !baseUrl || !username}
            className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            <TestTube2 className="h-3.5 w-3.5" />
            {testMut.isPending ? "Testing…" : "Test Connection"}
          </button>
          {testResult && (
            <span
              role={testResult.ok ? undefined : "alert"}
              className={`text-xs ${
                testResult.ok
                  ? "text-emerald-600 dark:text-emerald-400"
                  : "text-destructive"
              }`}
            >
              {testResult.ok ? "✓" : "✗"} {testResult.message}
            </span>
          )}
        </div>

        {error && (
          <FormError className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </FormError>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saveMut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : editing ? "Save" : "Add"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
