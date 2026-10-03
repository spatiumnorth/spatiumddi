/**
 * InfluxDB push-export target manager (issue #889).
 *
 * SpatiumDDI is the writer here — a Celery beat task formats line
 * protocol from the existing metric tables and POSTs it on each
 * target's own interval. Nothing is read back, so the row's health is
 * whatever the last push reported.
 *
 * Three versions, two forms: v1 shows database + username/password, v2
 * and v3 show org/bucket + token. v3 is InfluxDB 3 over the v2 write
 * endpoint (a v3 *database* goes in the bucket field), which is why the
 * label changes rather than the field.
 *
 * "Test" performs a real single-point write instead of a reachability
 * check: a correct URL with the wrong bucket, org or token answers a
 * GET perfectly well and then rejects every point.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Pencil, Play, Plus, Trash2, X } from "lucide-react";

import { Modal } from "@/components/ui/modal";
import { ListReadError } from "@/components/ui/list-read-error";
import { pollUnlessRefused } from "@/lib/refusal";
import {
  settingsApi,
  type InfluxDBTarget,
  type InfluxDBTargetWrite,
  type InfluxDBVersion,
} from "@/lib/api";

const inputCls =
  "w-full rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50";

const VERSION_LABELS: Record<InfluxDBVersion, string> = {
  v1: "v1.x — /write, basic auth",
  v2: "v2.x — /api/v2/write, token auth",
  v3: "v3 (Core / Enterprise / Cloud) — v2 endpoint, bearer token",
};

// The beat tick is 30 s, so a shorter interval can't be honoured. The
// real data floor is the 60 s agent metric bucket regardless.
const MIN_INTERVAL_SECONDS = 30;

const EMPTY: InfluxDBTargetWrite = {
  name: "",
  enabled: true,
  version: "v2",
  url: "",
  verify_tls: true,
  timeout_seconds: 10,
  database: "",
  username: "",
  password: null,
  org: "",
  bucket: "",
  token: null,
  measurement_prefix: "spatiumddi_",
  push_interval_seconds: 60,
  push_dns_metrics: true,
  push_dhcp_metrics: true,
  push_subnet_utilization: true,
  push_dhcp_scope_leases: true,
};

function targetToBody(t: InfluxDBTarget): InfluxDBTargetWrite {
  return {
    name: t.name,
    enabled: t.enabled,
    version: t.version,
    url: t.url,
    verify_tls: t.verify_tls,
    timeout_seconds: t.timeout_seconds,
    database: t.database,
    username: t.username,
    // Secrets are write-only — the server returns booleans only.
    // ``null`` means "leave what is stored alone".
    password: null,
    org: t.org,
    bucket: t.bucket,
    token: null,
    measurement_prefix: t.measurement_prefix,
    push_interval_seconds: t.push_interval_seconds,
    push_dns_metrics: t.push_dns_metrics,
    push_dhcp_metrics: t.push_dhcp_metrics,
    push_subnet_utilization: t.push_subnet_utilization,
    push_dhcp_scope_leases: t.push_dhcp_scope_leases,
  };
}

function errorDetail(e: unknown, fallback: string): string {
  if (e && typeof e === "object" && "response" in e) {
    const resp = (e as { response?: { data?: { detail?: unknown } } }).response;
    if (resp?.data?.detail) return String(resp.data.detail);
  }
  return fallback;
}

function relativeTime(iso: string | null): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "never";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

export function InfluxDBTargets({ isSuperadmin }: { isSuperadmin: boolean }) {
  const qc = useQueryClient();
  const {
    data: targets = [],
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["influxdb-targets"],
    queryFn: settingsApi.listInfluxTargets,
    // The row carries last-push state written by a beat task, so it goes
    // stale on its own; refresh while the page is open, unless the read
    // was refused (#1343).
    refetchInterval: pollUnlessRefused(30000),
  });

  const [editing, setEditing] = useState<
    { mode: "create" } | { mode: "edit"; row: InfluxDBTarget } | null
  >(null);
  const [confirmDelete, setConfirmDelete] = useState<InfluxDBTarget | null>(
    null,
  );
  const [testState, setTestState] = useState<
    Record<string, { status: "ok" | "error"; msg: string } | undefined>
  >({});

  const deleteMut = useMutation({
    mutationFn: (id: string) => settingsApi.deleteInfluxTarget(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["influxdb-targets"] });
      setConfirmDelete(null);
    },
  });

  async function doTest(id: string) {
    try {
      const r = await settingsApi.testInfluxTarget(id);
      setTestState((s) => ({
        ...s,
        [id]: { status: r.ok ? "ok" : "error", msg: r.message },
      }));
    } catch (e) {
      setTestState((s) => ({
        ...s,
        [id]: { status: "error", msg: errorDetail(e, "test write failed") },
      }));
    }
    window.setTimeout(() => {
      setTestState((s) => {
        const { [id]: _unused, ...rest } = s;
        return rest;
      });
    }, 8000);
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-2xl text-xs text-muted-foreground">
          Each enabled target receives DNS + DHCP counter deltas and, if
          selected, point-in-time IPAM utilization and per-scope lease gauges,
          as InfluxDB line protocol. Counter deltas carry the 60&nbsp;s agent
          bucket's own timestamp — that bucket, not the push interval, is the
          resolution floor.
        </div>
        {isSuperadmin && (
          <button
            type="button"
            onClick={() => setEditing({ mode: "create" })}
            className="inline-flex flex-shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md border bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
          >
            <Plus className="h-3.5 w-3.5" /> Add Target
          </button>
        )}
      </div>

      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[860px] text-xs">
          <thead className="bg-muted/40 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="whitespace-nowrap px-3 py-2 font-medium">Name</th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Version
              </th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Destination
              </th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Carries
              </th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Last push
              </th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Status
              </th>
              <th className="whitespace-nowrap px-3 py-2 text-right font-medium">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-3 py-4 text-center text-muted-foreground"
                >
                  Loading…
                </td>
              </tr>
            ) : targets.length === 0 ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  {/* A refused or failed read is not an empty list (#1343). */}
                  {isError ? (
                    <ListReadError error={error} what="the InfluxDB targets" />
                  ) : (
                    "No InfluxDB targets configured."
                  )}
                </td>
              </tr>
            ) : (
              targets.map((t) => {
                const dest =
                  t.version === "v1"
                    ? `${t.url || "?"} · db=${t.database || "?"}`
                    : `${t.url || "?"} · ${t.version === "v3" ? "database" : "bucket"}=${t.bucket || "?"}`;
                const carries = [
                  t.push_dns_metrics ? "dns" : null,
                  t.push_dhcp_metrics ? "dhcp" : null,
                  t.push_subnet_utilization ? "ipam" : null,
                  t.push_dhcp_scope_leases ? "leases" : null,
                ]
                  .filter(Boolean)
                  .join(" · ");
                const ts = testState[t.id];
                return (
                  <tr key={t.id}>
                    <td className="whitespace-nowrap px-3 py-2 font-medium">
                      {t.name}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">{t.version}</td>
                    <td className="break-all px-3 py-2 font-mono text-[11px]">
                      {dest}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                      {carries || "nothing selected"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                      {relativeTime(t.last_push_at)}
                      {t.last_push_at && (
                        <span className="ml-1 text-[11px]">
                          ({t.last_push_points} pts)
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {!t.enabled ? (
                        <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                          disabled
                        </span>
                      ) : t.last_push_error ? (
                        <span
                          className="inline-flex items-center gap-1 rounded bg-red-500/15 px-1.5 py-0.5 text-[11px] text-red-600"
                          title={t.last_push_error}
                        >
                          <X className="h-3 w-3" /> push failing
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-[11px] font-medium text-emerald-600">
                          <Check className="h-3 w-3" /> enabled
                        </span>
                      )}
                      {ts && (
                        <span
                          className={
                            "ml-2 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] " +
                            (ts.status === "ok"
                              ? "bg-emerald-500/15 text-emerald-600"
                              : "bg-red-500/15 text-red-600")
                          }
                        >
                          {ts.status === "ok" ? (
                            <Check className="h-3 w-3" />
                          ) : (
                            <X className="h-3 w-3" />
                          )}
                          {ts.msg}
                        </span>
                      )}
                      {t.enabled && t.last_push_error && (
                        <div className="mt-1 max-w-md break-all text-[11px] text-red-600">
                          {t.last_push_error}
                        </div>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                      <div className="inline-flex items-center gap-1">
                        {isSuperadmin && (
                          <>
                            <button
                              type="button"
                              onClick={() => doTest(t.id)}
                              title="Write one synthetic point to this target"
                              className="rounded p-1 hover:bg-accent"
                            >
                              <Play className="h-3.5 w-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                setEditing({ mode: "edit", row: t })
                              }
                              title="Edit"
                              className="rounded p-1 hover:bg-accent"
                            >
                              <Pencil className="h-3.5 w-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmDelete(t)}
                              title="Delete"
                              className="rounded p-1 text-destructive hover:bg-destructive/10"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {editing && (
        <InfluxTargetModal
          initial={
            editing.mode === "create" ? EMPTY : targetToBody(editing.row)
          }
          existingId={editing.mode === "edit" ? editing.row.id : undefined}
          passwordSet={
            editing.mode === "edit" ? editing.row.password_set : false
          }
          tokenSet={editing.mode === "edit" ? editing.row.token_set : false}
          onClose={() => setEditing(null)}
        />
      )}

      {confirmDelete && (
        <Modal
          title={`Delete "${confirmDelete.name}"?`}
          onClose={() => setConfirmDelete(null)}
        >
          <p className="text-sm text-muted-foreground">
            Metrics stop being exported to this destination. Points already
            written to InfluxDB are not removed.
          </p>
          <div className="mt-4 flex justify-end gap-2">
            <button
              onClick={() => setConfirmDelete(null)}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
            >
              Cancel
            </button>
            <button
              onClick={() => deleteMut.mutate(confirmDelete.id)}
              disabled={deleteMut.isPending}
              className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:opacity-90 disabled:opacity-50"
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function InfluxTargetModal({
  initial,
  existingId,
  passwordSet,
  tokenSet,
  onClose,
}: {
  initial: InfluxDBTargetWrite;
  existingId?: string;
  passwordSet: boolean;
  tokenSet: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [form, setForm] = useState<InfluxDBTargetWrite>(initial);
  const [error, setError] = useState<string | null>(null);

  const saveMut = useMutation({
    mutationFn: async () => {
      const body: InfluxDBTargetWrite = { ...form };
      // ``null`` (the default on edit) means "keep the stored secret";
      // the server reads an absent key the same way, so drop it rather
      // than sending a null the operator never chose.
      if (body.password === null) delete body.password;
      if (body.token === null) delete body.token;
      if (existingId) return settingsApi.updateInfluxTarget(existingId, body);
      return settingsApi.createInfluxTarget(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["influxdb-targets"] });
      onClose();
    },
    onError: (e: unknown) => setError(errorDetail(e, "Save failed")),
  });

  const isV1 = form.version === "v1";
  // v3 reuses v2's bucket parameter, but an InfluxDB 3 operator knows
  // the value as a database name.
  const bucketLabel = form.version === "v3" ? "Database" : "Bucket";

  return (
    <Modal
      title={existingId ? `Edit "${initial.name}"` : "Add InfluxDB Target"}
      onClose={onClose}
      wide
    >
      <div className="space-y-3">
        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-400">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Name
            </div>
            <input
              className={inputCls}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Grafana prod"
            />
          </label>
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Enabled
            </div>
            <select
              className={inputCls}
              value={form.enabled ? "1" : "0"}
              onChange={(e) =>
                setForm({ ...form, enabled: e.target.value === "1" })
              }
            >
              <option value="1">Enabled</option>
              <option value="0">Disabled</option>
            </select>
          </label>
        </div>

        <label className="block">
          <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Version
          </div>
          <select
            className={inputCls}
            value={form.version}
            onChange={(e) =>
              setForm({ ...form, version: e.target.value as InfluxDBVersion })
            }
          >
            {Object.entries(VERSION_LABELS).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </label>

        <label className="block">
          <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Base URL
          </div>
          <input
            className={inputCls}
            value={form.url}
            onChange={(e) => setForm({ ...form, url: e.target.value })}
            placeholder="http://influxdb:8086"
          />
          <p className="mt-1 text-[11px] text-muted-foreground">
            Base URL only — the write path is appended for you.
          </p>
        </label>

        {isV1 ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Database
              </div>
              <input
                className={inputCls}
                value={form.database}
                onChange={(e) => setForm({ ...form, database: e.target.value })}
                placeholder="spatiumddi"
              />
            </label>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Username
              </div>
              <input
                className={inputCls}
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                placeholder="(blank if unauthenticated)"
              />
            </label>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Password
              </div>
              <input
                type="password"
                className={inputCls}
                value={form.password ?? ""}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                placeholder={
                  passwordSet ? "(stored — leave blank to keep)" : "Password"
                }
              />
            </label>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Org
              </div>
              <input
                className={inputCls}
                value={form.org}
                onChange={(e) => setForm({ ...form, org: e.target.value })}
                placeholder={
                  form.version === "v3" ? "(optional on v3)" : "my-org"
                }
              />
            </label>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                {bucketLabel}
              </div>
              <input
                className={inputCls}
                value={form.bucket}
                onChange={(e) => setForm({ ...form, bucket: e.target.value })}
                placeholder="spatiumddi"
              />
            </label>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Token
              </div>
              <input
                type="password"
                className={inputCls}
                value={form.token ?? ""}
                onChange={(e) => setForm({ ...form, token: e.target.value })}
                placeholder={
                  tokenSet ? "(stored — leave blank to keep)" : "API token"
                }
              />
            </label>
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Measurement prefix
            </div>
            <input
              className={inputCls}
              value={form.measurement_prefix}
              onChange={(e) =>
                setForm({ ...form, measurement_prefix: e.target.value })
              }
              placeholder="spatiumddi_"
            />
          </label>
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Push interval (s)
            </div>
            <input
              type="number"
              min={MIN_INTERVAL_SECONDS}
              max={86400}
              className={inputCls}
              value={form.push_interval_seconds}
              onChange={(e) =>
                setForm({
                  ...form,
                  push_interval_seconds: Number(e.target.value),
                })
              }
            />
          </label>
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Timeout (s)
            </div>
            <input
              type="number"
              min={1}
              max={120}
              className={inputCls}
              value={form.timeout_seconds}
              onChange={(e) =>
                setForm({ ...form, timeout_seconds: Number(e.target.value) })
              }
            />
          </label>
        </div>

        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={form.verify_tls}
            onChange={(e) => setForm({ ...form, verify_tls: e.target.checked })}
          />
          Verify TLS certificate (uncheck only for a private CA you cannot
          install)
        </label>

        <div className="rounded-md border p-3">
          <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            What this target carries
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {(
              [
                [
                  "push_dns_metrics",
                  "DNS query counters (per server, 60 s buckets)",
                ],
                [
                  "push_dhcp_metrics",
                  "DHCP message counters (per server, 60 s buckets)",
                ],
                [
                  "push_subnet_utilization",
                  "Subnet utilization gauge (sampled at push time)",
                ],
                [
                  "push_dhcp_scope_leases",
                  "Active leases per DHCP scope (sampled at push time)",
                ],
              ] as const
            ).map(([key, label]) => (
              <label key={key} className="flex items-center gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={form[key]}
                  onChange={(e) =>
                    setForm({ ...form, [key]: e.target.checked })
                  }
                />
                {label}
              </label>
            ))}
          </div>
        </div>

        <div className="flex justify-end gap-2 border-t pt-3">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => saveMut.mutate()}
            disabled={saveMut.isPending || !form.name || !form.url}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : existingId ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}
