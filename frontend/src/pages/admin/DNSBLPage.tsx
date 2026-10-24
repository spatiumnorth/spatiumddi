import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Check,
  Plus,
  Power,
  RefreshCw,
  ShieldAlert,
  Trash2,
} from "lucide-react";

import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import {
  dnsblApi,
  type DNSBLList,
  type DNSBLPinnedIP,
  type DNSBLSettings,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { Toggle } from "@/components/ui/toggle";
import { ConfirmModal } from "@/components/ui/confirm-modal";

const inputCls =
  "rounded-md border bg-background px-2 py-1 text-sm outline-none focus:ring-1 focus:ring-ring";

export function DNSBLPage() {
  const qc = useQueryClient();
  // The router takes `require_resource_permission("dnsbl")`: write for the
  // pin / enable / sweep-settings writes, delete for unpin and deleting a
  // custom list. Gate each on the grant the route checks (#2698), not on
  // superadmin: the built-in Network Editor holds admin on `dnsbl`.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "dnsbl"),
    "Requires write on DNS blocklists",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "dnsbl"),
    "Requires delete on DNS blocklists",
  );
  const canWrite = !writeGate.disabled;

  const { data: lists = [], isLoading: listsLoading } = useQuery({
    queryKey: ["dnsbl-lists"],
    queryFn: dnsblApi.listLists,
  });
  const { data: pinned = [] } = useQuery({
    queryKey: ["dnsbl-pinned"],
    queryFn: dnsblApi.listPinned,
  });
  const { data: settings } = useQuery({
    queryKey: ["dnsbl-settings"],
    queryFn: dnsblApi.getSettings,
  });
  const { data: listings } = useQuery({
    queryKey: ["dnsbl-listings"],
    queryFn: () => dnsblApi.listListings({ listed_only: true, limit: 100 }),
  });

  const toggleList = useMutation({
    mutationFn: (l: DNSBLList) =>
      dnsblApi.updateList(l.id, { enabled: !l.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dnsbl-lists"] }),
  });
  const deleteList = useMutation({
    mutationFn: (id: string) => dnsblApi.deleteList(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dnsbl-lists"] }),
  });
  const saveSettings = useMutation({
    mutationFn: (data: Partial<DNSBLSettings>) => dnsblApi.updateSettings(data),
    onSuccess: (updated) => {
      qc.setQueryData(["dnsbl-settings"], updated);
    },
  });
  const addPinned = useMutation({
    mutationFn: (data: { ip: string; note?: string }) =>
      dnsblApi.addPinned(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dnsbl-pinned"] });
      setNewIp("");
      setNewNote("");
      setPinError(null);
    },
    onError: (err: unknown) => {
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      setPinError(typeof detail === "string" ? detail : "Failed to pin IP");
    },
  });
  const deletePinned = useMutation({
    mutationFn: (id: string) => dnsblApi.deletePinned(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dnsbl-pinned"] }),
  });

  const [newIp, setNewIp] = useState("");
  const [newNote, setNewNote] = useState("");
  const [pinError, setPinError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<DNSBLList | null>(null);
  const [confirmUnpin, setConfirmUnpin] = useState<DNSBLPinnedIP | null>(null);

  const enabledCount = lists.filter((l) => l.enabled).length;
  const listedCount = listings?.total ?? 0;

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
            <ShieldAlert className="h-6 w-6" /> DNS Blocklists (DNSBL / RBL)
          </h1>
          <p className="mt-1 text-xs text-muted-foreground">
            Check every public-facing IP (public IPAM addresses, internet-facing
            subnets, NAT/PAT egress, pinned IPs) against the major DNS
            blocklists on a daily reversed-octet sweep. IPv4 only.
          </p>
        </div>
      </div>

      {/* Sweep settings */}
      <section className="rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">Sweep settings</h2>
        <div className="space-y-3">
          <label className="flex items-center justify-between gap-4">
            <div>
              <div className="text-sm font-medium">Enable daily sweep</div>
              <div className="text-xs text-muted-foreground">
                Master switch. No external DNS queries run until this is on and
                at least one list is enabled below.
              </div>
            </div>
            <Toggle
              label="Enable daily DNSBL sweep"
              checked={!!settings?.dnsbl_monitoring_enabled}
              disabled={!canWrite || saveSettings.isPending}
              title={writeGate.title}
              onChange={(v) =>
                saveSettings.mutate({ dnsbl_monitoring_enabled: v })
              }
            />
          </label>
          <label className="flex items-center justify-between gap-4">
            <div>
              <div className="text-sm font-medium">Sweep interval (hours)</div>
              <div className="text-xs text-muted-foreground">
                Beat fires daily; this bounds re-check cadence (6–168).
              </div>
            </div>
            <input
              type="number"
              min={6}
              max={168}
              className={cn(inputCls, "w-24")}
              defaultValue={settings?.dnsbl_check_interval_hours ?? 24}
              {...writeGate}
              onBlur={(e) =>
                saveSettings.mutate({
                  dnsbl_check_interval_hours: Number(e.target.value),
                })
              }
            />
          </label>
          <div className="flex items-center justify-between gap-4">
            <div className="text-sm font-medium">Last sweep</div>
            <span className="rounded bg-muted px-2 py-1 text-xs font-mono text-muted-foreground">
              {settings?.dnsbl_sweep_last_run_at
                ? new Date(settings.dnsbl_sweep_last_run_at).toLocaleString()
                : "never"}
            </span>
          </div>
          <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
            <span>{enabledCount} list(s) enabled</span>
            <span
              className={cn(listedCount > 0 && "font-medium text-rose-600")}
            >
              {listedCount} IP-listing(s) currently active
            </span>
          </div>
        </div>
      </section>

      {/* Blocklisted IPs overview */}
      {listedCount > 0 && (
        <section className="rounded-lg border p-4">
          <h2 className="mb-3 flex items-center gap-1 text-sm font-semibold text-rose-600">
            <AlertTriangle className="h-4 w-4" /> Blocklisted IPs
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[600px] text-sm">
              <thead className="text-xs uppercase tracking-wider text-muted-foreground">
                <tr className="border-b">
                  <th className="px-2 py-1 text-left">IP</th>
                  <th className="px-2 py-1 text-left">List</th>
                  <th className="px-2 py-1 text-left">Source</th>
                  <th className="px-2 py-1 text-left">Codes</th>
                  <th className="px-2 py-1 text-left">Since</th>
                </tr>
              </thead>
              <tbody>
                {(listings?.items ?? []).map((it) => (
                  <tr key={it.id} className="border-b">
                    <td className="px-2 py-1 font-mono">{it.ip}</td>
                    <td className="px-2 py-1">{it.list_name}</td>
                    <td className="px-2 py-1 text-muted-foreground">
                      {it.source}
                    </td>
                    <td className="px-2 py-1 font-mono text-xs">
                      {it.return_codes.join(", ")}
                    </td>
                    <td className="px-2 py-1 text-xs text-muted-foreground">
                      {it.first_listed_at
                        ? new Date(it.first_listed_at).toLocaleDateString()
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Pinned IPs */}
      <section className="rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">Pinned IPs</h2>
        <p className="mb-2 text-xs text-muted-foreground">
          Always monitor these IPs on top of the auto-derived candidate set.
        </p>
        <div className="mb-3 flex flex-wrap items-end gap-2">
          <input
            className={cn(inputCls, "w-40")}
            placeholder="203.0.113.5"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            {...writeGate}
          />
          <input
            className={cn(inputCls, "flex-1")}
            placeholder="note (optional)"
            value={newNote}
            onChange={(e) => setNewNote(e.target.value)}
            {...writeGate}
          />
          <button
            type="button"
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60"
            disabled={!canWrite || !newIp.trim() || addPinned.isPending}
            title={writeGate.title}
            onClick={() =>
              addPinned.mutate({ ip: newIp.trim(), note: newNote.trim() })
            }
          >
            <Plus className="h-3.5 w-3.5" /> Pin
          </button>
        </div>
        {pinError && (
          <div className="mb-2 text-xs text-rose-600">{pinError}</div>
        )}
        <ul className="divide-y rounded border text-sm">
          {pinned.length === 0 && (
            <li className="px-2 py-2 text-xs text-muted-foreground">
              No pinned IPs.
            </li>
          )}
          {pinned.map((p) => (
            <li
              key={p.id}
              className="flex items-center justify-between gap-2 px-2 py-1.5"
            >
              <div className="min-w-0">
                <span className="font-mono">{p.ip}</span>
                {p.note && (
                  <span className="ml-2 text-xs text-muted-foreground">
                    {p.note}
                  </span>
                )}
              </div>
              <button
                type="button"
                className="rounded p-1.5 hover:bg-accent"
                title="Unpin"
                {...deleteGate}
                onClick={() => setConfirmUnpin(p)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </li>
          ))}
        </ul>
      </section>

      {/* Catalog */}
      <section className="rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">Blocklist catalog</h2>
        {listsLoading ? (
          <div className="text-sm text-muted-foreground">Loading…</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead className="text-xs uppercase tracking-wider text-muted-foreground">
                <tr className="border-b">
                  <th className="px-2 py-1 text-left">List</th>
                  <th className="px-2 py-1 text-left">Zone suffix</th>
                  <th className="px-2 py-1 text-left">Category</th>
                  <th className="px-2 py-1 text-left">Policy</th>
                  <th className="px-2 py-1 text-left">Status</th>
                  <th className="px-2 py-1" />
                </tr>
              </thead>
              <tbody>
                {lists.map((l) => (
                  <tr key={l.id} className="border-b align-top">
                    <td className="px-2 py-1.5">
                      <div className="font-medium">{l.name}</div>
                      <div className="max-w-md text-xs text-muted-foreground">
                        {l.description}
                      </div>
                    </td>
                    <td className="px-2 py-1.5 font-mono text-xs">
                      {l.zone_suffix}
                    </td>
                    <td className="px-2 py-1.5 text-xs">{l.category}</td>
                    <td className="px-2 py-1.5">
                      {l.requires_registration && (
                        <span className="mb-1 inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600">
                          <AlertTriangle className="h-3 w-3" /> registration
                        </span>
                      )}
                      {l.qps_note && (
                        <div className="max-w-xs text-[11px] text-muted-foreground">
                          {l.qps_note}
                        </div>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      {l.enabled ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-600">
                          <Check className="h-3.5 w-3.5" /> enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                          <Power className="h-3.5 w-3.5" /> disabled
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      <div className="flex justify-end gap-1">
                        <button
                          type="button"
                          className="rounded p-1.5 hover:bg-accent"
                          title={l.enabled ? "Disable" : "Enable"}
                          disabled={!canWrite || toggleList.isPending}
                          {...(canWrite ? {} : { title: writeGate.title })}
                          onClick={() => toggleList.mutate(l)}
                        >
                          {toggleList.isPending &&
                          toggleList.variables?.id === l.id ? (
                            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Power className="h-3.5 w-3.5" />
                          )}
                        </button>
                        {!l.is_builtin && (
                          <button
                            type="button"
                            className="rounded p-1.5 hover:bg-accent"
                            title="Delete custom list"
                            {...deleteGate}
                            onClick={() => setConfirmDelete(l)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {confirmDelete && (
        <ConfirmModal
          open
          title="Delete blocklist"
          message={`Delete the custom list "${confirmDelete.name}"? This removes its listing history.`}
          confirmLabel="Delete"
          tone="destructive"
          onClose={() => setConfirmDelete(null)}
          onConfirm={() => {
            deleteList.mutate(confirmDelete.id);
            setConfirmDelete(null);
          }}
        />
      )}
      {confirmUnpin && (
        <ConfirmModal
          open
          title="Unpin IP"
          message={`Stop monitoring ${confirmUnpin.ip}?`}
          confirmLabel="Unpin"
          tone="destructive"
          onClose={() => setConfirmUnpin(null)}
          onConfirm={() => {
            deletePinned.mutate(confirmUnpin.id);
            setConfirmUnpin(null);
          }}
        />
      )}
    </div>
  );
}
