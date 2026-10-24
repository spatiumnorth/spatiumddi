import { poolDeleteSummary } from "@/lib/pool-delete-copy";
import { useState } from "react";
import { humanTime } from "../network/_shared";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  ExternalLink,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import {
  dnsApi,
  type DNSPoolListEntry,
  type DNSServerGroup,
  type DNSZone,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import { useStickyLocation } from "@/lib/stickyLocation";
import { PoolModal } from "./PoolsView";

/**
 * Top-level DNS Pools admin page (sidebar entry under DNS).
 *
 * Lists every health-checked pool across every zone in one table.
 * Operators creating a new pool from this page get a small "Pick
 * server group + zone" picker before the full PoolModal opens —
 * scoping the pool to a zone is required because pools render
 * regular ``DNSRecord`` rows in that zone.
 *
 * For in-context management of one zone's pools, the zone-detail
 * page also has a Pools sub-tab (``PoolsView``). Both surfaces share
 * ``PoolModal``.
 */
export function DNSPoolsPage() {
  useStickyLocation("spatium.lastUrl.dnsPools");
  const qc = useQueryClient();
  const nav = useNavigate();
  // Every pool write takes a superadmin (dns/pool_router.py): create, edit,
  // delete and check-now all carry the SuperAdmin dependency (#1879).
  const poolGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );

  const [showPicker, setShowPicker] = useState(false);
  const [createCtx, setCreateCtx] = useState<{
    group: DNSServerGroup;
    zone: DNSZone;
  } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<DNSPoolListEntry | null>(
    null,
  );

  const { data: pools = [], isFetching } = useQuery({
    queryKey: ["dns-pools-all"],
    queryFn: () => dnsApi.listAllPools(),
    refetchInterval: 30_000,
  });

  const checkNow = useMutation({
    mutationFn: (poolId: string) => dnsApi.checkPoolNow(poolId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-pools-all"] }),
  });

  const del = useMutation({
    mutationFn: (poolId: string) => dnsApi.deletePool(poolId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-pools-all"] });
      qc.invalidateQueries({ queryKey: ["dns-pools"] });
      qc.invalidateQueries({ queryKey: ["dns-records"] });
      setConfirmDelete(null);
    },
  });

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b px-6 py-4">
        <div>
          <h1 className="text-lg font-semibold">DNS Pools</h1>
          <p className="text-xs text-muted-foreground">
            Health-checked pools of A / AAAA targets. Members render as regular
            records that flip in/out of the rendered set on health change.{" "}
            <strong>Not a real load balancer</strong> — clients still cache the
            records for the pool&apos;s TTL.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowPicker(true)}
          className="flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
          {...poolGate}
        >
          <Plus className="h-3 w-3" /> New Pool
        </button>
      </div>

      <div className="flex-1 overflow-auto p-6">
        {isFetching && pools.length === 0 && (
          <p className="text-sm text-muted-foreground">Loading…</p>
        )}
        {!isFetching && pools.length === 0 && (
          <div className="flex flex-col items-center justify-center rounded-md border border-dashed bg-card py-16 text-center">
            <p className="text-sm text-muted-foreground">No DNS pools yet.</p>
            <p className="mt-1 max-w-md text-xs text-muted-foreground">
              A pool maps one DNS name (e.g.{" "}
              <code className="font-mono">www.example.com</code>) to a set of
              target IPs with health checks. Click <em>New Pool</em> to create
              one.
            </p>
          </div>
        )}
        {pools.length > 0 && (
          <div className="overflow-hidden rounded-md border bg-card">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/30 text-xs">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Pool</th>
                  <th className="px-3 py-2 text-left font-medium">FQDN</th>
                  <th className="px-3 py-2 text-left font-medium">Group</th>
                  <th className="px-3 py-2 text-left font-medium">Type</th>
                  <th className="px-3 py-2 text-left font-medium">Check</th>
                  <th className="px-3 py-2 text-left font-medium">Health</th>
                  <th className="px-3 py-2 text-right font-medium">TTL</th>
                  <th className="px-3 py-2 text-right font-medium">
                    Last check
                  </th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {pools.map((p) => (
                  <PoolRow
                    key={p.id}
                    pool={p}
                    gate={poolGate}
                    onCheckNow={() => checkNow.mutate(p.id)}
                    onOpen={() =>
                      nav(
                        `/dns?group=${p.group_id}&zone=${p.zone_id}&subtab=pools`,
                      )
                    }
                    onDelete={() => setConfirmDelete(p)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showPicker && (
        <PickGroupZoneModal
          onPick={(g, z) => {
            setShowPicker(false);
            setCreateCtx({ group: g, zone: z });
          }}
          onClose={() => setShowPicker(false)}
        />
      )}
      {createCtx && (
        <PoolModal
          group={createCtx.group}
          zone={createCtx.zone}
          onClose={() => {
            setCreateCtx(null);
            qc.invalidateQueries({ queryKey: ["dns-pools-all"] });
          }}
        />
      )}
      {confirmDelete && (
        <ConfirmDeleteModal
          pool={confirmDelete}
          onConfirm={() => del.mutate(confirmDelete.id)}
          onClose={() => setConfirmDelete(null)}
          pending={del.isPending}
        />
      )}
    </div>
  );
}

function PoolRow({
  pool,
  gate,
  onCheckNow,
  onOpen,
  onDelete,
}: {
  pool: DNSPoolListEntry;
  gate: { disabled?: boolean; title?: string };
  onCheckNow: () => void;
  onOpen: () => void;
  onDelete: () => void;
}) {
  const fqdn =
    pool.record_name === "@"
      ? pool.zone_name.replace(/\.$/, "")
      : `${pool.record_name}.${pool.zone_name.replace(/\.$/, "")}`;
  const allHealthy =
    pool.member_count > 0 && pool.healthy_count === pool.member_count;
  const someHealthy = pool.healthy_count > 0;
  const healthIcon = !pool.member_count ? (
    <Clock className="h-3.5 w-3.5 text-muted-foreground" />
  ) : allHealthy ? (
    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
  ) : someHealthy ? (
    <AlertCircle className="h-3.5 w-3.5 text-amber-500" />
  ) : (
    <AlertCircle className="h-3.5 w-3.5 text-red-500" />
  );
  return (
    <tr className="border-b last:border-0 hover:bg-muted/40">
      <td className="px-3 py-2">
        <button
          type="button"
          onClick={onOpen}
          className="font-medium hover:text-primary hover:underline"
          title="Open zone Pools tab"
        >
          {pool.name}
        </button>
        {!pool.enabled && (
          <span className="ml-2 rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
            disabled
          </span>
        )}
      </td>
      <td className="px-3 py-2 font-mono text-xs">
        {fqdn}{" "}
        <span className="text-muted-foreground">· {pool.record_type}</span>
      </td>
      <td className="px-3 py-2 text-xs text-muted-foreground">
        {pool.group_name}
      </td>
      <td className="px-3 py-2 text-xs uppercase">{pool.hc_type}</td>
      <td className="px-3 py-2 text-xs text-muted-foreground">
        {pool.hc_type === "none"
          ? "—"
          : `${pool.hc_target_port ? `:${pool.hc_target_port}` : ""} every ${pool.hc_interval_seconds}s`}
      </td>
      <td className="px-3 py-2">
        <div className="flex items-center gap-1.5 text-xs">
          {healthIcon}
          <span>
            {pool.live_count}/{pool.member_count} live
            {pool.healthy_count !== pool.live_count && (
              <span className="text-muted-foreground">
                {" "}
                · {pool.healthy_count} healthy
              </span>
            )}
          </span>
        </div>
      </td>
      <td className="px-3 py-2 text-right text-xs tabular-nums">{pool.ttl}s</td>
      <td className="px-3 py-2 text-right text-xs text-muted-foreground">
        {pool.last_checked_at ? humanTime(pool.last_checked_at) : "—"}
      </td>
      <td className="px-3 py-2 text-right">
        <div className="flex items-center justify-end gap-1">
          <button
            type="button"
            onClick={onCheckNow}
            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
            title="Check now"
            aria-label="Check now"
            {...gate}
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={onOpen}
            className="rounded p-1 text-muted-foreground hover:text-foreground"
            title="Open in zone Pools tab"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={onDelete}
            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
            title="Delete pool"
            aria-label="Delete pool"
            {...gate}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </td>
    </tr>
  );
}

// ── Picker modal — pick group + zone before launching PoolModal ───────────

function PickGroupZoneModal({
  onPick,
  onClose,
}: {
  onPick: (group: DNSServerGroup, zone: DNSZone) => void;
  onClose: () => void;
}) {
  const [groupId, setGroupId] = useState("");
  const [zoneId, setZoneId] = useState("");

  const { data: groups = [] } = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });
  const { data: zones = [] } = useQuery({
    queryKey: ["dns-zones", groupId],
    queryFn: () => (groupId ? dnsApi.listZones(groupId) : Promise.resolve([])),
    enabled: !!groupId,
  });

  // Pools render regular A/AAAA records — they must target a forward-lookup zone.
  // Conditional-forwarder zones (zone_type === "forward"), reverse zones (kind === "reverse"),
  // and Tailscale-synthesised zones are hidden from the picker (issue #571).
  const eligibleZones = zones.filter(
    (z) =>
      z.zone_type !== "forward" &&
      z.kind !== "reverse" &&
      !z.tailscale_tenant_id,
  );

  const group = groups.find((g) => g.id === groupId);
  const zone = eligibleZones.find((z) => z.id === zoneId);
  const ready = !!group && !!zone;

  return (
    <Modal title="New DNS pool — pick zone" onClose={onClose}>
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Pools belong to a zone — that&apos;s where the rendered records land.
        </p>
        <div className="space-y-2">
          <label className="block text-xs font-medium text-muted-foreground">
            Server group
          </label>
          <select
            value={groupId}
            onChange={(e) => {
              setGroupId(e.target.value);
              setZoneId("");
            }}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="">— pick a group —</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </div>
        <div className="space-y-2">
          <label className="block text-xs font-medium text-muted-foreground">
            Zone
          </label>
          <select
            value={zoneId}
            onChange={(e) => setZoneId(e.target.value)}
            disabled={!groupId}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
          >
            <option value="">
              {groupId ? "— pick a zone —" : "(pick a group first)"}
            </option>
            {eligibleZones.map((z) => (
              <option key={z.id} value={z.id}>
                {z.name.replace(/\.$/, "")} ({z.zone_type})
              </option>
            ))}
          </select>
          {groupId && eligibleZones.length === 0 && (
            <p className="text-[11px] text-muted-foreground">
              No eligible forward zones in this group. Conditional-forwarder
              zones, reverse (in-addr.arpa / ip6.arpa) zones, and
              Tailscale-synthesised zones can&apos;t host pools.
            </p>
          )}
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!ready}
            onClick={() => {
              if (group && zone) onPick(group, zone);
            }}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            Continue
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function ConfirmDeleteModal({
  pool,
  onConfirm,
  onClose,
  pending,
}: {
  pool: DNSPoolListEntry;
  onConfirm: () => void;
  onClose: () => void;
  pending: boolean;
}) {
  const fqdn =
    pool.record_name === "@"
      ? pool.zone_name.replace(/\.$/, "")
      : `${pool.record_name}.${pool.zone_name.replace(/\.$/, "")}`;
  return (
    <Modal title={`Delete pool: ${pool.name}`} onClose={onClose}>
      <p className="text-sm text-muted-foreground">
        {poolDeleteSummary({
          name: pool.name,
          fqdn,
          recordType: pool.record_type,
          poolEnabled: pool.enabled,
          memberCount: pool.member_count,
          publishedCount: pool.enabled ? pool.live_count : 0,
        })}
      </p>
      <div className="mt-4 flex justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onConfirm}
          disabled={pending}
          className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
        >
          {pending ? "Deleting…" : "Delete"}
        </button>
      </div>
    </Modal>
  );
}
