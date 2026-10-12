import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  X,
} from "lucide-react";
import {
  dnsApi,
  sitesApi,
  type DNSPool,
  type DNSPoolMember,
  type DNSPoolWrite,
  type DNSServerGroup,
  type DNSZone,
  type SiteRead,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { poolHealthCheckFields } from "@/lib/formPayloads";

/**
 * Pools view — manages health-checked A / AAAA pools for one zone.
 *
 * Each pool maps a DNS name (e.g. ``www``) to a set of target IPs
 * with health checks. Members render as regular ``DNSRecord`` rows
 * (one per healthy + enabled member) — the operator can toggle a
 * member out manually like a load balancer pool.
 *
 * Caveat (also surfaced in the create modal): DNS is cached
 * client-side, so a member dropping out doesn't take effect until
 * the pool's TTL expires. Default 30s. This is **not** a real
 * L4/L7 load balancer; for real LB see the LBMapping roadmap.
 */
export function PoolsView({
  group,
  zone,
}: {
  group: DNSServerGroup;
  zone: DNSZone;
}) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editPool, setEditPool] = useState<DNSPool | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<DNSPool | null>(null);

  const { data: pools = [], isFetching } = useQuery({
    queryKey: ["dns-pools", group.id, zone.id],
    queryFn: () => dnsApi.listPools(group.id, zone.id),
    refetchInterval: 30_000,
  });

  const checkNow = useMutation({
    mutationFn: (poolId: string) => dnsApi.checkPoolNow(poolId),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["dns-pools", group.id, zone.id] }),
  });
  const del = useMutation({
    mutationFn: (poolId: string) => dnsApi.deletePool(poolId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-pools", group.id, zone.id] });
      qc.invalidateQueries({ queryKey: ["dns-records", zone.id] });
      setConfirmDelete(null);
    },
  });

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b px-5 py-3">
        <div>
          <h2 className="text-sm font-semibold">Pools (GSLB-lite)</h2>
          <p className="text-xs text-muted-foreground">
            Health-checked A / AAAA targets for one DNS name. Members render as
            regular records that flip in/out of the rendered set on health
            change. Not a real load balancer — clients still cache for{" "}
            <em>ttl</em> seconds.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="h-3 w-3" /> New Pool
        </button>
      </div>

      <div className="flex-1 overflow-auto">
        {isFetching && pools.length === 0 && (
          <p className="px-5 py-4 text-sm text-muted-foreground">Loading…</p>
        )}
        {pools.length === 0 && !isFetching && (
          <div className="flex h-40 flex-col items-center justify-center">
            <p className="text-sm italic text-muted-foreground">
              No pools yet. Click <em>New Pool</em> to create one.
            </p>
          </div>
        )}
        <div className="space-y-3 p-5">
          {pools.map((p) => (
            <PoolCard
              key={p.id}
              pool={p}
              zone={zone}
              onEdit={() => setEditPool(p)}
              onDelete={() => setConfirmDelete(p)}
              onCheckNow={() => checkNow.mutate(p.id)}
            />
          ))}
        </div>
      </div>

      {showCreate && (
        <PoolModal
          group={group}
          zone={zone}
          onClose={() => setShowCreate(false)}
        />
      )}
      {editPool && (
        <PoolModal
          group={group}
          zone={zone}
          pool={editPool}
          onClose={() => setEditPool(null)}
        />
      )}
      {confirmDelete && (
        <ConfirmDelete
          pool={confirmDelete}
          zone={zone}
          onConfirm={() => del.mutate(confirmDelete.id)}
          onClose={() => setConfirmDelete(null)}
          pending={del.isPending}
        />
      )}
    </div>
  );
}

function PoolCard({
  pool,
  zone,
  onEdit,
  onDelete,
  onCheckNow,
}: {
  pool: DNSPool;
  zone: DNSZone;
  onEdit: () => void;
  onDelete: () => void;
  onCheckNow: () => void;
}) {
  const fqdn =
    pool.record_name === "@"
      ? zone.name.replace(/\.$/, "")
      : `${pool.record_name}.${zone.name.replace(/\.$/, "")}`;
  const counts = pool.members.reduce(
    (acc, m) => {
      const k = (m.last_check_state || "unknown") as keyof typeof acc;
      acc[k] = (acc[k] || 0) + 1;
      return acc;
    },
    { healthy: 0, unhealthy: 0, unknown: 0 } as Record<string, number>,
  );
  const live = pool.members.filter(
    (m) => m.enabled && m.last_check_state === "healthy",
  ).length;
  return (
    <div className="rounded-md border bg-card">
      <div className="flex items-start justify-between border-b px-4 py-2.5">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">{pool.name}</span>
            <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {fqdn} · {pool.record_type}
            </span>
            {!pool.enabled && (
              <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                disabled
              </span>
            )}
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {pool.hc_type === "none"
              ? "No health check — all enabled members rendered"
              : `${pool.hc_type.toUpperCase()} check${pool.hc_target_port ? ` :${pool.hc_target_port}` : ""}${pool.hc_path && pool.hc_type !== "tcp" ? ` ${pool.hc_path}` : ""} · every ${pool.hc_interval_seconds}s`}
            {" · "}
            ttl {pool.ttl}s
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">
            {live}/{pool.members.length} live
          </span>
          <button
            onClick={onCheckNow}
            className="rounded p-1 text-muted-foreground hover:text-foreground"
            title="Check now"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={onEdit}
            className="rounded p-1 text-muted-foreground hover:text-foreground"
            title="Edit"
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={onDelete}
            className="rounded p-1 text-muted-foreground hover:text-destructive"
            title="Delete"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
      <div className="px-4 py-2">
        {pool.members.length === 0 ? (
          <p className="text-xs italic text-muted-foreground">
            No members — edit the pool to add some.
          </p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="text-left">Address</th>
                <th className="text-left">State</th>
                <th className="text-left">Last check</th>
                <th className="text-left">Error</th>
                <th className="text-right">Enabled</th>
              </tr>
            </thead>
            <tbody>
              {pool.members.map((m) => (
                <MemberRow key={m.id} member={m} />
              ))}
            </tbody>
          </table>
        )}
        <div className="mt-2 flex gap-2 text-[10px] text-muted-foreground">
          <span>healthy {counts.healthy}</span>
          <span>·</span>
          <span>unhealthy {counts.unhealthy}</span>
          {counts.unknown > 0 && (
            <>
              <span>·</span>
              <span>unknown {counts.unknown}</span>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function MemberRow({ member }: { member: DNSPoolMember }) {
  const qc = useQueryClient();
  const toggle = useMutation({
    mutationFn: () =>
      dnsApi.updatePoolMember(member.id, { enabled: !member.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-pools"] }),
  });
  const stateIcon =
    member.last_check_state === "healthy" ? (
      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
    ) : member.last_check_state === "unhealthy" ? (
      <AlertCircle className="h-3.5 w-3.5 text-red-500" />
    ) : (
      <Clock className="h-3.5 w-3.5 text-amber-500" />
    );
  const scoped =
    (member.serving_cidrs?.length ?? 0) > 0 || member.site_id != null;
  const scopeTitle = scoped
    ? `Geo-scoped — served only to ${[
        ...(member.serving_cidrs ?? []),
        member.site_id ? "site clients" : "",
      ]
        .filter(Boolean)
        .join(", ")}`
    : "Default target — served to everyone";
  return (
    <tr className="border-t">
      <td className="py-1.5 font-mono">
        <span className="inline-flex items-center gap-1.5">
          {member.address}
          {scoped && (
            <span
              title={scopeTitle}
              className="rounded bg-sky-500/15 px-1 py-0.5 text-[9px] font-medium uppercase tracking-wider text-sky-600 dark:text-sky-400"
            >
              geo
            </span>
          )}
        </span>
      </td>
      <td className="py-1.5">
        <div className="flex items-center gap-1.5">
          {stateIcon}
          <span className="capitalize">{member.last_check_state}</span>
        </div>
      </td>
      <td className="py-1.5 text-muted-foreground">
        {member.last_check_at
          ? new Date(member.last_check_at).toLocaleTimeString()
          : "—"}
      </td>
      <td
        className="max-w-md truncate py-1.5 text-muted-foreground"
        title={member.last_check_error ?? ""}
      >
        {member.last_check_error ?? "—"}
      </td>
      <td className="py-1.5 text-right">
        <button
          type="button"
          onClick={() => toggle.mutate()}
          className={
            "rounded px-2 py-0.5 text-[10px] font-medium " +
            (member.enabled
              ? "bg-emerald-500/15 text-emerald-600"
              : "bg-muted text-muted-foreground")
          }
        >
          {member.enabled ? "enabled" : "disabled"}
        </button>
      </td>
    </tr>
  );
}

// ── Pool create / edit modal ──────────────────────────────────────────────

interface MemberDraft {
  id?: string;
  address: string;
  weight: number;
  enabled: boolean;
  // Geo / topology-aware steering scope (issue #530). ``servingCidrs`` is
  // the raw comma/space/newline-separated text the operator types; parsed
  // to a string[] on submit. Empty scope + no site ⇒ default target.
  servingCidrs: string;
  siteId: string | null;
}

/** Parse the free-text CIDR box into a clean list. */
function parseCidrs(raw: string): string[] {
  return raw
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function PoolModal({
  group,
  zone,
  pool,
  onClose,
}: {
  group: DNSServerGroup;
  zone: DNSZone;
  pool?: DNSPool;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!pool;
  const [name, setName] = useState(pool?.name ?? "");
  const [description, setDescription] = useState(pool?.description ?? "");
  const [recordName, setRecordName] = useState(pool?.record_name ?? "");
  const [recordType, setRecordType] = useState<"A" | "AAAA">(
    pool?.record_type ?? "A",
  );
  const [ttl, setTtl] = useState(pool?.ttl ?? 30);
  const [enabled, setEnabled] = useState(pool?.enabled ?? true);
  const [hcType, setHcType] = useState<DNSPoolWrite["hc_type"]>(
    pool?.hc_type ?? "tcp",
  );
  const [hcPort, setHcPort] = useState(pool?.hc_target_port ?? 80);
  const [hcPath, setHcPath] = useState(pool?.hc_path ?? "/");
  const [hcMethod, setHcMethod] = useState(pool?.hc_method ?? "GET");
  const [hcVerifyTls, setHcVerifyTls] = useState(pool?.hc_verify_tls ?? false);
  const [hcCodes, setHcCodes] = useState<string>(
    (pool?.hc_expected_status_codes ?? [200]).join(","),
  );
  const [hcInterval, setHcInterval] = useState(pool?.hc_interval_seconds ?? 30);
  const [hcTimeout, setHcTimeout] = useState(pool?.hc_timeout_seconds ?? 5);
  const [hcUnhealthy, setHcUnhealthy] = useState(
    pool?.hc_unhealthy_threshold ?? 2,
  );
  const [hcHealthy, setHcHealthy] = useState(pool?.hc_healthy_threshold ?? 2);
  const [members, setMembers] = useState<MemberDraft[]>(
    (pool?.members ?? []).map((m) => ({
      id: m.id,
      address: m.address,
      weight: m.weight,
      enabled: m.enabled,
      servingCidrs: (m.serving_cidrs ?? []).join(", "),
      siteId: m.site_id,
    })),
  );
  const [error, setError] = useState<string | null>(null);

  // Sites for the per-member serving-scope picker (issue #530).
  const { data: siteList } = useQuery({
    queryKey: ["sites", "pool-geo-picker"],
    queryFn: () => sitesApi.list({ limit: 500 }),
  });
  const sites: SiteRead[] = siteList?.items ?? [];

  const mut = useMutation({
    mutationFn: async () => {
      const codes = hcCodes
        .split(/[,\s]+/)
        .map((s) => parseInt(s, 10))
        .filter((n) => !Number.isNaN(n) && n >= 100 && n <= 599);
      const body: DNSPoolWrite = {
        name,
        description,
        record_name: recordName || "@",
        record_type: recordType,
        ttl,
        enabled,
        hc_type: hcType,
        hc_path: hcPath,
        hc_method: hcMethod,
        ...poolHealthCheckFields({ hcType, hcPort, hcVerifyTls }, editing),
        hc_expected_status_codes:
          codes.length > 0 ? codes : [200, 201, 202, 204, 301, 302, 304],
        hc_interval_seconds: hcInterval,
        hc_timeout_seconds: hcTimeout,
        hc_unhealthy_threshold: hcUnhealthy,
        hc_healthy_threshold: hcHealthy,
      };
      if (editing) {
        const updated = await dnsApi.updatePool(pool!.id, body);
        // Reconcile members: add new, remove deleted, update existing.
        const existing = new Map(pool!.members.map((m) => [m.id, m]));
        const desired = new Map(
          members.filter((m) => m.id).map((m) => [m.id!, m]),
        );
        for (const [id, m] of existing) {
          if (!desired.has(id)) {
            await dnsApi.deletePoolMember(id);
          } else {
            const d = desired.get(id)!;
            const dCidrs = parseCidrs(d.servingCidrs);
            const scopeChanged =
              dCidrs.join(",") !== (m.serving_cidrs ?? []).join(",") ||
              (d.siteId ?? null) !== (m.site_id ?? null);
            if (
              d.address !== m.address ||
              d.enabled !== m.enabled ||
              d.weight !== m.weight ||
              scopeChanged
            ) {
              await dnsApi.updatePoolMember(id, {
                address: d.address,
                enabled: d.enabled,
                weight: d.weight,
                serving_cidrs: dCidrs,
                site_id: d.siteId,
              });
            }
          }
        }
        for (const m of members.filter((m) => !m.id)) {
          await dnsApi.addPoolMember(updated.id, {
            address: m.address,
            weight: m.weight,
            enabled: m.enabled,
            serving_cidrs: parseCidrs(m.servingCidrs),
            site_id: m.siteId,
          });
        }
        return updated;
      }
      const created = await dnsApi.createPool(group.id, zone.id, {
        ...body,
        members: members.map((m) => ({
          address: m.address,
          weight: m.weight,
          enabled: m.enabled,
          serving_cidrs: parseCidrs(m.servingCidrs),
          site_id: m.siteId,
        })),
      });
      return created;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-pools", group.id, zone.id] });
      qc.invalidateQueries({ queryKey: ["dns-records", zone.id] });
      onClose();
    },
    onError: (err: unknown) => {
      const e = err as { response?: { data?: { detail?: string } } };
      setError(e?.response?.data?.detail ?? "Failed to save pool");
    },
  });

  function addMember() {
    setMembers((prev) => [
      ...prev,
      {
        address: "",
        weight: 1,
        enabled: true,
        servingCidrs: "",
        siteId: null,
      },
    ]);
  }
  function removeMember(idx: number) {
    setMembers((prev) => prev.filter((_, i) => i !== idx));
  }
  function updateMember(idx: number, patch: Partial<MemberDraft>) {
    setMembers((prev) =>
      prev.map((m, i) => (i === idx ? { ...m, ...patch } : m)),
    );
  }

  return (
    <Modal
      title={editing ? `Edit pool: ${pool!.name}` : "New DNS pool"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          mut.mutate();
        }}
        className="space-y-4"
      >
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-[11px] text-amber-700 dark:text-amber-400">
          <strong>Heads up:</strong> DNS is cached client-side. A member
          dropping out doesn&apos;t take effect until the pool&apos;s TTL
          expires. Use a short TTL (default 30s). This is <em>not</em> a real
          load balancer — see the LBMapping roadmap entry for that.
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" hint="Operator-facing label.">
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={inputCls}
            />
          </Field>
          <Field
            label="Record name"
            hint="Relative to the zone (e.g. www, api, @)."
          >
            <input
              required
              value={recordName}
              onChange={(e) => setRecordName(e.target.value)}
              className={inputCls}
              placeholder="www"
            />
          </Field>
          <Field label="Record type">
            <select
              value={recordType}
              onChange={(e) => setRecordType(e.target.value as "A" | "AAAA")}
              className={inputCls}
            >
              <option value="A">A (IPv4)</option>
              <option value="AAAA">AAAA (IPv6)</option>
            </select>
          </Field>
          <Field label="TTL (seconds)">
            <input
              type="number"
              min={1}
              max={86400}
              value={ttl}
              onChange={(e) => setTtl(parseInt(e.target.value, 10) || 30)}
              className={inputCls}
            />
          </Field>
        </div>
        <Field label="Description">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className={inputCls}
          />
        </Field>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Enabled (when off, no checks run + no records rendered)
        </label>

        <fieldset className="rounded-md border p-3">
          <legend className="px-1 text-xs font-medium text-muted-foreground">
            Health check
          </legend>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Type">
              <select
                value={hcType}
                onChange={(e) =>
                  setHcType(e.target.value as DNSPoolWrite["hc_type"])
                }
                className={inputCls}
              >
                <option value="tcp">TCP connect</option>
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
                <option value="icmp">ICMP echo (ping)</option>
                <option value="none">None (always healthy)</option>
              </select>
            </Field>
            {hcType !== "none" && hcType !== "icmp" && (
              <Field label="Target port">
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={hcPort}
                  onChange={(e) => setHcPort(parseInt(e.target.value, 10) || 0)}
                  className={inputCls}
                />
              </Field>
            )}
            {(hcType === "http" || hcType === "https") && (
              <>
                <Field label="Method">
                  <select
                    value={hcMethod}
                    onChange={(e) => setHcMethod(e.target.value)}
                    className={inputCls}
                  >
                    <option>GET</option>
                    <option>HEAD</option>
                    <option>POST</option>
                  </select>
                </Field>
                <Field label="Path">
                  <input
                    value={hcPath}
                    onChange={(e) => setHcPath(e.target.value)}
                    className={inputCls}
                    placeholder="/"
                  />
                </Field>
                <Field
                  label="Expected status codes"
                  hint="Comma-separated. Defaults to 2xx + common 3xx."
                >
                  <input
                    value={hcCodes}
                    onChange={(e) => setHcCodes(e.target.value)}
                    className={inputCls}
                    placeholder="200,204,301,302"
                  />
                </Field>
              </>
            )}
            {hcType === "https" && (
              <div className="col-span-2 rounded-md border bg-muted/30 p-3 text-xs">
                <label className="flex cursor-pointer items-start gap-2">
                  <input
                    type="checkbox"
                    checked={hcVerifyTls}
                    onChange={(e) => setHcVerifyTls(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>
                    <span className="font-medium">
                      Validate TLS certificate
                    </span>
                    <span className="block text-[11px] text-muted-foreground">
                      When on, the check fails fast if the cert is self-signed,
                      expired, or the hostname doesn&apos;t match — useful for
                      public-facing targets where a bad cert should itself be a
                      signal. Default <strong>off</strong> because internal pool
                      members commonly ship self-signed certs.
                    </span>
                  </span>
                </label>
              </div>
            )}
            <Field label="Interval (seconds)">
              <input
                type="number"
                min={10}
                max={3600}
                value={hcInterval}
                onChange={(e) =>
                  setHcInterval(parseInt(e.target.value, 10) || 30)
                }
                className={inputCls}
              />
            </Field>
            <Field label="Timeout (seconds)">
              <input
                type="number"
                min={1}
                max={60}
                value={hcTimeout}
                onChange={(e) =>
                  setHcTimeout(parseInt(e.target.value, 10) || 5)
                }
                className={inputCls}
              />
            </Field>
            <Field
              label="Unhealthy threshold"
              hint="Consecutive failed checks before flipping to unhealthy."
            >
              <input
                type="number"
                min={1}
                max={20}
                value={hcUnhealthy}
                onChange={(e) =>
                  setHcUnhealthy(parseInt(e.target.value, 10) || 2)
                }
                className={inputCls}
              />
            </Field>
            <Field
              label="Healthy threshold"
              hint="Consecutive successful checks before flipping back to healthy."
            >
              <input
                type="number"
                min={1}
                max={20}
                value={hcHealthy}
                onChange={(e) =>
                  setHcHealthy(parseInt(e.target.value, 10) || 2)
                }
                className={inputCls}
              />
            </Field>
          </div>
        </fieldset>

        <fieldset className="rounded-md border p-3">
          <legend className="px-1 text-xs font-medium text-muted-foreground">
            Members
          </legend>
          <p className="mb-2 text-[11px] text-muted-foreground">
            Leave <em>Serving scope</em> empty for a default target (served to
            everyone). Set client CIDRs and/or a Site to steer that member only
            to clients whose resolver source IP matches — a geo view. Clients
            matching no scope get just the default members.{" "}
            <span className="text-amber-600 dark:text-amber-400">
              Steering keys on the resolver source IP (not the end client) and
              is subject to the pool TTL cache window.
            </span>
          </p>
          {members.length === 0 && (
            <p className="text-xs italic text-muted-foreground">
              No members. Add at least one.
            </p>
          )}
          <div className="space-y-3">
            {members.map((m, idx) => (
              <div key={idx} className="rounded-md border bg-muted/20 p-2">
                <div className="flex items-center gap-2">
                  <input
                    required
                    value={m.address}
                    onChange={(e) =>
                      updateMember(idx, { address: e.target.value })
                    }
                    className={inputCls + " font-mono"}
                    placeholder={
                      recordType === "AAAA" ? "2001:db8::1" : "10.0.0.10"
                    }
                  />
                  {/* Weight is advisory today — the basic A/AAAA
                      rrset rendering doesn't honour it. Hidden from
                      the form until weighted-record-set support
                      actually lands; the value is still shipped at
                      its default ``1`` so the field is round-trip
                      safe and re-surfacing the input later doesn't
                      break existing rows. */}
                  <label className="flex items-center gap-1 text-xs">
                    <input
                      type="checkbox"
                      checked={m.enabled}
                      onChange={(e) =>
                        updateMember(idx, { enabled: e.target.checked })
                      }
                    />
                    enabled
                  </label>
                  <button
                    type="button"
                    onClick={() => removeMember(idx)}
                    className="rounded p-1 text-muted-foreground hover:text-destructive"
                    title="Remove"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
                <div className="mt-2 grid grid-cols-2 gap-2">
                  <div className="space-y-1">
                    <label className="block text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                      Serving scope — client CIDRs
                    </label>
                    <input
                      value={m.servingCidrs}
                      onChange={(e) =>
                        updateMember(idx, { servingCidrs: e.target.value })
                      }
                      className={inputCls + " font-mono text-xs"}
                      placeholder="e.g. 203.0.113.0/24, 10.1.0.0/16"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                      Serving scope — Site
                    </label>
                    <select
                      value={m.siteId ?? ""}
                      onChange={(e) =>
                        updateMember(idx, {
                          siteId: e.target.value || null,
                        })
                      }
                      className={inputCls + " text-xs"}
                    >
                      <option value="">— none (default) —</option>
                      {sites.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name}
                          {s.code ? ` (${s.code})` : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={addMember}
            className="mt-2 flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
          >
            <Plus className="h-3 w-3" /> Add member
          </button>
        </fieldset>

        {error && (
          <div className="rounded border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
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
            disabled={mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : editing ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ConfirmDelete({
  pool,
  zone,
  onConfirm,
  onClose,
  pending,
}: {
  pool: DNSPool;
  zone: DNSZone;
  onConfirm: () => void;
  onClose: () => void;
  pending: boolean;
}) {
  const fqdn =
    pool.record_name === "@"
      ? zone.name.replace(/\.$/, "")
      : `${pool.record_name}.${zone.name.replace(/\.$/, "")}`;
  return (
    <Modal title={`Delete pool: ${pool.name}`} onClose={onClose}>
      <p className="text-sm text-muted-foreground">
        Delete pool <span className="font-medium">{pool.name}</span> and remove
        the {pool.members.length} record{pool.members.length === 1 ? "" : "s"}{" "}
        currently published as{" "}
        <span className="font-mono">
          {fqdn} {pool.record_type}
        </span>
        ?
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

// ── Local UI helpers (kept inline to avoid expanding the shared bundle) ──

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground/70">{hint}</p>}
    </div>
  );
}
