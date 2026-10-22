import { useModuleOn } from "@/hooks/useModuleOn";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  Boxes,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  ShieldBan,
  TestTube2,
  RotateCw,
  Trash2,
} from "lucide-react";

import {
  merakiApi,
  dnsApi,
  type DNSServerGroup,
  type MerakiOrg,
  type MerakiOrgCreate,
  type MerakiOrgUpdate,
  type MerakiTestResult,
  type FirewallObject,
  type PANOSDrift,
} from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { IPSpacePicker } from "@/components/ipam/space-picker";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import { secondsFieldError, SYNC_INTERVAL_BOUNDS } from "@/lib/seconds";

// ── Page ─────────────────────────────────────────────────────────────

export function MerakiPage() {
  // #1340 — every write on this integration takes a superadmin (its
  // router's create / update / delete / sync / test handlers take
  // SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: orgs = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["meraki-orgs"],
    queryFn: merakiApi.list,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<MerakiOrg | null>(null);
  const [del, setDel] = useState<MerakiOrg | null>(null);
  const [objectsFor, setObjectsFor] = useState<MerakiOrg | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, MerakiTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => merakiApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["meraki-orgs"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => merakiApi.test({ org_id_pk: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["meraki-orgs"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => merakiApi.sync(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["meraki-orgs"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["meraki-orgs"] }),
        5000,
      );
    },
  });

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="border-b px-6 py-4 bg-card">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Network className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Cisco Meraki</h1>
              <span className="text-xs text-muted-foreground">
                {orgs.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each Meraki organization is polled via the
              cloud Dashboard API with a read-only API key. Policy objects
              resolve to CIDRs and link to IPAM addresses / subnets; VLANs and
              DHCP reservations mirror in too. SpatiumDDI never writes to Meraki
              from this integration.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["meraki-orgs"] })
              }
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowCreate(true)}
              {...superadminGate}
            >
              Add Organization
            </HeaderButton>
          </div>
        </div>

        {/* Per-client Blocked enforcement is armed on the Block Sync page. */}
        <div className="mt-3 flex items-start gap-2 rounded-md border border-sky-500/30 bg-sky-500/5 px-3 py-2 text-xs text-sky-800 dark:text-sky-300 max-w-3xl">
          <ShieldBan className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          <span>
            Per-client Blocked enforcement is armed on the Active block sync
            page (Security → Block Sync) with a separate write-scoped API key.
          </span>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {orgs.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="Meraki organizations">
                  No Meraki organizations configured yet.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> Add Organization
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1100px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Name
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Enabled
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Org ID
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Networks
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Mirror
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Drift
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Last sync
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Test
                    </th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {orgs.map((o) => {
                    const tr = inlineTest[o.id];
                    return (
                      <tr key={o.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          {o.name}
                          {o.block_sync_enabled && (
                            <span className="ml-1.5 inline-flex rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-red-700 dark:text-red-400">
                              armed
                            </span>
                          )}
                          {o.description && (
                            <div
                              className="text-[11px] text-muted-foreground max-w-md truncate"
                              title={o.description}
                            >
                              {o.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {o.enabled ? (
                            <span className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
                              enabled
                            </span>
                          ) : (
                            <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                              disabled
                            </span>
                          )}
                        </td>
                        <td
                          className="max-w-xs truncate px-3 py-2 font-mono text-[11px]"
                          title={o.org_id}
                        >
                          {o.org_id}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {o.network_count != null
                            ? `${o.network_count} net${o.network_count === 1 ? "" : "s"}`
                            : "—"}
                          {o.object_count != null && (
                            <div className="text-[11px] text-muted-foreground/70">
                              {o.object_count} obj
                              {o.object_count === 1 ? "" : "s"}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {o.mirror_policy_objects && (
                              <MirrorChip label="objects" />
                            )}
                            {o.mirror_vlans && <MirrorChip label="VLANs" />}
                            {o.mirror_dhcp_reservations && (
                              <MirrorChip label="DHCP" />
                            )}
                            {o.mirror_nat_rules && <MirrorChip label="NAT" />}
                            {o.mirror_clients && <MirrorChip label="clients" />}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <DriftBadge org={o} />
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {o.last_synced_at
                            ? new Date(o.last_synced_at).toLocaleString()
                            : "never"}
                          {o.last_sync_error && (
                            <div
                              className="text-[11px] text-destructive max-w-xs truncate"
                              title={o.last_sync_error}
                            >
                              {o.last_sync_error}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <button
                            onClick={() => testMut.mutate(o.id)}
                            disabled={testMut.isPending}
                            className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
                            {...superadminGate}
                          >
                            <TestTube2 className="h-3 w-3" />
                            Test
                          </button>
                          {tr && (
                            <div
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
                            onClick={() => setObjectsFor(o)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground"
                            title="View policy objects"
                          >
                            <Boxes className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => syncMut.mutate(o.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === o.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
                            {...superadminGate}
                          >
                            <RotateCw
                              className={`h-3.5 w-3.5 ${
                                syncMut.isPending && syncMut.variables === o.id
                                  ? "animate-spin"
                                  : ""
                              }`}
                            />
                          </button>
                          <button
                            onClick={() => setEdit(o)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                            title="Edit"
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(o)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                            title="Delete"
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
      </div>

      {showCreate && <OrgModal onClose={() => setShowCreate(false)} />}
      {edit && <OrgModal org={edit} onClose={() => setEdit(null)} />}
      {objectsFor && (
        <ObjectsModal org={objectsFor} onClose={() => setObjectsFor(null)} />
      )}
      {del && (
        <DeleteOrgModal
          org={del}
          onClose={() => {
            delMut.reset();
            setDel(null);
          }}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
          error={delMut.isError ? errMsg(delMut.error, "Delete failed") : null}
        />
      )}
    </div>
  );
}

function MirrorChip({ label }: { label: string }) {
  return (
    <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
      {label}
    </span>
  );
}

// Per-org drift summary — objects_unlinked + subnets_uncovered.
function DriftBadge({ org }: { org: MerakiOrg }) {
  const { data, isLoading, isError } = useQuery<PANOSDrift>({
    queryKey: ["meraki-drift", org.id, org.last_synced_at],
    queryFn: () => merakiApi.drift(org.id),
    enabled: org.enabled,
  });
  if (!org.enabled) return <span className="text-muted-foreground">—</span>;
  if (isLoading) return <span className="text-muted-foreground/70">…</span>;
  if (isError || !data) return <span className="text-muted-foreground">—</span>;
  const clean = data.objects_unlinked === 0 && data.subnets_uncovered === 0;
  if (clean)
    return (
      <span className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
        in sync
      </span>
    );
  return (
    <span
      className="inline-flex rounded bg-amber-500/10 px-1.5 py-0.5 text-[11px] text-amber-700 dark:text-amber-400"
      title={
        data.subnets_uncovered_cidrs.length > 0
          ? `Uncovered: ${data.subnets_uncovered_cidrs.join(", ")}`
          : undefined
      }
    >
      {data.objects_unlinked} unlinked · {data.subnets_uncovered} uncovered
    </span>
  );
}

// ── Objects modal ───────────────────────────────────────────────────

function ObjectsModal({
  org,
  onClose,
}: {
  org: MerakiOrg;
  onClose: () => void;
}) {
  const { data: objects = [], isLoading } = useQuery<FirewallObject[]>({
    queryKey: ["meraki-objects", org.id],
    queryFn: () => merakiApi.listObjects(org.id),
  });

  return (
    <Modal title={`Policy objects · ${org.name}`} onClose={onClose} wide>
      <div className="space-y-3">
        {isLoading ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            Loading…
          </p>
        ) : objects.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            No policy objects mirrored from this organization yet. Run a sync
            first.
          </p>
        ) : (
          <div className="max-h-[60vh] overflow-auto rounded-md border">
            <table className="w-full min-w-[720px] text-xs">
              <thead className="sticky top-0">
                <tr className="border-b bg-muted/50">
                  <th className="px-3 py-2 text-left font-medium">Name</th>
                  <th className="px-3 py-2 text-left font-medium">Kind</th>
                  <th className="px-3 py-2 text-left font-medium">Value</th>
                  <th className="px-3 py-2 text-left font-medium">
                    Resolved CIDR
                  </th>
                  <th className="px-3 py-2 text-left font-medium">Tags</th>
                  <th className="px-3 py-2 text-left font-medium">Linked</th>
                </tr>
              </thead>
              <tbody>
                {objects.map((o) => (
                  <tr key={o.id} className="border-b last:border-0">
                    <td className="px-3 py-2 font-medium">
                      {o.name}
                      {o.description && (
                        <div
                          className="max-w-xs truncate text-[11px] text-muted-foreground"
                          title={o.description}
                        >
                          {o.description}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {o.kind}
                    </td>
                    <td className="break-all px-3 py-2 font-mono text-[11px]">
                      {o.value}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                      {o.resolved_cidr ?? "—"}
                    </td>
                    <td className="px-3 py-2">
                      {o.tags.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {o.tags.map((t) => (
                            <span
                              key={t}
                              className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {o.unlinked ? (
                        <span className="inline-flex rounded bg-amber-500/10 px-1.5 py-0.5 text-[11px] text-amber-700 dark:text-amber-400">
                          unlinked
                        </span>
                      ) : (
                        <span className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
                          linked
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function OrgModal({ org, onClose }: { org?: MerakiOrg; onClose: () => void }) {
  const qc = useQueryClient();
  const editing = !!org;

  // DNS off (#2135): no /dns/groups read and no picker. The stored
  // dns_group_id is sent back untouched, so saving here cannot clear it.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: dnsOn,
  });

  const [name, setName] = useState(org?.name ?? "");
  const [description, setDescription] = useState(org?.description ?? "");
  const [enabled, setEnabled] = useState(org?.enabled ?? true);
  const [baseUrl, setBaseUrl] = useState(
    org?.base_url ?? "https://api.meraki.com/api/v1",
  );
  const [orgId, setOrgId] = useState(org?.org_id ?? "");
  const [networkIds, setNetworkIds] = useState(
    (org?.network_ids ?? []).join(", "),
  );
  const [apiKey, setApiKey] = useState("");
  const [spaceId, setSpaceId] = useState(org?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(org?.dns_group_id ?? "");
  const [mirrorPolicyObjects, setMirrorPolicyObjects] = useState(
    org?.mirror_policy_objects ?? true,
  );
  const [mirrorVlans, setMirrorVlans] = useState(org?.mirror_vlans ?? true);
  const [mirrorDhcpReservations, setMirrorDhcpReservations] = useState(
    org?.mirror_dhcp_reservations ?? false,
  );
  const [mirrorNatRules, setMirrorNatRules] = useState(
    org?.mirror_nat_rules ?? false,
  );
  const [mirrorClients, setMirrorClients] = useState(
    org?.mirror_clients ?? false,
  );
  const [syncInterval, setSyncInterval] = useState(
    String(org?.sync_interval_seconds ?? 300),
  );
  const [error, setError] = useState("");

  const [testResult, setTestResult] = useState<MerakiTestResult | null>(null);

  // Comma / whitespace separated network-id allow-list → string[].
  function parseNetworkIds(): string[] {
    return networkIds
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  const testMut = useMutation({
    mutationFn: () =>
      merakiApi.test({
        org_id_pk: org?.id,
        base_url: baseUrl || undefined,
        org_id: orgId || undefined,
        api_key: apiKey || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: MerakiOrgUpdate = {
          name,
          description,
          enabled,
          base_url: baseUrl,
          org_id: orgId,
          network_ids: parseNetworkIds(),
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          mirror_policy_objects: mirrorPolicyObjects,
          mirror_vlans: mirrorVlans,
          mirror_dhcp_reservations: mirrorDhcpReservations,
          mirror_nat_rules: mirrorNatRules,
          mirror_clients: mirrorClients,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (apiKey) update.api_key = apiKey;
        return merakiApi.update(org!.id, update);
      }
      const create: MerakiOrgCreate = {
        name,
        description,
        enabled,
        base_url: baseUrl,
        org_id: orgId,
        network_ids: parseNetworkIds(),
        api_key: apiKey,
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        mirror_policy_objects: mirrorPolicyObjects,
        mirror_vlans: mirrorVlans,
        mirror_dhcp_reservations: mirrorDhcpReservations,
        mirror_nat_rules: mirrorNatRules,
        mirror_clients: mirrorClients,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return merakiApi.create(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["meraki-orgs"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save organization")),
  });

  return (
    <Modal
      title={editing ? "Edit Meraki Organization" : "Add Meraki Organization"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          // #2110 — "1h" and an empty field are refused, not read as 1 / the default.
          const intervalError = secondsFieldError(
            "Sync interval",
            syncInterval,
            SYNC_INTERVAL_BOUNDS,
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
        <div className="rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
          Generate a read-only Dashboard API key in the Meraki dashboard (My
          Profile → API access) and paste it below with the organization ID.
          SpatiumDDI authenticates with the API key over HTTPS and never writes
          to Meraki from this integration.
        </div>

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

        <Field
          label="Base URL"
          hint="The Meraki Dashboard API base. Change only for a regional shard (e.g. api.meraki.cn)."
        >
          <input
            className={`${inputCls} font-mono text-[11px]`}
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://api.meraki.com/api/v1"
          />
        </Field>

        <Field
          label="Organization ID"
          hint="The Meraki organization id (numeric string), from the dashboard URL or GET /organizations."
        >
          <input
            className={`${inputCls} font-mono text-[11px]`}
            value={orgId}
            onChange={(e) => setOrgId(e.target.value)}
            placeholder="123456"
            required
          />
        </Field>

        <Field
          label="Network IDs (optional allow-list)"
          hint="Comma-separated network ids to limit the mirror. Leave blank to include every network in the org."
        >
          <input
            className={`${inputCls} font-mono text-[11px]`}
            value={networkIds}
            onChange={(e) => setNetworkIds(e.target.value)}
            placeholder="L_123..., N_456..."
          />
        </Field>

        <div className="space-y-2 border-t pt-3">
          <Field
            label="API key"
            hint="The read-only Dashboard API key. On edit, leave blank to keep the stored key."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              type="password"
              autoComplete="new-password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={
                editing && org?.api_key_present
                  ? "••• stored — enter to replace"
                  : "API key"
              }
              required={!editing}
            />
          </Field>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !orgId || !apiKey}
            className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            <TestTube2 className="h-3.5 w-3.5" />
            {testMut.isPending ? "Testing…" : "Test Connection"}
          </button>
          {testResult && (
            <span
              className={`text-xs ${
                testResult.ok
                  ? "text-emerald-600 dark:text-emerald-400"
                  : "text-destructive"
              }`}
              title={testResult.message}
            >
              {testResult.ok ? "✓" : "✗"} {testResult.message}
              {testResult.ok &&
                testResult.org_name &&
                ` · ${testResult.org_name}`}
              {testResult.ok &&
                testResult.network_count != null &&
                ` · ${testResult.network_count} net${testResult.network_count === 1 ? "" : "s"}`}
            </span>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3 border-t pt-3">
          <Field label="IPAM space">
            <IPSpacePicker value={spaceId} onChange={setSpaceId} required />
          </Field>
          {dnsOn && (
            <Field label="DNS server group (optional)">
              <select
                className={inputCls}
                value={dnsGroupId ?? ""}
                onChange={(e) => setDnsGroupId(e.target.value)}
              >
                <option value="">— none —</option>
                {dnsGroups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </Field>
          )}
        </div>

        <Field label="Sync interval (seconds)" hint="Minimum 30 s.">
          <input
            type="number"
            className={inputCls}
            value={syncInterval}
            min={30}
            onChange={(e) => setSyncInterval(e.target.value)}
          />
        </Field>

        <div className="space-y-2 border-t pt-2">
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorPolicyObjects}
              onChange={(e) => setMirrorPolicyObjects(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror policy objects</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Policy objects resolve to CIDRs and link to IPAM
                addresses / subnets.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorVlans}
              onChange={(e) => setMirrorVlans(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror VLANs into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Configured VLAN subnets land as subnets in the
                bound IPAM space.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorDhcpReservations}
              onChange={(e) => setMirrorDhcpReservations(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror DHCP reservations into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                Off by default. Fixed IP assignments land as <code>dhcp</code>{" "}
                IP rows.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorNatRules}
              onChange={(e) => setMirrorNatRules(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror NAT rules</span>
              <p className="text-[11px] text-muted-foreground/70">
                Off by default. Port-forward / 1:1 NAT rules land as NAT
                mappings.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorClients}
              onChange={(e) => setMirrorClients(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror clients into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                Off by default. Recently-seen clients land as <code>dhcp</code>{" "}
                IP rows.
              </p>
            </div>
          </label>
        </div>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saveMut.isPending || (!editing && !apiKey)}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : editing ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DeleteOrgModal({
  org,
  onConfirm,
  onClose,
  isPending,
  error,
}: {
  org: MerakiOrg;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
  error?: string | null;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete Meraki Organization" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the Meraki organization{" "}
          <span className="font-semibold">{org.name}</span>? This only affects
          SpatiumDDI — nothing on the Meraki side changes. If active block sync
          is armed, disarm it first (that lifts the pushed blocks from the
          device); delete is refused while it is armed. All IPAM rows mirrored
          from this organization (subnets + addresses) will be removed via the
          FK cascade.
        </p>
        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => setChecked(e.target.checked)}
            className="mt-0.5"
          />
          <span>I understand.</span>
        </label>
        {error && (
          <p className="break-words rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            disabled={!checked || isPending}
            onClick={onConfirm}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {isPending ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Helpers (local to this page) ────────────────────────────────────

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

function errMsg(e: unknown, fallback: string): string {
  const ae = e as {
    response?: { data?: { detail?: unknown } };
    message?: string;
  };
  const d = ae?.response?.data?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    return (
      (d as Array<{ loc?: (string | number)[]; msg?: string }>)
        .map((err) => {
          const field = (err.loc ?? []).filter((p) => p !== "body").join(".");
          return field ? `${field}: ${err.msg}` : err.msg;
        })
        .filter(Boolean)
        .join("; ") || fallback
    );
  }
  return ae?.message || fallback;
}
