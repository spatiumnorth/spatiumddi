import { useModuleOn } from "@/hooks/useModuleOn";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  Boxes,
  Check,
  Clipboard,
  Pencil,
  Plus,
  RefreshCw,
  ShieldAlert,
  TestTube2,
  RotateCw,
  Trash2,
} from "lucide-react";

import {
  panosApi,
  dnsApi,
  type DNSServerGroup,
  type PANOSFirewall,
  type PANOSFirewallCreate,
  type PANOSFirewallUpdate,
  type PANOSTestResult,
  type FirewallObject,
  type PANOSDrift,
} from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { IPSpacePicker } from "@/components/ipam/space-picker";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import { secondsFieldError, SYNC_INTERVAL_BOUNDS } from "@/lib/seconds";

// ── Setup guide ─────────────────────────────────────────────────────
// Steps an operator follows in the PAN-OS / Panorama web UI to mint a
// read-only API key for SpatiumDDI.

const SETUP_GUIDE = `# In the PAN-OS / Panorama web UI:

# 1. Create a dedicated read-only admin for SpatiumDDI:
#      Device → Administrators → Add
#      Name: spatiumddi
#      Administrator Type: Role Based → an XML-API-read role
#      (Superuser (read-only) works too; least privilege is preferred).
#
# 2. Ensure the XML API is permitted for that role
#    (Device → Admin Roles → XML API → Report / Configuration = Enable).
#
# 3. Mint an API key for the account (from a workstation):
#      curl -k 'https://<fw>/api/?type=keygen&user=spatiumddi&password=<pw>'
#    The <key> element in the response is your API key.
#
# Paste that key into "API Key" below — or paste the username + password
# and click "Test Connection", and SpatiumDDI will mint the key for you
# and capture it into the form. SpatiumDDI never writes to PAN-OS from
# this integration (block sync is armed separately).`;

// ── Page ─────────────────────────────────────────────────────────────

export function PanosPage() {
  // #1340 — every write on this integration takes a superadmin (its
  // router's create / update / delete / sync / test handlers take
  // SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: firewalls = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["panos-firewalls"],
    queryFn: panosApi.list,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<PANOSFirewall | null>(null);
  const [del, setDel] = useState<PANOSFirewall | null>(null);
  const [objectsFor, setObjectsFor] = useState<PANOSFirewall | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, PANOSTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => panosApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["panos-firewalls"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => panosApi.test({ firewall_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["panos-firewalls"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => panosApi.sync(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["panos-firewalls"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["panos-firewalls"] }),
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
              <ShieldAlert className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Palo Alto Firewalls</h1>
              <span className="text-xs text-muted-foreground">
                {firewalls.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each PAN-OS firewall (or Panorama) is
              polled via the XML API. Address objects resolve to CIDRs and link
              to IPAM addresses / subnets; interfaces with a CIDR land in the
              bound IPAM space as subnets; NAT rules and DHCP leases mirror in
              too. SpatiumDDI never writes to PAN-OS from this integration.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["panos-firewalls"] })
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
              Add Firewall
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {firewalls.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="Palo Alto firewalls">
                  No Palo Alto firewalls configured yet.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> Add Firewall
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
                      Endpoint
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Version
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
                  {firewalls.map((f) => {
                    const tr = inlineTest[f.id];
                    return (
                      <tr key={f.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          {f.name}
                          {f.is_panorama ? (
                            <span className="ml-1.5 inline-flex rounded bg-sky-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-sky-700 dark:text-sky-400">
                              Panorama
                            </span>
                          ) : (
                            <span className="ml-1.5 inline-flex rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                              vsys {f.vsys}
                            </span>
                          )}
                          {f.description && (
                            <div
                              className="text-[11px] text-muted-foreground max-w-md truncate"
                              title={f.description}
                            >
                              {f.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {f.enabled ? (
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
                          title={`https://${f.host}:${f.port}`}
                        >
                          <span className="text-muted-foreground">
                            https://
                          </span>
                          {f.host}:{f.port}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {f.sw_version ?? "—"}
                          {(f.model || f.object_count != null) && (
                            <div className="text-[11px] text-muted-foreground/70">
                              {f.model ? `${f.model}` : ""}
                              {f.object_count != null
                                ? `${f.model ? " · " : ""}${f.object_count} obj${f.object_count === 1 ? "" : "s"}`
                                : ""}
                              {f.nat_rule_count != null
                                ? ` · ${f.nat_rule_count} NAT`
                                : ""}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {f.mirror_address_objects && (
                              <MirrorChip label="objects" />
                            )}
                            {f.mirror_nat_rules && <MirrorChip label="NAT" />}
                            {f.mirror_interfaces && (
                              <MirrorChip label="iface" />
                            )}
                            {f.mirror_dhcp_leases && (
                              <MirrorChip label="DHCP" />
                            )}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <DriftBadge firewall={f} />
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {f.last_synced_at
                            ? new Date(f.last_synced_at).toLocaleString()
                            : "never"}
                          {f.last_sync_error && (
                            <div
                              className="text-[11px] text-destructive max-w-xs truncate"
                              title={f.last_sync_error}
                            >
                              {f.last_sync_error}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <button
                            onClick={() => testMut.mutate(f.id)}
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
                            onClick={() => setObjectsFor(f)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground"
                            title="View address objects"
                          >
                            <Boxes className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => syncMut.mutate(f.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === f.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
                            {...superadminGate}
                          >
                            <RotateCw
                              className={`h-3.5 w-3.5 ${
                                syncMut.isPending && syncMut.variables === f.id
                                  ? "animate-spin"
                                  : ""
                              }`}
                            />
                          </button>
                          <button
                            onClick={() => setEdit(f)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                            title="Edit"
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(f)}
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

      {showCreate && <FirewallModal onClose={() => setShowCreate(false)} />}
      {edit && <FirewallModal firewall={edit} onClose={() => setEdit(null)} />}
      {objectsFor && (
        <ObjectsModal
          firewall={objectsFor}
          onClose={() => setObjectsFor(null)}
        />
      )}
      {del && (
        <DeleteFirewallModal
          firewall={del}
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

// Per-firewall drift summary — objects_unlinked + subnets_uncovered.
function DriftBadge({ firewall }: { firewall: PANOSFirewall }) {
  const { data, isLoading, isError } = useQuery<PANOSDrift>({
    queryKey: ["panos-drift", firewall.id, firewall.last_synced_at],
    queryFn: () => panosApi.drift(firewall.id),
    enabled: firewall.enabled,
  });
  if (!firewall.enabled)
    return <span className="text-muted-foreground">—</span>;
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
  firewall,
  onClose,
}: {
  firewall: PANOSFirewall;
  onClose: () => void;
}) {
  const { data: objects = [], isLoading } = useQuery<FirewallObject[]>({
    queryKey: ["panos-objects", firewall.id],
    queryFn: () => panosApi.listObjects(firewall.id),
  });

  return (
    <Modal title={`Address objects · ${firewall.name}`} onClose={onClose} wide>
      <div className="space-y-3">
        {isLoading ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            Loading…
          </p>
        ) : objects.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            No address objects mirrored from this firewall yet. Run a sync
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

export function FirewallModal({
  firewall,
  onClose,
}: {
  firewall?: PANOSFirewall;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!firewall;

  // DNS off (#2135): no /dns/groups read and no picker. The stored
  // dns_group_id is sent back untouched, so saving here cannot clear it.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: dnsOn,
  });

  const [name, setName] = useState(firewall?.name ?? "");
  const [description, setDescription] = useState(firewall?.description ?? "");
  const [enabled, setEnabled] = useState(firewall?.enabled ?? true);
  const [host, setHost] = useState(firewall?.host ?? "");
  const [port, setPort] = useState(firewall?.port ?? 443);
  const [verifyTls, setVerifyTls] = useState(firewall?.verify_tls ?? true);
  const [caBundlePem, setCaBundlePem] = useState("");
  const [apiVersion, setApiVersion] = useState(firewall?.api_version ?? "11.0");
  const [isPanorama, setIsPanorama] = useState(firewall?.is_panorama ?? false);
  const [vsys, setVsys] = useState(firewall?.vsys ?? "vsys1");
  const [deviceGroup, setDeviceGroup] = useState(firewall?.device_group ?? "");
  // Auth — either paste an API key, or username + password to keygen via Test.
  const [authMode, setAuthMode] = useState<"api_key" | "keygen">("api_key");
  const [apiKey, setApiKey] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [spaceId, setSpaceId] = useState(firewall?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(firewall?.dns_group_id ?? "");
  const [mirrorAddressObjects, setMirrorAddressObjects] = useState(
    firewall?.mirror_address_objects ?? true,
  );
  const [mirrorNatRules, setMirrorNatRules] = useState(
    firewall?.mirror_nat_rules ?? true,
  );
  const [mirrorInterfaces, setMirrorInterfaces] = useState(
    firewall?.mirror_interfaces ?? true,
  );
  const [mirrorDhcpLeases, setMirrorDhcpLeases] = useState(
    firewall?.mirror_dhcp_leases ?? false,
  );
  const [syncInterval, setSyncInterval] = useState(
    String(firewall?.sync_interval_seconds ?? 300),
  );
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");

  const [testResult, setTestResult] = useState<PANOSTestResult | null>(null);

  const testMut = useMutation({
    mutationFn: () =>
      panosApi.test({
        firewall_id: firewall?.id,
        host: host || undefined,
        port,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundlePem || undefined,
        api_version: apiVersion || undefined,
        is_panorama: isPanorama,
        vsys: vsys || undefined,
        device_group: deviceGroup || undefined,
        api_key: authMode === "api_key" && apiKey ? apiKey : undefined,
        username: authMode === "keygen" && username ? username : undefined,
        password: authMode === "keygen" && password ? password : undefined,
      }),
    onSuccess: (result) => {
      setTestResult(result);
      // A keygen test mints and returns a fresh API key — capture it into the
      // form so the operator doesn't have to paste it manually.
      if (result.ok && result.api_key) {
        setApiKey(result.api_key);
        setAuthMode("api_key");
      }
    },
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: PANOSFirewallUpdate = {
          name,
          description,
          enabled,
          host,
          port,
          verify_tls: verifyTls,
          api_version: apiVersion,
          is_panorama: isPanorama,
          vsys,
          device_group: deviceGroup,
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          mirror_address_objects: mirrorAddressObjects,
          mirror_nat_rules: mirrorNatRules,
          mirror_interfaces: mirrorInterfaces,
          mirror_dhcp_leases: mirrorDhcpLeases,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (caBundlePem) update.ca_bundle_pem = caBundlePem;
        if (apiKey) update.api_key = apiKey;
        return panosApi.update(firewall!.id, update);
      }
      const create: PANOSFirewallCreate = {
        name,
        description,
        enabled,
        host,
        port,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundlePem,
        api_version: apiVersion,
        is_panorama: isPanorama,
        vsys,
        device_group: deviceGroup,
        api_key: apiKey,
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        mirror_address_objects: mirrorAddressObjects,
        mirror_nat_rules: mirrorNatRules,
        mirror_interfaces: mirrorInterfaces,
        mirror_dhcp_leases: mirrorDhcpLeases,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return panosApi.create(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["panos-firewalls"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save firewall")),
  });

  return (
    <Modal
      title={editing ? "Edit Palo Alto Firewall" : "Add Palo Alto Firewall"}
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
        <div className="rounded-md border bg-muted/30 p-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">Setup guide</h3>
            <button
              type="button"
              onClick={() => setShowGuide((v) => !v)}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              {showGuide ? "Hide" : "Show"}
            </button>
          </div>
          {showGuide && (
            <div className="mt-2 space-y-2 text-xs">
              <p className="text-muted-foreground">
                Mint a read-only XML-API key in PAN-OS / Panorama. SpatiumDDI
                authenticates with the API key over HTTPS and never writes to
                PAN-OS from this integration.
              </p>
              <CopyablePre text={SETUP_GUIDE} label="PAN-OS API key setup" />
            </div>
          )}
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

        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <Field
              label="Host"
              hint="Hostname or IP of the PAN-OS firewall or Panorama (e.g. fw.example.com)."
            >
              <input
                className={`${inputCls} font-mono text-[11px]`}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="fw.example.com"
                required
              />
            </Field>
          </div>
          <Field label="Port">
            <input
              type="number"
              className={inputCls}
              value={port}
              min={1}
              max={65535}
              onChange={(e) => setPort(parseInt(e.target.value) || 443)}
            />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field
            label="REST API version"
            hint="PAN-OS REST API version — number only, no leading 'v' (e.g. 11.0, 10.1)."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={apiVersion}
              onChange={(e) => setApiVersion(e.target.value)}
              placeholder="11.0"
            />
          </Field>
          <label className="flex cursor-pointer items-start gap-2 pt-6 text-sm">
            <input
              type="checkbox"
              checked={isPanorama}
              onChange={(e) => setIsPanorama(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>This endpoint is Panorama</span>
              <p className="text-[11px] text-muted-foreground/70">
                Off = standalone firewall (uses a vsys). On = Panorama (uses a
                device group).
              </p>
            </div>
          </label>
        </div>

        {isPanorama ? (
          <Field
            label="Device group"
            hint="The Panorama device group to read objects / rules from."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={deviceGroup}
              onChange={(e) => setDeviceGroup(e.target.value)}
              placeholder="e.g. Branch-Firewalls"
            />
          </Field>
        ) : (
          <Field label="vsys" hint="The virtual system on the firewall.">
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={vsys}
              onChange={(e) => setVsys(e.target.value)}
              placeholder="vsys1"
            />
          </Field>
        )}

        <div className="space-y-2 border-t pt-3">
          <label className="block text-xs font-medium text-muted-foreground">
            Authentication
          </label>
          <div className="flex flex-wrap gap-4 text-sm">
            <label className="flex cursor-pointer items-center gap-2">
              <input
                type="radio"
                name="panos-auth-mode"
                checked={authMode === "api_key"}
                onChange={() => setAuthMode("api_key")}
              />
              <span>Paste API key</span>
            </label>
            <label className="flex cursor-pointer items-center gap-2">
              <input
                type="radio"
                name="panos-auth-mode"
                checked={authMode === "keygen"}
                onChange={() => setAuthMode("keygen")}
              />
              <span>Mint from username / password</span>
            </label>
          </div>
          {authMode === "api_key" ? (
            <Field
              label="API Key"
              hint="The XML API key. On edit, leave blank to keep the stored key."
            >
              <input
                className={`${inputCls} font-mono text-[11px]`}
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={
                  editing && firewall?.api_key_present
                    ? "••• stored — enter to replace"
                    : "API key"
                }
                required={!editing && authMode === "api_key"}
              />
            </Field>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Username">
                  <input
                    className={inputCls}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="off"
                    placeholder="spatiumddi"
                  />
                </Field>
                <Field label="Password">
                  <input
                    type="password"
                    className={inputCls}
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </Field>
              </div>
              <p className="text-[11px] text-muted-foreground/70">
                Click <span className="font-medium">Test Connection</span> below
                — SpatiumDDI runs a keygen against PAN-OS and captures the
                minted API key into the form. The password is never stored.
              </p>
              {apiKey && (
                <p className="text-[11px] text-emerald-600 dark:text-emerald-400">
                  ✓ API key captured from keygen.
                </p>
              )}
            </>
          )}
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
              On by default. Uncheck for a self-signed lab host, or paste the
              firewall&apos;s CA bundle below and leave this on.
            </p>
          </div>
        </label>

        <Field
          label="CA bundle (PEM, optional)"
          hint="Leave blank to trust the system CA store. Useful for internal CAs."
        >
          <textarea
            className={`${inputCls} font-mono text-[11px]`}
            rows={3}
            value={caBundlePem}
            onChange={(e) => setCaBundlePem(e.target.value)}
            placeholder={
              editing && firewall?.ca_bundle_present
                ? "••• stored — paste to replace"
                : "-----BEGIN CERTIFICATE-----\n..."
            }
          />
        </Field>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={
              testMut.isPending ||
              !host ||
              (authMode === "api_key" ? !apiKey : !username || !password)
            }
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
              checked={mirrorAddressObjects}
              onChange={(e) => setMirrorAddressObjects(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror address objects</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Address objects resolve to CIDRs and link to IPAM
                addresses / subnets.
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
                On by default. NAT rules land as NAT mappings.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorInterfaces}
              onChange={(e) => setMirrorInterfaces(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror interfaces into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Interfaces with a CIDR land as subnets in the
                bound IPAM space.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorDhcpLeases}
              onChange={(e) => setMirrorDhcpLeases(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror DHCP leases into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                Off by default. Active leases land as <code>dhcp</code> IP rows.
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
            // A new firewall always needs a resolved API key. In keygen mode
            // `apiKey` stays empty until Test Connection mints it (and flips
            // authMode back to "api_key"), so this also forces a successful
            // Test before Create. Editing leaves the key blank to keep the
            // stored one, so no gate there.
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

function DeleteFirewallModal({
  firewall,
  onConfirm,
  onClose,
  isPending,
  error,
}: {
  firewall: PANOSFirewall;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
  error?: string | null;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete Palo Alto Firewall" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the Palo Alto firewall{" "}
          <span className="font-semibold">{firewall.name}</span>? This only
          affects SpatiumDDI — nothing on the PAN-OS side changes. If active
          block sync is armed, disarm it first (that lifts the pushed blocks
          from the device); delete is refused while it is armed. Only rows that
          were purely mirrored are removed. Anything you added yourself
          (addresses, DHCP scopes, reservations, edited rows, custom fields) is
          kept and detached from this integration.
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

function CopyablePre({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function handle() {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }
  }
  return (
    <div className="relative">
      <pre className="overflow-auto rounded bg-background p-2 pr-20 font-mono text-[11px] leading-tight">
        {text}
      </pre>
      <button
        type="button"
        onClick={handle}
        className="absolute right-1.5 top-1.5 inline-flex items-center gap-1 rounded border bg-background px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground"
        aria-label={`Copy ${label}`}
        title={`Copy ${label}`}
      >
        {copied ? (
          <>
            <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
            Copied
          </>
        ) : (
          <>
            <Clipboard className="h-3 w-3" />
            Copy
          </>
        )}
      </button>
    </div>
  );
}

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
