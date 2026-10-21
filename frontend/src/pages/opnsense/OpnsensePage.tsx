import { useModuleOn } from "@/hooks/useModuleOn";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  Check,
  Clipboard,
  Pencil,
  Plus,
  RefreshCw,
  Shield,
  TestTube2,
  RotateCw,
  Trash2,
} from "lucide-react";

import {
  opnsenseApi,
  dnsApi,
  type DNSServerGroup,
  type OPNsenseRouter,
  type OPNsenseRouterCreate,
  type OPNsenseRouterUpdate,
  type OPNsenseTestResult,
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
// Steps an operator follows in the OPNsense web UI to mint a read-only
// API key/secret pair for SpatiumDDI.

const SETUP_GUIDE = `# In the OPNsense web UI:

# 1. Create a dedicated read-only user for SpatiumDDI:
#      System → Access → Users → +
#      Username: spatiumddi   (no shell access needed)
#
# 2. Grant it read access. The simplest path is the built-in
#    "GUI - All pages (read only)" privilege, or scope it to just
#    Diagnostics + DHCPv4 + Interfaces if you prefer least privilege.
#
# 3. Edit the user → "API keys" → "+" to generate a key/secret pair.
#    OPNsense downloads an apikey.txt containing two lines:
#        key=<API KEY>
#        secret=<API SECRET>
#
# Paste 'key' into "API Key" and 'secret' into "API Secret" below.
# SpatiumDDI authenticates over HTTPS with HTTP Basic auth
# (key as username, secret as password) and never writes to OPNsense.`;

// ── Page ─────────────────────────────────────────────────────────────

export function OpnsensePage() {
  // #1340 — every write on this integration takes a superadmin (its
  // router's create / update / delete / sync / test handlers take
  // SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: routers = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["opnsense-routers"],
    queryFn: opnsenseApi.listRouters,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<OPNsenseRouter | null>(null);
  const [del, setDel] = useState<OPNsenseRouter | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, OPNsenseTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => opnsenseApi.deleteRouter(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["opnsense-routers"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => opnsenseApi.testConnection({ router_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["opnsense-routers"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => opnsenseApi.syncNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["opnsense-routers"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["opnsense-routers"] }),
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
              <Shield className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">OPNsense Firewalls</h1>
              <span className="text-xs text-muted-foreground">
                {routers.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each firewall is polled via the OPNsense
              REST API. Interfaces with a CIDR (LAN / OPT* / VLANs) land in the
              bound IPAM space as subnets; DHCPv4 leases land as IP addresses,
              static reservations as reserved entries, and (optionally) the ARP
              table as discovered hosts. SpatiumDDI never writes to OPNsense.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["opnsense-routers"] })
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
          {routers.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="OPNsense firewalls">
                  No OPNsense firewalls configured yet.
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
              <table className="w-full min-w-[1020px] text-xs">
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
                      Firmware
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Mirror
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
                  {routers.map((r) => {
                    const tr = inlineTest[r.id];
                    return (
                      <tr key={r.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          {r.name}
                          {r.description && (
                            <div
                              className="text-[11px] text-muted-foreground max-w-md truncate"
                              title={r.description}
                            >
                              {r.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {r.enabled ? (
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
                          title={`https://${r.host}:${r.port}`}
                        >
                          <span className="text-muted-foreground">
                            https://
                          </span>
                          {r.host}:{r.port}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {r.firmware_version ?? "—"}
                          {r.interface_count != null && (
                            <div className="text-[11px] text-muted-foreground/70">
                              {r.interface_count} iface
                              {r.interface_count === 1 ? "" : "s"}
                              {r.lease_count != null
                                ? ` · ${r.lease_count} lease${r.lease_count === 1 ? "" : "s"}`
                                : ""}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {r.mirror_dhcp_leases && (
                              <MirrorChip label="DHCP" />
                            )}
                            {r.mirror_static_mappings && (
                              <MirrorChip label="static" />
                            )}
                            {r.mirror_arp && <MirrorChip label="ARP" />}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {r.last_synced_at
                            ? new Date(r.last_synced_at).toLocaleString()
                            : "never"}
                          {r.last_sync_error && (
                            <div
                              className="text-[11px] text-destructive max-w-xs truncate"
                              title={r.last_sync_error}
                            >
                              {r.last_sync_error}
                            </div>
                          )}
                          {/* #797 — a pass can succeed and still mirror
                              nothing. Amber, below any red error, with the
                              full multi-line text on hover. */}
                          {!r.last_sync_error && r.last_sync_warning && (
                            <div
                              className="text-[11px] text-amber-600 dark:text-amber-500 max-w-xs truncate"
                              title={r.last_sync_warning}
                            >
                              {r.last_sync_warning.split("\n")[0]}
                              {r.last_sync_warning.includes("\n") &&
                                ` (+${r.last_sync_warning.split("\n").length - 1} more)`}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <button
                            onClick={() => testMut.mutate(r.id)}
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
                            onClick={() => syncMut.mutate(r.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === r.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
                            {...superadminGate}
                          >
                            <RotateCw
                              className={`h-3.5 w-3.5 ${
                                syncMut.isPending && syncMut.variables === r.id
                                  ? "animate-spin"
                                  : ""
                              }`}
                            />
                          </button>
                          <button
                            onClick={() => setEdit(r)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                            title="Edit"
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(r)}
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

      {showCreate && <RouterModal onClose={() => setShowCreate(false)} />}
      {edit && <RouterModal router={edit} onClose={() => setEdit(null)} />}
      {del && (
        <DeleteRouterModal
          router={del}
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

// ── Create / Edit modal ─────────────────────────────────────────────

function RouterModal({
  router,
  onClose,
}: {
  router?: OPNsenseRouter;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!router;

  // DNS off (#2135): no /dns/groups read and no picker. The stored
  // dns_group_id is sent back untouched, so saving here cannot clear it.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: dnsOn,
  });

  const [name, setName] = useState(router?.name ?? "");
  const [description, setDescription] = useState(router?.description ?? "");
  const [enabled, setEnabled] = useState(router?.enabled ?? true);
  const [host, setHost] = useState(router?.host ?? "");
  const [port, setPort] = useState(router?.port ?? 443);
  const [verifyTls, setVerifyTls] = useState(router?.verify_tls ?? true);
  const [caBundlePem, setCaBundlePem] = useState("");
  const [apiKey, setApiKey] = useState(router?.api_key ?? "");
  const [apiSecret, setApiSecret] = useState("");
  const [spaceId, setSpaceId] = useState(router?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(router?.dns_group_id ?? "");
  const [mirrorDhcpLeases, setMirrorDhcpLeases] = useState(
    router?.mirror_dhcp_leases ?? true,
  );
  const [mirrorStaticMappings, setMirrorStaticMappings] = useState(
    router?.mirror_static_mappings ?? true,
  );
  const [mirrorArp, setMirrorArp] = useState(router?.mirror_arp ?? false);
  const [syncInterval, setSyncInterval] = useState(
    String(router?.sync_interval_seconds ?? 60),
  );
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");

  const [testResult, setTestResult] = useState<OPNsenseTestResult | null>(null);

  const testMut = useMutation({
    mutationFn: () =>
      opnsenseApi.testConnection({
        router_id: router?.id,
        host: host || undefined,
        port,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundlePem || undefined,
        api_key: apiKey || undefined,
        api_secret: apiSecret || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        firmware_version: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: OPNsenseRouterUpdate = {
          name,
          description,
          enabled,
          host,
          port,
          verify_tls: verifyTls,
          api_key: apiKey,
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          mirror_dhcp_leases: mirrorDhcpLeases,
          mirror_static_mappings: mirrorStaticMappings,
          mirror_arp: mirrorArp,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (caBundlePem) update.ca_bundle_pem = caBundlePem;
        if (apiSecret) update.api_secret = apiSecret;
        return opnsenseApi.updateRouter(router!.id, update);
      }
      const create: OPNsenseRouterCreate = {
        name,
        description,
        enabled,
        host,
        port,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundlePem,
        api_key: apiKey,
        api_secret: apiSecret,
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        mirror_dhcp_leases: mirrorDhcpLeases,
        mirror_static_mappings: mirrorStaticMappings,
        mirror_arp: mirrorArp,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return opnsenseApi.createRouter(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["opnsense-routers"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save firewall")),
  });

  return (
    <Modal
      title={editing ? "Edit OPNsense Firewall" : "Add OPNsense Firewall"}
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
                Mint a read-only API key/secret pair in OPNsense. SpatiumDDI
                authenticates with HTTP Basic auth — the API key is the
                username, the API secret is the password.
              </p>
              <CopyablePre text={SETUP_GUIDE} label="OPNsense API key setup" />
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
              hint="Hostname or IP of the OPNsense firewall (e.g. opnsense.example.com)."
            >
              <input
                className={`${inputCls} font-mono text-[11px]`}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="opnsense.example.com"
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
          <Field label="API Key" hint="The 'key' line from apikey.txt.">
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="API key"
              required
            />
          </Field>
          <Field label="API Secret" hint="The 'secret' line from apikey.txt.">
            <input
              type="password"
              className={`${inputCls} font-mono text-[11px]`}
              value={apiSecret}
              onChange={(e) => setApiSecret(e.target.value)}
              placeholder={
                editing && router?.api_secret_present
                  ? "••• stored — enter to replace"
                  : "API secret"
              }
              required={!editing}
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
              editing && router?.ca_bundle_present
                ? "••• stored — paste to replace"
                : "-----BEGIN CERTIFICATE-----\n..."
            }
          />
        </Field>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !host || !apiKey}
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
              checked={mirrorDhcpLeases}
              onChange={(e) => setMirrorDhcpLeases(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror DHCPv4 leases into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Active leases land as <code>dhcp</code> IP rows.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorStaticMappings}
              onChange={(e) => setMirrorStaticMappings(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror static DHCP reservations</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Static mappings land as <code>reserved</code>{" "}
                rows.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorArp}
              onChange={(e) => setMirrorArp(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror the ARP table</span>
              <p className="text-[11px] text-muted-foreground/70">
                Off by default. Noisier secondary source — every host the
                firewall has seen on the wire lands as an{" "}
                <code>opnsense-arp</code> row.
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
            disabled={saveMut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : editing ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DeleteRouterModal({
  router,
  onConfirm,
  onClose,
  isPending,
  error,
}: {
  router: OPNsenseRouter;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
  error?: string | null;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete OPNsense Firewall" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the OPNsense firewall{" "}
          <span className="font-semibold">{router.name}</span>? This only
          affects SpatiumDDI — nothing on the OPNsense side changes. If active
          block sync is armed, disarm it first (that lifts the pushed blocks
          from the device); delete is refused while it is armed. All IPAM rows
          mirrored from this firewall (subnets + addresses) will be removed via
          the FK cascade.
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
