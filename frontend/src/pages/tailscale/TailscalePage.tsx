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
  Trash2,
  TestTube2,
  RotateCw,
  Waypoints,
} from "lucide-react";

import {
  tailscaleApi,
  dnsApi,
  type DNSServerGroup,
  type TailscaleTenant,
  type TailscaleTenantCreate,
  type TailscaleTenantUpdate,
  type TailscaleTestResult,
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
import { CredentialChip } from "@/components/CredentialChip";

// ── Setup guide ─────────────────────────────────────────────────────
// One-shot snippet operators can paste into the Tailscale admin
// console to mint a read-only API key with the right scope.

const SETUP_KEY = `# Generate a Tailscale API key:
#
# 1. Open https://login.tailscale.com/admin/settings/keys
# 2. Click "Generate API key…"
# 3. Set an expiry between 1 and 90 days — 90 is Tailscale's
#    maximum, and there are no non-expiring API access tokens.
#    SpatiumDDI reads the expiry back from Tailscale and warns
#    (alert + chip) 30 days before it lapses.
# 4. Copy the printed value (starts with "tskey-api-").
#
# The key inherits your user's permissions on the tailnet — it can
# read everything but SpatiumDDI never writes back, so the
# read-only side of that surface is all that's used.
#
# Tailnet name: open
#   https://login.tailscale.com/admin/settings/general
# and copy the "Organization" slug. For solo accounts the literal
# "-" works as shorthand for "the API key's default tailnet".`;

// ── Page ─────────────────────────────────────────────────────────────

export function TailscalePage() {
  // #1340 — every write on this integration takes a superadmin (its
  // router's create / update / delete / sync / test handlers take
  // SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: tenants = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["tailscale-tenants"],
    queryFn: tailscaleApi.listTenants,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<TailscaleTenant | null>(null);
  const [del, setDel] = useState<TailscaleTenant | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, TailscaleTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => tailscaleApi.deleteTenant(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tailscale-tenants"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => tailscaleApi.testConnection({ tenant_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["tailscale-tenants"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => tailscaleApi.syncNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tailscale-tenants"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["tailscale-tenants"] }),
        5000,
      );
    },
  });

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="border-b px-6 py-4 bg-card">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Waypoints className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Tailscale Tenants</h1>
              <span className="text-xs text-muted-foreground">
                {tenants.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each tenant is polled via the Tailscale
              REST API with a personal-access token. The CGNAT
              <code className="font-mono"> 100.64.0.0/10</code> IPv4 block + the
              IPv6 ULA block are auto-created under the bound IPAM space, and
              every tailnet device&apos;s addresses land as IP rows with OS,
              client version, user, tags, and routes in custom fields.
              SpatiumDDI never writes to Tailscale.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["tailscale-tenants"] })
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
              Add Tenant
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {tenants.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="Tailscale tenants">
                  No Tailscale tenants configured yet.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> Add Tenant
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1140px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Name
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Enabled
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Tailnet
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Domain
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Devices
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Token
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
                  {tenants.map((t) => {
                    const tr = inlineTest[t.id];
                    return (
                      <tr key={t.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          {t.name}
                          {t.description && (
                            <div
                              className="text-[11px] text-muted-foreground max-w-md truncate"
                              title={t.description}
                            >
                              {t.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {t.enabled ? (
                            <span className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
                              enabled
                            </span>
                          ) : (
                            <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                              disabled
                            </span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                          {t.tailnet}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground font-mono text-[11px]">
                          {t.tailnet_domain ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {t.device_count ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <CredentialChip
                            state={t.credential_state}
                            daysLeft={t.credential_days_left}
                            expiresAt={t.api_key_expires_at}
                            showOk
                            showUnknown
                            onClick={
                              superadminGate.disabled
                                ? undefined
                                : () => setEdit(t)
                            }
                          />
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {t.last_synced_at
                            ? new Date(t.last_synced_at).toLocaleString()
                            : "never"}
                          {t.last_sync_error && (
                            <div
                              className={
                                t.enabled
                                  ? "text-[11px] text-destructive max-w-xs truncate"
                                  : "text-[11px] text-muted-foreground max-w-xs truncate"
                              }
                              title={t.last_sync_error}
                              data-testid="tenant-last-error"
                            >
                              {t.enabled ? "" : "Last error (disabled): "}
                              {t.last_sync_error}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
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
                            onClick={() => syncMut.mutate(t.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === t.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
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
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(t)}
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

      {showCreate && <TenantModal onClose={() => setShowCreate(false)} />}
      {edit && <TenantModal tenant={edit} onClose={() => setEdit(null)} />}
      {del && (
        <DeleteTenantModal
          tenant={del}
          onClose={() => setDel(null)}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function TenantModal({
  tenant,
  onClose,
}: {
  tenant?: TailscaleTenant;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!tenant;

  // DNS off (#2135): no /dns/groups read and no picker. The stored
  // dns_group_id is sent back untouched, so saving here cannot clear it.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: dnsOn,
  });

  const [name, setName] = useState(tenant?.name ?? "");
  const [description, setDescription] = useState(tenant?.description ?? "");
  const [enabled, setEnabled] = useState(tenant?.enabled ?? true);
  const [tailnet, setTailnet] = useState(tenant?.tailnet ?? "-");
  const [apiKey, setApiKey] = useState("");
  const [spaceId, setSpaceId] = useState(tenant?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(tenant?.dns_group_id ?? "");
  const [cgnatCidr, setCgnatCidr] = useState(
    tenant?.cgnat_cidr ?? "100.64.0.0/10",
  );
  const [ipv6Cidr, setIpv6Cidr] = useState(
    tenant?.ipv6_cidr ?? "fd7a:115c:a1e0::/48",
  );
  const [skipExpired, setSkipExpired] = useState(tenant?.skip_expired ?? true);
  const [syncInterval, setSyncInterval] = useState(
    String(tenant?.sync_interval_seconds ?? 60),
  );
  // #2138 — operator-entered token expiry (YYYY-MM-DD). Only the fallback:
  // a date Tailscale reports always wins on the server.
  const initialExpiresOn =
    tenant?.api_key_expires_at && tenant.api_key_expiry_source === "operator"
      ? tenant.api_key_expires_at.slice(0, 10)
      : "";
  const [expiresOn, setExpiresOn] = useState(initialExpiresOn);
  const expiryReadFromApi =
    editing && !apiKey && tenant?.api_key_expiry_source === "api";
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");

  const [testResult, setTestResult] = useState<TailscaleTestResult | null>(
    null,
  );

  const testMut = useMutation({
    mutationFn: () =>
      tailscaleApi.testConnection({
        tenant_id: tenant?.id,
        tailnet: tailnet || undefined,
        api_key: apiKey || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        tailnet_domain: null,
        device_count: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: TailscaleTenantUpdate = {
          name,
          description,
          enabled,
          tailnet,
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          cgnat_cidr: cgnatCidr,
          ipv6_cidr: ipv6Cidr,
          skip_expired: skipExpired,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (apiKey) {
          update.api_key = apiKey;
          update.api_key_expires_at = expiresOnToIso(expiresOn);
        } else if (!expiryReadFromApi && expiresOn !== initialExpiresOn) {
          update.api_key_expires_at = expiresOnToIso(expiresOn);
        }
        return tailscaleApi.updateTenant(tenant!.id, update);
      }
      const create: TailscaleTenantCreate = {
        name,
        description,
        enabled,
        tailnet,
        api_key: apiKey,
        api_key_expires_at: expiresOnToIso(expiresOn),
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        cgnat_cidr: cgnatCidr,
        ipv6_cidr: ipv6Cidr,
        skip_expired: skipExpired,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return tailscaleApi.createTenant(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tailscale-tenants"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save tenant")),
  });

  return (
    <Modal
      title={editing ? "Edit Tailscale Tenant" : "Add Tailscale Tenant"}
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
                Generate a personal-access token in the Tailscale admin console.
                The token inherits your user&apos;s permissions but SpatiumDDI
                only ever reads — never writes — to Tailscale.
              </p>
              <CopyablePre text={SETUP_KEY} label="Tailscale key setup" />
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

        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Tailnet"
            hint="Tailnet slug from the admin console, or '-' for the API key's default tailnet."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={tailnet}
              onChange={(e) => setTailnet(e.target.value)}
              placeholder="-"
              required
            />
          </Field>
          <Field label="API key">
            <input
              type="password"
              className={`${inputCls} font-mono text-[11px]`}
              value={apiKey}
              onChange={(e) => {
                const v = e.target.value;
                setApiKey(v);
                // Tailscale's maximum lifetime; the server replaces it with
                // the real expiry whenever Tailscale reports one. A date
                // entered for the OLD key says nothing about a new one, so
                // replacing the key resets it too; clearing the key again
                // puts the stored date back.
                if (!v) setExpiresOn(initialExpiresOn);
                else if (!expiresOn || expiresOn === initialExpiresOn)
                  setExpiresOn(dateInDays(90));
              }}
              placeholder={
                editing && tenant?.api_key_present
                  ? "••• stored — enter to replace"
                  : "tskey-api-..."
              }
              required={!editing}
            />
          </Field>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !tailnet || (!editing && !apiKey)}
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

        {expiryReadFromApi ? (
          <p className="text-[11px] text-muted-foreground">
            Token expires{" "}
            <span className="font-medium text-foreground">
              {fmtExpiry(
                tenant!.api_key_expires_at!,
                tenant!.api_key_expiry_source === "operator",
              )}
            </span>{" "}
            (read from Tailscale). Enter a new API key above to replace it.
          </p>
        ) : (
          <Field
            label="Token expires on (optional)"
            hint={
              testResult?.api_key_expires_at
                ? `Tailscale reports this token expires ${new Date(testResult.api_key_expires_at).toLocaleDateString()}; that date is used instead.`
                : "Read from Tailscale when it can be; this date is the fallback. Defaults to 90 days from today, Tailscale's maximum."
            }
          >
            <input
              type="date"
              className={inputCls}
              value={expiresOn}
              onChange={(e) => setExpiresOn(e.target.value)}
            />
          </Field>
        )}

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

        <div className="grid grid-cols-2 gap-3">
          <Field
            label="CGNAT IPv4 CIDR"
            hint="Tailscale assigns 100.64.0.0/10 by default. Override only if your tailnet uses a custom slice."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={cgnatCidr}
              onChange={(e) => setCgnatCidr(e.target.value)}
              placeholder="100.64.0.0/10"
              required
            />
          </Field>
          <Field
            label="IPv6 ULA CIDR"
            hint="Default fd7a:115c:a1e0::/48 — Tailscale's standard ULA prefix."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={ipv6Cidr}
              onChange={(e) => setIpv6Cidr(e.target.value)}
              placeholder="fd7a:115c:a1e0::/48"
              required
            />
          </Field>
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
              checked={skipExpired}
              onChange={(e) => setSkipExpired(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Skip expired devices</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Devices whose Tailscale node-key has expired are
                stale — they show in the admin console but can&apos;t actually
                reach the tailnet. Turn off to surface them in IPAM anyway
                (useful for capacity-planning views of churned hosts).
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

function DeleteTenantModal({
  tenant,
  onConfirm,
  onClose,
  isPending,
}: {
  tenant: TailscaleTenant;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete Tailscale Tenant" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the Tailscale tenant{" "}
          <span className="font-semibold">{tenant.name}</span>? This only
          affects SpatiumDDI — nothing on the Tailscale side changes. All IPAM
          rows mirrored from this tenant (the auto-created CGNAT block + IPv6
          ULA block + every device IP) will be removed via the FK cascade.
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

function dateInDays(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${mm}-${dd}`;
}

// An operator-entered expiry is stored as UTC midnight of the chosen day, so
// it must render in UTC or it reads a day early west of UTC (#2260). An
// expiry Tailscale reported is a real instant and renders in local time.
function fmtExpiry(iso: string, operatorDate: boolean): string {
  return new Date(iso).toLocaleDateString(
    undefined,
    operatorDate ? { timeZone: "UTC" } : undefined,
  );
}

// Start of the chosen day, UTC: erring early means warning early.
function expiresOnToIso(date: string): string | null {
  return date ? `${date}T00:00:00Z` : null;
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
