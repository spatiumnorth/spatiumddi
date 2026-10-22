import { useModuleOn } from "@/hooks/useModuleOn";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  Bird,
  Check,
  Clipboard,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  TestTube2,
  RotateCw,
} from "lucide-react";

import {
  netbirdApi,
  dnsApi,
  type DNSServerGroup,
  type NetbirdInstance,
  type NetbirdInstanceCreate,
  type NetbirdInstanceUpdate,
  type NetbirdTestResult,
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
// One-shot notes operators follow to mint a read-only NetBird token.

const SETUP_KEY = `# Generate a NetBird API token (personal-access token):
#
# 1. Open your NetBird dashboard → Settings → Users
#    (cloud: https://app.netbird.io/users)
# 2. Select your user (or create a dedicated service user with a
#    read-only role) and add an Access Token — give it a name +
#    expiry.
# 3. Copy the printed token (starts with "nbp_"). It is shown once.
#
# Management URL:
#   Cloud:        https://api.netbird.io
#   Self-hosted:  your dashboard/management host,
#                 e.g. https://netbird.example.com
#
# The token reads the peer inventory; SpatiumDDI never writes to
# NetBird. For a self-hosted install with a private-CA / self-signed
# certificate, untick "Verify TLS".`;

// ── Page ─────────────────────────────────────────────────────────────

export function NetbirdPage() {
  // #1340 — every write on this integration takes a superadmin (its
  // router's create / update / delete / sync / test handlers take
  // SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: instances = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["netbird-instances"],
    queryFn: netbirdApi.listInstances,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<NetbirdInstance | null>(null);
  const [del, setDel] = useState<NetbirdInstance | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, NetbirdTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => netbirdApi.deleteInstance(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["netbird-instances"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => netbirdApi.testConnection({ instance_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["netbird-instances"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => netbirdApi.syncNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["netbird-instances"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["netbird-instances"] }),
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
              <Bird className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">NetBird Instances</h1>
              <span className="text-xs text-muted-foreground">
                {instances.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each instance is polled via the NetBird
              management API with a personal-access token. The overlay
              <code className="font-mono"> 100.64.0.0/10</code> block is
              auto-created under the bound IPAM space, and every mesh
              peer&apos;s address lands as an IP row with OS, version, groups,
              and connection state in custom fields. Bind a DNS group to also
              mirror the mesh&apos;s DNS domain as a read-only zone. SpatiumDDI
              never writes to NetBird.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["netbird-instances"] })
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
              Add Instance
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {instances.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="NetBird instances">
                  No NetBird instances configured yet.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> Add Instance
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
                      Management URL
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Domain
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Peers
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
                  {instances.map((t) => {
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
                          {t.api_url}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground font-mono text-[11px]">
                          {t.dns_domain ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {t.peer_count ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {t.last_synced_at
                            ? new Date(t.last_synced_at).toLocaleString()
                            : "never"}
                          {t.last_sync_error && (
                            <div
                              className="text-[11px] text-destructive max-w-xs truncate"
                              title={t.last_sync_error}
                            >
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

      {showCreate && <InstanceModal onClose={() => setShowCreate(false)} />}
      {edit && <InstanceModal instance={edit} onClose={() => setEdit(null)} />}
      {del && (
        <DeleteInstanceModal
          instance={del}
          onClose={() => setDel(null)}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function InstanceModal({
  instance,
  onClose,
}: {
  instance?: NetbirdInstance;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!instance;

  // DNS off (#2135): no /dns/groups read and no picker. The stored
  // dns_group_id is sent back untouched, so saving here cannot clear it.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: dnsOn,
  });

  const [name, setName] = useState(instance?.name ?? "");
  const [description, setDescription] = useState(instance?.description ?? "");
  const [enabled, setEnabled] = useState(instance?.enabled ?? true);
  const [apiUrl, setApiUrl] = useState(
    instance?.api_url ?? "https://api.netbird.io",
  );
  const [verifyTls, setVerifyTls] = useState(instance?.verify_tls ?? true);
  const [apiKey, setApiKey] = useState("");
  const [spaceId, setSpaceId] = useState(instance?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(instance?.dns_group_id ?? "");
  const [networkCidr, setNetworkCidr] = useState(
    instance?.network_cidr ?? "100.64.0.0/10",
  );
  const [skipExpired, setSkipExpired] = useState(
    instance?.skip_expired ?? true,
  );
  const [syncInterval, setSyncInterval] = useState(
    String(instance?.sync_interval_seconds ?? 60),
  );
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");

  const [testResult, setTestResult] = useState<NetbirdTestResult | null>(null);

  const testMut = useMutation({
    mutationFn: () =>
      netbirdApi.testConnection({
        instance_id: instance?.id,
        api_url: apiUrl || undefined,
        verify_tls: verifyTls,
        api_key: apiKey || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        dns_domain: null,
        peer_count: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: NetbirdInstanceUpdate = {
          name,
          description,
          enabled,
          api_url: apiUrl,
          verify_tls: verifyTls,
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          network_cidr: networkCidr,
          skip_expired: skipExpired,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (apiKey) update.api_key = apiKey;
        return netbirdApi.updateInstance(instance!.id, update);
      }
      const create: NetbirdInstanceCreate = {
        name,
        description,
        enabled,
        api_url: apiUrl,
        verify_tls: verifyTls,
        api_key: apiKey,
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        network_cidr: networkCidr,
        skip_expired: skipExpired,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return netbirdApi.createInstance(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["netbird-instances"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save instance")),
  });

  return (
    <Modal
      title={editing ? "Edit NetBird Instance" : "Add NetBird Instance"}
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
                Generate a personal-access token in the NetBird dashboard. The
                token reads the peer inventory; SpatiumDDI only ever reads —
                never writes — to NetBird.
              </p>
              <CopyablePre text={SETUP_KEY} label="NetBird token setup" />
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
            label="Management URL"
            hint="Cloud: https://api.netbird.io — or your self-hosted dashboard host."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              placeholder="https://api.netbird.io"
              required
            />
          </Field>
          <Field label="API token">
            <input
              type="password"
              className={`${inputCls} font-mono text-[11px]`}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={
                editing && instance?.api_key_present
                  ? "••• stored — enter to replace"
                  : "nbp_..."
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
              On by default. Untick for a self-hosted management server using a
              private-CA or self-signed certificate.
            </p>
          </div>
        </label>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !apiUrl || (!editing && !apiKey)}
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

        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Overlay CIDR"
            hint="NetBird allocates peer IPs from 100.64.0.0/10 by default. Override only if your mesh uses a custom range."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={networkCidr}
              onChange={(e) => setNetworkCidr(e.target.value)}
              placeholder="100.64.0.0/10"
              required
            />
          </Field>
          <Field label="Sync interval (seconds)" hint="Minimum 30 s.">
            <input
              type="number"
              className={inputCls}
              value={syncInterval}
              min={30}
              onChange={(e) => setSyncInterval(e.target.value)}
            />
          </Field>
        </div>

        <div className="space-y-2 border-t pt-2">
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={skipExpired}
              onChange={(e) => setSkipExpired(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Skip login-expired peers</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. Peers whose NetBird login has expired can&apos;t
                reach the mesh. Turn off to surface them in IPAM anyway (useful
                for capacity-planning views of churned hosts).
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

function DeleteInstanceModal({
  instance,
  onConfirm,
  onClose,
  isPending,
}: {
  instance: NetbirdInstance;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete NetBird Instance" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the NetBird instance{" "}
          <span className="font-semibold">{instance.name}</span>? This only
          affects SpatiumDDI — nothing on the NetBird side changes. All IPAM
          rows mirrored from this instance (the auto-created overlay block +
          subnet + every peer IP, plus any synthetic DNS zone) will be removed
          via the FK cascade.
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
