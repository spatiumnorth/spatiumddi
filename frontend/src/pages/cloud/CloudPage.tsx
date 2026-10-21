import { useModuleOn } from "@/hooks/useModuleOn";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import { pollUnlessRefused } from "@/lib/refusal";
import {
  Check,
  Cloud,
  Clipboard,
  Pencil,
  Plus,
  RefreshCw,
  RotateCw,
  TestTube2,
  Trash2,
} from "lucide-react";

import {
  cloudApi,
  dnsApi,
  type CloudEndpoint,
  type CloudEndpointCreate,
  type CloudEndpointUpdate,
  type CloudProvider,
  type CloudTestResult,
  type DNSServerGroup,
} from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { IPSpacePicker } from "@/components/ipam/space-picker";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import { secondsFieldError, CLOUD_SYNC_INTERVAL_BOUNDS } from "@/lib/seconds";

// ── Provider metadata ───────────────────────────────────────────────

const PROVIDER_LABEL: Record<CloudProvider, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
};

// Setup guides — one-shot snippets operators paste into a shell to mint
// the read-only credential each provider's reconciler needs.

const AWS_GUIDE = `# In the AWS console (or via the CLI):
#
# 1. Create a dedicated IAM user for SpatiumDDI (no console access).
# 2. Attach these AWS-managed, read-only policies:
#      - AmazonVPCReadOnlyAccess
#      - AmazonEC2ReadOnlyAccess
#      - ElasticLoadBalancingReadOnly   (only if mirroring load balancers)
# 3. Generate an access key for the user and paste both halves below.
#
# CLI equivalent:
aws iam create-user --user-name spatiumddi
aws iam attach-user-policy --user-name spatiumddi \\
  --policy-arn arn:aws:iam::aws:policy/AmazonVPCReadOnlyAccess
aws iam attach-user-policy --user-name spatiumddi \\
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess
aws iam attach-user-policy --user-name spatiumddi \\
  --policy-arn arn:aws:iam::aws:policy/ElasticLoadBalancingReadOnly
aws iam create-access-key --user-name spatiumddi
#   Prints AccessKeyId + SecretAccessKey — paste them below.`;

const AZURE_GUIDE = `# Create a service principal with the read-only "Reader" role,
# scoped to each subscription you want SpatiumDDI to mirror:

az ad sp create-for-rbac --name spatiumddi --role Reader \\
  --scopes /subscriptions/<sub-id>

#   Prints:
#     {
#       "appId":    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",  → Client ID
#       "password": "xxxxxxxx~xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  → Client Secret
#       "tenant":   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   → Tenant ID
#     }
#
# Paste appId → Client ID, password → Client Secret, tenant → Tenant ID.
# List the subscription IDs (comma-separated) in "Subscription IDs".`;

const GCP_GUIDE = `# Create a service account, grant it the read-only Compute Viewer
# role on each project, and download a JSON key:

gcloud iam service-accounts create spatiumddi \\
  --display-name "SpatiumDDI"

gcloud projects add-iam-policy-binding <project-id> \\
  --member "serviceAccount:spatiumddi@<project-id>.iam.gserviceaccount.com" \\
  --role roles/compute.viewer

gcloud iam service-accounts keys create key.json \\
  --iam-account spatiumddi@<project-id>.iam.gserviceaccount.com

# Paste the full contents of key.json into "Service account JSON".
# List the project IDs (comma-separated) in "Project IDs".`;

// ── Page ─────────────────────────────────────────────────────────────

export function CloudPage() {
  // #1340 — every write on this integration takes a superadmin (its
  // router's create / update / delete / sync / test handlers take
  // SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: endpoints = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["cloud-endpoints"],
    queryFn: cloudApi.listEndpoints,
    refetchInterval: pollUnlessRefused(30_000),
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<CloudEndpoint | null>(null);
  const [del, setDel] = useState<CloudEndpoint | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, CloudTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => cloudApi.deleteEndpoint(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cloud-endpoints"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => cloudApi.testConnection({ endpoint_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["cloud-endpoints"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => cloudApi.syncNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cloud-endpoints"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["cloud-endpoints"] }),
        5000,
      );
    },
  });

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="border-b px-6 py-4 bg-card">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Cloud className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Cloud</h1>
              <span className="text-xs text-muted-foreground">
                {endpoints.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each account is polled with a read-only
              credential (AWS / Azure / GCP). VPCs / VNets / GCP networks land
              in the bound IPAM space as subnets; instances land as IP addresses
              (private and, optionally, public). SpatiumDDI never writes to the
              cloud provider.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["cloud-endpoints"] })
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
              Add account
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {endpoints.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="cloud accounts">
                  No cloud accounts configured yet.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> Add account
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1020px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Enabled
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Name
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Provider
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Account
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Networks
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Instances
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Last sync
                    </th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((ep) => {
                    const tr = inlineTest[ep.id];
                    return (
                      <tr key={ep.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2">
                          {ep.enabled ? (
                            <span className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
                              enabled
                            </span>
                          ) : (
                            <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                              disabled
                            </span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          {ep.name}
                          {ep.description && (
                            <div
                              className="text-[11px] text-muted-foreground max-w-md truncate"
                              title={ep.description}
                            >
                              {ep.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {PROVIDER_LABEL[ep.provider]}
                        </td>
                        <td
                          className="max-w-xs truncate px-3 py-2 font-mono text-[11px] text-muted-foreground"
                          title={ep.provider_account_id ?? undefined}
                        >
                          {ep.provider_account_id ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {ep.network_count ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {ep.instance_count ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {ep.last_synced_at
                            ? new Date(ep.last_synced_at).toLocaleString()
                            : "never"}
                          {ep.last_sync_error && (
                            <div
                              className="text-[11px] text-destructive max-w-xs truncate"
                              title={ep.last_sync_error}
                            >
                              {ep.last_sync_error}
                            </div>
                          )}
                          {tr && (
                            <div
                              className={`max-w-xs truncate text-[11px] ${
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
                            onClick={() => testMut.mutate(ep.id)}
                            disabled={
                              testMut.isPending && testMut.variables === ep.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Test connection"
                            {...superadminGate}
                          >
                            <TestTube2 className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => syncMut.mutate(ep.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === ep.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync now"
                            {...superadminGate}
                          >
                            <RotateCw
                              className={`h-3.5 w-3.5 ${
                                syncMut.isPending && syncMut.variables === ep.id
                                  ? "animate-spin"
                                  : ""
                              }`}
                            />
                          </button>
                          <button
                            onClick={() => setEdit(ep)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                            title="Edit"
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(ep)}
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

      {showCreate && <EndpointModal onClose={() => setShowCreate(false)} />}
      {edit && <EndpointModal endpoint={edit} onClose={() => setEdit(null)} />}
      <ConfirmModal
        open={!!del}
        title="Delete cloud account"
        confirmLabel="Delete"
        tone="destructive"
        loading={delMut.isPending}
        onConfirm={() => del && delMut.mutate(del.id)}
        onClose={() => setDel(null)}
        message={
          del ? (
            <>
              Remove the cloud account{" "}
              <span className="font-semibold">{del.name}</span>? This only
              affects SpatiumDDI — nothing on the {PROVIDER_LABEL[del.provider]}{" "}
              side changes. Only rows that were purely mirrored are removed.
              Anything you added yourself (addresses, DHCP scopes, reservations,
              edited rows, custom fields) is kept and detached from this
              integration.
            </>
          ) : (
            ""
          )
        }
      />
    </div>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function EndpointModal({
  endpoint,
  onClose,
}: {
  endpoint?: CloudEndpoint;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!endpoint;

  // DNS off (#2135): no /dns/groups read and no picker. The stored
  // dns_group_id is sent back untouched, so saving here cannot clear it.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: dnsOn,
  });

  const [provider, setProvider] = useState<CloudProvider>(
    endpoint?.provider ?? "aws",
  );
  const [name, setName] = useState(endpoint?.name ?? "");
  const [description, setDescription] = useState(endpoint?.description ?? "");
  const [enabled, setEnabled] = useState(endpoint?.enabled ?? true);
  const [spaceId, setSpaceId] = useState(endpoint?.ipam_space_id ?? "");
  const [publicSpaceId, setPublicSpaceId] = useState(
    endpoint?.public_space_id ?? "",
  );
  const [dnsGroupId, setDnsGroupId] = useState(endpoint?.dns_group_id ?? "");
  const [regions, setRegions] = useState((endpoint?.regions ?? []).join(", "));
  const [mirrorLoadBalancers, setMirrorLoadBalancers] = useState(
    endpoint?.mirror_load_balancers ?? true,
  );
  const [mirrorStoppedInstances, setMirrorStoppedInstances] = useState(
    endpoint?.mirror_stopped_instances ?? false,
  );
  const [syncInterval, setSyncInterval] = useState(
    String(endpoint?.sync_interval_seconds ?? 300),
  );

  // AWS credentials
  const [awsAccessKeyId, setAwsAccessKeyId] = useState("");
  const [awsSecretAccessKey, setAwsSecretAccessKey] = useState("");

  // Azure credentials + config
  const [azTenantId, setAzTenantId] = useState("");
  const [azClientId, setAzClientId] = useState("");
  const [azClientSecret, setAzClientSecret] = useState("");
  const [azSubscriptionIds, setAzSubscriptionIds] = useState(
    providerConfigList(endpoint?.provider_config, "subscription_ids"),
  );

  // GCP credentials + config
  const [gcpServiceAccountJson, setGcpServiceAccountJson] = useState("");
  const [gcpProjectIds, setGcpProjectIds] = useState(
    providerConfigList(endpoint?.provider_config, "project_ids"),
  );

  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");
  const [testResult, setTestResult] = useState<CloudTestResult | null>(null);

  const credsStored = editing && endpoint?.credentials_present;
  const credPlaceholder = credsStored
    ? "••• stored — leave blank to keep"
    : undefined;

  // Build the credential dict from the active provider's form fields.
  // Returns {} when nothing was typed (editing: keep stored creds).
  function buildCredentials(): Record<string, string> {
    if (provider === "aws") {
      const c: Record<string, string> = {};
      if (awsAccessKeyId) c.access_key_id = awsAccessKeyId;
      if (awsSecretAccessKey) c.secret_access_key = awsSecretAccessKey;
      return c;
    }
    if (provider === "azure") {
      const c: Record<string, string> = {};
      if (azTenantId) c.tenant_id = azTenantId;
      if (azClientId) c.client_id = azClientId;
      if (azClientSecret) c.client_secret = azClientSecret;
      return c;
    }
    const c: Record<string, string> = {};
    if (gcpServiceAccountJson) c.service_account_json = gcpServiceAccountJson;
    return c;
  }

  function buildProviderConfig(): Record<string, unknown> {
    if (provider === "azure") {
      return { subscription_ids: parseCsv(azSubscriptionIds) };
    }
    if (provider === "gcp") {
      return { project_ids: parseCsv(gcpProjectIds) };
    }
    return {};
  }

  const testMut = useMutation({
    mutationFn: () =>
      cloudApi.testConnection({
        endpoint_id: endpoint?.id,
        provider,
        credentials: buildCredentials(),
        provider_config: buildProviderConfig(),
        regions: parseCsv(regions),
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        provider_account_id: null,
        network_count: null,
        instance_count: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      const creds = buildCredentials();
      if (editing) {
        const update: CloudEndpointUpdate = {
          name,
          description,
          enabled,
          provider_config: buildProviderConfig(),
          regions: parseCsv(regions),
          ipam_space_id: spaceId,
          public_space_id: publicSpaceId || null,
          dns_group_id: dnsGroupId || null,
          mirror_load_balancers: mirrorLoadBalancers,
          mirror_stopped_instances: mirrorStoppedInstances,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (Object.keys(creds).length > 0) update.credentials = creds;
        return cloudApi.updateEndpoint(endpoint!.id, update);
      }
      const create: CloudEndpointCreate = {
        name,
        description,
        enabled,
        provider,
        credentials: creds,
        provider_config: buildProviderConfig(),
        regions: parseCsv(regions),
        ipam_space_id: spaceId,
        public_space_id: publicSpaceId || null,
        dns_group_id: dnsGroupId || null,
        mirror_load_balancers: mirrorLoadBalancers,
        mirror_stopped_instances: mirrorStoppedInstances,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return cloudApi.createEndpoint(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cloud-endpoints"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save account")),
  });

  // Whether enough is filled in to enable Test. On create we need
  // credentials; on edit we can test stored creds.
  const credsFilled = Object.keys(buildCredentials()).length > 0;
  const canTest = editing ? true : credsFilled;

  const guide =
    provider === "aws"
      ? AWS_GUIDE
      : provider === "azure"
        ? AZURE_GUIDE
        : GCP_GUIDE;

  return (
    <Modal
      title={editing ? "Edit cloud account" : "Add cloud account"}
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
            CLOUD_SYNC_INTERVAL_BOUNDS,
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
        {/* Provider FIRST */}
        <Field
          label="Provider"
          hint={
            editing ? "Provider can't be changed after creation." : undefined
          }
        >
          <select
            className={`${inputCls} disabled:opacity-60`}
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value as CloudProvider);
              setTestResult(null);
            }}
            disabled={editing}
          >
            <option value="aws">AWS</option>
            <option value="azure">Azure</option>
            <option value="gcp">GCP</option>
          </select>
        </Field>

        {/* Setup guide — provider-specific */}
        <div className="rounded-md border bg-muted/30 p-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">
              Setup guide — {PROVIDER_LABEL[provider]}
            </h3>
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
                Create a read-only credential. SpatiumDDI only ever reads from{" "}
                {PROVIDER_LABEL[provider]} — it never writes.
              </p>
              <CopyablePre
                text={guide}
                label={`${PROVIDER_LABEL[provider]} setup`}
              />
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

        {/* ── Provider-specific credential form ───────────────────── */}
        <div className="space-y-3 border-t pt-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Credentials
          </h3>

          {provider === "aws" && (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Access key ID">
                <input
                  className={`${inputCls} font-mono text-[11px]`}
                  value={awsAccessKeyId}
                  onChange={(e) => setAwsAccessKeyId(e.target.value)}
                  placeholder={credPlaceholder ?? "AKIA…"}
                  autoComplete="off"
                  required={!editing}
                />
              </Field>
              <Field label="Secret access key">
                <input
                  type="password"
                  className={`${inputCls} font-mono text-[11px]`}
                  value={awsSecretAccessKey}
                  onChange={(e) => setAwsSecretAccessKey(e.target.value)}
                  placeholder={credPlaceholder}
                  autoComplete="off"
                  required={!editing}
                />
              </Field>
            </div>
          )}

          {provider === "azure" && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Tenant ID">
                  <input
                    className={`${inputCls} font-mono text-[11px]`}
                    value={azTenantId}
                    onChange={(e) => setAzTenantId(e.target.value)}
                    placeholder={credPlaceholder ?? "xxxxxxxx-xxxx-…"}
                    autoComplete="off"
                    required={!editing}
                  />
                </Field>
                <Field label="Client ID (appId)">
                  <input
                    className={`${inputCls} font-mono text-[11px]`}
                    value={azClientId}
                    onChange={(e) => setAzClientId(e.target.value)}
                    placeholder={credPlaceholder ?? "xxxxxxxx-xxxx-…"}
                    autoComplete="off"
                    required={!editing}
                  />
                </Field>
              </div>
              <Field label="Client secret (password)">
                <input
                  type="password"
                  className={`${inputCls} font-mono text-[11px]`}
                  value={azClientSecret}
                  onChange={(e) => setAzClientSecret(e.target.value)}
                  placeholder={credPlaceholder}
                  autoComplete="off"
                  required={!editing}
                />
              </Field>
              <Field
                label="Subscription IDs"
                hint="Comma-separated. The reconciler enumerates VNets across these subscriptions."
              >
                <input
                  className={`${inputCls} font-mono text-[11px]`}
                  value={azSubscriptionIds}
                  onChange={(e) => setAzSubscriptionIds(e.target.value)}
                  placeholder="xxxxxxxx-xxxx-…, yyyyyyyy-yyyy-…"
                  required
                />
              </Field>
            </>
          )}

          {provider === "gcp" && (
            <>
              <Field
                label="Service account JSON"
                hint="Paste the entire downloaded key file."
              >
                <textarea
                  className={`${inputCls} font-mono text-[11px]`}
                  rows={5}
                  value={gcpServiceAccountJson}
                  onChange={(e) => setGcpServiceAccountJson(e.target.value)}
                  placeholder={
                    credPlaceholder ??
                    '{\n  "type": "service_account",\n  ...\n}'
                  }
                  required={!editing}
                />
              </Field>
              <Field
                label="Project IDs"
                hint="Comma-separated. The reconciler enumerates networks across these projects."
              >
                <input
                  className={`${inputCls} font-mono text-[11px]`}
                  value={gcpProjectIds}
                  onChange={(e) => setGcpProjectIds(e.target.value)}
                  placeholder="my-project, my-other-project"
                  required
                />
              </Field>
            </>
          )}

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => testMut.mutate()}
              disabled={testMut.isPending || !canTest}
              className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
            >
              <TestTube2 className="h-3.5 w-3.5" />
              {testMut.isPending ? "Testing…" : "Test connection"}
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
        </div>

        {/* ── Mirror destination ──────────────────────────────────── */}
        <div className="grid grid-cols-2 gap-3 border-t pt-3">
          <Field label="IPAM space">
            <IPSpacePicker value={spaceId} onChange={setSpaceId} required />
          </Field>
          <Field
            label="Public IPAM space (optional)"
            hint="Where public IPs land. Leave blank to skip public IP mirroring."
          >
            <IPSpacePicker value={publicSpaceId} onChange={setPublicSpaceId} />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
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
          <Field
            label="Regions"
            hint="Comma-separated. Leave blank to use the provider default region set."
          >
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={regions}
              onChange={(e) => setRegions(e.target.value)}
              placeholder="us-east-1, eu-west-1"
            />
          </Field>
        </div>

        <Field label="Sync interval (seconds)" hint="Minimum 60 s.">
          <input
            type="number"
            className={inputCls}
            value={syncInterval}
            min={60}
            onChange={(e) => setSyncInterval(e.target.value)}
          />
        </Field>

        <div className="space-y-2 border-t pt-2">
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorLoadBalancers}
              onChange={(e) => setMirrorLoadBalancers(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror load balancers</span>
              <p className="text-[11px] text-muted-foreground/70">
                On by default. ELB / Azure LB / GCP forwarding-rule frontends
                land in IPAM as addresses.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorStoppedInstances}
              onChange={(e) => setMirrorStoppedInstances(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Include stopped instances</span>
              <p className="text-[11px] text-muted-foreground/70">
                Off by default. Only running instances land in IPAM unless
                enabled — useful for capacity-planning views.
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

// ── Helpers ─────────────────────────────────────────────────────────

function parseCsv(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function providerConfigList(
  config: Record<string, unknown> | undefined,
  key: string,
): string {
  const v = config?.[key];
  if (Array.isArray(v)) return v.map((x) => String(x)).join(", ");
  return "";
}

function CopyablePre({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  // Reset the "Copied" flash if the snippet changes (e.g. provider swap).
  useEffect(() => setCopied(false), [text]);
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
