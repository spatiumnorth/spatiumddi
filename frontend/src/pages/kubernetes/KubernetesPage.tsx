import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Boxes,
  Check,
  Clipboard,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  TestTube2,
  RotateCw,
  Wand2,
} from "lucide-react";

import {
  dnsApi,
  kubernetesApi,
  type DNSServerGroup,
  type KubernetesCluster,
  type KubernetesClusterCreate,
  type KubernetesClusterUpdate,
  type KubernetesDetectCIDRsResult,
  type KubernetesTestResult,
} from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { IPSpacePicker } from "@/components/ipam/space-picker";

// ── Setup guide ─────────────────────────────────────────────────────
// Shown in the create modal so operators know what to run on their
// cluster. Plain text — the YAML + kubectl commands are copy-paste
// safe. Lives here rather than a separate Markdown file so we can keep
// it in lock-step with the ClusterRole the backend expects.

const SETUP_YAML = `# Run on your cluster (cluster-admin context):
apiVersion: v1
kind: Namespace
metadata: { name: spatiumddi }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: spatiumddi-reader, namespace: spatiumddi }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: spatiumddi-reader }
rules:
  - apiGroups: [""]
    resources: ["nodes", "services", "namespaces", "pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "servicecidrs"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: spatiumddi-reader }
subjects:
  - kind: ServiceAccount
    name: spatiumddi-reader
    namespace: spatiumddi
roleRef:
  kind: ClusterRole
  name: spatiumddi-reader
  apiGroup: rbac.authorization.k8s.io
---
# Non-expiring token (k8s 1.24+)
apiVersion: v1
kind: Secret
metadata:
  name: spatiumddi-reader-token
  namespace: spatiumddi
  annotations:
    kubernetes.io/service-account.name: spatiumddi-reader
type: kubernetes.io/service-account-token`;

const EXTRACT_COMMANDS = `# Extract the bearer token:
kubectl -n spatiumddi get secret spatiumddi-reader-token \\
  -o jsonpath='{.data.token}' | base64 -d

# Extract the CA bundle:
kubectl -n spatiumddi get secret spatiumddi-reader-token \\
  -o jsonpath='{.data.ca\\.crt}' | base64 -d

# The API server URL:
kubectl cluster-info | head -1`;

// ── Page ─────────────────────────────────────────────────────────────

export function KubernetesPage() {
  const qc = useQueryClient();
  const { data: clusters = [], isFetching } = useQuery({
    queryKey: ["kubernetes-clusters"],
    queryFn: kubernetesApi.listClusters,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<KubernetesCluster | null>(null);
  const [del, setDel] = useState<KubernetesCluster | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, KubernetesTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => kubernetesApi.deleteCluster(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["kubernetes-clusters"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) =>
      kubernetesApi.testConnection({ cluster_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["kubernetes-clusters"] });
    },
  });

  // "Sync Now" — queues the reconciler for this cluster. Fire-and-
  // forget; the list endpoint will pick up updated last_synced_at on
  // the next poll (we refetch a few seconds later to catch the
  // completed state).
  const syncMut = useMutation({
    mutationFn: (id: string) => kubernetesApi.syncNow(id),
    onSuccess: () => {
      // Immediate invalidate so the row shows "syncing…", then a
      // delayed refetch so the new last_synced_at / error show up
      // after the worker finishes.
      qc.invalidateQueries({ queryKey: ["kubernetes-clusters"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["kubernetes-clusters"] }),
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
              <Boxes className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Kubernetes Clusters</h1>
              <span className="text-xs text-muted-foreground">
                {clusters.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each cluster is polled by SpatiumDDI;
              LoadBalancer VIPs, Node IPs, and Ingress hostnames land in the
              bound IPAM space and DNS group. SpatiumDDI never writes to the
              cluster.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["kubernetes-clusters"] })
              }
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowCreate(true)}
            >
              Add Cluster
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {clusters.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                No clusters configured yet.
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
              >
                <Plus className="h-3 w-3" /> Add Cluster
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1120px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Name
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Enabled
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      API Server
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Version
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Nodes
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Pod CIDR
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Service CIDR
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
                  {clusters.map((c) => {
                    const tr = inlineTest[c.id];
                    return (
                      <tr key={c.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          {c.name}
                          {c.description && (
                            <div
                              className="text-[11px] text-muted-foreground max-w-md truncate"
                              title={c.description}
                            >
                              {c.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {c.enabled ? (
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
                          title={c.api_server_url}
                        >
                          {c.api_server_url}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {c.cluster_version ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {c.node_count ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                          {c.pod_cidr || (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                          {c.service_cidr || (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {c.last_synced_at
                            ? new Date(c.last_synced_at).toLocaleString()
                            : "never"}
                          {c.last_sync_error && (
                            <div
                              className="text-[11px] text-destructive max-w-xs truncate"
                              title={c.last_sync_error}
                            >
                              {c.last_sync_error}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <button
                            onClick={() => testMut.mutate(c.id)}
                            disabled={testMut.isPending}
                            className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
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
                            onClick={() => syncMut.mutate(c.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === c.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
                          >
                            <RotateCw
                              className={`h-3.5 w-3.5 ${
                                syncMut.isPending && syncMut.variables === c.id
                                  ? "animate-spin"
                                  : ""
                              }`}
                            />
                          </button>
                          <button
                            onClick={() => setEdit(c)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground"
                            title="Edit"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(c)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive"
                            title="Delete"
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

      {showCreate && <ClusterModal onClose={() => setShowCreate(false)} />}
      {edit && <ClusterModal cluster={edit} onClose={() => setEdit(null)} />}
      {del && (
        <DeleteClusterModal
          cluster={del}
          onClose={() => setDel(null)}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function ClusterModal({
  cluster,
  onClose,
}: {
  cluster?: KubernetesCluster;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!cluster;

  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });

  const [name, setName] = useState(cluster?.name ?? "");
  const [description, setDescription] = useState(cluster?.description ?? "");
  const [enabled, setEnabled] = useState(cluster?.enabled ?? true);
  const [apiServerUrl, setApiServerUrl] = useState(
    cluster?.api_server_url ?? "",
  );
  const [caBundlePem, setCaBundlePem] = useState("");
  const [token, setToken] = useState("");
  const [spaceId, setSpaceId] = useState(cluster?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(cluster?.dns_group_id ?? "");
  const [podCidr, setPodCidr] = useState(cluster?.pod_cidr ?? "");
  const [serviceCidr, setServiceCidr] = useState(cluster?.service_cidr ?? "");
  const [syncInterval, setSyncInterval] = useState(
    cluster?.sync_interval_seconds ?? 60,
  );
  const [mirrorPods, setMirrorPods] = useState(cluster?.mirror_pods ?? false);
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");

  const [testResult, setTestResult] = useState<KubernetesTestResult | null>(
    null,
  );
  const [detectResult, setDetectResult] =
    useState<KubernetesDetectCIDRsResult | null>(null);

  const testMut = useMutation({
    mutationFn: () =>
      kubernetesApi.testConnection({
        cluster_id: cluster?.id,
        api_server_url: apiServerUrl || undefined,
        ca_bundle_pem: caBundlePem || undefined,
        token: token || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        version: null,
        node_count: null,
      }),
  });

  const detectMut = useMutation({
    mutationFn: () =>
      kubernetesApi.detectCidrs({
        cluster_id: cluster?.id,
        api_server_url: apiServerUrl || undefined,
        ca_bundle_pem: caBundlePem || undefined,
        token: token || undefined,
      }),
    onSuccess: (result) => {
      setDetectResult(result);
      // Only overwrite empty fields so the operator's typed value
      // wins if they've already entered one.
      if (result.pod_cidr && !podCidr) setPodCidr(result.pod_cidr);
      if (result.service_cidr && !serviceCidr)
        setServiceCidr(result.service_cidr);
    },
    onError: (e) =>
      setDetectResult({
        pod_cidr: null,
        service_cidr: null,
        messages: [errMsg(e, "Detection failed")],
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: KubernetesClusterUpdate = {
          name,
          description,
          enabled,
          api_server_url: apiServerUrl,
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          pod_cidr: podCidr,
          service_cidr: serviceCidr,
          sync_interval_seconds: syncInterval,
          mirror_pods: mirrorPods,
        };
        if (caBundlePem) update.ca_bundle_pem = caBundlePem;
        if (token) update.token = token;
        return kubernetesApi.updateCluster(cluster!.id, update);
      }
      if (!token) {
        throw new Error("Bearer token is required");
      }
      const create: KubernetesClusterCreate = {
        name,
        description,
        enabled,
        api_server_url: apiServerUrl,
        ca_bundle_pem: caBundlePem,
        token,
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        pod_cidr: podCidr,
        service_cidr: serviceCidr,
        sync_interval_seconds: syncInterval,
        mirror_pods: mirrorPods,
      };
      return kubernetesApi.createCluster(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["kubernetes-clusters"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save cluster")),
  });

  return (
    <Modal
      title={editing ? "Edit Kubernetes Cluster" : "Add Kubernetes Cluster"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
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
                SpatiumDDI connects to Kubernetes with a read-only
                ServiceAccount. Apply this YAML on your cluster (requires
                cluster-admin):
              </p>
              <CopyablePre text={SETUP_YAML} label="YAML" />
              <p className="text-muted-foreground">
                Then extract the values to paste below:
              </p>
              <CopyablePre text={EXTRACT_COMMANDS} label="commands" />
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

        <Field label="API server URL" hint="e.g. https://k8s.example.com:6443">
          <input
            className={inputCls}
            value={apiServerUrl}
            onChange={(e) => setApiServerUrl(e.target.value)}
            placeholder="https://..."
            required
          />
        </Field>

        <Field
          label="CA bundle (PEM)"
          hint="Leave blank to trust the system CA store (cloud-managed clusters)."
        >
          <textarea
            className={`${inputCls} font-mono text-[11px]`}
            rows={4}
            value={caBundlePem}
            onChange={(e) => setCaBundlePem(e.target.value)}
            placeholder={
              editing && cluster?.ca_bundle_present
                ? "••• stored — paste to replace"
                : "-----BEGIN CERTIFICATE-----\n..."
            }
          />
        </Field>

        <Field
          label="Bearer token"
          hint={
            editing && cluster?.token_present
              ? "Stored. Leave blank to keep the existing token."
              : "Service account token (single line)."
          }
        >
          <textarea
            className={`${inputCls} font-mono text-[11px]`}
            rows={2}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={
              editing && cluster?.token_present ? "••• stored" : "eyJhbGciOi..."
            }
          />
        </Field>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending}
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
              {testResult.node_count !== null &&
                ` · ${testResult.node_count} node${testResult.node_count === 1 ? "" : "s"}`}
            </span>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3 border-t pt-3">
          <Field label="IPAM space">
            <IPSpacePicker value={spaceId} onChange={setSpaceId} required />
          </Field>
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
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">
              Pod / Service CIDRs
            </span>
            <button
              type="button"
              onClick={() => detectMut.mutate()}
              disabled={detectMut.isPending || (!apiServerUrl && !cluster?.id)}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] hover:bg-accent disabled:opacity-50"
              title="Probe the cluster for pod and service CIDRs"
            >
              <Wand2 className="h-3 w-3" />
              {detectMut.isPending ? "Detecting…" : "Auto-detect"}
            </button>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Pod CIDR" hint="e.g. 10.244.0.0/16">
              <input
                className={`${inputCls} font-mono`}
                value={podCidr}
                onChange={(e) => setPodCidr(e.target.value)}
                placeholder="10.244.0.0/16"
              />
            </Field>
            <Field label="Service CIDR" hint="e.g. 10.96.0.0/12">
              <input
                className={`${inputCls} font-mono`}
                value={serviceCidr}
                onChange={(e) => setServiceCidr(e.target.value)}
                placeholder="10.96.0.0/12"
              />
            </Field>
          </div>
          {detectResult && detectResult.messages.length > 0 && (
            <ul className="space-y-0.5 text-[11px] text-muted-foreground">
              {detectResult.messages.map((m, i) => (
                <li key={i} className="flex gap-1">
                  <span className="text-muted-foreground/50">•</span>
                  <span>{m}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <Field label="Sync interval (seconds)" hint="Minimum 30 s.">
          <input
            type="number"
            className={inputCls}
            value={syncInterval}
            min={30}
            onChange={(e) => setSyncInterval(parseInt(e.target.value) || 60)}
          />
        </Field>

        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={mirrorPods}
            onChange={(e) => setMirrorPods(e.target.checked)}
            className="mt-0.5"
          />
          <div>
            <span>Mirror pod IPs into IPAM</span>
            <p className="text-[11px] text-muted-foreground/70">
              Off by default. Pods churn — every restart or rolling deploy is a
              create/delete event. Turn on if you want per-pod visibility; node
              IPs, LoadBalancer VIPs and Service ClusterIPs are always mirrored
              regardless.
            </p>
          </div>
        </label>

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

function DeleteClusterModal({
  cluster,
  onConfirm,
  onClose,
  isPending,
}: {
  cluster: KubernetesCluster;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete Kubernetes Cluster" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the cluster connection for{" "}
          <span className="font-semibold">{cluster.name}</span>? This only
          affects SpatiumDDI — nothing on the cluster changes. Any IPAM / DNS
          rows previously mirrored from this cluster will be cleaned up on the
          next reconcile pass.
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
