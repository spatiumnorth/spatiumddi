import { useModuleOn } from "@/hooks/useModuleOn";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  Check,
  Clipboard,
  Container as ContainerIcon,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  TestTube2,
  RotateCw,
} from "lucide-react";

import {
  dockerApi,
  dnsApi,
  type DNSServerGroup,
  type DockerHost,
  type DockerHostCreate,
  type DockerHostUpdate,
  type DockerTestResult,
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
// Shown in the create modal so operators know how to expose their
// Docker daemon securely. For local sockets there's no setup — just
// mount the socket into the SpatiumDDI api container.

const SETUP_TCP_TLS = `# On the Docker host — enable the daemon on TCP+TLS.
# Docker ships a helper; if you prefer, follow
# https://docs.docker.com/engine/security/protect-access/

# /etc/docker/daemon.json
{
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"],
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/certs/ca.pem",
  "tlscert": "/etc/docker/certs/server-cert.pem",
  "tlskey": "/etc/docker/certs/server-key.pem"
}

# systemd override — drop the -H flag from ExecStart so it doesn't fight
# daemon.json's hosts:
sudo systemctl edit docker
  # paste:
  [Service]
  ExecStart=
  ExecStart=/usr/bin/dockerd

sudo systemctl daemon-reload
sudo systemctl restart docker`;

const SETUP_UNIX = `# On the SpatiumDDI host — mount the Docker socket into the api container.
# docker-compose.yml (SpatiumDDI):
services:
  api:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
  worker:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

# Then restart the stack:
#   docker compose up -d --force-recreate api worker

# Endpoint to enter below: /var/run/docker.sock`;

// ── Page ─────────────────────────────────────────────────────────────

export function DockerPage() {
  // #1340 — every write on this integration takes a superadmin (its
  // router's create / update / delete / sync / test handlers take
  // SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: hosts = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["docker-hosts"],
    queryFn: dockerApi.listHosts,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<DockerHost | null>(null);
  const [del, setDel] = useState<DockerHost | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, DockerTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => dockerApi.deleteHost(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["docker-hosts"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => dockerApi.testConnection({ host_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["docker-hosts"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => dockerApi.syncNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["docker-hosts"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["docker-hosts"] }),
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
              <ContainerIcon className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Docker Hosts</h1>
              <span className="text-xs text-muted-foreground">
                {hosts.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each host is polled by SpatiumDDI; Docker
              networks land in the bound IPAM space as subnets, and (opt-in)
              containers land as IP addresses. SpatiumDDI never writes to the
              daemon.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["docker-hosts"] })
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
              Add Host
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {hosts.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="Docker hosts">
                  No hosts configured yet.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> Add Host
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
                      Engine
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Containers
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
                  {hosts.map((h) => {
                    const tr = inlineTest[h.id];
                    return (
                      <tr key={h.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          {h.name}
                          {h.description && (
                            <div
                              className="text-[11px] text-muted-foreground max-w-md truncate"
                              title={h.description}
                            >
                              {h.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          {h.enabled ? (
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
                          title={`${h.connection_type}://${h.endpoint}`}
                        >
                          <span className="text-muted-foreground">
                            {h.connection_type}://
                          </span>
                          {h.endpoint}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {h.engine_version ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {h.container_count ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {h.last_synced_at
                            ? new Date(h.last_synced_at).toLocaleString()
                            : "never"}
                          {h.last_sync_error && (
                            <div
                              className="text-[11px] text-destructive max-w-xs truncate"
                              title={h.last_sync_error}
                            >
                              {h.last_sync_error}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <button
                            onClick={() => testMut.mutate(h.id)}
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
                            onClick={() => syncMut.mutate(h.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === h.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
                            {...superadminGate}
                          >
                            <RotateCw
                              className={`h-3.5 w-3.5 ${
                                syncMut.isPending && syncMut.variables === h.id
                                  ? "animate-spin"
                                  : ""
                              }`}
                            />
                          </button>
                          <button
                            onClick={() => setEdit(h)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                            title="Edit"
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(h)}
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

      {showCreate && <HostModal onClose={() => setShowCreate(false)} />}
      {edit && <HostModal host={edit} onClose={() => setEdit(null)} />}
      {del && (
        <DeleteHostModal
          host={del}
          onClose={() => setDel(null)}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function HostModal({
  host,
  onClose,
}: {
  host?: DockerHost;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!host;

  // DNS off (#2135): no /dns/groups read and no picker. The stored
  // dns_group_id is sent back untouched, so saving here cannot clear it.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: dnsOn,
  });

  const [name, setName] = useState(host?.name ?? "");
  const [description, setDescription] = useState(host?.description ?? "");
  const [enabled, setEnabled] = useState(host?.enabled ?? true);
  const [connectionType, setConnectionType] = useState<"unix" | "tcp">(
    host?.connection_type ?? "tcp",
  );
  const [endpoint, setEndpoint] = useState(host?.endpoint ?? "");
  const [caBundlePem, setCaBundlePem] = useState("");
  const [clientCertPem, setClientCertPem] = useState("");
  const [clientKeyPem, setClientKeyPem] = useState("");
  const [spaceId, setSpaceId] = useState(host?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(host?.dns_group_id ?? "");
  const [mirrorContainers, setMirrorContainers] = useState(
    host?.mirror_containers ?? false,
  );
  const [includeDefaults, setIncludeDefaults] = useState(
    host?.include_default_networks ?? false,
  );
  const [includeStopped, setIncludeStopped] = useState(
    host?.include_stopped_containers ?? false,
  );
  const [syncInterval, setSyncInterval] = useState(
    String(host?.sync_interval_seconds ?? 60),
  );
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");

  const [testResult, setTestResult] = useState<DockerTestResult | null>(null);

  const testMut = useMutation({
    mutationFn: () =>
      dockerApi.testConnection({
        host_id: host?.id,
        connection_type: connectionType,
        endpoint: endpoint || undefined,
        ca_bundle_pem: caBundlePem || undefined,
        client_cert_pem: clientCertPem || undefined,
        client_key_pem: clientKeyPem || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        engine_version: null,
        container_count: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: DockerHostUpdate = {
          name,
          description,
          enabled,
          connection_type: connectionType,
          endpoint,
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          mirror_containers: mirrorContainers,
          include_default_networks: includeDefaults,
          include_stopped_containers: includeStopped,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (caBundlePem) update.ca_bundle_pem = caBundlePem;
        if (clientCertPem) update.client_cert_pem = clientCertPem;
        if (clientKeyPem) update.client_key_pem = clientKeyPem;
        return dockerApi.updateHost(host!.id, update);
      }
      const create: DockerHostCreate = {
        name,
        description,
        enabled,
        connection_type: connectionType,
        endpoint,
        ca_bundle_pem: caBundlePem,
        client_cert_pem: clientCertPem,
        client_key_pem: clientKeyPem,
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        mirror_containers: mirrorContainers,
        include_default_networks: includeDefaults,
        include_stopped_containers: includeStopped,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return dockerApi.createHost(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["docker-hosts"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save host")),
  });

  return (
    <Modal
      title={editing ? "Edit Docker Host" : "Add Docker Host"}
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
                Choose a transport based on where the daemon runs:
              </p>
              <p className="font-medium">
                Remote daemon with TLS (recommended):
              </p>
              <CopyablePre text={SETUP_TCP_TLS} label="TCP+TLS setup" />
              <p className="font-medium">Local Docker on the same host:</p>
              <CopyablePre text={SETUP_UNIX} label="unix socket setup" />
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
          <Field label="Connection">
            <select
              className={inputCls}
              value={connectionType}
              onChange={(e) =>
                setConnectionType(e.target.value as "unix" | "tcp")
              }
            >
              <option value="tcp">TCP (remote)</option>
              <option value="unix">Unix socket (local)</option>
            </select>
          </Field>
          <div className="col-span-2">
            <Field
              label="Endpoint"
              hint={
                connectionType === "unix"
                  ? "Socket path, e.g. /var/run/docker.sock"
                  : "host:port — e.g. docker.example.com:2376"
              }
            >
              <input
                className={`${inputCls} font-mono text-[11px]`}
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder={
                  connectionType === "unix"
                    ? "/var/run/docker.sock"
                    : "docker.example.com:2376"
                }
                required
              />
            </Field>
          </div>
        </div>

        {connectionType === "tcp" && (
          <>
            <Field
              label="CA bundle (PEM)"
              hint="Leave blank for unencrypted TCP (not recommended outside trusted LAN)."
            >
              <textarea
                className={`${inputCls} font-mono text-[11px]`}
                rows={3}
                value={caBundlePem}
                onChange={(e) => setCaBundlePem(e.target.value)}
                placeholder={
                  editing && host?.ca_bundle_present
                    ? "••• stored — paste to replace"
                    : "-----BEGIN CERTIFICATE-----\n..."
                }
              />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Client cert (PEM)">
                <textarea
                  className={`${inputCls} font-mono text-[11px]`}
                  rows={3}
                  value={clientCertPem}
                  onChange={(e) => setClientCertPem(e.target.value)}
                  placeholder={
                    editing && host?.client_cert_present
                      ? "••• stored — paste to replace"
                      : "-----BEGIN CERTIFICATE-----\n..."
                  }
                />
              </Field>
              <Field label="Client key (PEM)">
                <textarea
                  className={`${inputCls} font-mono text-[11px]`}
                  rows={3}
                  value={clientKeyPem}
                  onChange={(e) => setClientKeyPem(e.target.value)}
                  placeholder={
                    editing && host?.client_key_present
                      ? "••• stored — paste to replace"
                      : "-----BEGIN PRIVATE KEY-----\n..."
                  }
                />
              </Field>
            </div>
          </>
        )}

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !endpoint}
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
              {testResult.container_count !== null &&
                ` · ${testResult.container_count} container${
                  testResult.container_count === 1 ? "" : "s"
                }`}
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
              checked={mirrorContainers}
              onChange={(e) => setMirrorContainers(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror container IPs into IPAM</span>
              <p className="text-[11px] text-muted-foreground/70">
                Off by default. A busy CI host with ephemeral test containers
                can churn the IP table. Networks are always mirrored.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={includeDefaults}
              onChange={(e) => setIncludeDefaults(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>
                Include default networks (<code>bridge</code>, <code>host</code>
                , <code>none</code>)
              </span>
              <p className="text-[11px] text-muted-foreground/70">
                Usually noise — the default bridge is a 172.17.0.0/16 dynamic
                pool that Docker auto-creates.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={includeStopped}
              onChange={(e) => setIncludeStopped(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Include stopped containers</span>
              <p className="text-[11px] text-muted-foreground/70">
                Requires Mirror container IPs. By default only Running
                containers land in IPAM.
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

function DeleteHostModal({
  host,
  onConfirm,
  onClose,
  isPending,
}: {
  host: DockerHost;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete Docker Host" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the host connection for{" "}
          <span className="font-semibold">{host.name}</span>? This only affects
          SpatiumDDI — nothing on the Docker host changes. Only rows that were
          purely mirrored are removed. Anything you added yourself (addresses,
          DHCP scopes, reservations, edited rows, custom fields) is kept and
          detached from this integration.
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
