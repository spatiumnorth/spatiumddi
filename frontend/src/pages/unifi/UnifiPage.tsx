import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Clipboard,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  TestTube2,
  RotateCw,
  Wifi,
} from "lucide-react";

import {
  unifiApi,
  dnsApi,
  type DNSServerGroup,
  type UnifiController,
  type UnifiControllerCreate,
  type UnifiControllerUpdate,
  type UnifiTestResult,
} from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { IPSpacePicker } from "@/components/ipam/space-picker";

// One-shot snippet operators can paste into Settings → Control
// Plane → Integrations on UniFi OS to mint an API key with the
// permissions the integration actually needs.

const SETUP_KEY = `# Generate a UniFi Network API key:
#
# 1. Open https://<controller>/network/default/settings/control-plane/integrations
# 2. Click "Create API Key"
# 3. Name it "spatiumddi" with an expiry that matches your rotation
#    window. The key inherits your admin's permissions on the
#    controller. The mirror only reads, so a read-only role is the
#    correct choice for this key when your UniFi version supports
#    it. Active block sync, if you arm it for this controller,
#    writes with its own credentials, entered on the Block Sync page.
# 4. Copy the printed value. The key only displays once.
#
# Cloud-hosted controllers (UniFi Site Manager): generate at
#   https://unifi.ui.com → Settings → API. Then capture your
#   console's host id from the URL bar
#   (https://unifi.ui.com/consoles/<host_id>/...) and paste it
#   into the "Cloud host id" field below.`;

// ── Page ─────────────────────────────────────────────────────────────

export function UnifiPage() {
  const qc = useQueryClient();
  const { data: controllers = [], isFetching } = useQuery({
    queryKey: ["unifi-controllers"],
    queryFn: unifiApi.listControllers,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<UnifiController | null>(null);
  const [del, setDel] = useState<UnifiController | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, UnifiTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => unifiApi.deleteController(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["unifi-controllers"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => unifiApi.testConnection({ controller_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["unifi-controllers"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => unifiApi.syncNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["unifi-controllers"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["unifi-controllers"] }),
        5000,
      );
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Wifi className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">UniFi Controllers</h1>
              <span className="text-xs text-muted-foreground">
                {controllers.length} configured
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              Each controller is polled via the UniFi REST API; networks, VLANs,
              active clients, and DHCP fixed-IP reservations are mirrored into
              IPAM. Local controllers connect directly; cloud controllers proxy
              through <code className="font-mono">api.ui.com</code>. The mirror
              only reads. SpatiumDDI writes to a controller only when Active
              block sync is armed on it (Tools → Block Sync): it then pushes
              client blocks (L2 quarantine) with the separate write credentials
              entered there.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["unifi-controllers"] })
              }
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowCreate(true)}
            >
              Add Controller
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {controllers.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                No UniFi controllers configured yet.
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
              >
                <Plus className="h-3 w-3" /> Add Controller
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
                      Mode
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Endpoint
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Version
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Sites / Networks / Clients
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
                  {controllers.map((c) => {
                    const tr = inlineTest[c.id];
                    const endpoint =
                      c.mode === "cloud"
                        ? c.cloud_host_id
                          ? `cloud:${c.cloud_host_id.slice(0, 8)}…`
                          : "cloud"
                        : c.host
                          ? `${c.host}:${c.port}`
                          : "—";
                    return (
                      <tr key={c.id} className="border-b last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-medium">
                          <Link
                            to={`/unifi/${c.id}`}
                            className={`hover:underline ${
                              c.enabled
                                ? "text-primary"
                                : "text-muted-foreground/60"
                            }`}
                          >
                            {c.name}
                          </Link>
                          {c.description && (
                            <div
                              className="max-w-md truncate text-[11px] text-muted-foreground"
                              title={c.description}
                            >
                              {c.description}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <span
                            className={
                              c.mode === "cloud"
                                ? "inline-flex rounded bg-sky-500/10 px-1.5 py-0.5 text-[11px] text-sky-700 dark:text-sky-400"
                                : "inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px]"
                            }
                          >
                            {c.mode}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                          {endpoint}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {c.controller_version ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {c.site_count ?? "—"} / {c.network_count ?? "—"} /{" "}
                          {c.client_count ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {c.last_synced_at
                            ? new Date(c.last_synced_at).toLocaleString()
                            : "never"}
                          {c.last_sync_error && (
                            <div
                              className="max-w-xs truncate text-[11px] text-destructive"
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

      {showCreate && <ControllerModal onClose={() => setShowCreate(false)} />}
      {edit && (
        <ControllerModal controller={edit} onClose={() => setEdit(null)} />
      )}
      {del && (
        <DeleteControllerModal
          controller={del}
          onClose={() => setDel(null)}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function ControllerModal({
  controller,
  onClose,
}: {
  controller?: UnifiController;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!controller;

  const { data: dnsGroups = [] } = useQuery<DNSServerGroup[]>({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });

  const [name, setName] = useState(controller?.name ?? "");
  const [description, setDescription] = useState(controller?.description ?? "");
  const [enabled, setEnabled] = useState(controller?.enabled ?? true);

  const [mode, setMode] = useState<"local" | "cloud">(
    controller?.mode ?? "local",
  );
  const [host, setHost] = useState(controller?.host ?? "");
  const [port, setPort] = useState(controller?.port ?? 443);
  const [cloudHostId, setCloudHostId] = useState(
    controller?.cloud_host_id ?? "",
  );
  const [verifyTls, setVerifyTls] = useState(controller?.verify_tls ?? true);
  const [caBundle, setCaBundle] = useState("");

  const [authKind, setAuthKind] = useState<"api_key" | "user_password">(
    controller?.auth_kind ?? "api_key",
  );
  const [apiKey, setApiKey] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [spaceId, setSpaceId] = useState(controller?.ipam_space_id ?? "");
  const [dnsGroupId, setDnsGroupId] = useState(controller?.dns_group_id ?? "");

  const [mirrorNetworks, setMirrorNetworks] = useState(
    controller?.mirror_networks ?? true,
  );
  const [mirrorClients, setMirrorClients] = useState(
    controller?.mirror_clients ?? true,
  );
  const [mirrorFixedIps, setMirrorFixedIps] = useState(
    controller?.mirror_fixed_ips ?? true,
  );
  const [siteAllowlist, setSiteAllowlist] = useState(
    (controller?.site_allowlist ?? []).join(", "),
  );
  const [includeWired, setIncludeWired] = useState(
    controller?.include_wired ?? true,
  );
  const [includeWireless, setIncludeWireless] = useState(
    controller?.include_wireless ?? true,
  );
  const [includeVpn, setIncludeVpn] = useState(
    controller?.include_vpn ?? false,
  );
  const [syncInterval, setSyncInterval] = useState(
    controller?.sync_interval_seconds ?? 60,
  );
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");
  const [testResult, setTestResult] = useState<UnifiTestResult | null>(null);

  // TS narrows ``controller`` past undefined inside a few JSX expressions
  // (the `!editing && !controller?.foo` pattern triggers a discriminated
  // union edge case). Pre-compute the boolean flags once so the JSX never
  // touches the optional chain inside a negated conjunction.
  const hasStoredApiKey = !!controller?.api_key_present;
  const hasStoredUsername = !!controller?.username_present;
  const hasStoredPassword = !!controller?.password_present;
  const hasStoredCaBundle = !!controller?.ca_bundle_present;

  // Cloud + user_password is illegal — flip to api_key when mode
  // switches to cloud so the form doesn't carry an invalid combo.
  function setModeAndFix(m: "local" | "cloud") {
    setMode(m);
    if (m === "cloud" && authKind === "user_password") {
      setAuthKind("api_key");
    }
  }

  const allowlist = siteAllowlist
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const testMut = useMutation({
    mutationFn: () =>
      unifiApi.testConnection({
        controller_id: controller?.id,
        mode,
        host: host || null,
        port,
        cloud_host_id: cloudHostId || null,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundle || undefined,
        auth_kind: authKind,
        api_key: apiKey || undefined,
        username: username || undefined,
        password: password || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        controller_version: null,
        site_count: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: UnifiControllerUpdate = {
          name,
          description,
          enabled,
          mode,
          host: host || null,
          port,
          cloud_host_id: cloudHostId || null,
          verify_tls: verifyTls,
          auth_kind: authKind,
          ipam_space_id: spaceId,
          dns_group_id: dnsGroupId || null,
          mirror_networks: mirrorNetworks,
          mirror_clients: mirrorClients,
          mirror_fixed_ips: mirrorFixedIps,
          site_allowlist: allowlist,
          include_wired: includeWired,
          include_wireless: includeWireless,
          include_vpn: includeVpn,
          sync_interval_seconds: syncInterval,
        };
        if (caBundle) update.ca_bundle_pem = caBundle;
        if (apiKey) update.api_key = apiKey;
        if (username) update.username = username;
        if (password) update.password = password;
        return unifiApi.updateController(controller!.id, update);
      }
      const create: UnifiControllerCreate = {
        name,
        description,
        enabled,
        mode,
        host: host || null,
        port,
        cloud_host_id: cloudHostId || null,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundle || undefined,
        auth_kind: authKind,
        api_key: apiKey || undefined,
        username: username || undefined,
        password: password || undefined,
        ipam_space_id: spaceId,
        dns_group_id: dnsGroupId || null,
        mirror_networks: mirrorNetworks,
        mirror_clients: mirrorClients,
        mirror_fixed_ips: mirrorFixedIps,
        site_allowlist: allowlist,
        include_wired: includeWired,
        include_wireless: includeWireless,
        include_vpn: includeVpn,
        sync_interval_seconds: syncInterval,
      };
      return unifiApi.createController(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["unifi-controllers"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save controller")),
  });

  return (
    <Modal
      title={editing ? "Edit UniFi Controller" : "Add UniFi Controller"}
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
                On UniFi OS controllers, generate an API key under Settings →
                Control Plane → Integrations. On older controllers without the
                integrations panel, use the legacy username + password option
                below.
              </p>
              <CopyablePre text={SETUP_KEY} label="UniFi key setup" />
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

        <div className="grid grid-cols-3 gap-3 border-t pt-3">
          <Field label="Mode">
            <select
              className={inputCls}
              value={mode}
              onChange={(e) =>
                setModeAndFix(e.target.value as "local" | "cloud")
              }
            >
              <option value="local">Local (direct)</option>
              <option value="cloud">Cloud (api.ui.com)</option>
            </select>
          </Field>
          {mode === "local" ? (
            <>
              <Field
                label="Host"
                hint="Hostname or IP. https:// is implied; do not include the scheme."
              >
                <input
                  className={`${inputCls} font-mono text-[11px]`}
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="192.168.1.1"
                  required
                />
              </Field>
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
            </>
          ) : (
            <Field
              label="Cloud host id"
              hint="UniFi console UUID — visible in the Site Manager URL."
            >
              <input
                className={`${inputCls} font-mono text-[11px]`}
                value={cloudHostId}
                onChange={(e) => setCloudHostId(e.target.value)}
                placeholder="abcd1234-…"
                required
              />
            </Field>
          )}
        </div>

        {mode === "local" && (
          <div className="grid grid-cols-2 gap-3">
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
                  Off for self-signed lab controllers; upload the controller CA
                  below for prod.
                </p>
              </div>
            </label>
            <Field label="CA bundle (PEM, optional)">
              <textarea
                className={`${inputCls} font-mono text-[11px]`}
                value={caBundle}
                onChange={(e) => setCaBundle(e.target.value)}
                rows={3}
                placeholder={
                  editing && hasStoredCaBundle
                    ? "••• stored — paste new PEM to replace"
                    : "-----BEGIN CERTIFICATE-----…"
                }
              />
            </Field>
          </div>
        )}

        <div className="grid grid-cols-3 gap-3 border-t pt-3">
          <Field label="Auth">
            <select
              className={inputCls}
              value={authKind}
              onChange={(e) =>
                setAuthKind(e.target.value as "api_key" | "user_password")
              }
              disabled={mode === "cloud"}
            >
              <option value="api_key">API key (UniFi OS ≥ 4.x)</option>
              <option value="user_password">
                Username + password (legacy)
              </option>
            </select>
          </Field>
          {authKind === "api_key" ? (
            <Field label="API key" className="col-span-2">
              <input
                type="password"
                className={`${inputCls} font-mono text-[11px]`}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={
                  editing && hasStoredApiKey
                    ? "••• stored — enter to replace"
                    : "<api key>"
                }
                required={!editing && !hasStoredApiKey}
              />
            </Field>
          ) : (
            <>
              <Field label="Username">
                <input
                  className={inputCls}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={
                    editing && hasStoredUsername
                      ? "••• stored — enter to replace"
                      : "spatiumddi"
                  }
                  required={!editing && !hasStoredUsername}
                />
              </Field>
              <Field label="Password">
                <input
                  type="password"
                  className={inputCls}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={
                    editing && hasStoredPassword
                      ? "••• stored — enter to replace"
                      : ""
                  }
                  required={!editing && !hasStoredPassword}
                />
              </Field>
            </>
          )}
        </div>

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

        <Field
          label="Site allowlist"
          hint="Comma-separated site short ids or labels. Empty = mirror every site."
        >
          <input
            className={inputCls}
            value={siteAllowlist}
            onChange={(e) => setSiteAllowlist(e.target.value)}
            placeholder="default, branch-office"
          />
        </Field>

        <div className="grid grid-cols-3 gap-3 border-t pt-2">
          <Toggle
            label="Mirror networks"
            value={mirrorNetworks}
            onChange={setMirrorNetworks}
          />
          <Toggle
            label="Mirror clients"
            value={mirrorClients}
            onChange={setMirrorClients}
          />
          <Toggle
            label="Mirror fixed IPs"
            value={mirrorFixedIps}
            onChange={setMirrorFixedIps}
          />
          <Toggle
            label="Include wired"
            value={includeWired}
            onChange={setIncludeWired}
          />
          <Toggle
            label="Include wireless"
            value={includeWireless}
            onChange={setIncludeWireless}
          />
          <Toggle
            label="Include VPN"
            value={includeVpn}
            onChange={setIncludeVpn}
          />
        </div>

        <Field
          label="Sync interval (seconds)"
          hint="Minimum 30 s. Cloud mode has a 60 s floor enforced server-side."
        >
          <input
            type="number"
            className={inputCls}
            value={syncInterval}
            min={30}
            onChange={(e) => setSyncInterval(parseInt(e.target.value) || 60)}
          />
        </Field>

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

function DeleteControllerModal({
  controller,
  onConfirm,
  onClose,
  isPending,
}: {
  controller: UnifiController;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete UniFi Controller" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the UniFi controller{" "}
          <span className="font-semibold">{controller.name}</span>? This only
          affects SpatiumDDI — nothing on the controller side changes. All IPAM
          rows mirrored from this controller (subnets, blocks, IP addresses)
          will be removed via the FK cascade.
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

// ── Helpers ────────────────────────────────────────────────────────

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
  className,
  children,
}: {
  label: string;
  hint?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={`space-y-1 ${className ?? ""}`}>
      <label className="block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground/70">{hint}</p>}
    </div>
  );
}

function Toggle({
  label,
  value,
  onChange,
}: {
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm">
      <input
        type="checkbox"
        checked={value}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>{label}</span>
    </label>
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
