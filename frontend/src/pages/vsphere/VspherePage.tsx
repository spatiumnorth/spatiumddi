import { useCredentialReask } from "@/hooks/useCredentialReask";
import { Field } from "@/components/ui/field";
import { FreshEdit } from "@/components/FreshEdit";
import { changedFields } from "@/hooks/useFreshRow";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  Check,
  Clipboard,
  Eye,
  Pencil,
  Plus,
  RefreshCw,
  Boxes,
  TestTube2,
  Trash2,
  RotateCw,
} from "lucide-react";

import {
  vsphereApi,
  type VSphereTarget,
  type VSphereTargetCreate,
  type VSphereTargetUpdate,
  type VSphereTestResult,
} from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { countNoun } from "@/lib/count-noun";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { IPSpacePicker } from "@/components/ipam/space-picker";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import { secondsFieldError, SYNC_INTERVAL_BOUNDS } from "@/lib/seconds";
import { FormError } from "@/components/ui/form-error";

// ── Setup guide ─────────────────────────────────────────────────────

const SETUP_GUIDE = `# A read-only vCenter account for SpatiumDDI:
#
# 1. In the vSphere Client: Administration → Access Control → Roles →
#    clone the built-in "Read-only" role (or use it as is).
# 2. Create a service user (e.g. svc-spatium@vsphere.local) and, on the
#    vCenter root object, add a permission: that user + the read-only
#    role, "Propagate to children" ticked.
# 3. Requires vCenter 7.0 Update 2 or later (the vSphere Automation
#    REST API: POST /api/session, GET /api/vcenter/vm, ...).
#
# What is mirrored: each powered-on VM's guest addresses (read from
# VMware Tools through vCenter) and each ESXi host whose vCenter
# inventory name is its IP address. VMs without VMware Tools running
# show NICs/MACs but no address; they are listed under Discovery and
# their existing rows are kept, not deleted.
#
# Addresses are mirrored into subnets that ALREADY exist in the bound
# IPAM space; SpatiumDDI creates none. Untick "Verify TLS" only for a
# lab vCenter with a self-signed certificate; otherwise paste its CA.`;

// ── Page ─────────────────────────────────────────────────────────────

export function VspherePage() {
  // Every write on this integration takes a superadmin.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const {
    data: targets = [],
    isFetching,
    error: listError,
  } = useQuery({
    queryKey: ["vsphere-targets"],
    queryFn: vsphereApi.listTargets,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<VSphereTarget | null>(null);
  const [del, setDel] = useState<VSphereTarget | null>(null);
  const [discovery, setDiscovery] = useState<VSphereTarget | null>(null);
  const [inlineTest, setInlineTest] = useState<
    Record<string, VSphereTestResult | undefined>
  >({});

  const delMut = useMutation({
    mutationFn: (id: string) => vsphereApi.deleteTarget(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vsphere-targets"] });
      setDel(null);
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => vsphereApi.testConnection({ target_id: id }),
    onMutate: (id) => {
      setInlineTest((prev) => ({ ...prev, [id]: undefined }));
    },
    onSuccess: (result, id) => {
      setInlineTest((prev) => ({ ...prev, [id]: result }));
      qc.invalidateQueries({ queryKey: ["vsphere-targets"] });
    },
  });

  const syncMut = useMutation({
    mutationFn: (id: string) => vsphereApi.syncNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vsphere-targets"] });
      setTimeout(
        () => qc.invalidateQueries({ queryKey: ["vsphere-targets"] }),
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
              <h1 className="text-lg font-semibold">VMware vSphere</h1>
              <span className="text-xs text-muted-foreground">
                {countNoun(targets.length, "vCenter")} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Read-only integration. Each vCenter is polled over the vSphere
              Automation REST API (vCenter 7.0 Update 2 or later). Powered-on
              VMs&apos; guest addresses (from VMware Tools) and ESXi hosts named
              by IP land as IP rows in subnets you already have in the bound
              IPAM space; none are created. SpatiumDDI never writes to vCenter.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["vsphere-targets"] })
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
              Add vCenter
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {targets.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                <ListEmpty error={listError} what="vCenter targets">
                  No vCenter configured yet.
                </ListEmpty>
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> Add vCenter
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
                      vCenter
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Hosts / VMs
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
                  {targets.map((t) => {
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
                          {t.host}:{t.port}
                          {t.vcenter_version && (
                            <div className="text-muted-foreground">
                              v{t.vcenter_version}
                            </div>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                          {t.host_count ?? "—"} / {t.vm_count ?? "—"}
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
                            onClick={() => setDiscovery(t)}
                            className="rounded p-1 text-muted-foreground hover:text-foreground"
                            title="Discovery"
                            aria-label="Discovery"
                          >
                            <Eye className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => syncMut.mutate(t.id)}
                            disabled={
                              syncMut.isPending && syncMut.variables === t.id
                            }
                            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Sync Now"
                            aria-label="Sync Now"
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
                            aria-label="Edit"
                            {...superadminGate}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setDel(t)}
                            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                            title="Delete"
                            aria-label="Delete"
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

      {showCreate && <TargetModal onClose={() => setShowCreate(false)} />}
      {edit && (
        <FreshEdit
          row={edit}
          queryKeys={[["vsphere-targets"]]}
          title="Edit vCenter"
          onClose={() => setEdit(null)}
        >
          {(fresh) => (
            <TargetModal target={fresh} onClose={() => setEdit(null)} />
          )}
        </FreshEdit>
      )}
      {discovery && (
        <DiscoveryModal target={discovery} onClose={() => setDiscovery(null)} />
      )}
      {del && (
        <DeleteTargetModal
          target={del}
          onClose={() => setDel(null)}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Discovery (why a VM has no address) ──────────────────────────────

function DiscoveryModal({
  target,
  onClose,
}: {
  target: VSphereTarget;
  onClose: () => void;
}) {
  const d = target.last_discovery;
  const vms = d?.vms ?? [];
  return (
    <Modal title={`Discovery — ${target.name}`} onClose={onClose} wide>
      {!d ? (
        <p className="text-sm text-muted-foreground">
          No sync has completed yet. Use Sync Now, then reopen this view.
        </p>
      ) : (
        <div className="space-y-3 text-xs">
          <p className="text-muted-foreground">
            {countNoun(d.summary.vm_total, "VM")} · {d.summary.vm_reporting}{" "}
            reporting an address · {d.summary.vm_tools_not_running} without
            VMware Tools running · {d.summary.vm_powered_off} powered off ·{" "}
            {countNoun(
              d.summary.addresses_skipped_no_subnet,
              "address",
              "addresses",
            )}{" "}
            with no enclosing subnet. A VM whose VMware Tools is not running is
            unknown, not empty: its existing rows are kept.
          </p>
          <div className="max-h-96 overflow-auto rounded border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b bg-muted/30">
                  <th className="px-3 py-1.5 text-left font-medium">VM</th>
                  <th className="px-3 py-1.5 text-left font-medium">Power</th>
                  <th className="px-3 py-1.5 text-left font-medium">
                    Addresses
                  </th>
                  <th className="px-3 py-1.5 text-left font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {vms.map((v) => (
                  <tr key={v.vm} className="border-b last:border-0 align-top">
                    <td className="px-3 py-1.5">
                      {v.name}
                      <div className="font-mono text-[11px] text-muted-foreground">
                        {v.vm}
                      </div>
                    </td>
                    <td className="px-3 py-1.5 text-muted-foreground">
                      {v.power_state}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[11px]">
                      {v.ips.length ? v.ips.join(", ") : "—"}
                    </td>
                    <td className="px-3 py-1.5">
                      {v.issue ? (
                        <span title={v.hint ?? undefined}>
                          <span className="font-medium">{v.issue}</span>
                          {v.hint && (
                            <div className="text-[11px] text-muted-foreground">
                              {v.hint}
                            </div>
                          )}
                        </span>
                      ) : (
                        <span className="text-emerald-600 dark:text-emerald-400">
                          mirrored
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Modal>
  );
}

// ── Create / Edit modal ─────────────────────────────────────────────

function TargetModal({
  target,
  onClose,
}: {
  target?: VSphereTarget;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!target;

  const [name, setName] = useState(target?.name ?? "");
  const [description, setDescription] = useState(target?.description ?? "");
  const [enabled, setEnabled] = useState(target?.enabled ?? true);
  const [host, setHost] = useState(target?.host ?? "");
  const [port, setPort] = useState(String(target?.port ?? 443));
  const [verifyTls, setVerifyTls] = useState(target?.verify_tls ?? true);
  const [caBundle, setCaBundle] = useState("");
  const [username, setUsername] = useState(target?.username ?? "");
  const [password, setPassword] = useState("");
  // #4135 — a moved address needs the stored password entered again.
  const reask = useCredentialReask(
    { host, port },
    target && { host: target.host, port: target.port },
    () => setPassword(""),
  );
  const mustEnter = reask.asks(target?.password_present);
  const [spaceId, setSpaceId] = useState(target?.ipam_space_id ?? "");
  const [mirrorVms, setMirrorVms] = useState(target?.mirror_vms ?? true);
  const [mirrorHosts, setMirrorHosts] = useState(target?.mirror_hosts ?? true);
  const [syncInterval, setSyncInterval] = useState(
    String(target?.sync_interval_seconds ?? 120),
  );
  const [showGuide, setShowGuide] = useState(!editing);
  const [error, setError] = useState("");
  const [testResult, setTestResult] = useState<VSphereTestResult | null>(null);

  const testMut = useMutation({
    mutationFn: () =>
      vsphereApi.testConnection({
        target_id: target?.id,
        host: host || undefined,
        port: Number(port) || undefined,
        verify_tls: verifyTls,
        ca_bundle_pem: caBundle || undefined,
        username: username || undefined,
        password: password || undefined,
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (e) =>
      setTestResult({
        ok: false,
        message: errMsg(e, "Test failed"),
        vcenter_version: null,
        host_count: null,
        vm_count: null,
      }),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (editing) {
        const update: VSphereTargetUpdate = {
          name,
          description,
          enabled,
          host,
          port: Number(port),
          verify_tls: verifyTls,
          username,
          ipam_space_id: spaceId,
          mirror_vms: mirrorVms,
          mirror_hosts: mirrorHosts,
          sync_interval_seconds: Number(syncInterval.trim()),
        };
        if (caBundle) update.ca_bundle_pem = caBundle;
        if (password) update.password = password;
        // Send only what the operator changed against the row read when the
        // dialog opened (#4370). A password left blank is never in `update`.
        const body = changedFields(target!, update);
        if (Object.keys(body).length === 0) return Promise.resolve(target!);
        return vsphereApi.updateTarget(target!.id, body);
      }
      const create: VSphereTargetCreate = {
        name,
        description,
        enabled,
        host,
        port: Number(port),
        verify_tls: verifyTls,
        ca_bundle_pem: caBundle,
        username,
        password,
        ipam_space_id: spaceId,
        mirror_vms: mirrorVms,
        mirror_hosts: mirrorHosts,
        sync_interval_seconds: Number(syncInterval.trim()),
      };
      return vsphereApi.createTarget(create);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vsphere-targets"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save vCenter")),
  });

  return (
    <Modal
      title={editing ? "Edit vCenter" : "Add vCenter"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
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
                Create a read-only vCenter account. SpatiumDDI opens a session
                per sync, only reads inventory and guest networking, and closes
                the session afterwards.
              </p>
              <CopyablePre text={SETUP_GUIDE} label="vCenter setup" />
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
              label="vCenter host"
              hint="Host name or IP, without https://."
            >
              <input
                className={`${inputCls} font-mono text-[11px]`}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="vcenter.example.com"
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
              onChange={(e) => setPort(e.target.value)}
            />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Username">
            <input
              className={`${inputCls} font-mono text-[11px]`}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="svc-spatium@vsphere.local"
              autoComplete="off"
              required
            />
          </Field>
          <Field label="Password" hint={mustEnter ? reask.hint : undefined}>
            <input
              type="password"
              className={`${inputCls} font-mono text-[11px]`}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              placeholder={
                mustEnter
                  ? reask.placeholder
                  : editing && target?.password_present
                    ? "••• stored — enter to replace"
                    : ""
              }
              required={!editing || mustEnter}
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
              On by default. Untick only for a lab vCenter with a self-signed
              certificate; for a private CA, paste it below instead.
            </p>
          </div>
        </label>

        {verifyTls && (
          <Field
            label="CA bundle (optional)"
            hint={
              target?.ca_bundle_present
                ? "A CA bundle is stored; paste a PEM to replace it."
                : "PEM of the CA that signed the vCenter certificate."
            }
          >
            <textarea
              className={`${inputCls} font-mono text-[11px]`}
              rows={3}
              value={caBundle}
              onChange={(e) => setCaBundle(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----"
            />
          </Field>
        )}

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={
              testMut.isPending ||
              !host ||
              !username ||
              (!editing && !password) ||
              (mustEnter && !password)
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
          <Field
            label="IPAM space"
            hint="Addresses are mirrored into subnets that already exist here."
          >
            <IPSpacePicker value={spaceId} onChange={setSpaceId} required />
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
              checked={mirrorVms}
              onChange={(e) => setMirrorVms(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror VM guest addresses</span>
              <p className="text-[11px] text-muted-foreground/70">
                Powered-on VMs with VMware Tools running. Turning this off
                removes the rows it created on the next sync.
              </p>
            </div>
          </label>
          <label className="flex cursor-pointer items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={mirrorHosts}
              onChange={(e) => setMirrorHosts(e.target.checked)}
              className="mt-0.5"
            />
            <div>
              <span>Mirror ESXi hosts</span>
              <p className="text-[11px] text-muted-foreground/70">
                Only hosts whose vCenter inventory name is an IP address;
                vCenter does not report a host&apos;s management address
                otherwise.
              </p>
            </div>
          </label>
        </div>

        {error && (
          <FormError className="text-xs text-destructive">{error}</FormError>
        )}

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
            disabled={saveMut.isPending || (mustEnter && !password.trim())}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : editing ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DeleteTargetModal({
  target,
  onConfirm,
  onClose,
  isPending,
}: {
  target: VSphereTarget;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete vCenter" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Remove the vCenter{" "}
          <span className="font-semibold">{target.name}</span>? This only
          affects SpatiumDDI — nothing in vSphere changes. Only rows that were
          purely mirrored are removed. Anything you added yourself (edited rows,
          DHCP reservations, custom fields) is kept and detached from this
          integration.
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
