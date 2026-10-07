import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  Wifi,
  Plus,
  Ban,
  KeyRound,
  RotateCw,
  Eye,
  EyeOff,
  Copy,
} from "lucide-react";

import {
  blockSyncApi,
  type BlockTarget,
  type BlockTargetDiff,
  type NetworkBlock,
  type BlockPushOut,
  type BlockPushStatus,
  type BlockKind,
  type BlockRevealResult,
  type BlockUnifiAuthKind,
} from "@/lib/api";
import {
  handleApprovalQueued,
  APPROVAL_QUEUED_MESSAGE,
  CHANGE_REQUEST_QUERY_KEY,
} from "@/lib/approvalQueue";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { ListReadError } from "@/components/ui/list-read-error";
import { pollUnlessRefused } from "@/lib/refusal";
import { errMsg, inputCls } from "@/pages/dhcp/_shared";

// Relative "time ago" for the sync/pushed columns. Cheap, no dependency.
function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  return `${days}d ago`;
}

const PUSH_STATUS_STYLE: Record<BlockPushStatus, string> = {
  pushed: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  pending: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
  removing: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
  error: "bg-red-500/10 text-red-700 dark:text-red-400",
};

export function BlockSyncPage() {
  const qc = useQueryClient();

  const [showArm, setShowArm] = useState<BlockTarget | null>(null);
  const [showReveal, setShowReveal] = useState<BlockTarget | null>(null);
  const [showNewBlock, setShowNewBlock] = useState(false);
  const [reconcilePreview, setReconcilePreview] = useState<{
    target: BlockTarget;
    diff: BlockTargetDiff | null;
  } | null>(null);
  const [liftTarget, setLiftTarget] = useState<NetworkBlock | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [pageNotice, setPageNotice] = useState<string | null>(null);

  // Both stop polling once refused (#1343): each refused read is a denied
  // audit row, and asking again does not change the answer.
  const targetsQ = useQuery({
    queryKey: ["block-sync", "targets"],
    queryFn: blockSyncApi.listTargets,
    refetchInterval: pollUnlessRefused(30_000),
  });
  const blocksQ = useQuery({
    queryKey: ["block-sync", "blocks"],
    queryFn: blockSyncApi.listBlocks,
    refetchInterval: pollUnlessRefused(30_000),
  });

  const targets = targetsQ.data ?? [];
  const blocks = blocksQ.data ?? [];

  // target_id → display name, for rendering push chips on the Blocks table.
  const targetNames = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of targets) m.set(t.target_id, t.name);
    return m;
  }, [targets]);

  function invalidateAll() {
    qc.invalidateQueries({ queryKey: ["block-sync"] });
  }

  const reconcileMut = useMutation({
    mutationFn: ({
      target,
      preview,
    }: {
      target: BlockTarget;
      preview: boolean;
    }) => blockSyncApi.reconcile(target.target_kind, target.target_id, preview),
    onError: (e) => setPageError(errMsg(e, "Reconcile failed")),
  });

  function previewReconcile(target: BlockTarget) {
    setPageError(null);
    setReconcilePreview({ target, diff: null });
    reconcileMut.mutate(
      { target, preview: true },
      {
        onSuccess: (diff) => setReconcilePreview({ target, diff }),
      },
    );
  }

  function pushReconcile(target: BlockTarget) {
    setPageError(null);
    reconcileMut.mutate(
      { target, preview: false },
      {
        onSuccess: () => {
          setPageNotice(`Reconcile enqueued for ${target.name}.`);
          setReconcilePreview(null);
          invalidateAll();
        },
      },
    );
  }

  const liftMut = useMutation({
    mutationFn: (id: string) => blockSyncApi.liftBlock(id),
    onSuccess: () => {
      invalidateAll();
      setLiftTarget(null);
    },
    onError: (e) => setPageError(errMsg(e, "Failed to lift block")),
  });

  return (
    <div className="space-y-4 p-4 md:p-6">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1">
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <ShieldBan className="h-5 w-5 flex-shrink-0" />
            Active block sync
          </h1>
          <p className="text-sm text-muted-foreground">
            SpatiumDDI-owned blocked IPs / MACs, pushed into armed OPNsense
            firewalls (alias membership), Palo Alto firewalls (Dynamic Address
            Group tag), UniFi controllers (L2 quarantine), and Meraki
            organizations (per-client Blocked policy). Each target is armed
            separately with distinct write credentials; every push is
            previewable + audited.
          </p>
        </div>
        <HeaderButton
          icon={RefreshCw}
          iconClassName={
            targetsQ.isFetching || blocksQ.isFetching
              ? "animate-spin"
              : undefined
          }
          onClick={() => invalidateAll()}
          disabled={targetsQ.isFetching || blocksQ.isFetching}
        >
          Refresh
        </HeaderButton>
        <HeaderButton
          icon={Plus}
          variant="primary"
          onClick={() => {
            setPageError(null);
            setShowNewBlock(true);
          }}
        >
          New block
        </HeaderButton>
      </div>

      {pageError && (
        <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          {pageError}
        </div>
      )}
      {pageNotice && (
        <div className="flex items-start justify-between gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-400">
          <span>{pageNotice}</span>
          <button
            type="button"
            onClick={() => setPageNotice(null)}
            className="text-emerald-700/70 hover:text-emerald-700 dark:text-emerald-400/70"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Targets */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-muted-foreground">Targets</h2>
        <div className="rounded-lg border">
          {targets.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted-foreground">
              {targetsQ.isLoading ? (
                "Loading…"
              ) : targetsQ.isError ? (
                <ListReadError
                  error={targetsQ.error}
                  what="the block-sync targets"
                />
              ) : (
                "No OPNsense routers, Palo Alto firewalls, UniFi controllers, or Meraki organizations to arm. Add an OPNsense, Palo Alto, UniFi, or Meraki integration first."
              )}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[880px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="px-3 py-2 text-left font-medium">Name</th>
                    <th className="px-3 py-2 text-left font-medium">Kind</th>
                    <th className="px-3 py-2 text-left font-medium">Armed</th>
                    <th className="px-3 py-2 text-left font-medium">
                      Alias / Tag / Site
                    </th>
                    <th className="px-3 py-2 text-left font-medium">
                      Write creds
                    </th>
                    <th className="px-3 py-2 text-left font-medium">
                      Last sync
                    </th>
                    <th className="px-3 py-2 text-right font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {targets.map((t) => (
                    <tr
                      key={`${t.target_kind}:${t.target_id}`}
                      className="border-b last:border-0"
                    >
                      <td className="px-3 py-2 font-medium">{t.name}</td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-1 text-muted-foreground">
                          {t.target_kind === "unifi" ? (
                            <Wifi className="h-3.5 w-3.5" />
                          ) : t.target_kind === "paloalto" ? (
                            <ShieldAlert className="h-3.5 w-3.5" />
                          ) : t.target_kind === "meraki" ? (
                            <Network className="h-3.5 w-3.5" />
                          ) : (
                            <ShieldCheck className="h-3.5 w-3.5" />
                          )}
                          {t.target_kind === "unifi"
                            ? "UniFi"
                            : t.target_kind === "paloalto"
                              ? "Palo Alto"
                              : t.target_kind === "meraki"
                                ? "Meraki"
                                : "OPNsense"}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        {t.block_sync_enabled ? (
                          <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400">
                            Armed
                          </span>
                        ) : (
                          <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium bg-muted text-muted-foreground">
                            Off
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {t.target_kind === "opnsense"
                          ? t.block_alias_name || "—"
                          : t.target_kind === "paloalto"
                            ? t.block_tag_name || "—"
                            : t.target_kind === "meraki"
                              ? t.block_policy_name || "—"
                              : t.block_sync_site || "—"}
                      </td>
                      <td className="px-3 py-2">
                        {t.write_credentials_present ? (
                          <span className="text-emerald-600 dark:text-emerald-400">
                            Present
                          </span>
                        ) : (
                          <span className="text-muted-foreground">Missing</span>
                        )}
                      </td>
                      <td
                        className="px-3 py-2 text-muted-foreground"
                        title={
                          t.last_block_sync_at
                            ? new Date(t.last_block_sync_at).toLocaleString()
                            : undefined
                        }
                      >
                        {t.last_block_sync_error ? (
                          <span
                            className="text-red-600 dark:text-red-400"
                            title={t.last_block_sync_error}
                          >
                            error
                          </span>
                        ) : t.last_block_sync_at ? (
                          timeAgo(t.last_block_sync_at)
                        ) : (
                          "never"
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => previewReconcile(t)}
                            className="inline-flex items-center gap-1 rounded border px-2 py-1 hover:bg-muted disabled:opacity-40"
                            disabled={!t.block_sync_enabled}
                            title={
                              t.block_sync_enabled
                                ? "Preview + reconcile now"
                                : "Arm the target first"
                            }
                          >
                            <RotateCw className="h-3 w-3" />
                            Reconcile
                          </button>
                          {t.write_credentials_present && (
                            <button
                              type="button"
                              onClick={() => setShowReveal(t)}
                              className="inline-flex items-center gap-1 rounded border px-2 py-1 hover:bg-muted"
                              title="Reveal stored write credentials"
                            >
                              <Eye className="h-3 w-3" />
                              Reveal
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => {
                              setPageError(null);
                              setShowArm(t);
                            }}
                            className="inline-flex items-center gap-1 rounded border px-2 py-1 hover:bg-muted"
                          >
                            <KeyRound className="h-3 w-3" />
                            Arm / Edit
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* Blocks */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-muted-foreground">Blocks</h2>
        <div className="rounded-lg border">
          {blocks.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted-foreground">
              {blocksQ.isLoading ? (
                "Loading…"
              ) : blocksQ.isError ? (
                <ListReadError
                  error={blocksQ.error}
                  what="the network blocks"
                />
              ) : (
                "No network blocks yet. Create one with New block."
              )}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="px-3 py-2 text-left font-medium">Kind</th>
                    <th className="px-3 py-2 text-left font-medium">Value</th>
                    <th className="px-3 py-2 text-left font-medium">Reason</th>
                    <th className="px-3 py-2 text-left font-medium">Source</th>
                    <th className="px-3 py-2 text-left font-medium">State</th>
                    <th className="px-3 py-2 text-left font-medium">Pushes</th>
                    <th className="px-3 py-2 text-right font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {blocks.map((b) => (
                    <tr
                      key={b.id}
                      className={`border-b last:border-0 ${
                        b.enabled ? "" : "opacity-50"
                      }`}
                    >
                      <td className="px-3 py-2 uppercase text-muted-foreground">
                        {b.kind}
                      </td>
                      <td className="break-all px-3 py-2 font-mono">
                        {b.value}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {b.reason || "—"}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {b.source}
                      </td>
                      <td className="px-3 py-2">
                        {b.enabled ? (
                          <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium bg-red-500/10 text-red-700 dark:text-red-400">
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium bg-muted text-muted-foreground">
                            Lifted
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <PushChips
                          pushes={b.pushes}
                          targetNames={targetNames}
                        />
                      </td>
                      <td className="px-3 py-2 text-right">
                        {b.enabled && (
                          <button
                            type="button"
                            onClick={() => setLiftTarget(b)}
                            className="inline-flex items-center gap-1 rounded border border-destructive/40 px-2 py-1 text-destructive hover:bg-destructive/10"
                          >
                            <Ban className="h-3 w-3" />
                            Lift
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* Modals */}
      {showArm && (
        <ArmTargetModal
          target={showArm}
          onClose={() => setShowArm(null)}
          onDone={() => {
            invalidateAll();
            setShowArm(null);
          }}
        />
      )}
      {showReveal && (
        <RevealModal target={showReveal} onClose={() => setShowReveal(null)} />
      )}
      {showNewBlock && (
        <NewBlockModal
          onClose={() => setShowNewBlock(false)}
          onDone={(notice) => {
            invalidateAll();
            if (notice) setPageNotice(notice);
            setShowNewBlock(false);
          }}
        />
      )}
      {reconcilePreview && (
        <ReconcilePreviewModal
          target={reconcilePreview.target}
          diff={reconcilePreview.diff}
          loading={reconcileMut.isPending}
          onClose={() => setReconcilePreview(null)}
          onConfirm={() => pushReconcile(reconcilePreview.target)}
        />
      )}
      <ConfirmModal
        open={!!liftTarget}
        title="Lift block"
        message={
          <>
            Lift the block on{" "}
            <span className="font-mono">{liftTarget?.value}</span>? This
            disables it and pushes the removal to every target it landed on. The
            row is kept (disabled) as audit history.
          </>
        }
        tone="destructive"
        confirmLabel="Lift block"
        loading={liftMut.isPending}
        onConfirm={() => liftTarget && liftMut.mutate(liftTarget.id)}
        onClose={() => setLiftTarget(null)}
      />
    </div>
  );
}

// ── Per-target push status chips on the Blocks table ─────────────────
function PushChips({
  pushes,
  targetNames,
}: {
  pushes: BlockPushOut[];
  targetNames: Map<string, string>;
}) {
  if (pushes.length === 0)
    return <span className="text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {pushes.map((p) => {
        const name = targetNames.get(p.target_id) ?? p.target_kind;
        const style =
          PUSH_STATUS_STYLE[p.push_status] ?? "bg-muted text-muted-foreground";
        return (
          <span
            key={`${p.target_kind}:${p.target_id}`}
            className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${style}`}
            title={
              p.last_error
                ? `${name}: ${p.last_error}`
                : `${name}: ${p.push_status}${
                    p.last_pushed_at
                      ? ` · ${new Date(p.last_pushed_at).toLocaleString()}`
                      : ""
                  }`
            }
          >
            {name} · {p.push_status}
          </span>
        );
      })}
    </div>
  );
}

// ── Arm / edit a target ───────────────────────────────────────────────
function ArmTargetModal({
  target,
  onClose,
  onDone,
}: {
  target: BlockTarget;
  onClose: () => void;
  onDone: () => void;
}) {
  const isUnifi = target.target_kind === "unifi";
  const isPaloalto = target.target_kind === "paloalto";
  const isMeraki = target.target_kind === "meraki";
  // A Panorama target can't drive Dynamic Address Group enforcement — that
  // needs a standalone firewall with a vsys. The backend 422s the arm call;
  // gate the UI so operators don't hit it.
  const isPanoramaTarget = isPaloalto && !!target.is_panorama;

  const [enabled, setEnabled] = useState(target.block_sync_enabled);
  // OPNsense
  const [alias, setAlias] = useState(target.block_alias_name ?? "");
  const [apiKey, setApiKey] = useState("");
  const [apiSecret, setApiSecret] = useState("");
  // Palo Alto PAN-OS
  const [tagName, setTagName] = useState(target.block_tag_name ?? "");
  const [panosApiKey, setPanosApiKey] = useState("");
  // Meraki
  const [policyName, setPolicyName] = useState(
    target.block_policy_name ?? "Blocked",
  );
  const [merakiApiKey, setMerakiApiKey] = useState("");
  // UniFi
  const [site, setSite] = useState(target.block_sync_site ?? "default");
  const [authKind, setAuthKind] = useState<BlockUnifiAuthKind>(
    (target.block_sync_auth_kind as BlockUnifiAuthKind) ?? "api_key",
  );
  const [unifiApiKey, setUnifiApiKey] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () => {
      if (isUnifi) {
        return blockSyncApi.armUnifi(target.target_id, {
          block_sync_enabled: enabled,
          block_sync_site: site.trim() || "default",
          block_sync_auth_kind: authKind,
          block_sync_api_key:
            authKind === "api_key" && unifiApiKey.trim()
              ? unifiApiKey.trim()
              : undefined,
          block_sync_username:
            authKind === "user_password" && username.trim()
              ? username.trim()
              : undefined,
          block_sync_password:
            authKind === "user_password" && password ? password : undefined,
        });
      }
      if (isPaloalto) {
        return blockSyncApi.armPaloalto(target.target_id, {
          block_sync_enabled: enabled,
          block_tag_name: tagName.trim(),
          block_sync_api_key: panosApiKey.trim() || undefined,
        });
      }
      if (isMeraki) {
        return blockSyncApi.armMeraki(target.target_id, {
          block_sync_enabled: enabled,
          block_policy_name: policyName.trim() || "Blocked",
          block_sync_api_key: merakiApiKey.trim() || undefined,
        });
      }
      return blockSyncApi.armOpnsense(target.target_id, {
        block_sync_enabled: enabled,
        block_alias_name: alias.trim(),
        block_sync_api_key: apiKey.trim() || undefined,
        block_sync_api_secret: apiSecret || undefined,
      });
    },
    onSuccess: onDone,
    onError: (e) => setError(errMsg(e, "Failed to save arming config")),
  });

  const credsHint = target.write_credentials_present
    ? "Credentials are stored. Leave blank to keep them; type to rotate."
    : "No credentials stored yet — required to arm.";

  return (
    <Modal
      title={`Arm ${
        isUnifi
          ? "UniFi"
          : isPaloalto
            ? "Palo Alto"
            : isMeraki
              ? "Meraki"
              : "OPNsense"
      } · ${target.name}`}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-4"
      >
        {isPanoramaTarget && (
          <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            This is a Panorama target. Dynamic Address Group enforcement needs a
            standalone firewall with a vsys — arm the individual firewalls
            instead. The server rejects arming a Panorama target.
          </div>
        )}

        <label className="flex cursor-pointer items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            disabled={isPanoramaTarget}
          />
          <span className="font-medium">Arm block sync on this target</span>
        </label>
        <p className="text-xs text-muted-foreground">
          Arming enables pushes to this target. Distinct write-scoped
          credentials are required — they never leave the server except through
          the audited Reveal flow.
        </p>

        {isUnifi ? (
          <>
            <Field label="Site">
              <input
                className={inputCls}
                value={site}
                onChange={(e) => setSite(e.target.value)}
                placeholder="default"
              />
            </Field>
            <Field label="Auth kind">
              <select
                className={inputCls}
                value={authKind}
                onChange={(e) =>
                  setAuthKind(e.target.value as BlockUnifiAuthKind)
                }
              >
                <option value="api_key">API key</option>
                <option value="user_password">Username / password</option>
              </select>
            </Field>
            {authKind === "api_key" ? (
              <Field label="API key" hint={credsHint}>
                <input
                  className={`${inputCls} font-mono`}
                  type="password"
                  autoComplete="new-password"
                  value={unifiApiKey}
                  onChange={(e) => setUnifiApiKey(e.target.value)}
                  placeholder={
                    target.write_credentials_present ? "•••••• (unchanged)" : ""
                  }
                />
              </Field>
            ) : (
              <>
                <Field label="Username" hint={credsHint}>
                  <input
                    className={inputCls}
                    autoComplete="off"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder={
                      target.write_credentials_present
                        ? "•••••• (unchanged)"
                        : ""
                    }
                  />
                </Field>
                <Field label="Password">
                  <input
                    className={`${inputCls} font-mono`}
                    type="password"
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={
                      target.write_credentials_present
                        ? "•••••• (unchanged)"
                        : ""
                    }
                  />
                </Field>
              </>
            )}
          </>
        ) : isPaloalto ? (
          <>
            <Field
              label="Block tag name"
              hint="The tag SpatiumDDI writes onto blocked IPs. A Dynamic Address Group matching this tag, referenced by a deny rule, does the enforcement."
            >
              <input
                className={`${inputCls} font-mono`}
                value={tagName}
                onChange={(e) => setTagName(e.target.value)}
                placeholder="spatiumddi-quarantine"
                disabled={isPanoramaTarget}
              />
            </Field>
            <Field label="API key" hint={credsHint}>
              <input
                className={`${inputCls} font-mono`}
                type="password"
                autoComplete="new-password"
                value={panosApiKey}
                onChange={(e) => setPanosApiKey(e.target.value)}
                placeholder={
                  target.write_credentials_present ? "•••••• (unchanged)" : ""
                }
                disabled={isPanoramaTarget}
              />
            </Field>
          </>
        ) : isMeraki ? (
          <>
            <Field
              label="Block policy name"
              hint="The per-client group policy SpatiumDDI applies to blocked MACs. Defaults to Meraki's built-in Blocked policy."
            >
              <input
                className={`${inputCls} font-mono`}
                value={policyName}
                onChange={(e) => setPolicyName(e.target.value)}
                placeholder="Blocked"
              />
            </Field>
            <Field label="API key" hint={credsHint}>
              <input
                className={`${inputCls} font-mono`}
                type="password"
                autoComplete="new-password"
                value={merakiApiKey}
                onChange={(e) => setMerakiApiKey(e.target.value)}
                placeholder={
                  target.write_credentials_present ? "•••••• (unchanged)" : ""
                }
              />
            </Field>
          </>
        ) : (
          <>
            <Field
              label="Block alias name"
              hint="The OPNsense firewall alias (table) whose members SpatiumDDI manages. Must already exist and be referenced by a block rule."
            >
              <input
                className={`${inputCls} font-mono`}
                value={alias}
                onChange={(e) => setAlias(e.target.value)}
                placeholder="spatium_blocklist"
              />
            </Field>
            <Field label="API key" hint={credsHint}>
              <input
                className={`${inputCls} font-mono`}
                autoComplete="off"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={
                  target.write_credentials_present ? "•••••• (unchanged)" : ""
                }
              />
            </Field>
            <Field label="API secret">
              <input
                className={`${inputCls} font-mono`}
                type="password"
                autoComplete="new-password"
                value={apiSecret}
                onChange={(e) => setApiSecret(e.target.value)}
                placeholder={
                  target.write_credentials_present ? "•••••• (unchanged)" : ""
                }
              />
            </Field>
          </>
        )}

        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
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
            disabled={mut.isPending || isPanoramaTarget}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ── Reveal stored write credentials (password / TOTP re-confirm) ──────
function RevealModal({
  target,
  onClose,
}: {
  target: BlockTarget;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [revealed, setRevealed] = useState<BlockRevealResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () =>
      blockSyncApi.reveal(
        target.target_kind,
        target.target_id,
        password || undefined,
        totp || undefined,
      ),
    onSuccess: (data) => {
      setRevealed(data);
      setError(null);
      setPassword("");
      setTotp("");
    },
    onError: (e) => setError(errMsg(e, "Password or code is incorrect")),
  });

  const entries = revealed ? Object.entries(revealed) : [];

  return (
    <Modal title={`Reveal credentials · ${target.name}`} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Re-confirm your identity to reveal the stored write-scoped secret.
          Every reveal is audited. SSO accounts: enter an authenticator code
          instead of a password (enrol under Account → Two-factor).
        </p>

        {revealed === null ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (password || totp) mut.mutate();
            }}
            className="space-y-3"
          >
            <input
              type="password"
              autoComplete="current-password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              className={`${inputCls} font-mono`}
            />
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              placeholder="or 6-digit code"
              className={`${inputCls} font-mono`}
            />
            {error && <p className="text-xs text-destructive">{error}</p>}
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={(!password && !totp) || mut.isPending}
                className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {mut.isPending ? "Verifying…" : "Reveal"}
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-2">
            {entries.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No stored secret to reveal for this target.
              </p>
            ) : (
              entries.map(([k, v]) => (
                <div key={k} className="space-y-1">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    {k.replace(/_/g, " ")}
                  </p>
                  <div className="flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 px-2 py-1">
                    <span className="break-all font-mono text-xs">{v}</span>
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(v)}
                      className="ml-auto rounded p-1 hover:bg-accent"
                      title="Copy to clipboard"
                    >
                      <Copy className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              ))
            )}
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setRevealed(null)}
                className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
              >
                <EyeOff className="h-3.5 w-3.5" />
                Hide
              </button>
              <button
                type="button"
                onClick={onClose}
                className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
              >
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

// ── New block — preview → create (handles the 202 approval envelope) ──
function NewBlockModal({
  onClose,
  onDone,
}: {
  onClose: () => void;
  onDone: (notice?: string) => void;
}) {
  const [kind, setKind] = useState<BlockKind>("ip");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("quarantine");
  const [description, setDescription] = useState("");
  const [diff, setDiff] = useState<BlockTargetDiff[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  function body() {
    return {
      kind,
      value: value.trim(),
      reason: reason.trim() || undefined,
      description: description.trim() || undefined,
    };
  }

  const previewMut = useMutation({
    mutationFn: () => blockSyncApi.previewBlock(body()),
    onSuccess: (d) => {
      setDiff(d);
      setError(null);
    },
    onError: (e) => setError(errMsg(e, "Preview failed")),
  });

  const createMut = useMutation({
    mutationFn: () => blockSyncApi.createBlock(body()),
    onSuccess: (resp) => {
      if (handleApprovalQueued(resp)) {
        onDone(APPROVAL_QUEUED_MESSAGE);
        return;
      }
      onDone(`Block created for ${value.trim()}.`);
    },
    onError: (e) => setError(errMsg(e, "Failed to create block")),
  });

  // Invalidating the change-request badge on a 202 lives in the parent
  // via ``invalidateAll``; the approval queue keys refresh here too.
  const qc = useQueryClient();

  return (
    <Modal title="New network block" onClose={onClose} wide>
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="Kind">
            <select
              className={inputCls}
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as BlockKind);
                setDiff(null);
              }}
            >
              <option value="ip">IP address</option>
              <option value="mac">MAC address</option>
            </select>
          </Field>
          <Field label="Value" className="sm:col-span-2">
            <input
              className={`${inputCls} font-mono`}
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
                setDiff(null);
              }}
              placeholder={kind === "ip" ? "192.0.2.10" : "aa:bb:cc:dd:ee:ff"}
            />
          </Field>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Reason">
            <input
              className={inputCls}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="quarantine"
            />
          </Field>
          <Field label="Description">
            <input
              className={inputCls}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="optional note"
            />
          </Field>
        </div>

        {/* Preview */}
        <div className="rounded-md border">
          <div className="flex items-center justify-between border-b bg-muted/30 px-3 py-2">
            <span className="text-xs font-semibold text-muted-foreground">
              Preview — armed targets this block would land on
            </span>
            <button
              type="button"
              onClick={() => previewMut.mutate()}
              disabled={!value.trim() || previewMut.isPending}
              className="inline-flex items-center gap-1 rounded border px-2 py-1 text-xs hover:bg-muted disabled:opacity-40"
            >
              <RotateCw
                className={`h-3 w-3 ${
                  previewMut.isPending ? "animate-spin" : ""
                }`}
              />
              Preview
            </button>
          </div>
          <div className="p-3 text-xs">
            {diff === null ? (
              <p className="text-muted-foreground">
                Run a preview to see the exact per-target changes without
                pushing anything.
              </p>
            ) : diff.length === 0 ? (
              <p className="text-muted-foreground">
                No armed targets of this kind. Nothing would be pushed.
              </p>
            ) : (
              <ul className="space-y-1">
                {diff.map((d) => (
                  <li
                    key={`${d.target_kind}:${d.target_id}`}
                    className="flex flex-wrap items-center gap-2"
                  >
                    <span className="font-medium">{d.target_name}</span>
                    {d.error ? (
                      <span className="text-destructive">{d.error}</span>
                    ) : d.to_add.length > 0 ? (
                      <span className="text-emerald-600 dark:text-emerald-400">
                        + {d.to_add.join(", ")}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">
                        no change (already blocked)
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => {
              createMut.mutate(undefined, {
                onSuccess: () =>
                  qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY }),
              });
            }}
            disabled={!value.trim() || createMut.isPending}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {createMut.isPending ? "Creating…" : "Create block"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Reconcile-now preview modal ───────────────────────────────────────
function ReconcilePreviewModal({
  target,
  diff,
  loading,
  onClose,
  onConfirm,
}: {
  target: BlockTarget;
  diff: BlockTargetDiff | null;
  loading: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal title={`Reconcile · ${target.name}`} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Compares the desired block set against what's live on the device, then
          converges. Review the diff below before pushing.
        </p>
        <div className="rounded-md border p-3 text-xs">
          {diff === null ? (
            <p className="text-muted-foreground">Reading device…</p>
          ) : diff.error ? (
            <p className="text-destructive">{diff.error}</p>
          ) : diff.to_add.length === 0 && diff.to_remove.length === 0 ? (
            <p className="text-muted-foreground">
              Already in sync — nothing to change.
            </p>
          ) : (
            <div className="space-y-2">
              {diff.to_add.length > 0 && (
                <div>
                  <p className="font-semibold text-emerald-600 dark:text-emerald-400">
                    Add ({diff.to_add.length})
                  </p>
                  <p className="break-all font-mono text-muted-foreground">
                    {diff.to_add.join(", ")}
                  </p>
                </div>
              )}
              {diff.to_remove.length > 0 && (
                <div>
                  <p className="font-semibold text-red-600 dark:text-red-400">
                    Remove ({diff.to_remove.length})
                  </p>
                  <p className="break-all font-mono text-muted-foreground">
                    {diff.to_remove.join(", ")}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={loading || diff === null || !!diff?.error}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? "Working…" : "Reconcile now"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Small labelled field ──────────────────────────────────────────────
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
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}
