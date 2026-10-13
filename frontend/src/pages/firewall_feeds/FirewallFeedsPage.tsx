import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Clipboard,
  Eye,
  EyeOff,
  Pencil,
  Plus,
  RefreshCw,
  RotateCw,
  Rss,
  Trash2,
} from "lucide-react";

import {
  firewallFeedsApi,
  type FirewallFeed,
  type FirewallFeedCreate,
  type FirewallFeedTokenResult,
  type FirewallFeedUpdate,
} from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";

// Full poll URL for a feed — prefix the server-relative poll_path with
// the current origin so operators can paste it straight into a
// FortiGate External Threat Feed / Cisco SI feed.
function fullPollUrl(pollPath: string): string {
  return `${window.location.origin}${pollPath}`;
}

// ── Page ─────────────────────────────────────────────────────────────

export function FirewallFeedsPage() {
  // #1341 — every write on this page takes a superadmin (its handlers
  // take SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const { data: feeds = [], isFetching } = useQuery({
    queryKey: ["firewall-feeds"],
    queryFn: firewallFeedsApi.list,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [created, setCreated] = useState<FirewallFeedTokenResult | null>(null);
  const [edit, setEdit] = useState<FirewallFeed | null>(null);
  const [del, setDel] = useState<FirewallFeed | null>(null);
  const [reveal, setReveal] = useState<FirewallFeed | null>(null);
  const [rotate, setRotate] = useState<FirewallFeed | null>(null);
  const [rotated, setRotated] = useState<FirewallFeedTokenResult | null>(null);

  const delMut = useMutation({
    mutationFn: (id: string) => firewallFeedsApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["firewall-feeds"] });
      setDel(null);
    },
  });

  const rotateMut = useMutation({
    mutationFn: (id: string) => firewallFeedsApi.rotateToken(id),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["firewall-feeds"] });
      setRotate(null);
      setRotated(result);
    },
  });

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="border-b px-6 py-4 bg-card">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Rss className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Firewall feeds</h1>
              <span className="text-xs text-muted-foreground">
                {feeds.length} configured
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground max-w-3xl">
              Credential-free enforcement, inverted: SpatiumDDI serves a
              token-guarded plaintext blocklist that your firewall polls, rather
              than SpatiumDDI writing to the firewall. Point a FortiGate
              External Threat Feed (or a Cisco Security Intelligence feed) at a
              feed URL and the firewall pulls the current SpatiumDDI-owned IP
              blocks on its own schedule.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["firewall-feeds"] })
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
              New feed
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="rounded-lg border">
          {feeds.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-sm text-muted-foreground">
                No firewall feeds yet.
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-3 inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                {...superadminGate}
              >
                <Plus className="h-3 w-3" /> New feed
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px] text-xs">
                <thead>
                  <tr className="border-b bg-muted/30">
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Name
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Enabled
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Kind
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Polls
                    </th>
                    <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                      Last polled
                    </th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {feeds.map((f) => (
                    <tr key={f.id} className="border-b last:border-0">
                      <td className="whitespace-nowrap px-3 py-2 font-medium">
                        {f.name}
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
                      <td className="whitespace-nowrap px-3 py-2 uppercase text-muted-foreground">
                        {f.kind}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                        {f.poll_count}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                        {f.last_polled_at
                          ? new Date(f.last_polled_at).toLocaleString()
                          : "never"}
                        {f.last_polled_ip && (
                          <div className="text-[11px] text-muted-foreground/70 font-mono">
                            {f.last_polled_ip}
                          </div>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-right">
                        <button
                          onClick={() => setReveal(f)}
                          className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                          title="Reveal poll URL"
                          {...superadminGate}
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setRotate(f)}
                          className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                          title="Rotate token"
                          {...superadminGate}
                        >
                          <RotateCw className="h-3.5 w-3.5" />
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
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {showCreate && (
        <CreateFeedModal
          onClose={() => setShowCreate(false)}
          onCreated={(result) => {
            setShowCreate(false);
            setCreated(result);
          }}
        />
      )}
      {created && (
        <TokenModal
          title="Feed created — copy the poll URL now"
          subtitle="This is the only time the token is shown in full. You can re-reveal it later with a password confirmation."
          result={created}
          onClose={() => setCreated(null)}
        />
      )}
      {rotated && (
        <TokenModal
          title="Token rotated — copy the new poll URL"
          subtitle="The previous URL is now invalid. Update your firewall's feed configuration with this URL."
          result={rotated}
          onClose={() => setRotated(null)}
        />
      )}
      {edit && <EditFeedModal feed={edit} onClose={() => setEdit(null)} />}
      {reveal && <RevealModal feed={reveal} onClose={() => setReveal(null)} />}
      <ConfirmModal
        open={!!rotate}
        title="Rotate feed token"
        message={
          <>
            Rotate the token for{" "}
            <span className="font-semibold">{rotate?.name}</span>? The current
            poll URL stops working immediately and every firewall pointed at it
            must be updated with the new URL.
          </>
        }
        tone="destructive"
        confirmLabel="Rotate token"
        loading={rotateMut.isPending}
        onConfirm={() => rotate && rotateMut.mutate(rotate.id)}
        onClose={() => setRotate(null)}
      />
      {del && (
        <DeleteFeedModal
          feed={del}
          onClose={() => setDel(null)}
          onConfirm={() => delMut.mutate(del.id)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

// ── Token reveal modal (shown once on create + on rotate) ────────────

function TokenModal({
  title,
  subtitle,
  result,
  onClose,
}: {
  title: string;
  subtitle: string;
  result: FirewallFeedTokenResult;
  onClose: () => void;
}) {
  const url = fullPollUrl(result.poll_path);
  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">{subtitle}</p>
        <div className="space-y-1">
          <label className="block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Poll URL
          </label>
          <CopyableValue value={url} />
          <p className="text-[11px] text-muted-foreground">
            Point your FortiGate External Threat Feed (or Cisco SI feed) at this
            URL.
          </p>
        </div>
        <div className="space-y-1">
          <label className="block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Token
          </label>
          <CopyableValue value={result.token} mono />
        </div>
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            Done
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Reveal (password / TOTP re-confirm) ──────────────────────────────

function RevealModal({
  feed,
  onClose,
}: {
  feed: FirewallFeed;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [revealed, setRevealed] = useState<FirewallFeedTokenResult | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () =>
      firewallFeedsApi.reveal(
        feed.id,
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

  return (
    <Modal title={`Reveal poll URL · ${feed.name}`} onClose={onClose} wide>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Re-confirm your identity to reveal the feed token and full poll URL.
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
          <div className="space-y-3">
            <div className="space-y-1">
              <label className="block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                Poll URL
              </label>
              <CopyableValue value={fullPollUrl(revealed.poll_path)} />
            </div>
            <div className="space-y-1">
              <label className="block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                Token
              </label>
              <CopyableValue value={revealed.token} mono />
            </div>
            <div className="flex justify-end gap-2 pt-1">
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

// ── Create / Edit ────────────────────────────────────────────────────

function CreateFeedModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (result: FirewallFeedTokenResult) => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: () => {
      const body: FirewallFeedCreate = {
        name,
        description,
        enabled,
        kind: "ip",
      };
      return firewallFeedsApi.create(body);
    },
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["firewall-feeds"] });
      onCreated({ token: result.token, poll_path: result.poll_path });
    },
    onError: (e) => setError(errMsg(e, "Failed to create feed")),
  });

  return (
    <Modal title="New firewall feed" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. FortiGate quarantine"
            required
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <label className="flex cursor-pointer items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          <span>Enabled</span>
        </label>
        <p className="text-[11px] text-muted-foreground">
          The feed serves the current SpatiumDDI-owned IP blocks as a plaintext
          list. The poll URL + token are shown once after create.
        </p>

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
            disabled={mut.isPending || !name}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Creating…" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditFeedModal({
  feed,
  onClose,
}: {
  feed: FirewallFeed;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(feed.name);
  const [description, setDescription] = useState(feed.description);
  const [enabled, setEnabled] = useState(feed.enabled);
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: () => {
      const body: FirewallFeedUpdate = { name, description, enabled };
      return firewallFeedsApi.update(feed.id, body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["firewall-feeds"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save feed")),
  });

  return (
    <Modal title="Edit firewall feed" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <label className="flex cursor-pointer items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          <span>Enabled</span>
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
            disabled={mut.isPending || !name}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DeleteFeedModal({
  feed,
  onConfirm,
  onClose,
  isPending,
}: {
  feed: FirewallFeed;
  onConfirm: () => void;
  onClose: () => void;
  isPending: boolean;
}) {
  const [checked, setChecked] = useState(false);
  return (
    <Modal title="Delete firewall feed" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Delete the feed <span className="font-semibold">{feed.name}</span>?
          Its poll URL stops working immediately — any firewall pointed at it
          will fail to refresh and eventually fall back to an empty list.
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

function CopyableValue({ value, mono }: { value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false);
  async function handle() {
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }
  }
  return (
    <div className="flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 px-2 py-1.5">
      <span className={`break-all text-xs ${mono ? "font-mono" : ""}`}>
        {value}
      </span>
      <button
        type="button"
        onClick={handle}
        className="ml-auto inline-flex flex-shrink-0 items-center gap-1 rounded border bg-background px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground"
        title="Copy to clipboard"
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
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
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
