import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Copy,
  Eye,
  Loader2,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";

import {
  appliancePairingApi,
  authApi,
  settingsApi,
  type PairingCodeCreated,
  type PairingCodeRow,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { ReauthFields } from "@/components/ReauthFields";
import { cn } from "@/lib/utils";

/**
 * Appliance → Pairing codes tab (#169 + #170 Wave A3 reshape).
 *
 * Operator clicks "New pairing code" → modal asks ephemeral
 * (single-use) or persistent (multi-claim), optional expiry +
 * max_claims, generates an 8-digit code shown once in a large mono
 * box. Persistent codes can be re-revealed later via a password-
 * gated reveal action; ephemeral codes are gone after the create
 * response is closed.
 *
 * The table below polls every 2s while at least one pending code
 * exists (so a freshly-claimed ephemeral code flips state without
 * a refresh), 15s when nothing is pending.
 */

/**
 * Format an 8-digit pairing code as ``1234-5678`` for display. The
 * dash is cosmetic — the backend's pairing-code validator, the
 * installer wizard, and the supervisor entrypoint all strip
 * non-digits before validating, so an operator can type the dash
 * or leave it out and either resolves to the same hash.
 */

// #1356 — the server's default for a persistent code: 30 days.
const PERSISTENT_DEFAULT_MINUTES = 30 * 24 * 60;

function formatPairingCode(code: string): string {
  const digits = code.replace(/\D/g, "");
  if (digits.length !== 8) return code;
  return `${digits.slice(0, 4)}-${digits.slice(4)}`;
}

const inputCls =
  "rounded-md border bg-background px-3 py-1.5 text-sm disabled:opacity-60";

export function PairingTab() {
  const qc = useQueryClient();
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: authApi.me,
    staleTime: 60_000,
  });
  const isSuperadmin = me?.is_superadmin ?? false;

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["appliance", "pairing-codes"],
    queryFn: () => appliancePairingApi.list({ include_terminal: true }),
    refetchInterval: (query) => {
      const codes = query.state.data?.codes ?? [];
      const hasPending = codes.some((c) => c.state === "pending");
      return hasPending ? 2_000 : 15_000;
    },
    enabled: isSuperadmin,
  });

  const [modalOpen, setModalOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<PairingCodeRow | null>(null);
  const [revealTarget, setRevealTarget] = useState<PairingCodeRow | null>(null);
  const revokeMutation = useMutation({
    mutationFn: (id: string) => appliancePairingApi.revoke(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "pairing-codes"] });
      setRevokeTarget(null);
    },
  });
  const toggleMutation = useMutation({
    mutationFn: ({ id, enable }: { id: string; enable: boolean }) =>
      enable ? appliancePairingApi.enable(id) : appliancePairingApi.disable(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "pairing-codes"] });
    },
  });

  // #407 — supervisor (appliance) registration gate. When OFF, the
  // register endpoint 404s so no supervisor can pair, no matter how many
  // pairing codes exist. OS-appliance control-plane installs self-enable
  // this on first boot; generic Kubernetes/Helm control planes do not, so
  // the operator must flip it on here before pairing the first appliance.
  const settingsQuery = useQuery({
    queryKey: ["settings"],
    queryFn: settingsApi.get,
    enabled: isSuperadmin,
    staleTime: 30_000,
  });
  const registrationEnabled =
    settingsQuery.data?.supervisor_registration_enabled ?? null;
  const registrationToggle = useMutation({
    mutationFn: (enabled: boolean) =>
      settingsApi.update({ supervisor_registration_enabled: enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  if (!isSuperadmin) {
    return (
      <div className="mx-auto max-w-4xl">
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-4 text-sm">
          <div className="flex items-start gap-2">
            <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
            <div>
              <p className="font-medium text-amber-700 dark:text-amber-400">
                Superadmin only
              </p>
              <p className="mt-1 text-muted-foreground">
                Pairing codes hand out agent bootstrap secrets, so only
                superadmin accounts can mint or list them. Ask your platform
                admin if you need to register a new appliance.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const codes = data?.codes ?? [];

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold">Appliance pairing codes</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            8-digit codes that a new supervisor appliance swaps for a
            pending-approval registration on{" "}
            <code className="rounded bg-muted px-1">
              /api/v1/appliance/supervisor/register
            </code>
            . Ephemeral codes are single-use with a short expiry; persistent
            codes admit many appliances and can be re-revealed.
          </p>
        </div>
        <div className="flex flex-shrink-0 gap-2">
          <button
            type="button"
            onClick={() => refetch()}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            disabled={isFetching}
            title="Refresh"
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", isFetching && "animate-spin")}
            />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => setModalOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-3.5 w-3.5" />
            New pairing code
          </button>
        </div>
      </div>

      {/* #407 — registration gate. Surfaces + toggles
          ``supervisor_registration_enabled`` so an operator can enable
          appliance pairing from the UI instead of hand-editing the DB.
          Generic Kubernetes/Helm control planes ship with it OFF. */}
      <div
        className={cn(
          "mb-4 rounded-md border p-3",
          registrationEnabled === false &&
            "border-amber-500/40 bg-amber-500/10",
        )}
      >
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium">
              Appliance registration{" "}
              {registrationEnabled === null ? (
                <span className="text-muted-foreground">…</span>
              ) : registrationEnabled ? (
                <span className="text-emerald-600 dark:text-emerald-400">
                  enabled
                </span>
              ) : (
                <span className="text-amber-700 dark:text-amber-400">
                  disabled
                </span>
              )}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {registrationEnabled === false
                ? "New supervisors cannot pair while this is off — the register endpoint returns 404. Enable it before pairing an appliance."
                : "Remote supervisors may register with a valid pairing code. Turn this off to refuse all new pairings."}
            </p>
          </div>
          <button
            type="button"
            disabled={
              registrationEnabled === null || registrationToggle.isPending
            }
            onClick={() => registrationToggle.mutate(!registrationEnabled)}
            className={cn(
              "inline-flex flex-shrink-0 items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium disabled:opacity-60",
              registrationEnabled
                ? "border hover:bg-muted"
                : "bg-primary text-primary-foreground hover:bg-primary/90",
            )}
          >
            {registrationToggle.isPending && (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            )}
            {registrationEnabled ? "Disable" : "Enable"} registration
          </button>
        </div>
        {registrationToggle.isError && (
          <p className="mt-2 text-xs text-rose-700 dark:text-rose-300">
            {formatApiError(registrationToggle.error)}
          </p>
        )}
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading pairing codes…
        </div>
      ) : codes.length === 0 ? (
        <div className="rounded-md border bg-muted/30 p-6 text-center text-sm text-muted-foreground">
          No pairing codes yet. Click{" "}
          <span className="font-medium">New pairing code</span> to mint one.
        </div>
      ) : (
        <CodesTable
          codes={codes}
          onRevoke={(row) => setRevokeTarget(row)}
          onReveal={(row) => setRevealTarget(row)}
          onToggleEnabled={(row) =>
            toggleMutation.mutate({ id: row.id, enable: !row.enabled })
          }
          toggleInFlight={toggleMutation.isPending}
        />
      )}

      {modalOpen && (
        <GenerateCodeModal
          onClose={() => setModalOpen(false)}
          onCreated={() => {
            qc.invalidateQueries({ queryKey: ["appliance", "pairing-codes"] });
          }}
        />
      )}

      <ConfirmModal
        open={revokeTarget !== null}
        title="Revoke pairing code?"
        message={
          revokeTarget ? (
            <>
              Revoke this {revokeTarget.persistent ? "persistent" : "ephemeral"}{" "}
              pairing code? Already-claimed appliances keep working — only new
              claims are blocked. This is permanent; revoked codes can't be
              re-enabled.
            </>
          ) : (
            ""
          )
        }
        confirmLabel="Revoke"
        tone="destructive"
        loading={revokeMutation.isPending}
        onClose={() => setRevokeTarget(null)}
        onConfirm={() => revokeTarget && revokeMutation.mutate(revokeTarget.id)}
      />

      {revealTarget && (
        <RevealModal row={revealTarget} onClose={() => setRevealTarget(null)} />
      )}
    </div>
  );
}

// ── Table ───────────────────────────────────────────────────────────

function CodesTable({
  codes,
  onRevoke,
  onReveal,
  onToggleEnabled,
  toggleInFlight,
}: {
  codes: PairingCodeRow[];
  onRevoke: (row: PairingCodeRow) => void;
  onReveal: (row: PairingCodeRow) => void;
  onToggleEnabled: (row: PairingCodeRow) => void;
  toggleInFlight: boolean;
}) {
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="min-w-full text-sm">
        <thead className="bg-muted/40 text-left text-xs font-medium text-muted-foreground">
          <tr>
            <th className="px-3 py-2">Code</th>
            <th className="px-3 py-2">Kind</th>
            <th className="px-3 py-2">State</th>
            <th className="px-3 py-2">Claims</th>
            <th className="px-3 py-2">Expires</th>
            <th className="px-3 py-2">Note</th>
            <th className="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody>
          {codes.map((row) => (
            <tr key={row.id} className="border-t">
              <td className="px-3 py-2 font-mono text-xs">
                ••{row.code_last_two}
              </td>
              <td className="px-3 py-2">
                <KindChip persistent={row.persistent} />
              </td>
              <td className="px-3 py-2">
                <StateChip state={row.state} />
              </td>
              <td className="px-3 py-2 text-xs">
                {row.claim_count}
                {row.max_claims != null && (
                  <span className="text-muted-foreground">
                    {" "}
                    / {row.max_claims}
                  </span>
                )}
              </td>
              <td className="px-3 py-2 text-xs text-muted-foreground">
                {row.expires_at ? <RelativeTime iso={row.expires_at} /> : "—"}
              </td>
              <td className="px-3 py-2 max-w-[16rem] truncate text-xs">
                {row.note ?? "—"}
              </td>
              <td className="px-3 py-2">
                <div className="flex justify-end gap-1">
                  {row.persistent && row.state !== "revoked" && (
                    <button
                      type="button"
                      onClick={() => onReveal(row)}
                      title="Reveal code"
                      className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                    >
                      <Eye className="h-3.5 w-3.5" />
                    </button>
                  )}
                  {row.persistent && row.state !== "revoked" && (
                    <button
                      type="button"
                      onClick={() => onToggleEnabled(row)}
                      disabled={toggleInFlight}
                      title={row.enabled ? "Pause new claims" : "Resume claims"}
                      className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-50"
                    >
                      {row.enabled ? (
                        <Pause className="h-3.5 w-3.5" />
                      ) : (
                        <Play className="h-3.5 w-3.5" />
                      )}
                    </button>
                  )}
                  {row.state !== "revoked" && row.state !== "expired" && (
                    <button
                      type="button"
                      onClick={() => onRevoke(row)}
                      title="Revoke"
                      className="rounded p-1 text-destructive hover:bg-destructive/10"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function KindChip({ persistent }: { persistent: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex rounded px-1.5 py-0.5 text-xs",
        persistent
          ? "bg-violet-100 text-violet-700 dark:bg-violet-500/15 dark:text-violet-300"
          : "bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300",
      )}
    >
      {persistent ? "persistent" : "ephemeral"}
    </span>
  );
}

function StateChip({ state }: { state: PairingCodeRow["state"] }) {
  const cls: Record<PairingCodeRow["state"], string> = {
    pending:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300",
    claimed: "bg-blue-100 text-blue-700 dark:bg-blue-500/15 dark:text-blue-300",
    disabled:
      "bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300",
    expired: "bg-zinc-100 text-zinc-700 dark:bg-zinc-500/15 dark:text-zinc-300",
    revoked: "bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300",
  };
  return (
    <span
      className={cn("inline-flex rounded px-1.5 py-0.5 text-xs", cls[state])}
    >
      {state}
    </span>
  );
}

function RelativeTime({ iso }: { iso: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(t);
  }, []);
  const target = useMemo(() => new Date(iso).getTime(), [iso]);
  const diffSec = Math.round((target - now) / 1000);
  if (diffSec < 0) return <span>expired</span>;
  if (diffSec < 60) return <span>in {diffSec}s</span>;
  if (diffSec < 3600) return <span>in {Math.round(diffSec / 60)}m</span>;
  if (diffSec < 86400) return <span>in {Math.round(diffSec / 3600)}h</span>;
  return <span>in {Math.round(diffSec / 86400)}d</span>;
}

// ── Generate modal ──────────────────────────────────────────────────

function GenerateCodeModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [persistent, setPersistent] = useState(false);
  const [expiresInMinutes, setExpiresInMinutes] = useState<number | null>(15);
  const [maxClaims, setMaxClaims] = useState<number | "">("");
  const [note, setNote] = useState("");
  const [generated, setGenerated] = useState<PairingCodeCreated | null>(null);

  // Reset expiry default when toggling persistent: ephemeral defaults
  // to 15 min, persistent to 30 days (#1356). 0 = never, persistent only.
  useEffect(() => {
    setExpiresInMinutes(persistent ? PERSISTENT_DEFAULT_MINUTES : 15);
    if (!persistent) setMaxClaims("");
  }, [persistent]);

  const mutation = useMutation({
    mutationFn: () =>
      appliancePairingApi.create({
        persistent,
        expires_in_minutes: expiresInMinutes,
        max_claims: persistent && maxClaims !== "" ? Number(maxClaims) : null,
        note: note.trim() || null,
      }),
    onSuccess: (body) => {
      setGenerated(body);
      onCreated();
    },
  });

  return (
    <Modal onClose={onClose} title="New pairing code">
      {generated ? (
        <GeneratedView code={generated} onClose={onClose} />
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
          className="flex flex-col gap-4"
        >
          {/* Persistent toggle — two card-style radios */}
          <fieldset className="flex flex-col gap-2">
            <legend className="text-sm font-medium">Flavour</legend>
            <div className="grid grid-cols-2 gap-2">
              {[
                {
                  value: false,
                  title: "Ephemeral",
                  subtitle: "Single-use, short expiry",
                },
                {
                  value: true,
                  title: "Persistent",
                  subtitle: "Multi-claim, re-revealable",
                },
              ].map((opt) => (
                <label
                  key={String(opt.value)}
                  className={cn(
                    "cursor-pointer rounded-md border p-2",
                    persistent === opt.value
                      ? "border-primary bg-primary/5"
                      : "hover:bg-muted",
                  )}
                >
                  <input
                    type="radio"
                    className="sr-only"
                    checked={persistent === opt.value}
                    onChange={() => setPersistent(opt.value)}
                  />
                  <div className="text-sm font-medium">{opt.title}</div>
                  <div className="text-xs text-muted-foreground">
                    {opt.subtitle}
                  </div>
                </label>
              ))}
            </div>
          </fieldset>

          <label className="flex flex-col gap-1 text-sm">
            <span className="text-xs font-medium">
              Expiry{" "}
              <span className="text-muted-foreground">
                {persistent
                  ? "(minutes — default 30 days, 0 for no expiry)"
                  : "(minutes)"}
              </span>
            </span>
            <input
              type="number"
              className={inputCls}
              min={persistent ? 0 : 5}
              max={persistent ? undefined : 60}
              value={expiresInMinutes ?? 0}
              onChange={(e) => setExpiresInMinutes(Number(e.target.value))}
            />
          </label>
          {persistent && expiresInMinutes === 0 && (
            <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-300">
              A code that never expires lets any appliance that learns its 8
              digits ask to join, for as long as the code exists. Prefer an
              expiry, and revoke the code when the rollout is done.
            </p>
          )}

          {persistent && (
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-xs font-medium">
                Max claims{" "}
                <span className="text-muted-foreground">
                  (blank = unlimited)
                </span>
              </span>
              <input
                type="number"
                className={inputCls}
                min={1}
                value={maxClaims}
                onChange={(e) =>
                  setMaxClaims(e.target.value ? Number(e.target.value) : "")
                }
              />
            </label>
          )}

          <label className="flex flex-col gap-1 text-sm">
            <span className="text-xs font-medium">
              Note <span className="text-muted-foreground">(optional)</span>
            </span>
            <input
              type="text"
              className={inputCls}
              maxLength={255}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="e.g. staging fleet"
            />
          </label>

          {mutation.error && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
              {formatApiError(mutation.error)}
            </div>
          )}

          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60"
            >
              {mutation.isPending && (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              )}
              Generate
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function GeneratedView({
  code,
  onClose,
}: {
  code: PairingCodeCreated;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const copyRef = useRef<number | null>(null);
  const formatted = formatPairingCode(code.code);
  const onCopy = async () => {
    // Copy the formatted form (1234-5678) so paste into the
    // installer / Settings field carries the same characters the
    // operator sees on screen. The backend + installer + supervisor
    // all strip non-digits before validating, so the dashes are
    // cosmetic only.
    await navigator.clipboard.writeText(formatted);
    setCopied(true);
    if (copyRef.current !== null) window.clearTimeout(copyRef.current);
    copyRef.current = window.setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm">
        {code.persistent ? (
          <>
            Persistent code minted. The cleartext is{" "}
            <strong>also recoverable</strong> later via the{" "}
            <Eye className="inline h-3 w-3" /> reveal action.
          </>
        ) : (
          <>
            Ephemeral code minted. <strong>Copy it now</strong> — the cleartext
            is shown exactly once and not recoverable later.
          </>
        )}
      </p>
      <div className="flex items-center gap-2">
        <code className="flex-1 rounded-md border bg-muted px-4 py-3 text-center font-mono text-2xl tracking-widest">
          {formatted}
        </code>
        <button
          type="button"
          onClick={onCopy}
          className="rounded-md border p-2 hover:bg-muted"
          title="Copy"
        >
          {copied ? (
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
          ) : (
            <Copy className="h-4 w-4" />
          )}
        </button>
      </div>
      {code.expires_at && (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Clock className="h-3 w-3" />
          Expires <RelativeTime iso={code.expires_at} />
        </p>
      )}
      {code.max_claims != null && (
        <p className="text-xs text-muted-foreground">
          Max claims: {code.max_claims}
        </p>
      )}
      <div className="flex justify-end">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Done
        </button>
      </div>
    </div>
  );
}

// ── Reveal modal ────────────────────────────────────────────────────

function RevealModal({
  row,
  onClose,
}: {
  row: PairingCodeRow;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [revealed, setRevealed] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const mutation = useMutation({
    mutationFn: () =>
      appliancePairingApi.reveal(
        row.id,
        password || undefined,
        totp || undefined,
      ),
    onSuccess: (body) => setRevealed(body.code),
  });

  const formattedRevealed = revealed ? formatPairingCode(revealed) : null;
  const onCopy = async () => {
    if (!formattedRevealed) return;
    await navigator.clipboard.writeText(formattedRevealed);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <Modal onClose={onClose} title="Reveal pairing code">
      {revealed ? (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded-md border bg-muted px-4 py-3 text-center font-mono text-2xl tracking-widest">
              {formattedRevealed}
            </code>
            <button
              type="button"
              onClick={onCopy}
              className="rounded-md border p-2 hover:bg-muted"
              title="Copy"
            >
              {copied ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </button>
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            >
              Done
            </button>
          </div>
        </div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
          className="flex flex-col gap-3"
        >
          <p className="text-xs text-muted-foreground">
            Re-display the cleartext of this persistent code. Re-confirm with
            your password (local accounts) or an authenticator code (SSO).
          </p>
          <ReauthFields
            password={password}
            onPassword={setPassword}
            totp={totp}
            onTotp={setTotp}
            autoFocus
          />
          {mutation.error && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
              {formatApiError(mutation.error)}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending || (!password && !totp)}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60"
            >
              {mutation.isPending && (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              )}
              Reveal
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
