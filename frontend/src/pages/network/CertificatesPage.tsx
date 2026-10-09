import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";

import {
  settingsApi,
  tlsCertsApi,
  type TLSCertSource,
  type TLSCertState,
  type TLSCertTarget,
  type TLSCertTargetCreate,
  type TLSCertTargetUpdate,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { SavedViewsMenu } from "@/components/SavedViewsMenu";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import {
  TLS_CERT_STATES,
  fmtDateTime,
  tlsStateCls,
} from "@/lib/tls-cert-state";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// ── Shared state pill components ──────────────────────────────────────
//
// Re-exported so the Domain / DNS-zone Certs tabs and the DNS record
// pill render the same styling. The colour/label helpers themselves
// live in ``@/lib/tls-cert-state`` (kept out of this component file so
// Fast Refresh doesn't warn on mixed exports).

export function TLSStateBadge({ state }: { state: TLSCertState }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        tlsStateCls(state),
      )}
    >
      {state}
    </span>
  );
}

/** Subtle inline pill — used on the DNS record table for A/AAAA rows. */
export function TLSStatePill({ state }: { state: TLSCertState }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        tlsStateCls(state),
      )}
      title={`TLS cert: ${state}`}
    >
      TLS {state}
    </span>
  );
}

/** Compact "<date> · <Nd>" cell showing expiry + days-remaining badge. */
export function NotAfterCell({
  notAfter,
  daysRemaining,
}: {
  notAfter: string | null;
  daysRemaining: number | null;
}) {
  if (!notAfter) return <span className="text-muted-foreground/50">—</span>;
  let cls =
    "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400";
  let label = daysRemaining !== null ? `${daysRemaining}d` : "—";
  if (daysRemaining !== null) {
    if (daysRemaining < 0) {
      cls = "bg-red-200 text-red-900 dark:bg-red-950/50 dark:text-red-300";
      label = `expired ${Math.abs(daysRemaining)}d ago`;
    } else if (daysRemaining <= 14) {
      cls = "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400";
    } else if (daysRemaining <= 30) {
      cls =
        "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400";
    }
  }
  return (
    <span className="inline-flex items-center gap-2">
      <span className="text-[11px] tabular-nums text-muted-foreground">
        {new Date(notAfter).toLocaleDateString()}
      </span>
      <span
        className={cn(
          "rounded px-2 py-0.5 text-[10px] font-medium tabular-nums",
          cls,
        )}
      >
        {label}
      </span>
    </span>
  );
}

/** Compact read-only certs table reused by the Domain / DNS-zone Certs
 *  tabs. Takes a pre-fetched list so the parent owns the gated query. */
export function CertsCompactTable({
  targets,
  isLoading,
  emptyLabel = "No TLS certificates linked.",
}: {
  targets: TLSCertTarget[];
  isLoading?: boolean;
  emptyLabel?: string;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-sm">
        <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-3 py-2 text-left">Host</th>
            <th className="px-3 py-2 text-left">State</th>
            <th className="px-3 py-2 text-left">Issuer</th>
            <th className="px-3 py-2 text-left">Expires</th>
          </tr>
        </thead>
        <tbody className={zebraBodyCls}>
          {isLoading && (
            <tr>
              <td
                colSpan={4}
                className="px-3 py-6 text-center text-muted-foreground"
              >
                Loading…
              </td>
            </tr>
          )}
          {!isLoading && targets.length === 0 && (
            <tr>
              <td
                colSpan={4}
                className="px-3 py-6 text-center text-muted-foreground"
              >
                {emptyLabel}
              </td>
            </tr>
          )}
          {targets.map((t) => (
            <tr key={t.id} className="border-t">
              <td className="px-3 py-2 align-top break-words">
                <span className="font-medium">{t.host}</span>
                <span className="text-muted-foreground">:{t.port}</span>
              </td>
              <td className="px-3 py-2 align-top">
                <TLSStateBadge state={t.state} />
              </td>
              <td className="px-3 py-2 align-top break-words text-muted-foreground">
                {t.issuer_cn ?? "—"}
              </td>
              <td className="px-3 py-2 align-top">
                <NotAfterCell
                  notAfter={t.not_after}
                  daysRemaining={t.days_remaining}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ChainBadge({ target }: { target: TLSCertTarget }) {
  if (target.chain_valid === null) {
    return <span className="text-muted-foreground/50">—</span>;
  }
  if (target.chain_valid) {
    return (
      <span className="inline-flex items-center rounded bg-emerald-100 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400">
        valid
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center rounded bg-red-100 px-2 py-0.5 text-[10px] font-medium text-red-700 dark:bg-red-950/30 dark:text-red-400"
      title={target.chain_error ?? "Chain invalid"}
    >
      {target.self_signed ? "self-signed" : "invalid"}
    </span>
  );
}

function SourceChip({ source }: { source: TLSCertSource }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider",
        source === "manual"
          ? "bg-blue-100 text-blue-700 dark:bg-blue-950/30 dark:text-blue-400"
          : "bg-violet-100 text-violet-700 dark:bg-violet-950/30 dark:text-violet-400",
      )}
    >
      {source}
    </span>
  );
}

// ── Editor modal ─────────────────────────────────────────────────────

function CertTargetEditorModal({
  existing,
  onClose,
}: {
  existing: TLSCertTarget | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();

  const [host, setHost] = useState(existing?.host ?? "");
  const [port, setPort] = useState(String(existing?.port ?? 443));
  const [serverName, setServerName] = useState(existing?.server_name ?? "");
  const [displayName, setDisplayName] = useState(existing?.display_name ?? "");
  const [intervalHours, setIntervalHours] = useState(
    existing?.interval_hours != null ? String(existing.interval_hours) : "",
  );
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);

  // Platform default cadence — shown so the operator knows what "blank" means.
  const { data: settings } = useQuery({
    queryKey: ["platform-settings"],
    queryFn: settingsApi.get,
    staleTime: 5 * 60 * 1000,
  });
  const defaultHours = settings?.tls_cert_check_interval_hours ?? 6;

  const mut = useMutation({
    mutationFn: async () => {
      if (!host.trim()) throw new Error("Host is required");
      const parsedInterval = intervalHours.trim()
        ? Number(intervalHours)
        : null;
      const body: TLSCertTargetCreate | TLSCertTargetUpdate = {
        host: host.trim(),
        port: Number(port) || 443,
        server_name: serverName.trim() || null,
        display_name: displayName.trim() || null,
        interval_hours: parsedInterval,
        enabled,
      };
      if (existing) return tlsCertsApi.update(existing.id, body);
      return tlsCertsApi.create(body as TLSCertTargetCreate);
    },
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: ["tls-certs"] });
      onClose();
      // A freshly-added target probes immediately so the row shows a real
      // state within seconds instead of sitting at "unknown" until the next
      // sweep. Detached — the modal closes right away; the synchronous probe
      // refreshes the list when it lands (~a few seconds).
      if (!existing && saved?.id) {
        tlsCertsApi
          .probeNow(saved.id)
          .catch(() => {})
          .finally(() => qc.invalidateQueries({ queryKey: ["tls-certs"] }));
      }
    },
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string } };
      };
      setError(err?.response?.data?.detail ?? err?.message ?? "Save failed");
    },
  });

  return (
    <Modal
      onClose={onClose}
      title={
        existing
          ? `Edit ${existing.display_name || existing.host}`
          : "New TLS cert target"
      }
    >
      <div className="grid grid-cols-1 gap-3 pb-2 sm:grid-cols-2">
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Host
          </label>
          <input
            className={inputCls}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="e.g. www.example.com or 10.0.0.5"
            autoFocus={!existing}
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Port
          </label>
          <input
            type="number"
            min={1}
            max={65535}
            className={inputCls}
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Server name (SNI, optional)
          </label>
          <input
            className={inputCls}
            value={serverName}
            onChange={(e) => setServerName(e.target.value)}
            placeholder="Overrides the SNI sent during the handshake"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Display name (optional)
          </label>
          <input
            className={inputCls}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Friendly label for the list view"
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Check interval (hours, optional)
          </label>
          <input
            type="number"
            min={1}
            max={168}
            className={inputCls}
            value={intervalHours}
            onChange={(e) => setIntervalHours(e.target.value)}
            placeholder={`Default: every ${defaultHours}h`}
          />
          <p className="mt-1 text-[11px] text-muted-foreground">
            Leave blank to use the platform default (every {defaultHours} h).
          </p>
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enabled
          </label>
        </div>
      </div>

      {error && <p className="mt-3 text-sm text-destructive">{error}</p>}

      <div className="mt-6 flex justify-end gap-2 border-t pt-3">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={mut.isPending}
          onClick={() => mut.mutate()}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
        </button>
      </div>
    </Modal>
  );
}

// ── Detail modal ──────────────────────────────────────────────────────

function DetailRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-2 py-1 text-sm">
      <div className="text-muted-foreground">{label}</div>
      <div className="min-w-0 break-words">{children}</div>
    </div>
  );
}

function DetailSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="mt-4 first:mt-0">
      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {title}
      </h3>
      <div className="rounded-md border px-3 py-1.5">{children}</div>
    </div>
  );
}

const DASH = "—";

function chainRoleCls(role: string): string {
  if (role === "leaf")
    return "bg-blue-100 text-blue-700 dark:bg-blue-950/30 dark:text-blue-400";
  if (role === "root")
    return "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400";
  return "bg-violet-100 text-violet-700 dark:bg-violet-950/30 dark:text-violet-400";
}

function CertDetailModal({
  target,
  onClose,
  onEdit,
}: {
  target: TLSCertTarget;
  onClose: () => void;
  onEdit: () => void;
}) {
  const qc = useQueryClient();
  const [showPem, setShowPem] = useState(false);
  // CT log is an off-prem call (leaks the hostname to crt.sh) — opt-in,
  // fetched only when the operator expands it.
  const [showCt, setShowCt] = useState(false);

  // Live row so a probe-now reflects without reopening.
  const { data: t = target } = useQuery({
    queryKey: ["tls-certs", "detail", target.id],
    queryFn: () => tlsCertsApi.get(target.id),
    initialData: target,
  });

  const chainQuery = useQuery({
    queryKey: ["tls-certs", "chain", target.id],
    queryFn: () => tlsCertsApi.chain(target.id),
    retry: false, // 404 until the first successful probe — don't hammer
  });
  const chain = chainQuery.data?.chain ?? [];

  const ctQuery = useQuery({
    queryKey: ["tls-certs", "ct-log", target.id],
    queryFn: () => tlsCertsApi.ctLog(target.id, { limit: 50 }),
    enabled: showCt,
    retry: false,
    staleTime: 5 * 60 * 1000,
  });

  const probe = useMutation({
    mutationFn: () => tlsCertsApi.probeNow(target.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tls-certs"] });
    },
  });

  const effectiveInterval = t.interval_hours
    ? `${t.interval_hours} h (override)`
    : "platform default";

  return (
    <Modal onClose={onClose} title={t.display_name || t.host} wide>
      <div>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          <span className="font-mono text-xs text-muted-foreground">
            {t.host}:{t.port}
          </span>
          <TLSStateBadge state={t.state} />
        </div>
        <DetailSection title="Endpoint">
          <DetailRow label="Host : port">
            <span className="font-mono">
              {t.host}:{t.port}
            </span>
          </DetailRow>
          <DetailRow label="SNI">
            <span className="font-mono">{t.server_name || `(${t.host})`}</span>
          </DetailRow>
          <DetailRow label="Source">{t.source}</DetailRow>
          <DetailRow label="Enabled">{t.enabled ? "Yes" : "No"}</DetailRow>
          <DetailRow label="Check interval">{effectiveInterval}</DetailRow>
          <DetailRow label="Last checked">
            {fmtDateTime(t.last_checked_at)}
          </DetailRow>
          <DetailRow label="Next check">
            {fmtDateTime(t.next_check_at)}
          </DetailRow>
          {t.last_error && (
            <DetailRow label="Last error">
              <span className="text-destructive">{t.last_error}</span>
            </DetailRow>
          )}
        </DetailSection>

        <DetailSection title="Certificate">
          <DetailRow label="Subject CN">{t.subject_cn || DASH}</DetailRow>
          <DetailRow label="Issuer CN">{t.issuer_cn || DASH}</DetailRow>
          <DetailRow label="Serial">
            <span className="font-mono text-xs">{t.serial || DASH}</span>
          </DetailRow>
          <DetailRow label="Valid from">{fmtDateTime(t.not_before)}</DetailRow>
          <DetailRow label="Valid to">
            <NotAfterCell
              notAfter={t.not_after}
              daysRemaining={t.days_remaining}
            />
          </DetailRow>
          <DetailRow label="Self-signed">
            {t.self_signed == null ? DASH : t.self_signed ? "Yes" : "No"}
          </DetailRow>
        </DetailSection>

        <DetailSection title="Chain & key">
          <DetailRow label="Chain valid">
            {t.chain_valid == null ? DASH : t.chain_valid ? "Yes" : "No"}
          </DetailRow>
          {t.chain_error && (
            <DetailRow label="Chain error">
              <span className="text-destructive">{t.chain_error}</span>
            </DetailRow>
          )}
          <DetailRow label="Chain depth">{t.chain_depth ?? DASH}</DetailRow>
          <DetailRow label="Key">
            {t.key_algo
              ? `${t.key_algo}${t.key_size ? ` ${t.key_size}-bit` : ""}`
              : DASH}
          </DetailRow>
          <DetailRow label="Signature">{t.sig_algo || DASH}</DetailRow>
        </DetailSection>

        <DetailSection
          title={`Subject alternative names (${t.sans_json.length})`}
        >
          {t.sans_json.length === 0 ? (
            <p className="py-1 text-sm text-muted-foreground">{DASH}</p>
          ) : (
            <div className="flex flex-wrap gap-1.5 py-1">
              {t.sans_json.map((s) => (
                <span
                  key={s}
                  className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                >
                  {s}
                </span>
              ))}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Fingerprint (SHA-256)">
          <p className="break-all py-1 font-mono text-xs">
            {t.fingerprint_sha256 || DASH}
          </p>
        </DetailSection>

        <DetailSection
          title={`Certificate chain${chain.length ? ` (${chain.length})` : ""}`}
        >
          {chainQuery.isLoading ? (
            <p className="py-1 text-sm text-muted-foreground">Loading chain…</p>
          ) : chain.length === 0 ? (
            <p className="py-1 text-sm text-muted-foreground">
              No chain captured yet — run a probe.
            </p>
          ) : (
            <div className="space-y-2 py-1">
              {chain.map((c) => (
                <div
                  key={c.position}
                  className="rounded-md border px-2.5 py-1.5"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider",
                        chainRoleCls(c.role),
                      )}
                    >
                      {c.role}
                    </span>
                    <span className="min-w-0 break-words text-sm font-medium">
                      {c.subject_cn}
                    </span>
                  </div>
                  <div className="mt-1 grid grid-cols-[88px_1fr] gap-x-2 gap-y-0.5 text-[11px] text-muted-foreground">
                    <span>Issuer</span>
                    <span className="break-words">{c.issuer_cn}</span>
                    <span>Valid to</span>
                    <span>{new Date(c.not_after).toLocaleDateString()}</span>
                    <span>Key</span>
                    <span>
                      {c.key_algo
                        ? `${c.key_algo}${c.key_size ? ` ${c.key_size}-bit` : ""}`
                        : DASH}
                      {c.sig_algo ? ` · ${c.sig_algo}` : ""}
                    </span>
                    <span>SHA-256</span>
                    <span className="break-all font-mono">
                      {c.fingerprint_sha256}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </DetailSection>

        <div className="mt-4">
          <button
            type="button"
            onClick={() => setShowPem((v) => !v)}
            className="text-xs font-medium text-primary hover:underline"
          >
            {showPem ? "Hide" : "Show"} PEM
          </button>
          {showPem && (
            <pre className="mt-2 max-h-64 overflow-auto rounded-md border bg-muted/40 p-2 text-[11px] leading-tight">
              {chainQuery.isLoading
                ? "Loading…"
                : chainQuery.isError
                  ? "No successful probe captured a certificate yet."
                  : (chainQuery.data?.chain_pem ??
                    chainQuery.data?.leaf_pem ??
                    "No PEM captured.")}
            </pre>
          )}
        </div>

        <div className="mt-3">
          <button
            type="button"
            onClick={() => setShowCt((v) => !v)}
            className="text-xs font-medium text-primary hover:underline"
            title="Queries crt.sh — sends this hostname off-prem"
          >
            {showCt ? "Hide" : "Show"} CT-log cross-reference (crt.sh ↗)
          </button>
          {showCt && (
            <div className="mt-2 rounded-md border">
              {ctQuery.isLoading ? (
                <p className="px-3 py-2 text-xs text-muted-foreground">
                  Querying crt.sh…
                </p>
              ) : ctQuery.isError ? (
                <p className="px-3 py-2 text-xs text-destructive">
                  CT-log lookup failed.
                </p>
              ) : (ctQuery.data?.entries.length ?? 0) === 0 ? (
                <p className="px-3 py-2 text-xs text-muted-foreground">
                  {ctQuery.data?.error
                    ? `crt.sh: ${ctQuery.data.error}`
                    : "No CT-log entries found for this host."}
                </p>
              ) : (
                <table className="w-full text-[11px]">
                  <thead className="text-left uppercase tracking-wider text-muted-foreground">
                    <tr className="border-b bg-muted/30">
                      <th className="px-2 py-1">Issuer</th>
                      <th className="px-2 py-1">Common name</th>
                      <th className="px-2 py-1">Not before</th>
                      <th className="px-2 py-1">Not after</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ctQuery.data?.entries.map((e) => (
                      <tr key={`${e.id}`} className="border-t align-top">
                        <td className="px-2 py-1 break-words">
                          {e.issuer_name ?? "—"}
                        </td>
                        <td className="px-2 py-1 break-words font-mono">
                          {e.common_name ?? "—"}
                        </td>
                        <td className="px-2 py-1 tabular-nums">
                          {e.not_before
                            ? new Date(e.not_before).toLocaleDateString()
                            : "—"}
                        </td>
                        <td className="px-2 py-1 tabular-nums">
                          {e.not_after
                            ? new Date(e.not_after).toLocaleDateString()
                            : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="mt-5 flex justify-end gap-2 border-t pt-3">
        <button
          type="button"
          disabled={probe.isPending}
          onClick={() => probe.mutate()}
          className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
        >
          <RefreshCw
            className={cn("h-3.5 w-3.5", probe.isPending && "animate-spin")}
          />
          {probe.isPending ? "Probing…" : "Probe now"}
        </button>
        <button
          type="button"
          onClick={onEdit}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Edit
        </button>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          Close
        </button>
      </div>
    </Modal>
  );
}

// ── Page ──────────────────────────────────────────────────────────────

export function CertificatesPage() {
  const qc = useQueryClient();
  const { enabled, ready } = useFeatureModules();
  const moduleOn = enabled("security.tls_certs");

  const [search, setSearch] = useState("");
  const [stateFilter, setStateFilter] = useState<TLSCertState | "">("");
  const [sourceFilter, setSourceFilter] = useState<TLSCertSource | "">("");
  const [editing, setEditing] = useState<TLSCertTarget | null>(null);
  const [detail, setDetail] = useState<TLSCertTarget | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);

  // Saved-views payload (#77) — the page's filter state, stored verbatim.
  type CertsViewPayload = {
    search: string;
    state: TLSCertState | "";
    source: TLSCertSource | "";
  };
  const viewPayload: CertsViewPayload = {
    search,
    state: stateFilter,
    source: sourceFilter,
  };
  function applyView(p: CertsViewPayload) {
    setSearch(typeof p.search === "string" ? p.search : "");
    setStateFilter((p.state ?? "") as TLSCertState | "");
    setSourceFilter((p.source ?? "") as TLSCertSource | "");
  }

  const query = useQuery({
    queryKey: ["tls-certs", "list", search, stateFilter, sourceFilter],
    queryFn: () =>
      tlsCertsApi.list({
        limit: 500,
        search: search || undefined,
        state: (stateFilter || undefined) as TLSCertState | undefined,
        source: (sourceFilter || undefined) as TLSCertSource | undefined,
      }),
    enabled: ready && moduleOn,
  });

  const items = query.data?.items ?? [];

  const probeNow = useMutation({
    mutationFn: (id: string) => tlsCertsApi.probeNow(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tls-certs"] }),
  });

  const removeOne = useMutation({
    mutationFn: (id: string) => tlsCertsApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tls-certs"] }),
  });

  if (ready && !moduleOn) {
    return (
      <div className="flex h-full items-center justify-center p-6 text-sm text-muted-foreground">
        TLS certificate monitoring is disabled. An administrator can enable the
        "security.tls_certs" feature module on the Features & Integrations page.
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="flex items-center gap-2 text-xl font-semibold">
              <ShieldCheck className="h-5 w-5 text-muted-foreground" />
              TLS certificates
            </h1>
            <p className="text-sm text-muted-foreground">
              Watch list of TLS endpoints — subject, issuer, validity window and
              chain status are probed on a schedule (or on demand) so expiring
              and misconfigured certs surface before they break clients.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <SavedViewsMenu
              page="network.certificates"
              currentPayload={viewPayload}
              onApply={applyView}
            />
            <HeaderButton
              icon={RefreshCw}
              onClick={() => query.refetch()}
              iconClassName={query.isFetching ? "animate-spin" : undefined}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowNew(true)}
            >
              New target
            </HeaderButton>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            className={cn(inputCls, "max-w-xs")}
            placeholder="Search host / subject / issuer…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className={cn(inputCls, "max-w-[180px]")}
            value={stateFilter}
            onChange={(e) =>
              setStateFilter(e.target.value as TLSCertState | "")
            }
          >
            <option value="">All states</option>
            {TLS_CERT_STATES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            className={cn(inputCls, "max-w-[180px]")}
            value={sourceFilter}
            onChange={(e) =>
              setSourceFilter(e.target.value as TLSCertSource | "")
            }
          >
            <option value="">All sources</option>
            <option value="manual">manual</option>
            <option value="discovered">discovered</option>
          </select>
        </div>

        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Host</th>
                <th className="px-3 py-2 text-left">State</th>
                <th className="px-3 py-2 text-left">Issuer</th>
                <th className="px-3 py-2 text-left">Expires</th>
                <th className="px-3 py-2 text-left">Chain</th>
                <th className="px-3 py-2 text-left">Source</th>
                <th className="px-3 py-2 text-left">Last checked</th>
                <th className="w-28 px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {query.isLoading && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={8}
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!query.isLoading && items.length === 0 && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={8}
                  >
                    No targets yet — click "New target" to add one.
                  </td>
                </tr>
              )}
              {items.map((t) => (
                <tr
                  key={t.id}
                  className="cursor-pointer border-t hover:bg-muted/30"
                  onClick={() => setDetail(t)}
                  title="View certificate details"
                >
                  <td className="px-3 py-2 align-top break-words">
                    <div className="font-medium">
                      {t.host}
                      <span className="text-muted-foreground">:{t.port}</span>
                    </div>
                    {t.display_name && (
                      <div className="text-[11px] text-muted-foreground">
                        {t.display_name}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <TLSStateBadge state={t.state} />
                  </td>
                  <td className="px-3 py-2 align-top break-words text-muted-foreground">
                    {t.issuer_cn ?? "—"}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <NotAfterCell
                      notAfter={t.not_after}
                      daysRemaining={t.days_remaining}
                    />
                  </td>
                  <td className="px-3 py-2 align-top">
                    <ChainBadge target={t} />
                  </td>
                  <td className="px-3 py-2 align-top">
                    <SourceChip source={t.source} />
                  </td>
                  <td className="px-3 py-2 align-top text-[11px] tabular-nums text-muted-foreground">
                    {fmtDateTime(t.last_checked_at)}
                  </td>
                  <td
                    className="px-3 py-2 align-top text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      type="button"
                      title="Probe now"
                      disabled={probeNow.isPending}
                      onClick={() => probeNow.mutate(t.id)}
                      className="ml-1 rounded p-1 hover:bg-muted disabled:opacity-50"
                    >
                      <RefreshCw
                        className={cn(
                          "h-3.5 w-3.5",
                          probeNow.isPending &&
                            probeNow.variables === t.id &&
                            "animate-spin",
                        )}
                      />
                    </button>
                    <button
                      type="button"
                      title="Edit"
                      onClick={() => setEditing(t)}
                      className="ml-1 rounded p-1 hover:bg-muted"
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      title="Delete"
                      onClick={() => {
                        setConfirm({
                          title: "Delete TLS cert target",
                          message: `Delete the target "${t.display_name || t.host}"?`,
                          confirmLabel: "Delete",
                          onConfirm: () => removeOne.mutate(t.id),
                        });
                      }}
                      className="ml-1 rounded p-1 text-destructive hover:bg-destructive/10"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {detail && (
          <CertDetailModal
            target={detail}
            onClose={() => setDetail(null)}
            onEdit={() => {
              setEditing(detail);
              setDetail(null);
            }}
          />
        )}
        {showNew && (
          <CertTargetEditorModal
            existing={null}
            onClose={() => setShowNew(false)}
          />
        )}
        {editing && (
          <CertTargetEditorModal
            existing={editing}
            onClose={() => setEditing(null)}
          />
        )}
        <ConfirmModal
          open={confirm !== null}
          title={confirm?.title ?? ""}
          message={confirm?.message ?? ""}
          confirmLabel={confirm?.confirmLabel}
          tone="destructive"
          onConfirm={() => {
            confirm?.onConfirm();
            setConfirm(null);
          }}
          onClose={() => setConfirm(null)}
        />
      </div>
    </div>
  );
}
