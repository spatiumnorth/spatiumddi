/**
 * Multi-target audit forwarding manager.
 *
 * Replaces the single-syslog + single-webhook flat form on the
 * Settings page. Each row is one ``AuditForwardTarget``; operators
 * can mix formats (RFC 5424 JSON / CEF / LEEF / RFC 3164 /
 * JSON-lines) and transports (UDP / TCP / TLS) per destination.
 *
 * Modal is intentionally large — syslog and webhook fields share the
 * same form with kind-conditional visibility. "Test" sends a
 * synthetic event to the target so the operator gets fast feedback
 * without waiting for the next audited write.
 */

import { useState } from "react";
import { useCredentialReask } from "@/hooks/useCredentialReask";
import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Check, Pencil, Play, Plus, Send, Trash2, X } from "lucide-react";

import { Modal } from "@/components/ui/modal";
import { FreshRowError } from "@/components/FreshRowError";
import { changedFields, refetchRow, useFreshRow } from "@/hooks/useFreshRow";
import { ListReadError } from "@/components/ui/list-read-error";
import {
  dhcpApi,
  dnsApi,
  settingsApi,
  type AuditForwardFormat,
  type AuditForwardKind,
  type AuditForwardLogFilterKey,
  type AuditForwardProtocol,
  type AuditForwardSeverity,
  type AuditForwardTarget,
  type AuditForwardTargetWrite,
  formatApiError,
} from "@/lib/api";
import { FormError } from "@/components/ui/form-error";

const inputCls =
  "w-full rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50";

// Full descriptive labels — used in the modal dropdown where there's
// room to explain each choice.
const FORMAT_LABELS: Record<AuditForwardFormat, string> = {
  rfc5424_json: "RFC 5424 + JSON",
  rfc5424_cef: "RFC 5424 + CEF 0 (ArcSight)",
  rfc5424_leef: "RFC 5424 + LEEF 2.0 (QRadar)",
  rfc3164: "RFC 3164 (legacy BSD syslog)",
  json_lines: "JSON lines (no syslog wrapper)",
};

// Compact labels — used in the targets table cell where space is
// tight. Keeps the cell on a single line without wrapping.
const FORMAT_SHORT: Record<AuditForwardFormat, string> = {
  rfc5424_json: "RFC 5424 JSON",
  rfc5424_cef: "CEF 0",
  rfc5424_leef: "LEEF 2.0",
  rfc3164: "RFC 3164",
  json_lines: "JSON lines",
};

const PROTOCOL_LABELS: Record<AuditForwardProtocol, string> = {
  udp: "UDP",
  tcp: "TCP",
  tls: "TLS",
};

const SEVERITY_LABELS: Record<AuditForwardSeverity, string> = {
  info: "info (forward everything)",
  warn: "warn",
  error: "error",
  denied: "denied",
};

const EMPTY: AuditForwardTargetWrite = {
  name: "",
  enabled: true,
  kind: "syslog",
  format: "rfc5424_json",
  host: "",
  port: 514,
  protocol: "udp",
  facility: 16,
  ca_cert_pem: null,
  url: "",
  auth_header: "",
  webhook_flavor: "generic",
  smtp_host: "",
  smtp_port: 587,
  smtp_security: "starttls",
  smtp_username: "",
  smtp_password: null,
  smtp_from_address: "",
  smtp_to_addresses: null,
  smtp_reply_to: "",
  min_severity: null,
  resource_types: null,
  stream_dns_query_log: false,
  stream_dhcp_activity_log: false,
  log_stream_filters: null,
  dns_query_sample_percent: 100,
};

function targetToBody(t: AuditForwardTarget): AuditForwardTargetWrite {
  return {
    name: t.name,
    enabled: t.enabled,
    kind: t.kind,
    format: t.format,
    host: t.host,
    port: t.port,
    protocol: t.protocol,
    facility: t.facility,
    ca_cert_pem: t.ca_cert_pem ?? null,
    // url, auth_header and smtp_password are write-only: the server
    // returns booleans (plus the URL's host) only (#1502). ``null`` means
    // "keep what's stored"; the save drops a blank field for the same
    // reason, and an explicit empty string is sent only to clear.
    url: null,
    auth_header: null,
    webhook_flavor: t.webhook_flavor,
    smtp_host: t.smtp_host,
    smtp_port: t.smtp_port,
    smtp_security: t.smtp_security,
    smtp_username: t.smtp_username,
    smtp_password: null,
    smtp_from_address: t.smtp_from_address,
    smtp_to_addresses: t.smtp_to_addresses,
    smtp_reply_to: t.smtp_reply_to,
    min_severity: t.min_severity,
    resource_types: t.resource_types,
    stream_dns_query_log: t.stream_dns_query_log,
    stream_dhcp_activity_log: t.stream_dhcp_activity_log,
    log_stream_filters: t.log_stream_filters,
    dns_query_sample_percent: t.dns_query_sample_percent,
  };
}

export function AuditForwardTargets({
  isSuperadmin,
}: {
  isSuperadmin: boolean;
}) {
  const qc = useQueryClient();
  const {
    data: targets = [],
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["audit-forward-targets"],
    queryFn: settingsApi.listAuditTargets,
  });

  const [editing, setEditing] = useState<
    { mode: "create" } | { mode: "edit"; row: AuditForwardTarget } | null
  >(null);
  const [confirmDelete, setConfirmDelete] = useState<AuditForwardTarget | null>(
    null,
  );
  const [testState, setTestState] = useState<
    Record<string, { status: "ok" | "sent" | "error"; msg: string } | undefined>
  >({});

  const [deleteError, setDeleteError] = useState<string | null>(null);
  const deleteMut = useMutation({
    mutationFn: (id: string) => settingsApi.deleteAuditTarget(id),
    onSuccess: () => {
      setDeleteError(null);
      qc.invalidateQueries({ queryKey: ["audit-forward-targets"] });
      setConfirmDelete(null);
    },
    // A refused delete (403 / 404 / 409) says why and re-reads the list, so
    // a row already deleted elsewhere leaves it (#3822).
    onError: (e: unknown) => {
      setDeleteError(formatApiError(e, "Delete failed"));
      qc.invalidateQueries({ queryKey: ["audit-forward-targets"] });
      setConfirmDelete(null);
    },
  });

  async function doTest(id: string) {
    try {
      const r = await settingsApi.testAuditTarget(id);
      // UDP syslog cannot confirm delivery (#4237): never say "delivered".
      const sent = r.status === "sent";
      setTestState((s) => ({
        ...s,
        [id]: sent
          ? {
              status: "sent",
              msg: `sent to ${r.target} over UDP — delivery cannot be confirmed`,
            }
          : { status: "ok", msg: `delivered to ${r.target}` },
      }));
    } catch (e) {
      const msg = formatApiError(e, "delivery failed");
      setTestState((s) => ({ ...s, [id]: { status: "error", msg } }));
    }
    // A success clears itself; a failure stays until the next Test, so it is
    // still there for a screen-reader user who looks away (#4966).
    window.setTimeout(() => {
      setTestState((s) => {
        if (s[id]?.status === "error") return s;
        const { [id]: _, ...rest } = s;
        return rest;
      });
    }, 6000);
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-2xl text-xs text-muted-foreground">
          Each enabled target receives the committed AuditLog rows that pass its
          own minimum severity and resource type filters. Delivery is
          fire-and-forget — a dead target never blocks the audit write or the
          other targets.
        </div>
        {isSuperadmin && (
          <button
            type="button"
            onClick={() => setEditing({ mode: "create" })}
            className="inline-flex flex-shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md border bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
          >
            <Plus className="h-3.5 w-3.5" /> Add Target
          </button>
        )}
      </div>

      {deleteError && (
        <div
          role="alert"
          className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-400"
        >
          {deleteError}
        </div>
      )}

      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[800px] text-xs">
          <thead className="bg-muted/40 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="whitespace-nowrap px-3 py-2 font-medium">Name</th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">Kind</th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Destination
              </th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Format
              </th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Filter
              </th>
              <th className="whitespace-nowrap px-3 py-2 font-medium">
                Status
              </th>
              <th className="whitespace-nowrap px-3 py-2 text-right font-medium">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-3 py-4 text-center text-muted-foreground"
                >
                  Loading…
                </td>
              </tr>
            ) : targets.length === 0 ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-3 py-6 text-center text-muted-foreground"
                >
                  {/* A refused or failed read is not an empty list (#1343). */}
                  {isError ? (
                    <ListReadError
                      error={error}
                      what="the audit-forward targets"
                    />
                  ) : (
                    "No audit-forward targets configured."
                  )}
                </td>
              </tr>
            ) : (
              targets.map((t) => {
                const dest =
                  t.kind === "syslog"
                    ? `${t.host || "?"}:${t.port} ${t.protocol.toUpperCase()}`
                    : t.url_display || "—";
                const filter =
                  t.min_severity ||
                  (t.resource_types && t.resource_types.length > 0)
                    ? [
                        t.min_severity ? `≥${t.min_severity}` : null,
                        t.resource_types && t.resource_types.length > 0
                          ? `types: ${t.resource_types.join(",")}`
                          : null,
                      ]
                        .filter(Boolean)
                        .join(" · ")
                    : "all events";
                const ts = testState[t.id];
                return (
                  <tr key={t.id}>
                    <td className="whitespace-nowrap px-3 py-2 font-medium">
                      {t.name}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">{t.kind}</td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px]">
                      {dest}
                    </td>
                    <td
                      className="whitespace-nowrap px-3 py-2"
                      title={
                        t.kind === "webhook"
                          ? "JSON body"
                          : FORMAT_LABELS[t.format]
                      }
                    >
                      {t.kind === "webhook"
                        ? "JSON (body)"
                        : FORMAT_SHORT[t.format]}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                      {filter}
                      {(t.stream_dns_query_log ||
                        t.stream_dhcp_activity_log) && (
                        <div className="text-[11px]">
                          streams:{" "}
                          {[
                            t.stream_dns_query_log ? "DNS queries" : null,
                            t.stream_dhcp_activity_log ? "DHCP activity" : null,
                          ]
                            .filter(Boolean)
                            .join(", ")}
                          {t.log_stream_dropped_total > 0 && (
                            <span
                              className="ml-1 text-amber-600 dark:text-amber-400"
                              title={
                                t.log_stream_last_drop_at
                                  ? `Last drop ${t.log_stream_last_drop_at}`
                                  : undefined
                              }
                            >
                              · {t.log_stream_dropped_total} dropped
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      {t.enabled ? (
                        <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-[11px] font-medium text-emerald-600">
                          <Check className="h-3 w-3" /> enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                          disabled
                        </span>
                      )}
                      {ts && ts.status === "error" && (
                        <span
                          role="alert"
                          className="ml-2 inline-flex items-center gap-1 rounded bg-red-500/15 px-1.5 py-0.5 text-[11px] text-red-600"
                        >
                          <X className="h-3 w-3" aria-hidden="true" />
                          {ts.msg}
                        </span>
                      )}
                      {ts && ts.status === "ok" && (
                        <span className="ml-2 inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-[11px] text-emerald-600">
                          <Check className="h-3 w-3" />
                          {ts.msg}
                        </span>
                      )}
                      {ts && ts.status === "sent" && (
                        <span className="ml-2 inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                          <Send className="h-3 w-3" />
                          {ts.msg}
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                      <div className="inline-flex items-center gap-1">
                        {isSuperadmin && (
                          <>
                            <button
                              type="button"
                              onClick={() => doTest(t.id)}
                              title="Send a synthetic event to this target"
                              className="rounded p-1 hover:bg-accent"
                            >
                              <Play className="h-3.5 w-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                setEditing({ mode: "edit", row: t })
                              }
                              title="Edit"
                              className="rounded p-1 hover:bg-accent"
                            >
                              <Pencil className="h-3.5 w-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmDelete(t)}
                              title="Delete"
                              className="rounded p-1 text-destructive hover:bg-destructive/10"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {editing?.mode === "create" && (
        <TargetModal
          initial={EMPTY}
          urlSet={false}
          urlDisplay=""
          authHeaderSet={false}
          smtpPasswordSet={false}
          onClose={() => setEditing(null)}
        />
      )}
      {editing?.mode === "edit" && (
        <EditAuditTarget row={editing.row} onClose={() => setEditing(null)} />
      )}

      {confirmDelete && (
        <Modal
          title={`Delete "${confirmDelete.name}"?`}
          onClose={() => setConfirmDelete(null)}
        >
          <p className="text-sm text-muted-foreground">
            This target will no longer receive forwarded audit events.
          </p>
          <div className="mt-4 flex justify-end gap-2">
            <button
              onClick={() => setConfirmDelete(null)}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
            >
              Cancel
            </button>
            <button
              onClick={() => deleteMut.mutate(confirmDelete.id)}
              disabled={deleteMut.isPending}
              className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:opacity-90 disabled:opacity-50"
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

// Edit reads the target when it opens (#3926) and the Save sends only what
// the operator changed against what was read.
function EditAuditTarget({
  row,
  onClose,
}: {
  row: AuditForwardTarget;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const fresh = useFreshRow<AuditForwardTarget>(row, () =>
    refetchRow<AuditForwardTarget>(qc, [["audit-forward-targets"]], row.id),
  );
  if (fresh.error)
    return (
      <FreshRowError
        title="Edit Audit Forward Target"
        error={fresh.error}
        onRetry={fresh.retry}
        onClose={onClose}
      />
    );
  if (!fresh.ready || !fresh.row) return null;
  return (
    <TargetModal
      initial={targetToBody(fresh.row)}
      existingId={fresh.row.id}
      urlSet={fresh.row.url_set}
      urlDisplay={fresh.row.url_display}
      authHeaderSet={fresh.row.auth_header_set}
      smtpPasswordSet={fresh.row.smtp_password_set}
      onClose={onClose}
    />
  );
}

function TargetModal({
  initial,
  existingId,
  urlSet,
  urlDisplay,
  authHeaderSet,
  smtpPasswordSet,
  onClose,
}: {
  initial: AuditForwardTargetWrite;
  existingId?: string;
  urlSet: boolean;
  urlDisplay: string;
  authHeaderSet: boolean;
  smtpPasswordSet: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [form, setForm] = useState<AuditForwardTargetWrite>(initial);
  const [clearAuthHeader, setClearAuthHeader] = useState(false);
  const [clearSmtpPassword, setClearSmtpPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // #4135 — a new webhook URL (write-only, so any value typed is a move) or
  // a moved SMTP host / port needs the stored credential entered again.
  const reaskWebhook = form.kind === "webhook";
  const reaskSmtp = form.kind === "smtp";
  const reask = useCredentialReask(
    reaskWebhook
      ? { url: form.url ?? "" }
      : { smtp_host: form.smtp_host, smtp_port: form.smtp_port },
    !existingId
      ? null
      : reaskWebhook
        ? { url: "" }
        : reaskSmtp
          ? { smtp_host: initial.smtp_host, smtp_port: initial.smtp_port }
          : null,
    () => {
      setForm((f) => ({ ...f, auth_header: null, smtp_password: null }));
      setClearAuthHeader(false);
      setClearSmtpPassword(false);
    },
  );
  const mustEnterAuthHeader =
    reaskWebhook &&
    form.webhook_flavor === "generic" &&
    reask.asks(authHeaderSet) &&
    !clearAuthHeader &&
    !form.auth_header;
  const mustEnterSmtpPassword =
    reaskSmtp &&
    reask.asks(smtpPasswordSet) &&
    !clearSmtpPassword &&
    !form.smtp_password;

  const saveMut = useMutation({
    mutationFn: async () => {
      // The three write-only secrets are handled apart from the plain
      // fields: blank (untouched, or typed then erased) keeps what is on
      // file, and only an explicit checkbox (or, for the URL, a new value)
      // changes one.
      const { url, auth_header, smtp_password, ...plain } = form;
      if (plain.resource_types && plain.resource_types.length === 0) {
        plain.resource_types = null;
      }
      // Edit sends only what the operator changed against what the dialog
      // read when it opened (#3926), so a field another client set since is
      // not put back. Create sends the whole form.
      const body: Partial<AuditForwardTargetWrite> = existingId
        ? changedFields(initial as unknown as Record<string, unknown>, plain)
        : { ...plain };
      if (url) body.url = url;
      if (clearAuthHeader) {
        body.auth_header = "";
      } else if (auth_header) {
        body.auth_header = auth_header;
      }
      if (clearSmtpPassword) {
        body.smtp_password = "";
      } else if (smtp_password) {
        body.smtp_password = smtp_password;
      }
      if (existingId) {
        if (Object.keys(body).length === 0) return null;
        return settingsApi.updateAuditTarget(existingId, body);
      }
      return settingsApi.createAuditTarget(body as AuditForwardTargetWrite);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audit-forward-targets"] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  const isSyslog = form.kind === "syslog";
  const isWebhook = form.kind === "webhook";

  return (
    <Modal
      title={existingId ? `Edit "${initial.name}"` : "Add Audit Forward Target"}
      onClose={onClose}
      wide
    >
      <div className="space-y-3">
        {error && (
          <FormError className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-400">
            {error}
          </FormError>
        )}

        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Name
            </div>
            <input
              className={inputCls}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="SIEM prod"
            />
          </label>
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Enabled
            </div>
            <select
              className={inputCls}
              value={form.enabled ? "1" : "0"}
              onChange={(e) =>
                setForm({ ...form, enabled: e.target.value === "1" })
              }
            >
              <option value="1">Enabled</option>
              <option value="0">Disabled</option>
            </select>
          </label>
        </div>

        <label className="block">
          <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Kind
          </div>
          <select
            className={inputCls}
            value={form.kind}
            onChange={(e) =>
              setForm({ ...form, kind: e.target.value as AuditForwardKind })
            }
          >
            <option value="syslog">Syslog</option>
            <option value="webhook">HTTP Webhook</option>
            <option value="smtp">Email (SMTP)</option>
          </select>
        </label>

        {isSyslog ? (
          <>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Output Format
              </div>
              <select
                className={inputCls}
                value={form.format}
                onChange={(e) =>
                  setForm({
                    ...form,
                    format: e.target.value as AuditForwardFormat,
                  })
                }
              >
                {Object.entries(FORMAT_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </label>

            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Host
                </div>
                <input
                  className={inputCls}
                  value={form.host ?? ""}
                  onChange={(e) => setForm({ ...form, host: e.target.value })}
                  placeholder="syslog.example.com"
                />
              </label>
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Port
                </div>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  className={inputCls}
                  value={form.port ?? 514}
                  onChange={(e) =>
                    setForm({ ...form, port: Number(e.target.value) })
                  }
                />
              </label>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Protocol
                </div>
                <select
                  className={inputCls}
                  value={form.protocol ?? "udp"}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      protocol: e.target.value as AuditForwardProtocol,
                    })
                  }
                >
                  {Object.entries(PROTOCOL_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Facility
                </div>
                <select
                  className={inputCls}
                  value={form.facility ?? 16}
                  onChange={(e) =>
                    setForm({ ...form, facility: Number(e.target.value) })
                  }
                >
                  <option value={1}>user (1)</option>
                  <option value={4}>auth (4)</option>
                  <option value={10}>authpriv (10)</option>
                  <option value={13}>log_audit (13)</option>
                  <option value={16}>local0 (16)</option>
                  <option value={17}>local1 (17)</option>
                  <option value={18}>local2 (18)</option>
                  <option value={19}>local3 (19)</option>
                  <option value={20}>local4 (20)</option>
                  <option value={21}>local5 (21)</option>
                  <option value={22}>local6 (22)</option>
                  <option value={23}>local7 (23)</option>
                </select>
              </label>
            </div>

            {form.protocol === "tls" && (
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  CA Certificate (PEM, optional)
                </div>
                <textarea
                  className={inputCls}
                  rows={4}
                  value={form.ca_cert_pem ?? ""}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      ca_cert_pem: e.target.value || null,
                    })
                  }
                  placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"
                />
                <div className="mt-1 text-[11px] text-muted-foreground">
                  Leave blank to use the system CA bundle.
                </div>
              </label>
            )}
          </>
        ) : isWebhook ? (
          <>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Flavor
              </div>
              <select
                className={inputCls}
                value={form.webhook_flavor ?? "generic"}
                onChange={(e) =>
                  setForm({
                    ...form,
                    webhook_flavor: e.target.value as
                      | "generic"
                      | "slack"
                      | "teams"
                      | "discord",
                  })
                }
              >
                <option value="generic">Generic JSON</option>
                <option value="slack">Slack (mrkdwn blocks)</option>
                <option value="teams">
                  Microsoft Teams (Workflows / Adaptive Card)
                </option>
                <option value="discord">Discord (embed)</option>
              </select>
              <div className="mt-1 text-[11px] text-muted-foreground">
                {form.webhook_flavor === "generic"
                  ? "Posts the raw audit/alert JSON. For collectors that parse it themselves."
                  : form.webhook_flavor === "teams"
                    ? "Create the URL with the Workflows app in the Teams channel → “Send webhook alerts to a channel”. Teams accepts the request before the flow runs, so a successful Test doesn't prove the card was posted; check the flow's run history."
                    : "Wraps the payload in the platform's incoming-webhook block format. Paste the URL the platform issued."}
              </div>
            </label>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                URL
              </div>
              {/* Write-only: a chat webhook URL is the credential (#1502). */}
              <input
                type="password"
                autoComplete="new-password"
                className={inputCls}
                value={form.url ?? ""}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder={
                  urlSet
                    ? "(stored — leave blank to keep unchanged)"
                    : form.webhook_flavor === "slack"
                      ? "https://hooks.slack.com/services/T…/B…/…"
                      : form.webhook_flavor === "teams"
                        ? "https://….environment.api.powerplatform.com/powerautomate/automations/direct/workflows/…"
                        : form.webhook_flavor === "discord"
                          ? "https://discord.com/api/webhooks/…/…"
                          : "https://collector.example.com/ingest"
                }
              />
              <div className="mt-1 text-[11px] text-muted-foreground">
                {urlSet
                  ? `Stored: ${urlDisplay || "(set)"}. Encrypted at rest and never shown again — paste a new URL to replace it.`
                  : "Encrypted at rest and never shown again after saving."}
              </div>
            </label>
            {form.webhook_flavor === "generic" && (
              <div>
                <label className="block">
                  <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                    Authorization Header (optional)
                  </div>
                  <input
                    type="password"
                    autoComplete="new-password"
                    className={inputCls}
                    value={form.auth_header ?? ""}
                    disabled={clearAuthHeader}
                    onChange={(e) =>
                      setForm({ ...form, auth_header: e.target.value })
                    }
                    required={mustEnterAuthHeader}
                    placeholder={
                      reask.asks(authHeaderSet)
                        ? reask.placeholder
                        : authHeaderSet
                          ? "(stored — leave blank to keep unchanged)"
                          : "Bearer …"
                    }
                  />
                  {reask.asks(authHeaderSet) && (
                    <div className="mt-1 text-[11px] text-muted-foreground">
                      {reask.hint} Or remove it below.
                    </div>
                  )}
                </label>
                {existingId && authHeaderSet && (
                  <label className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
                    <input
                      type="checkbox"
                      checked={clearAuthHeader}
                      onChange={(e) => setClearAuthHeader(e.target.checked)}
                    />
                    Remove the stored header
                  </label>
                )}
              </div>
            )}
          </>
        ) : (
          // SMTP
          <>
            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  SMTP Host
                </div>
                <input
                  className={inputCls}
                  value={form.smtp_host ?? ""}
                  onChange={(e) =>
                    setForm({ ...form, smtp_host: e.target.value })
                  }
                  placeholder="smtp.example.com"
                />
              </label>
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Port
                </div>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  className={inputCls}
                  value={form.smtp_port ?? 587}
                  onChange={(e) =>
                    setForm({ ...form, smtp_port: Number(e.target.value) })
                  }
                />
              </label>
            </div>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Security
              </div>
              <select
                className={inputCls}
                value={form.smtp_security ?? "starttls"}
                onChange={(e) =>
                  setForm({
                    ...form,
                    smtp_security: e.target.value as
                      | "none"
                      | "starttls"
                      | "ssl",
                  })
                }
              >
                <option value="starttls">STARTTLS (587)</option>
                <option value="ssl">SSL/TLS (465)</option>
                <option value="none">None (plain)</option>
              </select>
            </label>
            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Username
                </div>
                <input
                  className={inputCls}
                  value={form.smtp_username ?? ""}
                  onChange={(e) =>
                    setForm({ ...form, smtp_username: e.target.value })
                  }
                  placeholder="(blank = no auth)"
                />
              </label>
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Password
                </div>
                <input
                  type="password"
                  autoComplete="new-password"
                  className={inputCls}
                  value={form.smtp_password ?? ""}
                  disabled={clearSmtpPassword}
                  onChange={(e) =>
                    setForm({ ...form, smtp_password: e.target.value })
                  }
                  required={mustEnterSmtpPassword}
                  placeholder={
                    reask.asks(smtpPasswordSet)
                      ? reask.placeholder
                      : smtpPasswordSet
                        ? "(stored — leave blank to keep unchanged)"
                        : ""
                  }
                />
                {reask.asks(smtpPasswordSet) && (
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    {reask.hint} Or remove it below.
                  </div>
                )}
              </label>
              {existingId && smtpPasswordSet && (
                <label className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={clearSmtpPassword}
                    onChange={(e) => setClearSmtpPassword(e.target.checked)}
                  />
                  Remove the stored password
                </label>
              )}
            </div>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                From Address
              </div>
              <input
                className={inputCls}
                value={form.smtp_from_address ?? ""}
                onChange={(e) =>
                  setForm({ ...form, smtp_from_address: e.target.value })
                }
                placeholder="alerts@example.com"
              />
            </label>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Recipients (comma-separated)
              </div>
              <input
                className={inputCls}
                value={(form.smtp_to_addresses ?? []).join(", ")}
                onChange={(e) => {
                  const list = e.target.value
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean);
                  setForm({
                    ...form,
                    smtp_to_addresses: list.length > 0 ? list : null,
                  });
                }}
                placeholder="oncall@example.com, soc@example.com"
              />
            </label>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                Reply-To (optional)
              </div>
              <input
                className={inputCls}
                value={form.smtp_reply_to ?? ""}
                onChange={(e) =>
                  setForm({ ...form, smtp_reply_to: e.target.value })
                }
                placeholder="(leave blank to use From address)"
              />
            </label>
          </>
        )}

        <div className="grid grid-cols-2 gap-3 border-t pt-3">
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Minimum Severity
            </div>
            <select
              className={inputCls}
              value={form.min_severity ?? ""}
              onChange={(e) =>
                setForm({
                  ...form,
                  min_severity:
                    (e.target.value as AuditForwardSeverity) || null,
                })
              }
            >
              <option value="">(forward everything)</option>
              {Object.entries(SEVERITY_LABELS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Resource Types (comma-separated)
            </div>
            <input
              className={inputCls}
              value={(form.resource_types ?? []).join(",")}
              onChange={(e) => {
                const list = e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean);
                setForm({
                  ...form,
                  resource_types: list.length > 0 ? list : null,
                });
              }}
              placeholder="dns_zone,subnet,dhcp_scope (blank = all)"
            />
          </label>
        </div>

        {isSyslog && <LogStreamsSection form={form} setForm={setForm} />}

        <div className="flex justify-end gap-2 border-t pt-3">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => saveMut.mutate()}
            disabled={
              saveMut.isPending ||
              !form.name ||
              mustEnterAuthHeader ||
              mustEnterSmtpPassword
            }
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : existingId ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

const STREAM_FORMATS: AuditForwardFormat[] = [
  "rfc5424_json",
  "rfc3164",
  "json_lines",
];

function splitList(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function CheckList({
  label,
  options,
  selected,
  onChange,
}: {
  label: string;
  options: { id: string; name: string }[];
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  if (options.length === 0) return null;
  return (
    <div className="block">
      <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="max-h-24 space-y-0.5 overflow-y-auto rounded-md border p-1.5">
        {options.map((o) => (
          <label key={o.id} className="flex items-center gap-1.5 text-xs">
            <input
              type="checkbox"
              checked={selected.includes(o.id)}
              onChange={(e) =>
                onChange(
                  e.target.checked
                    ? [...selected, o.id]
                    : selected.filter((x) => x !== o.id),
                )
              }
            />
            {o.name}
          </label>
        ))}
      </div>
    </div>
  );
}

/**
 * #4545 — opt a syslog target into the DNS query log and the DHCP activity
 * log, and narrow what it receives. Both streams are off by default: a query
 * log is high-volume and names clients.
 */
function LogStreamsSection({
  form,
  setForm,
}: {
  form: AuditForwardTargetWrite;
  setForm: (f: AuditForwardTargetWrite) => void;
}) {
  const formatOk = STREAM_FORMATS.includes(form.format);
  const filters = form.log_stream_filters ?? {};
  const setFilter = (key: AuditForwardLogFilterKey, values: string[]) => {
    const next = { ...filters };
    if (values.length > 0) next[key] = values;
    else delete next[key];
    setForm({
      ...form,
      log_stream_filters: Object.keys(next).length > 0 ? next : null,
    });
  };
  const dnsGroups = useQuery({
    queryKey: ["dns-groups"],
    queryFn: dnsApi.listGroups,
    enabled: !!form.stream_dns_query_log,
  });
  const dnsServers = useQueries({
    queries: (dnsGroups.data ?? []).map((g) => ({
      queryKey: ["dns-group-servers", g.id],
      queryFn: () => dnsApi.listServers(g.id),
    })),
  });
  const dhcpGroups = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: dhcpApi.listGroups,
    enabled: !!form.stream_dhcp_activity_log,
  });
  const dhcpServers = useQuery({
    queryKey: ["dhcp-servers-all"],
    queryFn: () => dhcpApi.listServers(),
    enabled: !!form.stream_dhcp_activity_log,
  });
  const get = (k: AuditForwardLogFilterKey) => filters[k] ?? [];

  return (
    <div className="space-y-3 border-t pt-3" data-testid="log-streams">
      <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        Log streams
      </div>
      <p className="text-xs text-muted-foreground">
        Also forward the logs the DNS and DHCP agents ship to the control plane,
        one event per query or message. Off by default: query logs are
        high-volume and carry client addresses. Delivery is best-effort and
        never slows the agents; entries are dropped and counted when a target's
        queue is full or when sending a batch fails three times (shown in the
        Filter column and raised by the <code>log_forward_dropping</code>{" "}
        alert).
        {!formatOk &&
          " Streams need the RFC 5424 + JSON, RFC 3164 or JSON lines format."}
      </p>
      <label className="flex items-center gap-2 text-xs">
        <input
          type="checkbox"
          disabled={!formatOk}
          checked={!!form.stream_dns_query_log}
          onChange={(e) =>
            setForm({ ...form, stream_dns_query_log: e.target.checked })
          }
        />
        Forward the DNS query log
      </label>
      {form.stream_dns_query_log && formatOk && (
        <div className="grid grid-cols-2 gap-3 rounded-md border p-2">
          <CheckList
            label="DNS server groups (none = all)"
            options={dnsGroups.data ?? []}
            selected={get("dns_server_group_ids")}
            onChange={(v) => setFilter("dns_server_group_ids", v)}
          />
          <CheckList
            label="DNS servers (none = all)"
            options={dnsServers.flatMap((q) => q.data ?? [])}
            selected={get("dns_server_ids")}
            onChange={(v) => setFilter("dns_server_ids", v)}
          />
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Response codes
            </div>
            <input
              className={inputCls}
              value={get("dns_rcodes").join(",")}
              onChange={(e) =>
                setFilter("dns_rcodes", splitList(e.target.value))
              }
              placeholder="NXDOMAIN,SERVFAIL (blank = all)"
            />
          </label>
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Query types
            </div>
            <input
              className={inputCls}
              value={get("dns_qtypes").join(",")}
              onChange={(e) =>
                setFilter("dns_qtypes", splitList(e.target.value))
              }
              placeholder="A,AAAA,TXT (blank = all)"
            />
          </label>
          <label className="block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Sample (% of queries)
            </div>
            <input
              type="number"
              min={1}
              max={100}
              className={inputCls}
              value={form.dns_query_sample_percent ?? 100}
              onChange={(e) =>
                setForm({
                  ...form,
                  dns_query_sample_percent: Math.min(
                    100,
                    Math.max(1, Number(e.target.value) || 100),
                  ),
                })
              }
            />
          </label>
          <p className="self-end text-[11px] text-muted-foreground">
            Response code filters match only queries whose answer was recorded
            (BIND9 response logging); the rest are not forwarded.
          </p>
        </div>
      )}
      <label className="flex items-center gap-2 text-xs">
        <input
          type="checkbox"
          disabled={!formatOk}
          checked={!!form.stream_dhcp_activity_log}
          onChange={(e) =>
            setForm({ ...form, stream_dhcp_activity_log: e.target.checked })
          }
        />
        Forward the DHCP activity log
      </label>
      {form.stream_dhcp_activity_log && formatOk && (
        <div className="grid grid-cols-2 gap-3 rounded-md border p-2">
          <CheckList
            label="DHCP server groups (none = all)"
            options={dhcpGroups.data ?? []}
            selected={get("dhcp_server_group_ids")}
            onChange={(v) => setFilter("dhcp_server_group_ids", v)}
          />
          <CheckList
            label="DHCP servers (none = all)"
            options={dhcpServers.data ?? []}
            selected={get("dhcp_server_ids")}
            onChange={(v) => setFilter("dhcp_server_ids", v)}
          />
          <label className="col-span-2 block">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Message types (Kea log codes)
            </div>
            <input
              className={inputCls}
              value={get("dhcp_codes").join(",")}
              onChange={(e) =>
                setFilter("dhcp_codes", splitList(e.target.value))
              }
              placeholder="DHCP4_LEASE_ALLOC,DHCP4_PACKET_DROP_0001 (blank = all)"
            />
          </label>
        </div>
      )}
    </div>
  );
}
