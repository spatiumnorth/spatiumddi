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
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Pencil, Play, Plus, Trash2, X } from "lucide-react";

import { Modal } from "@/components/ui/modal";
import { ListReadError } from "@/components/ui/list-read-error";
import {
  settingsApi,
  type AuditForwardFormat,
  type AuditForwardKind,
  type AuditForwardProtocol,
  type AuditForwardSeverity,
  type AuditForwardTarget,
  type AuditForwardTargetWrite,
} from "@/lib/api";

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
    url: t.url,
    // auth_header + smtp_password are write-only — server returns
    // booleans only. Leaving them blank on edit means "don't change";
    // ``null`` on smtp_password mirrors that intent (the form sends
    // null when not retyped, an explicit empty string only when the
    // operator hits "clear stored password").
    auth_header: "",
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
    Record<string, { status: "ok" | "error"; msg: string } | undefined>
  >({});

  const deleteMut = useMutation({
    mutationFn: (id: string) => settingsApi.deleteAuditTarget(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audit-forward-targets"] });
      setConfirmDelete(null);
    },
  });

  async function doTest(id: string) {
    try {
      const r = await settingsApi.testAuditTarget(id);
      setTestState((s) => ({
        ...s,
        [id]: { status: "ok", msg: `delivered to ${r.target}` },
      }));
    } catch (e) {
      let msg = "delivery failed";
      if (e && typeof e === "object" && "response" in e) {
        const resp = (e as { response?: { data?: { detail?: string } } })
          .response;
        if (resp?.data?.detail) msg = resp.data.detail;
      }
      setTestState((s) => ({ ...s, [id]: { status: "error", msg } }));
    }
    window.setTimeout(() => {
      setTestState((s) => {
        const { [id]: _, ...rest } = s;
        return rest;
      });
    }, 6000);
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-2xl text-xs text-muted-foreground">
          Every enabled target receives every committed AuditLog row. Delivery
          is fire-and-forget — a dead target never blocks the audit write or the
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
                    : t.url || "—";
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
                      {ts && (
                        <span
                          className={
                            "ml-2 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] " +
                            (ts.status === "ok"
                              ? "bg-emerald-500/15 text-emerald-600"
                              : "bg-red-500/15 text-red-600")
                          }
                        >
                          {ts.status === "ok" ? (
                            <Check className="h-3 w-3" />
                          ) : (
                            <X className="h-3 w-3" />
                          )}
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

      {editing && (
        <TargetModal
          initial={
            editing.mode === "create" ? EMPTY : targetToBody(editing.row)
          }
          existingId={editing.mode === "edit" ? editing.row.id : undefined}
          authHeaderSet={
            editing.mode === "edit" ? editing.row.auth_header_set : false
          }
          smtpPasswordSet={
            editing.mode === "edit" ? editing.row.smtp_password_set : false
          }
          onClose={() => setEditing(null)}
        />
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

function TargetModal({
  initial,
  existingId,
  authHeaderSet,
  smtpPasswordSet,
  onClose,
}: {
  initial: AuditForwardTargetWrite;
  existingId?: string;
  authHeaderSet: boolean;
  smtpPasswordSet: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [form, setForm] = useState<AuditForwardTargetWrite>(initial);
  const [error, setError] = useState<string | null>(null);

  const saveMut = useMutation({
    mutationFn: async () => {
      const body: AuditForwardTargetWrite = { ...form };
      // Don't clobber the stored auth_header when editing if the user
      // left the field blank — that means "keep what's on file".
      if (existingId && authHeaderSet && !body.auth_header) {
        delete body.auth_header;
      }
      // Same dance for SMTP password — ``null`` (default on edit) means
      // "keep". Empty string keeps as is; the operator opens a separate
      // dialog to clear if they ever need to.
      if (existingId && smtpPasswordSet && body.smtp_password === null) {
        delete body.smtp_password;
      }
      if (body.resource_types && body.resource_types.length === 0) {
        body.resource_types = null;
      }
      if (existingId) {
        return settingsApi.updateAuditTarget(existingId, body);
      }
      return settingsApi.createAuditTarget(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audit-forward-targets"] });
      onClose();
    },
    onError: (e: unknown) => {
      let msg = "Save failed";
      if (e && typeof e === "object" && "response" in e) {
        const resp = (e as { response?: { data?: { detail?: unknown } } })
          .response;
        if (resp?.data?.detail) msg = String(resp.data.detail);
      }
      setError(msg);
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
          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-400">
            {error}
          </div>
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
                <option value="teams">Microsoft Teams (MessageCard)</option>
                <option value="discord">Discord (embed)</option>
              </select>
              <div className="mt-1 text-[11px] text-muted-foreground">
                {form.webhook_flavor === "generic"
                  ? "Posts the raw audit/alert JSON. For collectors that parse it themselves."
                  : "Wraps the payload in the platform's incoming-webhook block format. Paste the URL the platform issued."}
              </div>
            </label>
            <label className="block">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                URL
              </div>
              <input
                className={inputCls}
                value={form.url ?? ""}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder={
                  form.webhook_flavor === "slack"
                    ? "https://hooks.slack.com/services/T…/B…/…"
                    : form.webhook_flavor === "teams"
                      ? "https://…webhook.office.com/webhookb2/…"
                      : form.webhook_flavor === "discord"
                        ? "https://discord.com/api/webhooks/…/…"
                        : "https://collector.example.com/ingest"
                }
              />
            </label>
            {form.webhook_flavor === "generic" && (
              <label className="block">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Authorization Header (optional)
                </div>
                <input
                  className={inputCls}
                  value={form.auth_header ?? ""}
                  onChange={(e) =>
                    setForm({ ...form, auth_header: e.target.value })
                  }
                  placeholder={
                    authHeaderSet
                      ? "(stored — leave blank to keep unchanged)"
                      : "Bearer …"
                  }
                />
              </label>
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
                  onChange={(e) =>
                    setForm({ ...form, smtp_password: e.target.value })
                  }
                  placeholder={
                    smtpPasswordSet
                      ? "(stored — leave blank to keep unchanged)"
                      : ""
                  }
                />
              </label>
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

        <div className="flex justify-end gap-2 border-t pt-3">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => saveMut.mutate()}
            disabled={saveMut.isPending || !form.name}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : existingId ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}
