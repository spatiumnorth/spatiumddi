import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Plus, Trash2 } from "lucide-react";

import {
  formatDialogError,
  settingsApi,
  type PlatformSettings,
  type SyslogFormat,
  type SyslogProtocol,
  type SyslogTarget,
  type SyslogTargetWrite,
} from "@/lib/api";
import { Toggle } from "@/components/ui/toggle";
import { cn } from "@/lib/utils";

interface Props {
  values: PlatformSettings;
  isSuperadmin: boolean;
  applianceMode: boolean;
  inputCls: string;
}

function Field({
  label,
  description,
  children,
}: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-8 py-3">
      <div className="max-w-xl">
        <div className="text-sm font-medium">{label}</div>
        {description && (
          <div className="text-xs text-muted-foreground">{description}</div>
        )}
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

// Per-target editor draft. ``ca_cert_set`` carries whether a CA PEM is
// already stored server-side; ``ca_cert_pem`` is the local edit buffer
// (undefined = leave stored value alone, "" = clear, non-empty =
// replace) — same tri-state shape as the SNMP community field.
interface TargetDraft {
  host: string;
  port: number;
  protocol: SyslogProtocol;
  format: SyslogFormat;
  ca_cert_set: boolean;
  ca_cert_pem?: string;
}

function toDraft(t: SyslogTarget): TargetDraft {
  return {
    host: t.host,
    port: t.port,
    protocol: t.protocol,
    format: t.format,
    ca_cert_set: t.ca_cert_set,
    ca_cert_pem: undefined,
  };
}

export function SyslogSection({
  values,
  isSuperadmin,
  applianceMode,
  inputCls,
}: Props) {
  const qc = useQueryClient();
  const [enabled, setEnabled] = useState<boolean>(values.syslog_enabled);
  const [targets, setTargets] = useState<TargetDraft[]>(
    (values.syslog_targets || []).map(toDraft),
  );
  const [filter, setFilter] = useState<string>(values.syslog_filter || "");
  const [bufferDisk, setBufferDisk] = useState<boolean>(
    values.syslog_buffer_disk,
  );

  const dirty =
    enabled !== values.syslog_enabled ||
    filter !== (values.syslog_filter || "") ||
    bufferDisk !== values.syslog_buffer_disk ||
    JSON.stringify(targets.map(({ ca_cert_pem: _drop, ...rest }) => rest)) !==
      JSON.stringify(
        (values.syslog_targets || [])
          .map(toDraft)
          .map(({ ca_cert_pem: _d, ...r }) => r),
      ) ||
    targets.some((t) => t.ca_cert_pem !== undefined);

  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  const mutation = useMutation({
    mutationFn: (patch: Partial<PlatformSettings>) => settingsApi.update(patch),
    onSuccess: (updated) => {
      qc.setQueryData(["settings"], updated);
      setEnabled(updated.syslog_enabled);
      setTargets((updated.syslog_targets || []).map(toDraft));
      setFilter(updated.syslog_filter || "");
      setBufferDisk(updated.syslog_buffer_disk);
      setSaveErr(null);
      setSavedAt(Date.now());
      setTimeout(() => setSavedAt(null), 2500);
    },
    // formatDialogError, not err.message: on an AxiosError the latter is only
    // "Request failed with status code N", which hides the server's reason,
    // the validator's sentence naming the refused value (#3424).
    onError: (err: unknown) => {
      setSaveErr(formatDialogError(err));
    },
  });

  function handleSave() {
    const writeTargets: SyslogTargetWrite[] = targets.map((t) => {
      const w: SyslogTargetWrite = {
        host: t.host.trim(),
        port: t.port,
        protocol: t.protocol,
        format: t.format,
      };
      // None/omit = leave stored CA alone; "" = clear; non-empty =
      // replace. Only relevant for TLS targets.
      if (t.ca_cert_pem !== undefined) w.ca_cert_pem = t.ca_cert_pem;
      return w;
    });
    // PlatformSettings.syslog_targets is the read shape; the write shape
    // (SyslogTargetWrite) carries ca_cert_pem instead of ca_cert_set, so
    // cast through unknown for the partial patch.
    const patch = {
      syslog_enabled: enabled,
      syslog_targets: writeTargets,
      syslog_filter: filter,
      syslog_buffer_disk: bufferDisk,
    } as unknown as Partial<PlatformSettings>;
    mutation.mutate(patch);
  }

  function addTarget() {
    setTargets((prev) => [
      ...prev,
      {
        host: "",
        port: 514,
        protocol: "udp",
        format: "rfc5424",
        ca_cert_set: false,
        ca_cert_pem: undefined,
      },
    ]);
  }
  function updateTarget(idx: number, partial: Partial<TargetDraft>) {
    setTargets((prev) =>
      prev.map((t, i) => (i === idx ? { ...t, ...partial } : t)),
    );
  }
  function removeTarget(idx: number) {
    setTargets((prev) => prev.filter((_, i) => i !== idx));
  }

  return (
    <div className="space-y-2">
      {!applianceMode && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
          <div className="space-y-1">
            <p className="font-medium text-amber-700 dark:text-amber-400">
              rsyslog forwarding is only configured on appliance hosts
            </p>
            <p className="text-muted-foreground">
              This control plane is running in docker / k8s, where rsyslog isn't
              part of the SpatiumDDI image. Use your host's standard log
              shipping. Settings saved here still flow through the ConfigBundle
              to any <em>appliance agents</em> registered with this control
              plane — useful for hybrid deployments.
            </p>
          </div>
        </div>
      )}

      <Field
        label="Forward logs off-box"
        description="When on, rsyslog ships the appliance's journald + file log sources to the destinations below. Forwarding is outbound only — no inbound firewall port is opened."
      >
        <Toggle
          checked={enabled}
          onChange={setEnabled}
          disabled={!isSuperadmin}
        />
      </Field>

      <div className="rounded-md border bg-muted/30 p-3">
        <div className="mb-2 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Forward targets</div>
            <div className="text-xs text-muted-foreground">
              One collector per row. TLS targets need a CA PEM to validate the
              collector's certificate.
            </div>
          </div>
          <button
            type="button"
            onClick={addTarget}
            disabled={!isSuperadmin}
            className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-40"
          >
            <Plus className="h-3 w-3" />
            Add target
          </button>
        </div>
        {targets.length === 0 ? (
          <div className="py-2 text-xs text-muted-foreground">
            No forward targets configured.
          </div>
        ) : (
          <div className="space-y-3">
            {targets.map((t, idx) => (
              <div key={idx} className="rounded-md border bg-background p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={t.host}
                    onChange={(e) =>
                      updateTarget(idx, { host: e.target.value })
                    }
                    placeholder="collector.example.com"
                    disabled={!isSuperadmin}
                    className={cn(inputCls, "w-56 font-mono")}
                  />
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={t.port}
                    onChange={(e) =>
                      updateTarget(idx, {
                        port: Number(e.target.value) || 514,
                      })
                    }
                    disabled={!isSuperadmin}
                    className={cn(inputCls, "w-24 font-mono")}
                  />
                  <select
                    value={t.protocol}
                    onChange={(e) =>
                      updateTarget(idx, {
                        protocol: e.target.value as SyslogProtocol,
                      })
                    }
                    disabled={!isSuperadmin}
                    className={inputCls}
                  >
                    <option value="udp">UDP</option>
                    <option value="tcp">TCP</option>
                    <option value="tls">TLS</option>
                  </select>
                  <select
                    value={t.format}
                    onChange={(e) =>
                      updateTarget(idx, {
                        format: e.target.value as SyslogFormat,
                      })
                    }
                    disabled={!isSuperadmin}
                    className={inputCls}
                  >
                    <option value="rfc5424">RFC 5424</option>
                    <option value="rfc3164">RFC 3164</option>
                    <option value="json">JSON</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => removeTarget(idx)}
                    disabled={!isSuperadmin}
                    className="ml-auto rounded p-1 text-destructive hover:bg-destructive/10 disabled:opacity-40"
                    title="Remove target"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
                {t.protocol === "tls" && (
                  <div className="mt-2">
                    <CaCertField
                      target={t}
                      isSuperadmin={isSuperadmin}
                      inputCls={inputCls}
                      onChange={(pem) =>
                        updateTarget(idx, { ca_cert_pem: pem })
                      }
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <Field
        label="Filter (rsyslog selector)"
        description="Which messages to forward, as an rsyslog selector (e.g. ``*.*`` for everything, ``authpriv.*`` for auth logs, ``*.warning`` for warnings and above). Empty defaults to ``*.*``."
      >
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="*.*"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-64 max-w-full font-mono")}
        />
      </Field>

      <Field
        label="Disk-assisted buffering"
        description="When on, each forward action uses a disk-backed queue so a brief collector outage doesn't drop logs (capped at 256 MB per target, saved across restarts). Adds disk I/O; leave off for high-volume/low-latency setups that prefer to drop on outage."
      >
        <Toggle
          checked={bufferDisk}
          onChange={setBufferDisk}
          disabled={!isSuperadmin}
        />
      </Field>

      <div className="mt-4 flex items-center gap-3 border-t pt-4">
        <button
          type="button"
          onClick={handleSave}
          disabled={!isSuperadmin || !dirty || mutation.isPending}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40"
        >
          {mutation.isPending
            ? "Saving…"
            : savedAt
              ? "Saved!"
              : "Save syslog settings"}
        </button>
        {saveErr && (
          <span className="text-xs text-destructive">
            Failed to save: {saveErr}
          </span>
        )}
      </div>
    </div>
  );
}

// Per-target CA PEM field with the tri-state set/replace/clear shape
// mirroring the SNMP community field. Stored value is never returned by
// the API (only ``ca_cert_set``), so the operator pastes a fresh PEM to
// replace; the textarea stays hidden behind a "Configured ✓ / Replace"
// chip when one is already stored.
function CaCertField({
  target,
  isSuperadmin,
  inputCls,
  onChange,
}: {
  target: TargetDraft;
  isSuperadmin: boolean;
  inputCls: string;
  onChange: (pem: string | undefined) => void;
}) {
  const [replacing, setReplacing] = useState(false);
  const draft = target.ca_cert_pem;
  const showInput = !target.ca_cert_set || replacing || draft !== undefined;

  if (target.ca_cert_set && !showInput) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground">CA certificate:</span>
        <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
          Configured ✓
        </span>
        <button
          type="button"
          onClick={() => {
            setReplacing(true);
            onChange("");
          }}
          disabled={!isSuperadmin}
          className="rounded-md border px-2 py-0.5 text-xs hover:bg-accent disabled:opacity-40"
        >
          Replace
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          CA certificate (PEM){" "}
          {target.ca_cert_set
            ? "— pasting a new value replaces the stored CA"
            : "— required for TLS"}
        </span>
        {target.ca_cert_set && (
          <button
            type="button"
            onClick={() => {
              setReplacing(false);
              onChange(undefined);
            }}
            disabled={!isSuperadmin}
            className="rounded-md border px-2 py-0.5 text-xs hover:bg-accent disabled:opacity-40"
            title="Keep the existing CA"
          >
            Cancel
          </button>
        )}
      </div>
      <textarea
        value={draft ?? ""}
        onChange={(e) => onChange(e.target.value)}
        placeholder={
          "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"
        }
        disabled={!isSuperadmin}
        rows={4}
        className={cn(inputCls, "w-full font-mono text-xs")}
      />
    </div>
  );
}
