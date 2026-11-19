import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Plus, Trash2 } from "lucide-react";

import {
  formatDialogError,
  settingsApi,
  type NtpCustomServer,
  type NtpSourceMode,
  type PlatformSettings,
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

export function NTPSection({
  values,
  isSuperadmin,
  applianceMode,
  inputCls,
}: Props) {
  const qc = useQueryClient();
  // Local state separate from the global form. NTP doesn't need
  // pass-merge semantics like SNMP, but giving it its own atomic
  // Save keeps the UX symmetrical with the SNMP tab next door.
  const [sourceMode, setSourceMode] = useState<NtpSourceMode>(
    values.ntp_source_mode,
  );
  const [poolServers, setPoolServers] = useState<string>(
    (values.ntp_pool_servers || []).join(", "),
  );
  const [customServers, setCustomServers] = useState<NtpCustomServer[]>(
    values.ntp_custom_servers || [],
  );
  const [allowClients, setAllowClients] = useState<boolean>(
    values.ntp_allow_clients,
  );
  const [allowNetworks, setAllowNetworks] = useState<string>(
    (values.ntp_allow_client_networks || []).join(", "),
  );

  const dirty =
    sourceMode !== values.ntp_source_mode ||
    poolServers !== (values.ntp_pool_servers || []).join(", ") ||
    JSON.stringify(customServers) !==
      JSON.stringify(values.ntp_custom_servers || []) ||
    allowClients !== values.ntp_allow_clients ||
    allowNetworks !== (values.ntp_allow_client_networks || []).join(", ");

  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  const mutation = useMutation({
    mutationFn: (patch: Partial<PlatformSettings>) => settingsApi.update(patch),
    onSuccess: (updated) => {
      qc.setQueryData(["settings"], updated);
      setSourceMode(updated.ntp_source_mode);
      setPoolServers((updated.ntp_pool_servers || []).join(", "));
      setCustomServers(updated.ntp_custom_servers || []);
      setAllowClients(updated.ntp_allow_clients);
      setAllowNetworks((updated.ntp_allow_client_networks || []).join(", "));
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
    const patch: Partial<PlatformSettings> = {
      ntp_source_mode: sourceMode,
      ntp_pool_servers: poolServers
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
      ntp_custom_servers: customServers,
      ntp_allow_clients: allowClients,
      ntp_allow_client_networks: allowNetworks
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    };
    mutation.mutate(patch);
  }

  function addCustomServer() {
    setCustomServers((prev) => [
      ...prev,
      { host: "", iburst: true, prefer: false },
    ]);
  }
  function updateCustomServer(idx: number, partial: Partial<NtpCustomServer>) {
    setCustomServers((prev) =>
      prev.map((s, i) => (i === idx ? { ...s, ...partial } : s)),
    );
  }
  function removeCustomServer(idx: number) {
    setCustomServers((prev) => prev.filter((_, i) => i !== idx));
  }

  return (
    <div className="space-y-2">
      {!applianceMode && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
          <div className="space-y-1">
            <p className="font-medium text-amber-700 dark:text-amber-400">
              chrony is only configured on appliance hosts
            </p>
            <p className="text-muted-foreground">
              This control plane is running in docker / k8s, where chrony isn't
              part of the SpatiumDDI image. Use your host's standard time-sync
              (systemd-timesyncd / ntpd / chrony installed separately). Settings
              saved here still flow through the ConfigBundle to any{" "}
              <em>appliance agents</em> registered with this control plane —
              useful for hybrid deployments.
            </p>
          </div>
        </div>
      )}

      <Field
        label="Source mode"
        description="Pool — resolver-expanded NTP pool (e.g. pool.ntp.org); good for internet-connected appliances. Servers — explicit unicast servers only; required for air-gapped sites or compliance shops. Mixed — both, with custom servers taking precedence."
      >
        <select
          value={sourceMode}
          onChange={(e) => setSourceMode(e.target.value as NtpSourceMode)}
          disabled={!isSuperadmin}
          className={inputCls}
        >
          <option value="pool">Pool</option>
          <option value="servers">Servers</option>
          <option value="mixed">Mixed</option>
        </select>
      </Field>

      {(sourceMode === "pool" || sourceMode === "mixed") && (
        <Field
          label="Pool servers"
          description="Comma- or space-separated list of NTP pool hostnames (e.g. ‘pool.ntp.org’, ‘2.debian.pool.ntp.org’). Each name expands to multiple servers via DNS. ‘iburst’ is implied so initial sync is fast."
        >
          <input
            type="text"
            value={poolServers}
            onChange={(e) => setPoolServers(e.target.value)}
            placeholder="pool.ntp.org"
            disabled={!isSuperadmin}
            className={cn(inputCls, "w-96 max-w-full font-mono")}
          />
        </Field>
      )}

      {(sourceMode === "servers" || sourceMode === "mixed") && (
        <div className="rounded-md border bg-muted/30 p-3">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <div className="text-sm font-medium">Unicast servers</div>
              <div className="text-xs text-muted-foreground">
                Explicit NTP servers (host or IP).{" "}
                <code className="font-mono">iburst</code> speeds initial sync;{" "}
                <code className="font-mono">prefer</code> tags a canonical
                source — chrony biases toward it during selection when multiple
                servers are healthy.
              </div>
            </div>
            <button
              type="button"
              onClick={addCustomServer}
              disabled={!isSuperadmin}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-40"
            >
              <Plus className="h-3 w-3" />
              Add server
            </button>
          </div>
          {customServers.length === 0 ? (
            <div className="py-2 text-xs text-muted-foreground">
              No unicast servers configured.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="py-1 pr-2">Host</th>
                    <th className="py-1 pr-2 text-center">iburst</th>
                    <th className="py-1 pr-2 text-center">prefer</th>
                    <th className="py-1"></th>
                  </tr>
                </thead>
                <tbody>
                  {customServers.map((s, idx) => (
                    <tr key={idx} className="border-b last:border-b-0">
                      <td className="py-1 pr-2">
                        <input
                          type="text"
                          value={s.host}
                          onChange={(e) =>
                            updateCustomServer(idx, { host: e.target.value })
                          }
                          placeholder="time.example.com"
                          disabled={!isSuperadmin}
                          className={cn(inputCls, "w-60 font-mono")}
                        />
                      </td>
                      <td className="py-1 pr-2 text-center">
                        <input
                          type="checkbox"
                          checked={s.iburst}
                          onChange={(e) =>
                            updateCustomServer(idx, {
                              iburst: e.target.checked,
                            })
                          }
                          disabled={!isSuperadmin}
                        />
                      </td>
                      <td className="py-1 pr-2 text-center">
                        <input
                          type="checkbox"
                          checked={s.prefer}
                          onChange={(e) =>
                            updateCustomServer(idx, {
                              prefer: e.target.checked,
                            })
                          }
                          disabled={!isSuperadmin}
                        />
                      </td>
                      <td className="py-1">
                        <button
                          type="button"
                          onClick={() => removeCustomServer(idx)}
                          disabled={!isSuperadmin}
                          className="rounded p-1 text-destructive hover:bg-destructive/10 disabled:opacity-40"
                          title="Remove server"
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      <Field
        label="Serve NTP to clients"
        description="When on, this appliance also acts as an NTP server. Useful for isolated networks where the appliance is the time source. Opens UDP 123 inbound in the host firewall on enable; closes on disable."
      >
        <Toggle
          checked={allowClients}
          onChange={setAllowClients}
          disabled={!isSuperadmin}
        />
      </Field>

      {allowClients && (
        <Field
          label="Allowed client CIDRs"
          description="Comma- or space-separated list of CIDRs allowed to query this appliance for time. Empty = nothing allowed (chrony refuses every query). Use ‘0.0.0.0/0’ to allow everything (rare; rely on the host firewall + perimeter instead)."
        >
          <input
            type="text"
            value={allowNetworks}
            onChange={(e) => setAllowNetworks(e.target.value)}
            placeholder="10.0.0.0/8, 192.168.0.0/16"
            disabled={!isSuperadmin}
            className={cn(inputCls, "w-96 max-w-full font-mono")}
          />
        </Field>
      )}

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
              : "Save NTP settings"}
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
