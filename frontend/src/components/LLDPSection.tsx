import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle } from "lucide-react";

import {
  settingsApi,
  type LldpProtocol,
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

const ALL_PROTOCOLS: { key: LldpProtocol; label: string }[] = [
  { key: "cdp", label: "CDP (Cisco)" },
  { key: "edp", label: "EDP (Extreme)" },
  { key: "fdp", label: "FDP (Foundry)" },
  { key: "sonmp", label: "SONMP (Nortel)" },
];

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

export function LLDPSection({
  values,
  isSuperadmin,
  applianceMode,
  inputCls,
}: Props) {
  const qc = useQueryClient();
  const [enabled, setEnabled] = useState<boolean>(values.lldp_enabled);
  const [txInterval, setTxInterval] = useState<number>(values.lldp_tx_interval);
  const [txHold, setTxHold] = useState<number>(values.lldp_tx_hold);
  const [protocols, setProtocols] = useState<LldpProtocol[]>(
    values.lldp_protocols || [],
  );
  const [ifacePattern, setIfacePattern] = useState<string>(
    values.lldp_interface_pattern,
  );
  const [mgmtPattern, setMgmtPattern] = useState<string>(
    values.lldp_management_pattern,
  );
  const [sysName, setSysName] = useState<string>(values.lldp_sys_name);
  const [sysDesc, setSysDesc] = useState<string>(values.lldp_sys_description);
  const [agentx, setAgentx] = useState<boolean>(values.lldp_snmp_agentx);
  const [elin, setElin] = useState<string>(
    String((values.lldp_med_location as { elin?: unknown } | null)?.elin ?? ""),
  );

  const dirty =
    enabled !== values.lldp_enabled ||
    txInterval !== values.lldp_tx_interval ||
    txHold !== values.lldp_tx_hold ||
    JSON.stringify([...protocols].sort()) !==
      JSON.stringify([...(values.lldp_protocols || [])].sort()) ||
    ifacePattern !== values.lldp_interface_pattern ||
    mgmtPattern !== values.lldp_management_pattern ||
    sysName !== values.lldp_sys_name ||
    sysDesc !== values.lldp_sys_description ||
    agentx !== values.lldp_snmp_agentx ||
    elin !==
      String(
        (values.lldp_med_location as { elin?: unknown } | null)?.elin ?? "",
      );

  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  const mutation = useMutation({
    mutationFn: (patch: Partial<PlatformSettings>) => settingsApi.update(patch),
    onSuccess: (updated) => {
      qc.setQueryData(["settings"], updated);
      setEnabled(updated.lldp_enabled);
      setTxInterval(updated.lldp_tx_interval);
      setTxHold(updated.lldp_tx_hold);
      setProtocols(updated.lldp_protocols || []);
      setIfacePattern(updated.lldp_interface_pattern);
      setMgmtPattern(updated.lldp_management_pattern);
      setSysName(updated.lldp_sys_name);
      setSysDesc(updated.lldp_sys_description);
      setAgentx(updated.lldp_snmp_agentx);
      setElin(
        String(
          (updated.lldp_med_location as { elin?: unknown } | null)?.elin ?? "",
        ),
      );
      setSaveErr(null);
      setSavedAt(Date.now());
      setTimeout(() => setSavedAt(null), 2500);
    },
    onError: (err: unknown) => {
      setSaveErr(err instanceof Error ? err.message : String(err));
    },
  });

  function toggleProtocol(p: LldpProtocol) {
    setProtocols((prev) =>
      prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p],
    );
  }

  function handleSave() {
    mutation.mutate({
      lldp_enabled: enabled,
      lldp_tx_interval: txInterval,
      lldp_tx_hold: txHold,
      lldp_protocols: protocols,
      lldp_interface_pattern: ifacePattern.trim(),
      lldp_management_pattern: mgmtPattern.trim(),
      lldp_sys_name: sysName,
      lldp_sys_description: sysDesc,
      lldp_snmp_agentx: agentx,
      lldp_med_location: elin.trim() ? { elin: elin.trim() } : {},
    });
  }

  const ttl = Math.max(1, txInterval) * Math.max(1, txHold);

  return (
    <div className="space-y-2">
      {!applianceMode && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
          <div className="space-y-1">
            <p className="font-medium text-amber-700 dark:text-amber-400">
              lldpd is only configured on appliance hosts
            </p>
            <p className="text-muted-foreground">
              This control plane is running in docker / k8s, where lldpd isn't
              part of the SpatiumDDI image. Settings saved here still flow
              through the ConfigBundle to any <em>appliance agents</em>{" "}
              registered with this control plane.
            </p>
          </div>
        </div>
      )}

      <Field
        label="Enable LLDP"
        description="Run lldpd on the appliance host(s) to advertise this node to upstream switches and discover L2 neighbours. Off by default — when off, the host advertises nothing."
      >
        <Toggle
          checked={enabled}
          onChange={setEnabled}
          disabled={!isSuperadmin}
        />
      </Field>

      <Field
        label="Transmit interval (s)"
        description={`How often lldpd sends advertisements. TTL advertised to neighbours = interval × hold = ${ttl}s.`}
      >
        <input
          type="number"
          min={1}
          max={3600}
          value={txInterval}
          onChange={(e) => setTxInterval(Number(e.target.value))}
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-24")}
        />
      </Field>

      <Field
        label="Transmit hold"
        description="TTL multiplier. The advertised time-to-live is interval × hold; neighbours drop this node that long after the last frame."
      >
        <input
          type="number"
          min={1}
          max={100}
          value={txHold}
          onChange={(e) => setTxHold(Number(e.target.value))}
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-24")}
        />
      </Field>

      <Field
        label="Also receive"
        description="Enable reception of legacy/vendor neighbour protocols on top of LLDP. Useful when upstream gear only speaks CDP (Cisco) etc."
      >
        <div className="flex flex-wrap gap-3">
          {ALL_PROTOCOLS.map((p) => (
            <label key={p.key} className="flex items-center gap-1.5 text-sm">
              <input
                type="checkbox"
                checked={protocols.includes(p.key)}
                onChange={() => toggleProtocol(p.key)}
                disabled={!isSuperadmin}
              />
              {p.label}
            </label>
          ))}
        </div>
      </Field>

      <Field
        label="Interface pattern"
        description="lldpd interface allowlist (comma-separated globs; ! excludes). The default excludes docker / k3s vNICs so the appliance never advertises into the overlay network."
      >
        <input
          type="text"
          value={ifacePattern}
          onChange={(e) => setIfacePattern(e.target.value)}
          placeholder="eth*,en*,!docker*,!veth*,!br-*,!cni0,!flannel.1"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-96 max-w-full font-mono")}
        />
      </Field>

      <Field
        label="Management address pattern"
        description="Which interface / CIDR's IP to advertise as the management address. Empty = let lldpd auto-select the primary routable IP."
      >
        <input
          type="text"
          value={mgmtPattern}
          onChange={(e) => setMgmtPattern(e.target.value)}
          placeholder="(auto) — or e.g. eth0 / 10.0.0.0/8"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-96 max-w-full font-mono")}
        />
      </Field>

      <Field
        label="System name override"
        description="Advertised system name. Empty = the host's FQDN."
      >
        <input
          type="text"
          value={sysName}
          onChange={(e) => setSysName(e.target.value)}
          placeholder="(host FQDN)"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-96 max-w-full")}
        />
      </Field>

      <Field
        label="System description override"
        description="Advertised system description. Empty = lldpd's default (kernel + OS)."
      >
        <input
          type="text"
          value={sysDesc}
          onChange={(e) => setSysDesc(e.target.value)}
          placeholder="(default)"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-96 max-w-full")}
        />
      </Field>

      <Field
        label="SNMP AgentX (LLDP-MIB)"
        description="Register lldpd as an AgentX subagent of the host snmpd so LLDP-MIB (lldpRemTable) is queryable over SNMP. Only meaningful when SNMP is also enabled. Local socket only — no firewall change."
      >
        <Toggle
          checked={agentx}
          onChange={setAgentx}
          disabled={!isSuperadmin}
        />
      </Field>

      <Field
        label="MED location (ELIN)"
        description="LLDP-MED Emergency Location Identification Number advertised to MED endpoints (IP phones) for E911 routing. Digits only; empty = none. Coordinate / civic forms are API-only for now."
      >
        <input
          type="text"
          inputMode="numeric"
          value={elin}
          onChange={(e) => setElin(e.target.value)}
          placeholder="(none)"
          disabled={!isSuperadmin}
          className={cn(inputCls, "w-48")}
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
              : "Save LLDP settings"}
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
