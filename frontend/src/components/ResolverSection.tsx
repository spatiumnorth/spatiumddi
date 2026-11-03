import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle } from "lucide-react";

import {
  formatDialogError,
  settingsApi,
  type PlatformSettings,
  type ResolverDnssec,
  type ResolverDoT,
  type ResolverMode,
} from "@/lib/api";
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

// Comma- or space-separated input → trimmed, de-blanked list.
function splitList(s: string): string[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

export function ResolverSection({
  values,
  isSuperadmin,
  applianceMode,
  inputCls,
}: Props) {
  const qc = useQueryClient();
  // Local state separate from the global form. Own atomic Save keeps the
  // UX symmetrical with the NTP / SNMP / SSH tabs next door.
  const [mode, setMode] = useState<ResolverMode>(values.resolver_mode);
  const [servers, setServers] = useState<string>(
    (values.resolver_servers || []).join(", "),
  );
  const [fallback, setFallback] = useState<string>(
    (values.resolver_fallback_servers || []).join(", "),
  );
  const [search, setSearch] = useState<string>(
    (values.resolver_search_domains || []).join(", "),
  );
  const [dnssec, setDnssec] = useState<ResolverDnssec>(values.resolver_dnssec);
  const [dot, setDot] = useState<ResolverDoT>(values.resolver_dns_over_tls);

  const dirty =
    mode !== values.resolver_mode ||
    servers !== (values.resolver_servers || []).join(", ") ||
    fallback !== (values.resolver_fallback_servers || []).join(", ") ||
    search !== (values.resolver_search_domains || []).join(", ") ||
    dnssec !== values.resolver_dnssec ||
    dot !== values.resolver_dns_over_tls;

  // Override mode routes ALL host DNS to the global DNS= list (Domains=~.),
  // so an empty server list leaves the host with zero working upstream DNS.
  // Mirror the server-side guard: require at least one server in override
  // mode (disable Save + show why) so the operator can't lock the host out.
  const overrideNeedsServers =
    mode === "override" && splitList(servers).length === 0;

  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  const mutation = useMutation({
    mutationFn: (patch: Partial<PlatformSettings>) => settingsApi.update(patch),
    onSuccess: (updated) => {
      qc.setQueryData(["settings"], updated);
      setMode(updated.resolver_mode);
      setServers((updated.resolver_servers || []).join(", "));
      setFallback((updated.resolver_fallback_servers || []).join(", "));
      setSearch((updated.resolver_search_domains || []).join(", "));
      setDnssec(updated.resolver_dnssec);
      setDot(updated.resolver_dns_over_tls);
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
      resolver_mode: mode,
      resolver_servers: splitList(servers),
      resolver_fallback_servers: splitList(fallback),
      resolver_search_domains: splitList(search),
      resolver_dnssec: dnssec,
      resolver_dns_over_tls: dot,
    };
    mutation.mutate(patch);
  }

  return (
    <div className="space-y-2">
      {!applianceMode && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
          <div className="space-y-1">
            <p className="font-medium text-amber-700 dark:text-amber-400">
              systemd-resolved is only configured on appliance hosts
            </p>
            <p className="text-muted-foreground">
              This control plane is running in docker / k8s, where
              systemd-resolved isn't part of the SpatiumDDI image. Manage your
              host's resolver directly. Settings saved here still flow through
              the ConfigBundle to any <em>appliance agents</em> registered with
              this control plane — useful for hybrid deployments.
            </p>
          </div>
        </div>
      )}

      <Field
        label="Resolver mode"
        description="Automatic — leave systemd-resolved to pick upstream DNS from per-link NetworkManager / DHCP (the default; reverting to it removes the managed drop-in). Override — pin the global DNS servers below so they win over the per-link resolvers."
      >
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value as ResolverMode)}
          disabled={!isSuperadmin}
          className={inputCls}
        >
          <option value="automatic">Automatic</option>
          <option value="override">Override</option>
        </select>
      </Field>

      {mode === "override" && (
        <>
          <Field
            label="DNS servers"
            description="Comma- or space-separated resolver IPs (v4 or v6) rendered as systemd-resolved DNS=. A route-only ~. default domain is emitted automatically so these servers win over per-link resolvers. At least one server is required in override mode — override routes all host DNS here, so an empty list would leave the host with no working upstream DNS."
          >
            <input
              type="text"
              value={servers}
              onChange={(e) => setServers(e.target.value)}
              placeholder="1.1.1.1, 9.9.9.9"
              disabled={!isSuperadmin}
              className={cn(
                inputCls,
                "w-96 max-w-full font-mono",
                overrideNeedsServers && "border-destructive",
              )}
            />
          </Field>

          <Field
            label="Fallback DNS servers"
            description="Comma- or space-separated resolver IPs used only when every primary server is unreachable (rendered as FallbackDNS=). Optional."
          >
            <input
              type="text"
              value={fallback}
              onChange={(e) => setFallback(e.target.value)}
              placeholder="8.8.8.8"
              disabled={!isSuperadmin}
              className={cn(inputCls, "w-96 max-w-full font-mono")}
            />
          </Field>

          <Field
            label="Search domains"
            description="Comma- or space-separated DNS search domains (rendered after the route-only ~. default in Domains=). Optional — leave empty for none."
          >
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="corp.example.com, lab.example.com"
              disabled={!isSuperadmin}
              className={cn(inputCls, "w-96 max-w-full font-mono")}
            />
          </Field>

          <Field
            label="DNSSEC"
            description="systemd-resolved DNSSEC= validation. allow-downgrade (default) validates when the upstream supports it and falls back gracefully; yes enforces; no disables."
          >
            <select
              value={dnssec}
              onChange={(e) => setDnssec(e.target.value as ResolverDnssec)}
              disabled={!isSuperadmin}
              className={inputCls}
            >
              <option value="allow-downgrade">allow-downgrade</option>
              <option value="yes">yes</option>
              <option value="no">no</option>
            </select>
          </Field>

          <Field
            label="DNS-over-TLS"
            description="systemd-resolved DNSOverTLS=. no (default) sends plaintext; opportunistic uses TLS when the server supports it; yes requires TLS (lookups fail if the server can't do it)."
          >
            <select
              value={dot}
              onChange={(e) => setDot(e.target.value as ResolverDoT)}
              disabled={!isSuperadmin}
              className={inputCls}
            >
              <option value="no">no</option>
              <option value="opportunistic">opportunistic</option>
              <option value="yes">yes</option>
            </select>
          </Field>
        </>
      )}

      <div className="mt-4 flex items-center gap-3 border-t pt-4">
        <button
          type="button"
          onClick={handleSave}
          disabled={
            !isSuperadmin ||
            !dirty ||
            mutation.isPending ||
            overrideNeedsServers
          }
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40"
        >
          {mutation.isPending
            ? "Saving…"
            : savedAt
              ? "Saved!"
              : "Save resolver settings"}
        </button>
        {overrideNeedsServers && (
          <span className="text-xs text-destructive">
            Override mode requires at least one DNS server.
          </span>
        )}
        {saveErr && (
          <span className="text-xs text-destructive">
            Failed to save: {saveErr}
          </span>
        )}
      </div>
    </div>
  );
}
