import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  ShieldAlert,
} from "lucide-react";

import { ReauthFields } from "@/components/ReauthFields";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import {
  agentBootstrapKeysApi,
  type AgentBootstrapKeysReveal,
  formatApiError,
} from "@/lib/api";

/**
 * Security → Agent bootstrap keys section.
 *
 * Reveals DNS_AGENT_KEY + DHCP_AGENT_KEY behind a password-confirm
 * gate. The keys are the pre-shared secrets every distributed agent
 * (DNS or DHCP, on appliance / docker / k8s / bare metal) uses to
 * bootstrap registration against the control plane. Operators
 * need them at agent install time — without this UI they'd have to
 * SSH into the control-plane host and ``cat /etc/spatiumddi/.env``.
 *
 * Restricted server-side to superadmin + correct password; revealed
 * data lives only in component state and is auto-hidden if the user
 * navigates away (state lost on unmount). Both reveal attempts +
 * successful reveals emit AuditLog rows.
 */
export function AgentBootstrapKeysSection() {
  // The reveal is superadmin-only on the server (and a refusal is audited),
  // so a non-superadmin is not asked for a password at all (#2527).
  const { isSuperadmin } = usePermissions();
  const gate = permissionGate(isSuperadmin, NEEDS_SUPERADMIN);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [data, setData] = useState<AgentBootstrapKeysReveal | null>(null);
  const [shown, setShown] = useState<{ dns: boolean; dhcp: boolean }>({
    dns: false,
    dhcp: false,
  });
  const [copied, setCopied] = useState<"dns" | "dhcp" | null>(null);

  const reveal = useMutation({
    mutationFn: () =>
      agentBootstrapKeysApi.reveal(password || undefined, totp || undefined),
    onSuccess: (resp) => {
      setData(resp);
      setPassword("");
      setTotp("");
      // Show both as masked by default — operator chooses which to
      // uncover. Reduces shoulder-surf risk when only one is needed.
      setShown({ dns: false, dhcp: false });
    },
  });

  const copy = async (which: "dns" | "dhcp", value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(which);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard not available — operator can still select+copy */
    }
  };

  return (
    <section className="space-y-4">
      <div>
        <h2 className="flex items-center gap-2 text-base font-semibold">
          <KeyRound className="h-4 w-4 text-muted-foreground" />
          Agent bootstrap keys
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          The pre-shared keys distributed DNS / DHCP agents need on first boot
          to register against this control plane. Re-enter your password to
          reveal them — every reveal is logged to the audit trail.
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          Same keys work for every agent topology: appliance role-split
          installs, docker-compose agents on another host, the k8s agent chart,
          or a bare-metal install. The agent exchanges the pre-shared key for a
          rotating JWT on first contact + caches it locally so it only needs the
          bootstrap key once.
        </p>
      </div>

      {!data ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (isSuperadmin) reveal.mutate();
          }}
          className="max-w-md space-y-3 rounded-lg border bg-card p-4 shadow-sm"
        >
          <fieldset disabled={!isSuperadmin} className="min-w-0 space-y-3">
            <ReauthFields
              password={password}
              onPassword={setPassword}
              totp={totp}
              onTotp={setTotp}
              autoFocus={isSuperadmin}
            />
          </fieldset>
          {!isSuperadmin && (
            <p className="text-xs text-muted-foreground">
              Only a superadmin can reveal the agent bootstrap keys.
            </p>
          )}
          {reveal.isError && (
            <div className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-2 text-xs text-destructive">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{formatApiError(reveal.error)}</span>
            </div>
          )}
          <button
            type="submit"
            disabled={reveal.isPending || (!password && !totp)}
            {...gate}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            <Eye className="h-3.5 w-3.5" />
            {reveal.isPending ? "Verifying…" : "Reveal keys"}
          </button>
        </form>
      ) : (
        <div className="space-y-3">
          <KeyCard
            label="DNS_AGENT_KEY"
            description="DNS agents (BIND9 / PowerDNS / Technitium) paste this at install time."
            envVar="DNS_AGENT_KEY"
            configured={data.dns_agent_configured}
            value={data.dns_agent_key}
            shown={shown.dns}
            onToggleShown={() => setShown((s) => ({ ...s, dns: !s.dns }))}
            onCopy={() => copy("dns", data.dns_agent_key)}
            copied={copied === "dns"}
          />
          <KeyCard
            label="DHCP_AGENT_KEY"
            description="DHCP agents (Kea) paste this at install time."
            envVar="DHCP_AGENT_KEY"
            configured={data.dhcp_agent_configured}
            value={data.dhcp_agent_key}
            shown={shown.dhcp}
            onToggleShown={() => setShown((s) => ({ ...s, dhcp: !s.dhcp }))}
            onCopy={() => copy("dhcp", data.dhcp_agent_key)}
            copied={copied === "dhcp"}
          />
          <button
            type="button"
            onClick={() => {
              setData(null);
              setShown({ dns: false, dhcp: false });
            }}
            className="rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-accent"
          >
            Hide keys
          </button>
        </div>
      )}

      <details className="rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
        <summary className="cursor-pointer font-medium text-foreground">
          Where do I paste these keys?
        </summary>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>
            <strong>Role-split appliance ISO</strong> — the installer wizard
            asks for them on "DNS agent" / "DHCP agent" role selection.
          </li>
          <li>
            <strong>Docker / docker-compose agent</strong> — set the matching
            env var in the agent container's <code>.env</code> or compose file.
            See <code>docker-compose.standalone-dns.yml</code> /{" "}
            <code>docker-compose.standalone-dhcp.yml</code>.
          </li>
          <li>
            <strong>Kubernetes (Helm umbrella chart)</strong> — set{" "}
            <code>dnsAgents.bootstrapKey</code> /{" "}
            <code>dhcpAgents.bootstrapKey</code> in your{" "}
            <code>values.yaml</code>.
          </li>
          <li>
            The agent exchanges this key for a rotating JWT on first contact.
            Subsequent registrations don't need it; rotate it here only if the
            secret has leaked or you want to invalidate every existing agent in
            one shot.
          </li>
        </ul>
      </details>
    </section>
  );
}

function KeyCard({
  label,
  description,
  envVar,
  configured,
  value,
  shown,
  onToggleShown,
  onCopy,
  copied,
}: {
  label: string;
  description: string;
  envVar: string;
  configured: boolean;
  value: string;
  shown: boolean;
  onToggleShown: () => void;
  onCopy: () => void;
  copied: boolean;
}) {
  if (!configured) {
    return (
      <div className="rounded-lg border bg-card p-3 shadow-sm">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
          <h3 className="text-sm font-medium">{label}</h3>
          <span className="rounded-full bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-700 dark:text-amber-400">
            Not configured
          </span>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          The control plane's {envVar} env var is empty — set it on the api
          container (in <code>.env</code> for docker-compose, Helm values for
          k8s, <code>/etc/spatiumddi/.env</code> on the appliance) and restart
          the api before deploying matching agents.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border bg-card p-3 shadow-sm">
      <div className="flex items-start gap-2">
        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-medium">{label}</h3>
            <span className="rounded-full bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-700 dark:text-emerald-400">
              Configured
            </span>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>
        </div>
      </div>
      <div className="mt-2 flex items-center gap-2 rounded-md border bg-muted/50 px-2 py-1.5 font-mono text-xs">
        <span className="flex-1 overflow-x-auto whitespace-nowrap">
          {shown ? value : "•".repeat(Math.min(value.length, 48))}
        </span>
        <button
          type="button"
          onClick={onToggleShown}
          title={shown ? "Hide" : "Show"}
          className="shrink-0 rounded-md border bg-background px-1.5 py-0.5 text-[11px] hover:bg-accent"
        >
          {shown ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
        </button>
        <button
          type="button"
          onClick={onCopy}
          title="Copy"
          className="shrink-0 rounded-md border bg-background px-1.5 py-0.5 text-[11px] hover:bg-accent"
        >
          <Copy className="h-3 w-3" />
          {copied && (
            <span className="ml-1 text-emerald-600 dark:text-emerald-400">
              copied
            </span>
          )}
        </button>
      </div>
    </div>
  );
}
