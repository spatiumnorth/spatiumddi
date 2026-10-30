import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  AlertCircle,
  CheckCircle2,
  Circle,
  Container as ContainerIcon,
  KeyRound,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

import {
  applianceSetupApi,
  applianceSystemApi,
  applianceTlsApi,
  versionApi,
  formatApiError,
} from "@/lib/api";
import { useApplianceAdminGate } from "@/hooks/useApplianceAdmin";

/**
 * Phase 4g — Web first-boot setup wizard.
 *
 * Single-page checklist (not multi-step routing) so operators can
 * scan progress at a glance + jump to the relevant tab. Each item
 * shows status derived from the underlying state:
 *  - Admin password changed → User.force_password_change is false
 *    (we don't probe that here; we trust that auth gates already
 *    redirected to /change-password on first login; this surface is
 *    primarily about appliance-shaped config)
 *  - Web UI cert ≠ self-signed default → at least one active cert
 *    where source != self-signed
 *  - SSH key uploaded → manual today, gets a "manage via SSH" note
 *
 * "Finish setup" marks the file-backed flag complete. After that the
 * banner stops showing + the redirect-on-first-hit logic stops firing.
 */
export function SetupWizardPage() {
  // #1342 — every appliance action takes `admin` on `appliance`.
  const applianceGate = useApplianceAdminGate();
  const qc = useQueryClient();
  const navigate = useNavigate();

  const setup = useQuery({
    queryKey: ["appliance", "setup"],
    queryFn: applianceSetupApi.state,
  });
  const version = useQuery({
    queryKey: ["version"],
    queryFn: versionApi.get,
  });
  const sys = useQuery({
    queryKey: ["appliance", "system", "info"],
    queryFn: applianceSystemApi.info,
  });
  const certs = useQuery({
    queryKey: ["appliance", "tls"],
    queryFn: applianceTlsApi.list,
  });

  const finish = useMutation({
    mutationFn: applianceSetupApi.complete,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "setup"] });
      navigate("/dashboard");
    },
  });

  const activeCert = certs.data?.find((c) => c.is_active && !c.pending);
  const certIsCustom = !!activeCert && activeCert.source !== "self-signed";

  return (
    <div className="mx-auto max-w-3xl space-y-6 px-6 py-8">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <Sparkles className="h-5 w-5 text-primary" />
          SpatiumDDI Appliance — first-boot setup
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Welcome. This page walks through the optional polish steps after a
          fresh install. The appliance is already serving HTTPS on a self-signed
          cert; you can run it as-is and come back later.
        </p>
        {setup.data?.complete && (
          <div className="mt-3 inline-flex items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-700 dark:text-emerald-400">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Setup completed
            {setup.data.completed_at && (
              <span className="text-muted-foreground">
                · {new Date(setup.data.completed_at).toLocaleDateString()}
              </span>
            )}
            {setup.data.completed_by && (
              <span className="text-muted-foreground">
                by {setup.data.completed_by}
              </span>
            )}
          </div>
        )}
      </div>

      <section className="rounded-lg border bg-card shadow-sm">
        <Step
          done={true}
          title="Appliance running"
          subtitle={
            sys.data
              ? `${sys.data.hostname} · ${
                  sys.data.host_ips.join(", ") || "no public IPs"
                }${
                  sys.data.appliance_version
                    ? ` · v${sys.data.appliance_version}`
                    : ""
                }`
              : "Loading…"
          }
          icon={ShieldCheck}
        />
        <Step
          done={certIsCustom}
          title="Web UI certificate"
          subtitle={
            certIsCustom
              ? `Active: ${activeCert?.name} (${activeCert?.source})`
              : "Currently serving the self-signed default — replace with a real cert or Let's Encrypt"
          }
          actionLabel="Manage certificate"
          onAction={() => navigate("/appliance?tab=tls")}
          icon={KeyRound}
        />
        <Step
          done={false}
          title="SSH access"
          subtitle="Manage SSH keys from the web under Appliance → Fleet → SSH (Authorized keys), or directly on the OS account you created in the installer (~/.ssh/authorized_keys)."
          icon={ContainerIcon}
        />
        <Step
          done={true}
          title="Running version"
          subtitle={`${version.data?.version ?? "loading"} ${
            version.data?.update_available
              ? `— update available: ${version.data.latest_version}`
              : ""
          }`}
          icon={Sparkles}
          actionLabel={
            version.data?.update_available ? "View releases" : undefined
          }
          onAction={() => navigate("/appliance?tab=releases")}
        />
      </section>

      {finish.isError && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{formatApiError(finish.error)}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-md text-xs text-muted-foreground">
          Hitting <strong>Finish setup</strong> dismisses this wizard. Re-open
          from the Appliance management hub at any time —{" "}
          <code className="rounded bg-muted px-1">/appliance/setup</code>.
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => navigate("/dashboard")}
            className="rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-accent"
          >
            Skip for now
          </button>
          <button
            type="button"
            onClick={() => finish.mutate()}
            disabled={finish.isPending || setup.data?.complete}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            {...applianceGate}
          >
            <CheckCircle2 className="h-3.5 w-3.5" />
            {setup.data?.complete
              ? "Already finished"
              : finish.isPending
                ? "Saving…"
                : "Finish setup"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Step({
  done,
  title,
  subtitle,
  icon: Icon,
  actionLabel,
  onAction,
}: {
  done: boolean;
  title: string;
  subtitle: string;
  icon: typeof CheckCircle2;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <div className="flex items-start gap-3 border-b px-4 py-3 last:border-b-0">
      {done ? (
        <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-500" />
      ) : (
        <Circle className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground/50" />
      )}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5 text-sm font-medium">
          <Icon className="h-3.5 w-3.5 text-muted-foreground" />
          {title}
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>
      </div>
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="shrink-0 rounded-md border bg-background px-2 py-1 text-xs hover:bg-accent"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
