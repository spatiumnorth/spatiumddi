import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Box,
  CheckCircle2,
  ChevronRight,
  Download,
  ExternalLink,
  RefreshCw,
} from "lucide-react";

import {
  applianceReleasesApi,
  type ApplianceRelease,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { helmChartVersion } from "@/lib/versions";

// Number of most-recent releases rendered as full cards. Anything older
// collapses behind a "Show N older releases" disclosure so the tab
// stays scannable even after dozens of releases have shipped.
const FULL_CARDS = 3;

/**
 * Phase 4c — Release listing (read-only).
 *
 * Lists recent GitHub releases (top 25, 60 s cached server-side) and
 * shows the currently-installed version.
 *
 * #294 — there is no one-click "Apply" here anymore. It used to write a
 * trigger file watched by a host-side ``spatiumddi-update.path`` unit
 * running ``docker-compose pull && up -d`` — a pre-#183 mechanism that
 * does nothing on the k3s appliance (no compose stack, no such unit).
 * OS upgrades on the appliance go through the A/B slot image flow on the
 * **Fleet** tab; docker / k8s control planes run the manual
 * ``docker compose`` / ``helm upgrade`` command shown in the per-release
 * "Manual…" modal. So this tab is informational: "what's available" +
 * "what you're running".
 */
export function ReleasesTab({
  applianceMode = false,
}: {
  applianceMode?: boolean;
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["appliance", "releases"],
    queryFn: applianceReleasesApi.list,
    refetchInterval: 60_000,
  });

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold">
            <Box className="h-4 w-4 text-muted-foreground" />
            SpatiumDDI Releases
          </h2>
          <p className="mt-1 text-xs text-muted-foreground">
            Published releases from{" "}
            <code className="rounded bg-muted px-1">ghcr.io/spatiumnorth</code>{" "}
            and the version this control plane is running.
          </p>
        </div>
        <div className="shrink-0 rounded-md border bg-muted px-2 py-1.5 text-xs">
          Running:{" "}
          <span className="ml-1 font-mono text-foreground">
            {data?.installed_version ?? "—"}
          </span>
        </div>
      </div>

      {/* #404 — Releases now live alongside the Rolling Upgrade orchestrator
          in the Fleet sidebar, so the old "go to Fleet for OS upgrades"
          banner is gone; on the appliance this catalog stays read-only
          (upgrades are driven by the orchestrator above / OS Versions). */}
      {error && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load releases: {formatApiError(error)}
        </div>
      )}

      {isLoading ? (
        <div className="py-12 text-center text-sm text-muted-foreground">
          Loading…
        </div>
      ) : !data || data.releases.length === 0 ? (
        <div className="rounded-lg border border-dashed bg-muted/30 px-6 py-12 text-center text-sm text-muted-foreground">
          <RefreshCw className="mx-auto h-6 w-6 text-muted-foreground/50" />
          <p className="mt-3 font-medium">No releases found</p>
          <p className="mt-1 text-xs">
            GitHub API may be rate-limiting unauthenticated requests, or no
            releases have been published for this repo yet. Refresh in a minute.
          </p>
        </div>
      ) : (
        <ReleasesList releases={data.releases} applianceMode={applianceMode} />
      )}
    </div>
  );
}

function ReleasesList({
  releases,
  applianceMode,
}: {
  releases: ApplianceRelease[];
  applianceMode: boolean;
}) {
  // Always render the top ``FULL_CARDS`` as full-detail cards. The
  // remainder collapses behind a disclosure to keep the page scannable
  // once the project has shipped dozens of releases. Releases are
  // returned newest-first from the backend, so a simple slice is fine.
  const recent = releases.slice(0, FULL_CARDS);
  const older = releases.slice(FULL_CARDS);

  // If the operator's currently-installed version sits inside the
  // older bucket (they're behind on upgrades), flag it on the disclosure
  // so they can find their row without expanding-and-scanning.
  const installedInOlder = older.find((r) => r.is_installed);

  return (
    <div className="space-y-3">
      {recent.map((rel) => (
        <ReleaseCard
          key={rel.tag}
          release={rel}
          applianceMode={applianceMode}
        />
      ))}
      {older.length > 0 && (
        <details className="group rounded-lg border bg-card">
          <summary className="flex cursor-pointer items-center gap-2 px-4 py-2.5 text-sm hover:bg-muted/50">
            <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform group-open:rotate-90" />
            <span className="font-medium">
              Show {older.length} older release{older.length === 1 ? "" : "s"}
            </span>
            {installedInOlder && (
              <span className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-primary">
                <CheckCircle2 className="h-3 w-3" />
                installed: {installedInOlder.tag}
              </span>
            )}
          </summary>
          <div className="divide-y border-t">
            {older.map((rel) => (
              <CompactReleaseRow
                key={rel.tag}
                release={rel}
                applianceMode={applianceMode}
              />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

// One-line compact row used inside the "older releases" disclosure.
// Notes are collapsed by default behind a click-to-expand — operators
// scanning for a specific tag shouldn't have to scroll past every
// release's notes preview.
function CompactReleaseRow({
  release,
  applianceMode,
}: {
  release: ApplianceRelease;
  applianceMode: boolean;
}) {
  const [manualOpen, setManualOpen] = useState(false);
  return (
    <div className={release.is_installed ? "bg-primary/5" : ""}>
      <div className="flex items-center gap-2 px-4 py-2">
        <span className="min-w-0 flex-1 font-mono text-xs">{release.tag}</span>
        {release.is_installed && (
          <span className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-primary">
            <CheckCircle2 className="h-3 w-3" />
            Installed
          </span>
        )}
        {release.is_prerelease && (
          <span className="rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-700 dark:text-amber-400">
            Pre
          </span>
        )}
        <span className="shrink-0 text-xs text-muted-foreground">
          {fmtDate(release.published_at)}
        </span>
        <a
          href={release.html_url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex shrink-0 items-center text-muted-foreground hover:text-foreground"
          title="Open on GitHub"
        >
          <ExternalLink className="h-3 w-3" />
        </a>
        {/* No per-release apply on the appliance (OS upgrades live on the
            Fleet tab). docker / k8s control planes get the manual command. */}
        {!applianceMode && !release.is_installed && (
          <button
            type="button"
            onClick={() => setManualOpen(true)}
            className="inline-flex shrink-0 items-center gap-1 rounded-md border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent"
            title="Show the operator-run upgrade command for docker / k8s"
          >
            <Download className="h-3 w-3" />
            Manual…
          </button>
        )}
      </div>
      {release.body && (
        <details className="px-4 pb-2">
          <summary className="cursor-pointer text-[11px] text-muted-foreground hover:text-foreground">
            Release notes
          </summary>
          <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded border bg-muted/30 px-2 py-1.5 text-[11px] leading-tight">
            {release.body}
          </pre>
        </details>
      )}
      {manualOpen && (
        <ManualApplyModal
          tag={release.tag}
          onClose={() => setManualOpen(false)}
        />
      )}
    </div>
  );
}

function ReleaseCard({
  release,
  applianceMode,
}: {
  release: ApplianceRelease;
  applianceMode: boolean;
}) {
  const [manualOpen, setManualOpen] = useState(false);
  return (
    <div
      className={`rounded-lg border bg-card p-4 shadow-sm ${
        release.is_installed ? "ring-1 ring-primary/40" : ""
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold">
              <span className="font-mono">{release.tag}</span>
            </h3>
            {release.is_installed && (
              <span className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-primary">
                <CheckCircle2 className="h-3 w-3" />
                Installed
              </span>
            )}
            {release.is_prerelease && (
              <span className="rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-700 dark:text-amber-400">
                Pre-release
              </span>
            )}
            <span className="text-xs text-muted-foreground">
              {fmtDate(release.published_at)}
            </span>
            <a
              href={release.html_url}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-auto inline-flex shrink-0 items-center gap-0.5 text-xs text-muted-foreground hover:text-foreground"
            >
              <ExternalLink className="h-3 w-3" />
              GitHub
            </a>
          </div>
          {release.body && (
            <details className="mt-2">
              <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
                Release notes
              </summary>
              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded border bg-muted/30 px-2 py-1.5 text-[11px] leading-tight">
                {release.body}
              </pre>
            </details>
          )}
        </div>
        <div className="shrink-0">
          {release.is_installed ? (
            <span className="text-xs text-muted-foreground">Active</span>
          ) : !applianceMode ? (
            <button
              type="button"
              onClick={() => setManualOpen(true)}
              className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent"
              title="Show the operator-run upgrade command for docker / k8s"
            >
              <Download className="h-3 w-3" />
              Manual…
            </button>
          ) : null}
        </div>
      </div>
      {manualOpen && (
        <ManualApplyModal
          tag={release.tag}
          onClose={() => setManualOpen(false)}
        />
      )}
    </div>
  );
}

// Shown on docker / k8s control planes (no host-side update mechanism,
// and no A/B slot flow either). The operator copies a command + runs it
// against the deployment they manage.
function ManualApplyModal({
  tag,
  onClose,
}: {
  tag: string;
  onClose: () => void;
}) {
  const dockerCmd = [
    "# On the control-plane host, in the directory holding docker-compose.yml:",
    `SPATIUMDDI_VERSION=${tag} docker compose pull && \\`,
    `SPATIUMDDI_VERSION=${tag} docker compose up -d`,
  ].join("\n");
  // --version is required, not optional (#1182): every CalVer chart is a
  // SemVer pre-release, and Helm's unversioned resolution skips those, so
  // without it Helm finds no chart at all.
  const chartVersion = helmChartVersion(tag);
  const k8sCmd = [
    "# On a workstation with kubectl + helm pointed at the cluster:",
    "helm upgrade spatiumddi \\",
    "  oci://ghcr.io/spatiumnorth/charts/spatiumddi \\",
    ...(chartVersion ? [`  --version ${chartVersion} \\`] : []),
    `  --set image.tag=${tag} \\`,
    "  --reuse-values",
  ].join("\n");
  return (
    <Modal title={`Manual upgrade — ${tag}`} onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          This control plane runs on docker / kubernetes — pick the deploy shape
          that matches your install, copy the command, and run it on the
          control-plane host.
        </p>
        <div>
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="text-xs font-medium">Docker compose</span>
            <button
              type="button"
              className="text-xs text-muted-foreground hover:text-foreground"
              onClick={() => {
                if (navigator.clipboard) {
                  void navigator.clipboard.writeText(dockerCmd);
                }
              }}
            >
              Copy
            </button>
          </div>
          <pre className="overflow-x-auto rounded-md border bg-muted/40 p-2 font-mono text-[11px] leading-tight">
            {dockerCmd}
          </pre>
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="text-xs font-medium">Kubernetes (helm)</span>
            <button
              type="button"
              className="text-xs text-muted-foreground hover:text-foreground"
              onClick={() => {
                if (navigator.clipboard) {
                  void navigator.clipboard.writeText(k8sCmd);
                }
              }}
            >
              Copy
            </button>
          </div>
          <pre className="overflow-x-auto rounded-md border bg-muted/40 p-2 font-mono text-[11px] leading-tight">
            {k8sCmd}
          </pre>
        </div>
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

function fmtDate(s: string): string {
  return new Date(s).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}
