import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";
import {
  webExposureApi,
  type WebExposureVerdict,
  type WebExposureVerdictName,
} from "@/lib/api";

/**
 * Reachability card on the Security dashboard tab, and the evidence table the
 * Settings → Reachability section reuses (#3651).
 *
 * A verdict is shown WITH its evidence, never as a bare "you are exposed":
 * which outside networks, how many requests, first / last seen, which
 * endpoints. The word is "exposed" (reachable and probed), not "breached".
 * Counts for everyone who can see the tab; the per-network rows for callers
 * who may read the audit log; exact addresses for superadmins only.
 */

const LABEL: Record<WebExposureVerdictName, string> = {
  exposed: "Exposed",
  reached_from_outside: "Reached from outside",
  not_observed: "Not observed",
  unknown: "Unknown",
};

const TONE: Record<WebExposureVerdictName, string> = {
  exposed: "text-rose-600 dark:text-rose-400",
  reached_from_outside: "text-amber-600 dark:text-amber-400",
  not_observed: "text-emerald-600 dark:text-emerald-400",
  unknown: "text-muted-foreground",
};

function useVerdict() {
  // Gate the QUERY on the module (#942): the route 404s while it is off.
  const { enabled, ready } = useFeatureModules();
  const on = ready && enabled("security.web_exposure");
  const q = useQuery<WebExposureVerdict>({
    queryKey: ["web-exposure", "verdict"],
    queryFn: webExposureApi.verdict,
    refetchInterval: 60_000,
    retry: false,
    enabled: on,
  });
  return { on, ...q };
}

function Evidence({
  v,
  onTrust,
  trusting,
}: {
  v: WebExposureVerdict;
  onTrust?: (cidr: string) => void;
  trusting?: boolean;
}) {
  if (v.buckets.length === 0) return null;
  return (
    <div className="overflow-x-auto">
      <table className="mt-2 w-full text-left text-xs">
        <thead className="text-muted-foreground">
          <tr>
            <th className="py-1 pr-3 font-medium">Network</th>
            <th className="pr-3 font-medium">Requests</th>
            <th className="pr-3 font-medium">Login page</th>
            <th className="pr-3 font-medium">Other api</th>
            <th className="pr-3 font-medium">Failed sign-ins</th>
            <th className="pr-3 font-medium">First / last seen</th>
            <th className="pr-3 font-medium">Endpoints</th>
            {onTrust && <th />}
          </tr>
        </thead>
        <tbody>
          {v.buckets.map((b) => (
            <tr key={b.bucket} className="border-t align-top">
              <td className="py-1 pr-3 font-mono">
                {b.bucket}
                {b.addresses && (
                  <div className="text-muted-foreground">
                    {b.addresses.join(", ")}
                  </div>
                )}
              </td>
              <td className="pr-3">{b.requests}</td>
              <td className="pr-3">{b.login_page}</td>
              <td className="pr-3">{b.other_api}</td>
              <td className="pr-3">{b.login_failures}</td>
              <td className="pr-3">
                {b.first_seen ? new Date(b.first_seen).toLocaleString() : "—"}
                <br />
                {b.last_seen ? new Date(b.last_seen).toLocaleString() : "—"}
              </td>
              <td className="pr-3 font-mono">{b.endpoints.join(" ")}</td>
              {onTrust && (
                <td>
                  <button
                    type="button"
                    disabled={trusting}
                    className="text-primary hover:underline disabled:opacity-60"
                    onClick={() => onTrust(b.bucket)}
                    title="Add this network to the trusted list: it is yours"
                  >
                    This is ours
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The verdict, its numbers and the per-network table, for Settings. */
export function WebExposureEvidence({
  showTrust,
  onTrust,
  trusting,
}: {
  showTrust?: boolean;
  onTrust?: (cidr: string) => void;
  trusting?: boolean;
}) {
  const { data } = useVerdict();
  if (!data) return null;
  return (
    <div className="rounded-lg border p-4">
      <div className={`text-sm font-semibold ${TONE[data.verdict]}`}>
        {LABEL[data.verdict]}
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{data.summary}</p>
      <Evidence
        v={data}
        onTrust={showTrust ? onTrust : undefined}
        trusting={trusting}
      />
    </div>
  );
}

export function WebExposureCard() {
  const { on, data, error, isLoading } = useVerdict();
  const { isLoading: permsLoading } = usePermissions();
  const moduleOff =
    (error as { response?: { status?: number } } | null)?.response?.status ===
    404;
  if (!on || permsLoading || moduleOff || isLoading || !data) return null;

  return (
    <div className="rounded-lg border bg-card p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">
            Reachability ({data.window_hours} h)
          </h3>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Is this install reachable from outside your networks?
          </p>
        </div>
        <Link
          to="/settings"
          className="shrink-0 text-xs text-primary hover:underline"
        >
          Settings →
        </Link>
      </div>
      <div className={`mt-3 text-2xl font-semibold ${TONE[data.verdict]}`}>
        {LABEL[data.verdict]}
      </div>
      <p className="mt-1 break-words text-xs text-muted-foreground">
        {data.summary}
      </p>
      {data.attribution_warning && (
        <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">
          A proxy in front of the api forwards a client chain but not X-Real-IP,
          so clients may all look like the proxy: exposure cannot be judged
          until the proxy is trusted (docs/deployment/REVERSE_PROXY.md §2).
        </p>
      )}
      {data.verdict === "exposed" && (
        <p className="mt-2 break-words text-xs">
          <strong>Fix for this deployment:</strong> {data.fix_hint}
        </p>
      )}
      <Evidence v={{ ...data, buckets: data.buckets.slice(0, 5) }} />
    </div>
  );
}
