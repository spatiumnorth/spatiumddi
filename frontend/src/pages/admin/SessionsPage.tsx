import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { LogOut, Monitor, RefreshCcw } from "lucide-react";
import { authApi, sessionsApi, type UserSessionRow } from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";

const headerCls =
  "flex shrink-0 items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50";

function relativeAge(iso: string | null): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return "in the future";
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec} s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr} h ago`;
  const day = Math.floor(hr / 24);
  return `${day} d ago`;
}

function shortenUA(ua: string | null): string {
  if (!ua) return "unknown";
  // Keep the first browser identifier without the long version string —
  // the operator wants "Chrome on macOS" not the full Mozilla / WebKit
  // soup. Falls back to the first 60 chars when no known token matches.
  const lower = ua.toLowerCase();
  let kind = "browser";
  if (lower.includes("firefox")) kind = "Firefox";
  else if (lower.includes("edg/")) kind = "Edge";
  else if (lower.includes("chrome")) kind = "Chrome";
  else if (lower.includes("safari")) kind = "Safari";
  else if (lower.includes("curl")) kind = "curl";
  else if (lower.includes("python")) kind = "Python";
  let os = "";
  if (lower.includes("windows")) os = "Windows";
  else if (lower.includes("mac os") || lower.includes("macintosh"))
    os = "macOS";
  else if (lower.includes("iphone") || lower.includes("ios")) os = "iOS";
  else if (lower.includes("android")) os = "Android";
  else if (lower.includes("linux")) os = "Linux";
  return os ? `${kind} on ${os}` : kind;
}

export function SessionsPage() {
  const { data: me } = useQuery({
    queryKey: ["auth-me"],
    queryFn: () => authApi.me(),
    staleTime: 60_000,
  });
  const isSuperadmin = !!me?.is_superadmin;
  const [scope, setScope] = useState<"mine" | "all">(
    isSuperadmin ? "all" : "mine",
  );
  const [includeExpired, setIncludeExpired] = useState(false);
  const qc = useQueryClient();

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["sessions", scope, includeExpired],
    queryFn: () =>
      scope === "all"
        ? sessionsApi.listAll(includeExpired)
        : sessionsApi.listMine(includeExpired),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => sessionsApi.revoke(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
              <Monitor className="h-5 w-5" /> Active Sessions
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Every live JWT is backed by a session row. Revoke a session and
              the in-flight access token using its <code>jti</code> starts
              401-ing on the next request.
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {isSuperadmin && (
              <div className="flex rounded-md border bg-background p-0.5 text-xs">
                <button
                  onClick={() => setScope("all")}
                  className={cn(
                    "rounded px-2 py-1",
                    scope === "all"
                      ? "bg-muted font-medium"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  All users
                </button>
                <button
                  onClick={() => setScope("mine")}
                  className={cn(
                    "rounded px-2 py-1",
                    scope === "mine"
                      ? "bg-muted font-medium"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  My sessions
                </button>
              </div>
            )}
            <label className="flex shrink-0 items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs">
              <input
                type="checkbox"
                checked={includeExpired}
                onChange={(e) => setIncludeExpired(e.target.checked)}
              />
              Include expired / revoked
            </label>
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className={headerCls}
            >
              <RefreshCcw
                className={cn("h-3.5 w-3.5", isFetching && "animate-spin")}
              />
              Refresh
            </button>
          </div>
        </div>

        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full min-w-[840px] text-sm">
            <thead>
              <tr className="border-b bg-muted/50 text-xs">
                <th className="px-4 py-3 text-left font-medium">User</th>
                <th className="px-4 py-3 text-left font-medium">Source</th>
                <th className="px-4 py-3 text-left font-medium">IP</th>
                <th className="px-4 py-3 text-left font-medium">Client</th>
                <th className="px-4 py-3 text-left font-medium">Started</th>
                <th className="px-4 py-3 text-left font-medium">Last seen</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {isLoading && (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-6 text-center text-muted-foreground"
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!isLoading && (data?.length ?? 0) === 0 && (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-6 text-center text-muted-foreground"
                  >
                    No sessions match the current filter.
                  </td>
                </tr>
              )}
              {data?.map((s: UserSessionRow) => {
                const expired = new Date(s.expires_at).getTime() <= Date.now();
                return (
                  <tr
                    key={s.id}
                    className="border-b last:border-0 hover:bg-muted/20"
                  >
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap items-center gap-1.5 font-medium">
                        {s.username}
                        {s.is_current && (
                          <span className="rounded-full bg-sky-100 px-2 py-0.5 text-xs font-normal text-sky-800 dark:bg-sky-900/30 dark:text-sky-300">
                            this session
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {s.display_name}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="rounded-full bg-muted px-2 py-0.5 text-xs">
                        {s.auth_source}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {s.source_ip ?? "—"}
                    </td>
                    <td
                      className="px-4 py-3 text-xs text-muted-foreground"
                      title={s.user_agent ?? ""}
                    >
                      {shortenUA(s.user_agent)}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {relativeAge(s.created_at)}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {relativeAge(s.last_seen_at)}
                    </td>
                    <td className="px-4 py-3">
                      {s.revoked ? (
                        <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                          revoked
                        </span>
                      ) : expired ? (
                        <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                          expired
                        </span>
                      ) : (
                        <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400">
                          active
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {!s.revoked && !expired && (
                        <button
                          onClick={() => revoke.mutate(s.id)}
                          disabled={revoke.isPending}
                          className="inline-flex items-center gap-1 rounded p-1 text-amber-600 hover:text-amber-700 disabled:opacity-50 dark:text-amber-400"
                          title="Revoke (force-logout this session)"
                        >
                          <LogOut className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
