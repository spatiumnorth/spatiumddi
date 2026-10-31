import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Info,
  MinusCircle,
  PlusCircle,
  RefreshCw,
  ShieldQuestion,
} from "lucide-react";
import {
  dnsApi,
  type DNSServerGroup,
  type DNSZone,
  type ZoneDriftRecord,
  type ZoneDriftServer,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  RECORD_TYPE_BADGE,
  RECORD_TYPE_BADGE_FALLBACK,
} from "./recordTypeBadge";

/**
 * Config-drift view (#61) — what each server is *actually serving*
 * versus what SpatiumDDI has in the database.
 *
 * Distinct from the ZoneSyncPill in the zone header, which compares SOA
 * serials only: a host can sit on exactly the right serial and still serve
 * the wrong records if someone edited the zone file by hand. This view
 * AXFRs / driver-pulls the live zone from every server in the group and
 * diffs it record by record.
 *
 * Strictly read-only. The backend never applies anything from this report,
 * and neither does this view — an operator who wants the server to match
 * the DB uses the existing Sync path. A changed value shows up as a
 * missing+extra pair, because the diff key includes the value (matching
 * the additive-sync semantics).
 */

// A zone with thousands of records diffed against an empty server produces
// one row per record. Render a slice and let the operator opt into the rest
// rather than locking the tab up laying out 5,000 <tr>s nobody scrolls to.
const ROW_CAP = 50;

// A server whose zone was actually read, so the record diff means something.
// An unknown status is treated as NOT transferred rather than as ok (#3198).
function isTransferred(server: ZoneDriftServer) {
  return (
    server.status === "ok" ||
    server.status === "syncing" ||
    server.status === "behind" ||
    server.status === "drift"
  );
}

function statusChip(server: ZoneDriftServer) {
  if (server.status === "unsupported")
    return {
      cls: "bg-muted text-muted-foreground",
      icon: ShieldQuestion,
      label: "Not supported",
    };
  if (server.status === "error")
    return {
      cls: "bg-rose-500/15 text-rose-600 dark:text-rose-400",
      icon: AlertTriangle,
      label: "Pull failed",
    };
  if (server.status === "behind")
    return {
      cls: "bg-rose-500/15 text-rose-600 dark:text-rose-400",
      icon: AlertTriangle,
      label: "Behind",
    };
  if (server.status === "syncing")
    return {
      cls: "bg-sky-500/15 text-sky-600 dark:text-sky-400",
      icon: RefreshCw,
      label: "Syncing",
    };
  if (server.status === "drift" || server.drift_count > 0)
    return {
      cls: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
      icon: AlertTriangle,
      label: `${server.drift_count} drifted`,
    };
  if (server.status !== "ok")
    return {
      cls: "bg-muted text-muted-foreground",
      icon: ShieldQuestion,
      label: "Unknown",
    };
  return {
    cls: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
    icon: CheckCircle2,
    label: "In sync",
  };
}

function RecordTable({
  records,
  kind,
}: {
  records: ZoneDriftRecord[];
  kind: "extra" | "missing";
}) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? records : records.slice(0, ROW_CAP);
  const hidden = records.length - shown.length;

  return (
    <div>
      <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
        {kind === "extra" ? (
          <>
            <PlusCircle className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
            <span>Extra on server ({records.length})</span>
            <span className="font-normal text-muted-foreground">
              — served but not in SpatiumDDI, usually a manual edit on the host
            </span>
          </>
        ) : (
          <>
            <MinusCircle className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
            <span>Missing on server ({records.length})</span>
            <span className="font-normal text-muted-foreground">
              — in SpatiumDDI but not being served
            </span>
          </>
        )}
      </div>
      <div className="overflow-x-auto rounded border">
        <table className="w-full min-w-[32rem] text-xs">
          <thead className="bg-muted/50 text-muted-foreground">
            <tr>
              <th className="px-2 py-1 text-left font-medium">Name</th>
              <th className="px-2 py-1 text-left font-medium">Type</th>
              <th className="px-2 py-1 text-left font-medium">Value</th>
              <th className="px-2 py-1 text-right font-medium">TTL</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r, i) => (
              <tr
                // Records have no id — and a name+type+value triple can
                // legitimately repeat across TTLs — so the index is part of
                // the key. The list is read-only and never reordered.
                key={`${r.name}|${r.record_type}|${r.value}|${i}`}
                className="border-t"
              >
                <td className="px-2 py-1 font-mono">{r.name}</td>
                <td className="px-2 py-1">
                  <span
                    className={cn(
                      "rounded px-1.5 py-0.5 text-[10px] font-medium",
                      RECORD_TYPE_BADGE[r.record_type] ??
                        RECORD_TYPE_BADGE_FALLBACK,
                    )}
                  >
                    {r.record_type}
                  </span>
                </td>
                <td
                  className="max-w-md truncate px-2 py-1 font-mono"
                  title={r.value}
                >
                  {r.value}
                </td>
                <td className="px-2 py-1 text-right text-muted-foreground">
                  {r.ttl ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="mt-1.5 text-xs text-primary hover:underline"
        >
          Show {hidden.toLocaleString()} more
        </button>
      )}
    </div>
  );
}

function ServerCard({ server }: { server: ZoneDriftServer }) {
  const chip = statusChip(server);
  const ChipIcon = chip.icon;

  return (
    <div className="rounded-md border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-medium">
            {server.server_name}
          </span>
          <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            {server.driver}
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-2 text-xs">
          {isTransferred(server) && (
            <span className="text-muted-foreground">
              {server.in_sync.toLocaleString()} matching
            </span>
          )}
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-medium",
              chip.cls,
            )}
          >
            <ChipIcon className="h-3 w-3" />
            {chip.label}
          </span>
        </div>
      </div>

      <div className="px-4 py-3">
        {!isTransferred(server) ? (
          // `error` is `str(exc)` server-side, and some exceptions stringify
          // to "" — so test for a non-blank string rather than just null,
          // otherwise the card renders "Pull failed" over an empty body.
          <p className="text-xs text-muted-foreground">
            {server.error?.trim() ||
              (server.status === "unsupported"
                ? "This driver can't pull live records, so drift can't be computed for it."
                : "The zone could not be pulled from this server. Check that it's reachable and that AXFR from the control plane is permitted.")}
          </p>
        ) : server.status === "ok" && server.drift_count === 0 ? (
          <p className="text-xs text-muted-foreground">
            Every record in SpatiumDDI is being served, nothing extra is present
            on the host, and the server is at the zone's serial.
          </p>
        ) : (
          <div className="space-y-4">
            {server.status === "behind" && (
              <p className="text-xs text-rose-600 dark:text-rose-400">
                The zone transferred, but this server is not serving it as saved
                {server.reason ? `: ${server.reason}` : ""}. It is behind the
                database, not merely different — check its config apply status.
              </p>
            )}
            {server.status === "syncing" && (
              <p className="text-xs text-sky-600 dark:text-sky-400">
                This server is still applying a recent change
                {server.reason ? `: ${server.reason}` : ""}.
              </p>
            )}
            {server.status === "drift" && (
              <p className="text-xs text-amber-600 dark:text-amber-400">
                {server.reason
                  ? `The server is not behind, but the records differ: ${server.reason}.`
                  : "The server is not behind, but the host serves records SpatiumDDI does not hold — typically a manual change on the host."}
              </p>
            )}
            {server.extra_on_server.length > 0 && (
              <RecordTable records={server.extra_on_server} kind="extra" />
            )}
            {server.missing_on_server.length > 0 && (
              <RecordTable records={server.missing_on_server} kind="missing" />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export function DriftView({
  group,
  zone,
}: {
  group: DNSServerGroup;
  zone: DNSZone;
}) {
  // Deliberately NOT auto-refetched: one call fans out an AXFR to every
  // server in the group, so it runs when the operator opens this tab and
  // then only when they ask for it again. `retry: false` for the same
  // reason — silently replaying a slow multi-host pull three times on a
  // timeout is worse than showing the error.
  const { data, isFetching, error, refetch } = useQuery({
    queryKey: ["dns-zone-drift", group.id, zone.id],
    queryFn: () => dnsApi.getZoneDrift(group.id, zone.id),
    refetchOnWindowFocus: false,
    retry: false,
    staleTime: 30_000,
  });

  const servers = data?.servers ?? [];
  const comparable = servers.filter(isTransferred);
  // A server still applying a fresh change has not drifted.
  const drifted = comparable.filter(
    (s) => s.status !== "ok" && s.status !== "syncing",
  );
  const syncing = comparable.filter((s) => s.status === "syncing");
  const failed = servers.filter((s) => s.status === "error");

  return (
    <div className="flex-1 overflow-auto p-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm">
            Compares what each server is actually serving against the{" "}
            {(data?.db_record_count ?? 0).toLocaleString()} record
            {data?.db_record_count === 1 ? "" : "s"} SpatiumDDI holds for this
            zone.
          </p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Read-only — nothing here is applied. Use Sync to push the database
            state to a server that has drifted.
          </p>
        </div>
        <button
          type="button"
          onClick={() => refetch()}
          disabled={isFetching}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
        >
          <RefreshCw
            className={cn("h-3.5 w-3.5", isFetching && "animate-spin")}
          />
          Refresh
        </button>
      </div>

      {isFetching && !data ? (
        <p className="text-sm text-muted-foreground">
          Pulling the live zone from every server in the group…
        </p>
      ) : error ? (
        <p className="text-sm text-destructive">
          Could not build the drift report:{" "}
          {error instanceof Error ? error.message : String(error)}
        </p>
      ) : servers.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          This server group has no servers, so there's nothing to compare
          against.
        </p>
      ) : (
        <>
          {(data?.warnings ?? []).map((w) => (
            <div
              key={w}
              className="mb-3 flex items-start gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300"
            >
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{w}</span>
            </div>
          ))}
          <div className="mb-4 flex flex-wrap items-center gap-3 text-xs">
            {drifted.length > 0 ? (
              <span className="inline-flex items-center gap-1.5 rounded bg-amber-500/15 px-2 py-1 font-medium text-amber-600 dark:text-amber-400">
                <AlertTriangle className="h-3.5 w-3.5" />
                {drifted.length} of {comparable.length} comparable server
                {comparable.length === 1 ? "" : "s"} drifted
              </span>
            ) : comparable.length > 0 && syncing.length === 0 ? (
              <span className="inline-flex items-center gap-1.5 rounded bg-emerald-500/15 px-2 py-1 font-medium text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                All {comparable.length} comparable server
                {comparable.length === 1 ? "" : "s"} match the database
              </span>
            ) : null}
            {syncing.length > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded bg-sky-500/15 px-2 py-1 font-medium text-sky-600 dark:text-sky-400">
                <RefreshCw className="h-3.5 w-3.5" />
                {syncing.length} server{syncing.length === 1 ? "" : "s"} still
                applying a recent change
              </span>
            )}
            {failed.length > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded bg-rose-500/15 px-2 py-1 font-medium text-rose-600 dark:text-rose-400">
                <AlertTriangle className="h-3.5 w-3.5" />
                {failed.length} server{failed.length === 1 ? "" : "s"} could not
                be pulled
              </span>
            )}
          </div>
          <div className="space-y-3">
            {servers.map((s) => (
              <ServerCard key={s.server_id} server={s} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
