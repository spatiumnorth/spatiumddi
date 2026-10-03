import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Loader2,
  Radar,
  XCircle,
} from "lucide-react";
import { Modal } from "@/components/ui/modal";
import {
  dnsApi,
  formatApiError,
  type PropagationCheckResult,
  type PropagationResolverResult,
} from "@/lib/api";

/**
 * Multi-resolver propagation check — fires the same DNS query against
 * 4 public resolvers (Cloudflare / Google / Quad9 / OpenDNS) in parallel
 * and surfaces per-resolver answer + RTT. Useful right after a record
 * edit to confirm the change has propagated everywhere.
 *
 * The resolver list comes from the backend so the curated set stays
 * authoritative on the server side.
 */
export function PropagationCheckModal({
  fqdn,
  recordType,
  onClose,
}: {
  fqdn: string;
  recordType: string;
  onClose: () => void;
}) {
  const [activeType, setActiveType] = useState(recordType);

  const { data: resolvers = [] } = useQuery({
    queryKey: ["dns", "default-resolvers"],
    queryFn: () => dnsApi.defaultResolvers(),
    staleTime: 60 * 60 * 1000,
  });

  const checkMut = useMutation({
    mutationFn: () =>
      dnsApi.checkPropagation({ name: fqdn, record_type: activeType }),
  });

  // Auto-fire the first check on mount.
  useEffect(() => {
    checkMut.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Modal title={`Propagation check — ${fqdn}`} onClose={onClose} wide>
      <div className="space-y-4 text-sm">
        <div className="flex items-center gap-3">
          <label className="text-xs text-muted-foreground">Record type</label>
          <select
            value={activeType}
            onChange={(e) => setActiveType(e.target.value)}
            className="rounded border bg-background px-2 py-1 text-xs"
          >
            {[
              "A",
              "AAAA",
              "CNAME",
              "MX",
              "TXT",
              "NS",
              "SOA",
              "PTR",
              "SRV",
              "CAA",
              "TLSA",
            ].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <button
            type="button"
            disabled={checkMut.isPending}
            onClick={() => checkMut.mutate()}
            className="ml-auto inline-flex items-center gap-1 rounded border px-2 py-1 text-xs hover:bg-muted/50 disabled:opacity-50"
          >
            {checkMut.isPending ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <Radar className="h-3 w-3" />
            )}
            Re-check
          </button>
        </div>

        <ResultsTable
          result={checkMut.data}
          isLoading={checkMut.isPending}
          errorMessage={
            checkMut.isError ? formatApiError(checkMut.error) : undefined
          }
          resolvers={resolvers.map((r) => ({
            address: r.address,
            name: r.name,
          }))}
        />
      </div>
    </Modal>
  );
}

function ResultsTable({
  result,
  isLoading,
  errorMessage,
  resolvers,
}: {
  result: PropagationCheckResult | undefined;
  isLoading: boolean;
  errorMessage: string | undefined;
  resolvers: { address: string; name: string }[];
}) {
  // While the first request is in flight we render placeholder rows so
  // the operator sees what's about to be queried. A placeholder is not a
  // result: its status is never shown, so a check that failed (#1344)
  // leaves every resolver unanswered rather than "OK".
  const rows: PropagationResolverResult[] = result
    ? result.results
    : resolvers.map((r) => ({
        resolver: r.address,
        name: r.name,
        status: "ok",
        rtt_ms: null,
        answers: [],
        error: null,
      }));

  return (
    <div className="overflow-x-auto rounded border">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b bg-muted/30">
            <th className="px-2 py-1.5 text-left">Resolver</th>
            <th className="px-2 py-1.5 text-left">Status</th>
            <th className="px-2 py-1.5 text-left">RTT</th>
            <th className="px-2 py-1.5 text-left">Answer</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.resolver} className="border-b last:border-0">
              <td className="px-2 py-1.5">
                <div className="font-medium">{r.name ?? "Custom"}</div>
                <div className="font-mono text-[11px] text-muted-foreground">
                  {r.resolver}
                </div>
              </td>
              <td className="px-2 py-1.5">
                {result ? (
                  <StatusBadge status={r.status} />
                ) : isLoading ? (
                  <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </td>
              <td className="px-2 py-1.5 font-mono text-muted-foreground">
                {r.rtt_ms != null ? `${r.rtt_ms.toFixed(0)} ms` : "—"}
              </td>
              <td className="px-2 py-1.5">
                {r.answers.length > 0 ? (
                  <div className="space-y-0.5">
                    {r.answers.map((a, i) => (
                      <div key={i} className="font-mono">
                        {a}
                      </div>
                    ))}
                  </div>
                ) : r.error ? (
                  <span className="text-destructive/80">{r.error}</span>
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {errorMessage && (
        <div className="border-t bg-destructive/5 px-2 py-1.5 text-xs text-destructive">
          The check failed: {errorMessage}
        </div>
      )}
      {result && (
        <div className="border-t bg-muted/20 px-2 py-1.5 text-[11px] text-muted-foreground">
          Queried at {new Date(result.queried_at_ms).toLocaleString()} ·{" "}
          {result.results.filter((r) => r.status === "ok").length} of{" "}
          {result.results.length} resolvers returned an answer
        </div>
      )}
    </div>
  );
}

function StatusBadge({
  status,
}: {
  status: "ok" | "nxdomain" | "timeout" | "error";
}) {
  if (status === "ok") {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-emerald-700 dark:text-emerald-400">
        <CheckCircle2 className="h-3 w-3" />
        OK
      </span>
    );
  }
  if (status === "nxdomain") {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-amber-700 dark:text-amber-400">
        <AlertCircle className="h-3 w-3" />
        NXDOMAIN
      </span>
    );
  }
  if (status === "timeout") {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-zinc-500/15 px-1.5 py-0.5 text-zinc-700 dark:text-zinc-300">
        <Clock className="h-3 w-3" />
        Timeout
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded bg-destructive/15 px-1.5 py-0.5 text-destructive">
      <XCircle className="h-3 w-3" />
      Error
    </span>
  );
}
