import { useQuery } from "@tanstack/react-query";

import { applianceApprovalApi, type ApplianceRow } from "@/lib/api";

/**
 * #4801 — what each appliance's chrony last reported on its heartbeat
 * (`ntp_sync_state`). An unsynchronized node is a normal state on an isolated
 * network, so it reads as a quiet note, not an error.
 */
function ntpStateLabel(state: string | null): {
  text: string;
  tone: "ok" | "calm" | "muted";
} {
  if (state === "synchronized") return { text: "Synchronized", tone: "ok" };
  if (state === "unsynchronized")
    return {
      text: "No time source reachable — the clock is free-running.",
      tone: "calm",
    };
  return { text: "Not reported yet", tone: "muted" };
}

export function NtpSyncState() {
  const { data } = useQuery({
    queryKey: ["appliance-approvals", "ntp-sync"],
    queryFn: applianceApprovalApi.list,
    refetchInterval: 30_000,
    retry: false,
  });
  const rows: ApplianceRow[] = (data ?? []).filter(
    (r) => r.state === "approved",
  );
  if (rows.length === 0) return null;
  return (
    <div className="mb-4 rounded-md border p-3" data-testid="ntp-sync-state">
      <h3 className="text-sm font-semibold">Sync state</h3>
      <ul className="mt-2 space-y-1 text-xs">
        {rows.map((r) => {
          const s = ntpStateLabel(r.ntp_sync_state);
          return (
            <li key={r.id} className="flex flex-wrap gap-x-2">
              <span className="font-mono">{r.hostname}</span>
              <span
                data-tone={s.tone}
                className={
                  s.tone === "ok"
                    ? "text-emerald-600"
                    : s.tone === "calm"
                      ? "text-amber-600"
                      : "text-muted-foreground"
                }
              >
                {s.text}
              </span>
            </li>
          );
        })}
      </ul>
      {rows.some((r) => r.ntp_sync_state === "unsynchronized") && (
        <p className="mt-2 text-xs text-muted-foreground">
          On an isolated network this is expected. Point chrony at an internal
          time source below, or leave it; nothing else depends on it.
        </p>
      )}
    </div>
  );
}
