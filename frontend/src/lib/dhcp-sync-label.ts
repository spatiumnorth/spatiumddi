/** #2448 — what a DHCP server's header says about its last sync.
 *
 *  `last_sync_at` is written only by the lease pull and the cloud push, so
 *  an agent-managed Kea server never sets it. Its signal is the agent's own
 *  apply report: an "ok" `config_apply_status` with a `config_apply_at`.
 *  "Never synced" is kept for a server with neither.
 *
 *  #3046 — when a server carries both, the more recent one wins. A server
 *  whose driver was changed from an agentless one keeps its old
 *  `last_sync_at` forever (nothing clears it, and the pull skips agent
 *  drivers), while the agent re-stamps `config_apply_at` on every report;
 *  "`last_sync_at` first" would show that frozen time over a live one.
 *  A non-"ok" apply report is never a sync: the ConfigApplyBanner above the
 *  inspector's cards reports it. */
export interface SyncLabelInput {
  last_sync_at: string | null;
  config_apply_status: string | null;
  config_apply_at: string | null;
}

type SyncSignal = { kind: "sync" | "applied"; at: string } | null;

function latestSignal(s: SyncLabelInput): SyncSignal {
  const applied =
    s.config_apply_status === "ok" && s.config_apply_at
      ? s.config_apply_at
      : null;
  if (s.last_sync_at && applied)
    return Date.parse(applied) > Date.parse(s.last_sync_at)
      ? { kind: "applied", at: applied }
      : { kind: "sync", at: s.last_sync_at };
  if (s.last_sync_at) return { kind: "sync", at: s.last_sync_at };
  if (applied) return { kind: "applied", at: applied };
  return null;
}

export function syncLabel(s: SyncLabelInput, fmt = fmtDate): string {
  const sig = latestSignal(s);
  if (sig?.kind === "sync") return `Last sync ${fmt(sig.at)}`;
  if (sig?.kind === "applied") return `Config applied ${fmt(sig.at)}`;
  return "Never synced";
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

/** #3046 — the DHCP and DNS server inspectors' "Last sync" card.
 *
 *  Same rule as `syncLabel`, split into a card label and a timestamp. An
 *  apply report is not a sync, so it is labelled "Config applied" rather
 *  than shown under "Last sync". `at` is null for a server with neither,
 *  which the caller renders as its placeholder (or, where nothing can ever
 *  record a sync, as the reason). */
export function syncCard(s: SyncLabelInput): {
  label: string;
  at: string | null;
} {
  const sig = latestSignal(s);
  if (sig?.kind === "applied") return { label: "Config applied", at: sig.at };
  return { label: "Last sync", at: sig?.at ?? null };
}
