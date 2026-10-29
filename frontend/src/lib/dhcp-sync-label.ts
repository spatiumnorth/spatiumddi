/** #2448 — what a DHCP server's header says about its last sync.
 *
 *  `last_sync_at` is written only by the lease pull and the cloud push, so
 *  an agent-managed Kea server never sets it. Its signal is the agent's own
 *  apply report: an "ok" `config_apply_status` with a `config_apply_at`.
 *  "Never synced" is kept for a server with neither. */
export interface SyncLabelInput {
  last_sync_at: string | null;
  config_apply_status: string | null;
  config_apply_at: string | null;
}

export function syncLabel(s: SyncLabelInput, fmt = fmtDate): string {
  if (s.last_sync_at) return `Last sync ${fmt(s.last_sync_at)}`;
  if (s.config_apply_status === "ok" && s.config_apply_at)
    return `Config applied ${fmt(s.config_apply_at)}`;
  return "Never synced";
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

/** #3046 — the server inspectors' "Last sync" card.
 *
 *  Same rule as `syncLabel`, split into a card label and a timestamp. An
 *  apply report is not a sync, so it is labelled "Config applied" rather
 *  than shown under "Last sync". `at` is null for a server with neither,
 *  which the caller renders as its placeholder. */
export function syncCard(s: SyncLabelInput): {
  label: string;
  at: string | null;
} {
  if (s.last_sync_at) return { label: "Last sync", at: s.last_sync_at };
  if (s.config_apply_status === "ok" && s.config_apply_at)
    return { label: "Config applied", at: s.config_apply_at };
  return { label: "Last sync", at: null };
}
