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
