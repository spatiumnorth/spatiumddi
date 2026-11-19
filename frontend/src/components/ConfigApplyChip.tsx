import type { ConfigApplyFields, ConfigApplyStatus } from "@/lib/api";
import {
  isPartialApply,
  PARTIAL_APPLY_EXPLAIN,
  PARTIAL_APPLY_LABEL,
  partialApplyDetail,
} from "@/lib/configApply";

/**
 * Chip surfacing an agent's last config-apply verdict (#882).
 *
 * This exists because every other signal on a server row lies in exactly one
 * case. A DNS or DHCP agent that rejects a config reverts to its
 * last-known-good and keeps serving, so `status` reads `active`, the health
 * check passes, `last_seen_at` is seconds old — and the zone or scope the
 * operator saved is not live anywhere. The chip is the only place that
 * divergence is visible.
 *
 * Renders nothing on `ok` and nothing on `null`. `null` means the agent has
 * never reported — a pre-#882 agent, or an agentless driver with no apply
 * loop — and inventing a green "converged" badge for a server we have heard
 * nothing from would be the same false reassurance the chip is here to fix.
 */

const LABEL: Record<ConfigApplyStatus, string> = {
  ok: "Config applied",
  reverted: "Config reverted",
  revert_failed: "Rollback failed",
  no_previous: "Config not applied",
};

const EXPLAIN: Record<ConfigApplyStatus, string> = {
  ok: "Running the saved configuration.",
  reverted:
    "This agent could not apply the saved configuration and rolled back to the last one that worked. It is healthy and answering — but NOT with what is saved here.",
  revert_failed:
    "This agent could not apply the saved configuration AND could not roll back to the previous one. Its running state is unknown.",
  no_previous:
    "This agent could not apply the saved configuration and had no previously-working configuration to fall back to, so the service may not be running at all.",
};

// reverted is amber, not red: the daemon is up and serving. The other two are
// rose because the service may be down or in an unknown state.
const TONE: Record<ConfigApplyStatus, string> = {
  ok: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  reverted: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  revert_failed: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
  no_previous: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
};

export function ConfigApplyChip({
  server,
  className = "",
}: {
  server: Partial<ConfigApplyFields>;
  className?: string;
}) {
  const status = server.config_apply_status;
  if (!status || status === "ok") return null;
  // A partial apply reports `reverted`, but nothing rolled back (#1280).
  const partial = isPartialApply(status, server.config_apply_error);

  const when = server.config_apply_at
    ? new Date(server.config_apply_at).toLocaleString()
    : null;
  const title = [
    partial ? PARTIAL_APPLY_EXPLAIN : EXPLAIN[status],
    server.config_apply_error
      ? `\n\nAgent reported: ${partial ? partialApplyDetail(server.config_apply_error) : server.config_apply_error}`
      : "",
    server.config_failed_etag && !partial
      ? `\n\nRejected config: ${server.config_failed_etag}`
      : "",
    when ? `\n\nReported: ${when}` : "",
  ].join("");

  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${TONE[status]} ${className}`}
      title={title}
    >
      {partial ? PARTIAL_APPLY_LABEL : LABEL[status]}
    </span>
  );
}

/**
 * Full-width version for a server-detail view, where there is room for the
 * daemon's own error text.
 *
 * The chip's tooltip is fine for a list row but a tooltip is a poor place to
 * put a multi-line `named-checkconf` failure — which is the one piece of
 * information that actually tells the operator what to fix.
 */
export function ConfigApplyBanner({
  server,
}: {
  server: Partial<ConfigApplyFields>;
}) {
  const status = server.config_apply_status;
  if (!status || status === "ok") return null;
  const partial = isPartialApply(status, server.config_apply_error);

  const tone =
    status === "reverted"
      ? "border-amber-600/40 bg-amber-500/10 text-amber-800 dark:text-amber-300"
      : "border-rose-600/40 bg-rose-500/10 text-rose-800 dark:text-rose-300";

  return (
    <div className={`rounded border px-3 py-2 text-xs ${tone}`}>
      <div className="font-medium">
        {partial ? PARTIAL_APPLY_LABEL : LABEL[status]}
      </div>
      <p className="mt-0.5 opacity-90">
        {partial ? PARTIAL_APPLY_EXPLAIN : EXPLAIN[status]}
      </p>
      {server.config_apply_error && (
        <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-black/5 p-2 font-mono text-[11px] dark:bg-white/5">
          {partial
            ? partialApplyDetail(server.config_apply_error)
            : server.config_apply_error}
        </pre>
      )}
      <div className="mt-1.5 flex flex-wrap gap-x-3 opacity-75">
        {server.config_failed_etag && !partial && (
          <span className="font-mono break-all">
            rejected: {server.config_failed_etag}
          </span>
        )}
        {server.config_apply_at && (
          <span>
            reported {new Date(server.config_apply_at).toLocaleString()}
          </span>
        )}
      </div>
    </div>
  );
}
