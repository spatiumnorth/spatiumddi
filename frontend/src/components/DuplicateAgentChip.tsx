/**
 * Chip for a DNS (#2044) or DHCP (#3143) server that two live agent
 * processes are polling as.
 *
 * A cloned VM or a copied agent state directory keeps the same agent_id, so
 * two agents share one server row. The control plane serves only the most
 * recent one and refuses the other, which keeps answering from its last
 * cached configuration while heartbeating normally — nothing else on the row
 * looks wrong. Renders nothing unless an episode is current; the same reading
 * raises the `dns_agent_duplicate_instance` / `dhcp_agent_duplicate_instance`
 * alert.
 */
export function DuplicateAgentChip({
  server,
  kind = "DNS",
  className = "",
}: {
  server: {
    duplicate_agent?: boolean;
    duplicate_agent_since?: string | null;
    duplicate_agent_ip?: string | null;
  };
  /** Which agent family the server row belongs to, for the tooltip. */
  kind?: "DNS" | "DHCP";
  className?: string;
}) {
  if (!server.duplicate_agent) return null;
  const where = server.duplicate_agent_ip
    ? ` The refused agent last polled from ${server.duplicate_agent_ip}.`
    : "";
  const since = server.duplicate_agent_since
    ? `\n\nSince ${new Date(server.duplicate_agent_since).toLocaleString()}.`
    : "";
  const title =
    `Two ${kind} agent processes are polling as this server at once. Only the most recent one is served; the other is refused and keeps serving a configuration that no longer changes.` +
    where +
    "\n\nUsually a cloned VM or a copied agent state directory that kept the same agent_id: stop the extra agent, or clear its state directory so it registers as a server of its own." +
    since;
  return (
    <span
      className={`inline-flex items-center rounded bg-rose-500/15 px-1.5 py-0.5 text-[11px] font-medium text-rose-700 dark:text-rose-400 ${className}`}
      title={title}
    >
      Duplicate agent
    </span>
  );
}
