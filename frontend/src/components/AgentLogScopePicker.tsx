import { Server } from "lucide-react";
import type { AgentLogSource } from "@/lib/api";
import {
  ALL_SERVERS,
  type AgentLogSelection,
  groupSelection,
  groupSources,
  serverLabel,
  serverSelection,
} from "@/lib/agent-log-scope";

/**
 * Grouped server picker for Logs → DNS Queries / DHCP Activity (#2120):
 * `All servers`, then per group `<Group> (all N servers)` followed by that
 * group's servers. Selection model in `lib/agent-log-scope.ts`.
 */
export function AgentLogScopePicker({
  sources,
  value,
  onChange,
}: {
  sources: AgentLogSource[];
  value: AgentLogSelection | null;
  onChange: (v: AgentLogSelection) => void;
}) {
  const groups = groupSources(sources);
  return (
    <label className="flex items-center gap-1.5 text-xs">
      <span className="inline-flex items-center gap-1 text-muted-foreground">
        <Server className="h-3 w-3" />
        Server
      </span>
      <select
        aria-label="Server"
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        className="max-w-[22rem] rounded-md border bg-background px-2 py-1 text-sm"
      >
        <option value={ALL_SERVERS}>All servers ({sources.length})</option>
        {groups.map((g) => (
          <optgroup key={g.id ?? "__none__"} label={g.name}>
            {/* A group entry only for a real group: the API cannot select
                "servers with no group", and a one-server group's entry
                would read the same as the server below it. */}
            {g.id && g.servers.length > 1 && (
              <option value={groupSelection(g.id)}>
                {g.name} (all {g.servers.length} servers)
              </option>
            )}
            {g.servers.map((s) => (
              <option key={s.server_id} value={serverSelection(s.server_id)}>
                {serverLabel(s)}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
    </label>
  );
}
