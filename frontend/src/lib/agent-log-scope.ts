import type { AgentLogScope, AgentLogSource } from "@/lib/api";

/**
 * Selection model for the grouped server picker on the agent-log tabs (Logs → DNS Queries /
 * DHCP Activity, #2120).
 *
 * A group behind one load-balanced address spreads a client's queries
 * across its servers, so the useful unit is often the group, not one
 * server. The picker offers `All servers`, then per group a
 * `<Group> (all N servers)` entry followed by that group's servers.
 *
 * Kept apart from the component (`components/AgentLogScopePicker.tsx`)
 * so fast-refresh sees a components-only module. The selection is encoded
 * as one string so it fits a native <select>:
 * `all`, `group:<id>` or `server:<id>`. The server narrows every read to
 * what the caller may read, so this is a request, never an authorisation.
 */

export type AgentLogSelection = string;

export const ALL_SERVERS: AgentLogSelection = "all";

export function groupSelection(groupId: string): AgentLogSelection {
  return `group:${groupId}`;
}

export function serverSelection(serverId: string): AgentLogSelection {
  return `server:${serverId}`;
}

/** The request scope a selection maps to. */
export function selectionToScope(sel: AgentLogSelection): AgentLogScope {
  if (sel.startsWith("group:")) return { group_id: sel.slice(6) };
  if (sel.startsWith("server:")) return { server_id: sel.slice(7) };
  return {};
}

/** Name, plus the hostname only when it says something the name does not. */
export function serverLabel(s: AgentLogSource): string {
  return s.host && s.host !== s.server_name
    ? `${s.server_name} (${s.host})`
    : s.server_name;
}

export interface AgentLogGroup {
  /** `null` for servers in no group (a DHCP server may have none). */
  id: string | null;
  name: string;
  servers: AgentLogSource[];
}

/** Sources bucketed by group, groups by name, ungrouped last. */
export function groupSources(sources: AgentLogSource[]): AgentLogGroup[] {
  const byId = new Map<string, AgentLogGroup>();
  const ungrouped: AgentLogSource[] = [];
  for (const s of sources) {
    if (!s.group_id) {
      ungrouped.push(s);
      continue;
    }
    let g = byId.get(s.group_id);
    if (!g) {
      g = { id: s.group_id, name: s.group_name ?? s.group_id, servers: [] };
      byId.set(s.group_id, g);
    }
    g.servers.push(s);
  }
  const byName = (a: AgentLogSource, b: AgentLogSource) =>
    a.server_name.localeCompare(b.server_name);
  const groups = [...byId.values()].sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  for (const g of groups) g.servers.sort(byName);
  if (ungrouped.length > 0) {
    groups.push({
      id: null,
      name: "No group",
      servers: [...ungrouped].sort(byName),
    });
  }
  return groups;
}

/** How many of `sources` a selection covers. */
export function selectionServerCount(
  sel: AgentLogSelection,
  sources: AgentLogSource[],
): number {
  const scope = selectionToScope(sel);
  if (scope.server_id) {
    return sources.some((s) => s.server_id === scope.server_id) ? 1 : 0;
  }
  if (scope.group_id) {
    return sources.filter((s) => s.group_id === scope.group_id).length;
  }
  return sources.length;
}

/** Whether a selection still names something in `sources`. */
export function selectionIsValid(
  sel: AgentLogSelection | null,
  sources: AgentLogSource[],
): boolean {
  if (!sel) return false;
  if (sel === ALL_SERVERS) return true;
  return selectionServerCount(sel, sources) > 0;
}

/**
 * The selection a tab opens on. Kept as it always was — the first server —
 * so the tab opens on the same narrow, fast read as before; `All servers`
 * and the group entries are one click away.
 */
export function defaultSelection(
  sources: AgentLogSource[],
): AgentLogSelection | null {
  return sources[0] ? serverSelection(sources[0].server_id) : null;
}

/** The host to name in the "querying …" indicator, when there is one. */
export function selectionHost(
  sel: AgentLogSelection | null,
  sources: AgentLogSource[],
): string | undefined {
  if (!sel) return undefined;
  const { server_id } = selectionToScope(sel);
  return server_id
    ? sources.find((s) => s.server_id === server_id)?.host
    : undefined;
}
