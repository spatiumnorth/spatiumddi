import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  dnsApi,
  dnsBlocklistApi,
  type AgentLogSource,
  type BlocklistMatchEntry,
  type DNSBlockListEntry,
  type DNSBlockListException,
  type DNSQueryLogRow,
} from "@/lib/api";
import { usePermissions } from "@/hooks/usePermissions";

/** State and gates behind the DNS query details actions (#4250). Kept apart
 *  from the components so the component file exports only components. */

// Blocking lists are applied by the BIND9 RPZ renderer and by Technitium's
// blocked / allowed sets; no other driver reads them.
const BLOCKLIST_DRIVERS: ReadonlySet<string> = new Set(["bind9", "technitium"]);

/** Lower-cased qname without the trailing dot, or null when it cannot be a
 *  blocking-list name: empty, one label, or a reverse (.arpa) name. */
export function blockableName(qname: string | null | undefined): string | null {
  if (!qname) return null;
  const d = qname.trim().toLowerCase().replace(/\.$/, "");
  if (!d.includes(".") || d.split(".").some((l) => l === "")) return null;
  if (d.endsWith(".arpa")) return null;
  return d;
}

/** The name and each parent down to two labels: `a.b.example.com` →
 *  `a.b.example.com`, `b.example.com`, `example.com`. */
export function nameChoices(name: string): string[] {
  const labels = name.split(".");
  const out: string[] = [];
  for (let i = 0; i <= labels.length - 2; i++)
    out.push(labels.slice(i).join("."));
  return out;
}

/** The longest zone name that is the qname or a parent of it. */
export function longestZoneMatch<T extends { name: string }>(
  qname: string,
  zones: T[],
): T | null {
  let best: T | null = null;
  for (const z of zones) {
    const zn = z.name.toLowerCase().replace(/\.$/, "");
    if (qname === zn || qname.endsWith("." + zn)) {
      if (!best || zn.length > best.name.replace(/\.$/, "").length) best = z;
    }
  }
  return best;
}

// ── state shared by the modal's pieces ────────────────────────────────

export type TriageDone =
  | {
      kind: "blocked";
      listId: string;
      listName: string;
      entry: DNSBlockListEntry;
    }
  | {
      kind: "excepted";
      listId: string;
      listName: string;
      exception: DNSBlockListException;
      domain: string;
    }
  | { kind: "removed"; entries: BlocklistMatchEntry[]; domain: string }
  | { kind: "undone"; message: string };

export function useDnsQueryTriage(
  row: DNSQueryLogRow,
  source: AgentLogSource | undefined,
) {
  const perms = usePermissions();
  const qname = blockableName(row.qname);
  const groupId = source?.group_id ?? null;
  const canReadBl = perms.can("read", "dns_blocklist");
  const canReadGroup = perms.can("read", "dns_group");

  // The row names its view; the match needs the view's id. Without read on
  // the group the view cannot be resolved, and the dialog says so.
  const viewsQ = useQuery({
    queryKey: ["dns-views", groupId],
    queryFn: () => dnsApi.listViews(groupId!),
    enabled: !!groupId && !!row.view && canReadGroup,
    staleTime: 60_000,
  });
  const viewId = row.view
    ? viewsQ.data?.find((v) => v.name === row.view)?.id
    : undefined;
  const viewsSettled = !row.view || !canReadGroup || !viewsQ.isLoading;

  const matchQ = useQuery({
    queryKey: ["blocklist-match", qname, groupId, viewId ?? null],
    queryFn: () =>
      dnsBlocklistApi.match({
        domain: qname!,
        group_id: groupId ?? undefined,
        view_id: viewId,
      }),
    enabled: canReadBl && !!qname && !!groupId && viewsSettled,
    retry: false,
  });
  const listsQ = useQuery({
    queryKey: ["dns-blocklists"],
    queryFn: () => dnsBlocklistApi.list(),
    enabled: canReadBl,
    staleTime: 30_000,
  });
  const groupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: canReadGroup,
    staleTime: 60_000,
  });

  const applicable = useMemo(
    () =>
      (listsQ.data ?? []).filter(
        (l) =>
          l.enabled &&
          ((!!groupId && l.applied_group_ids.includes(groupId)) ||
            (!!viewId && l.applied_view_ids.includes(viewId))),
      ),
    [listsQ.data, groupId, viewId],
  );

  return {
    perms,
    qname,
    groupId,
    viewId,
    source,
    matchQ,
    match: matchQ.data,
    lists: listsQ.data,
    listsLoading: listsQ.isLoading,
    applicable,
    groupNames: new Map((groupsQ.data ?? []).map((g) => [g.id, g.name])),
    viewUnresolved: !!row.view && !canReadGroup,
    blocked: matchQ.data?.effective === "blocked",
  };
}

export type Triage = ReturnType<typeof useDnsQueryTriage>;

/** ``pending`` = the answer is not known yet (grants or lists still loading):
 *  disabled, with no reason to show. */
type Gate = { hidden?: boolean; reason: string | null; pending?: boolean };

export function blockGate(t: Triage): Gate {
  const { perms, qname, source, applicable } = t;
  if (!perms.can("read", "dns_blocklist")) {
    // Loading fails closed; only a settled answer may hide the button.
    return perms.unanswered
      ? { reason: null, pending: true }
      : { hidden: true, reason: null };
  }
  if (!perms.can("write", "dns_blocklist")) {
    return { reason: "Needs write on DNS blocklists." };
  }
  if (!qname) return { reason: "This name cannot be blocked." };
  if (!source?.group_id) {
    return {
      reason: "Cannot tell which DNS server group answered this query.",
    };
  }
  if (!BLOCKLIST_DRIVERS.has(source.driver)) {
    return {
      reason: `Blocking lists are not applied by ${source.driver} servers.`,
    };
  }
  if (t.listsLoading) return { reason: null, pending: true };
  if (!applicable.some((l) => l.source_type === "manual")) {
    const group = source.group_name ?? "this group";
    return {
      reason: `No manual blocking list is applied to ${group}. A superadmin can create and assign one under DNS → ${group} → Blocklists.`,
    };
  }
  return { reason: null };
}

export function allowGate(t: Triage): Gate {
  if (t.perms.unanswered) return { reason: null, pending: true };
  if (!t.perms.can("write", "dns_blocklist")) {
    return { reason: "Needs write on DNS blocklists." };
  }
  return { reason: null };
}
