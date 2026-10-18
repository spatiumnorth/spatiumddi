import { type DNSPerServerZoneStateResponse, type DNSServer } from "@/lib/api";
import { isPartialApply } from "@/lib/configApply";

export type Summary = DNSPerServerZoneStateResponse["summary"];

export interface ZoneSerialsInput {
  zoneCount: number;
  servers: Pick<
    DNSServer,
    "id" | "config_apply_status" | "config_apply_error"
  >[];
  /** Per-server rollup keyed by server id; absent while it is loading or failed. */
  summaries: Record<string, Summary | undefined>;
  /** Ids whose rollup request failed. A server in neither map is still loading. */
  failed?: ReadonlySet<string>;
}

export interface ZoneSerialsReading {
  text: string;
  tone: "ok" | "warn" | "muted";
}

const plural = (n: number, one: string, many = `${one}s`) =>
  `${n} ${n === 1 ? one : many}`;

/**
 * What the group's servers have reported for the group's zones. Unknown is
 * never "in sync": a server that has not reported a zone, or whose rollup could
 * not be read, is named as such.
 */
export function readZoneSerials(input: ZoneSerialsInput): ZoneSerialsReading {
  const { zoneCount, servers, summaries } = input;
  const failed = input.failed ?? new Set<string>();
  if (zoneCount === 0) return { text: "no zones", tone: "muted" };
  const zones = plural(zoneCount, "zone");
  if (servers.length === 0) {
    return { text: `${zones} · no servers`, tone: "muted" };
  }
  const known = servers.filter((s) => summaries[s.id]);
  const refused = servers.filter((s) =>
    isPartialApply(s.config_apply_status, s.config_apply_error),
  ).length;
  const behind = known.filter((s) => (summaries[s.id]?.drift ?? 0) > 0).length;
  const silent = known.filter(
    (s) => (summaries[s.id]?.not_reported ?? 0) > 0,
  ).length;
  const unread = servers.filter(
    (s) => !summaries[s.id] && failed.has(s.id),
  ).length;
  const loading = servers.filter(
    (s) => !summaries[s.id] && !failed.has(s.id),
  ).length;

  const problems: string[] = [];
  if (behind > 0) problems.push(`${plural(behind, "server")} behind`);
  if (refused > 0) problems.push(`${plural(refused, "server")} refused zones`);
  if (silent > 0) {
    problems.push(`${plural(silent, "server")} not reported on every zone yet`);
  }
  if (unread > 0) problems.push(`${plural(unread, "server")} unreadable`);
  if (problems.length === 0 && loading > 0) {
    return { text: `${zones} · per-server serials not loaded`, tone: "muted" };
  }
  if (problems.length === 0) {
    return {
      text: `${zones} · in sync on ${plural(servers.length, "server")}`,
      tone: "ok",
    };
  }
  return { text: `${zones} · ${problems.join(" · ")}`, tone: "warn" };
}
