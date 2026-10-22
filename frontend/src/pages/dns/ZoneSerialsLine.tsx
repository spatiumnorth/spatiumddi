import { useQueries } from "@tanstack/react-query";
import { dnsApi } from "@/lib/api";
import {
  readZoneSerials,
  type Summary,
  type ZoneSerialsInput,
} from "./zoneSerials";

const toneCls = {
  ok: "text-emerald-600 dark:text-emerald-400",
  warn: "text-amber-700 dark:text-amber-400",
  muted: "text-muted-foreground",
} as const;

export function ZoneSerialsLine({
  zoneCount,
  servers,
}: Pick<ZoneSerialsInput, "zoneCount" | "servers">) {
  // One request per server (a handful), never one per zone.
  const results = useQueries({
    queries: servers.map((s) => ({
      queryKey: ["dns-server-zone-state", s.id],
      queryFn: () => dnsApi.getServerZoneState(s.id),
      refetchInterval: 30_000,
    })),
  });
  const summaries: Record<string, Summary | undefined> = {};
  const failed = new Set<string>();
  servers.forEach((s, i) => {
    summaries[s.id] = results[i]?.data?.summary;
    if (results[i]?.isError) failed.add(s.id);
  });
  const reading = readZoneSerials({ zoneCount, servers, summaries, failed });
  return (
    <span className={`ml-auto ${toneCls[reading.tone]}`}>
      Zone serials: {reading.text}
    </span>
  );
}
