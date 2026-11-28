// Per-subnet utilization trend (#44).
//
// Renders the daily allocated/total snapshots recorded by the
// `snapshot_subnet_utilization` beat task as a "% used over time" line
// chart with a 30 / 90-day window toggle. Self-contained so it can be
// dropped onto the subnet detail without bloating IPAMPage.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { TrendingUp } from "lucide-react";

import { ipamApi } from "@/lib/api";

const WINDOWS = [30, 90] as const;

export function SubnetUtilizationHistory({ subnetId }: { subnetId: string }) {
  const [days, setDays] = useState<(typeof WINDOWS)[number]>(90);

  const { data, isLoading } = useQuery({
    queryKey: ["subnet-utilization-history", subnetId, days],
    queryFn: () => ipamApi.getUtilizationHistory(subnetId, days),
  });

  const { data: forecast } = useQuery({
    queryKey: ["subnet-capacity-forecast"],
    queryFn: () => ipamApi.getCapacityForecasts(),
    staleTime: 60_000,
    select: (rows) => rows.find((r) => r.subnet_id === subnetId) ?? null,
  });

  const points = (data ?? []).map((p) => ({
    t: new Date(p.sampled_at).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
    }),
    util: p.utilization_percent,
    allocated: p.allocated_ips,
    total: p.total_ips,
  }));

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          <TrendingUp className="h-4 w-4 text-muted-foreground" />
          Utilization history
        </div>
        <div className="flex items-center gap-1">
          {WINDOWS.map((w) => (
            <button
              key={w}
              type="button"
              onClick={() => setDays(w)}
              className={`rounded-md px-2 py-0.5 text-xs ${
                days === w
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-muted"
              }`}
            >
              {w}d
            </button>
          ))}
        </div>
      </div>
      {forecast && (
        <div className="border-b px-4 py-2 text-xs text-muted-foreground">
          {forecast.days_to_full === 0
            ? "Full now and still growing."
            : `Trends to 100% on ${forecast.forecast_full_date} at the current rate (${forecast.days_to_full} days, +${forecast.slope_percent_per_day.toFixed(2)} points/day over the last 30 days).`}
        </div>
      )}
      <div className="h-44 px-2 py-3">
        {isLoading ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            Loading…
          </div>
        ) : points.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-1 text-center text-xs text-muted-foreground">
            <span>No utilization history yet.</span>
            <span className="text-[11px]">
              A daily snapshot is recorded each night — check back tomorrow.
            </span>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={points}
              margin={{ top: 5, right: 12, left: 0, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
              <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={32} />
              <YAxis
                tick={{ fontSize: 10 }}
                width={40}
                domain={[0, 100]}
                tickFormatter={(v) => `${v}%`}
              />
              <Tooltip
                contentStyle={{ fontSize: 11, borderRadius: 6 }}
                labelStyle={{ fontWeight: 600 }}
                formatter={(value, _name, item) => [
                  `${Number(value).toFixed(1)}% (${item.payload.allocated} / ${item.payload.total})`,
                  "Utilization",
                ]}
              />
              <Line
                type="monotone"
                dataKey="util"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
                name="Utilization"
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
