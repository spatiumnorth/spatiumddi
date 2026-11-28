// Per-token usage (#4491): calls per UTC day from
// GET /api-tokens/{id}/usage, with a 30 / 90-day window toggle. The series
// carries counts and the last client address only, never the token itself.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { apiTokensApi } from "@/lib/api";

const WINDOWS = [30, 90] as const;

export function ApiTokenUsageChart({ tokenId }: { tokenId: string }) {
  const [days, setDays] = useState<(typeof WINDOWS)[number]>(30);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["api-token-usage", tokenId, days],
    queryFn: () => apiTokensApi.usage(tokenId, days),
  });

  const points = (data?.days ?? []).map((d) => ({
    t: new Date(`${d.day}T00:00:00Z`).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      timeZone: "UTC",
    }),
    calls: d.calls,
  }));

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground" data-testid="usage-total">
          {data
            ? `${data.total.toLocaleString()} calls in the last ${days} days (UTC days)`
            : " "}
        </p>
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
      {data && (
        <p className="text-xs text-muted-foreground">
          Last used:{" "}
          {data.last_used_at
            ? new Date(data.last_used_at).toLocaleString()
            : "never"}
          {data.last_client_ip && (
            <>
              {" "}
              from <span className="font-mono">{data.last_client_ip}</span>
            </>
          )}
        </p>
      )}
      <div className="h-44">
        {isLoading ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            Loading…
          </div>
        ) : isError ? (
          <div className="flex h-full items-center justify-center text-xs text-destructive">
            Could not load usage.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={points}
              margin={{ top: 5, right: 12, left: 0, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
              <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={32} />
              <YAxis tick={{ fontSize: 10 }} width={40} allowDecimals={false} />
              <Tooltip
                contentStyle={{ fontSize: 11, borderRadius: 6 }}
                labelStyle={{ fontWeight: 600 }}
                formatter={(value) => [Number(value).toLocaleString(), "Calls"]}
              />
              <Bar dataKey="calls" fill="#3b82f6" name="Calls" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
