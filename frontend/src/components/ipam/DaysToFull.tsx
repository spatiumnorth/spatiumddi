// "Full in N d" caption for a subnet's utilization cell (#43).
//
// One shared query serves every row of a table (react-query dedupes by key);
// only subnets with a projectable trend are in the response, so a flat,
// falling or short-history subnet renders nothing.
import { useQuery } from "@tanstack/react-query";

import { ipamApi } from "@/lib/api";

export function DaysToFull({ subnetId }: { subnetId: string }) {
  const { data } = useQuery({
    queryKey: ["subnet-capacity-forecast"],
    queryFn: () => ipamApi.getCapacityForecasts(),
    staleTime: 60_000,
    select: (rows) => rows.find((r) => r.subnet_id === subnetId) ?? null,
  });
  if (!data) return null;
  return (
    <span
      className="ml-2 whitespace-nowrap text-[11px] text-muted-foreground"
      title={`Trends to 100% on ${data.forecast_full_date} at the current rate`}
    >
      {data.days_to_full === 0 ? "full now" : `full in ${data.days_to_full} d`}
    </span>
  );
}
