import { ListReadError } from "@/components/ui/list-read-error";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import {
  ipamApi,
  type FreeCidrRange,
  type IPBlock,
  type Subnet,
} from "@/lib/api";
import { parseCidr } from "@/lib/cidr";
import { cn } from "@/lib/utils";

interface Segment {
  start: number; // fraction 0..1 relative to block
  width: number; // fraction width
  kind: "block" | "subnet" | "free";
  label: string;
  size: number;
  network?: string;
  utilization?: number; // 0..100 — only set for blocks/subnets
}

/**
 * Horizontal band visualizing used vs free CIDR space inside an IP block.
 *
 * - Violet segments: direct child blocks
 * - Blue segments: direct child subnets
 * - Zinc hashed segments: free (unallocated) ranges
 *
 * Clicking a free segment invokes `onSelectFree(range)` which typically opens
 * CreateSubnetModal prefilled with that CIDR.
 */
export function FreeSpaceBand({
  block,
  directSubnets,
  childBlocks,
  onSelectFree,
  createDisabledReason,
}: {
  block: IPBlock;
  directSubnets: Subnet[];
  childBlocks: IPBlock[];
  onSelectFree: (range: FreeCidrRange) => void;
  /** Set when the caller may not create a subnet (#3391): a free segment is
   *  then disabled and this is its tooltip. */
  createDisabledReason?: string;
}) {
  const {
    data: freeRanges = [],
    isLoading,
    error,
  } = useQuery({
    queryKey: [
      "block-free-space",
      block.id,
      directSubnets.length,
      childBlocks.length,
    ],
    queryFn: () => ipamApi.blockFreeSpace(block.id),
  });

  const segments = useMemo<Segment[]>(() => {
    const parent = parseCidr(block.network);
    if (!parent) return [];
    const parentSize = Math.pow(2, 32 - parent.prefix);

    const mapRange = (
      net: string,
      kind: Segment["kind"],
      label: string,
      utilization?: number,
    ): Segment | null => {
      const p = parseCidr(net);
      if (!p) return null;
      const size = Math.pow(2, 32 - p.prefix);
      const start = (p.base - parent.base) / parentSize;
      return {
        start,
        width: size / parentSize,
        kind,
        label,
        size,
        network: net,
        utilization,
      };
    };

    const out: Segment[] = [];
    for (const b of childBlocks) {
      const s = mapRange(
        b.network,
        "block",
        `${b.network}${b.name ? ` (${b.name})` : ""} — ${Math.round(b.utilization_percent)}% used`,
        b.utilization_percent,
      );
      if (s) out.push(s);
    }
    for (const sn of directSubnets) {
      const s = mapRange(
        sn.network,
        "subnet",
        `${sn.network}${sn.name ? ` (${sn.name})` : ""} — ${Math.round(sn.utilization_percent)}% used`,
        sn.utilization_percent,
      );
      if (s) out.push(s);
    }
    for (const fr of freeRanges) {
      const s = mapRange(
        fr.network,
        "free",
        `Free ${fr.network} (${fr.size.toLocaleString()} addrs)`,
      );
      if (s) out.push(s);
    }
    out.sort((a, b) => a.start - b.start);
    return out;
  }, [block.network, childBlocks, directSubnets, freeRanges]);

  const [hovered, setHovered] = useState<Segment | null>(null);

  if (isLoading) {
    return <div className="h-5 w-full animate-pulse rounded-sm bg-muted/40" />;
  }

  // A refused or failed read says so, not "No allocation data" (#3337): the
  // block's own grant may not reach the subnets the free-space walk needs.
  if (error != null) {
    return (
      <p className="text-[11px]">
        <ListReadError error={error} what="this block's allocation map" />
      </p>
    );
  }

  if (segments.length === 0) {
    return (
      <div className="flex h-5 w-full items-center justify-center rounded-sm border border-dashed border-border/60 text-[10px] text-muted-foreground">
        No allocation data
      </div>
    );
  }

  return (
    <div className="space-y-1">
      <div className="relative h-5 w-full overflow-hidden rounded-sm border border-border bg-muted/30 dark:bg-muted/50">
        {segments.map((seg, i) => (
          <button
            key={`${seg.kind}-${seg.network ?? i}`}
            type="button"
            onMouseEnter={() => setHovered(seg)}
            onMouseLeave={() => setHovered(null)}
            onClick={() => {
              if (seg.kind === "free") {
                const fr = freeRanges.find((r) => r.network === seg.network);
                if (fr) onSelectFree(fr);
              }
            }}
            title={
              seg.kind === "free" && createDisabledReason
                ? createDisabledReason
                : seg.label
            }
            style={{
              left: `${seg.start * 100}%`,
              width: `${Math.max(seg.width * 100, 0.25)}%`,
            }}
            className={cn(
              "absolute top-0 h-full overflow-hidden border-r border-background/60 last:border-r-0",
              // Mid-saturation background = the slice exists; the inner fill
              // (below) shows how much of it is allocated.
              seg.kind === "block" && "bg-violet-600/40 hover:bg-violet-600/55",
              seg.kind === "subnet" && "bg-blue-600/40 hover:bg-blue-600/55",
              seg.kind === "free" &&
                "cursor-pointer bg-[repeating-linear-gradient(45deg,theme(colors.zinc.400/.5)_0_4px,transparent_4px_8px)] dark:bg-[repeating-linear-gradient(45deg,theme(colors.zinc.500/.6)_0_4px,transparent_4px_8px)] hover:bg-[repeating-linear-gradient(45deg,theme(colors.emerald.500/.6)_0_4px,transparent_4px_8px)] dark:hover:bg-[repeating-linear-gradient(45deg,theme(colors.emerald.400/.5)_0_4px,transparent_4px_8px)]",
            )}
            aria-label={seg.label}
            disabled={seg.kind !== "free" || !!createDisabledReason}
          >
            {(seg.kind === "block" || seg.kind === "subnet") && (
              <span
                className={cn(
                  "absolute left-0 top-0 h-full",
                  seg.kind === "block" ? "bg-violet-700" : "bg-blue-700",
                )}
                style={{
                  width: `${Math.min(100, Math.max(0, seg.utilization ?? 0))}%`,
                }}
              />
            )}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
        <Legend color="bg-violet-700" label="Child blocks" />
        <Legend color="bg-blue-700" label="Subnets" />
        <Legend
          color="bg-[repeating-linear-gradient(45deg,theme(colors.zinc.400/.6)_0_4px,transparent_4px_8px)] dark:bg-[repeating-linear-gradient(45deg,theme(colors.zinc.500/.7)_0_4px,transparent_4px_8px)]"
          label="Free"
        />
        <span className="text-muted-foreground/70">
          (saturated portion = % allocated)
        </span>
        {hovered && (
          <span className="ml-auto font-mono text-foreground">
            {hovered.label}
          </span>
        )}
      </div>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span
        className={cn(
          "inline-block h-2 w-3 rounded-sm border border-border/60",
          color,
        )}
      />
      {label}
    </span>
  );
}
