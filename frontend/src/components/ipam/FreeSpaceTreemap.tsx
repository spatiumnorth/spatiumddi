import { ListReadError } from "@/components/ui/list-read-error";
import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { ResponsiveContainer, Tooltip, Treemap } from "recharts";
import {
  ipamApi,
  type FreeCidrRange,
  type IPBlock,
  type Subnet,
} from "@/lib/api";
import { cidrAddressCountExact, formatCount } from "@/lib/format-count";

type Kind = "block" | "subnet" | "free";

interface Cell {
  name: string;
  size: number;
  // Exact address count as a decimal string, for the tooltip (#3708).
  exact?: string | null;
  kind: Kind;
  network: string;
  subName?: string;
  utilization?: number; // 0..100 — only set for blocks/subnets
  [k: string]: unknown;
}

// Each non-free kind has a pale base (the slice exists) and a saturated fill
// (how much of it is allocated). Free is just a muted fill.
const COLORS: Record<Kind, { base: string; fill: string }> = {
  block: {
    base: "rgb(124 58 237 / 0.45)", // violet-600 mid
    fill: "rgb(109 40 217)", // violet-700 solid
  },
  subnet: {
    base: "rgb(37 99 235 / 0.45)", // blue-600 mid
    fill: "rgb(29 78 216)", // blue-700 solid
  },
  free: {
    base: "rgb(82 82 91 / 0.55)", // zinc-600 — clearly distinct from blocks/subnets
    fill: "rgb(82 82 91 / 0.55)",
  },
};

/**
 * 2-D proportional view of a block's address space — complements the 1-D
 * FreeSpaceBand. Tiny CIDR slices that are pixel-thin on the band become
 * visible squares here, which makes fragmentation easy to spot.
 *
 * Sizes are rendered as raw address counts; the chart math is handled by
 * Recharts' built-in squarified Treemap.
 */
export function FreeSpaceTreemap({
  block,
  directSubnets,
  childBlocks,
}: {
  block: IPBlock;
  directSubnets: Subnet[];
  childBlocks: IPBlock[];
}) {
  const { data: freeRanges = [], error } = useQuery<FreeCidrRange[]>({
    queryKey: [
      "block-free-space",
      block.id,
      directSubnets.length,
      childBlocks.length,
    ],
    queryFn: () => ipamApi.blockFreeSpace(block.id),
  });

  const cells = useMemo<Cell[]>(() => {
    const out: Cell[] = [];
    for (const b of childBlocks) {
      out.push({
        name: b.network,
        subName: b.name ?? undefined,
        size: addressCount(b.network),
        exact: cidrAddressCountExact(b.network),
        kind: "block",
        network: b.network,
        utilization: b.utilization_percent,
      });
    }
    for (const s of directSubnets) {
      out.push({
        name: s.network,
        subName: s.name ?? undefined,
        size: addressCount(s.network),
        exact: cidrAddressCountExact(s.network),
        kind: "subnet",
        network: s.network,
        utilization: s.utilization_percent,
      });
    }
    for (const f of freeRanges) {
      out.push({
        name: f.network,
        size: f.size,
        exact: f.size_exact,
        kind: "free",
        network: f.network,
      });
    }
    return out.filter((c) => c.size > 0);
  }, [childBlocks, directSubnets, freeRanges]);

  if (error != null) {
    return (
      <p className="flex h-32 items-center justify-center text-xs">
        <ListReadError error={error} what="this block's allocation map" />
      </p>
    );
  }

  if (cells.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center rounded-md border border-dashed text-xs text-muted-foreground">
        No allocation data
      </div>
    );
  }

  return (
    <div className="w-full">
      <ResponsiveContainer width="100%" height={192} minWidth={0}>
        <Treemap
          data={cells}
          dataKey="size"
          stroke="hsl(var(--background))"
          content={<TreemapCell />}
          isAnimationActive={false}
        >
          <Tooltip content={<TreemapTooltip />} />
        </Treemap>
      </ResponsiveContainer>
    </div>
  );
}

function addressCount(cidr: string): number {
  const slash = cidr.indexOf("/");
  if (slash === -1) return 1;
  const prefix = parseInt(cidr.slice(slash + 1), 10);
  const isV6 = cidr.includes(":");
  const total = isV6 ? 128 : 32;
  const hostBits = total - prefix;
  // For IPv6, sizes can exceed Number.MAX_SAFE_INTEGER (>= /53). Clamp to a
  // visualisation-sized number — Recharts treats this as a relative weight,
  // not an exact count.
  if (hostBits >= 53) return Number.MAX_SAFE_INTEGER / 2;
  return Math.pow(2, hostBits);
}

interface TreemapCellProps {
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  // Recharts v3 spreads the data fields directly onto the render props,
  // and *also* exposes the original datum at `payload` (with the same fields
  // re-nested). Read from the top-level fields first; fall back to payload.
  kind?: Kind;
  network?: string;
  utilization?: number;
  payload?: Cell;
}

function TreemapCell(props: TreemapCellProps) {
  const { x = 0, y = 0, width = 0, height = 0 } = props;
  const datum: Cell | undefined =
    props.kind && props.network
      ? {
          kind: props.kind,
          network: props.network,
          utilization: props.utilization,
          name: props.network,
          size: 0,
        }
      : props.payload;
  const colors = datum ? COLORS[datum.kind] : COLORS.free;

  if (width <= 0 || height <= 0) return null;

  const showLabel = width > 60 && height > 28 && datum;
  const utilFrac =
    datum && datum.kind !== "free" && typeof datum.utilization === "number"
      ? Math.min(1, Math.max(0, datum.utilization / 100))
      : 0;
  const fillHeight = Math.round(height * utilFrac);

  return (
    <g>
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        fill={colors.base}
        stroke="rgb(255 255 255 / 0.4)"
        strokeWidth={1}
      />
      {fillHeight > 0 && (
        <rect
          x={x}
          y={y + height - fillHeight}
          width={width}
          height={fillHeight}
          fill={colors.fill}
        />
      )}
      {showLabel && (
        <>
          <text
            x={x + 4}
            y={y + 14}
            fontSize={10}
            fill="rgb(255 255 255 / 0.95)"
            fontFamily="monospace"
          >
            {datum!.network}
          </text>
          {datum!.kind !== "free" && typeof datum!.utilization === "number" && (
            <text
              x={x + 4}
              y={y + 26}
              fontSize={9}
              fill="rgb(255 255 255 / 0.85)"
            >
              {Math.round(datum!.utilization)}% used
            </text>
          )}
        </>
      )}
    </g>
  );
}

function TreemapTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: { payload: Cell }[];
}) {
  if (!active || !payload?.length) return null;
  const c = payload[0].payload;
  return (
    <div className="rounded border bg-popover px-2 py-1 text-xs shadow-md">
      <div className="font-mono">{c.network}</div>
      {c.subName && <div className="text-muted-foreground">{c.subName}</div>}
      <div className="text-muted-foreground">
        {c.kind} · {formatCount(c.exact, c.size)} addrs
        {c.kind !== "free" && typeof c.utilization === "number" && (
          <> · {Math.round(c.utilization)}% used</>
        )}
      </div>
    </div>
  );
}
