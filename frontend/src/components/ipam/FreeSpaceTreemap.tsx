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
import { bigFraction, cidrSpan } from "@/lib/cidr";

type Kind = "block" | "subnet" | "free";

interface Cell {
  name: string;
  size: number; // relative weight (fraction of the block), not a count
  addrs: bigint; // exact address count, for the tooltip
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
    const parent = cidrSpan(block.network);
    const weigh = (cidr: string): { size: number; addrs: bigint } => {
      const span = cidrSpan(cidr);
      if (!span || !parent) return { size: 0, addrs: 0n };
      // At least 1 so a vanishing child stays a (hairline) cell.
      return {
        size: Math.max(1, bigFraction(span.size, parent.size) * 2 ** 48),
        addrs: span.size,
      };
    };
    for (const b of childBlocks) {
      out.push({
        name: b.network,
        subName: b.name ?? undefined,
        ...weigh(b.network),
        kind: "block",
        network: b.network,
        utilization: b.utilization_percent,
      });
    }
    for (const s of directSubnets) {
      out.push({
        name: s.network,
        subName: s.name ?? undefined,
        ...weigh(s.network),
        kind: "subnet",
        network: s.network,
        utilization: s.utilization_percent,
      });
    }
    for (const f of freeRanges) {
      out.push({
        name: f.network,
        // The API's `size` saturates for IPv6; the prefix is exact.
        ...weigh(f.network),
        kind: "free",
        network: f.network,
      });
    }
    // A capped answer names the rest on its last range (#3848): one cell for
    // the block's remainder, less what the children already draw inside it.
    const last = freeRanges[freeRanges.length - 1];
    const lastSpan = last ? cidrSpan(last.network) : null;
    if (last?.more_after && lastSpan && parent) {
      const tailStart = lastSpan.base + lastSpan.size;
      let size = parent.base + parent.size - tailStart;
      for (const n of [
        ...childBlocks.map((b) => b.network),
        ...directSubnets.map((x) => x.network),
      ]) {
        const sp = cidrSpan(n);
        if (sp && sp.base >= tailStart) size -= sp.size;
      }
      if (size > 0n) {
        out.push({
          name: `Rest of block (${last.more_after.toLocaleString()} more free ranges)`,
          size: Math.max(1, bigFraction(size, parent.size) * 2 ** 48),
          addrs: size,
          kind: "free",
          network: `rest of block after ${last.network}`,
        });
      }
    }
    return out.filter((c) => c.size > 0);
  }, [block.network, childBlocks, directSubnets, freeRanges]);
  const omitted = freeRanges[freeRanges.length - 1]?.more_after ?? 0;

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
      {omitted > 0 && (
        <p className="mt-1 text-[10px] text-amber-600 dark:text-amber-400">
          Showing {freeRanges.length.toLocaleString()} of{" "}
          {(freeRanges.length + omitted).toLocaleString()} free ranges; the rest
          of the block is drawn as one free cell.
        </p>
      )}
    </div>
  );
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
          addrs: 0n,
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
        {c.kind} · {c.addrs.toLocaleString()} addrs
        {c.kind !== "free" && typeof c.utilization === "number" && (
          <> · {Math.round(c.utilization)}% used</>
        )}
      </div>
    </div>
  );
}
