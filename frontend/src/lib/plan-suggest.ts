import { addressToBigInt } from "@/lib/cidr";
import type { PlanNode } from "@/lib/api";

/** An address as text from its integer value, either family (IPv6 compressed). */
export function formatAddress(n: bigint, v6: boolean): string {
  if (!v6) {
    return [24n, 16n, 8n, 0n].map((sh) => String((n >> sh) & 0xffn)).join(".");
  }
  const g = Array.from({ length: 8 }, (_, i) =>
    Number((n >> BigInt((7 - i) * 16)) & 0xffffn),
  );
  let bestAt = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) [bestAt, bestLen] = [i, j - i];
    i = j;
  }
  const hex = (xs: number[]) => xs.map((x) => x.toString(16)).join(":");
  if (bestLen < 2) return hex(g);
  return `${hex(g.slice(0, bestAt))}::${hex(g.slice(bestAt + bestLen))}`;
}

/** A CIDR's first address and size as exact BigInts (either family). */
function cidrSpan(cidr: string): { base: bigint; size: bigint } | null {
  const [ip, prefixStr] = cidr.split("/");
  if (!ip || !prefixStr) return null;
  const total = ip.includes(":") ? 128 : 32;
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > total) return null;
  if (total === 32 && ip.split(".").length !== 4) return null;
  const hostBits = BigInt(total - prefix);
  return {
    base: (addressToBigInt(ip) >> hostBits) << hostBits,
    size: 1n << hostBits,
  };
}

/**
 * A CIDR inside `parent` that no sibling in `existing` holds, or "" when
 * nothing fits (#3711). Aims at parent + 8 bits (IPv4, held to /30) or + 16
 * (IPv6, held to /127; a subnet under an IPv6 node shorter than /64 aims
 * at /64), walks the aligned slots of that size for the first
 * free one, and halves the slot size when all are taken. BigInt throughout:
 * an IPv6 node is far past 2^53 addresses. Never answers a sibling's CIDR;
 * the operator fills an empty field in.
 */
export function suggestChildCidr(
  parent: PlanNode,
  existing: PlanNode[],
  kind: "block" | "subnet" = "block",
): string {
  const span = cidrSpan(parent.network);
  if (!span) return "";
  const v6 = parent.network.includes(":");
  const total = v6 ? 128 : 32;
  const max = v6 ? 127 : 30;
  const parentPrefix = total - (span.size.toString(2).length - 1);
  const end = span.base + span.size;
  const taken = existing
    .filter((c) => c.network.includes(":") === v6)
    .map((c) => cidrSpan(c.network))
    .filter((c): c is NonNullable<typeof c> => c !== null)
    .map((c) => ({ start: c.base, end: c.base + c.size }));

  // An IPv6 subnet starts on /64 like New Subnet and Find Free (#3850): SLAAC
  // needs 64-bit interface IDs. Only a node already past /63 goes deeper.
  const aim =
    v6 && kind === "subnet" && parentPrefix < 64
      ? 64
      : parentPrefix + (v6 ? 16 : 8);
  const first = Math.min(aim, max);
  for (let target = first; target <= max; target++) {
    if (target <= parentPrefix) continue;
    const slot = 1n << BigInt(total - target);
    let addr = span.base;
    while (addr < end) {
      const hit = taken.filter((t) => addr < t.end && t.start < addr + slot);
      if (hit.length === 0) return `${formatAddress(addr, v6)}/${target}`;
      // Jump to the first slot boundary past every sibling in the way.
      const past = hit.reduce((m, t) => (t.end > m ? t.end : m), addr);
      addr = ((past + slot - 1n) / slot) * slot;
    }
  }
  return "";
}
