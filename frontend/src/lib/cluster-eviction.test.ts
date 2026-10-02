/**
 * Promote eligibility while an eviction is pending (#1284).
 *
 * Fleet → Replace clears a row's roles at once, so the picker used to offer
 * the row again while the seed was still evicting it — and the seed removes
 * every etcd member under that hostname until the eviction settles. A node
 * promoted then would join and lose its member again on the seed's next tick.
 */

import { describe, expect, it } from "vitest";

import type { ApplianceRow } from "@/lib/api";
import { heldByEviction, hostnamesBeingEvicted } from "./cluster-eviction";

const row = (
  hostname: string,
  cluster_join_state: string | null,
): ApplianceRow => ({ hostname, cluster_join_state }) as ApplianceRow;

describe("heldByEviction", () => {
  it("holds back the row the seed is still evicting", () => {
    const evicted = row("ddi-3", "evicting");
    const evicting = hostnamesBeingEvicted([evicted]);
    expect(heldByEviction(evicted, evicting)).toBe(true);
  });

  it("holds back a box sharing that hostname, whatever its case", () => {
    const evicting = hostnamesBeingEvicted([
      row("ddi-3", "evicting"),
      row("ddi-4", null),
    ]);
    expect(heldByEviction(row("ddi-3", null), evicting)).toBe(true);
    expect(heldByEviction(row("DDI-3", null), evicting)).toBe(true);
    expect(heldByEviction(row("ddi-4", null), evicting)).toBe(false);
    expect(heldByEviction(row("ddi-30", null), evicting)).toBe(false);
  });

  it("releases the row and its namesakes once it settles left", () => {
    const settled = row("ddi-3", "left");
    const evicting = hostnamesBeingEvicted([settled]);
    expect(evicting.size).toBe(0);
    expect(heldByEviction(settled, evicting)).toBe(false);
    expect(heldByEviction(row("ddi-3", null), evicting)).toBe(false);
  });

  it("never matches a row without a hostname", () => {
    const evicting = hostnamesBeingEvicted([row("", "evicting")]);
    expect(evicting.size).toBe(0);
    expect(heldByEviction(row("", null), evicting)).toBe(false);
  });
});
