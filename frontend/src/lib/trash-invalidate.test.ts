import { describe, expect, it } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { invalidateAfterTrashChange } from "@/lib/trash-invalidate";

describe("invalidateAfterTrashChange (#4205)", () => {
  it("invalidates the DNS, IPAM and DHCP key families the pages use", async () => {
    const qc = new QueryClient();
    const keys = [
      ["dns-records", "z1"],
      ["dns-zones", "g1"],
      ["dns-views", "g1"],
      ["ipam-subnets", "s1"],
      ["subnets", "b1"],
      ["dhcp-scopes-subnet", "s1"],
      ["trash"],
    ];
    for (const k of keys) qc.setQueryData(k, []);
    await invalidateAfterTrashChange(qc);
    for (const k of keys) {
      expect(qc.getQueryState(k)?.isInvalidated, JSON.stringify(k)).toBe(true);
    }
  });
});
