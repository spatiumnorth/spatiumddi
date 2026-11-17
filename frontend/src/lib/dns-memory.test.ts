/**
 * #3551 — the memory banner on a DNS group's Views and Blocklists tabs.
 * Each view that applies a blocklist loads its own copy of it, so the banner
 * names the numbers and the fix when the estimate reaches 80 % of the limit.
 */
import { describe, expect, it } from "vitest";
import type { DNSMemoryEstimate } from "@/lib/api";
import { memoryBannerLines } from "@/lib/dns-memory";

const MIB = 1024 * 1024;

function est(over: Partial<DNSMemoryEstimate> = {}): DNSMemoryEstimate {
  return {
    group_id: "g1",
    estimated_bytes: 925 * MIB,
    limit_bytes: 1024 * MIB,
    limit_source: "agent",
    limit_server: "ns1",
    unknown_limit_servers: [],
    percent: 90.3,
    warn: true,
    message: "x",
    baseline_bytes: 400 * MIB,
    zone_records_loaded: 0,
    zone_bytes: 0,
    rpz_bytes: 512 * MIB,
    rpz: [
      {
        zone: "spatium-blocklist-restricted.rpz.",
        views: ["restricted"],
        entries: 187544,
        estimated_bytes: 256 * MIB,
      },
      {
        zone: "spatium-blocklist-default.rpz.",
        views: ["default"],
        entries: 187544,
        estimated_bytes: 256 * MIB,
      },
    ],
    views: ["restricted", "default"],
    ...over,
  };
}

describe("memoryBannerLines", () => {
  it("says nothing below the threshold, or without an estimate", () => {
    expect(memoryBannerLines(est({ warn: false }))).toBeNull();
    expect(memoryBannerLines(null)).toBeNull();
    expect(memoryBannerLines(undefined)).toBeNull();
  });

  it("names the numbers, the per-view copies and the fix", () => {
    const l = memoryBannerLines(est())!;
    expect(l.headline).toContain("925 MiB");
    expect(l.headline).toContain("90%");
    expect(l.headline).toContain("1.0 GiB limit ns1 reports");
    expect(l.detail).toContain("restricted: 187,544 entries");
    expect(l.detail).toContain("default: 187,544 entries");
    expect(l.detail).toContain("cannot share a blocklist between views");
    expect(l.fix).toContain("fewer views");
    expect(l.fix).toContain("memory limit");
  });

  it("says when the limit is the assumed default", () => {
    const l = memoryBannerLines(
      est({
        limit_source: "default",
        limit_server: null,
        limit_bytes: 2048 * MIB,
      }),
    )!;
    expect(l.headline).toContain("default 2.0 GiB DNS pod limit");
  });
});
